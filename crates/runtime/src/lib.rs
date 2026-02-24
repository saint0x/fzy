pub mod service;

use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Host,
    Deterministic,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub mode: Mode,
    pub seed: Option<u64>,
}

impl RuntimeConfig {
    pub fn deterministic(seed: u64) -> Self {
        Self {
            mode: Mode::Deterministic,
            seed: Some(seed),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Host,
            seed: None,
        }
    }
}

pub type TaskId = u64;

pub type Task = Box<dyn FnOnce() + Send + 'static>;

#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheduler {
    Fifo,
    Random,
    CoverageGuided,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceMode {
    Off,
    ReplayCritical,
    Full,
}

impl Default for TraceMode {
    fn default() -> Self {
        Self::Full
    }
}

pub fn plan_async_checkpoints(
    execution_order: &[TaskId],
    scheduler: Scheduler,
    seed: u64,
    checkpoints: usize,
) -> Vec<TaskId> {
    if checkpoints == 0 || execution_order.is_empty() {
        return Vec::new();
    }
    let mut decisions = Vec::with_capacity(checkpoints);
    let mut random_state = seed.max(1);
    let mut coverage_flip = false;
    for step in 0..checkpoints {
        let task_id = match scheduler {
            Scheduler::Fifo => execution_order[step % execution_order.len()],
            Scheduler::Random => {
                random_state = random_state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1);
                let index = (random_state as usize) % execution_order.len();
                execution_order[index]
            }
            Scheduler::CoverageGuided => {
                let index = if coverage_flip {
                    execution_order.len() - 1 - (step / 2 % execution_order.len())
                } else {
                    step / 2 % execution_order.len()
                };
                coverage_flip = !coverage_flip;
                execution_order[index]
            }
        };
        decisions.push(task_id);
    }
    decisions
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Completed,
    Panicked,
    TimedOut,
    Cancelled,
    Waiting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicReport {
    pub task_id: TaskId,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinOutcome {
    Completed,
    Panicked(PanicReport),
    TimedOut,
    Cancelled,
    Deadlock(Vec<TaskId>),
    Detached,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskEvent {
    Spawned { task_id: TaskId, detached: bool },
    Started { task_id: TaskId },
    Completed { task_id: TaskId },
    Panicked { task_id: TaskId, message: String },
    PanicRootCause {
        task_id: TaskId,
        cause_task_id: Option<TaskId>,
    },
    TimedOut { task_id: TaskId, timeout_ms: u64 },
    Cancelled { task_id: TaskId },
    Backpressure {
        queue_depth: usize,
        capacity: usize,
    },
    JoinWait { waiter: TaskId, target: TaskId },
    JoinCycle { path: Vec<TaskId> },
    Yielded { task_id: TaskId, reason: String },
    IoWait { task_id: TaskId, key: String },
    IoReady { task_id: TaskId, key: String },
    ChannelSend {
        task_id: TaskId,
        channel: String,
        bytes: usize,
        payload_hash: u64,
    },
    ChannelRecv {
        task_id: TaskId,
        channel: String,
        bytes: usize,
        payload_hash: u64,
    },
    Detached { task_id: TaskId },
}

#[derive(Debug, Clone, Copy)]
pub struct ExecutorConfig {
    pub max_queue_depth: Option<usize>,
    pub task_timeout: Option<Duration>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_queue_depth: None,
            task_timeout: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    QueueSaturated { capacity: usize, queue_depth: usize },
}

#[derive(Default)]
pub struct DeterministicExecutor {
    next_task_id: TaskId,
    queue: VecDeque<TaskId>,
    tasks: BTreeMap<TaskId, TaskEntry>,
    trace: Vec<TaskEvent>,
    coverage_flip: bool,
    trace_mode: TraceMode,
    config: ExecutorConfig,
    join_edges: BTreeMap<TaskId, Vec<TaskId>>,
    io_waiters: BTreeMap<String, Vec<TaskId>>,
    root_cause_hint: Option<TaskId>,
}

struct TaskEntry {
    detached: bool,
    state: TaskState,
    task: Option<Task>,
    panic_message: Option<String>,
    token: CancellationToken,
}

impl DeterministicExecutor {
    pub fn new() -> Self {
        Self::new_with_trace_mode(TraceMode::Full)
    }

    pub fn with_config(config: ExecutorConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    pub fn new_with_trace_mode(trace_mode: TraceMode) -> Self {
        Self {
            trace_mode,
            ..Self::default()
        }
    }

    pub fn spawn(&mut self, task: Task) -> TaskId {
        self.spawn_inner_unbounded(task, false).0
    }

    pub fn spawn_with_token(&mut self, task: Task) -> (TaskId, CancellationToken) {
        self.spawn_inner_unbounded(task, false)
    }

    pub fn spawn_bounded(&mut self, task: Task) -> Result<(TaskId, CancellationToken), SpawnError> {
        if let Some(capacity) = self.config.max_queue_depth {
            if self.queue.len() >= capacity {
                self.record_event(TaskEvent::Backpressure {
                    queue_depth: self.queue.len(),
                    capacity,
                });
                return Err(SpawnError::QueueSaturated {
                    capacity,
                    queue_depth: self.queue.len(),
                });
            }
        }
        Ok(self.spawn_inner_unbounded(task, false))
    }

    pub fn spawn_detached(&mut self, task: Task) -> TaskId {
        self.spawn_inner_unbounded(task, true).0
    }

    fn spawn_inner_unbounded(&mut self, task: Task, detached: bool) -> (TaskId, CancellationToken) {
        let task_id = self.next_task_id;
        self.next_task_id += 1;
        let token = CancellationToken::new();

        self.tasks.insert(
            task_id,
            TaskEntry {
                detached,
                state: TaskState::Pending,
                task: Some(task),
                panic_message: None,
                token: token.clone(),
            },
        );
        self.queue.push_back(task_id);
        self.record_event(TaskEvent::Spawned { task_id, detached });
        if detached {
            self.record_event(TaskEvent::Detached { task_id });
        }
        (task_id, token)
    }

    pub fn detach(&mut self, task_id: TaskId) -> bool {
        let Some(entry) = self.tasks.get_mut(&task_id) else {
            return false;
        };
        if entry.detached {
            return false;
        }
        entry.detached = true;
        self.record_event(TaskEvent::Detached { task_id });
        true
    }

    pub fn run_next(&mut self) -> Option<TaskId> {
        self.run_next_with_scheduler(Scheduler::Fifo, &mut 0)
    }

    pub fn run_next_with_scheduler(
        &mut self,
        scheduler: Scheduler,
        random_state: &mut u64,
    ) -> Option<TaskId> {
        let task_id = match scheduler {
            Scheduler::Fifo => self.queue.pop_front()?,
            Scheduler::Random => pop_random_task_id(&mut self.queue, random_state)?,
            Scheduler::CoverageGuided => {
                pop_coverage_guided_task_id(&mut self.queue, &mut self.coverage_flip)?
            }
        };

        self.execute_task(task_id);

        Some(task_id)
    }

    fn execute_task(&mut self, task_id: TaskId) {
        let task = {
            let Some(entry) = self.tasks.get_mut(&task_id) else {
                return;
            };
            if entry.token.is_cancelled() {
                entry.state = TaskState::Cancelled;
                self.record_event(TaskEvent::Cancelled { task_id });
                return;
            }
            entry.state = TaskState::Running;
            entry.task.take()
        };
        self.record_event(TaskEvent::Started { task_id });

        let Some(task) = task else {
            return;
        };

        if let Some(timeout) = self.config.task_timeout {
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(task));
                let _ = tx.send(result);
            });
            match rx.recv_timeout(timeout) {
                Ok(Ok(())) => {
                    if let Some(entry) = self.tasks.get_mut(&task_id) {
                        entry.state = TaskState::Completed;
                    }
                    self.record_event(TaskEvent::Completed { task_id });
                }
                Ok(Err(panic)) => {
                    let message = panic_message(panic);
                    if let Some(entry) = self.tasks.get_mut(&task_id) {
                        entry.state = TaskState::Panicked;
                        entry.panic_message = Some(message.clone());
                    }
                    self.record_event(TaskEvent::Panicked { task_id, message });
                    self.record_event(TaskEvent::PanicRootCause {
                        task_id,
                        cause_task_id: self.root_cause_hint,
                    });
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(entry) = self.tasks.get_mut(&task_id) {
                        entry.state = TaskState::TimedOut;
                        entry.token.cancel();
                    }
                    self.record_event(TaskEvent::TimedOut {
                        task_id,
                        timeout_ms: timeout.as_millis() as u64,
                    });
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if let Some(entry) = self.tasks.get_mut(&task_id) {
                        entry.state = TaskState::Cancelled;
                    }
                    self.record_event(TaskEvent::Cancelled { task_id });
                }
            }
        } else {
            match catch_unwind(AssertUnwindSafe(task)) {
                Ok(()) => {
                    if let Some(entry) = self.tasks.get_mut(&task_id) {
                        entry.state = TaskState::Completed;
                    }
                    self.record_event(TaskEvent::Completed { task_id });
                }
                Err(panic) => {
                    let message = panic_message(panic);
                    if let Some(entry) = self.tasks.get_mut(&task_id) {
                        entry.state = TaskState::Panicked;
                        entry.panic_message = Some(message.clone());
                    }
                    self.record_event(TaskEvent::Panicked { task_id, message });
                    self.record_event(TaskEvent::PanicRootCause {
                        task_id,
                        cause_task_id: self.root_cause_hint,
                    });
                }
            }
        }

    }

    pub fn run_until_idle(&mut self) {
        while self.run_next().is_some() {}
    }

    pub fn run_until_idle_with_scheduler(
        &mut self,
        scheduler: Scheduler,
        seed: u64,
    ) -> Vec<TaskId> {
        let mut order = Vec::new();
        let mut random_state = seed.max(1);
        while let Some(task_id) = self.run_next_with_scheduler(scheduler, &mut random_state) {
            order.push(task_id);
        }
        order
    }

    pub fn join(&mut self, task_id: TaskId) -> JoinOutcome {
        loop {
            let Some(entry) = self.tasks.get(&task_id) else {
                return JoinOutcome::Missing;
            };
            if entry.detached {
                return JoinOutcome::Detached;
            }
            match entry.state {
                TaskState::Completed => return JoinOutcome::Completed,
                TaskState::Panicked => {
                    return JoinOutcome::Panicked(PanicReport {
                        task_id,
                        message: entry
                            .panic_message
                            .clone()
                            .unwrap_or_else(|| "task panicked".to_string()),
                    });
                }
                TaskState::TimedOut => return JoinOutcome::TimedOut,
                TaskState::Cancelled => return JoinOutcome::Cancelled,
                TaskState::Pending | TaskState::Running => {
                    if self.run_next().is_none() {
                        return JoinOutcome::Missing;
                    }
                }
                TaskState::Waiting => {
                    return JoinOutcome::Missing;
                }
            }
        }
    }

    pub fn join_with_waiter(&mut self, waiter: TaskId, target: TaskId) -> JoinOutcome {
        self.record_event(TaskEvent::JoinWait { waiter, target });
        self.join_edges.entry(waiter).or_default().push(target);
        if let Some(path) = self.detect_join_cycle(waiter, target) {
            self.record_event(TaskEvent::JoinCycle { path: path.clone() });
            return JoinOutcome::Deadlock(path);
        }
        self.root_cause_hint = Some(waiter);
        self.join(target)
    }

    fn detect_join_cycle(&self, waiter: TaskId, target: TaskId) -> Option<Vec<TaskId>> {
        if waiter == target {
            return Some(vec![waiter, target]);
        }
        let mut stack = vec![(target, vec![waiter, target])];
        while let Some((node, path)) = stack.pop() {
            if let Some(nexts) = self.join_edges.get(&node) {
                for next in nexts {
                    let mut next_path = path.clone();
                    next_path.push(*next);
                    if *next == waiter {
                        return Some(next_path);
                    }
                    if !path.contains(next) {
                        stack.push((*next, next_path));
                    }
                }
            }
        }
        None
    }

    pub fn cancel_task(&mut self, task_id: TaskId) -> bool {
        let Some(entry) = self.tasks.get_mut(&task_id) else {
            return false;
        };
        entry.token.cancel();
        entry.state = TaskState::Cancelled;
        self.record_event(TaskEvent::Cancelled { task_id });
        true
    }

    pub fn yield_task(&mut self, task_id: TaskId, reason: impl Into<String>) -> bool {
        let Some(entry) = self.tasks.get_mut(&task_id) else {
            return false;
        };
        if !matches!(entry.state, TaskState::Running | TaskState::Pending) {
            return false;
        }
        entry.state = TaskState::Pending;
        self.queue.push_back(task_id);
        self.record_event(TaskEvent::Yielded {
            task_id,
            reason: reason.into(),
        });
        true
    }

    pub fn io_wait(&mut self, task_id: TaskId, key: impl Into<String>) -> bool {
        let key = key.into();
        let Some(entry) = self.tasks.get_mut(&task_id) else {
            return false;
        };
        entry.state = TaskState::Waiting;
        self.io_waiters.entry(key.clone()).or_default().push(task_id);
        self.record_event(TaskEvent::IoWait { task_id, key });
        true
    }

    pub fn io_ready(&mut self, key: &str) -> usize {
        let waiters = self.io_waiters.remove(key).unwrap_or_default();
        let mut woken = 0usize;
        for task_id in waiters {
            if let Some(entry) = self.tasks.get_mut(&task_id) {
                entry.state = TaskState::Pending;
                self.queue.push_back(task_id);
                self.record_event(TaskEvent::IoReady {
                    task_id,
                    key: key.to_string(),
                });
                woken += 1;
            }
        }
        woken
    }

    pub fn record_channel_send(&mut self, task_id: TaskId, channel: impl Into<String>, payload: &[u8]) {
        self.record_event(TaskEvent::ChannelSend {
            task_id,
            channel: channel.into(),
            bytes: payload.len(),
            payload_hash: fnv1a(payload),
        });
    }

    pub fn record_channel_recv(&mut self, task_id: TaskId, channel: impl Into<String>, payload: &[u8]) {
        self.record_event(TaskEvent::ChannelRecv {
            task_id,
            channel: channel.into(),
            bytes: payload.len(),
            payload_hash: fnv1a(payload),
        });
    }

    pub fn replay_order(&mut self, execution_order: &[TaskId]) -> Vec<TaskId> {
        let mut replayed = Vec::new();
        for task_id in execution_order {
            if let Some(index) = self.queue.iter().position(|queued| queued == task_id) {
                let _ = self.queue.remove(index);
                self.execute_task(*task_id);
                replayed.push(*task_id);
            }
        }
        replayed
    }

    pub fn trace(&self) -> &[TaskEvent] {
        &self.trace
    }

    pub fn state(&self, task_id: TaskId) -> Option<TaskState> {
        self.tasks.get(&task_id).map(|entry| entry.state)
    }

    fn record_event(&mut self, event: TaskEvent) {
        match self.trace_mode {
            TraceMode::Off => {}
            TraceMode::ReplayCritical => {
                if matches!(event, TaskEvent::Panicked { .. }) {
                    self.trace.push(event);
                }
            }
            TraceMode::Full => self.trace.push(event),
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(value) = payload.downcast_ref::<i32>() {
        return format!("task panicked with i32 payload: {value}");
    }
    if let Some(value) = payload.downcast_ref::<u64>() {
        return format!("task panicked with u64 payload: {value}");
    }
    if let Some(value) = payload.downcast_ref::<bool>() {
        return format!("task panicked with bool payload: {value}");
    }
    "task panicked with non-string payload (unknown type)".to_string()
}

fn pop_random_task_id(queue: &mut VecDeque<TaskId>, random_state: &mut u64) -> Option<TaskId> {
    if queue.is_empty() {
        return None;
    }
    // LCG keeps schedule generation deterministic from a given seed.
    *random_state = random_state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1);
    let index = (*random_state as usize) % queue.len();
    queue.remove(index)
}

fn pop_coverage_guided_task_id(
    queue: &mut VecDeque<TaskId>,
    coverage_flip: &mut bool,
) -> Option<TaskId> {
    if queue.is_empty() {
        return None;
    }
    let from_back = *coverage_flip;
    *coverage_flip = !*coverage_flip;
    if from_back {
        queue.pop_back()
    } else {
        queue.pop_front()
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[derive(Default)]
pub struct TaskLocalStore {
    values: BTreeMap<TaskId, BTreeMap<String, String>>,
}

impl TaskLocalStore {
    pub fn set(&mut self, task_id: TaskId, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .entry(task_id)
            .or_default()
            .insert(key.into(), value.into());
    }

    pub fn get(&self, task_id: TaskId, key: &str) -> Option<&str> {
        self.values
            .get(&task_id)
            .and_then(|fields| fields.get(key))
            .map(String::as_str)
    }

    pub fn propagate(&mut self, from: TaskId, to: TaskId) {
        if let Some(values) = self.values.get(&from).cloned() {
            self.values.insert(to, values);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        plan_async_checkpoints, CancellationToken, DeterministicExecutor, ExecutorConfig,
        JoinOutcome, PanicReport, RuntimeConfig, Scheduler, TaskEvent, TaskLocalStore, TaskState,
    };

    #[test]
    fn deterministic_config_sets_mode_and_seed() {
        let config = RuntimeConfig::deterministic(7);
        assert_eq!(config.mode, super::Mode::Deterministic);
        assert_eq!(config.seed, Some(7));
    }

    #[test]
    fn executor_runs_tasks_in_spawn_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut executor = DeterministicExecutor::new();

        let first_log = Arc::clone(&log);
        let second_log = Arc::clone(&log);
        let first = executor.spawn(Box::new(move || first_log.lock().unwrap().push(1)));
        let second = executor.spawn(Box::new(move || second_log.lock().unwrap().push(2)));

        assert_eq!(executor.join(second), JoinOutcome::Completed);
        assert_eq!(executor.state(first), Some(TaskState::Completed));
        assert_eq!(executor.state(second), Some(TaskState::Completed));
        assert_eq!(*log.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn detached_tasks_cannot_be_joined() {
        let mut executor = DeterministicExecutor::new();
        let task_id = executor.spawn(Box::new(|| {}));
        assert!(executor.detach(task_id));
        assert_eq!(executor.join(task_id), JoinOutcome::Detached);
    }

    #[test]
    fn captures_panic_with_structured_report_and_trace() {
        let mut executor = DeterministicExecutor::new();
        let task_id = executor.spawn(Box::new(|| panic!("boom")));

        assert_eq!(
            executor.join(task_id),
            JoinOutcome::Panicked(PanicReport {
                task_id,
                message: "boom".to_string()
            })
        );
        assert_eq!(executor.state(task_id), Some(TaskState::Panicked));
        assert!(executor.trace().iter().any(|event| {
            matches!(
                event,
                TaskEvent::Panicked { task_id: id, message } if *id == task_id && message == "boom"
            )
        }));
    }

    #[test]
    fn random_scheduler_is_seed_deterministic() {
        let run = |seed| {
            let mut exec = DeterministicExecutor::new();
            for _ in 0..4 {
                exec.spawn(Box::new(|| {}));
            }
            exec.run_until_idle_with_scheduler(Scheduler::Random, seed)
        };
        assert_eq!(run(7), run(7));
        assert_eq!(run(7), vec![0, 3, 1, 2]);
    }

    #[test]
    fn coverage_guided_scheduler_alternates_front_and_back() {
        let mut exec = DeterministicExecutor::new();
        for _ in 0..5 {
            exec.spawn(Box::new(|| {}));
        }
        let order = exec.run_until_idle_with_scheduler(Scheduler::CoverageGuided, 1);
        assert_eq!(order, vec![0, 4, 1, 3, 2]);
    }

    #[test]
    fn async_checkpoints_follow_scheduler_policy() {
        let order = vec![0, 2, 1];
        assert_eq!(
            plan_async_checkpoints(&order, Scheduler::Fifo, 9, 6),
            vec![0, 2, 1, 0, 2, 1]
        );
        assert_eq!(
            plan_async_checkpoints(&order, Scheduler::CoverageGuided, 9, 5),
            vec![0, 1, 2, 2, 1]
        );
    }

    #[test]
    fn bounded_queue_reports_backpressure() {
        let mut executor = DeterministicExecutor::with_config(ExecutorConfig {
            max_queue_depth: Some(1),
            task_timeout: None,
        });
        let _ = executor.spawn_bounded(Box::new(|| {})).expect("first spawn");
        assert!(executor.spawn_bounded(Box::new(|| {})).is_err());
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::Backpressure { .. }
        )));
    }

    #[test]
    fn timeout_marks_task_terminal() {
        let mut executor = DeterministicExecutor::with_config(ExecutorConfig {
            max_queue_depth: None,
            task_timeout: Some(Duration::from_millis(5)),
        });
        let task_id = executor.spawn(Box::new(|| std::thread::sleep(Duration::from_millis(50))));
        let _ = executor.run_next();
        assert_eq!(executor.state(task_id), Some(TaskState::TimedOut));
        assert_eq!(executor.join(task_id), JoinOutcome::TimedOut);
    }

    #[test]
    fn join_cycle_is_detected() {
        let mut executor = DeterministicExecutor::new();
        let a = executor.spawn(Box::new(|| {}));
        let b = executor.spawn(Box::new(|| {}));
        let _ = executor.join_with_waiter(a, b);
        let cycle = executor.join_with_waiter(b, a);
        assert!(matches!(cycle, JoinOutcome::Deadlock(_)));
    }

    #[test]
    fn channel_payload_events_are_recorded() {
        let mut executor = DeterministicExecutor::new();
        executor.record_channel_send(1, "jobs", b"ping");
        executor.record_channel_recv(2, "jobs", b"pong");
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::ChannelSend { channel, .. } if channel == "jobs"
        )));
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::ChannelRecv { channel, .. } if channel == "jobs"
        )));
    }

    #[test]
    fn task_local_store_propagates_context() {
        let mut store = TaskLocalStore::default();
        store.set(1, "trace_id", "abc");
        store.propagate(1, 2);
        assert_eq!(store.get(2, "trace_id"), Some("abc"));
    }

    #[test]
    fn cancellation_token_flips_state() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }
}
