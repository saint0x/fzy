use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};

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
    Detached,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskEvent {
    Spawned { task_id: TaskId, detached: bool },
    Started { task_id: TaskId },
    Completed { task_id: TaskId },
    Panicked { task_id: TaskId, message: String },
    Detached { task_id: TaskId },
}

#[derive(Default)]
pub struct DeterministicExecutor {
    next_task_id: TaskId,
    queue: VecDeque<TaskId>,
    tasks: BTreeMap<TaskId, TaskEntry>,
    trace: Vec<TaskEvent>,
    coverage_flip: bool,
    trace_mode: TraceMode,
}

struct TaskEntry {
    detached: bool,
    state: TaskState,
    task: Option<Task>,
    panic_message: Option<String>,
}

impl DeterministicExecutor {
    pub fn new() -> Self {
        Self::new_with_trace_mode(TraceMode::Full)
    }

    pub fn new_with_trace_mode(trace_mode: TraceMode) -> Self {
        Self {
            trace_mode,
            ..Self::default()
        }
    }

    pub fn spawn(&mut self, task: Task) -> TaskId {
        self.spawn_inner(task, false)
    }

    pub fn spawn_detached(&mut self, task: Task) -> TaskId {
        self.spawn_inner(task, true)
    }

    fn spawn_inner(&mut self, task: Task, detached: bool) -> TaskId {
        let task_id = self.next_task_id;
        self.next_task_id += 1;

        self.tasks.insert(
            task_id,
            TaskEntry {
                detached,
                state: TaskState::Pending,
                task: Some(task),
                panic_message: None,
            },
        );
        self.queue.push_back(task_id);
        self.record_event(TaskEvent::Spawned { task_id, detached });
        if detached {
            self.record_event(TaskEvent::Detached { task_id });
        }
        task_id
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

        let task = {
            let entry = self.tasks.get_mut(&task_id)?;
            entry.state = TaskState::Running;
            entry.task.take()
        };
        self.record_event(TaskEvent::Started { task_id });

        let Some(task) = task else {
            return Some(task_id);
        };

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
            }
        }

        Some(task_id)
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
                TaskState::Pending | TaskState::Running => {
                    if self.run_next().is_none() {
                        return JoinOutcome::Missing;
                    }
                }
            }
        }
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
    "task panicked with non-string payload".to_string()
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        plan_async_checkpoints, DeterministicExecutor, JoinOutcome, PanicReport, RuntimeConfig,
        Scheduler, TaskEvent, TaskState,
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
}
