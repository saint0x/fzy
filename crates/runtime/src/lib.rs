pub mod browser;
pub mod service;

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceMode {
    Off,
    ReplayCritical,
    #[default]
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BrowserLane {
    Input,
    Render,
    Default,
    Background,
}

impl BrowserLane {
    const ORDER: [Self; 4] = [Self::Input, Self::Render, Self::Default, Self::Background];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Render => "render",
            Self::Default => "default",
            Self::Background => "background",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserQueueClass {
    Microtask,
    Macrotask,
}

impl BrowserQueueClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Microtask => "microtask",
            Self::Macrotask => "macrotask",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserAsyncOrigin {
    PromiseThen,
    PromiseCatch,
    PromiseFinally,
    EventCallback,
    Timer,
    Interval,
    AnimationFrame,
    Fetch,
    Input,
    Render,
    Background,
}

impl BrowserAsyncOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PromiseThen => "promise.then",
            Self::PromiseCatch => "promise.catch",
            Self::PromiseFinally => "promise.finally",
            Self::EventCallback => "event.callback",
            Self::Timer => "timer",
            Self::Interval => "interval",
            Self::AnimationFrame => "animation_frame",
            Self::Fetch => "fetch",
            Self::Input => "input",
            Self::Render => "render",
            Self::Background => "background",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromiseState {
    Fulfilled,
    Rejected,
}

impl PromiseState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fulfilled => "fulfilled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserSchedulerConfig {
    pub max_microtasks_per_tick: usize,
}

impl Default for BrowserSchedulerConfig {
    fn default() -> Self {
        Self {
            max_microtasks_per_tick: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserSpawn {
    pub lane: BrowserLane,
    pub queue: BrowserQueueClass,
    pub parent_task_id: Option<TaskId>,
    pub origin: BrowserAsyncOrigin,
    pub promise_id: Option<u64>,
}

impl BrowserSpawn {
    pub fn new(lane: BrowserLane, queue: BrowserQueueClass, origin: BrowserAsyncOrigin) -> Self {
        Self {
            lane,
            queue,
            parent_task_id: None,
            origin,
            promise_id: None,
        }
    }

    pub fn with_parent(mut self, parent_task_id: TaskId) -> Self {
        self.parent_task_id = Some(parent_task_id);
        self
    }

    pub fn with_promise(mut self, promise_id: u64) -> Self {
        self.promise_id = Some(promise_id);
        self
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
    Spawned {
        task_id: TaskId,
        detached: bool,
    },
    Started {
        task_id: TaskId,
    },
    Completed {
        task_id: TaskId,
    },
    Panicked {
        task_id: TaskId,
        message: String,
    },
    PanicRootCause {
        task_id: TaskId,
        cause_task_id: Option<TaskId>,
    },
    TimedOut {
        task_id: TaskId,
        timeout_ms: u64,
    },
    Cancelled {
        task_id: TaskId,
    },
    Backpressure {
        queue_depth: usize,
        capacity: usize,
    },
    JoinWait {
        waiter: TaskId,
        target: TaskId,
    },
    JoinCycle {
        path: Vec<TaskId>,
    },
    Yielded {
        task_id: TaskId,
        reason: String,
    },
    IoWait {
        task_id: TaskId,
        key: String,
    },
    IoReady {
        task_id: TaskId,
        key: String,
    },
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
    MemoryPressure {
        task_id: TaskId,
        bytes: usize,
        level: String,
    },
    ResourceLeak {
        task_id: TaskId,
        subsystem: String,
        resource: String,
    },
    Detached {
        task_id: TaskId,
    },
    BrowserSchedulerConfigured {
        max_microtasks_per_tick: usize,
    },
    BrowserTaskEnqueued {
        task_id: TaskId,
        lane: BrowserLane,
        queue: BrowserQueueClass,
        origin: BrowserAsyncOrigin,
        parent_task_id: Option<TaskId>,
        promise_id: Option<u64>,
    },
    BrowserTaskScheduled {
        task_id: TaskId,
        lane: BrowserLane,
        queue: BrowserQueueClass,
        origin: BrowserAsyncOrigin,
    },
    BrowserPromiseSettled {
        task_id: TaskId,
        promise_id: u64,
        state: PromiseState,
    },
    BrowserCausalLink {
        parent_task_id: TaskId,
        child_task_id: TaskId,
        relation: String,
    },
    BrowserStarvationPrevented {
        task_id: TaskId,
        lane: BrowserLane,
        queue: BrowserQueueClass,
        after_microtasks: usize,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExecutorConfig {
    pub max_queue_depth: Option<usize>,
    pub task_timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    QueueSaturated { capacity: usize, queue_depth: usize },
}

#[derive(Default)]
pub struct DeterministicExecutor {
    next_task_id: TaskId,
    queue: RunQueue,
    tasks: BTreeMap<TaskId, TaskEntry>,
    trace: Vec<TaskEvent>,
    coverage_flip: bool,
    trace_mode: TraceMode,
    config: ExecutorConfig,
    join_edges: BTreeMap<TaskId, Vec<TaskId>>,
    io_waiters: BTreeMap<String, Vec<TaskId>>,
    root_cause_hint: Option<TaskId>,
    browser_scheduler: Option<BrowserSchedulerState>,
    browser_tasks: BTreeMap<TaskId, BrowserTaskMetadata>,
}

struct TaskEntry {
    detached: bool,
    state: TaskState,
    task: Option<Task>,
    panic_message: Option<String>,
    token: CancellationToken,
}

#[derive(Debug, Clone, Copy)]
struct BrowserTaskMetadata {
    lane: BrowserLane,
    queue: BrowserQueueClass,
    origin: BrowserAsyncOrigin,
    parent_task_id: Option<TaskId>,
    promise_id: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct QueueNode {
    prev: Option<TaskId>,
    next: Option<TaskId>,
}

#[derive(Default)]
struct BrowserLaneQueues {
    input: RunQueue,
    render: RunQueue,
    default_lane: RunQueue,
    background: RunQueue,
}

impl BrowserLaneQueues {
    fn len(&self) -> usize {
        self.input.len() + self.render.len() + self.default_lane.len() + self.background.len()
    }

    fn push_back(&mut self, lane: BrowserLane, task_id: TaskId) {
        match lane {
            BrowserLane::Input => self.input.push_back(task_id),
            BrowserLane::Render => self.render.push_back(task_id),
            BrowserLane::Default => self.default_lane.push_back(task_id),
            BrowserLane::Background => self.background.push_back(task_id),
        }
    }

    fn remove(&mut self, task_id: TaskId) -> bool {
        self.input.remove(task_id)
            || self.render.remove(task_id)
            || self.default_lane.remove(task_id)
            || self.background.remove(task_id)
    }

    fn pop_from_lane(&mut self, lane: BrowserLane) -> Option<TaskId> {
        match lane {
            BrowserLane::Input => self.input.pop_front(),
            BrowserLane::Render => self.render.pop_front(),
            BrowserLane::Default => self.default_lane.pop_front(),
            BrowserLane::Background => self.background.pop_front(),
        }
    }

    fn next_non_empty_lane(&self, start: usize) -> Option<BrowserLane> {
        for offset in 0..BrowserLane::ORDER.len() {
            let lane = BrowserLane::ORDER[(start + offset) % BrowserLane::ORDER.len()];
            let len = match lane {
                BrowserLane::Input => self.input.len(),
                BrowserLane::Render => self.render.len(),
                BrowserLane::Default => self.default_lane.len(),
                BrowserLane::Background => self.background.len(),
            };
            if len > 0 {
                return Some(lane);
            }
        }
        None
    }
}

struct BrowserSchedulerState {
    config: BrowserSchedulerConfig,
    microtasks: BrowserLaneQueues,
    macrotasks: BrowserLaneQueues,
    lane_cursor: usize,
    consecutive_microtasks: usize,
}

#[derive(Default)]
struct RunQueue {
    head: Option<TaskId>,
    tail: Option<TaskId>,
    nodes: BTreeMap<TaskId, QueueNode>,
    random_pool: Vec<TaskId>,
    random_pos: BTreeMap<TaskId, usize>,
}

impl RunQueue {
    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn push_back(&mut self, task_id: TaskId) {
        if self.nodes.contains_key(&task_id) {
            return;
        }
        let node = QueueNode {
            prev: self.tail,
            next: None,
        };
        if let Some(tail) = self.tail {
            if let Some(tail_node) = self.nodes.get_mut(&tail) {
                tail_node.next = Some(task_id);
            }
        } else {
            self.head = Some(task_id);
        }
        self.tail = Some(task_id);
        self.nodes.insert(task_id, node);
        self.random_pos.insert(task_id, self.random_pool.len());
        self.random_pool.push(task_id);
    }

    fn remove(&mut self, task_id: TaskId) -> bool {
        let Some(node) = self.nodes.remove(&task_id) else {
            return false;
        };
        match node.prev {
            Some(prev) => {
                if let Some(prev_node) = self.nodes.get_mut(&prev) {
                    prev_node.next = node.next;
                }
            }
            None => self.head = node.next,
        }
        match node.next {
            Some(next) => {
                if let Some(next_node) = self.nodes.get_mut(&next) {
                    next_node.prev = node.prev;
                }
            }
            None => self.tail = node.prev,
        }
        if let Some(idx) = self.random_pos.remove(&task_id) {
            let last = self.random_pool.pop().expect("random pool non-empty");
            if idx < self.random_pool.len() {
                self.random_pool[idx] = last;
                self.random_pos.insert(last, idx);
            }
        }
        true
    }

    fn pop_front(&mut self) -> Option<TaskId> {
        let id = self.head?;
        let removed = self.remove(id);
        if removed {
            Some(id)
        } else {
            None
        }
    }

    fn pop_back(&mut self) -> Option<TaskId> {
        let id = self.tail?;
        let removed = self.remove(id);
        if removed {
            Some(id)
        } else {
            None
        }
    }

    fn pop_random(&mut self, random_state: &mut u64) -> Option<TaskId> {
        if self.random_pool.is_empty() {
            return None;
        }
        *random_state = random_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        let index = (*random_state as usize) % self.random_pool.len();
        let id = self.random_pool[index];
        let _ = self.remove(id);
        Some(id)
    }
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

    pub fn enable_browser_scheduler(&mut self, config: BrowserSchedulerConfig) {
        self.browser_scheduler = Some(BrowserSchedulerState {
            config,
            microtasks: BrowserLaneQueues::default(),
            macrotasks: BrowserLaneQueues::default(),
            lane_cursor: 0,
            consecutive_microtasks: 0,
        });
        self.record_event(TaskEvent::BrowserSchedulerConfigured {
            max_microtasks_per_tick: config.max_microtasks_per_tick,
        });
    }

    pub fn browser_scheduler_config(&self) -> Option<BrowserSchedulerConfig> {
        self.browser_scheduler.as_ref().map(|state| state.config)
    }

    pub fn spawn(&mut self, task: Task) -> TaskId {
        let browser_meta = self.default_browser_spawn_meta();
        self.spawn_inner_unbounded(task, false, browser_meta).0
    }

    pub fn spawn_with_token(&mut self, task: Task) -> (TaskId, CancellationToken) {
        let browser_meta = self.default_browser_spawn_meta();
        self.spawn_inner_unbounded(task, false, browser_meta)
    }

    pub fn spawn_bounded(&mut self, task: Task) -> Result<(TaskId, CancellationToken), SpawnError> {
        if let Some(capacity) = self.config.max_queue_depth {
            if self.pending_queue_depth() >= capacity {
                self.record_event(TaskEvent::Backpressure {
                    queue_depth: self.pending_queue_depth(),
                    capacity,
                });
                return Err(SpawnError::QueueSaturated {
                    capacity,
                    queue_depth: self.pending_queue_depth(),
                });
            }
        }
        let browser_meta = self.default_browser_spawn_meta();
        Ok(self.spawn_inner_unbounded(task, false, browser_meta))
    }

    pub fn spawn_detached(&mut self, task: Task) -> TaskId {
        let browser_meta = self.default_browser_spawn_meta();
        self.spawn_inner_unbounded(task, true, browser_meta).0
    }

    pub fn spawn_browser_task(&mut self, task: Task, spawn: BrowserSpawn) -> TaskId {
        self.spawn_inner_unbounded(
            task,
            false,
            Some(BrowserTaskMetadata {
                lane: spawn.lane,
                queue: spawn.queue,
                origin: spawn.origin,
                parent_task_id: spawn.parent_task_id,
                promise_id: spawn.promise_id,
            }),
        )
        .0
    }

    pub fn record_promise_settlement(
        &mut self,
        task_id: TaskId,
        promise_id: u64,
        state: PromiseState,
    ) -> bool {
        if !self.tasks.contains_key(&task_id) {
            return false;
        }
        self.record_event(TaskEvent::BrowserPromiseSettled {
            task_id,
            promise_id,
            state,
        });
        true
    }

    fn spawn_inner_unbounded(
        &mut self,
        task: Task,
        detached: bool,
        browser_meta: Option<BrowserTaskMetadata>,
    ) -> (TaskId, CancellationToken) {
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
        self.enqueue_task(task_id, browser_meta);
        self.record_event(TaskEvent::Spawned { task_id, detached });
        if detached {
            self.record_event(TaskEvent::Detached { task_id });
        }
        if let Some(meta) = browser_meta {
            self.record_event(TaskEvent::BrowserTaskEnqueued {
                task_id,
                lane: meta.lane,
                queue: meta.queue,
                origin: meta.origin,
                parent_task_id: meta.parent_task_id,
                promise_id: meta.promise_id,
            });
            if let Some(parent_task_id) = meta.parent_task_id {
                self.record_event(TaskEvent::BrowserCausalLink {
                    parent_task_id,
                    child_task_id: task_id,
                    relation: meta.origin.as_str().to_string(),
                });
            }
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

    pub fn simulate_memory_pressure(&mut self, task_id: TaskId, bytes: usize) -> bool {
        if !self.tasks.contains_key(&task_id) {
            return false;
        }
        let level = if bytes >= (1usize << 30) {
            "critical"
        } else if bytes >= (1usize << 28) {
            "high"
        } else if bytes >= (1usize << 24) {
            "medium"
        } else {
            "low"
        };
        self.record_event(TaskEvent::MemoryPressure {
            task_id,
            bytes,
            level: level.to_string(),
        });
        true
    }

    pub fn report_resource_leak(
        &mut self,
        task_id: TaskId,
        subsystem: impl Into<String>,
        resource: impl Into<String>,
    ) -> bool {
        if !self.tasks.contains_key(&task_id) {
            return false;
        }
        self.record_event(TaskEvent::ResourceLeak {
            task_id,
            subsystem: subsystem.into(),
            resource: resource.into(),
        });
        true
    }

    pub fn run_next(&mut self) -> Option<TaskId> {
        if self.browser_scheduler.is_some() {
            return self.run_next_browser();
        }
        self.run_next_with_scheduler(Scheduler::Fifo, &mut 0)
    }

    pub fn run_next_with_scheduler(
        &mut self,
        scheduler: Scheduler,
        random_state: &mut u64,
    ) -> Option<TaskId> {
        if self.browser_scheduler.is_some() {
            return self.run_next_browser();
        }
        let task_id = match scheduler {
            Scheduler::Fifo => self.queue.pop_front()?,
            Scheduler::Random => self.queue.pop_random(random_state)?,
            Scheduler::CoverageGuided => {
                let from_back = self.coverage_flip;
                self.coverage_flip = !self.coverage_flip;
                if from_back {
                    self.queue.pop_back()?
                } else {
                    self.queue.pop_front()?
                }
            }
        };

        self.execute_task(task_id);

        Some(task_id)
    }

    pub fn run_next_browser(&mut self) -> Option<TaskId> {
        let (task_id, lane, queue, origin, starvation_after) = self.pop_browser_scheduled_task()?;
        if let Some(after_microtasks) = starvation_after {
            self.record_event(TaskEvent::BrowserStarvationPrevented {
                task_id,
                lane,
                queue,
                after_microtasks,
            });
        }
        self.record_event(TaskEvent::BrowserTaskScheduled {
            task_id,
            lane,
            queue,
            origin,
        });
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

        let started = Instant::now();
        match catch_unwind(AssertUnwindSafe(task)) {
            Ok(()) => {
                if let Some(timeout) = self.config.task_timeout {
                    if started.elapsed() > timeout {
                        if let Some(entry) = self.tasks.get_mut(&task_id) {
                            entry.state = TaskState::TimedOut;
                            entry.token.cancel();
                        }
                        self.record_event(TaskEvent::TimedOut {
                            task_id,
                            timeout_ms: timeout.as_millis() as u64,
                        });
                        return;
                    }
                }
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

    pub fn run_until_idle(&mut self) {
        while self.run_next().is_some() {}
    }

    pub fn run_until_idle_with_scheduler(
        &mut self,
        scheduler: Scheduler,
        seed: u64,
    ) -> Vec<TaskId> {
        if self.browser_scheduler.is_some() {
            return self.run_until_idle_browser();
        }
        let mut order = Vec::new();
        let mut random_state = seed.max(1);
        while let Some(task_id) = self.run_next_with_scheduler(scheduler, &mut random_state) {
            order.push(task_id);
        }
        order
    }

    pub fn run_until_idle_browser(&mut self) -> Vec<TaskId> {
        let mut order = Vec::new();
        while let Some(task_id) = self.run_next_browser() {
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
        self.requeue_task(task_id);
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
        self.io_waiters
            .entry(key.clone())
            .or_default()
            .push(task_id);
        self.record_event(TaskEvent::IoWait { task_id, key });
        true
    }

    pub fn io_ready(&mut self, key: &str) -> usize {
        let waiters = self.io_waiters.remove(key).unwrap_or_default();
        let mut woken = 0usize;
        for task_id in waiters {
            if let Some(entry) = self.tasks.get_mut(&task_id) {
                entry.state = TaskState::Pending;
                self.requeue_task(task_id);
                self.record_event(TaskEvent::IoReady {
                    task_id,
                    key: key.to_string(),
                });
                woken += 1;
            }
        }
        woken
    }

    pub fn record_channel_send(
        &mut self,
        task_id: TaskId,
        channel: impl Into<String>,
        payload: &[u8],
    ) {
        self.record_event(TaskEvent::ChannelSend {
            task_id,
            channel: channel.into(),
            bytes: payload.len(),
            payload_hash: fnv1a(payload),
        });
    }

    pub fn record_channel_recv(
        &mut self,
        task_id: TaskId,
        channel: impl Into<String>,
        payload: &[u8],
    ) {
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
            if self.remove_pending_task(*task_id) {
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

    fn pending_queue_depth(&self) -> usize {
        if let Some(state) = &self.browser_scheduler {
            state.microtasks.len() + state.macrotasks.len()
        } else {
            self.queue.len()
        }
    }

    fn default_browser_spawn_meta(&self) -> Option<BrowserTaskMetadata> {
        self.browser_scheduler
            .as_ref()
            .map(|_| BrowserTaskMetadata {
                lane: BrowserLane::Default,
                queue: BrowserQueueClass::Macrotask,
                origin: BrowserAsyncOrigin::Background,
                parent_task_id: None,
                promise_id: None,
            })
    }

    fn enqueue_task(&mut self, task_id: TaskId, browser_meta: Option<BrowserTaskMetadata>) {
        if let Some(meta) = browser_meta {
            self.browser_tasks.insert(task_id, meta);
        }
        if let Some(meta) = self.browser_tasks.get(&task_id).copied() {
            if let Some(state) = self.browser_scheduler.as_mut() {
                match meta.queue {
                    BrowserQueueClass::Microtask => state.microtasks.push_back(meta.lane, task_id),
                    BrowserQueueClass::Macrotask => state.macrotasks.push_back(meta.lane, task_id),
                }
                return;
            }
        }
        self.queue.push_back(task_id);
    }

    fn requeue_task(&mut self, task_id: TaskId) {
        self.enqueue_task(task_id, None);
    }

    fn remove_pending_task(&mut self, task_id: TaskId) -> bool {
        if let Some(meta) = self.browser_tasks.get(&task_id).copied() {
            if let Some(state) = self.browser_scheduler.as_mut() {
                return match meta.queue {
                    BrowserQueueClass::Microtask => state.microtasks.remove(task_id),
                    BrowserQueueClass::Macrotask => state.macrotasks.remove(task_id),
                };
            }
        }
        self.queue.remove(task_id)
    }

    fn pop_browser_scheduled_task(
        &mut self,
    ) -> Option<(
        TaskId,
        BrowserLane,
        BrowserQueueClass,
        BrowserAsyncOrigin,
        Option<usize>,
    )> {
        let state = self.browser_scheduler.as_mut()?;
        let had_microtasks = state.microtasks.len() > 0;
        let should_force_macrotask = had_microtasks
            && state.consecutive_microtasks >= state.config.max_microtasks_per_tick
            && state.macrotasks.len() > 0;

        let (lane, queue, starvation_after) = if !should_force_macrotask {
            if let Some(lane) = state.microtasks.next_non_empty_lane(state.lane_cursor) {
                state.consecutive_microtasks += 1;
                (lane, BrowserQueueClass::Microtask, None)
            } else {
                let lane = state.macrotasks.next_non_empty_lane(state.lane_cursor)?;
                state.consecutive_microtasks = 0;
                (lane, BrowserQueueClass::Macrotask, None)
            }
        } else {
            let lane = state.macrotasks.next_non_empty_lane(state.lane_cursor)?;
            let after_microtasks = state.consecutive_microtasks;
            state.consecutive_microtasks = 0;
            (lane, BrowserQueueClass::Macrotask, Some(after_microtasks))
        };

        let task_id = match queue {
            BrowserQueueClass::Microtask => state.microtasks.pop_from_lane(lane)?,
            BrowserQueueClass::Macrotask => state.macrotasks.pop_from_lane(lane)?,
        };
        state.lane_cursor = BrowserLane::ORDER
            .iter()
            .position(|candidate| *candidate == lane)
            .map(|index| (index + 1) % BrowserLane::ORDER.len())
            .unwrap_or(0);
        let origin = self
            .browser_tasks
            .get(&task_id)
            .map(|meta| meta.origin)
            .unwrap_or(BrowserAsyncOrigin::Background);
        Some((task_id, lane, queue, origin, starvation_after))
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
        plan_async_checkpoints, BrowserAsyncOrigin, BrowserLane, BrowserQueueClass,
        BrowserSchedulerConfig, BrowserSpawn, CancellationToken, DeterministicExecutor,
        ExecutorConfig, JoinOutcome, PanicReport, PromiseState, RuntimeConfig, Scheduler,
        TaskEvent, TaskLocalStore, TaskState,
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
        assert_eq!(run(7), vec![0, 2, 3, 1]);
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
        let _ = executor
            .spawn_bounded(Box::new(|| {}))
            .expect("first spawn");
        assert!(executor.spawn_bounded(Box::new(|| {})).is_err());
        assert!(executor
            .trace()
            .iter()
            .any(|event| matches!(event, TaskEvent::Backpressure { .. })));
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

    #[test]
    fn memory_pressure_and_resource_leak_events_are_recorded() {
        let mut executor = DeterministicExecutor::new();
        let task_id = executor.spawn(Box::new(|| {}));
        assert!(executor.simulate_memory_pressure(task_id, 1 << 29));
        assert!(executor.report_resource_leak(task_id, "process", "fd:7"));
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::MemoryPressure { task_id: id, .. } if *id == task_id
        )));
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::ResourceLeak { task_id: id, subsystem, .. } if *id == task_id && subsystem == "process"
        )));
    }

    #[test]
    fn browser_scheduler_prioritizes_microtasks_then_respects_lane_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut executor = DeterministicExecutor::new();
        executor.enable_browser_scheduler(BrowserSchedulerConfig {
            max_microtasks_per_tick: 8,
        });

        let input_log = Arc::clone(&log);
        executor.spawn_browser_task(
            Box::new(move || input_log.lock().unwrap().push("input-micro")),
            BrowserSpawn::new(
                BrowserLane::Input,
                BrowserQueueClass::Microtask,
                BrowserAsyncOrigin::PromiseThen,
            ),
        );
        let render_log = Arc::clone(&log);
        executor.spawn_browser_task(
            Box::new(move || render_log.lock().unwrap().push("render-micro")),
            BrowserSpawn::new(
                BrowserLane::Render,
                BrowserQueueClass::Microtask,
                BrowserAsyncOrigin::AnimationFrame,
            ),
        );
        let macro_log = Arc::clone(&log);
        executor.spawn_browser_task(
            Box::new(move || macro_log.lock().unwrap().push("background-macro")),
            BrowserSpawn::new(
                BrowserLane::Background,
                BrowserQueueClass::Macrotask,
                BrowserAsyncOrigin::Timer,
            ),
        );

        let order = executor.run_until_idle_browser();
        assert_eq!(order, vec![0, 1, 2]);
        assert_eq!(
            *log.lock().unwrap(),
            vec!["input-micro", "render-micro", "background-macro"]
        );
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::BrowserTaskScheduled {
                task_id: 0,
                lane: BrowserLane::Input,
                queue: BrowserQueueClass::Microtask,
                ..
            }
        )));
    }

    #[test]
    fn browser_scheduler_prevents_macrotask_starvation() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut executor = DeterministicExecutor::new();
        executor.enable_browser_scheduler(BrowserSchedulerConfig {
            max_microtasks_per_tick: 2,
        });

        for label in ["micro-1", "micro-2", "micro-3"] {
            let log = Arc::clone(&log);
            executor.spawn_browser_task(
                Box::new(move || log.lock().unwrap().push(label)),
                BrowserSpawn::new(
                    BrowserLane::Default,
                    BrowserQueueClass::Microtask,
                    BrowserAsyncOrigin::PromiseThen,
                ),
            );
        }
        let macro_log = Arc::clone(&log);
        executor.spawn_browser_task(
            Box::new(move || macro_log.lock().unwrap().push("macro")),
            BrowserSpawn::new(
                BrowserLane::Background,
                BrowserQueueClass::Macrotask,
                BrowserAsyncOrigin::Timer,
            ),
        );

        let order = executor.run_until_idle_browser();
        assert_eq!(order, vec![0, 1, 3, 2]);
        assert_eq!(
            *log.lock().unwrap(),
            vec!["micro-1", "micro-2", "macro", "micro-3"]
        );
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::BrowserStarvationPrevented {
                task_id: 3,
                lane: BrowserLane::Background,
                queue: BrowserQueueClass::Macrotask,
                after_microtasks: 2,
            }
        )));
    }

    #[test]
    fn browser_scheduler_tracks_promise_lineage_and_settlement() {
        let mut executor = DeterministicExecutor::new();
        executor.enable_browser_scheduler(BrowserSchedulerConfig::default());
        let parent = executor.spawn(Box::new(|| {}));
        let child = executor.spawn_browser_task(
            Box::new(|| {}),
            BrowserSpawn::new(
                BrowserLane::Default,
                BrowserQueueClass::Microtask,
                BrowserAsyncOrigin::PromiseThen,
            )
            .with_parent(parent)
            .with_promise(17),
        );

        executor.record_promise_settlement(child, 17, PromiseState::Fulfilled);
        let _ = executor.run_until_idle_browser();

        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::BrowserTaskEnqueued {
                task_id,
                parent_task_id: Some(source),
                promise_id: Some(17),
                ..
            } if *task_id == child && *source == parent
        )));
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::BrowserCausalLink {
                parent_task_id,
                child_task_id,
                relation,
            } if *parent_task_id == parent && *child_task_id == child && relation == "promise.then"
        )));
        assert!(executor.trace().iter().any(|event| matches!(
            event,
            TaskEvent::BrowserPromiseSettled {
                task_id,
                promise_id: 17,
                state: PromiseState::Fulfilled,
            } if *task_id == child
        )));
    }
}
