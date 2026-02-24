use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProfile {
    Dev,
    Verify,
    Release,
}

#[derive(Debug, Clone)]
pub struct RuntimeProfileConfig {
    pub worker_count: usize,
    pub deterministic: bool,
    pub strict_verify: bool,
}

impl RuntimeProfile {
    pub fn config(self) -> RuntimeProfileConfig {
        match self {
            Self::Dev => RuntimeProfileConfig {
                worker_count: 2,
                deterministic: false,
                strict_verify: false,
            },
            Self::Verify => RuntimeProfileConfig {
                worker_count: 2,
                deterministic: true,
                strict_verify: true,
            },
            Self::Release => RuntimeProfileConfig {
                worker_count: 8,
                deterministic: true,
                strict_verify: false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestRuntimeContext {
    pub request_id: String,
    pub deadline_ms: Option<u64>,
    pub cancelled: bool,
}

impl RequestRuntimeContext {
    pub fn new(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            deadline_ms: None,
            cancelled: false,
        }
    }

    pub fn with_deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.cancelled
            || self
                .deadline_ms
                .map(|deadline| now_ms > deadline)
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownSignal {
    Sigterm,
    Sigint,
}

#[derive(Debug, Clone)]
pub struct ShutdownState {
    pub draining: bool,
    pub in_flight_requests: usize,
    pub started_at_ms: Option<u64>,
    pub timeout_ms: u64,
    pub signal: Option<ShutdownSignal>,
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self {
            draining: false,
            in_flight_requests: 0,
            started_at_ms: None,
            timeout_ms: 0,
            signal: None,
        }
    }
}

impl ShutdownState {
    pub fn begin(&mut self, signal: ShutdownSignal, timeout_ms: u64, now_ms: u64) {
        self.draining = true;
        self.signal = Some(signal);
        self.started_at_ms = Some(now_ms);
        self.timeout_ms = timeout_ms;
    }

    pub fn on_request_start(&mut self) -> Result<(), &'static str> {
        if self.draining {
            return Err("draining");
        }
        self.in_flight_requests += 1;
        Ok(())
    }

    pub fn on_request_finish(&mut self) {
        self.in_flight_requests = self.in_flight_requests.saturating_sub(1);
    }

    pub fn ready_to_stop(&self, now_ms: u64) -> bool {
        if !self.draining {
            return false;
        }
        if self.in_flight_requests == 0 {
            return true;
        }
        self.started_at_ms
            .map(|started| now_ms.saturating_sub(started) >= self.timeout_ms)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStats {
    pub task_queue_depth: usize,
    pub scheduler_lag_ms: u64,
    pub allocation_pressure_bytes: usize,
    pub open_file_count: usize,
    pub open_socket_count: usize,
}

#[derive(Default)]
pub struct ServiceRuntime {
    queue: VecDeque<String>,
    pub shutdown: ShutdownState,
    stats: RuntimeStats,
}

impl Default for RuntimeStats {
    fn default() -> Self {
        Self {
            task_queue_depth: 0,
            scheduler_lag_ms: 0,
            allocation_pressure_bytes: 0,
            open_file_count: 0,
            open_socket_count: 0,
        }
    }
}

impl ServiceRuntime {
    pub fn enqueue(&mut self, work_item: impl Into<String>) {
        self.queue.push_back(work_item.into());
        self.stats.task_queue_depth = self.queue.len();
    }

    pub fn dequeue(&mut self) -> Option<String> {
        let value = self.queue.pop_front();
        self.stats.task_queue_depth = self.queue.len();
        value
    }

    pub fn set_scheduler_lag(&mut self, lag_ms: u64) {
        self.stats.scheduler_lag_ms = lag_ms;
    }

    pub fn set_allocation_pressure(&mut self, bytes: usize) {
        self.stats.allocation_pressure_bytes = bytes;
    }

    pub fn set_file_count(&mut self, count: usize) {
        self.stats.open_file_count = count;
    }

    pub fn set_socket_count(&mut self, count: usize) {
        self.stats.open_socket_count = count;
    }

    pub fn snapshot_stats(&self) -> RuntimeStats {
        self.stats.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RequestRuntimeContext, RuntimeProfile, ServiceRuntime, ShutdownSignal, ShutdownState,
    };

    #[test]
    fn profile_contract_has_verify_mode_guarantees() {
        let cfg = RuntimeProfile::Verify.config();
        assert!(cfg.deterministic);
        assert!(cfg.strict_verify);
    }

    #[test]
    fn request_context_cancellation_and_deadline_propagate() {
        let mut ctx = RequestRuntimeContext::new("req-1").with_deadline(20);
        assert!(!ctx.is_expired(19));
        ctx.cancel();
        assert!(ctx.is_expired(19));
    }

    #[test]
    fn graceful_shutdown_drains_or_times_out() {
        let mut shutdown = ShutdownState::default();
        shutdown
            .on_request_start()
            .expect("request start should work");
        shutdown.begin(ShutdownSignal::Sigterm, 30, 10);
        assert!(!shutdown.ready_to_stop(20));
        shutdown.on_request_finish();
        assert!(shutdown.ready_to_stop(21));
    }

    #[test]
    fn runtime_stats_surface_updates() {
        let mut runtime = ServiceRuntime::default();
        runtime.enqueue("work");
        runtime.set_scheduler_lag(11);
        runtime.set_allocation_pressure(42);
        runtime.set_file_count(2);
        runtime.set_socket_count(3);
        let stats = runtime.snapshot_stats();
        assert_eq!(stats.task_queue_depth, 1);
        assert_eq!(stats.scheduler_lag_ms, 11);
        assert_eq!(stats.open_file_count, 2);
        assert_eq!(stats.open_socket_count, 3);
    }
}
