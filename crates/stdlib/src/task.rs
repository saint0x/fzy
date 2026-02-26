use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskError {
    Cancelled,
    Timeout,
    RetryExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_factor: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 25,
            max_delay_ms: 500,
            backoff_factor: 2,
        }
    }
}

impl RetryPolicy {
    pub fn validate(&self) -> Result<(), TaskError> {
        if self.max_attempts == 0 || self.backoff_factor < 1 {
            return Err(TaskError::RetryExhausted);
        }
        Ok(())
    }

    pub fn delay_for_attempt(&self, attempt: usize) -> u64 {
        let mut delay = self.initial_delay_ms.max(1);
        for _ in 1..attempt {
            delay = delay.saturating_mul(self.backoff_factor as u64);
            delay = delay.min(self.max_delay_ms.max(1));
        }
        delay
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutPolicy {
    pub timeout_ms: u64,
}

impl TimeoutPolicy {
    pub fn has_elapsed(&self, started_at: Instant) -> bool {
        started_at.elapsed() > Duration::from_millis(self.timeout_ms)
    }
}

pub fn retry_with_timeout<T, F>(
    retry: RetryPolicy,
    timeout: TimeoutPolicy,
    mut is_cancelled: impl FnMut() -> bool,
    mut op: F,
) -> Result<T, TaskError>
where
    F: FnMut(usize) -> Result<T, TaskError>,
{
    retry.validate()?;
    let started = Instant::now();
    for attempt in 1..=retry.max_attempts {
        if is_cancelled() {
            return Err(TaskError::Cancelled);
        }
        if timeout.has_elapsed(started) {
            return Err(TaskError::Timeout);
        }
        match op(attempt) {
            Ok(value) => return Ok(value),
            Err(TaskError::Cancelled) => return Err(TaskError::Cancelled),
            Err(TaskError::Timeout) => return Err(TaskError::Timeout),
            Err(TaskError::RetryExhausted) if attempt == retry.max_attempts => {
                return Err(TaskError::RetryExhausted)
            }
            Err(TaskError::RetryExhausted) => {
                let _ = retry.delay_for_attempt(attempt);
            }
        }
    }
    Err(TaskError::RetryExhausted)
}

pub fn fanout_map<I, T, U, F>(inputs: I, mut worker: F) -> Vec<U>
where
    I: IntoIterator<Item = T>,
    F: FnMut(T) -> U,
{
    // deterministic fan-out/fan-in: preserve input order
    inputs.into_iter().map(&mut worker).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_succeeds_before_limit() {
        let mut seen = 0usize;
        let out = retry_with_timeout(
            RetryPolicy::default(),
            TimeoutPolicy { timeout_ms: 1000 },
            || false,
            |_| {
                seen += 1;
                if seen < 2 {
                    Err(TaskError::RetryExhausted)
                } else {
                    Ok(42)
                }
            },
        )
        .expect("must succeed");
        assert_eq!(out, 42);
        assert_eq!(seen, 2);
    }

    #[test]
    fn deterministic_fanout_preserves_order() {
        let out = fanout_map([3, 1, 2], |v| v * 2);
        assert_eq!(out, vec![6, 2, 4]);
    }
}
