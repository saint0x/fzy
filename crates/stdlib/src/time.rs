use core::{Capability, CapabilityToken};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::core::{require_capability, CapabilityError};

pub fn required_capability_for_time() -> Capability {
    Capability::Time
}

pub fn now_millis_with_capability(
    clock: &dyn Clock,
    token: &CapabilityToken,
) -> Result<u64, CapabilityError> {
    require_capability(token, required_capability_for_time())?;
    Ok(clock.now_millis())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockMode {
    Host,
    Virtual,
}

pub trait Clock {
    fn now_millis(&self) -> u64;
    fn sleep_millis(&mut self, duration_ms: u64);
}

#[derive(Default)]
pub struct HostClock;

impl Clock for HostClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_millis(0))
            .as_millis() as u64
    }

    fn sleep_millis(&mut self, duration_ms: u64) {
        if duration_ms == 0 {
            std::thread::yield_now();
            return;
        }
        let mut remaining = duration_ms;
        while remaining > 0 {
            std::thread::sleep(Duration::from_millis(1));
            std::thread::yield_now();
            remaining -= 1;
        }
    }
}

#[derive(Debug, Clone)]
pub struct VirtualClock {
    now_ms: u64,
}

impl VirtualClock {
    pub fn from_millis(start_ms: u64) -> Self {
        Self { now_ms: start_ms }
    }

    pub fn advance(&mut self, delta_ms: u64) {
        self.now_ms += delta_ms;
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::from_millis(0)
    }
}

impl Clock for VirtualClock {
    fn now_millis(&self) -> u64 {
        self.now_ms
    }

    fn sleep_millis(&mut self, duration_ms: u64) {
        self.advance(duration_ms);
    }
}

pub enum ClockRuntime {
    Host(HostClock),
    Virtual(VirtualClock),
}

impl ClockRuntime {
    pub fn new(mode: ClockMode) -> Self {
        match mode {
            ClockMode::Host => Self::Host(HostClock),
            ClockMode::Virtual => Self::Virtual(VirtualClock::default()),
        }
    }
}

impl Clock for ClockRuntime {
    fn now_millis(&self) -> u64 {
        match self {
            Self::Host(clock) => clock.now_millis(),
            Self::Virtual(clock) => clock.now_millis(),
        }
    }

    fn sleep_millis(&mut self, duration_ms: u64) {
        match self {
            Self::Host(clock) => clock.sleep_millis(duration_ms),
            Self::Virtual(clock) => clock.sleep_millis(duration_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, VirtualClock};

    #[test]
    fn virtual_clock_is_deterministic() {
        let mut clock = VirtualClock::from_millis(10);
        assert_eq!(clock.now_millis(), 10);
        clock.sleep_millis(5);
        assert_eq!(clock.now_millis(), 15);
        clock.advance(10);
        assert_eq!(clock.now_millis(), 25);
    }
}
