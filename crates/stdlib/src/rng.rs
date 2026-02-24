use capabilities::{Capability, CapabilityToken};

use crate::capability::{require_capability, CapabilityError};

pub fn required_capability_for_rng() -> Capability {
    Capability::Random
}

pub fn next_u64_with_capability(
    runtime: &mut RngRuntime,
    token: &CapabilityToken,
) -> Result<u64, CapabilityError> {
    require_capability(token, required_capability_for_rng())?;
    Ok(runtime.next_u64())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngMode {
    Host,
    Deterministic,
}

pub trait RngBackend {
    fn next_u64(&mut self) -> u64;
}

#[derive(Debug, Clone)]
pub struct HostRng {
    state: u64,
}

impl Default for HostRng {
    fn default() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            state: nanos.max(1),
        }
    }
}

impl RngBackend for HostRng {
    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }
}

#[derive(Debug, Clone)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn seeded(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }
}

impl Default for DeterministicRng {
    fn default() -> Self {
        Self::seeded(1)
    }
}

impl RngBackend for DeterministicRng {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }
}

pub enum RngRuntime {
    Host(HostRng),
    Deterministic(DeterministicRng),
}

impl RngRuntime {
    pub fn new(mode: RngMode) -> Self {
        match mode {
            RngMode::Host => Self::Host(HostRng::default()),
            RngMode::Deterministic => Self::Deterministic(DeterministicRng::default()),
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        match self {
            Self::Host(rng) => rng.next_u64(),
            Self::Deterministic(rng) => rng.next_u64(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicRng, RngBackend};

    #[test]
    fn deterministic_rng_repeats_for_same_seed() {
        let mut left = DeterministicRng::seeded(7);
        let mut right = DeterministicRng::seeded(7);
        let l = (left.next_u64(), left.next_u64(), left.next_u64());
        let r = (right.next_u64(), right.next_u64(), right.next_u64());
        assert_eq!(l, r);
    }
}
