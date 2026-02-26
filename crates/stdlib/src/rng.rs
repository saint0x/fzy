use core::{Capability, CapabilityToken};
use rand::RngCore;
use rand::SeedableRng;
use rand_distr::{Distribution, Exp, Normal};
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::core::{require_capability, CapabilityError};

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
    fn uniform_u64(&mut self, low: u64, high: u64) -> u64;
    fn normal_f64(&mut self, mean: f64, std_dev: f64) -> f64;
    fn exponential_f64(&mut self, lambda: f64) -> f64;
}

#[derive(Debug, Clone)]
pub struct HostRng {
    inner: Xoshiro256PlusPlus,
}

impl Default for HostRng {
    fn default() -> Self {
        let mut seed = <Xoshiro256PlusPlus as SeedableRng>::Seed::default();
        let mut os = rand::rngs::OsRng;
        os.fill_bytes(&mut seed);
        Self {
            inner: Xoshiro256PlusPlus::from_seed(seed),
        }
    }
}

impl RngBackend for HostRng {
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn uniform_u64(&mut self, low: u64, high: u64) -> u64 {
        if low >= high {
            return low;
        }
        let span = high - low;
        low + (self.next_u64() % span)
    }

    fn normal_f64(&mut self, mean: f64, std_dev: f64) -> f64 {
        let dist = Normal::new(mean, std_dev.max(f64::EPSILON)).expect("normal params");
        dist.sample(&mut self.inner)
    }

    fn exponential_f64(&mut self, lambda: f64) -> f64 {
        let dist = Exp::new(lambda.max(f64::EPSILON)).expect("exp params");
        dist.sample(&mut self.inner)
    }
}

#[derive(Debug, Clone)]
pub struct DeterministicRng {
    inner: Xoshiro256PlusPlus,
}

impl DeterministicRng {
    pub fn seeded(seed: u64) -> Self {
        Self {
            inner: Xoshiro256PlusPlus::seed_from_u64(seed),
        }
    }
}

impl Default for DeterministicRng {
    fn default() -> Self {
        Self::seeded(1)
    }
}

impl RngBackend for DeterministicRng {
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn uniform_u64(&mut self, low: u64, high: u64) -> u64 {
        if low >= high {
            return low;
        }
        let span = high - low;
        low + (self.next_u64() % span)
    }

    fn normal_f64(&mut self, mean: f64, std_dev: f64) -> f64 {
        let dist = Normal::new(mean, std_dev.max(f64::EPSILON)).expect("normal params");
        dist.sample(&mut self.inner)
    }

    fn exponential_f64(&mut self, lambda: f64) -> f64 {
        let dist = Exp::new(lambda.max(f64::EPSILON)).expect("exp params");
        dist.sample(&mut self.inner)
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

    pub fn uniform_u64(&mut self, low: u64, high: u64) -> u64 {
        match self {
            Self::Host(rng) => rng.uniform_u64(low, high),
            Self::Deterministic(rng) => rng.uniform_u64(low, high),
        }
    }

    pub fn normal_f64(&mut self, mean: f64, std_dev: f64) -> f64 {
        match self {
            Self::Host(rng) => rng.normal_f64(mean, std_dev),
            Self::Deterministic(rng) => rng.normal_f64(mean, std_dev),
        }
    }

    pub fn exponential_f64(&mut self, lambda: f64) -> f64 {
        match self {
            Self::Host(rng) => rng.exponential_f64(lambda),
            Self::Deterministic(rng) => rng.exponential_f64(lambda),
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
        let l = (
            left.next_u64(),
            left.next_u64(),
            left.uniform_u64(10, 20),
            left.normal_f64(0.0, 1.0),
        );
        let r = (
            right.next_u64(),
            right.next_u64(),
            right.uniform_u64(10, 20),
            right.normal_f64(0.0, 1.0),
        );
        assert_eq!(l.0, r.0);
        assert_eq!(l.1, r.1);
        assert_eq!(l.2, r.2);
        assert_eq!(l.3, r.3);
    }
}
