use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProfile {
    Dev,
    Verify,
    Release,
}

#[derive(Debug, Clone)]
pub struct ProfileConfig {
    pub worker_count: usize,
    pub deterministic_replay: bool,
    pub strict_verify: bool,
}

impl RuntimeProfile {
    pub fn config(self) -> ProfileConfig {
        match self {
            Self::Dev => ProfileConfig {
                worker_count: 2,
                deterministic_replay: false,
                strict_verify: false,
            },
            Self::Verify => ProfileConfig {
                worker_count: 2,
                deterministic_replay: true,
                strict_verify: true,
            },
            Self::Release => ProfileConfig {
                worker_count: 8,
                deterministic_replay: true,
                strict_verify: false,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Ready,
    NotReady,
    Unhealthy,
}

#[derive(Debug, Clone)]
pub struct ServiceManifest {
    pub service_name: String,
    pub ports: Vec<u16>,
    pub resource_limits: BTreeMap<String, u64>,
    pub worker_count: usize,
    pub graceful_stop_budget_ms: u64,
}

impl ServiceManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.service_name.trim().is_empty() {
            return Err("service name must not be empty".to_string());
        }
        if self.ports.is_empty() {
            return Err("at least one port is required".to_string());
        }
        if self.worker_count == 0 {
            return Err("worker_count must be > 0".to_string());
        }
        if self.graceful_stop_budget_ms < 100 {
            return Err("graceful stop budget too low".to_string());
        }
        Ok(())
    }

    pub fn health_probe_contract() -> &'static str {
        "/healthz returns liveness; /readyz returns readiness with dependency checks"
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{RuntimeProfile, ServiceManifest};

    #[test]
    fn runtime_profiles_have_defined_behavior() {
        let verify = RuntimeProfile::Verify.config();
        let release = RuntimeProfile::Release.config();
        assert!(verify.deterministic_replay);
        assert!(verify.strict_verify);
        assert!(release.deterministic_replay);
        assert!(!release.strict_verify);
    }

    #[test]
    fn manifest_validation_catches_bad_config() {
        let manifest = ServiceManifest {
            service_name: "".to_string(),
            ports: vec![],
            resource_limits: BTreeMap::new(),
            worker_count: 0,
            graceful_stop_budget_ms: 10,
        };
        assert!(manifest.validate().is_err());
    }
}
