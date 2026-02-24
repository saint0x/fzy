use capabilities::{Capability, CapabilitySet};

#[derive(Debug, Clone)]
pub struct ServerHardeningDefaults {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_connections: usize,
    pub request_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub parse_timeout_ms: u64,
}

impl Default for ServerHardeningDefaults {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_body_bytes: 1 * 1024 * 1024,
            max_connections: 1024,
            request_timeout_ms: 5_000,
            idle_timeout_ms: 15_000,
            parse_timeout_ms: 1_000,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: value.as_ref().to_vec(),
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn redacted(&self) -> &'static str {
        "[redacted]"
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("value", &"[redacted]")
            .finish()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegedOperation {
    NetworkBind,
    FileWrite,
    ProcessSpawn,
}

impl PrivilegedOperation {
    pub fn required_capability(&self) -> Capability {
        match self {
            Self::NetworkBind => Capability::Network,
            Self::FileWrite => Capability::FileSystem,
            Self::ProcessSpawn => Capability::Process,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAudit {
    pub operation: PrivilegedOperation,
    pub allowed: bool,
    pub reason: String,
}

pub fn audit_privileged_operation(
    caps: &CapabilitySet,
    operation: PrivilegedOperation,
    reason: impl Into<String>,
) -> CapabilityAudit {
    let required = operation.required_capability();
    CapabilityAudit {
        operation,
        allowed: caps.contains(required),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use capabilities::{Capability, CapabilitySet};

    use super::{audit_privileged_operation, PrivilegedOperation, Secret};

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new("token");
        let printed = format!("{:?}", secret);
        assert!(printed.contains("[redacted]"));
        assert!(!printed.contains("token"));
    }

    #[test]
    fn capability_audit_enforces_gate() {
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::Network);
        let network =
            audit_privileged_operation(&caps, PrivilegedOperation::NetworkBind, "server bootstrap");
        let process =
            audit_privileged_operation(&caps, PrivilegedOperation::ProcessSpawn, "worker shell");

        assert!(network.allowed);
        assert!(!process.allowed);
    }
}
