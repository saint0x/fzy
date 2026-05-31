use diagnostics::{Diagnostic, Severity};

mod ffi;
mod unsafe_contracts;
mod verify_logic;

#[derive(Debug, Clone, Default)]
pub struct VerifyPolicy {
    pub safe_profile: bool,
    pub production_memory_safety: bool,
    pub strict_unsafe_contracts: bool,
    pub deny_unsafe_in: Vec<String>,
    pub allow_unsafe_in: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl VerifyReport {
    pub fn is_clean(&self) -> bool {
        self.diagnostics
            .iter()
            .all(|d| !matches!(d.severity, Severity::Error))
    }
}

pub use verify_logic::{verify, verify_with_policy};

#[cfg(test)]
mod tests;
