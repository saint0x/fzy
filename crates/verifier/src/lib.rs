use diagnostics::{Diagnostic, Severity};
use fir::FirModule;

#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyPolicy {
    pub safe_profile: bool,
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

pub fn verify(module: &FirModule) -> VerifyReport {
    verify_with_policy(module, VerifyPolicy::default())
}

pub fn verify_with_policy(module: &FirModule, policy: VerifyPolicy) -> VerifyReport {
    let mut report = VerifyReport::default();

    if module.name.trim().is_empty() {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            "module name missing",
            Some("set a module name before verification".to_string()),
        ));
    }

    if module.nodes > 0 && module.effects.len() == 0 {
        report.diagnostics.push(Diagnostic::new(
            Severity::Warning,
            "module has declarations but no explicit capabilities",
            Some("declare required capabilities with `use cap.<name>;`".to_string()),
        ));
    }

    for required in module.required_effects.iter() {
        if !module.effects.contains(required) {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("missing required capability: {}", required.as_str()),
                Some(format!(
                    "add `use cap.{};` to module scope",
                    required.as_str()
                )),
            ));
        }
    }

    for effect in &module.unknown_effects {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            format!("unknown capability: {effect}"),
            Some("allowed: time, rng, fs, net, proc, mem, thread".to_string()),
        ));
    }

    if policy.safe_profile {
        for disallowed in [
            capabilities::Capability::Time,
            capabilities::Capability::Random,
            capabilities::Capability::FileSystem,
            capabilities::Capability::Network,
            capabilities::Capability::Process,
            capabilities::Capability::Memory,
            capabilities::Capability::Thread,
        ] {
            if module.effects.contains(disallowed) || module.required_effects.contains(disallowed) {
                report.diagnostics.push(Diagnostic::new(
                    Severity::Error,
                    format!("safe profile forbids capability: {}", disallowed.as_str()),
                    Some(
                        "remove unsafe capability usage or compile with a non-safe profile"
                            .to_string(),
                    ),
                ));
            }
        }
    }

    if module.host_syscall_sites > 0 {
        if module.extern_c_abi_functions == 0 {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                "host syscall usage requires an `extern \"C\" fn` boundary",
                Some("declare syscall wrappers as `extern \"C\" fn ...;`".to_string()),
            ));
        }
        if policy.safe_profile {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                "host syscall usage is forbidden in safe profile",
                Some("move syscall code behind non-safe profile targets".to_string()),
            ));
        }
    }

    if module.unsafe_sites > 0 {
        let missing_reasons = module
            .unsafe_sites
            .saturating_sub(module.unsafe_reasoned_sites);
        report.diagnostics.push(Diagnostic::new(
            if policy.safe_profile {
                Severity::Error
            } else {
                Severity::Warning
            },
            format!(
                "detected {} explicit unsafe escape marker(s)",
                module.unsafe_sites
            ),
            Some("unsafe escapes must be isolated and are rejected in safe profile".to_string()),
        ));
        if missing_reasons > 0 {
            report.diagnostics.push(Diagnostic::new(
                if policy.safe_profile {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                format!(
                    "{} unsafe escape site(s) missing reason string (use `unsafe(\"reason\")`)",
                    missing_reasons
                ),
                Some("add explicit reason string for every unsafe escape".to_string()),
            ));
        }
    }
    if module.reference_sites > 0 && policy.safe_profile {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            format!(
                "safe profile rejects {} reference-region site(s) without region proof",
                module.reference_sites
            ),
            Some("replace borrowed references with owned values or non-safe profile".to_string()),
        ));
    }
    if module.alloc_sites > module.free_sites {
        let severity = if policy.safe_profile {
            Severity::Error
        } else {
            Severity::Warning
        };
        report.diagnostics.push(Diagnostic::new(
            severity,
            format!(
                "memory lifecycle imbalance: alloc sites={} free sites={}",
                module.alloc_sites, module.free_sites
            ),
            Some("pair allocations with explicit `free(...)` or defer-based cleanup".to_string()),
        ));
    }

    for resource in &module.linear_resources {
        let released = module
            .deferred_resources
            .iter()
            .any(|deferred| deferred == resource);
        if !released {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("linear resource `{resource}` is not released via defer"),
                Some(format!(
                    "add `defer close({resource})` or equivalent cleanup in scope"
                )),
            ));
        }
    }

    if module.matches_without_wildcard > 0 {
        report.diagnostics.push(Diagnostic::new(
            if policy.safe_profile {
                Severity::Error
            } else {
                Severity::Warning
            },
            format!(
                "{} match statement(s) are non-exhaustive in v0 baseline",
                module.matches_without_wildcard
            ),
            Some("add `_ => ...` wildcard arm for deterministic behavior".to_string()),
        ));
    }

    if let Some(return_type) = &module.entry_return_type {
        match return_type.as_str() {
            "i32" => {
                if module.entry_return_const_i32.is_none() {
                    report.diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        "main must return an i32 expression in this profile",
                        Some("add `return <i32>` in `fn main() -> i32`".to_string()),
                    ));
                }
            }
            "void" => {}
            _ => report.diagnostics.push(Diagnostic::new(
                Severity::Warning,
                format!("unverified return type in v0: {return_type}"),
                Some("supported now: `void`, `i32`".to_string()),
            )),
        }
    }

    for (index, requires) in module.entry_requires.iter().enumerate() {
        if matches!(requires, Some(false)) {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("requires[{index}] is statically false"),
                Some("change requires condition or remove impossible precondition".to_string()),
            ));
        }
    }

    for (index, ensures) in module.entry_ensures.iter().enumerate() {
        if matches!(ensures, Some(false)) {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("ensures[{index}] is statically false"),
                Some("change ensures condition or update postcondition logic".to_string()),
            ));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use capabilities::Capability;

    use super::{verify, verify_with_policy, VerifyPolicy};

    #[test]
    fn warns_when_capabilities_missing() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: Vec::new(),
            nodes: 1,
            entry_return_type: None,
            entry_return_const_i32: None,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert_eq!(report.diagnostics.len(), 1);
    }

    #[test]
    fn errors_for_unknown_capabilities() {
        let mut effects = capabilities::CapabilitySet::default();
        effects.insert(Capability::Time);
        let module = fir::FirModule {
            name: "m".to_string(),
            effects,
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec!["weird".to_string()],
            nodes: 1,
            entry_return_type: None,
            entry_return_const_i32: None,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown capability")));
    }

    #[test]
    fn errors_when_required_capability_missing() {
        let mut required = capabilities::CapabilitySet::default();
        required.insert(Capability::Network);
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: required,
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: None,
            entry_return_const_i32: None,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("missing required capability: net")));
    }

    #[test]
    fn errors_when_i32_main_has_no_return_expr() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: None,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("main must return an i32")));
    }

    #[test]
    fn errors_for_unreleased_linear_resource() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: Some(0),
            linear_resources: vec!["socket_res".to_string()],
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not released via defer")));
    }

    #[test]
    fn warns_for_non_exhaustive_match_baseline() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: Some(0),
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 1,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("non-exhaustive")));
    }

    #[test]
    fn safe_profile_rejects_unsafe_capabilities() {
        let mut effects = capabilities::CapabilitySet::default();
        effects.insert(Capability::Network);
        effects.insert(Capability::Thread);
        let module = fir::FirModule {
            name: "m".to_string(),
            effects,
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: Some(0),
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify_with_policy(&module, VerifyPolicy { safe_profile: true });
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("safe profile forbids capability: net")));
        assert!(report.diagnostics.iter().any(|d| d
            .message
            .contains("safe profile forbids capability: thread")));
    }

    #[test]
    fn safe_profile_rejects_all_runtime_backed_effects() {
        let mut effects = capabilities::CapabilitySet::default();
        for capability in [
            Capability::Time,
            Capability::Random,
            Capability::FileSystem,
            Capability::Network,
            Capability::Process,
            Capability::Memory,
            Capability::Thread,
        ] {
            effects.insert(capability);
        }
        let module = fir::FirModule {
            name: "m".to_string(),
            effects,
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: Some(0),
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify_with_policy(&module, VerifyPolicy { safe_profile: true });
        for expected in ["time", "rng", "fs", "net", "proc", "mem", "thread"] {
            assert!(report.diagnostics.iter().any(|d| d
                .message
                .contains(&format!("safe profile forbids capability: {expected}"))));
        }
    }

    #[test]
    fn contract_false_conditions_error() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: Some(0),
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: vec![Some(false)],
            entry_ensures: vec![Some(false)],
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("requires[0] is statically false")));
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("ensures[0] is statically false")));
    }

    #[test]
    fn host_syscall_requires_abi_boundary() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: Some(0),
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: vec![],
            entry_ensures: vec![],
            host_syscall_sites: 1,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 1,
            generic_instantiations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("extern \"C\" fn")));
    }

    #[test]
    fn safe_profile_rejects_alloc_free_imbalance() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: capabilities::CapabilitySet::default(),
            required_effects: capabilities::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some("i32".to_string()),
            entry_return_const_i32: Some(0),
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            entry_requires: vec![],
            entry_ensures: vec![],
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            reference_sites: 0,
            alloc_sites: 2,
            free_sites: 1,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
        };
        let report = verify_with_policy(&module, VerifyPolicy { safe_profile: true });
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("memory lifecycle imbalance")));
    }
}
