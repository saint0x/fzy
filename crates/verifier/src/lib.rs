use diagnostics::{assign_stable_codes, Diagnostic, DiagnosticDomain, Severity};
use fir::FirModule;

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

pub fn verify(module: &FirModule) -> VerifyReport {
    verify_with_policy(module, VerifyPolicy::default())
}

pub fn verify_with_policy(module: &FirModule, policy: VerifyPolicy) -> VerifyReport {
    let mut report = VerifyReport::default();
    let memory_safety_enforced = policy.safe_profile || policy.production_memory_safety;

    if module.name.trim().is_empty() {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            "module name missing",
            Some("set a module name before verification".to_string()),
        ));
    }

    if module.nodes > 0 && module.effects.is_empty() {
        report.diagnostics.push(Diagnostic::new(
            Severity::Warning,
            "module has declarations but no explicit capabilities",
            Some("declare required capabilities with `use core.<name>;`".to_string()),
        ));
    }

    for required in module.required_effects.iter() {
        if !module.effects.contains(required) {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("missing required capability: {}", required.as_str()),
                Some(format!(
                    "add `use core.{};` to module scope",
                    required.as_str()
                )),
            ));
        }
    }
    for function in &module.function_capability_requirements {
        for required in &function.required {
            if let Some(parsed) = core::Capability::parse(required) {
                if !module.effects.contains(parsed) {
                    report.diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        format!(
                            "function `{}` is missing required capability: {}",
                            function.function, required
                        ),
                        Some(format!(
                            "declare `use core.{}` or propagate a capability token to `{}`",
                            required, function.function
                        )),
                    ));
                }
            }
        }
    }

    for effect in &module.unknown_effects {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            format!("unknown capability: {effect}"),
            Some("allowed: time, rng, fs, http, proc, mem, thread".to_string()),
        ));
    }

    if policy.safe_profile {
        for disallowed in [
            core::Capability::Time,
            core::Capability::Random,
            core::Capability::FileSystem,
            core::Capability::Http,
            core::Capability::Process,
            core::Capability::Memory,
            core::Capability::Thread,
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
                "host syscall usage requires an `ext c fn` boundary",
                Some("declare syscall wrappers as `ext c fn ...;`".to_string()),
            ));
        }
        if memory_safety_enforced {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                "host syscall usage is forbidden under production memory safety",
                Some("move syscall code behind audited FFI boundaries".to_string()),
            ));
        }
    }

    for function in &module.typed_functions {
        if function.is_extern
            && function.abi.as_deref() == Some("c")
            && !function.is_unsafe
            && (function.return_type.is_pointer_like()
                || function.params.iter().any(|param| {
                    param.ty.is_pointer_like()
                        && (param.name.ends_with("_owned")
                            || param.name.ends_with("_out")
                            || param.name.ends_with("_inout"))
                }))
        {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!(
                    "extern C import `{}` exposes pointer-like contract and must be declared `ext unsafe c fn`",
                    function.name
                ),
                Some(
                    "mark this import as `ext unsafe c fn` or change signature to a safe non-pointer contract"
                        .to_string(),
                ),
            ));
        }
    }

    if !module.unsafe_contract_sites.is_empty() {
        let module_name = module.name.as_str();
        if !policy.allow_unsafe_in.is_empty()
            && !policy
                .allow_unsafe_in
                .iter()
                .any(|scope| unsafe_scope_matches(module_name, scope))
        {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!(
                    "unsafe usage in module `{module_name}` is not in allowlisted unsafe scope"
                ),
                Some(
                    "add module to `[unsafe].allow_unsafe_in` or remove unsafe sites from this module"
                        .to_string(),
                ),
            ));
        }
        if policy
            .deny_unsafe_in
            .iter()
            .any(|scope| unsafe_scope_matches(module_name, scope))
        {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("unsafe usage is denied in module `{module_name}` by policy"),
                Some(
                    "remove unsafe sites from this module or adjust `[unsafe].deny_unsafe_in`"
                        .to_string(),
                ),
            ));
        }
        let unsafe_sites = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.kind != "unsafe_violation_callsite")
            .count();
        let missing_reasons = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.kind != "unsafe_violation_callsite")
            .filter(|site| {
                site.reason.as_deref().is_none_or(str::is_empty)
                    || site.invariant.as_deref().is_none_or(str::is_empty)
                    || site.owner.as_deref().is_none_or(str::is_empty)
                    || site.owner_id.as_deref().is_none_or(str::is_empty)
                    || site.scope.as_deref().is_none_or(str::is_empty)
                    || site.risk_class.as_deref().is_none_or(str::is_empty)
                    || site.proof_ref.as_deref().is_none_or(str::is_empty)
            })
            .count();
        let unsafe_context_violations = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.kind == "unsafe_violation_callsite")
            .count();
        let async_unsafe_sites = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.async_context && site.kind != "unsafe_violation_callsite")
            .count();
        report.diagnostics.push(Diagnostic::new(
            if policy.safe_profile {
                Severity::Error
            } else {
                Severity::Warning
            },
            format!("detected {} explicit unsafe escape marker(s)", unsafe_sites),
            Some(if policy.safe_profile {
                "unsafe escapes are forbidden in safe profile".to_string()
            } else {
                "unsafe escapes must be isolated and audited with compiler-generated contracts"
                    .to_string()
            }),
        ));
        if missing_reasons > 0 {
            report.diagnostics.push(Diagnostic::new(
                if policy.safe_profile || policy.strict_unsafe_contracts {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                format!(
                    "{} unsafe escape site(s) missing required contract fields",
                    missing_reasons
                ),
                Some(
                    if policy.safe_profile {
                        "safe profile rejects unsafe escapes regardless of metadata completeness"
                            .to_string()
                    } else if policy.strict_unsafe_contracts {
                        "strict unsafe contracts are enabled; all unsafe sites require complete generated contracts"
                            .to_string()
                    } else {
                        "compiler-generated contracts are recommended by default and enforced in strict unsafe-audit mode"
                            .to_string()
                    },
                ),
            ));
        }
        if unsafe_context_violations > 0 {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!(
                    "{} unsafe callsite violation(s) detected outside unsafe context",
                    unsafe_context_violations
                ),
                Some(
                    "wrap callsites in `unsafe { ... }` or move logic into an `unsafe fn`"
                        .to_string(),
                ),
            ));
        }
        if async_unsafe_sites > 0 {
            report.diagnostics.push(Diagnostic::new(
                if policy.strict_unsafe_contracts || policy.safe_profile {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                format!(
                    "{} unsafe site(s) execute in async context",
                    async_unsafe_sites
                ),
                Some(
                    "async + unsafe requires explicit invariants and deterministic evidence links"
                        .to_string(),
                ),
            ));
        }
        let malformed_invariants = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.kind != "unsafe_violation_callsite")
            .filter(|site| {
                !unsafe_invariant_matches_owner(
                    site.invariant.as_deref().unwrap_or_default(),
                    site.owner.as_deref().unwrap_or_default(),
                )
            })
            .count();
        if malformed_invariants > 0 {
            report.diagnostics.push(Diagnostic::new(
                if policy.strict_unsafe_contracts || policy.safe_profile {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                format!(
                    "{} unsafe site(s) have malformed invariant metadata",
                    malformed_invariants
                ),
                Some(
                    "expected semantic invariant form `owner_live(<owner>)` matching the resolved owner"
                        .to_string(),
                ),
            ));
        }
    }
    if module.reference_sites > 0
        && memory_safety_enforced
        && module.reference_lifetime_violations.is_empty()
    {
        report.diagnostics.push(Diagnostic::new(
            Severity::Warning,
            format!(
                "safe profile observed {} reference-region site(s) with explicit lifetime proofs",
                module.reference_sites
            ),
            Some("continue preferring owned values when possible in safe profile".to_string()),
        ));
    }
    if module.alloc_sites > module.free_sites {
        let severity = if memory_safety_enforced {
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
    for violation in &module.ownership_violations {
        report.diagnostics.push(Diagnostic::new(
            if memory_safety_enforced {
                Severity::Error
            } else {
                Severity::Warning
            },
            violation.clone(),
            Some(
                "enforce ownership transfer semantics and ensure every allocation is released"
                    .to_string(),
            ),
        ));
    }
    for violation in &module.unsafe_context_violations {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            violation.clone(),
            Some("wrap the operation in `unsafe { ... }` or move it into `unsafe fn`".to_string()),
        ));
    }
    for violation in &module.capability_token_violations {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            violation.clone(),
            Some(
                "add capability token parameters and propagate delegated tokens explicitly"
                    .to_string(),
            ),
        ));
    }
    for violation in &module.trait_violations {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            violation.clone(),
            Some("implement required trait methods and satisfy generic trait bounds".to_string()),
        ));
    }
    for violation in &module.reference_lifetime_violations {
        report.diagnostics.push(Diagnostic::new(
            if memory_safety_enforced {
                Severity::Error
            } else {
                Severity::Warning
            },
            violation.clone(),
            Some("introduce explicit lifetime/region-safe ownership handoff".to_string()),
        ));
    }
    for violation in &module.linear_type_violations {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            violation.clone(),
            Some("linear resources must be consumed exactly once".to_string()),
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
    if module.match_unreachable_arms > 0 {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            format!(
                "{} match arm(s) are unreachable due to earlier catch-all arms",
                module.match_unreachable_arms
            ),
            Some("remove unreachable arms or place catch-all arm last".to_string()),
        ));
    }
    if module.match_duplicate_catchall_arms > 0 {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            format!(
                "{} duplicate catch-all match arm(s) detected",
                module.match_duplicate_catchall_arms
            ),
            Some("keep exactly one unguarded catch-all arm (`_` or binding pattern)".to_string()),
        ));
    }

    if module.type_errors > 0 {
        for (index, detail) in module.type_error_details.iter().enumerate() {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    detail.clone(),
                    Some("type-check detail".to_string()),
                )
                .with_note(format!("detail_index={index}")),
            );
        }
    }

    if let Some(return_type) = &module.entry_return_type {
        if !matches!(return_type, ast::Type::Void) && !module.entry_has_return_expr {
            report.diagnostics.push(Diagnostic::new(
                Severity::Error,
                format!("main must return a `{return_type}` expression in this profile"),
                Some(format!(
                    "add `return <{return_type}>` in `fn main() -> {return_type}`"
                )),
            ));
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

    assign_stable_codes(&mut report.diagnostics, DiagnosticDomain::Verifier);

    report
}

fn unsafe_scope_matches(module_name: &str, pattern: &str) -> bool {
    let module_name = module_name.trim();
    let pattern = pattern.trim();
    if module_name.is_empty() || pattern.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("::*") {
        return module_name == prefix || module_name.starts_with(&format!("{prefix}::"));
    }
    module_name == pattern
}

fn unsafe_invariant_matches_owner(invariant: &str, owner: &str) -> bool {
    let invariant = invariant.trim();
    let owner = owner.trim();
    if invariant.is_empty() || owner.is_empty() {
        return false;
    }
    invariant == format!("owner_live({owner})")
}

#[cfg(test)]
mod tests {
    use core::Capability;

    use super::{verify, verify_with_policy, VerifyPolicy};

    fn unsafe_site_complete() -> fir::UnsafeContractSite {
        fir::UnsafeContractSite {
            site_id: "usite_test".to_string(),
            kind: "unsafe_block".to_string(),
            function: "main".to_string(),
            snippet: "main: unsafe { ... }".to_string(),
            reason: Some("compiler-generated".to_string()),
            invariant: Some("owner_live(scope_root)".to_string()),
            owner: Some("scope_root".to_string()),
            owner_id: Some("owner::main::scope_root".to_string()),
            scope: Some("main::unsafe_block".to_string()),
            risk_class: Some("memory".to_string()),
            proof_ref: Some("gate://compiler-generated/main/usite_test".to_string()),
            async_context: false,
        }
    }

    fn unsafe_site_missing() -> fir::UnsafeContractSite {
        fir::UnsafeContractSite {
            site_id: "usite_missing".to_string(),
            kind: "unsafe_block".to_string(),
            function: "main".to_string(),
            snippet: "main: unsafe { ... }".to_string(),
            reason: None,
            invariant: None,
            owner: None,
            owner_id: None,
            scope: None,
            risk_class: None,
            proof_ref: None,
            async_context: false,
        }
    }

    #[test]
    fn warns_when_capabilities_missing() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: Vec::new(),
            nodes: 1,
            entry_return_type: None,
            entry_return_const_i32: None,
            entry_has_return_expr: false,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert_eq!(report.diagnostics.len(), 1);
    }

    #[test]
    fn errors_for_unknown_capabilities() {
        let mut effects = core::CapabilitySet::default();
        effects.insert(Capability::Time);
        let module = fir::FirModule {
            name: "m".to_string(),
            effects,
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec!["weird".to_string()],
            nodes: 1,
            entry_return_type: None,
            entry_return_const_i32: None,
            entry_has_return_expr: false,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown capability")));
    }

    #[test]
    fn errors_when_required_capability_missing() {
        let mut required = core::CapabilitySet::default();
        required.insert(Capability::Http);
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: required,
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: None,
            entry_return_const_i32: None,
            entry_has_return_expr: false,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("missing required capability: http")));
    }

    #[test]
    fn errors_when_i32_main_has_no_return_expr() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: None,
            entry_has_return_expr: false,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("main must return a `i32`")));
    }

    #[test]
    fn errors_for_unreleased_linear_resource() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: vec!["socket_res".to_string()],
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
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
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 1,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("non-exhaustive")));
    }

    #[test]
    fn errors_for_unreachable_and_duplicate_match_catchalls() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 2,
            match_duplicate_catchall_arms: 1,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unreachable")));
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("duplicate catch-all")));
    }

    #[test]
    fn safe_profile_rejects_unsafe_capabilities() {
        let mut effects = core::CapabilitySet::default();
        effects.insert(Capability::Http);
        effects.insert(Capability::Thread);
        let module = fir::FirModule {
            name: "m".to_string(),
            effects,
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                safe_profile: true,
                ..VerifyPolicy::default()
            },
        );
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("safe profile forbids capability: http")));
        assert!(report.diagnostics.iter().any(|d| d
            .message
            .contains("safe profile forbids capability: thread")));
    }

    #[test]
    fn safe_profile_rejects_all_runtime_backed_effects() {
        let mut effects = core::CapabilitySet::default();
        for capability in [
            Capability::Time,
            Capability::Random,
            Capability::FileSystem,
            Capability::Http,
            Capability::Process,
            Capability::Memory,
            Capability::Thread,
        ] {
            effects.insert(capability);
        }
        let module = fir::FirModule {
            name: "m".to_string(),
            effects,
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                safe_profile: true,
                ..VerifyPolicy::default()
            },
        );
        for expected in ["time", "rng", "fs", "http", "proc", "mem", "thread"] {
            assert!(report.diagnostics.iter().any(|d| d
                .message
                .contains(&format!("safe profile forbids capability: {expected}"))));
        }
    }

    #[test]
    fn contract_false_conditions_error() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: vec![Some(false)],
            entry_ensures: vec![Some(false)],
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
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
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: vec![],
            entry_ensures: vec![],
            host_syscall_sites: 1,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 1,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("ext c fn")));
    }

    #[test]
    fn safe_profile_rejects_alloc_free_imbalance() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: vec![],
            entry_ensures: vec![],
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 2,
            free_sites: 1,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                safe_profile: true,
                ..VerifyPolicy::default()
            },
        );
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("memory lifecycle imbalance")));
    }

    #[test]
    fn production_memory_safety_rejects_alloc_free_imbalance_without_safe_profile() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: vec![],
            entry_ensures: vec![],
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 2,
            free_sites: 1,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                production_memory_safety: true,
                ..VerifyPolicy::default()
            },
        );
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("memory lifecycle imbalance")));
    }

    #[test]
    fn production_memory_safety_does_not_forbid_runtime_capability_set() {
        let mut effects = core::CapabilitySet::default();
        effects.insert(Capability::Http);
        let module = fir::FirModule {
            name: "m".to_string(),
            effects,
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: vec![],
            entry_ensures: vec![],
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: Vec::new(),
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                production_memory_safety: true,
                ..VerifyPolicy::default()
            },
        );
        assert!(!report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("safe profile forbids capability")));
    }

    #[test]
    fn production_mode_allows_unsafe_sites_with_warnings() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 1,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: vec![unsafe_site_complete()],
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                production_memory_safety: true,
                ..VerifyPolicy::default()
            },
        );
        assert!(report.diagnostics.iter().any(|d| d
            .message
            .contains("detected 1 explicit unsafe escape marker(s)")));
        assert!(report.is_clean());
    }

    #[test]
    fn safe_profile_rejects_unsafe_sites() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 1,
            unsafe_reasoned_sites: 1,
            unsafe_contract_sites: vec![unsafe_site_complete()],
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                safe_profile: true,
                ..VerifyPolicy::default()
            },
        );
        assert!(!report.is_clean());
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unsafe escape marker")));
    }

    #[test]
    fn strict_unsafe_contracts_reject_missing_metadata() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 1,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: vec![unsafe_site_missing()],
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                strict_unsafe_contracts: true,
                ..VerifyPolicy::default()
            },
        );
        assert!(!report.is_clean());
        assert!(report.diagnostics.iter().any(|d| {
            matches!(d.severity, diagnostics::Severity::Error)
                && d.message
                    .contains("unsafe escape site(s) missing required contract fields")
        }));
    }

    #[test]
    fn deny_unsafe_scope_rejects_module() {
        let module = fir::FirModule {
            name: "tests::smoke".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 1,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: vec![unsafe_site_complete()],
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                deny_unsafe_in: vec!["tests::*".to_string()],
                ..VerifyPolicy::default()
            },
        );
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unsafe usage is denied in module")));
    }

    #[test]
    fn allowlist_unsafe_scope_rejects_non_allowlisted_module() {
        let module = fir::FirModule {
            name: "tests::smoke".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec![],
            nodes: 1,
            entry_return_type: Some(ast::Type::Int {
                signed: true,
                bits: 32,
            }),
            entry_return_const_i32: Some(0),
            entry_has_return_expr: true,
            linear_resources: Vec::new(),
            deferred_resources: Vec::new(),
            matches_without_wildcard: 0,
            match_unreachable_arms: 0,
            match_duplicate_catchall_arms: 0,
            entry_requires: Vec::new(),
            entry_ensures: Vec::new(),
            host_syscall_sites: 0,
            unsafe_sites: 1,
            unsafe_reasoned_sites: 0,
            unsafe_contract_sites: vec![unsafe_site_complete()],
            reference_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            extern_c_abi_functions: 0,
            repr_c_layout_items: 0,
            generic_instantiations: Vec::new(),
            generic_specializations: Vec::new(),
            call_graph: Vec::new(),
            functions: Vec::new(),
            typed_functions: Vec::new(),
            typed_globals: Vec::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify_with_policy(
            &module,
            VerifyPolicy {
                allow_unsafe_in: vec!["runtime::*".to_string()],
                ..VerifyPolicy::default()
            },
        );
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not in allowlisted unsafe scope")));
    }
}
