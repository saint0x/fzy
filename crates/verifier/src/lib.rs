use diagnostics::{assign_stable_codes, Diagnostic, DiagnosticDomain, Severity};
use fir::{count_module_owned_return_transfers, FirModule, TypedFunction};
use std::collections::{BTreeMap, BTreeSet};

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

    if module.nodes > 0
        && module.effects.is_empty()
        && module.unknown_effects.is_empty()
        && module_needs_explicit_capabilities(module)
    {
        report.diagnostics.push(
            Diagnostic::new(
                Severity::Warning,
                "module has declarations but no explicit capabilities",
                Some("declare required capabilities with `use core.<name>;`".to_string()),
            )
            .with_catalog_key("verifier.missing_explicit_capabilities"),
        );
    }

    for required in module.required_effects.iter() {
        if !module.effects.contains(required) {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!("missing required capability: {}", required.as_str()),
                    Some(format!(
                        "add `use core.{};` to module scope",
                        required.as_str()
                    )),
                )
                .with_catalog_key("verifier.missing_required_capability"),
            );
        }
    }
    for function in &module.function_capability_requirements {
        for required in &function.required {
            if let Some(parsed) = core::Capability::parse(required) {
                if !module.effects.contains(parsed) {
                    report.diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            format!(
                                "function `{}` is missing required capability: {}",
                                function.function, required
                            ),
                            Some(format!(
                                "declare `use core.{}` or propagate a capability token to `{}`",
                                required, function.function
                            )),
                        )
                        .with_catalog_key("verifier.function_missing_required_capability"),
                    );
                }
            }
        }
    }

    for effect in &module.unknown_effects {
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            format!("unknown capability: {effect}"),
            Some(
                "allowed: time, rng, fs, storage, http, proc, mem, thread, log, error".to_string(),
            ),
        ));
    }

    if policy.safe_profile {
        for disallowed in [
            core::Capability::Time,
            core::Capability::Random,
            core::Capability::FileSystem,
            core::Capability::Storage,
            core::Capability::Http,
            core::Capability::Process,
            core::Capability::Memory,
            core::Capability::Thread,
            core::Capability::Log,
            core::Capability::Error,
        ] {
            if module.effects.contains(disallowed) || module.required_effects.contains(disallowed) {
                report.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("safe profile forbids capability: {}", disallowed.as_str()),
                        Some(
                            "remove unsafe capability usage or compile with a non-safe profile"
                                .to_string(),
                        ),
                    )
                    .with_catalog_key("verifier.safe_profile_forbidden_capability"),
                );
            }
        }
    }

    if module.host_syscall_sites > 0 {
        if module.extern_c_abi_functions == 0 {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "host syscall usage requires an `ext c fn` boundary",
                    Some("declare syscall wrappers as `ext c fn ...;`".to_string()),
                )
                .with_catalog_key("verifier.host_syscall_requires_abi_boundary"),
            );
        }
        if memory_safety_enforced {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "host syscall usage is forbidden under production memory safety",
                    Some("move syscall code behind audited FFI boundaries".to_string()),
                )
                .with_catalog_key("verifier.host_syscall_forbidden_under_production_memory_safety"),
            );
        }
    }

    for function in &module.typed_functions {
        if extern_c_import_requires_unsafe(function) {
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
            ).with_catalog_key("verifier.extern_c_pointer_requires_unsafe"));
        }
        if let Some(param_name) = extern_c_import_pointer_param_missing_contract(function) {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!(
                        "extern C import `{}` pointer parameter `{}` must declare ownership suffix and paired length/context contract",
                        function.name, param_name
                    ),
                    Some(
                        "use `_owned`, `_borrowed`, `_out`, or `_inout`, and pair raw pointers with `*_len`/`len` or an adjacent `*_ctx` anchor".to_string(),
                    ),
                )
                .with_catalog_key("verifier.extern_c_pointer_requires_contract"),
            );
        }
        if let Some(callback_param) = callback_param_missing_adjacent_context_anchor(function) {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!(
                        "extern C import `{}` callback parameter `{}` requires an adjacent `*_ctx` or `*_context` anchor",
                        function.name, callback_param
                    ),
                    Some(
                        "add a neighboring context parameter such as `cb_ctx` or `cb_context` to make the callback lifetime contract explicit"
                            .to_string(),
                    ),
                )
                .with_catalog_key("verifier.extern_c_callback_requires_context_anchor"),
            );
        }
        let repr_c_names = collect_repr_c_names(module);
        if let Some(detail) = extern_c_import_unstable_ffi_type(function, &repr_c_names) {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    detail,
                    Some(
                        "use only FFI-stable scalars, raw pointers, function pointers, or #[repr(C)] named types in extern C imports".to_string(),
                    ),
                )
                .with_catalog_key("verifier.extern_c_unstable_type"),
            );
        }
        if is_extern_c_import(function) && function.is_async {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!(
                        "extern C import `{}` cannot be async; async-handle ABI is export-only in native ship v0",
                        function.name
                    ),
                    Some(
                        "model this boundary as sync import or wrap it in an explicit exported async-handle facade".to_string(),
                    ),
                )
                .with_catalog_key("verifier.extern_c_import_async_unsupported"),
            );
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
        let malformed_owner_ids = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.kind != "unsafe_violation_callsite")
            .filter(|site| {
                !unsafe_owner_id_matches_owner(
                    site.function.as_str(),
                    site.owner.as_deref().unwrap_or_default(),
                    site.owner_id.as_deref().unwrap_or_default(),
                )
            })
            .count();
        let malformed_proof_refs = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.kind != "unsafe_violation_callsite")
            .filter(|site| !unsafe_proof_ref_valid(site.proof_ref.as_deref().unwrap_or_default()))
            .count();
        let placeholder_generated_sites = module
            .unsafe_contract_sites
            .iter()
            .filter(|site| site.kind != "unsafe_violation_callsite")
            .filter(|site| unsafe_contract_is_placeholder_generated(site))
            .count();
        let unsafe_attention_sites = missing_reasons
            + unsafe_context_violations
            + async_unsafe_sites
            + malformed_invariants
            + malformed_owner_ids
            + malformed_proof_refs;
        report.diagnostics.push(Diagnostic::new(
            if policy.safe_profile {
                Severity::Error
            } else {
                Severity::Warning
            },
            if !policy.safe_profile && unsafe_attention_sites == 0 && placeholder_generated_sites == 0
            {
                format!(
                    "detected {} explicit unsafe escape marker(s); compiler contract checks passed",
                    unsafe_sites
                )
            } else if !policy.safe_profile && unsafe_attention_sites == 0 {
                format!(
                    "detected {} explicit unsafe escape marker(s); compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites; independently reasoned evidence is still required for {} compiler-generated site(s)",
                    unsafe_sites, placeholder_generated_sites
                )
            } else if !policy.safe_profile {
                format!(
                    "detected {} explicit unsafe escape marker(s); {} unsafe check(s) require attention",
                    unsafe_sites, unsafe_attention_sites
                )
            } else {
                format!("detected {} explicit unsafe escape marker(s)", unsafe_sites)
            },
            Some(if policy.safe_profile {
                "unsafe escapes are forbidden in safe profile".to_string()
            } else if unsafe_attention_sites == 0 && placeholder_generated_sites == 0 {
                "warning is informational: unsafe exists and remains review-worthy, but the current compiler checks did not detect contract-policy defects".to_string()
            } else if unsafe_attention_sites == 0 {
                "warning is informational: the compiler is satisfied with the current unsafe-policy checks, but compiler-generated unsafe contracts still count only as structural audit records, not independently validated safety or correctness evidence".to_string()
            } else {
                "unsafe escapes exist and at least one contract or policy check still needs attention; review the accompanying unsafe diagnostics".to_string()
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
        if malformed_owner_ids > 0 {
            report.diagnostics.push(Diagnostic::new(
                if policy.strict_unsafe_contracts || policy.safe_profile {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                format!(
                    "{} unsafe site(s) have malformed owner identity metadata",
                    malformed_owner_ids
                ),
                Some(
                    "expected owner identity form `owner::<function>::<owner>` matching the resolved owner"
                        .to_string(),
                ),
            ));
        }
        if malformed_proof_refs > 0 {
            report.diagnostics.push(Diagnostic::new(
                if policy.strict_unsafe_contracts || policy.safe_profile {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                format!(
                    "{} unsafe site(s) have malformed proof references",
                    malformed_proof_refs
                ),
                Some(
                    "expected proof_ref to use gate://, trace://, run://, test://, or ci:// with non-empty location data"
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
                "safe profile observed {} reference-region site(s) with no lifetime violations detected by current compiler analysis",
                module.reference_sites
            ),
            Some("continue preferring owned values when possible and add regression coverage for borrowed control-flow paths".to_string()),
        ));
    }
    let returned_owned_sites = count_module_owned_return_transfers(&module.typed_functions);
    if module.alloc_sites > module.free_sites + returned_owned_sites {
        let severity = if memory_safety_enforced {
            Severity::Error
        } else {
            Severity::Warning
        };
        report.diagnostics.push(Diagnostic::new(
            severity,
            format!(
                "memory lifecycle imbalance: alloc sites={} free sites={} returned-owned sites={}",
                module.alloc_sites, module.free_sites, returned_owned_sites
            ),
            Some(
                "pair allocations with explicit `free(...)` or defer-based cleanup, or return the owned value explicitly on every allocating path"
                    .to_string(),
            ),
        ));
    }
    for violation in &module.ownership_violations {
        let help = if violation.contains("can hold mutable borrows across await boundary") {
            "move the `await` before borrowing, or switch the async call edge to owned/Send-safe data".to_string()
        } else if violation
            .contains("can propagate borrowed references across async suspension boundary")
        {
            "resolve borrowed data before the suspension point or return an owned value instead"
                .to_string()
        } else if violation.contains("generic/trait-heavy with borrowed parameters across await") {
            "specialize the borrowed call edge away from the async suspension path, or hand off owned values instead".to_string()
        } else if violation.contains("accesses owner `")
            && violation.contains("while mutable borrowed reference `")
        {
            "use the mutable-borrowed alias directly, or move the owner access after the borrow's last use".to_string()
        } else {
            "enforce ownership transfer semantics and ensure every allocation is released"
                .to_string()
        };
        report.diagnostics.push(Diagnostic::new(
            if memory_safety_enforced {
                Severity::Error
            } else {
                Severity::Warning
            },
            violation.clone(),
            Some(help),
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
    for violation in &module.thread_boundary_violations {
        let help = if violation
            .contains("returns borrowed reference across thread-capable boundary")
        {
            "return owned values or a Send/Sync-safe handle across thread boundaries".to_string()
        } else if violation.contains("captures shared borrowed reference `")
            || violation.contains("captures mutable borrowed reference `")
        {
            "move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type".to_string()
        } else if violation.contains("requires Send/Sync-safe wrapper before thread crossing") {
            "wrap borrowed references/pointers in a Send/Sync-safe owned boundary type before crossing threads"
                .to_string()
        } else {
            "change the borrowed thread boundary to an owned or Send/Sync-safe handoff".to_string()
        };
        report.diagnostics.push(Diagnostic::new(
            Severity::Error,
            violation.clone(),
            Some(help),
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
        fn apply_type_fix_hints(mut diag: Diagnostic, detail: &str) -> Diagnostic {
            if detail.contains("unresolved call target `json.object") && detail.contains("autofix")
            {
                diag = diag.with_fix(
                    "replace fixed-arity call with `json.object(#{\"k\": json.str(\"v\")})`",
                );
            } else if detail.contains("unresolved call target `json.array")
                && detail.contains("autofix")
            {
                diag = diag.with_fix("replace fixed-arity call with `json.array([item1, item2])`");
            } else if detail.contains("unresolved call target `log.fields")
                && detail.contains("autofix")
            {
                diag = diag.with_fix(
                    "replace removed arity helper with `log.fields(#{\"k\": json.str(\"v\")})`",
                );
            }
            diag
        }

        let mut grouped = BTreeMap::<String, Vec<usize>>::new();
        for (index, detail) in module.type_error_details.iter().enumerate() {
            grouped.entry(detail.clone()).or_default().push(index);
        }
        let unique_count = grouped.len();
        let primary_detail = module
            .type_error_details
            .first()
            .cloned()
            .unwrap_or_else(|| "type-check failed".to_string());
        let mut diag = Diagnostic::new(
            Severity::Error,
            format!("type-check failed: {primary_detail}"),
            Some(
                "fix the primary mismatch first; the compiler grouped related downstream failures below"
                    .to_string(),
            ),
        )
        .with_catalog_key("verifier.grouped_type_error")
        .with_note(format!(
            "detected {} type-check failure(s) collapsing to {} unique root cause(s)",
            module.type_errors, unique_count
        ));
        let additional_details = module
            .type_error_details
            .iter()
            .filter(|detail| *detail != &primary_detail)
            .fold(Vec::<String>::new(), |mut acc, detail| {
                if !acc.iter().any(|existing| existing == detail) {
                    acc.push(detail.clone());
                }
                acc
            });
        for detail in additional_details.iter().take(4) {
            diag = diag.with_note(format!("additional grouped root cause: {detail}"));
        }
        if unique_count > 5 {
            diag = diag.with_note(format!(
                "{} more grouped root cause(s) were suppressed after the first 5 for brevity",
                unique_count - 5
            ));
        }
        report
            .diagnostics
            .push(apply_type_fix_hints(diag, &primary_detail));
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

fn module_needs_explicit_capabilities(module: &FirModule) -> bool {
    module.host_syscall_sites > 0
        || module.unsafe_sites > 0
        || module.unsafe_reasoned_sites > 0
        || !module.required_effects.is_empty()
        || !module.capability_token_violations.is_empty()
        || !module.thread_boundary_violations.is_empty()
        || module.extern_c_abi_functions > 0
        || module.repr_c_layout_items > 0
}

fn extern_c_import_requires_unsafe(function: &TypedFunction) -> bool {
    is_extern_c_import(function)
        && !function.is_unsafe
        && (function.return_type.is_pointer_like()
            || function
                .params
                .iter()
                .any(|param| param.ty.is_pointer_like()))
}

fn extern_c_import_pointer_param_missing_contract(function: &TypedFunction) -> Option<&str> {
    if !is_extern_c_import(function) {
        return None;
    }
    for param in &function.params {
        if !matches!(param.ty, ast::Type::Ptr { .. }) {
            continue;
        }
        let tagged = param.name.ends_with("_owned")
            || param.name.ends_with("_borrowed")
            || param.name.ends_with("_out")
            || param.name.ends_with("_inout");
        let ctx_param = param.name.ends_with("_ctx") || param.name.ends_with("_context");
        if (!tagged && !ctx_param) || (!ctx_param && !has_len_pair(function, &param.name)) {
            return Some(param.name.as_str());
        }
    }
    None
}

fn callback_param_missing_adjacent_context_anchor(function: &TypedFunction) -> Option<&str> {
    if !is_extern_c_import(function) {
        return None;
    }
    for (index, param) in function.params.iter().enumerate() {
        if !is_callback_param(&param.ty) {
            continue;
        }
        let prev_is_anchor = if index > 0 {
            function
                .params
                .get(index - 1)
                .is_some_and(|neighbor| is_context_anchor_name(&neighbor.name))
        } else {
            false
        };
        let next_is_anchor = function
            .params
            .get(index + 1)
            .is_some_and(|neighbor| is_context_anchor_name(&neighbor.name));
        let has_adjacent_anchor = prev_is_anchor || next_is_anchor;
        if !has_adjacent_anchor {
            return Some(param.name.as_str());
        }
    }
    None
}

fn is_callback_param(ty: &ast::Type) -> bool {
    matches!(ty, ast::Type::Function { .. })
}

fn collect_repr_c_names(module: &FirModule) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (name, item) in &module.struct_defs {
        if item
            .repr
            .as_deref()
            .is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
        {
            names.insert(name.clone());
        }
    }
    for (name, item) in &module.enum_defs {
        if item
            .repr
            .as_deref()
            .is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
        {
            names.insert(name.clone());
        }
    }
    names
}

fn extern_c_import_unstable_ffi_type(
    function: &TypedFunction,
    repr_c_names: &BTreeSet<String>,
) -> Option<String> {
    if !is_extern_c_import(function) {
        return None;
    }
    if !ffi_stable_type(&function.return_type, repr_c_names) {
        return Some(format!(
            "extern C import `{}` uses unstable return type `{}`",
            function.name, function.return_type
        ));
    }
    for param in &function.params {
        if !ffi_stable_type(&param.ty, repr_c_names) {
            return Some(format!(
                "extern C import `{}` parameter `{}` uses unstable type `{}`",
                function.name, param.name, param.ty
            ));
        }
    }
    None
}

fn is_extern_c_import(function: &TypedFunction) -> bool {
    function.is_extern && function.abi.as_deref() == Some("c") && function.body.is_empty()
}

fn ffi_stable_type(ty: &ast::Type, repr_c_names: &BTreeSet<String>) -> bool {
    match ty {
        ast::Type::Never
        | ast::Type::Void
        | ast::Type::Bool
        | ast::Type::Char
        | ast::Type::Float { .. }
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. } => true,
        ast::Type::Ptr { to, .. } => ffi_stable_type(to, repr_c_names),
        ast::Type::Named { name, args } => args.is_empty() && repr_c_names.contains(name),
        ast::Type::Function { params, ret } => {
            params
                .iter()
                .all(|param| ffi_stable_type(param, repr_c_names))
                && ffi_stable_type(ret, repr_c_names)
        }
        _ => false,
    }
}

fn pointer_base_name(name: &str) -> String {
    for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

fn has_len_pair(function: &TypedFunction, pointer_param_name: &str) -> bool {
    let base = pointer_base_name(pointer_param_name);
    let expected = format!("{base}_len");
    function.params.iter().any(|candidate| {
        matches!(candidate.ty, ast::Type::USize)
            && (candidate.name == "len"
                || candidate.name == expected
                || candidate.name == format!("{base}_bytes"))
    })
}

fn is_context_anchor_name(name: &str) -> bool {
    name.ends_with("_ctx") || name.ends_with("_context")
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

fn unsafe_owner_id_matches_owner(function_name: &str, owner: &str, owner_id: &str) -> bool {
    let function_name = function_name.trim();
    let owner = owner.trim();
    let owner_id = owner_id.trim();
    if function_name.is_empty() || owner.is_empty() || owner_id.is_empty() {
        return false;
    }
    owner_id == format!("owner::{function_name}::{owner}")
}

fn unsafe_proof_ref_valid(proof_ref: &str) -> bool {
    let proof_ref = proof_ref.trim();
    if proof_ref.is_empty() {
        return false;
    }
    let Some((scheme, rest)) = proof_ref.split_once("://") else {
        return false;
    };
    if rest.trim().is_empty() {
        return false;
    }
    if matches!(scheme, "gate" | "rfc") {
        return true;
    }
    if !matches!(scheme, "trace" | "run" | "test" | "ci") {
        return false;
    }
    let path_part = rest.split('#').next().unwrap_or_default().trim();
    if path_part.is_empty() {
        return false;
    }
    std::path::Path::new(path_part).exists()
}

fn unsafe_contract_is_placeholder_generated(site: &fir::UnsafeContractSite) -> bool {
    site.proof_ref
        .as_deref()
        .is_some_and(|proof_ref| proof_ref.starts_with("gate://compiler-generated/"))
        || site
            .reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("compiler-generated:"))
        || site.owner.as_deref() == Some("scope_root")
}

#[cfg(test)]
mod tests {
    use core::Capability;
    use fir::TypedFunction;

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

    fn unsafe_site_bad_proof_ref() -> fir::UnsafeContractSite {
        fir::UnsafeContractSite {
            proof_ref: Some("bogus://missing".to_string()),
            ..unsafe_site_complete()
        }
    }

    fn unsafe_site_missing_trace_proof_ref() -> fir::UnsafeContractSite {
        fir::UnsafeContractSite {
            proof_ref: Some("trace:///definitely/missing/path.fozzy#site=usite_test".to_string()),
            ..unsafe_site_complete()
        }
    }

    fn unsafe_site_existing_trace_proof_ref() -> fir::UnsafeContractSite {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("fozzylang-verifier-proof-ref-{suffix}.fozzy"));
        std::fs::write(&path, "{}").expect("trace file should be written");
        fir::UnsafeContractSite {
            proof_ref: Some(format!("trace://{}#site=usite_test", path.display())),
            ..unsafe_site_complete()
        }
    }

    fn unsafe_site_bad_owner_id() -> fir::UnsafeContractSite {
        fir::UnsafeContractSite {
            owner_id: Some("owner::wrong::scope_root".to_string()),
            ..unsafe_site_complete()
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

    fn base_module() -> fir::FirModule {
        fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        }
    }

    fn extern_c_function(
        name: &str,
        params: Vec<ast::Param>,
        return_type: ast::Type,
        is_unsafe: bool,
    ) -> TypedFunction {
        TypedFunction {
            name: name.to_string(),
            link_name: None,
            generics: Vec::new(),
            params,
            local_types: std::collections::BTreeMap::new(),
            return_type,
            body: Vec::new(),
            is_unsafe,
            is_async: false,
            is_extern: true,
            abi: Some("c".to_string()),
            ffi_panic: None,
            required_capabilities: Vec::new(),
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
            host_syscall_sites: 1,
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report.diagnostics.iter().any(|d| d
            .message
            .contains("module has declarations but no explicit capabilities")));
    }

    #[test]
    fn pure_helper_module_without_effects_does_not_warn() {
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(!report.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("module has declarations but no explicit capabilities")
        }));
    }

    #[test]
    fn thread_boundary_borrowed_return_uses_thread_boundary_remediation() {
        let mut module = base_module();
        module.thread_boundary_violations.push(
            "function `worker` returns borrowed reference across thread-capable boundary; return owned/Send-safe handle instead"
                .to_string(),
        );

        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|d| {
                d.message
                    .contains("returns borrowed reference across thread-capable boundary")
            })
            .expect("thread-boundary diagnostic");
        let help = diagnostic.help.as_deref().unwrap_or_default();
        assert!(help.contains("return owned values or a Send/Sync-safe handle"));
        assert!(!help.contains("capability token parameters"));
    }

    #[test]
    fn thread_boundary_mutable_param_uses_send_sync_wrapper_guidance() {
        let mut module = base_module();
        module.thread_boundary_violations.push(
            "function `worker` parameter `buf` requires Send/Sync-safe wrapper before thread crossing"
                .to_string(),
        );

        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|d| {
                d.message
                    .contains("requires Send/Sync-safe wrapper before thread crossing")
            })
            .expect("thread-boundary diagnostic");
        let help = diagnostic.help.as_deref().unwrap_or_default();
        assert!(help.contains("wrap borrowed references/pointers"));
        assert!(!help.contains("capability token parameters"));
    }

    #[test]
    fn thread_boundary_shared_param_uses_send_sync_wrapper_guidance() {
        let mut module = base_module();
        module.thread_boundary_violations.push(
            "function `worker` parameter `shared` requires Send/Sync-safe wrapper before thread crossing"
                .to_string(),
        );

        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|d| {
                d.message.contains(
                    "parameter `shared` requires Send/Sync-safe wrapper before thread crossing",
                )
            })
            .expect("thread-boundary diagnostic");
        let help = diagnostic.help.as_deref().unwrap_or_default();
        assert!(help.contains("wrap borrowed references/pointers"));
        assert!(!help.contains("capability token parameters"));
    }

    #[test]
    fn spawned_closure_borrow_capture_uses_spawn_specific_guidance() {
        let mut module = base_module();
        module.thread_boundary_violations.push(
            "function `main` spawn captures shared borrowed reference `shared` across thread boundary"
                .to_string(),
        );

        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|d| {
                d.message.contains(
                    "spawn captures shared borrowed reference `shared` across thread boundary",
                )
            })
            .expect("thread-boundary diagnostic");
        let help = diagnostic.help.as_deref().unwrap_or_default();
        assert!(help.contains("move owned data into the spawned task"));
        assert!(help.contains("wrap borrowed references/pointers"));
    }

    #[test]
    fn capability_token_failures_keep_capability_specific_guidance() {
        let mut module = base_module();
        module
            .capability_token_violations
            .push("function `worker` delegates `fs` without explicit token handoff".to_string());

        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|d| {
                d.message
                    .contains("delegates `fs` without explicit token handoff")
            })
            .expect("capability-token diagnostic");
        let help = diagnostic.help.as_deref().unwrap_or_default();
        assert!(help.contains("capability token parameters"));
        assert!(!help.contains("Send/Sync-safe handle"));
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
    fn grouped_type_errors_use_human_readable_notes() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 3,
            type_error_details: vec![
                "let binding `value` type mismatch: expected `i32`, got `str`".to_string(),
                "unresolved call target `missing_symbol`".to_string(),
                "unresolved call target `missing_symbol`".to_string(),
            ],
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("type-check failed"))
            .expect("grouped type diagnostic should be present");
        assert!(diagnostic
            .notes
            .iter()
            .any(|note| note.contains("detected 3 type-check failure(s)")));
        assert!(diagnostic
            .notes
            .iter()
            .any(|note| note.contains("additional grouped root cause: unresolved call target")));
        assert!(diagnostic
            .notes
            .iter()
            .all(|note| !note.contains("type_error_count=")));
    }

    #[test]
    fn grouped_type_errors_do_not_repeat_primary_root_cause() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 3,
            type_error_details: vec![
                "let binding `value` type mismatch: expected `i32`, got `str`".to_string(),
                "let binding `value` type mismatch: expected `i32`, got `str`".to_string(),
                "unresolved call target `missing_symbol`".to_string(),
            ],
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("type-check failed"))
            .expect("grouped type diagnostic should be present");
        assert!(diagnostic.notes.iter().any(|note| {
            note.contains("additional grouped root cause: unresolved call target `missing_symbol`")
        }));
        assert!(!diagnostic.notes.iter().any(|note| {
            note.contains(
                "additional grouped root cause: let binding `value` type mismatch: expected `i32`, got `str`",
            )
        }));
    }

    #[test]
    fn invalid_capability_import_does_not_emit_missing_capability_warning() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
            unknown_effects: vec!["text".to_string()],
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unknown capability: text")));
        assert!(!report.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("module has declarations but no explicit capabilities")
        }));
    }

    #[test]
    fn removed_api_type_diagnostics_surface_fix_text() {
        let module = fir::FirModule {
            name: "m".to_string(),
            effects: core::CapabilitySet::default(),
            required_effects: core::CapabilitySet::default(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 1,
            type_error_details: vec![
                "unresolved call target `json.object3` (autofix: use `json.object(map_handle)` instead)"
                    .to_string(),
            ],
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: Vec::new(),
        };
        let report = verify(&module);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("type-check failed"))
            .expect("grouped type diagnostic should be present");
        assert_eq!(
            diagnostic.fix.as_deref(),
            Some("replace fixed-arity call with `json.object(#{\"k\": json.str(\"v\")})`")
        );
        assert!(diagnostic
            .suggested_fixes
            .iter()
            .any(|fix| fix.contains("json.object")));
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
    fn errors_for_linear_type_violations() {
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
            trait_violations: Vec::new(),
            reference_lifetime_violations: Vec::new(),
            linear_type_violations: vec![
                "function `main` linear value `socket_res` was not consumed/freed".to_string(),
            ],
        };
        let report = verify(&module);
        assert!(report.diagnostics.iter().any(|d| d
            .message
            .contains("function `main` linear value `socket_res` was not consumed/freed")));
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            Capability::Storage,
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
        for expected in [
            "time", "rng", "fs", "storage", "http", "proc", "mem", "thread",
        ] {
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
    fn safe_extern_c_pointer_param_requires_unsafe_boundary() {
        let mut module = base_module();
        module.typed_functions.push(extern_c_function(
            "c_read",
            vec![ast::Param {
                name: "buf".to_string(),
                ty: ast::Type::Ptr {
                    mutable: false,
                    to: Box::new(ast::Type::Int {
                        signed: false,
                        bits: 8,
                    }),
                },
            }],
            ast::Type::Int {
                signed: true,
                bits: 32,
            },
            false,
        ));

        let report = verify(&module);
        assert!(report.diagnostics.iter().any(|d| {
            d.message
                .contains("extern C import `c_read` exposes pointer-like contract")
        }));
    }

    #[test]
    fn safe_extern_c_borrowed_pointer_param_requires_unsafe_boundary() {
        let mut module = base_module();
        module.typed_functions.push(extern_c_function(
            "c_read_borrowed",
            vec![ast::Param {
                name: "buf_borrowed".to_string(),
                ty: ast::Type::Ptr {
                    mutable: false,
                    to: Box::new(ast::Type::Int {
                        signed: false,
                        bits: 8,
                    }),
                },
            }],
            ast::Type::Int {
                signed: true,
                bits: 32,
            },
            false,
        ));

        let report = verify(&module);
        assert!(report.diagnostics.iter().any(|d| {
            d.message
                .contains("extern C import `c_read_borrowed` exposes pointer-like contract")
        }));
    }

    #[test]
    fn safe_extern_c_mixed_pointer_signature_requires_unsafe_boundary() {
        let mut module = base_module();
        module.typed_functions.push(extern_c_function(
            "acquire_and_fill",
            vec![ast::Param {
                name: "out_ptr".to_string(),
                ty: ast::Type::Ptr {
                    mutable: true,
                    to: Box::new(ast::Type::Int {
                        signed: false,
                        bits: 8,
                    }),
                },
            }],
            ast::Type::Ptr {
                mutable: false,
                to: Box::new(ast::Type::Int {
                    signed: false,
                    bits: 8,
                }),
            },
            false,
        ));

        let report = verify(&module);
        assert!(report.diagnostics.iter().any(|d| {
            d.message
                .contains("extern C import `acquire_and_fill` exposes pointer-like contract")
        }));
    }

    #[test]
    fn callback_extern_c_import_without_context_anchor_fails() {
        let mut module = base_module();
        module.typed_functions.push(extern_c_function(
            "register",
            vec![
                ast::Param {
                    name: "cb_owned".to_string(),
                    ty: ast::Type::Ptr {
                        mutable: false,
                        to: Box::new(ast::Type::Int {
                            signed: false,
                            bits: 8,
                        }),
                    },
                },
                ast::Param {
                    name: "cb".to_string(),
                    ty: ast::Type::Function {
                        params: vec![ast::Type::Int {
                            signed: true,
                            bits: 32,
                        }],
                        ret: Box::new(ast::Type::Int {
                            signed: true,
                            bits: 32,
                        }),
                    },
                },
            ],
            ast::Type::Int {
                signed: true,
                bits: 32,
            },
            true,
        ));

        let report = verify(&module);
        assert!(report.diagnostics.iter().any(|d| {
            d.message.contains(
                "callback parameter `cb` requires an adjacent `*_ctx` or `*_context` anchor",
            )
        }));
    }

    #[test]
    fn callback_extern_c_import_with_adjacent_context_anchor_passes_structural_check() {
        let mut module = base_module();
        module.typed_functions.push(extern_c_function(
            "register",
            vec![
                ast::Param {
                    name: "cb_ctx".to_string(),
                    ty: ast::Type::Ptr {
                        mutable: false,
                        to: Box::new(ast::Type::Void),
                    },
                },
                ast::Param {
                    name: "cb".to_string(),
                    ty: ast::Type::Function {
                        params: vec![ast::Type::Int {
                            signed: true,
                            bits: 32,
                        }],
                        ret: Box::new(ast::Type::Int {
                            signed: true,
                            bits: 32,
                        }),
                    },
                },
            ],
            ast::Type::Int {
                signed: true,
                bits: 32,
            },
            true,
        ));

        let report = verify(&module);
        assert!(!report.diagnostics.iter().any(|d| {
            d.message.contains(
                "callback parameter `cb` requires an adjacent `*_ctx` or `*_context` anchor",
            )
        }));
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
        assert!(report.diagnostics.iter().any(|d| d.message.contains(
            "compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites"
        )));
        assert!(report.diagnostics.iter().any(|d| d
            .help
            .as_deref()
            .is_some_and(|help| help
                .contains("the compiler is satisfied with the current unsafe-policy checks"))));
        assert!(report.is_clean());
    }

    #[test]
    fn production_mode_distinguishes_placeholder_unsafe_contracts_from_reasoned_evidence() {
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
        assert!(report.diagnostics.iter().any(|d| d.message.contains(
            "compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites"
        )));
        assert!(report.diagnostics.iter().any(|d| d
            .help
            .as_deref()
            .is_some_and(|help| help
                .contains("the compiler is satisfied with the current unsafe-policy checks"))));
        assert!(!report.diagnostics.iter().any(|d| {
            d.message.contains(
                "detected 1 explicit unsafe escape marker(s); compiler contract checks passed",
            )
        }));
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
    fn strict_unsafe_contracts_reject_malformed_proof_refs() {
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
            unsafe_contract_sites: vec![unsafe_site_bad_proof_ref()],
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("malformed proof references")));
        assert!(!report.is_clean());
    }

    #[test]
    fn strict_unsafe_contracts_reject_missing_trace_artifact_proof_refs() {
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
            unsafe_contract_sites: vec![unsafe_site_missing_trace_proof_ref()],
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("malformed proof references")));
        assert!(!report.is_clean());
    }

    #[test]
    fn strict_unsafe_contracts_accept_existing_trace_artifact_proof_refs() {
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
            unsafe_contract_sites: vec![unsafe_site_existing_trace_proof_ref()],
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
        assert!(!report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("malformed proof references")));
        assert!(report.is_clean());
        if let Some(path) = module.unsafe_contract_sites[0]
            .proof_ref
            .as_deref()
            .and_then(|proof_ref| proof_ref.strip_prefix("trace://"))
            .and_then(|rest| rest.split('#').next())
        {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn strict_unsafe_contracts_reject_malformed_owner_ids() {
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
            unsafe_contract_sites: vec![unsafe_site_bad_owner_id()],
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("malformed owner identity metadata")));
        assert!(!report.is_clean());
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
            struct_defs: std::collections::HashMap::new(),
            enum_defs: std::collections::HashMap::new(),
            type_errors: 0,
            type_error_details: Vec::new(),
            function_capability_requirements: Vec::new(),
            ownership_violations: Vec::new(),
            unsafe_context_violations: Vec::new(),
            capability_token_violations: Vec::new(),
            thread_boundary_violations: Vec::new(),
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
