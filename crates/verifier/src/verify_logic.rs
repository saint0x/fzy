use diagnostics::{assign_stable_codes, Diagnostic, DiagnosticDomain, Severity};
use fir::{count_module_owned_return_transfers, FirModule};
use std::collections::BTreeMap;

use crate::ffi::{
    callback_param_missing_adjacent_context_anchor, collect_repr_c_names,
    extern_c_import_pointer_param_missing_contract, extern_c_import_requires_unsafe,
    extern_c_import_unstable_ffi_type, rpc_param_payload_violation, rpc_return_payload_violation,
};
use crate::unsafe_contracts::{
    unsafe_contract_is_placeholder_generated, unsafe_invariant_matches_owner,
    unsafe_owner_id_matches_owner, unsafe_proof_ref_valid, unsafe_scope_matches,
};
use crate::{VerifyPolicy, VerifyReport};

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
                "allowed: time, rng, fs, storage, http, proc, mem, thread, log, error, gpu"
                    .to_string(),
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
            core::Capability::Gpu,
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
        if function.is_extern
            && function.abi.as_deref() == Some("c")
            && function.body.is_empty()
            && function.is_async
        {
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
        if let Some((param_name, ty)) = rpc_param_payload_violation(function) {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!(
                        "RPC method `{}` parameter `{}` uses unsupported payload type `{}`",
                        function.name, param_name, ty
                    ),
                    Some(
                        "RPC payloads must cross the boundary as owned/value data; replace borrowed, pointer-like, async, or function payloads with `str`, bytes, JSON, or a typed owned struct/enum".to_string(),
                    ),
                )
                .with_catalog_key("verifier.rpc_param_payload_unsupported"),
            );
        }
        if let Some(ty) = rpc_return_payload_violation(function) {
            report.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!(
                        "RPC method `{}` returns unsupported payload type `{}`",
                        function.name, ty
                    ),
                    Some(
                        "RPC responses must return owned/value payloads; replace borrowed, pointer-like, async, or function returns with an owned response type".to_string(),
                    ),
                )
                .with_catalog_key("verifier.rpc_return_payload_unsupported"),
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
            if !policy.safe_profile
                && unsafe_attention_sites == 0
                && placeholder_generated_sites == 0
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
        } else if violation.contains("aliases GpuSlice parameters `") {
            "pass distinct buffer views to each mutable kernel slice parameter, or add explicit readonly/writeonly parameter modes before reusing the same owner".to_string()
        } else if violation.contains("cannot use `gpu.barrier` inside divergent control flow") {
            "move the barrier to straight-line kernel/device code that every lane executes uniformly, or split the kernel so the synchronization point is unconditional".to_string()
        } else if violation.contains("cannot call barrier-carrying function `")
            && violation.contains("inside divergent control flow")
        {
            "call the synchronization helper only from uniform control flow, or refactor it so the barrier executes unconditionally before branching".to_string()
        } else if violation.contains("stable GPU launch ABI") {
            "use only stable GPU launch ABI parameter shapes for kernels today: `i32`, `u32`, `f32`, and `GpuSlice<f32|i32|u32>`".to_string()
        } else if violation.contains("after provenance root") {
            "stop using aliases after freeing the owning value; move the free later, or return/assign a fresh owned value before reuse".to_string()
        } else if violation.contains("performs partial move") {
            "move or destructure the full owned aggregate, or borrow fields instead of extracting only one owned subvalue".to_string()
        } else if violation.contains("conditionally consumed value `")
            || violation.contains("divergent ownership state for `")
        {
            "make ownership outcomes consistent on every branch and loop path before reusing or freeing the value".to_string()
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
        } else if violation.contains("captures non-Send-safe handle `") {
            "move only Send-safe handles into spawned tasks, or finish/close the non-Send-safe handle before crossing the thread boundary".to_string()
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
        let help = if violation.contains("returns reference expression with mismatched lifetime") {
            "return the reference tied to the declared output lifetime on every path, or return an owned value instead".to_string()
        } else if violation
            .contains("returns reference expression without a statically traced lifetime source")
        {
            "bind the returned reference to one explicit input lifetime before returning, or switch the API to an owned return".to_string()
        } else if violation.contains("cannot use borrowed local reference `")
            && violation.contains("across await suspension points")
        {
            "resolve the borrowed local before `await`, or keep only owned data alive across the suspension point".to_string()
        } else if violation.contains("cannot use borrowed reference `")
            && violation.contains("across await suspension points")
        {
            "move the `await` before the borrowed use, or replace the borrowed path with an owned value across suspension".to_string()
        } else if violation.contains("cannot use non-async-stable handle `")
            && violation.contains("across await suspension points")
        {
            "finish, consume, or replace the non-async-stable handle before `await`, or move the suspension point earlier".to_string()
        } else {
            "introduce explicit lifetime/region-safe ownership handoff".to_string()
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

fn apply_type_fix_hints(mut diag: Diagnostic, detail: &str) -> Diagnostic {
    if detail.contains("unresolved call target `json.object") && detail.contains("autofix") {
        diag =
            diag.with_fix("replace fixed-arity call with `json.object(#{\"k\": json.str(\"v\")})`");
    } else if detail.contains("unresolved call target `json.array") && detail.contains("autofix") {
        diag = diag.with_fix("replace fixed-arity call with `json.array([item1, item2])`");
    } else if detail.contains("unresolved call target `log.fields") && detail.contains("autofix") {
        diag = diag
            .with_fix("replace removed arity helper with `log.fields(#{\"k\": json.str(\"v\")})`");
    }
    diag
}

fn module_needs_explicit_capabilities(module: &FirModule) -> bool {
    module.unsafe_sites > 0
        || module.unsafe_reasoned_sites > 0
        || !module.required_effects.is_empty()
        || !module.capability_token_violations.is_empty()
        || !module.thread_boundary_violations.is_empty()
        || module.extern_c_abi_functions > 0
        || module.repr_c_layout_items > 0
}
