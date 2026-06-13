fn diagnostic_catalog() -> Vec<DiagnosticCatalogEntry> {
    vec![
        DiagnosticCatalogEntry {
            key: "parser.expected_parameter_name".to_string(),
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "A function or method signature is missing a parameter identifier at the highlighted span.".to_string(),
            example: "E-PAR-xxxx: expected parameter name".to_string(),
            likely_fix: "Add the missing parameter name before `:` or remove the stray punctuation in the signature.".to_string(),
            common_triggers: vec![
                "a comma or `(` is followed directly by `:` or a type".to_string(),
                "the function signature was partially edited and lost an identifier".to_string(),
            ],
            production_action: "Repair the signature first, then rerun `fz check`; parser recovery after a broken parameter list is often noisy.".to_string(),
            production_risk: "High: this blocks parsing of the declaration and can mislead downstream diagnostics.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "parser.expected_function_body_or_semi".to_string(),
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "A function declaration ended without either a body or a terminating `;`.".to_string(),
            example: "E-PAR-xxxx: expected function body `{ ... }` or `;`".to_string(),
            likely_fix: "Finish the declaration with `{ ... }` for an implementation or `;` for an extern-style declaration.".to_string(),
            common_triggers: vec![
                "unfinished function signature after return type".to_string(),
                "extern/import declaration missing terminating `;`".to_string(),
            ],
            production_action: "Decide whether the declaration is implemented or external, then make that shape explicit and rerun parsing.".to_string(),
            production_risk: "High: this blocks the parser from establishing the function boundary correctly.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "parser.expected_token".to_string(),
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "The parser expected a required token or keyword at the highlighted location.".to_string(),
            example: "E-PAR-xxxx: expected `catch` in try/catch expression".to_string(),
            likely_fix: "Insert the missing token or keyword and re-run parsing before trusting later diagnostics.".to_string(),
            common_triggers: vec![
                "missing delimiter or keyword near the highlighted token".to_string(),
                "unfinished function signature, block, or expression".to_string(),
            ],
            production_action: "Fix the earliest parser error first; later parse diagnostics often collapse once the grammar is restored.".to_string(),
            production_risk: "High: parser failures block every later compiler stage and can hide real semantic issues.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "parser.unexpected_token_in_expression".to_string(),
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "The parser found a token that cannot continue the current expression.".to_string(),
            example: "E-PAR-xxxx: unexpected token in expression".to_string(),
            likely_fix: "Finish the expression before the highlighted token or insert the missing operator, separator, or delimiter.".to_string(),
            common_triggers: vec![
                "missing delimiter between expressions".to_string(),
                "unfinished call, tuple, or block expression".to_string(),
            ],
            production_action: "Fix the local expression shape first, then rerun `fz check` before trusting downstream semantic diagnostics.".to_string(),
            production_risk: "High: malformed expressions often trigger broad parser recovery noise.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "parser.invalid_match_pattern".to_string(),
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "A match arm pattern uses a syntax form that is not accepted in the current grammar.".to_string(),
            example: "E-PAR-xxxx: invalid match pattern".to_string(),
            likely_fix: "Rewrite the highlighted pattern into a supported variant, tuple, struct, wildcard, or literal pattern.".to_string(),
            common_triggers: vec![
                "enum variant pattern is missing required qualifiers".to_string(),
                "unsupported nested or malformed pattern syntax".to_string(),
            ],
            production_action: "Normalize the pattern shape first so later exhaustiveness and type diagnostics are anchored to a valid match tree.".to_string(),
            production_risk: "High: invalid patterns undermine both parsing and later semantic match analysis.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "parser.unsupported_syntax".to_string(),
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "The source uses a syntax form that is intentionally unsupported in the current language contract.".to_string(),
            example: "E-PAR-xxxx: unsupported attribute".to_string(),
            likely_fix: "Rewrite the highlighted syntax into a supported production form.".to_string(),
            common_triggers: vec![
                "removed syntax from an older language revision".to_string(),
                "experimental surface used without a supported production form".to_string(),
            ],
            production_action: "Replace the unsupported syntax rather than trying to recover around it; this class is a hard contract boundary.".to_string(),
            production_risk: "Medium to high: unsupported syntax blocks production compilation and usually indicates docs/tooling drift.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "parser.syntax_error".to_string(),
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "A general syntax error was detected at the highlighted source span.".to_string(),
            example: "E-PAR-xxxx: expected `{` after `unsafe`".to_string(),
            likely_fix: "Repair the highlighted syntax and rerun `fz check` to regenerate parser output.".to_string(),
            common_triggers: vec![
                "missing delimiter or keyword".to_string(),
                "partial edit left a declaration or expression incomplete".to_string(),
            ],
            production_action: "Start with the earliest syntax error in the file; later parse findings are often secondary effects.".to_string(),
            production_risk: "High: parser failures prevent trusted semantic analysis.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "native.unresolved_call".to_string(),
            code_prefix: "E-NAT-".to_string(),
            family: "native-lowering".to_string(),
            summary: "The native backend found a call target that has no native implementation on the chosen execution surface.".to_string(),
            example: "E-NAT-xxxx: native backend cannot execute unresolved call `missing_symbol`".to_string(),
            likely_fix: "Provide a native implementation, use the runtime/scenario path for that symbol, or switch to a backend that supports it.".to_string(),
            common_triggers: vec![
                "symbol only exists in scenario/runtime execution surface".to_string(),
                "backend-specific unsupported construct or missing native implementation".to_string(),
            ],
            production_action: "Confirm whether the symbol is supposed to run natively; if not, route it through the Fozzy runtime path instead of forcing native lowering.".to_string(),
            production_risk: "High: native builds may fail or exercise the wrong execution surface if ignored.".to_string(),
            next_command: "fz build <path> --backend llvm --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "native.cranelift_async_c_export_unsupported".to_string(),
            code_prefix: "E-NAT-".to_string(),
            family: "native-lowering".to_string(),
            summary: "The Cranelift backend cannot lower an async C export surface.".to_string(),
            example: "E-NAT-xxxx: backend `cranelift` does not support async C export `serve`".to_string(),
            likely_fix: "Switch to the LLVM backend or remove the async C export surface from the native path.".to_string(),
            common_triggers: vec![
                "async function is exported through `pubext c fn`".to_string(),
                "backend selection stayed on Cranelift for an FFI async surface".to_string(),
            ],
            production_action: "Treat this as a backend capability mismatch and make the backend/surface choice explicit before shipping.".to_string(),
            production_risk: "High: native builds on the selected backend cannot represent the exported ABI shape.".to_string(),
            next_command: "fz build <path> --backend llvm --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "native.cranelift_async_unsafe_unsupported".to_string(),
            code_prefix: "E-NAT-".to_string(),
            family: "native-lowering".to_string(),
            summary: "The Cranelift backend rejects functions that combine async execution with an unsafe body.".to_string(),
            example: "E-NAT-xxxx: backend `cranelift` rejects async+unsafe function `risky`".to_string(),
            likely_fix: "Switch to LLVM or refactor unsafe operations outside the async function boundary.".to_string(),
            common_triggers: vec![
                "async function body contains an unsafe contract surface".to_string(),
                "Cranelift selected for a code shape only supported by LLVM".to_string(),
            ],
            production_action: "Choose a backend that supports the shape or simplify the function surface before production release.".to_string(),
            production_risk: "High: the selected native backend cannot lower the function at all.".to_string(),
            next_command: "fz build <path> --backend llvm --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.grouped_type_error".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "The verifier collapsed multiple related type-check failures into a single root-cause diagnostic.".to_string(),
            example: "E-VER-xxxx: type-check failed: let binding `value` type mismatch: expected `i32`, got `str`".to_string(),
            likely_fix: "Fix the primary mismatch first, then re-run `fz check` or `fz verify` to see which grouped cascades disappear.".to_string(),
            common_triggers: vec![
                "declared type does not match inferred value".to_string(),
                "an unresolved call or invalid symbol triggered downstream type noise".to_string(),
            ],
            production_action: "Treat the first root cause as the real blocker and use the grouped notes only as supporting context.".to_string(),
            production_risk: "High: grouped type errors indicate the program is not semantically stable enough for trusted lowering.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.missing_explicit_capabilities".to_string(),
            code_prefix: "W-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "The module compiled without declaring any explicit capability surface.".to_string(),
            example: "W-VER-xxxx: module has declarations but no explicit capabilities".to_string(),
            likely_fix: "Add the required `use core.<capability>;` imports for effects the module actually uses, or leave the module effect-free on purpose.".to_string(),
            common_triggers: vec![
                "new module was created before capability imports were added".to_string(),
                "the code is effect-free but still being checked under production policy".to_string(),
            ],
            production_action: "Confirm whether the module is intentionally effect-free; if not, make the capability contract explicit before relying on the diagnostics surface.".to_string(),
            production_risk: "Low to medium: this is a warning, but it can hide incomplete capability declarations in growing modules.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.missing_required_capability".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "A module or function uses an effect that was not declared in the capability surface.".to_string(),
            example: "E-VER-xxxx: missing required capability: http".to_string(),
            likely_fix: "Add the required `use core.<capability>;` import or thread the capability requirement through the calling surface.".to_string(),
            common_triggers: vec![
                "module-level capability import is missing".to_string(),
                "function-level capability requirement is stronger than the enclosing module declaration".to_string(),
            ],
            production_action: "Update the capability contract explicitly; do not suppress this because it is part of the production trust boundary.".to_string(),
            production_risk: "High: the declared capability surface no longer matches the behavior the program requires.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.function_missing_required_capability".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "A specific function requires a capability that is not available from the enclosing module contract.".to_string(),
            example: "E-VER-xxxx: function `main` is missing required capability: proc".to_string(),
            likely_fix: "Declare the capability at module scope or thread the capability token through the affected function boundary.".to_string(),
            common_triggers: vec![
                "function-level capability requirement exceeds module imports".to_string(),
                "migration to a runtime intrinsic introduced a new capability dependency".to_string(),
            ],
            production_action: "Fix the narrowest function boundary that explains the missing effect, then rerun verifier checks to confirm the module contract is coherent.".to_string(),
            production_risk: "High: callers and module policy no longer match the function’s effect requirements.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.safe_profile_forbidden_capability".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "A safe-profile build attempted to use a capability that is forbidden under the production safety contract.".to_string(),
            example: "E-VER-xxxx: safe profile forbids capability: http".to_string(),
            likely_fix: "Remove the forbidden capability usage from the safe-profile path or build in a profile that explicitly permits it.".to_string(),
            common_triggers: vec![
                "safe profile was enabled for a runtime-backed capability".to_string(),
                "production safety policy conflicts with I/O, process, memory, or thread usage".to_string(),
            ],
            production_action: "Decide whether the code belongs in the safe-profile surface at all; if it does, refactor toward a capability-free path.".to_string(),
            production_risk: "High: safe-profile violations break the promised production memory/safety envelope.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.host_syscall_requires_abi_boundary".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "Host syscall usage was detected without the required audited `ext c fn` boundary.".to_string(),
            example: "E-VER-xxxx: host syscall usage requires an `ext c fn` boundary".to_string(),
            likely_fix: "Move the syscall surface behind an explicit `ext c fn` wrapper.".to_string(),
            common_triggers: vec![
                "raw host syscall primitives are called directly from language code".to_string(),
                "FFI wrapper surface was omitted during host integration".to_string(),
            ],
            production_action: "Force the syscall boundary to be explicit before release so review and policy checks have a concrete trust boundary.".to_string(),
            production_risk: "High: unaudited syscall surfaces bypass intended FFI policy enforcement.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.host_syscall_forbidden_under_production_memory_safety".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "Host syscall usage violated the production memory-safety policy.".to_string(),
            example: "E-VER-xxxx: host syscall usage is forbidden under production memory safety".to_string(),
            likely_fix: "Move the syscall path behind audited FFI boundaries or remove it from the production memory-safe surface.".to_string(),
            common_triggers: vec![
                "production memory-safety policy is enabled".to_string(),
                "host integration uses syscall surfaces that bypass audited wrappers".to_string(),
            ],
            production_action: "Treat this as a release blocker until the host effect boundary is redesigned or explicitly audited.".to_string(),
            production_risk: "High: the code is outside the supported production memory-safety model.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.extern_c_pointer_requires_unsafe".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "An extern C import exposes pointer-like ownership or aliasing risk without an explicit unsafe boundary.".to_string(),
            example: "E-VER-xxxx: extern C import `c_read` exposes pointer-like contract and must be declared `ext unsafe c fn`".to_string(),
            likely_fix: "Mark the import as `ext unsafe c fn` or redesign the signature to use a safe non-pointer contract.".to_string(),
            common_triggers: vec![
                "pointer-like return or out-parameter crosses a C boundary".to_string(),
                "FFI contract implies ownership or mutation without an unsafe marker".to_string(),
            ],
            production_action: "Audit the boundary explicitly and force callers to acknowledge the unsafe contract rather than treating it as a normal import.".to_string(),
            production_risk: "High: this is an FFI soundness boundary and should be treated as a release blocker.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.extern_c_pointer_requires_contract".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "An extern C pointer-like boundary is missing the audited ownership contract metadata required for production FFI review.".to_string(),
            example: "E-VER-xxxx: extern C import `host_touch` exposes pointer-like contract and must declare explicit ownership metadata".to_string(),
            likely_fix: "Add the required unsafe/FFI ownership metadata for the pointer boundary, including who owns the memory and how the len/aliasing contract is enforced.".to_string(),
            common_triggers: vec![
                "pointer-like import or export lacks explicit ownership annotation".to_string(),
                "buffer argument crosses the ABI without a matching contract or lifetime explanation".to_string(),
            ],
            production_action: "Fill in the narrowest audited ownership contract before release; do not allow pointer FFI to ship as implicit tribal knowledge.".to_string(),
            production_risk: "High: missing pointer ownership metadata turns an FFI edge into an unverifiable memory-safety boundary.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.extern_c_callback_requires_context_anchor".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "An extern C callback surface is missing the required context anchor that ties callback lifetime and ownership to a stable host object.".to_string(),
            example: "E-VER-xxxx: extern C callback `host_register` must declare a context anchor for callback state".to_string(),
            likely_fix: "Add the context anchor contract so callback state and teardown responsibility are explicit at the ABI boundary.".to_string(),
            common_triggers: vec![
                "callback pointer is registered without a stable owner/context handle".to_string(),
                "host callback teardown and lifetime are implied instead of declared".to_string(),
            ],
            production_action: "Make callback ownership and teardown explicit before release so cancellation, shutdown, and replay semantics stay reviewable.".to_string(),
            production_risk: "High: callback edges without context anchors are prone to lifetime, teardown, and reentrancy bugs.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "hir.semantic_error".to_string(),
            code_prefix: "E-HIR-".to_string(),
            family: "hir".to_string(),
            summary: "Type/name/call graph semantic mismatch in typed lowering.".to_string(),
            example: "E-HIR-xxxx: unresolved call target `missing_symbol`".to_string(),
            likely_fix: "Fix the unresolved symbol, field, variant, or type mismatch at the primary span and rerun `fz check`.".to_string(),
            common_triggers: vec![
                "unresolved symbol, field, or enum variant".to_string(),
                "declared type does not match inferred value".to_string(),
            ],
            production_action: "Fix the primary unresolved symbol or type mismatch, then rerun `fz check` to see whether grouped cascades disappear.".to_string(),
            production_risk: "High: HIR failures usually mean the program shape is not semantically well-formed enough for reliable lowering.".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "verifier.policy_error".to_string(),
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "Policy/safety contract violation in verification.".to_string(),
            example: "E-VER-xxxx: missing required capability: http".to_string(),
            likely_fix: "Fix the contract violation at the primary span or policy boundary, then rerun `fz verify`.".to_string(),
            common_triggers: vec![
                "missing capability import or policy contract".to_string(),
                "grouped type-check root cause promoted to verifier output".to_string(),
            ],
            production_action: "Treat verifier errors as production blockers; fix the primary contract violation and rerun `fz verify` or the full strict scenario gate.".to_string(),
            production_risk: "High: verifier failures indicate policy, safety, or production-readiness invariants are not satisfied.".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "native.lowering_error".to_string(),
            code_prefix: "E-NAT-".to_string(),
            family: "native-lowering".to_string(),
            summary: "Native backend lowerability contract violation.".to_string(),
            example: "E-NAT-xxxx: native backend cannot lower unresolved call target `missing_fn`"
                .to_string(),
            likely_fix: "Adjust the unsupported lowering shape or switch backend, then rerun `fz build`.".to_string(),
            common_triggers: vec![
                "symbol only exists in scenario/runtime execution surface".to_string(),
                "backend-specific unsupported construct or missing native implementation".to_string(),
            ],
            production_action: "Either provide a native implementation, move execution to the Fozzy runtime path, or switch to a backend that supports the construct.".to_string(),
            production_risk: "High: native builds may fail or silently miss the intended execution surface if this is ignored.".to_string(),
            next_command: "fz build <path> --backend llvm --json".to_string(),
        },
        DiagnosticCatalogEntry {
            key: "driver.pipeline_error".to_string(),
            code_prefix: "E-DRV-".to_string(),
            family: "driver".to_string(),
            summary: "Driver pipeline/configuration/runtime orchestration failure.".to_string(),
            example: "E-DRV-xxxx: lockfile drift detected".to_string(),
            likely_fix: "Repair the project or runtime orchestration issue, then rerun the failing command and the broader doctor path.".to_string(),
            common_triggers: vec![
                "manifest, lockfile, or project layout drift".to_string(),
                "command orchestration failure before compilation or execution completes".to_string(),
            ],
            production_action: "Repair the project/runtime setup first, then rerun the exact command that failed and the broader doctor/CI path if this is a release gate.".to_string(),
            production_risk: "Medium to high: driver failures can invalidate build reproducibility and release automation.".to_string(),
            next_command: "fz doctor project <path> --strict --json".to_string(),
        },
    ]
}

fn lint_command(path: &Path, tier: &str, format: Format) -> Result<String> {
    let tier = normalize_lint_tier(tier)?;
    let verify = verify_file_with_root_guidance(path)?;
    let mut items = verify.diagnostic_details;
    if tier == "pedantic" {
        items.extend(pedantic_lint_findings(path)?);
    } else if tier == "compat" {
        items.extend(compat_lint_findings(path)?);
    } else {
        items.extend(production_lint_findings(path)?);
    }
    let errors = items
        .iter()
        .filter(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error))
        .count();
    let warnings = items
        .iter()
        .filter(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Warning))
        .count();
    let status = if errors > 0 {
        "error"
    } else if tier == "pedantic" && warnings > 0 {
        "warn"
    } else {
        "ok"
    };
    match format {
        Format::Text => {
            let mut out = render_text_fields(&[
                ("status", status.to_string()),
                ("mode", "lint".to_string()),
                ("tier", tier.to_string()),
                ("errors", errors.to_string()),
                ("warnings", warnings.to_string()),
                (
                    "policy",
                    policy_summary_text("verify", Some("compiler"), Some("compiler"), true),
                ),
            ]);
            let details = render_diagnostics_text(&items);
            if !details.is_empty() {
                out.push('\n');
                out.push_str(&details);
            }
            Ok(out)
        }
        Format::Json => Ok(serde_json::json!({
            "status": status,
            "mode": "lint",
            "tier": tier,
            "errors": errors,
            "warnings": warnings,
            "items": items,
            "policy": {
                "profile": "verify",
                "unsafeEnforcement": "strict",
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": "present-or-created",
            }
        })
        .to_string()),
    }
}

fn normalize_lint_tier(tier: &str) -> Result<&'static str> {
    match tier.trim().to_ascii_lowercase().as_str() {
        "" | "production" => Ok("production"),
        "pedantic" => Ok("pedantic"),
        "compat" => Ok("compat"),
        _ => bail!("invalid lint tier `{tier}`; expected production|pedantic|compat"),
    }
}

fn collect_lint_sources(path: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    if path.is_file() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading {}", path.display()))?;
        out.push((path.to_path_buf(), text));
        return Ok(out);
    }
    if !path.is_dir() {
        bail!(
            "lint target must be a file or project directory: {}",
            path.display()
        );
    }
    let roots = discover_project_roots(path)?;
    if roots.is_empty() {
        bail!("no project roots found under {}", path.display());
    }
    for root in roots {
        let src = root.join("src");
        if !src.exists() {
            continue;
        }
        for file in walk_fzy_files(&src)? {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("failed reading {}", file.display()))?;
            out.push((file, text));
        }
    }
    Ok(out)
}

fn walk_fzy_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading directory {}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|v| v.to_str()) == Some("fzy") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn pedantic_lint_findings(path: &Path) -> Result<Vec<diagnostics::Diagnostic>> {
    let sources = collect_lint_sources(path)?;
    let mut out = Vec::new();
    for (file, text) in sources {
        if text.contains("discard ") && !text.contains("requires ") {
            out.push(
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Warning,
                    "pedantic lint: module uses `discard` without explicit contract clauses",
                    Some(
                        "prefer adding requires/ensures to make side-effect expectations explicit"
                            .to_string(),
                    ),
                )
                .with_path(file.display().to_string()),
            );
        }
        if text.matches("spawn(").count() > text.matches("yield()").count().saturating_add(2) {
            out.push(
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Warning,
                    "pedantic lint: spawn/yield imbalance may increase starvation pressure",
                    Some("add yield/checkpoint/join boundaries to keep scheduler pressure visible and bounded".to_string()),
                )
                .with_path(file.display().to_string()),
            );
        }
    }
    diagnostics::assign_stable_codes(&mut out, diagnostics::DiagnosticDomain::Driver);
    Ok(out)
}

fn compat_lint_findings(path: &Path) -> Result<Vec<diagnostics::Diagnostic>> {
    let sources = collect_lint_sources(path)?;
    let mut out = Vec::new();
    for (file, text) in sources {
        if text.contains("unsafe_reason(") || text.contains("unsafe(") {
            out.push(
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Warning,
                    "compat lint: removed unsafe metadata syntax detected",
                    Some("migrate to first-class `unsafe fn` / `unsafe { ... }` with compiler-generated contract docs".to_string()),
                )
                .with_path(file.display().to_string()),
            );
        }
        if text.contains("extern \"C\"") {
            out.push(
                diagnostics::Diagnostic::new(
                    diagnostics::Severity::Warning,
                    "compat lint: legacy extern syntax detected",
                    Some("prefer `pubext c fn` / `ext unsafe c fn` for production C interop contracts".to_string()),
                )
                .with_path(file.display().to_string()),
            );
        }
    }
    diagnostics::assign_stable_codes(&mut out, diagnostics::DiagnosticDomain::Driver);
    Ok(out)
}

fn production_lint_findings(path: &Path) -> Result<Vec<diagnostics::Diagnostic>> {
    let mut out = Vec::new();
    if path.is_dir() {
        let roots = discover_project_roots(path)?;
        for root in roots {
            let manifest_path = root.join("fozzy.toml");
            if !manifest_path.exists() {
                continue;
            }
            let text = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("failed reading {}", manifest_path.display()))?;
            let manifest = manifest::load(&text).context("failed parsing fozzy.toml")?;
            if manifest.unsafe_policy.enforce_verify == Some(false)
                || manifest.unsafe_policy.enforce_release == Some(false)
            {
                out.push(
                    diagnostics::Diagnostic::new(
                        diagnostics::Severity::Warning,
                        "production lint: unsafe enforcement is relaxed",
                        Some(
                            "set [unsafe].enforce_verify=true and enforce_release=true".to_string(),
                        ),
                    )
                    .with_path(manifest_path.display().to_string()),
                );
            }
        }
    }
    diagnostics::assign_stable_codes(&mut out, diagnostics::DiagnosticDomain::Driver);
    Ok(out)
}

