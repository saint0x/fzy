use std::path::Path;

use anyhow::{Context, Result};

use super::*;

pub(super) fn write_safety_artifacts(
    project_root: &Path,
    parsed: &ParsedProgram,
    fir: &fir::FirModule,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let out_dir = project_root.join(".fz");
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed creating safety artifact dir: {}", out_dir.display()))?;

    let memory_json = build_memory_report_json(fir);
    write_artifact_if_changed(
        &out_dir.join("memory-report.json"),
        &serde_json::to_vec_pretty(&memory_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("memory-report.md"),
        render_memory_report_markdown(&memory_json).as_bytes(),
    )?;

    let unsafe_json = build_unsafe_report_json(fir);
    write_artifact_if_changed(
        &out_dir.join("unsafe-report.json"),
        &serde_json::to_vec_pretty(&unsafe_json)?,
    )?;

    let async_json = build_async_safety_json(fir);
    write_artifact_if_changed(
        &out_dir.join("async-safety.json"),
        &serde_json::to_vec_pretty(&async_json)?,
    )?;

    let rpc_json = build_rpc_safety_json(&parsed.module, fir);
    write_artifact_if_changed(
        &out_dir.join("rpc-safety.json"),
        &serde_json::to_vec_pretty(&rpc_json)?,
    )?;

    let ffi_json = build_ffi_report_json(fir);
    write_artifact_if_changed(
        &out_dir.join("ffi-report.json"),
        &serde_json::to_vec_pretty(&ffi_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("ffi-report.md"),
        render_ffi_report_markdown(&ffi_json).as_bytes(),
    )?;

    let runtime_contracts_json = build_native_runtime_contracts_json();
    write_artifact_if_changed(
        &out_dir.join("native-runtime-contracts.json"),
        &serde_json::to_vec_pretty(&runtime_contracts_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("native-runtime-contracts.md"),
        render_native_runtime_contracts_markdown(&runtime_contracts_json).as_bytes(),
    )?;

    let handle_contracts_json = build_handle_contracts_json();
    write_artifact_if_changed(
        &out_dir.join("handle-contracts.json"),
        &serde_json::to_vec_pretty(&handle_contracts_json)?,
    )?;

    let language_policy_json = build_language_policy_json(manifest);
    write_artifact_if_changed(
        &out_dir.join("language-policy.json"),
        &serde_json::to_vec_pretty(&language_policy_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("language-policy.md"),
        render_language_policy_markdown(&language_policy_json).as_bytes(),
    )?;

    let release_policy_json = build_release_policy_json();
    write_artifact_if_changed(
        &out_dir.join("release-policy.json"),
        &serde_json::to_vec_pretty(&release_policy_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("release-policy.md"),
        render_release_policy_markdown(&release_policy_json).as_bytes(),
    )?;

    let stdlib_policy_json = build_stdlib_capability_policy_json();
    write_artifact_if_changed(
        &out_dir.join("stdlib-capability-policy.json"),
        &serde_json::to_vec_pretty(&stdlib_policy_json)?,
    )?;
    write_artifact_if_changed(
        &out_dir.join("stdlib-capability-policy.md"),
        render_stdlib_capability_policy_markdown(&stdlib_policy_json).as_bytes(),
    )?;

    Ok(())
}

fn write_artifact_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    std::fs::write(path, bytes)
        .with_context(|| format!("failed writing {}", path.display()))
}

pub(super) fn compatibility_versions_json() -> serde_json::Value {
    let compatibility = fzscenario::compatibility_info();
    serde_json::json!({
        "languageVersion": compatibility.language_version,
        "traceSchemaVersion": compatibility.trace_schema_version,
        "manifestSchemaVersion": compatibility.manifest_schema_version,
        "runtimeAbiVersion": compatibility.runtime_abi_version,
        "nativeImportTableVersion": compatibility.native_import_table_version,
        "diagnosticCatalogVersion": compatibility.diagnostic_catalog_version,
    })
}

fn syntax_freeze_entries() -> &'static [(&'static str, &'static str)] {
    &[
        ("fn", "function declarations"),
        ("let", "immutable bindings"),
        ("let mut", "mutable bindings"),
        ("struct", "struct declarations"),
        ("enum", "enum declarations"),
        ("match", "pattern matching"),
        ("trait", "trait declarations"),
        ("impl", "impl blocks"),
        ("async", "async declarations"),
        ("await", "async suspension"),
        ("rpc", "rpc declarations"),
        ("unsafe metadata", "compiler-generated unsafe contracts"),
        ("defer", "scope cleanup"),
        ("use core.*", "capability and stdlib imports"),
        ("extern", "external ABI imports"),
        ("pubext", "public ABI exports"),
    ]
}

fn default_profile_backend(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::Dev => "cranelift",
        BuildProfile::Release | BuildProfile::Verify | BuildProfile::Strict => "llvm",
    }
}

fn default_profile_optimize(profile: BuildProfile) -> bool {
    !matches!(profile, BuildProfile::Dev)
}

fn default_profile_optimization_level(profile: BuildProfile) -> &'static str {
    match profile {
        BuildProfile::Dev => "O0",
        BuildProfile::Verify => "O1+g",
        BuildProfile::Strict => "O2+g",
        BuildProfile::Release => "O3",
    }
}

fn default_profile_diagnostic_strictness(profile: BuildProfile) -> &'static str {
    if matches!(profile, BuildProfile::Strict) {
        "strict"
    } else {
        "standard"
    }
}

fn resolved_profile_emit_safety_artifacts(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> bool {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.emit_safety_artifacts)
        .unwrap_or(true)
}

fn resolved_profile_checks(manifest: Option<&manifest::Manifest>, profile: BuildProfile) -> bool {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.checks)
        .unwrap_or(true)
}

fn resolved_profile_backend(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> String {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.backend.clone())
        .unwrap_or_else(|| default_profile_backend(profile).to_string())
}

fn resolved_profile_optimize(manifest: Option<&manifest::Manifest>, profile: BuildProfile) -> bool {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize)
        .unwrap_or_else(|| default_profile_optimize(profile))
}

fn resolved_profile_diagnostic_strictness(
    manifest: Option<&manifest::Manifest>,
    profile: BuildProfile,
) -> String {
    manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.diagnostic_strictness.clone())
        .unwrap_or_else(|| default_profile_diagnostic_strictness(profile).to_string())
}

fn safety_artifact_names() -> &'static [&'static str] {
    &[
        "memory-report.json",
        "memory-report.md",
        "unsafe-report.json",
        "async-safety.json",
        "rpc-safety.json",
        "ffi-report.json",
        "ffi-report.md",
        "native-runtime-contracts.json",
        "native-runtime-contracts.md",
        "handle-contracts.json",
        "language-policy.json",
        "language-policy.md",
        "release-policy.json",
        "release-policy.md",
        "stdlib-capability-policy.json",
        "stdlib-capability-policy.md",
    ]
}

fn build_language_policy_json(manifest: Option<&manifest::Manifest>) -> serde_json::Value {
    let profiles = [
        BuildProfile::Dev,
        BuildProfile::Verify,
        BuildProfile::Release,
        BuildProfile::Strict,
    ]
    .into_iter()
    .map(|profile| {
        let profile_name = profile.as_str();
        (
            profile_name.to_string(),
            serde_json::json!({
                "checksEnabled": resolved_profile_checks(manifest, profile),
                "unsafeContractsEnforced": unsafe_contracts_enforced(manifest, profile),
                "backend": resolved_profile_backend(manifest, profile),
                "runtimeImportsAllowed": "declared_native_runtime_contracts_only",
                "capabilityPolicy": "explicit_compiler_checked",
                "emitSafetyArtifacts": resolved_profile_emit_safety_artifacts(manifest, profile),
                "optimize": resolved_profile_optimize(manifest, profile),
                "optimizationLevel": default_profile_optimization_level(profile),
                "diagnosticStrictness": resolved_profile_diagnostic_strictness(manifest, profile),
                "experimentalFeaturesAllowed": manifest.map(|m| m.language.tier == "experimental" && m.language.allow_experimental).unwrap_or(false),
                "artifactEmission": safety_artifact_names(),
            }),
        )
    })
    .collect::<serde_json::Map<String, serde_json::Value>>();
    serde_json::json!({
        "schemaVersion": "fozzylang.language_policy.v1",
        "versions": compatibility_versions_json(),
        "language": {
            "defaultTier": manifest.map(|m| m.language.tier.as_str()).unwrap_or("core_v1"),
            "experimentalOptInRequired": true,
            "allowExperimental": manifest.map(|m| m.language.allow_experimental).unwrap_or(false),
            "changePolicy": "additive_only",
        },
        "syntaxFreeze": {
            "frozen": true,
            "surface": syntax_freeze_entries().iter().map(|(name, description)| {
                serde_json::json!({
                    "name": name,
                    "description": description,
                })
            }).collect::<Vec<_>>(),
        },
        "profiles": profiles,
    })
}

fn render_language_policy_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# Language Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Language tier: `{}`\n- Experimental opt-in required: `{}`\n- Change policy: `{}`\n\n",
        value["schemaVersion"].as_str().unwrap_or("unknown"),
        value["language"]["defaultTier"].as_str().unwrap_or("core_v1"),
        value["language"]["experimentalOptInRequired"].as_bool().unwrap_or(true),
        value["language"]["changePolicy"].as_str().unwrap_or("additive_only"),
    ));
    out.push_str("## Syntax Freeze\n\n");
    if let Some(items) = value["syntaxFreeze"]["surface"].as_array() {
        for item in items {
            out.push_str(&format!(
                "- `{}`: {}\n",
                item["name"].as_str().unwrap_or("?"),
                item["description"].as_str().unwrap_or("?")
            ));
        }
    }
    out.push_str("\n## Profiles\n\n");
    out.push_str("| Profile | Checks | Unsafe | Backend | Runtime Imports | Capabilities | Emit Safety Artifacts | Optimize | Optimization | Diagnostics |\n|---|---|---|---|---|---|---|---|---|---|\n");
    if let Some(profiles) = value["profiles"].as_object() {
        for (name, profile) in profiles {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
                name,
                profile["checksEnabled"].as_bool().unwrap_or(true),
                profile["unsafeContractsEnforced"]
                    .as_bool()
                    .unwrap_or(false),
                profile["backend"].as_str().unwrap_or("?"),
                profile["runtimeImportsAllowed"].as_str().unwrap_or("?"),
                profile["capabilityPolicy"].as_str().unwrap_or("?"),
                profile["emitSafetyArtifacts"].as_bool().unwrap_or(true),
                profile["optimize"].as_bool().unwrap_or(false),
                profile["optimizationLevel"].as_str().unwrap_or("?"),
                profile["diagnosticStrictness"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}

fn release_policy_error_classes() -> &'static [(&'static str, &'static str, &'static [&'static str])]
{
    &[
        (
            "transport",
            "boundary and IO failures at runtime or service edges",
            &["Io"],
        ),
        (
            "parse",
            "invalid input and decode failures",
            &["InvalidInput"],
        ),
        ("timeout", "deadline and wait exhaustion", &["Timeout"]),
        (
            "policy",
            "capability, conflict, and safety-policy violations",
            &["Conflict"],
        ),
        (
            "internal",
            "not-found and internal runtime/compiler failure states",
            &["NotFound", "Internal"],
        ),
    ]
}

fn release_policy_benchmark_lanes() -> &'static [(&'static str, &'static str)] {
    &[
        ("cli_startup", "CLI startup latency"),
        ("http_throughput", "HTTP request throughput"),
        ("json_build_parse", "JSON construction and parsing"),
        ("proc_spawn_wait", "process spawn and wait"),
        ("stream_reading", "stream reading throughput"),
        ("task_group_execution", "task-group execution"),
        (
            "compiler_parse_lower_build",
            "compiler parse, lower, and build time",
        ),
        ("native_binary_size", "native binary size"),
    ]
}

fn release_policy_doc_surfaces() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        (
            "language-policy",
            ".fz/language-policy.json + .fz/language-policy.md",
            "compiler syntax-freeze and profile metadata",
        ),
        (
            "native-runtime-contracts",
            ".fz/native-runtime-contracts.json + .fz/native-runtime-contracts.md",
            "native runtime contract table",
        ),
        (
            "release-policy",
            ".fz/release-policy.json + .fz/release-policy.md",
            "compiler release-policy metadata",
        ),
        (
            "diagnostic-catalog",
            "fz explain catalog --json",
            "diagnostic catalog metadata",
        ),
        (
            "stability-dashboard",
            "artifacts/stability_dashboard.json",
            "exit criteria and perf-source metadata",
        ),
    ]
}

fn build_release_policy_json() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "fozzylang.release_policy.v1",
        "versions": compatibility_versions_json(),
        "errorModel": {
            "serviceFunctionsReturn": "Result<T, Error>",
            "statusType": "Status",
            "errorClassType": "ErrorClass",
            "exitStatusType": "ExitStatus",
            "runtimeErrorType": "RuntimeError",
            "cliMainReturn": "i32",
            "httpHandlersReturn": "i32_after_writing_response",
            "runtimeInternalsReturn": "typed_status_or_result",
            "errorClasses": release_policy_error_classes().iter().map(|(name, description, codes)| {
                serde_json::json!({
                    "name": name,
                    "description": description,
                    "mapsFromErrorCodes": codes,
                })
            }).collect::<Vec<_>>(),
        },
        "performance": {
            "summaryCommand": "fz perf [--artifact artifacts/bench_corelibs_rust_vs_fzy.json]",
            "benchmarkArtifact": "artifacts/bench_corelibs_rust_vs_fzy.json",
            "stabilityDashboardCommand": "fz stability-dashboard",
            "workloads": release_policy_benchmark_lanes().iter().map(|(name, description)| {
                serde_json::json!({
                    "name": name,
                    "description": description,
                })
            }).collect::<Vec<_>>(),
        },
        "documentation": {
            "implementationBacked": true,
            "surfaces": release_policy_doc_surfaces().iter().map(|(name, output, source)| {
                serde_json::json!({
                    "name": name,
                    "output": output,
                    "source": source,
                })
            }).collect::<Vec<_>>(),
        },
        "releaseGating": {
            "compatibilitySetRequired": true,
            "traceReplayCompatibilityRequired": true,
            "diagnosticCatalogStabilityRequired": true,
            "backendParityRequired": true,
        },
    })
}

fn render_release_policy_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# Release Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Compatibility set required: `{}`\n- Benchmark artifact: `{}`\n- Stability dashboard command: `{}`\n\n",
        value["schemaVersion"].as_str().unwrap_or("unknown"),
        value["releaseGating"]["compatibilitySetRequired"]
            .as_bool()
            .unwrap_or(false),
        value["performance"]["benchmarkArtifact"]
            .as_str()
            .unwrap_or("artifacts/bench_corelibs_rust_vs_fzy.json"),
        value["performance"]["stabilityDashboardCommand"]
            .as_str()
            .unwrap_or("fz stability-dashboard"),
    ));
    out.push_str("## Compatibility\n\n");
    if let Some(versions) = value["versions"].as_object() {
        for (name, version) in versions {
            out.push_str(&format!(
                "- `{}`: `{}`\n",
                name,
                version.as_str().unwrap_or("unknown")
            ));
        }
    }
    out.push_str("\n## Error Model\n\n");
    out.push_str(&format!(
        "- Service functions: `{}`\n- CLI main: `{}`\n- HTTP handlers: `{}`\n- Runtime internals: `{}`\n\n",
        value["errorModel"]["serviceFunctionsReturn"]
            .as_str()
            .unwrap_or("Result<T, Error>"),
        value["errorModel"]["cliMainReturn"]
            .as_str()
            .unwrap_or("i32"),
        value["errorModel"]["httpHandlersReturn"]
            .as_str()
            .unwrap_or("i32_after_writing_response"),
        value["errorModel"]["runtimeInternalsReturn"]
            .as_str()
            .unwrap_or("typed_status_or_result"),
    ));
    if let Some(classes) = value["errorModel"]["errorClasses"].as_array() {
        for class in classes {
            out.push_str(&format!(
                "- `{}`: {} (codes: {})\n",
                class["name"].as_str().unwrap_or("unknown"),
                class["description"].as_str().unwrap_or("unknown"),
                class["mapsFromErrorCodes"]
                    .as_array()
                    .map(|codes| codes
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
    }
    out.push_str("\n## Benchmark Lanes\n\n");
    if let Some(workloads) = value["performance"]["workloads"].as_array() {
        for workload in workloads {
            out.push_str(&format!(
                "- `{}`: {}\n",
                workload["name"].as_str().unwrap_or("unknown"),
                workload["description"].as_str().unwrap_or("unknown"),
            ));
        }
    }
    out.push_str("\n## Implementation-Backed Docs\n\n");
    if let Some(surfaces) = value["documentation"]["surfaces"].as_array() {
        for surface in surfaces {
            out.push_str(&format!(
                "- `{}`: {} (`{}`)\n",
                surface["name"].as_str().unwrap_or("unknown"),
                surface["output"].as_str().unwrap_or("unknown"),
                surface["source"].as_str().unwrap_or("unknown"),
            ));
        }
    }
    out
}

fn stdlib_contract_rows() -> &'static [(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)] {
    &[
        (
            "core.mem",
            "mem",
            "owned values + explicit alloc/free lifecycle",
            "runtime status + verifier ownership diagnostics",
            "heap pointers and owned allocations are linear",
            "cleanup with `free(...)` or `defer free(...)`",
            "thread-safe only through owned handoff; not raw-borrow safe across async/task boundaries",
        ),
        (
            "core.http",
            "http",
            "request/response bodies and network handles are owned",
            "parse vs timeout vs transport errors remain distinct",
            "HttpHandle/HttpStreamHandle/WebSocketHandle are linear",
            "cleanup with `close(...)`, `http.stream_close(...)`, or `http.websocket_close(...)`",
            "not send-safe; async-stable for owned handles only",
        ),
        (
            "core.proc",
            "proc",
            "argv/env builders and process handles are owned",
            "runtime status + last-error boundary",
            "ProcessArgv/ProcessEnv/ProcessHandle are linear",
            "cleanup with `proc.close(...)`; builders must be consumed by spawn/run",
            "process handles are async-stable but not send-safe; builders are neither",
        ),
        (
            "core.fs",
            "fs",
            "file handles are owned; path arguments are borrowed",
            "runtime status + host error mapping",
            "FileHandle is linear",
            "cleanup with `fs.close(...)`; durable writes prefer `fs.atomic_write(...)`",
            "file handles are async-stable but not send-safe",
        ),
        (
            "core.thread",
            "thread",
            "task handles and task groups are owned linear resources",
            "task result / cancellation / timeout policy is explicit",
            "TaskHandle and TaskGroupHandle are linear",
            "terminate with `join`, `detach`, `cancel_task`, `task.group_join_all`, or `task.group_cancel`",
            "send-safe task handles/groups only; borrowed values may not cross task boundaries",
        ),
        (
            "core.time",
            "time",
            "time values are plain owned data",
            "status-free deterministic time/runtime APIs",
            "no linear handles",
            "no explicit cleanup required",
            "thread-safe and async-safe",
        ),
        (
            "core.crypto",
            "rng",
            "crypto outputs are owned plain values",
            "decode and runtime-status failures are explicit",
            "no linear handles",
            "no explicit cleanup required",
            "thread-safe and async-safe; secret comparisons should use constant-time helpers",
        ),
        (
            "core.json",
            "http|fs|proc boundary payloads",
            "JSON stays at boundaries; typed structs/enums stay inside",
            "parse failures stay explicit; raw injection is policy-checked",
            "JsonHandle/ListHandle/MapHandle are owned non-linear handles",
            "no explicit cleanup; avoid `json.raw(...)` except for primitive/raw boundary escapes",
            "send-safe and async-stable owned collection handles",
        ),
        (
            "core.log",
            "log",
            "log payload maps/strings are owned values",
            "runtime status for sink/config failures",
            "no linear handles",
            "no explicit cleanup required",
            "thread-safe and async-safe logging facade",
        ),
    ]
}

fn stdlib_hazard_policies() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        (
            "json_raw_composite_or_dynamic_injection",
            "warning",
            "prefer `json.object`, `json.array`, or `json.str` over `json.raw(...)` for composite or user-shaped payloads",
        ),
        (
            "path_traversal_literal",
            "warning",
            "literal filesystem paths containing `..` are rejected as traversal-prone in strict mode",
        ),
        (
            "shell_process_builder",
            "warning",
            "shell command construction through `sh`/`bash` and `-c` is flagged in strict mode; prefer direct argv builders",
        ),
        (
            "tempfile_non_atomic_write",
            "warning",
            "writing directly into `/tmp` or `/var/tmp` is flagged when a durable atomic write is expected",
        ),
        (
            "http_header_non_normalized",
            "warning",
            "HTTP headers should be lowercase normalized tokens in strict mode",
        ),
        (
            "crypto_secret_eq",
            "warning",
            "secret-bearing comparisons should use `crypto.constant_time_eq` or `security.secure_eq`",
        ),
    ]
}

fn build_stdlib_capability_policy_json() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "fozzylang.stdlib_capability_policy.v1",
        "versions": compatibility_versions_json(),
        "capabilityPolicy": {
            "propagation": "explicit_compiler_checked",
            "tokenDelegation": "compiler_enforced_subset_only",
            "missingCapabilityPolicy": "error",
            "missingTokenPolicy": "error",
        },
        "jsonBoundaryRule": {
            "boundary": "json_at_boundaries",
            "inside": "typed_structs_and_enums",
            "strictRawPolicy": "warn_on_composite_or_dynamic_json_raw",
        },
        "modules": stdlib_contract_rows().iter().map(|(module, capability, ownership, error, handles, cleanup, safety)| {
            serde_json::json!({
                "module": module,
                "capability": capability,
                "ownershipBehavior": ownership,
                "errorBehavior": error,
                "linearHandles": handles,
                "cleanupRequirement": cleanup,
                "threadAsyncSafety": safety,
            })
        }).collect::<Vec<_>>(),
        "strictHazards": stdlib_hazard_policies().iter().map(|(kind, severity, policy)| {
            serde_json::json!({
                "kind": kind,
                "severity": severity,
                "policy": policy,
            })
        }).collect::<Vec<_>>(),
    })
}

fn render_stdlib_capability_policy_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# Stdlib Capability Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Capability propagation: `{}`\n- Token delegation: `{}`\n- JSON boundary rule: `{}` / `{}`\n\n",
        value["schemaVersion"].as_str().unwrap_or("unknown"),
        value["capabilityPolicy"]["propagation"].as_str().unwrap_or("unknown"),
        value["capabilityPolicy"]["tokenDelegation"].as_str().unwrap_or("unknown"),
        value["jsonBoundaryRule"]["boundary"].as_str().unwrap_or("json_at_boundaries"),
        value["jsonBoundaryRule"]["inside"].as_str().unwrap_or("typed_structs_and_enums"),
    ));
    out.push_str("## Module Contracts\n\n");
    out.push_str("| Module | Capability | Ownership | Errors | Linear Handles | Cleanup | Thread/Async Safety |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    if let Some(modules) = value["modules"].as_array() {
        for module in modules {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} | {} | {} | {} |\n",
                module["module"].as_str().unwrap_or("unknown"),
                module["capability"].as_str().unwrap_or("unknown"),
                module["ownershipBehavior"].as_str().unwrap_or("unknown"),
                module["errorBehavior"].as_str().unwrap_or("unknown"),
                module["linearHandles"].as_str().unwrap_or("unknown"),
                module["cleanupRequirement"].as_str().unwrap_or("unknown"),
                module["threadAsyncSafety"].as_str().unwrap_or("unknown"),
            ));
        }
    }
    out.push_str("\n## Strict Hazards\n\n");
    if let Some(hazards) = value["strictHazards"].as_array() {
        for hazard in hazards {
            out.push_str(&format!(
                "- `{}` (`{}`): {}\n",
                hazard["kind"].as_str().unwrap_or("unknown"),
                hazard["severity"].as_str().unwrap_or("warning"),
                hazard["policy"].as_str().unwrap_or("unknown"),
            ));
        }
    }
    out
}
