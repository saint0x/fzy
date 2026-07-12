use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(super) struct StdlibCapabilityPolicyReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: super::compat::CompatibilityVersions,
    #[serde(rename = "capabilityPolicy")]
    capability_policy: CapabilityPolicy,
    #[serde(rename = "jsonBoundaryRule")]
    json_boundary_rule: JsonBoundaryRule,
    modules: Vec<StdlibModuleContract>,
    #[serde(rename = "strictHazards")]
    strict_hazards: Vec<StrictHazardPolicy>,
}

#[derive(Debug, Clone, Serialize)]
struct CapabilityPolicy {
    propagation: &'static str,
    #[serde(rename = "tokenDelegation")]
    token_delegation: &'static str,
    #[serde(rename = "missingCapabilityPolicy")]
    missing_capability_policy: &'static str,
    #[serde(rename = "missingTokenPolicy")]
    missing_token_policy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct JsonBoundaryRule {
    boundary: &'static str,
    inside: &'static str,
    #[serde(rename = "strictRawPolicy")]
    strict_raw_policy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct StdlibModuleContract {
    module: &'static str,
    capability: &'static str,
    #[serde(rename = "ownershipBehavior")]
    ownership_behavior: &'static str,
    #[serde(rename = "errorBehavior")]
    error_behavior: &'static str,
    #[serde(rename = "linearHandles")]
    linear_handles: &'static str,
    #[serde(rename = "cleanupRequirement")]
    cleanup_requirement: &'static str,
    #[serde(rename = "threadAsyncSafety")]
    thread_async_safety: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct StrictHazardPolicy {
    kind: &'static str,
    severity: &'static str,
    policy: &'static str,
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
            "core.bytes",
            "none",
            "byte buffers are owned non-linear values",
            "runtime status + last-error boundary for malformed/bounds-checked reads",
            "BytesHandle is an owned non-linear handle",
            "no explicit cleanup; derive slices/views through `bytes.slice(...)`",
            "send-safe and async-stable owned byte buffers",
        ),
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

pub(super) fn build_stdlib_capability_policy_report() -> StdlibCapabilityPolicyReport {
    StdlibCapabilityPolicyReport {
        schema_version: "fozzylang.stdlib_capability_policy.v1",
        versions: super::compat::compatibility_versions(),
        capability_policy: CapabilityPolicy {
            propagation: "explicit_compiler_checked",
            token_delegation: "compiler_enforced_subset_only",
            missing_capability_policy: "error",
            missing_token_policy: "error",
        },
        json_boundary_rule: JsonBoundaryRule {
            boundary: "json_at_boundaries",
            inside: "typed_structs_and_enums",
            strict_raw_policy: "warn_on_composite_or_dynamic_json_raw",
        },
        modules: stdlib_contract_rows()
            .iter()
            .map(
                |(module, capability, ownership, error, handles, cleanup, safety)| {
                    StdlibModuleContract {
                        module,
                        capability,
                        ownership_behavior: ownership,
                        error_behavior: error,
                        linear_handles: handles,
                        cleanup_requirement: cleanup,
                        thread_async_safety: safety,
                    }
                },
            )
            .collect(),
        strict_hazards: stdlib_hazard_policies()
            .iter()
            .map(|(kind, severity, policy)| StrictHazardPolicy {
                kind,
                severity,
                policy,
            })
            .collect(),
    }
}

pub(super) fn render_stdlib_capability_policy_markdown(
    report: &StdlibCapabilityPolicyReport,
) -> String {
    let mut out = String::from("# Stdlib Capability Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Capability propagation: `{}`\n- Token delegation: `{}`\n- JSON boundary rule: `{}` / `{}`\n\n",
        report.schema_version,
        report.capability_policy.propagation,
        report.capability_policy.token_delegation,
        report.json_boundary_rule.boundary,
        report.json_boundary_rule.inside,
    ));
    out.push_str("## Module Contracts\n\n");
    out.push_str("| Module | Capability | Ownership | Errors | Linear Handles | Cleanup | Thread/Async Safety |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for module in &report.modules {
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} | {} |\n",
            module.module,
            module.capability,
            module.ownership_behavior,
            module.error_behavior,
            module.linear_handles,
            module.cleanup_requirement,
            module.thread_async_safety,
        ));
    }
    out.push_str("\n## Strict Hazards\n\n");
    for hazard in &report.strict_hazards {
        out.push_str(&format!(
            "- `{}` (`{}`): {}\n",
            hazard.kind, hazard.severity, hazard.policy,
        ));
    }
    out
}
