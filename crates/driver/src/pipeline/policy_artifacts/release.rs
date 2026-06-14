fn release_policy_error_classes() -> &'static [(&'static str, &'static str, &'static [&'static str])]
{
    &[
        ("transport", "boundary and IO failures at runtime or service edges", &["Io"]),
        ("parse", "invalid input and decode failures", &["InvalidInput"]),
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
        ("compiler_parse_lower_build", "compiler parse, lower, and build time"),
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

pub(super) fn build_release_policy_json() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "fozzylang.release_policy.v1",
        "versions": super::compat::compatibility_versions_json(),
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
            "summaryCommand": "fz perf [--artifact artifacts/bench_core_rust_vs_fzy.json]",
            "benchmarkArtifact": "artifacts/bench_core_rust_vs_fzy.json",
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

pub(super) fn render_release_policy_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# Release Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Compatibility set required: `{}`\n- Benchmark artifact: `{}`\n- Stability dashboard command: `{}`\n\n",
        value["schemaVersion"].as_str().unwrap_or("unknown"),
        value["releaseGating"]["compatibilitySetRequired"]
            .as_bool()
            .unwrap_or(false),
        value["performance"]["benchmarkArtifact"]
            .as_str()
            .unwrap_or("artifacts/bench_core_rust_vs_fzy.json"),
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
        value["errorModel"]["cliMainReturn"].as_str().unwrap_or("i32"),
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
