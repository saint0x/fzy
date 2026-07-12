use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(super) struct ReleasePolicyReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: super::compat::CompatibilityVersions,
    #[serde(rename = "errorModel")]
    error_model: ErrorModel,
    performance: PerformancePolicy,
    documentation: DocumentationPolicy,
    #[serde(rename = "releaseGating")]
    release_gating: ReleaseGating,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorModel {
    #[serde(rename = "serviceFunctionsReturn")]
    service_functions_return: &'static str,
    #[serde(rename = "statusType")]
    status_type: &'static str,
    #[serde(rename = "errorClassType")]
    error_class_type: &'static str,
    #[serde(rename = "exitStatusType")]
    exit_status_type: &'static str,
    #[serde(rename = "runtimeErrorType")]
    runtime_error_type: &'static str,
    #[serde(rename = "cliMainReturn")]
    cli_main_return: &'static str,
    #[serde(rename = "httpHandlersReturn")]
    http_handlers_return: &'static str,
    #[serde(rename = "runtimeInternalsReturn")]
    runtime_internals_return: &'static str,
    #[serde(rename = "errorClasses")]
    error_classes: Vec<ErrorClassPolicy>,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorClassPolicy {
    name: &'static str,
    description: &'static str,
    #[serde(rename = "mapsFromErrorCodes")]
    maps_from_error_codes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
struct PerformancePolicy {
    #[serde(rename = "summaryCommand")]
    summary_command: &'static str,
    #[serde(rename = "benchmarkArtifact")]
    benchmark_artifact: &'static str,
    #[serde(rename = "stabilityDashboardCommand")]
    stability_dashboard_command: &'static str,
    workloads: Vec<NamedDescription>,
}

#[derive(Debug, Clone, Serialize)]
struct NamedDescription {
    name: &'static str,
    description: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct DocumentationPolicy {
    #[serde(rename = "implementationBacked")]
    implementation_backed: bool,
    surfaces: Vec<DocumentationSurface>,
}

#[derive(Debug, Clone, Serialize)]
struct DocumentationSurface {
    name: &'static str,
    output: &'static str,
    source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReleaseGating {
    #[serde(rename = "compatibilitySetRequired")]
    compatibility_set_required: bool,
    #[serde(rename = "traceReplayCompatibilityRequired")]
    trace_replay_compatibility_required: bool,
    #[serde(rename = "diagnosticCatalogStabilityRequired")]
    diagnostic_catalog_stability_required: bool,
    #[serde(rename = "backendParityRequired")]
    backend_parity_required: bool,
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

pub(super) fn build_release_policy_report() -> ReleasePolicyReport {
    ReleasePolicyReport {
        schema_version: "fozzylang.release_policy.v1",
        versions: super::compat::compatibility_versions(),
        error_model: ErrorModel {
            service_functions_return: "Result<T, Error>",
            status_type: "Status",
            error_class_type: "ErrorClass",
            exit_status_type: "ExitStatus",
            runtime_error_type: "RuntimeError",
            cli_main_return: "i32",
            http_handlers_return: "i32_after_writing_response",
            runtime_internals_return: "typed_status_or_result",
            error_classes: release_policy_error_classes()
                .iter()
                .map(|(name, description, codes)| ErrorClassPolicy {
                    name,
                    description,
                    maps_from_error_codes: codes.to_vec(),
                })
                .collect(),
        },
        performance: PerformancePolicy {
            summary_command: "fz perf [--artifact artifacts/bench_core_rust_vs_fzy.json]",
            benchmark_artifact: "artifacts/bench_core_rust_vs_fzy.json",
            stability_dashboard_command: "fz stability-dashboard",
            workloads: release_policy_benchmark_lanes()
                .iter()
                .map(|(name, description)| NamedDescription { name, description })
                .collect(),
        },
        documentation: DocumentationPolicy {
            implementation_backed: true,
            surfaces: release_policy_doc_surfaces()
                .iter()
                .map(|(name, output, source)| DocumentationSurface {
                    name,
                    output,
                    source,
                })
                .collect(),
        },
        release_gating: ReleaseGating {
            compatibility_set_required: true,
            trace_replay_compatibility_required: true,
            diagnostic_catalog_stability_required: true,
            backend_parity_required: true,
        },
    }
}

pub(super) fn render_release_policy_markdown(report: &ReleasePolicyReport) -> String {
    let mut out = String::from("# Release Policy\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Compatibility set required: `{}`\n- Benchmark artifact: `{}`\n- Stability dashboard command: `{}`\n\n",
        report.schema_version,
        report.release_gating.compatibility_set_required,
        report.performance.benchmark_artifact,
        report.performance.stability_dashboard_command,
    ));
    out.push_str("## Compatibility\n\n");
    out.push_str(&format!(
        "- `languageVersion`: `{}`\n- `traceSchemaVersion`: `{}`\n- `manifestSchemaVersion`: `{}`\n- `runtimeAbiVersion`: `{}`\n- `nativeImportTableVersion`: `{}`\n- `diagnosticCatalogVersion`: `{}`\n",
        report.versions.language_version,
        report.versions.trace_schema_version,
        report.versions.manifest_schema_version,
        report.versions.runtime_abi_version,
        report.versions.native_import_table_version,
        report.versions.diagnostic_catalog_version,
    ));
    out.push_str("\n## Error Model\n\n");
    out.push_str(&format!(
        "- Service functions: `{}`\n- CLI main: `{}`\n- HTTP handlers: `{}`\n- Runtime internals: `{}`\n\n",
        report.error_model.service_functions_return,
        report.error_model.cli_main_return,
        report.error_model.http_handlers_return,
        report.error_model.runtime_internals_return,
    ));
    for class in &report.error_model.error_classes {
        out.push_str(&format!(
            "- `{}`: {} (codes: {})\n",
            class.name,
            class.description,
            class.maps_from_error_codes.join(", "),
        ));
    }
    out.push_str("\n## Benchmark Lanes\n\n");
    for workload in &report.performance.workloads {
        out.push_str(&format!(
            "- `{}`: {}\n",
            workload.name, workload.description
        ));
    }
    out.push_str("\n## Implementation-Backed Docs\n\n");
    for surface in &report.documentation.surfaces {
        out.push_str(&format!(
            "- `{}`: {} (`{}`)\n",
            surface.name, surface.output, surface.source,
        ));
    }
    out
}
