use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::error::Error as StdError;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use formatter::{format_source, is_fzy_source_path};
use runtime::{plan_async_checkpoints, DeterministicExecutor, Scheduler, TaskEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli_output;
use crate::lsp;
use crate::pipeline::{
    check_file, compile_file_with_backend, compile_library_with_backend,
    embedded_core_stdlib_module_source, emit_ir, gpu_backend_report_json,
    lower_fir_cached_with_metadata, parse_program, parse_program_with_metadata, refresh_lockfile,
    verify_file, BuildArtifact, BuildProfile, LibraryArtifact, Output,
};

mod interop;
mod non_scenario;
mod source;
mod trace_native;

use self::interop::{
    generate_c_headers, generate_rpc_artifacts, render_headers, render_rpc_artifacts,
    HeaderArtifact,
};
use self::non_scenario::{
    prepare_host_backed_bridge, run_non_scenario_test_plan_with_root_guidance,
};
use self::source::{
    discover_nested_project_roots, discover_project_roots, load_resolved_module_set,
    resolve_source, ResolvedModuleSource,
};
use self::trace_native::{
    convert_fozzy_trace_to_native, ensure_goal_trace_from_scenario, native_explore,
    render_trace_native_artifacts, resolve_replay_target,
};

#[cfg(test)]
use self::trace_native::{build_live_http_probe_steps, FOZZY_TRACE_FORMAT, FOZZY_TRACE_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone)]
pub struct CommandFailure {
    pub exit_code: i32,
    pub output: String,
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub output: String,
    pub exit_code: Option<i32>,
}

impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "command failed with exit code {}", self.exit_code)
    }
}

impl StdError for CommandFailure {}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

#[derive(Debug, Clone)]
struct BuildInteropArtifacts {
    library: LibraryArtifact,
    headers: HeaderArtifact,
    artifact_manifest: PathBuf,
    export_symbols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init {
        path: PathBuf,
        package_name: Option<String>,
        template: Option<String>,
        with: Vec<String>,
        force: bool,
    },
    Build {
        path: PathBuf,
        release: bool,
        strict: bool,
        lib: bool,
        threads: Option<u16>,
        backend: Option<String>,
        pgo_generate: bool,
        pgo_use: Option<PathBuf>,
        link_libs: Vec<String>,
        link_search: Vec<String>,
        frameworks: Vec<String>,
    },
    Run {
        path: PathBuf,
        args: Vec<String>,
        deterministic: bool,
        strict_verify: bool,
        safe_profile: bool,
        seed: Option<u64>,
        record: Option<PathBuf>,
        host_backends: bool,
        backend: Option<String>,
        max_seconds: Option<u64>,
        exit_on_healthcheck: Option<String>,
        smoke_http: Option<String>,
    },
    Test {
        path: PathBuf,
        deterministic: bool,
        strict_verify: bool,
        safe_profile: bool,
        seed: Option<u64>,
        record: Option<PathBuf>,
        host_backends: bool,
        backend: Option<String>,
        scheduler: Option<String>,
        rich_artifacts: bool,
        filter: Option<String>,
    },
    Fmt {
        targets: Vec<PathBuf>,
        check: bool,
    },
    Check {
        path: PathBuf,
    },
    Verify {
        path: PathBuf,
    },
    Lint {
        path: PathBuf,
        tier: String,
    },
    Explain {
        diag_code: String,
    },
    DoctorProject {
        path: PathBuf,
        strict: bool,
    },
    ScenarioDoctor {
        scenario: PathBuf,
        runs: Option<u64>,
        seed: Option<u64>,
        strict: bool,
        deep: bool,
        host_backends: bool,
    },
    DevLoop {
        path: PathBuf,
        backend: Option<String>,
    },
    DxCheck {
        path: PathBuf,
        strict: bool,
    },
    SpecCheck,
    EmitIr {
        path: PathBuf,
        backend: Option<String>,
    },
    Perf {
        artifact: Option<PathBuf>,
    },
    ArtifactsLsLatest,
    ReportShowLatest {
        output_format: String,
    },
    StabilityDashboard,
    Parity {
        path: PathBuf,
        seed: Option<u64>,
    },
    Equivalence {
        path: PathBuf,
        seed: Option<u64>,
    },
    AuditUnsafe {
        path: PathBuf,
        workspace: bool,
    },
    AuditFfi {
        path: PathBuf,
    },
    AuditMemory {
        path: PathBuf,
    },
    Vendor {
        path: PathBuf,
    },
    AbiCheck {
        current: PathBuf,
        baseline: PathBuf,
    },
    DebugCheck {
        path: PathBuf,
    },
    PgoMerge {
        path: PathBuf,
        output: Option<PathBuf>,
    },
    LspDiagnostics {
        path: PathBuf,
    },
    LspDefinition {
        path: PathBuf,
        symbol: String,
    },
    LspHover {
        path: PathBuf,
        symbol: String,
    },
    LspRename {
        path: PathBuf,
        from: String,
        to: String,
    },
    LspSmoke {
        path: PathBuf,
    },
    LspServe {
        path: Option<PathBuf>,
    },
    Fuzz {
        target: PathBuf,
    },
    Explore {
        target: PathBuf,
    },
    MapSuites {
        root: PathBuf,
        scenario_root: PathBuf,
        profile: String,
    },
    Usage,
    Env,
    Schema,
    Validate {
        scenario: PathBuf,
    },
    TraceVerify {
        trace: PathBuf,
        strict: bool,
    },
    Replay {
        trace: PathBuf,
    },
    Shrink {
        trace: PathBuf,
    },
    Ci {
        trace: PathBuf,
        strict: bool,
    },
    TraceNative {
        trace: PathBuf,
        output: Option<PathBuf>,
    },
    Headers {
        path: PathBuf,
        output: Option<PathBuf>,
    },
    RpcGen {
        path: PathBuf,
        out_dir: Option<PathBuf>,
    },
    DocGen {
        path: PathBuf,
        format: String,
        out: Option<PathBuf>,
        reference: Option<PathBuf>,
    },
    InspectSurface,
    InspectArtifacts {
        path: PathBuf,
        release: bool,
        backend: Option<String>,
    },
    InspectEmbedding {
        path: PathBuf,
    },
    InspectStdlib {
        module: String,
    },
    Version,
}

pub fn run(command: Command, format: Format) -> Result<String> {
    match command {
        Command::Init {
            path,
            package_name,
            template,
            with,
            force,
        } => init_project(
            &path,
            package_name.as_deref(),
            template.as_deref(),
            &with,
            force,
        )
        .map(|_| render(format, "initialized project")),
        Command::Build {
            path,
            release,
            strict,
            lib,
            threads,
            backend,
            pgo_generate,
            pgo_use,
            link_libs,
            link_search,
            frameworks,
        } => {
            if release && strict {
                bail!("`fz build` accepts either `--release` or `--strict`, not both");
            }
            let profile = if strict {
                BuildProfile::Strict
            } else if release {
                BuildProfile::Release
            } else {
                BuildProfile::Dev
            };
            let runtime_config = persist_runtime_threads_config(&path, threads)?;
            let _link_scope = BuildLinkArgsScope::new(&link_libs, &link_search, &frameworks);
            let _compile_scope =
                BuildCompileEnvScope::new(threads, pgo_generate, pgo_use.as_deref(), &path)?;
            if lib {
                let artifact = compile_library_with_backend_with_root_guidance(
                    &path,
                    profile,
                    backend.as_deref(),
                )?;
                let headers = generate_c_headers(&path, None)?;
                let interop = finalize_build_interop_artifacts(&path, &artifact, headers)?;
                let rendered = render_library_artifact(
                    format,
                    artifact,
                    threads,
                    runtime_config,
                    Some(&interop),
                );
                let unsafe_docs = maybe_generate_unsafe_docs(&path);
                Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
            } else {
                let artifact = compile_file_with_backend_with_root_guidance(
                    &path,
                    profile,
                    backend.as_deref(),
                )?;
                let interop = if artifact.status == "ok" {
                    maybe_generate_build_interop_artifacts(&path, profile, backend.as_deref())?
                } else {
                    None
                };
                let rendered =
                    render_artifact(format, artifact, threads, runtime_config, interop.as_ref());
                let unsafe_docs = maybe_generate_unsafe_docs(&path);
                Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
            }
        }
        Command::Run {
            path,
            args,
            deterministic,
            strict_verify,
            safe_profile,
            seed,
            record,
            host_backends,
            backend,
            max_seconds,
            exit_on_healthcheck,
            smoke_http,
        } => {
            if is_fozzy_scenario(&path) {
                let config = scenario_config_with_backends(host_backends)?;
                let run = fzscenario::run_scenario(
                    &config,
                    fzscenario::ScenarioPath::new(path.clone()),
                    &fzscenario::RunOptions {
                        det: deterministic,
                        seed,
                        timeout: None,
                        reporter: scenario_reporter(format),
                        record_trace_to: record.clone(),
                        filter: None,
                        jobs: None,
                        fail_fast: false,
                        record_collision: fzscenario::RecordCollisionPolicy::Append,
                        profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                        proc_backend: config.proc_backend,
                        fs_backend: config.fs_backend,
                        http_backend: config.http_backend,
                        memory: scenario_memory_options(&config),
                    },
                )
                .map_err(scenario_error)?;
                return render_scenario_run_result(format, run, strict_verify);
            }
            if host_backends && deterministic {
                let bridge_plan = prepare_host_backed_bridge(
                    &path,
                    NonScenarioPlanRequest {
                        strict_verify,
                        safe_profile,
                        scheduler: Some("fifo".to_string()),
                        seed,
                        filter: None,
                        deterministic: true,
                        record: None,
                        rich_artifacts: true,
                    },
                    "native-run",
                )?;
                let config = scenario_config_with_backends(true)?;
                let run = fzscenario::run_scenario(
                    &config,
                    fzscenario::ScenarioPath::new(bridge_plan.scenario_path.clone()),
                    &fzscenario::RunOptions {
                        det: deterministic,
                        seed,
                        timeout: None,
                        reporter: scenario_reporter(format),
                        record_trace_to: record.clone(),
                        filter: None,
                        jobs: None,
                        fail_fast: false,
                        record_collision: fzscenario::RecordCollisionPolicy::Append,
                        profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                        proc_backend: config.proc_backend,
                        fs_backend: config.fs_backend,
                        http_backend: config.http_backend,
                        memory: scenario_memory_options(&config),
                    },
                )
                .map_err(scenario_error)?;
                return render_host_bridge_run_result(
                    format,
                    path.as_path(),
                    bridge_plan.scenario_path.as_path(),
                    bridge_plan.trace_path.as_path(),
                    record.as_deref(),
                    run,
                    strict_verify,
                    deterministic,
                );
            }
            let unsafe_docs =
                maybe_generate_unsafe_docs(&path).map(|value| value.display().to_string());
            if deterministic && !host_backends {
                let plan = run_non_scenario_test_plan_with_root_guidance(
                    &path,
                    NonScenarioPlanRequest {
                        deterministic: true,
                        strict_verify,
                        safe_profile,
                        scheduler: Some("fifo".to_string()),
                        seed,
                        record: record.as_deref(),
                        rich_artifacts: true,
                        filter: None,
                    },
                )?;
                return match format {
                    Format::Text => Ok(render_text_fields(&[
                        ("status", "ok".to_string()),
                        ("mode", "deterministic-run".to_string()),
                        ("module", plan.module.clone()),
                        ("scheduler", plan.scheduler.clone()),
                        ("deterministic", "true".to_string()),
                        ("routing", "deterministic-language-async-model".to_string()),
                        ("diagnostics", plan.diagnostics.to_string()),
                        ("tasks", plan.executed_tasks.to_string()),
                        (
                            "async_checkpoints",
                            plan.async_checkpoint_count.to_string(),
                        ),
                        ("rpc_frames", plan.rpc_frame_count.to_string()),
                        (
                            "policy",
                            policy_summary_text(
                                "verify",
                                Some(if strict_verify { "strict" } else { "profile-driven" }),
                                Some("deterministic-model"),
                                true,
                            ),
                        ),
                        ("parse_ms", plan.telemetry.parse_ms.to_string()),
                        ("lower_ms", plan.telemetry.lower_ms.to_string()),
                        ("verify_ms", plan.telemetry.verify_ms.to_string()),
                        ("execute_ms", plan.telemetry.execute_ms.to_string()),
                        ("artifact_write_ms", plan.telemetry.artifact_write_ms.to_string()),
                        ("total_ms", plan.telemetry.total_ms.to_string()),
                        (
                            "unsafe_docs",
                            unsafe_docs.clone().unwrap_or_else(|| "<none>".to_string()),
                        ),
                    ])),
                    Format::Json => Ok(serde_json::json!({
                        "module": plan.module,
                        "status": "ok",
                        "diagnostics": plan.diagnostics,
                        "deterministicRequested": deterministic,
                        "deterministicApplied": true,
                        "strictVerify": strict_verify,
                        "safeProfile": safe_profile,
                        "productionMemorySafety": true,
                        "seed": seed,
                        "hostBackends": host_backends,
                        "maxSeconds": max_seconds,
                        "exitOnHealthcheck": exit_on_healthcheck,
                        "smokeHttp": smoke_http,
                        "policy": {
                            "profile": "verify",
                            "unsafeEnforcement": if strict_verify { "strict" } else { "profile-driven" },
                            "memorySafetyMode": "production",
                            "backend": "deterministic-model",
                            "lockfileState": "present-or-created",
                        },
                        "unsafeDocs": unsafe_docs,
                        "routing": {
                            "mode": "deterministic-language-async-model",
                            "reason": "non-scenario deterministic run uses parser/AST/HIR semantics and runtime deterministic model directly",
                        },
                        "execution": {
                            "scheduler": plan.scheduler,
                            "executedTasks": plan.executed_tasks,
                            "asyncCheckpointCount": plan.async_checkpoint_count,
                            "asyncExecution": plan.async_execution,
                            "rpcFrameCount": plan.rpc_frame_count,
                            "threadFindings": plan.thread_findings,
                            "runtimeEvents": plan.runtime_event_count,
                            "causalLinks": plan.causal_link_count,
                        },
                        "telemetry": {
                            "parseMs": plan.telemetry.parse_ms,
                            "lowerMs": plan.telemetry.lower_ms,
                            "verifyMs": plan.telemetry.verify_ms,
                            "executeMs": plan.telemetry.execute_ms,
                            "artifactWriteMs": plan.telemetry.artifact_write_ms,
                            "totalMs": plan.telemetry.total_ms,
                            "parseCacheHit": plan.telemetry.parse_cache_hit,
                            "lowerCacheHit": plan.telemetry.lower_cache_hit,
                            "inputBytes": plan.telemetry.input_bytes,
                        },
                        "artifacts": plan.artifacts.as_ref().map(|artifacts| {
                            serde_json::json!({
                                "trace": artifacts.trace_path.display().to_string(),
                                "report": artifacts.report_path.as_ref().map(|path| path.display().to_string()),
                                "timeline": artifacts.timeline_path.as_ref().map(|path| path.display().to_string()),
                                "manifest": artifacts.manifest_path.display().to_string(),
                                "explore": artifacts.explore_path.as_ref().map(|path| path.display().to_string()),
                                "shrink": artifacts.shrink_path.as_ref().map(|path| path.display().to_string()),
                                "scenariosIndex": artifacts.scenarios_index_path.as_ref().map(|path| path.display().to_string()),
                                "primaryScenario": artifacts
                                    .primary_scenario_path
                                    .as_ref()
                                    .map(|path| path.display().to_string()),
                                "goalTrace": artifacts
                                    .goal_trace_path
                                    .as_ref()
                                    .map(|path| path.display().to_string()),
                            })
                        }),
                    })
                    .to_string()),
                };
            }

            let artifact = compile_file_with_backend_with_root_guidance(
                &path,
                if strict_verify {
                    BuildProfile::Strict
                } else if safe_profile {
                    BuildProfile::Verify
                } else {
                    BuildProfile::Dev
                },
                backend.as_deref(),
            )?;
            if artifact.status != "ok" || artifact.output.is_none() {
                let rendered = render_run_compile_abort(format, &artifact);
                return Err(CommandFailure {
                    exit_code: 1,
                    output: rendered,
                }
                .into());
            }
            let binary = artifact
                .output
                .as_ref()
                .ok_or_else(|| anyhow!("missing native output artifact"))?;
            let routing_mode = if host_backends {
                "native-host-runtime"
            } else {
                "native"
            };
            let rendered = match format {
                Format::Text => {
                    let outcome = run_native_binary_with_bounds(
                        binary,
                        &args,
                        RunBounds {
                            max_seconds,
                            exit_on_healthcheck: exit_on_healthcheck.as_deref(),
                            smoke_http: smoke_http.as_deref(),
                        },
                        true,
                    )?;
                    let message = render_text_fields(&[
                        (
                            "status",
                            if outcome.exit_code == 0 {
                                "ok".to_string()
                            } else {
                                "error".to_string()
                            },
                        ),
                        ("mode", "run".to_string()),
                        ("module", artifact.module.clone()),
                        ("binary", binary.display().to_string()),
                        ("routing", routing_mode.to_string()),
                        (
                            "args",
                            if args.is_empty() {
                                "<none>".to_string()
                            } else {
                                args.join(" ")
                            },
                        ),
                        ("stdout", "<streamed-live>".to_string()),
                        ("stderr", "<streamed-live>".to_string()),
                        ("exit_code", outcome.exit_code.to_string()),
                        (
                            "policy",
                            policy_summary_text(
                                if strict_verify {
                                    "strict"
                                } else if safe_profile {
                                    "verify"
                                } else {
                                    "dev"
                                },
                                Some(if strict_verify {
                                    "strict"
                                } else {
                                    "profile-driven"
                                }),
                                Some(routing_mode),
                                true,
                            ),
                        ),
                        (
                            "unsafe_docs",
                            unsafe_docs.clone().unwrap_or_else(|| "<none>".to_string()),
                        ),
                    ]);
                    if outcome.exit_code != 0 {
                        return Err(CommandFailure {
                            exit_code: outcome.exit_code,
                            output: message,
                        }
                        .into());
                    }
                    message
                }
                Format::Json => {
                    let outcome = run_native_binary_with_bounds(
                        binary,
                        &args,
                        RunBounds {
                            max_seconds,
                            exit_on_healthcheck: exit_on_healthcheck.as_deref(),
                            smoke_http: smoke_http.as_deref(),
                        },
                        false,
                    )?;
                    let payload = serde_json::json!({
                        "module": artifact.module,
                        "status": artifact.status,
                        "diagnostics": artifact.diagnostics,
                        "items": artifact.diagnostic_details,
                        "binary": binary.display().to_string(),
                        "args": args,
                        "deterministic": deterministic,
                        "strictVerify": strict_verify,
                        "safeProfile": safe_profile,
                        "productionMemorySafety": true,
                        "seed": seed,
                        "hostBackends": host_backends,
                        "maxSeconds": max_seconds,
                        "exitOnHealthcheck": exit_on_healthcheck,
                        "smokeHttp": smoke_http,
                        "deterministicApplied": deterministic,
                        "policy": {
                            "profile": if strict_verify { "strict" } else if safe_profile { "verify" } else { "dev" },
                            "unsafeEnforcement": if strict_verify { "strict" } else { "profile-driven" },
                            "memorySafetyMode": "production",
                            "backend": routing_mode,
                            "lockfileState": "present-or-created",
                        },
                        "unsafeDocs": unsafe_docs,
                        "routing": {
                            "mode": routing_mode,
                            "reason": if host_backends && deterministic {
                                "host-backed deterministic run routed through the scenario bridge"
                            } else if host_backends {
                                "host-backed native live run"
                            } else {
                                "native run"
                            }
                        },
                        "exitCode": outcome.exit_code,
                        "stdout": outcome.stdout,
                        "stderr": outcome.stderr,
                    });
                    if outcome.exit_code != 0 {
                        return Err(CommandFailure {
                            exit_code: outcome.exit_code,
                            output: payload.to_string(),
                        }
                        .into());
                    }
                    payload.to_string()
                }
            };
            Ok(rendered)
        }
        Command::Test {
            path,
            deterministic,
            strict_verify,
            safe_profile,
            seed,
            record,
            host_backends,
            backend: _backend,
            scheduler,
            rich_artifacts,
            filter,
        } => {
            if is_fozzy_scenario(&path) {
                let config = scenario_config_with_backends(host_backends)?;
                let globs = vec![path.display().to_string()];
                let run = fzscenario::run_tests(
                    &config,
                    &globs,
                    &fzscenario::RunOptions {
                        det: deterministic,
                        seed,
                        timeout: None,
                        reporter: scenario_reporter(format),
                        record_trace_to: record.clone(),
                        filter: filter.clone(),
                        jobs: None,
                        fail_fast: false,
                        record_collision: fzscenario::RecordCollisionPolicy::Append,
                        profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                        proc_backend: config.proc_backend,
                        fs_backend: config.fs_backend,
                        http_backend: config.http_backend,
                        memory: scenario_memory_options(&config),
                    },
                )
                .map_err(scenario_error)?;
                return render_scenario_run_result(format, run, strict_verify);
            }
            if host_backends {
                let bridge_plan = prepare_host_backed_bridge(
                    &path,
                    NonScenarioPlanRequest {
                        strict_verify,
                        safe_profile,
                        scheduler: scheduler.clone(),
                        seed,
                        filter: filter.as_deref(),
                        deterministic: true,
                        record: None,
                        rich_artifacts: true,
                    },
                    "native-test",
                )?;
                let config = scenario_config_with_backends(true)?;
                let globs = vec![bridge_plan.scenario_path.display().to_string()];
                let run = fzscenario::run_tests(
                    &config,
                    &globs,
                    &fzscenario::RunOptions {
                        det: deterministic,
                        seed,
                        timeout: None,
                        reporter: scenario_reporter(format),
                        record_trace_to: record.clone(),
                        filter: None,
                        jobs: None,
                        fail_fast: false,
                        record_collision: fzscenario::RecordCollisionPolicy::Append,
                        profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                        proc_backend: config.proc_backend,
                        fs_backend: config.fs_backend,
                        http_backend: config.http_backend,
                        memory: scenario_memory_options(&config),
                    },
                )
                .map_err(scenario_error)?;
                return render_host_bridge_test_result(
                    format,
                    path.as_path(),
                    bridge_plan.scenario_path.as_path(),
                    bridge_plan.trace_path.as_path(),
                    record.as_deref(),
                    run,
                    strict_verify,
                );
            }
            let unsafe_docs =
                maybe_generate_unsafe_docs(&path).map(|value| value.display().to_string());

            let test_plan = run_non_scenario_test_plan_with_root_guidance(
                &path,
                NonScenarioPlanRequest {
                    deterministic,
                    strict_verify,
                    safe_profile,
                    scheduler: scheduler.clone(),
                    seed,
                    record: record.as_deref(),
                    rich_artifacts,
                    filter: filter.as_deref(),
                },
            )?;
            let message = render_text_fields(&[
                ("status", "ok".to_string()),
                ("mode", "test".to_string()),
                ("module", test_plan.module.clone()),
                ("deterministic", deterministic.to_string()),
                ("strict_verify", strict_verify.to_string()),
                ("scheduler", test_plan.scheduler.clone()),
                ("executed_tasks", test_plan.executed_tasks.to_string()),
                ("order", format!("{:?}", test_plan.execution_order)),
                ("parse_ms", test_plan.telemetry.parse_ms.to_string()),
                ("lower_ms", test_plan.telemetry.lower_ms.to_string()),
                ("verify_ms", test_plan.telemetry.verify_ms.to_string()),
                ("execute_ms", test_plan.telemetry.execute_ms.to_string()),
                (
                    "artifact_write_ms",
                    test_plan.telemetry.artifact_write_ms.to_string(),
                ),
                ("total_ms", test_plan.telemetry.total_ms.to_string()),
                (
                    "policy",
                    policy_summary_text(
                        if strict_verify { "strict" } else { "dev" },
                        Some(if strict_verify {
                            "strict"
                        } else {
                            "profile-driven"
                        }),
                        Some("deterministic-model"),
                        true,
                    ),
                ),
                (
                    "unsafe_docs",
                    unsafe_docs.clone().unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "artifacts",
                    test_plan
                        .artifacts
                        .as_ref()
                        .map(|artifacts| artifacts.trace_path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
            ]);
            match format {
                Format::Text => Ok(message),
                Format::Json => Ok(serde_json::json!({
                    "module": test_plan.module,
                    "deterministic": deterministic,
                    "strictVerify": strict_verify,
                    "safeProfile": safe_profile,
                    "productionMemorySafety": true,
                    "policy": {
                        "profile": if strict_verify { "strict" } else { "dev" },
                        "unsafeEnforcement": if strict_verify { "strict" } else { "profile-driven" },
                        "memorySafetyMode": "production",
                        "backend": "deterministic-model",
                        "lockfileState": "present-or-created",
                    },
                    "unsafeDocs": unsafe_docs,
                    "mode": test_plan.mode,
                    "scheduler": test_plan.scheduler,
                    "diagnostics": test_plan.diagnostics,
                    "executedTasks": test_plan.executed_tasks,
                    "executionOrder": test_plan.execution_order,
                    "asyncCheckpointCount": test_plan.async_checkpoint_count,
                    "asyncExecution": test_plan.async_execution,
                    "rpcFrameCount": test_plan.rpc_frame_count,
                    "rpcValidationErrors": test_plan.rpc_validation_errors,
                    "threadFindings": test_plan.thread_findings,
                    "runtimeEventCount": test_plan.runtime_event_count,
                    "causalLinkCount": test_plan.causal_link_count,
                    "discoveredTests": test_plan.discovered_tests,
                    "selectedTests": test_plan.selected_tests,
                    "discoveredTestNames": test_plan.discovered_test_names,
                    "selectedTestNames": test_plan.selected_test_names,
                    "deterministicTestNames": test_plan.deterministic_test_names,
                    "coverageRatio": test_plan.coverage_ratio,
                    "telemetry": {
                        "parseMs": test_plan.telemetry.parse_ms,
                        "lowerMs": test_plan.telemetry.lower_ms,
                        "verifyMs": test_plan.telemetry.verify_ms,
                        "executeMs": test_plan.telemetry.execute_ms,
                        "artifactWriteMs": test_plan.telemetry.artifact_write_ms,
                        "totalMs": test_plan.telemetry.total_ms,
                        "parseCacheHit": test_plan.telemetry.parse_cache_hit,
                        "lowerCacheHit": test_plan.telemetry.lower_cache_hit,
                        "inputBytes": test_plan.telemetry.input_bytes,
                    },
                    "artifacts": test_plan.artifacts.as_ref().map(|artifacts| {
                        serde_json::json!({
                            "trace": artifacts.trace_path.display().to_string(),
                            "report": artifacts.report_path.as_ref().map(|path| path.display().to_string()),
                            "timeline": artifacts.timeline_path.as_ref().map(|path| path.display().to_string()),
                            "manifest": artifacts.manifest_path.display().to_string(),
                            "explore": artifacts.explore_path.as_ref().map(|path| path.display().to_string()),
                            "shrink": artifacts.shrink_path.as_ref().map(|path| path.display().to_string()),
                            "scenariosIndex": artifacts.scenarios_index_path.as_ref().map(|path| path.display().to_string()),
                            "primaryScenario": artifacts
                                .primary_scenario_path
                                .as_ref()
                                .map(|path| path.display().to_string()),
                            "goalTrace": artifacts
                                .goal_trace_path
                                .as_ref()
                                .map(|path| path.display().to_string()),
                        })
                    }),
                })
                .to_string()),
            }
        }
        Command::Fmt { targets, check } => fmt_command(&targets, check, format),
        Command::Check { path } => {
            let output = check_file_with_root_guidance(&path)?;
            let rendered = render_output(format, output);
            let unsafe_docs = maybe_generate_unsafe_docs(&path);
            Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
        }
        Command::Verify { path } => {
            let output = verify_file_with_root_guidance(&path)?;
            let rendered = render_output(format, output);
            let unsafe_docs = maybe_generate_unsafe_docs(&path);
            Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
        }
        Command::Lint { path, tier } => lint_command(&path, &tier, format),
        Command::Explain { diag_code } => explain_command(&diag_code, format),
        Command::DoctorProject { path, strict } => doctor_project_command(&path, strict, format),
        Command::ScenarioDoctor {
            scenario,
            runs,
            seed,
            strict,
            deep,
            host_backends,
        } => {
            ensure_exists(&scenario)?;
            let config = scenario_config_with_backends(host_backends)?;
            let report = fzscenario::doctor(
                &config,
                &fzscenario::DoctorOptions {
                    deep,
                    scenario: Some(fzscenario::ScenarioPath::new(scenario.clone())),
                    runs: runs.unwrap_or(5) as u32,
                    seed,
                },
            )
            .map_err(scenario_error)?;
            render_doctor_report(format, report, strict)
        }
        Command::DevLoop { path, backend } => devloop_command(&path, backend.as_deref(), format),
        Command::DxCheck { path, strict } => dx_check_command(&path, strict, format),
        Command::SpecCheck => spec_check(format),
        Command::EmitIr { path, backend } => {
            let output = emit_ir(&path, backend.as_deref())?;
            Ok(render_output(format, output))
        }
        Command::Perf { artifact } => perf_command(artifact.as_deref(), format),
        Command::ArtifactsLsLatest => {
            let config = scenario_config()?;
            let output = fzscenario::artifacts_command(
                &config,
                &fzscenario::ArtifactCommand::Ls {
                    run: "latest".to_string(),
                },
            )
            .map_err(scenario_error)?;
            render_value_output(format, &output)
        }
        Command::ReportShowLatest { output_format } => {
            let config = scenario_config()?;
            let reporter = parse_scenario_reporter(&output_format)?;
            let output = fzscenario::report_command(
                &config,
                &fzscenario::ReportCommand::Show {
                    run: "latest".to_string(),
                    format: reporter,
                },
            )
            .map_err(scenario_error)?;
            render_report_show_output(format, reporter, output)
        }
        Command::StabilityDashboard => stability_dashboard_command(format),
        Command::Parity { path, seed } => parity_command(&path, seed.unwrap_or(1), format),
        Command::Equivalence { path, seed } => {
            equivalence_command(&path, seed.unwrap_or(1), format)
        }
        Command::AuditUnsafe { path, workspace } => audit_unsafe_command(&path, workspace, format),
        Command::AuditFfi { path } => audit_ffi_command(&path, format),
        Command::AuditMemory { path } => audit_memory_command(&path, format),
        Command::Vendor { path } => vendor_command(&path, format),
        Command::AbiCheck { current, baseline } => abi_check_command(&current, &baseline, format),
        Command::DebugCheck { path } => debug_check_command(&path, format),
        Command::PgoMerge { path, output } => pgo_merge_command(&path, output.as_deref(), format),
        Command::LspDiagnostics { path } => lsp_diagnostics_command(&path, format),
        Command::LspDefinition { path, symbol } => lsp_definition_command(&path, &symbol, format),
        Command::LspHover { path, symbol } => lsp_hover_command(&path, &symbol, format),
        Command::LspRename { path, from, to } => lsp_rename_command(&path, &from, &to, format),
        Command::LspSmoke { path } => lsp_smoke_command(&path, format),
        Command::LspServe { path } => {
            lsp::serve_stdio(path.as_deref())?;
            Ok(render(format, "lsp server exited cleanly"))
        }
        Command::Fuzz { target } => scenario_fuzz(&target, format),
        Command::Explore { target } => {
            if is_native_trace_or_manifest(&target) {
                native_explore(&target, format)
            } else {
                scenario_explore(&target, format)
            }
        }
        Command::MapSuites {
            root,
            scenario_root,
            profile,
        } => {
            let config = scenario_config()?;
            let output = fzscenario::map_command(
                &config,
                &fzscenario::MapCommand::Suites {
                    root,
                    scenario_root,
                    min_risk: 60,
                    profile: parse_topology_profile(&profile)?,
                    shrink_policy: fzscenario::ShrinkCoveragePolicy::NoKnownFailures,
                    limit: 100,
                    offset: 0,
                    max_matched_scenarios: 25,
                },
            )
            .map_err(scenario_error)?;
            render_value_output(format, &output)
        }
        Command::Usage => match format {
            Format::Text => Ok(native_usage_text()),
            Format::Json => Ok(native_usage_doc().to_string()),
        },
        Command::Env => {
            let config = scenario_config()?;
            let output = fzscenario::env_info(&config);
            let output = serde_json::json!({
                "os": output.os,
                "arch": output.arch,
                "fz": output.fz,
                "capabilities": output.capabilities,
                "install": output.install,
            });
            render_value_output(format, &output)
        }
        Command::Schema => {
            let output = fzscenario::schema_doc();
            render_value_output(format, &output)
        }
        Command::Validate { scenario } => {
            ensure_exists(&scenario)?;
            validate_scenario_file(&scenario)?;
            let output = serde_json::json!({
                "ok": true,
                "scenario": scenario.display().to_string(),
            });
            render_value_output(format, &output)
        }
        Command::TraceVerify { trace, strict } => {
            ensure_exists(&trace)?;
            let output = fzscenario::verify_trace_file(&trace).map_err(scenario_error)?;
            render_trace_verify_report(format, output, strict)
        }
        Command::Replay { trace } => replay_like("replay", &trace, false, format),
        Command::Shrink { trace } => replay_like("shrink", &trace, false, format),
        Command::Ci { trace, strict } => replay_like("ci", &trace, strict, format),
        Command::TraceNative { trace, output } => {
            let converted = convert_fozzy_trace_to_native(&trace, output.as_deref())?;
            Ok(render_trace_native_artifacts(format, converted))
        }
        Command::Headers { path, output } => {
            let generated = generate_c_headers(&path, output.as_deref())?;
            Ok(render_headers(format, generated))
        }
        Command::RpcGen { path, out_dir } => {
            let generated = generate_rpc_artifacts(&path, out_dir.as_deref())?;
            Ok(render_rpc_artifacts(format, generated))
        }
        Command::DocGen {
            path,
            format: doc_format,
            out,
            reference,
        } => {
            let generated =
                generate_doc_artifacts(&path, &doc_format, out.as_deref(), reference.as_deref())?;
            Ok(render_doc_artifacts(format, generated))
        }
        Command::InspectSurface => Ok(render_surface_inspection(format)),
        Command::InspectArtifacts {
            path,
            release,
            backend,
        } => inspect_artifacts_command(&path, release, backend.as_deref(), format),
        Command::InspectEmbedding { path } => inspect_embedding_command(&path, format),
        Command::InspectStdlib { module } => inspect_stdlib_command(&module, format),
        Command::Version => {
            let version = fzscenario::version_info();
            match format {
                Format::Json => Ok(serde_json::to_string(&version)?),
                Format::Text => {
                    let mut fields = vec![("version", version.version)];
                    if let Some(commit) = version.commit {
                        fields.push(("commit", commit));
                    }
                    if let Some(build_date) = version.build_date {
                        fields.push(("build_date", build_date));
                    }
                    fields.push(("language_version", version.compatibility.language_version));
                    fields.push((
                        "trace_schema_version",
                        version.compatibility.trace_schema_version,
                    ));
                    fields.push((
                        "manifest_schema_version",
                        version.compatibility.manifest_schema_version,
                    ));
                    fields.push((
                        "runtime_abi_version",
                        version.compatibility.runtime_abi_version,
                    ));
                    fields.push((
                        "native_import_table_version",
                        version.compatibility.native_import_table_version,
                    ));
                    fields.push((
                        "diagnostic_catalog_version",
                        version.compatibility.diagnostic_catalog_version,
                    ));
                    Ok(render_text_fields(&fields))
                }
            }
        }
    }
}

pub fn run_with_metadata(command: Command, format: Format) -> Result<CommandResult> {
    let output = run(command.clone(), format)?;
    Ok(CommandResult {
        exit_code: infer_success_exit_code(&command, &output, format),
        output,
    })
}

fn infer_success_exit_code(command: &Command, output: &str, format: Format) -> Option<i32> {
    match command {
        Command::Build { .. } => output_contains_status_error(output, format).then_some(1),
        Command::DoctorProject { .. }
        | Command::DevLoop { .. }
        | Command::Lint { .. }
        | Command::Fmt { .. } => output_contains_status_error(output, format).then_some(1),
        Command::Run { .. } => extract_json_i32(output, "\"exitCode\":")
            .or_else(|| extract_text_i32(output, "exit_code"))
            .filter(|code| *code != 0),
        Command::Check { .. } | Command::Verify { .. } | Command::LspDiagnostics { .. } => {
            let errors = extract_json_usize(output, "\"errors\":")
                .or_else(|| extract_text_usize(output, "errors"))
                .unwrap_or(0);
            if errors > 0
                || output_contains_ok_false(output)
                || output_contains_status_error(output, format)
            {
                Some(1)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn output_contains_status_error(output: &str, format: Format) -> bool {
    match format {
        Format::Json => output.contains("\"status\":\"error\""),
        Format::Text => output.contains("status: error") || output.contains("status:error"),
    }
}

fn output_contains_ok_false(output: &str) -> bool {
    output.contains("\"ok\":false") || output.contains("ok=false")
}

fn extract_json_i32(output: &str, key: &str) -> Option<i32> {
    let rest = output.split(key).nth(1)?;
    let digits = rest
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '-')
        .collect::<String>();
    digits.parse::<i32>().ok()
}

fn extract_json_usize(output: &str, key: &str) -> Option<usize> {
    let rest = output.split(key).nth(1)?;
    let digits = rest
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<usize>().ok()
}

fn extract_text_i32(output: &str, key: &str) -> Option<i32> {
    let rest = output.split(&format!("{key}:")).nth(1)?;
    rest.lines().next()?.trim().parse::<i32>().ok()
}

fn extract_text_usize(output: &str, key: &str) -> Option<usize> {
    let rest = output.split(&format!("{key}:")).nth(1)?;
    rest.lines().next()?.trim().parse::<usize>().ok()
}

struct BuildLinkArgsScope {
    previous: Option<String>,
    active: bool,
}

struct BuildCompileEnvScope {
    previous_codegen_jobs: Option<String>,
    previous_pgo_generate: Option<String>,
    previous_pgo_use: Option<String>,
}

impl BuildCompileEnvScope {
    fn new(
        threads: Option<u16>,
        pgo_generate: bool,
        pgo_use: Option<&Path>,
        path: &Path,
    ) -> Result<Self> {
        let previous_codegen_jobs = std::env::var("FZ_CODEGEN_JOBS").ok();
        let previous_pgo_generate = std::env::var("FZ_PGO_GENERATE").ok();
        let previous_pgo_use = std::env::var("FZ_PGO_USE").ok();

        if let Some(threads) = threads {
            if threads == 0 {
                bail!("--threads must be greater than zero");
            }
            std::env::set_var("FZ_CODEGEN_JOBS", threads.to_string());
        } else {
            std::env::remove_var("FZ_CODEGEN_JOBS");
        }

        if pgo_generate {
            let resolved = resolve_pgo_dir(path);
            std::fs::create_dir_all(&resolved).with_context(|| {
                format!(
                    "failed creating PGO profile generation directory: {}",
                    resolved.display()
                )
            })?;
            std::env::set_var("FZ_PGO_GENERATE", resolved.display().to_string());
            std::env::remove_var("FZ_PGO_USE");
        } else if let Some(profile) = pgo_use {
            if !profile.exists() {
                bail!("PGO profile data not found: {}", profile.display());
            }
            std::env::set_var("FZ_PGO_USE", profile.display().to_string());
            std::env::remove_var("FZ_PGO_GENERATE");
        } else {
            std::env::remove_var("FZ_PGO_GENERATE");
            std::env::remove_var("FZ_PGO_USE");
        }

        Ok(Self {
            previous_codegen_jobs,
            previous_pgo_generate,
            previous_pgo_use,
        })
    }
}

impl Drop for BuildCompileEnvScope {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous_codegen_jobs {
            std::env::set_var("FZ_CODEGEN_JOBS", previous);
        } else {
            std::env::remove_var("FZ_CODEGEN_JOBS");
        }
        if let Some(previous) = &self.previous_pgo_generate {
            std::env::set_var("FZ_PGO_GENERATE", previous);
        } else {
            std::env::remove_var("FZ_PGO_GENERATE");
        }
        if let Some(previous) = &self.previous_pgo_use {
            std::env::set_var("FZ_PGO_USE", previous);
        } else {
            std::env::remove_var("FZ_PGO_USE");
        }
    }
}

fn resolve_pgo_dir(path: &Path) -> PathBuf {
    let root = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    root.join(".fz").join("pgo").join("default")
}

fn collect_pgo_profile_inputs(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.exists() {
        bail!("PGO input path not found: {}", path.display());
    }
    if !path.is_dir() {
        bail!(
            "PGO input path is neither a file nor directory: {}",
            path.display()
        );
    }

    let mut inputs = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading PGO input directory: {}", dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!(
                    "failed reading directory entry while scanning {}",
                    dir.display()
                )
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
                continue;
            }
            let ext = entry_path.extension().and_then(|value| value.to_str());
            if matches!(ext, Some("profraw") | Some("profdata")) {
                inputs.push(entry_path);
            }
        }
    }
    inputs.sort();
    inputs.dedup();
    Ok(inputs)
}

fn pgo_merge_command(path: &Path, output: Option<&Path>, format: Format) -> Result<String> {
    let inputs = collect_pgo_profile_inputs(path)?;
    if inputs.is_empty() {
        bail!(
            "no PGO profile inputs found under {}; expected .profraw or .profdata files",
            path.display()
        );
    }
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| path.join("merged.profdata"));
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating output directory for merged profile: {}",
                parent.display()
            )
        })?;
    }

    let mut command = ProcessCommand::new("llvm-profdata");
    command
        .arg("merge")
        .arg("-sparse")
        .arg("-o")
        .arg(&output_path);
    for input in &inputs {
        command.arg(input);
    }
    let output = command.output().with_context(|| {
        "failed invoking llvm-profdata; ensure LLVM toolchain is installed and llvm-profdata is in PATH"
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "llvm-profdata merge failed for {} input(s): {}",
            inputs.len(),
            if stderr.is_empty() {
                "<no stderr>".to_string()
            } else {
                stderr
            }
        );
    }

    let rendered = match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "pgo-merge".to_string()),
            ("input_count", inputs.len().to_string()),
            ("output", output_path.display().to_string()),
        ]),
        Format::Json => serde_json::json!({
            "status": "ok",
            "mode": "pgo-merge",
            "inputCount": inputs.len(),
            "output": output_path.display().to_string(),
            "inputs": inputs
                .iter()
                .map(|value| value.display().to_string())
                .collect::<Vec<_>>(),
        })
        .to_string(),
    };
    Ok(rendered)
}

impl BuildLinkArgsScope {
    fn new(link_libs: &[String], link_search: &[String], frameworks: &[String]) -> Self {
        let mut args = Vec::new();
        for path in link_search {
            if !path.trim().is_empty() {
                args.push(format!("-L{}", path.trim()));
            }
        }
        for lib in link_libs {
            if !lib.trim().is_empty() {
                args.push(format!("-l{}", lib.trim()));
            }
        }
        if cfg!(target_vendor = "apple") {
            for framework in frameworks {
                if !framework.trim().is_empty() {
                    args.push("-framework".to_string());
                    args.push(framework.trim().to_string());
                }
            }
        }
        if args.is_empty() {
            return Self {
                previous: None,
                active: false,
            };
        }
        let previous = std::env::var("FZ_LINKER_ARGS").ok();
        let mut merged = previous.clone().unwrap_or_default();
        if !merged.trim().is_empty() {
            merged.push(' ');
        }
        merged.push_str(&args.join(" "));
        // Build executes synchronously in this process; scope restores previous value.
        std::env::set_var("FZ_LINKER_ARGS", merged);
        Self {
            previous,
            active: true,
        }
    }
}

impl Drop for BuildLinkArgsScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(previous) = &self.previous {
            std::env::set_var("FZ_LINKER_ARGS", previous);
        } else {
            std::env::remove_var("FZ_LINKER_ARGS");
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(test)]
struct ScenarioRunRouting {
    deterministic_applied: bool,
    mode: &'static str,
    reason: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct RunBounds<'a> {
    max_seconds: Option<u64>,
    exit_on_healthcheck: Option<&'a str>,
    smoke_http: Option<&'a str>,
}

#[derive(Debug, Clone)]
struct NativeRunOutcome {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

fn run_native_binary_with_bounds(
    binary: &Path,
    args: &[String],
    bounds: RunBounds<'_>,
    stream_stdio: bool,
) -> Result<NativeRunOutcome> {
    let mut child = ProcessCommand::new(binary);
    child.args(args);
    if stream_stdio {
        child.stdout(Stdio::inherit());
        child.stderr(Stdio::inherit());
    } else {
        child.stdout(Stdio::piped());
        child.stderr(Stdio::piped());
    }
    let mut child = child
        .spawn()
        .with_context(|| format!("failed to execute native artifact: {}", binary.display()))?;
    let started = Instant::now();
    let mut poll_sleep = Duration::from_millis(5);
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("failed waiting for native artifact: {}", binary.display()))?
        {
            let (stdout, stderr) = read_child_output(&mut child)?;
            return Ok(NativeRunOutcome {
                exit_code: status.code().unwrap_or(1),
                stdout,
                stderr,
            });
        }
        if let Some(max) = bounds.max_seconds {
            if started.elapsed() >= Duration::from_secs(max) {
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, mut stderr) = read_child_output(&mut child)?;
                if !stderr.is_empty() {
                    stderr.push('\n');
                }
                stderr.push_str("timed out");
                return Ok(NativeRunOutcome {
                    exit_code: 124,
                    stdout,
                    stderr,
                });
            }
        }
        if let Some(url) = bounds.exit_on_healthcheck {
            if probe_http_ok(url)? {
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, stderr) = read_child_output(&mut child)?;
                return Ok(NativeRunOutcome {
                    exit_code: 0,
                    stdout,
                    stderr,
                });
            }
        }
        if let Some(url) = bounds.smoke_http {
            if probe_http_ok(url)? {
                let _ = child.kill();
                let _ = child.wait();
                let (stdout, stderr) = read_child_output(&mut child)?;
                return Ok(NativeRunOutcome {
                    exit_code: 0,
                    stdout,
                    stderr,
                });
            }
        }
        thread::sleep(poll_sleep);
        if poll_sleep < Duration::from_millis(50) {
            poll_sleep = (poll_sleep * 2).min(Duration::from_millis(50));
        }
    }
}

fn read_child_output(child: &mut std::process::Child) -> Result<(String, String)> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout)
            .context("failed reading child stdout")?;
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr)
            .context("failed reading child stderr")?;
    }
    Ok((stdout, stderr))
}

fn probe_http_ok(url: &str) -> Result<bool> {
    let Some(without_scheme) = url.strip_prefix("http://") else {
        bail!("unsupported URL for smoke/health probe: {url} (only http:// is supported)");
    };
    let (host_port, path) = if let Some((host_port, path)) = without_scheme.split_once('/') {
        (host_port, format!("/{}", path))
    } else {
        (without_scheme, "/".to_string())
    };
    let (host, port) = if let Some((host, port_str)) = host_port.split_once(':') {
        let parsed = port_str
            .parse::<u16>()
            .with_context(|| format!("invalid probe port in URL: {url}"))?;
        (host, parsed)
    } else {
        (host_port, 80u16)
    };
    let connect_addr = format!("{host}:{port}");
    let resolved = connect_addr
        .to_socket_addrs()
        .with_context(|| format!("invalid probe host/port in URL: {url}"))?
        .next();
    let Some(socket_addr) = resolved else {
        return Ok(false);
    };
    let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(500)) {
        Ok(stream) => stream,
        Err(_) => return Ok(false),
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200"))
}

#[cfg(test)]
fn scenario_run_routing(deterministic_requested: bool, host_backends: bool) -> ScenarioRunRouting {
    if deterministic_requested && host_backends {
        return ScenarioRunRouting {
            deterministic_applied: true,
            mode: "host-backed-deterministic-scenario",
            reason: "host-backed deterministic scenario replay enabled",
        };
    }
    if deterministic_requested {
        return ScenarioRunRouting {
            deterministic_applied: true,
            mode: "deterministic-scenario",
            reason: "",
        };
    }
    ScenarioRunRouting {
        deterministic_applied: false,
        mode: "scenario",
        reason: "",
    }
}

fn init_project(
    path: &Path,
    package_name: Option<&str>,
    template: Option<&str>,
    with: &[String],
    force: bool,
) -> Result<()> {
    let root = if path.as_os_str().is_empty() {
        std::env::current_dir().context("failed to resolve current working directory")?
    } else {
        path.to_path_buf()
    };
    let root = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(root)
    };
    let root_name = root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("app");
    let package = normalize_init_package_name(package_name.unwrap_or(root_name));
    if package.is_empty() {
        bail!("project name cannot be empty");
    }

    let template = parse_init_template(template)?;
    let test_types = parse_init_test_types(with)?;
    ensure_init_target_ready(&root, &template, force)?;

    std::fs::create_dir_all(&root)
        .with_context(|| format!("failed creating project root {}", root.display()))?;
    let src = root.join("src");
    std::fs::create_dir_all(&src).context("failed to create src directory")?;

    let config_path = root.join("fozzy.toml");
    let manifest = render_init_manifest(&package);
    write_init_file(&config_path, manifest.as_bytes(), force)
        .context("failed to write fozzy.toml")?;
    write_init_file(
        &src.join("main.fzy"),
        render_init_main(&package).as_bytes(),
        force,
    )
    .context("failed to write src/main.fzy")?;

    let config = fzscenario::Config::default();
    fzscenario::init_project_with_options(
        &config,
        &config_path,
        &template,
        force,
        &test_types,
        fzscenario::InitProjectOptions {
            write_config: false,
        },
    )
    .map_err(|error| anyhow!(error.to_string()))?;

    Ok(())
}

fn parse_init_template(template: Option<&str>) -> Result<fzscenario::InitTemplate> {
    match template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        None => Ok(fzscenario::InitTemplate::Minimal),
        Some("minimal") => Ok(fzscenario::InitTemplate::Minimal),
        Some("rust") => Ok(fzscenario::InitTemplate::Rust),
        Some("ts") => Ok(fzscenario::InitTemplate::Ts),
        Some(other) => bail!("unsupported init template `{other}`; expected minimal, rust, or ts"),
    }
}

fn parse_init_test_types(values: &[String]) -> Result<Vec<fzscenario::InitTestType>> {
    let mut parsed = Vec::new();
    for value in values {
        let normalized = value.trim().to_ascii_lowercase();
        let kind = match normalized.as_str() {
            "run" => fzscenario::InitTestType::Run,
            "fuzz" => fzscenario::InitTestType::Fuzz,
            "explore" => fzscenario::InitTestType::Explore,
            "memory" => fzscenario::InitTestType::Memory,
            "host" => fzscenario::InitTestType::Host,
            "all" => fzscenario::InitTestType::All,
            _ => bail!(
                "unsupported init scaffold kind `{}`; expected run, fuzz, explore, memory, host, or all",
                value
            ),
        };
        parsed.push(kind);
    }
    Ok(parsed)
}

fn normalize_init_package_name(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn ensure_init_target_ready(
    root: &Path,
    template: &fzscenario::InitTemplate,
    force: bool,
) -> Result<()> {
    let collisions = init_collision_paths(root, template)
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    if !force && !collisions.is_empty() {
        bail!(
            "init target {} already contains scaffold-managed paths: {} (use --force to overwrite)",
            root.display(),
            collisions
                .iter()
                .map(|path| path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn init_collision_paths(root: &Path, template: &fzscenario::InitTemplate) -> Vec<PathBuf> {
    let mut paths = vec![
        root.join("fozzy.toml"),
        root.join("src"),
        root.join("tests"),
        root.join(".fozzy"),
    ];
    if matches!(template, fzscenario::InitTemplate::Rust) {
        paths.push(root.join("README.md"));
    }
    paths
}

fn render_init_manifest(package: &str) -> String {
    format!(
        "base_dir = \".fozzy\"\n\n[package]\nname = \"{package}\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"{package}\"\npath = \"src/main.fzy\"\n\n[unsafe]\ncontracts = \"compiler\"\nenforce_dev = false\nenforce_verify = true\nenforce_release = true\ndeny_unsafe_in = []\nallow_unsafe_in = []\n"
    )
}

fn render_init_main(package: &str) -> String {
    format!("fn main() -> i32 {{\n    let _app = \"{package}\"\n    return 0\n}}\n")
}

fn write_init_file(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

fn render(format: Format, message: &str) -> String {
    cli_output::format_message(format, message)
}

fn render_text_fields(fields: &[(&str, String)]) -> String {
    cli_output::format_fields(fields)
}

fn render_json(value: serde_json::Value) -> String {
    cli_output::format_json_value(&value)
}

fn policy_summary_text(
    profile: &str,
    unsafe_enforcement: Option<&str>,
    backend: Option<&str>,
    lockfile_present: bool,
) -> String {
    format!(
        "profile={profile}; unsafe={}; memory=production; backend={}; lockfile={}",
        unsafe_enforcement.unwrap_or("profile-driven"),
        backend.unwrap_or("auto"),
        if lockfile_present { "present" } else { "n/a" }
    )
}

fn doctor_checks_summary_text(checks: &[DoctorCheck]) -> String {
    checks
        .iter()
        .map(|check| format!("- {}:{}:{}", check.name, check.status, check.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

fn append_unsafe_docs_field(
    rendered: String,
    format: Format,
    unsafe_docs: Option<PathBuf>,
) -> String {
    match format {
        Format::Text => {
            if let Some(path) = unsafe_docs {
                format!("{rendered}\nunsafe_docs: {}", path.display())
            } else {
                rendered
            }
        }
        Format::Json => {
            let Ok(mut payload) = serde_json::from_str::<serde_json::Value>(&rendered) else {
                return rendered;
            };
            if let Some(path) = unsafe_docs {
                payload["unsafeDocs"] = serde_json::Value::String(path.display().to_string());
            }
            render_json(payload)
        }
    }
}

fn render_artifact(
    format: Format,
    artifact: BuildArtifact,
    threads: Option<u16>,
    runtime_config: Option<PathBuf>,
    interop: Option<&BuildInteropArtifacts>,
) -> String {
    match format {
        Format::Text => {
            let mut rendered = render_text_fields(&[
                ("status", artifact.status.to_string()),
                ("module", artifact.module.clone()),
                ("profile", format!("{:?}", artifact.profile)),
                ("diagnostics", artifact.diagnostics.to_string()),
                (
                    "output",
                    artifact
                        .output
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "threads",
                    threads
                        .map(|threads| threads.to_string())
                        .unwrap_or_else(|| "default".to_string()),
                ),
                (
                    "runtime_config",
                    runtime_config
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "dep_graph_hash",
                    artifact
                        .dependency_graph_hash
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "policy",
                    policy_summary_text(
                        artifact.profile.as_str(),
                        Some("compiler"),
                        None,
                        artifact.dependency_graph_hash.is_some(),
                    ),
                ),
            ]);
            if let Some(interop) = interop {
                rendered.push('\n');
                rendered.push_str(&render_text_fields(&[
                    (
                        "interop_static_lib",
                        interop
                            .library
                            .static_lib
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "<none>".to_string()),
                    ),
                    (
                        "interop_shared_lib",
                        interop
                            .library
                            .shared_lib
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "<none>".to_string()),
                    ),
                    ("interop_header", interop.headers.path.display().to_string()),
                    (
                        "interop_abi_manifest",
                        interop.headers.abi_manifest.display().to_string(),
                    ),
                    ("interop_exports", interop.headers.exports.to_string()),
                ]));
            }
            let details = render_diagnostics_text(&artifact.diagnostic_details);
            if !details.is_empty() {
                rendered.push('\n');
                rendered.push_str(&details);
            }
            rendered
        }
        Format::Json => {
            let mut payload = serde_json::json!({
                "module": artifact.module,
                "profile": format!("{:?}", artifact.profile),
                "status": artifact.status,
                "diagnostics": artifact.diagnostics,
                "items": artifact.diagnostic_details,
                "dependencyGraphHash": artifact.dependency_graph_hash,
                "policy": {
                    "profile": artifact.profile.as_str(),
                    "unsafeEnforcement": "profile-driven",
                    "memorySafetyMode": "production",
                    "backend": "compiler",
                    "lockfileState": if artifact.dependency_graph_hash.is_some() { "present" } else { "n/a" },
                },
                "threads": threads,
                "runtimeConfig": runtime_config.map(|path| path.display().to_string()),
                "output": artifact
                    .output
                    .as_ref()
                    .map(|path| path.display().to_string()),
            });
            if let Some(interop) = interop {
                payload["interop"] = serde_json::json!({
                    "buildMode": "lib",
                    "exports": interop.headers.exports,
                    "exportSymbols": interop.export_symbols,
                    "staticLib": interop
                        .library
                        .static_lib
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    "sharedLib": interop
                        .library
                        .shared_lib
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    "header": interop.headers.path.display().to_string(),
                    "abiManifest": interop.headers.abi_manifest.display().to_string(),
                    "artifactManifest": interop.artifact_manifest.display().to_string(),
                    "hostLifecycle": {
                        "init": "fz_host_init",
                        "shutdown": "fz_host_shutdown",
                        "cleanup": "fz_host_cleanup",
                        "lastErrorCode": "fz_host_last_error_code",
                        "lastErrorClass": "fz_host_last_error_class",
                        "lastErrorMessage": "fz_host_last_error_message",
                    },
                });
            }
            payload.to_string()
        }
    }
}

fn render_library_artifact(
    format: Format,
    artifact: LibraryArtifact,
    threads: Option<u16>,
    runtime_config: Option<PathBuf>,
    interop: Option<&BuildInteropArtifacts>,
) -> String {
    match format {
        Format::Text => {
            let mut fields = vec![
                ("status", artifact.status.to_string()),
                ("module", artifact.module.clone()),
                ("profile", format!("{:?}", artifact.profile)),
                ("diagnostics", artifact.diagnostics.to_string()),
                (
                    "static_lib",
                    artifact
                        .static_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "shared_lib",
                    artifact
                        .shared_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "threads",
                    threads
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "default".to_string()),
                ),
                (
                    "runtime_config",
                    runtime_config
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "dep_graph_hash",
                    artifact
                        .dependency_graph_hash
                        .clone()
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
                (
                    "policy",
                    policy_summary_text(
                        artifact.profile.as_str(),
                        Some("compiler"),
                        None,
                        artifact.dependency_graph_hash.is_some(),
                    ),
                ),
            ];
            if let Some(interop) = interop {
                fields.push(("header", interop.headers.path.display().to_string()));
                fields.push((
                    "abi_manifest",
                    interop.headers.abi_manifest.display().to_string(),
                ));
                fields.push((
                    "artifact_manifest",
                    interop.artifact_manifest.display().to_string(),
                ));
                fields.push(("exports", interop.headers.exports.to_string()));
                if !interop.export_symbols.is_empty() {
                    fields.push(("export_symbols", interop.export_symbols.join(", ")));
                }
            }
            let mut rendered = render_text_fields(&fields);
            let details = render_diagnostics_text(&artifact.diagnostic_details);
            if !details.is_empty() {
                rendered.push('\n');
                rendered.push_str(&details);
            }
            rendered
        }
        Format::Json => serde_json::json!({
            "module": artifact.module,
            "profile": format!("{:?}", artifact.profile),
            "status": artifact.status,
            "diagnostics": artifact.diagnostics,
            "items": artifact.diagnostic_details,
            "dependencyGraphHash": artifact.dependency_graph_hash,
            "policy": {
                "profile": artifact.profile.as_str(),
                "unsafeEnforcement": "profile-driven",
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": if artifact.dependency_graph_hash.is_some() { "present" } else { "n/a" },
            },
            "threads": threads,
            "runtimeConfig": runtime_config.map(|path| path.display().to_string()),
            "buildMode": "lib",
            "staticLib": artifact
                .static_lib
                .as_ref()
                .map(|path| path.display().to_string()),
            "sharedLib": artifact
                .shared_lib
                .as_ref()
                .map(|path| path.display().to_string()),
            "header": interop.map(|value| value.headers.path.display().to_string()),
            "abiManifest": interop.map(|value| value.headers.abi_manifest.display().to_string()),
            "artifactManifest": interop.map(|value| value.artifact_manifest.display().to_string()),
            "exports": interop.map(|value| value.headers.exports),
            "exportSymbols": interop.map(|value| value.export_symbols.clone()).unwrap_or_default(),
        })
        .to_string(),
    }
}

fn render_output(format: Format, output: Output) -> String {
    let errors = output
        .diagnostic_details
        .iter()
        .filter(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error))
        .count();
    let warnings = output
        .diagnostic_details
        .iter()
        .filter(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Warning))
        .count();
    let unsafe_enforcement = match output.validation_tier {
        crate::pipeline::ValidationTier::Check => "structural",
        crate::pipeline::ValidationTier::Verify => "strict",
    };
    match format {
        Format::Text => {
            let mut rendered = render_text_fields(&[
                ("module", output.module.clone()),
                ("nodes", output.nodes.to_string()),
                ("diagnostics", output.diagnostics.to_string()),
                ("errors", errors.to_string()),
                ("warnings", warnings.to_string()),
                (
                    "policy",
                    policy_summary_text(
                        output.validation_tier.as_str(),
                        Some(unsafe_enforcement),
                        None,
                        true,
                    ),
                ),
                ("parse_ms", output.telemetry.parse_ms.to_string()),
                ("lower_ms", output.telemetry.lower_ms.to_string()),
                ("verify_ms", output.telemetry.verify_ms.to_string()),
                ("backend_ms", output.telemetry.backend_ms.to_string()),
                ("contract_ms", output.telemetry.contract_ms.to_string()),
                ("total_ms", output.telemetry.total_ms.to_string()),
                (
                    "parse_cache_hit",
                    output.telemetry.parse_cache_hit.to_string(),
                ),
                (
                    "lower_cache_hit",
                    output.telemetry.lower_cache_hit.to_string(),
                ),
                ("input_bytes", output.telemetry.input_bytes.to_string()),
            ]);
            let details = render_diagnostics_text(&output.diagnostic_details);
            if !details.is_empty() {
                rendered.push('\n');
                rendered.push_str(&details);
            }
            if let Some(ir) = &output.backend_ir {
                rendered.push('\n');
                rendered.push_str(ir);
            }
            rendered
        }
        Format::Json => serde_json::json!({
            "schemaVersion": diagnostics::DIAGNOSTICS_SCHEMA_VERSION,
            "module": output.module,
            "nodes": output.nodes,
            "diagnostics": output.diagnostics,
            "errors": errors,
            "warnings": warnings,
            "policy": {
                "profile": output.validation_tier.as_str(),
                "unsafeEnforcement": unsafe_enforcement,
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": "present-or-created",
            },
            "telemetry": {
                "parseMs": output.telemetry.parse_ms,
                "lowerMs": output.telemetry.lower_ms,
                "verifyMs": output.telemetry.verify_ms,
                "backendMs": output.telemetry.backend_ms,
                "contractMs": output.telemetry.contract_ms,
                "totalMs": output.telemetry.total_ms,
                "parseCacheHit": output.telemetry.parse_cache_hit,
                "lowerCacheHit": output.telemetry.lower_cache_hit,
                "inputBytes": output.telemetry.input_bytes,
            },
            "items": output.diagnostic_details,
            "backendIr": output.backend_ir,
        })
        .to_string(),
    }
}

fn render_run_compile_abort(format: Format, artifact: &BuildArtifact) -> String {
    match format {
        Format::Text => {
            let mut rendered =
                String::from("run aborted before execution due to compile-time diagnostics\n");
            rendered.push_str(&render_artifact(
                Format::Text,
                artifact.clone(),
                None,
                None,
                None,
            ));
            rendered
        }
        Format::Json => serde_json::json!({
            "status": "error",
            "phase": "compile",
            "message": "run aborted before execution due to compile-time diagnostics",
            "module": artifact.module,
            "profile": format!("{:?}", artifact.profile),
            "diagnostics": artifact.diagnostics,
            "items": artifact.diagnostic_details,
            "output": artifact.output.as_ref().map(|path| path.display().to_string()),
            "dependencyGraphHash": artifact.dependency_graph_hash,
        })
        .to_string(),
    }
}

fn render_diagnostics_text(items: &[diagnostics::Diagnostic]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut source_cache: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut out = String::new();
    for (index, diagnostic) in items.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let severity = match diagnostic.severity {
            diagnostics::Severity::Error => "error",
            diagnostics::Severity::Warning => "warning",
            diagnostics::Severity::Note => "note",
        };
        if let Some(code) = &diagnostic.code {
            out.push_str(&format!("{severity}[{code}]: {}\n", diagnostic.message));
        } else {
            out.push_str(&format!("{severity}: {}\n", diagnostic.message));
        }
        if let (Some(path), Some(span)) = (&diagnostic.path, &diagnostic.span) {
            out.push_str(&format!(
                " --> {path}:{}:{}\n",
                span.start_line, span.start_col
            ));
            if let Some(frame) = render_code_frame(path, span, &mut source_cache) {
                out.push_str(&frame);
            }
        } else if let Some(path) = &diagnostic.path {
            out.push_str(&format!(" --> {path}\n"));
            if let Some(snippet) = &diagnostic.snippet {
                out.push_str(&format!(" snippet: {snippet}\n"));
            }
        }
        for label in &diagnostic.labels {
            let role = if label.primary { "primary" } else { "related" };
            if let Some(span) = &label.span {
                out.push_str(&format!(
                    " {role}: {} ({}:{}-{}:{})\n",
                    label.message, span.start_line, span.start_col, span.end_line, span.end_col
                ));
                if !label.primary {
                    let path = diagnostic.path.as_deref().unwrap_or("<unknown>");
                    out.push_str(&format!(
                        "  related --> {path}:{}:{}\n",
                        span.start_line, span.start_col
                    ));
                    if let Some(frame) = render_code_frame(path, span, &mut source_cache) {
                        out.push_str(&frame);
                    }
                }
            } else {
                out.push_str(&format!(" {role}: {}\n", label.message));
            }
        }
        if let Some(help) = &diagnostic.help {
            out.push_str(&format!(" help: {help}\n"));
        }
        if let Some(fix) = &diagnostic.fix {
            out.push_str(&format!(" fix: {fix}\n"));
        }
        out.push_str(&format!(" root_cause: {}\n", diagnostic.message));
        if let Some(catalog_key) = &diagnostic.catalog_key {
            out.push_str(&format!(" catalog_key: {catalog_key}\n"));
        }
        let verify_with = diagnostic
            .path
            .as_deref()
            .map(|path| format!("fz check {path}"))
            .unwrap_or_else(|| "fz check <path>".to_string());
        if let Some(catalog_key) = &diagnostic.catalog_key {
            out.push_str(&format!(" explain: fz explain {catalog_key}\n"));
        } else if let Some(code) = &diagnostic.code {
            out.push_str(&format!(" explain: fz explain {code}\n"));
        }
        out.push_str(&format!(" verify_with: {verify_with}\n"));
        out.push_str(&format!(
            " repro_token: {}\n",
            diagnostic_repro_token(diagnostic)
        ));
        out.push_str(&format!(
            " repro_with: {}\n",
            diagnostic_repro_command(diagnostic)
        ));
        for note in &diagnostic.notes {
            out.push_str(&format!(" note: {note}\n"));
        }
        for suggestion in &diagnostic.suggested_fixes {
            out.push_str(&format!(" suggestion: {suggestion}\n"));
        }
    }
    out.trim_end().to_string()
}

fn diagnostic_repro_token(diagnostic: &diagnostics::Diagnostic) -> String {
    let code = diagnostic.code.as_deref().unwrap_or("NO-CODE");
    let path = diagnostic.path.as_deref().unwrap_or("<path>");
    format!("schema=v1;code={code};profile=verify;backend=compiler;seed=1;path={path}")
}

fn diagnostic_repro_command(diagnostic: &diagnostics::Diagnostic) -> String {
    if let Some(path) = &diagnostic.path {
        format!(
            "fz check {} --json && fz verify {} --json",
            shell_escape(path),
            shell_escape(path)
        )
    } else {
        "fz check <path> --json && fz verify <path> --json".to_string()
    }
}

fn shell_escape(input: &str) -> String {
    if input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        return input.to_string();
    }
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn render_code_frame(
    path: &str,
    span: &diagnostics::Span,
    cache: &mut BTreeMap<String, Vec<String>>,
) -> Option<String> {
    let lines = if let Some(lines) = cache.get(path) {
        lines
    } else {
        let source = std::fs::read_to_string(path).ok()?;
        let loaded = source.lines().map(ToString::to_string).collect::<Vec<_>>();
        cache.insert(path.to_string(), loaded);
        cache.get(path)?
    };
    if span.start_line == 0 || span.start_line > lines.len() {
        return None;
    }
    let start_line = span.start_line.max(1).min(lines.len());
    let end_line = span.end_line.max(start_line).min(lines.len());
    let first_context = start_line.saturating_sub(1).max(1);
    let last_context = (end_line + 1).min(lines.len());
    let gutter_width = last_context.to_string().len();
    let mut frame = String::new();
    for line_no in first_context..=last_context {
        let line = &lines[line_no - 1];
        frame.push_str(&format!(
            " {:>width$} | {line}\n",
            line_no,
            width = gutter_width
        ));
        if (start_line..=end_line).contains(&line_no) {
            let line_len = line.chars().count();
            let highlight_start = if line_no == start_line {
                span.start_col.max(1)
            } else {
                1
            };
            let highlight_end = if line_no == end_line {
                span.end_col.max(highlight_start)
            } else {
                line_len.max(highlight_start)
            };
            let mut marker = String::new();
            marker.push_str(&" ".repeat(highlight_start.saturating_sub(1)));
            marker.push_str(&"^".repeat(highlight_end.saturating_sub(highlight_start) + 1));
            frame.push_str(&format!(
                " {:>width$} | {marker}\n",
                "",
                width = gutter_width
            ));
        }
    }
    Some(frame)
}

fn check_file_with_root_guidance(path: &Path) -> Result<Output> {
    check_file(path).map_err(|error| attach_project_root_guidance(path, error))
}

fn verify_file_with_root_guidance(path: &Path) -> Result<Output> {
    verify_file(path).map_err(|error| attach_project_root_guidance(path, error))
}

fn compile_file_with_backend_with_root_guidance(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    compile_file_with_backend(path, profile, backend_override)
        .map_err(|error| attach_project_root_guidance(path, error))
}

fn compile_library_with_backend_with_root_guidance(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<LibraryArtifact> {
    compile_library_with_backend(path, profile, backend_override)
        .map_err(|error| attach_project_root_guidance(path, error))
}

fn attach_project_root_guidance(path: &Path, error: anyhow::Error) -> anyhow::Error {
    let text = error.to_string();
    if !(text.contains("no valid compiler manifest found")
        || text.contains("path is neither a source file nor a project directory")
        || text.contains("expected a `.fzy` source file or a project directory"))
    {
        return error;
    }
    if path.is_file() {
        return error;
    }
    let manifest_path = path.join("fozzy.toml");
    if manifest_path.exists() {
        return error;
    }
    let nested = discover_nested_project_roots(path);
    if nested.is_empty() {
        anyhow!(
            "directory `{}` is not a Fozzy project root (missing {}). initialize a project here with `fz init [path]` or run against a project directory/file explicitly",
            path.display(),
            manifest_path.display()
        )
    } else {
        anyhow!(
            "directory `{}` is not a Fozzy project root (missing {}). detected nested project(s): {}. run the command against one of those project roots explicitly",
            path.display(),
            manifest_path.display(),
            nested
                .iter()
                .map(|candidate| candidate.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn maybe_generate_build_interop_artifacts(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<Option<BuildInteropArtifacts>> {
    if !project_has_c_exports(path)? {
        return Ok(None);
    }
    let library = compile_library_with_backend_with_root_guidance(path, profile, backend_override)?;
    let headers = generate_c_headers(path, None)?;
    Ok(Some(finalize_build_interop_artifacts(
        path, &library, headers,
    )?))
}

fn finalize_build_interop_artifacts(
    path: &Path,
    library: &LibraryArtifact,
    headers: HeaderArtifact,
) -> Result<BuildInteropArtifacts> {
    let export_symbols = read_abi_export_symbols(&headers.abi_manifest)?;
    let artifact_manifest =
        write_interop_artifact_manifest(path, library, &headers, &export_symbols)?;
    Ok(BuildInteropArtifacts {
        library: library.clone(),
        headers,
        artifact_manifest,
        export_symbols,
    })
}

fn read_abi_export_symbols(abi_manifest: &Path) -> Result<Vec<String>> {
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(abi_manifest)
            .with_context(|| format!("failed reading {}", abi_manifest.display()))?,
    )
    .with_context(|| format!("failed parsing {}", abi_manifest.display()))?;
    Ok(value
        .get("exports")
        .and_then(|exports| exports.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("name").and_then(|name| name.as_str()))
        .map(ToString::to_string)
        .collect())
}

fn write_interop_artifact_manifest(
    path: &Path,
    library: &LibraryArtifact,
    headers: &HeaderArtifact,
    export_symbols: &[String],
) -> Result<PathBuf> {
    let resolved = resolve_source(path)?;
    let manifest_path = headers.path.with_extension("artifacts.json");
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("artifact manifest path must have a parent directory"))?;
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.interop_artifacts.v1",
        "source": manifest_relative_path(manifest_dir, &resolved.source_path),
        "projectRoot": manifest_relative_path(manifest_dir, &resolved.project_root),
        "module": library.module,
        "profile": library.profile.as_str(),
        "buildMode": "lib",
        "staticLib": library.static_lib.as_ref().map(|path| manifest_relative_path(manifest_dir, path)),
        "sharedLib": library.shared_lib.as_ref().map(|path| manifest_relative_path(manifest_dir, path)),
        "header": manifest_relative_path(manifest_dir, &headers.path),
        "abiManifest": manifest_relative_path(manifest_dir, &headers.abi_manifest),
        "artifactManifest": manifest_relative_path(manifest_dir, &manifest_path),
        "exports": export_symbols,
        "hostLifecycle": {
            "init": "fz_host_init",
            "shutdown": "fz_host_shutdown",
            "cleanup": "fz_host_cleanup",
            "lastErrorCode": "fz_host_last_error_code",
            "lastErrorClass": "fz_host_last_error_class",
            "lastErrorMessage": "fz_host_last_error_message",
            "registerCallbackI32": "fz_host_register_callback_i32",
            "invokeCallbackI32": "fz_host_invoke_callback_i32",
        },
    });
    let bytes = serde_json::to_vec_pretty(&payload)?;
    if std::fs::read(&manifest_path).ok().as_deref() != Some(bytes.as_slice()) {
        std::fs::write(&manifest_path, &bytes)
            .with_context(|| format!("failed writing {}", manifest_path.display()))?;
    }
    Ok(manifest_path)
}

fn manifest_relative_path(base: &Path, path: &Path) -> String {
    relative_path_from(base, path).unwrap_or_else(|| path.to_string_lossy().into_owned())
}

fn relative_path_from(base: &Path, path: &Path) -> Option<String> {
    let base_components = normalized_path_components(base)?;
    let path_components = normalized_path_components(path)?;
    if base_components.first()? != path_components.first()? {
        return None;
    }

    let mut shared = 0usize;
    while shared < base_components.len()
        && shared < path_components.len()
        && base_components[shared] == path_components[shared]
    {
        shared += 1;
    }

    let mut relative = PathBuf::new();
    for _ in shared..base_components.len() {
        relative.push("..");
    }
    for component in &path_components[shared..] {
        relative.push(component);
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Some(relative.to_string_lossy().into_owned())
}

fn normalized_path_components(path: &Path) -> Option<Vec<String>> {
    use std::path::Component;

    let mut out = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                out.push(prefix.as_os_str().to_string_lossy().into_owned())
            }
            Component::RootDir => out.push("/".to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if out.last().is_some_and(|segment| segment != "/") {
                    out.pop();
                } else {
                    return None;
                }
            }
            Component::Normal(part) => out.push(part.to_string_lossy().into_owned()),
        }
    }
    Some(out)
}

fn project_has_c_exports(path: &Path) -> Result<bool> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    Ok(parsed.module.items.iter().any(|item| match item {
        ast::Item::Function(function) => {
            function.is_pub
                && function.is_extern
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        }
        _ => false,
    }))
}

fn maybe_generate_unsafe_docs(path: &Path) -> Option<PathBuf> {
    let resolved = resolve_source(path).ok()?;
    let parsed = parse_program(&resolved.source_path).ok()?;
    if parsed.module.unsafe_sites == 0 {
        return None;
    }
    let docs_path = resolved.project_root.join(".fz/unsafe-docs.md");
    if unsafe_docs_cache_hit(path, &docs_path).ok()? {
        return Some(docs_path);
    }
    if audit_unsafe_command(&resolved.project_root, false, Format::Json).is_ok() {
        let _ = write_unsafe_docs_cache_stamp(path, &docs_path);
        Some(docs_path)
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsafeDocsCacheStamp {
    fingerprint: String,
}

fn unsafe_docs_cache_hit(path: &Path, docs_path: &Path) -> Result<bool> {
    let stamp_path = unsafe_docs_cache_path(docs_path);
    let json_path = docs_path.with_extension("json");
    let html_path = docs_path.with_extension("html");
    if !docs_path.exists() || !json_path.exists() || !html_path.exists() || !stamp_path.exists() {
        return Ok(false);
    }
    let stamp: UnsafeDocsCacheStamp = serde_json::from_slice(
        &std::fs::read(&stamp_path)
            .with_context(|| format!("failed reading {}", stamp_path.display()))?,
    )
    .with_context(|| format!("failed parsing {}", stamp_path.display()))?;
    Ok(stamp.fingerprint == unsafe_docs_fingerprint(path)?)
}

fn write_unsafe_docs_cache_stamp(path: &Path, docs_path: &Path) -> Result<()> {
    let stamp_path = unsafe_docs_cache_path(docs_path);
    let payload = UnsafeDocsCacheStamp {
        fingerprint: unsafe_docs_fingerprint(path)?,
    };
    if let Some(parent) = stamp_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&stamp_path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing {}", stamp_path.display()))
}

fn unsafe_docs_cache_path(docs_path: &Path) -> PathBuf {
    docs_path.with_extension("stamp.json")
}

fn unsafe_docs_fingerprint(path: &Path) -> Result<String> {
    let module_set = load_resolved_module_set(path)?;
    let mut hasher = Sha256::new();
    hasher.update(
        module_set
            .resolved
            .project_root
            .to_string_lossy()
            .as_bytes(),
    );
    hasher.update(module_set.resolved.source_path.to_string_lossy().as_bytes());
    if let Some(manifest) = module_set.resolved.manifest.as_ref() {
        hasher.update(manifest.package.name.as_bytes());
        hasher.update(manifest.package.version.as_bytes());
    }
    for module in &module_set.modules {
        hasher.update(module.path.to_string_lossy().as_bytes());
        hasher.update(module.source.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) const DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION: &str = "fozzylang.diagnostic_explain.v1";
pub(crate) const LSP_DIAGNOSTIC_DATA_SCHEMA_VERSION: &str = "fozzylang.lsp_diagnostic_data.v1";

fn explain_command(diag_code: &str, format: Format) -> Result<String> {
    let raw = diag_code.trim();
    let normalized = raw.to_ascii_uppercase();
    if normalized.is_empty() {
        bail!("missing diagnostic code: usage `fz explain <diag-code>`");
    }
    let catalog = diagnostic_catalog();
    if normalized == "CATALOG" || normalized == "--CATALOG" {
        return match format {
            Format::Text => Ok(catalog
                .iter()
                .map(|entry| {
                    format!(
                        "code_prefix: {}\nfamily: {}\nsummary: {}\nexample: {}\nnext_command: {}",
                        entry.code_prefix,
                        entry.family,
                        entry.summary,
                        entry.example,
                        entry.next_command
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n")),
            Format::Json => Ok(serde_json::json!({
                "schemaVersion": "fozzylang.diagnostic_catalog.v1",
                "entries": catalog,
            })
            .to_string()),
        };
    }
    let resolution = resolve_diagnostic_explain(raw);
    match format {
        Format::Text => {
            let mut fields = vec![
                ("code", resolution.normalized.clone()),
                ("family", resolution.family.clone()),
                ("root_cause", resolution.root_cause.clone()),
                ("likely_fix", resolution.likely_fix.clone()),
                ("verify_with", "fz check <path> --json".to_string()),
                (
                    "diagnostic_identity",
                    "codes are stable within a domain for unchanged message and source anchor"
                        .to_string(),
                ),
                ("explain_command", resolution.explain_command.clone()),
            ];
            if let Some(entry) = resolution.catalog_entry {
                fields.push(("catalog_key", entry.key));
                fields.push(("catalog_summary", entry.summary));
                fields.push(("catalog_example", entry.example));
                fields.push(("common_triggers", entry.common_triggers.join(" | ")));
                fields.push(("production_action", entry.production_action));
                fields.push(("production_risk", entry.production_risk));
                fields.push(("next_command", entry.next_command));
            }
            Ok(render_text_fields(&fields))
        }
        Format::Json => Ok(serde_json::json!({
            "schemaVersion": DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION,
            "code": resolution.normalized,
            "family": resolution.family,
            "rootCause": resolution.root_cause,
            "likelyFix": resolution.likely_fix,
            "verifyWith": "fz check <path> --json",
            "diagnosticIdentity": "codes are stable within a domain for unchanged message and source anchor",
            "catalog": resolution.catalog_entry,
            "catalogKey": resolution.catalog_key,
            "commonTriggers": resolution.common_triggers,
            "productionAction": resolution.production_action,
            "productionRisk": resolution.production_risk,
            "nextCommand": resolution.next_command,
            "explainCommand": resolution.explain_command,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DiagnosticCatalogEntry {
    key: String,
    code_prefix: String,
    family: String,
    summary: String,
    example: String,
    likely_fix: String,
    common_triggers: Vec<String>,
    production_action: String,
    production_risk: String,
    next_command: String,
}

#[derive(Debug, Clone)]
pub(crate) struct DiagnosticExplainResolution {
    pub normalized: String,
    pub family: String,
    pub root_cause: String,
    pub likely_fix: String,
    pub catalog_entry: Option<DiagnosticCatalogEntry>,
    pub catalog_key: Option<String>,
    pub common_triggers: Vec<String>,
    pub production_action: Option<String>,
    pub production_risk: Option<String>,
    pub next_command: String,
    pub explain_command: String,
}

pub(crate) fn resolve_diagnostic_explain(raw: &str) -> DiagnosticExplainResolution {
    let normalized = raw.trim().to_ascii_uppercase();
    let catalog = diagnostic_catalog();
    let catalog_entry = catalog
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(raw))
        .cloned()
        .or_else(|| {
            catalog
                .iter()
                .find(|entry| normalized.starts_with(&entry.code_prefix))
                .cloned()
        });
    let family = catalog_entry
        .as_ref()
        .map(|entry| entry.family.clone())
        .unwrap_or_else(|| {
            if normalized.starts_with("E-PAR-") || normalized.starts_with("W-PAR-") {
                "parser".to_string()
            } else if normalized.starts_with("E-HIR-") || normalized.starts_with("W-HIR-") {
                "hir".to_string()
            } else if normalized.starts_with("E-VER-") || normalized.starts_with("W-VER-") {
                "verifier".to_string()
            } else if normalized.starts_with("E-NAT-") || normalized.starts_with("W-NAT-") {
                "native-lowering".to_string()
            } else if normalized.starts_with("E-DRV-") || normalized.starts_with("W-DRV-") {
                "driver".to_string()
            } else {
                "unknown".to_string()
            }
        });
    let likely_fix = catalog_entry
        .as_ref()
        .map(|entry| entry.likely_fix.clone())
        .unwrap_or_else(|| match family.as_str() {
            "parser" => "Fix syntax at the primary span, then rerun `fz check <path>`.".to_string(),
            "hir" => "Fix name/type mismatch and rerun `fz check <path>`.".to_string(),
            "verifier" => {
                "Fix policy/type contract violation and rerun `fz verify <path>`.".to_string()
            }
            "native-lowering" => {
                "Adjust unsupported lowering shape or switch backend, then rerun `fz build <path>`."
                    .to_string()
            }
            "driver" => {
                "Fix project/configuration issue and rerun the failing command.".to_string()
            }
            _ => {
                "Run `fz check <path>` to regenerate diagnostics with spans and helps.".to_string()
            }
        });
    let root_cause = catalog_entry
        .as_ref()
        .map(|entry| entry.summary.clone())
        .unwrap_or_else(|| format!("diagnostic family `{family}`"));
    let next_command = catalog_entry
        .as_ref()
        .map(|entry| entry.next_command.clone())
        .unwrap_or_else(|| "fz check <path> --json".to_string());
    let explain_target = catalog_entry
        .as_ref()
        .map(|entry| entry.key.clone())
        .unwrap_or_else(|| normalized.clone());
    DiagnosticExplainResolution {
        normalized,
        family,
        root_cause,
        likely_fix,
        catalog_key: catalog_entry.as_ref().map(|entry| entry.key.clone()),
        common_triggers: catalog_entry
            .as_ref()
            .map(|entry| entry.common_triggers.clone())
            .unwrap_or_default(),
        production_action: catalog_entry
            .as_ref()
            .map(|entry| entry.production_action.clone()),
        production_risk: catalog_entry
            .as_ref()
            .map(|entry| entry.production_risk.clone()),
        next_command,
        explain_command: format!("fz explain {explain_target}"),
        catalog_entry,
    }
}

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

fn perf_command(artifact: Option<&Path>, format: Format) -> Result<String> {
    let path = artifact
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("artifacts/bench_corelibs_rust_vs_fzy.json"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading benchmark artifact {}", path.display()))?;
    let payload: serde_json::Value =
        serde_json::from_str(&text).context("invalid benchmark artifact JSON")?;
    let benches = payload
        .get("benches")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("benchmark artifact missing `benches` array"))?;
    let mut worst = ("".to_string(), 0.0f64);
    let mut sum = 0.0f64;
    let mut count = 0usize;
    for bench in benches {
        let name = bench
            .get("bench")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let ratio = bench
            .get("ratio_fzy_over_rust")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);
        if ratio > worst.1 {
            worst = (name, ratio);
        }
        sum += ratio;
        count += 1;
    }
    let avg = if count == 0 { 0.0 } else { sum / count as f64 };
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "perf".to_string()),
            ("artifact", path.display().to_string()),
            ("bench_count", count.to_string()),
            ("average_ratio_fzy_over_rust", format!("{avg:.6}")),
            ("worst_kernel", worst.0),
            ("worst_ratio_fzy_over_rust", format!("{:.6}", worst.1)),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "perf",
            "artifact": path.display().to_string(),
            "benchCount": count,
            "averageRatioFzyOverRust": avg,
            "worstKernel": worst.0,
            "worstRatioFzyOverRust": worst.1,
        })
        .to_string()),
    }
}

fn stability_dashboard_command(format: Format) -> Result<String> {
    let repo_root = repo_root();
    let exit_criteria_script = repo_root.join("scripts/exit_criteria.py");
    let exit_status = ProcessCommand::new("python3")
        .arg(&exit_criteria_script)
        .arg("status")
        .current_dir(&repo_root)
        .output()
        .context("failed to run exit criteria status command")?;
    if !exit_status.status.success() {
        bail!(
            "exit criteria status failed for {}",
            exit_criteria_script.display()
        );
    }
    let exit_payload: serde_json::Value =
        serde_json::from_slice(&exit_status.stdout).context("invalid exit criteria payload")?;
    let dashboard = serde_json::json!({
        "schemaVersion": "fozzylang.stability_dashboard.v1",
        "generatedAt": chrono_like_now_utc(),
        "compatibility": fzscenario::compatibility_info(),
        "maturity": exit_payload.get("seriousSystemsLanguageMaturity").cloned().unwrap_or(serde_json::Value::Bool(false)),
        "criteria": exit_payload.get("criteria").cloned().unwrap_or(serde_json::json!({})),
        "performance": {
            "summaryCommand": "fz perf [--artifact artifacts/bench_corelibs_rust_vs_fzy.json]",
            "artifact": "artifacts/bench_corelibs_rust_vs_fzy.json",
            "workloads": [
                {"name": "cli_startup", "description": "CLI startup latency"},
                {"name": "http_throughput", "description": "HTTP request throughput"},
                {"name": "json_build_parse", "description": "JSON construction and parsing"},
                {"name": "proc_spawn_wait", "description": "process spawn and wait"},
                {"name": "stream_reading", "description": "stream reading throughput"},
                {"name": "task_group_execution", "description": "task-group execution"},
                {"name": "compiler_parse_lower_build", "description": "compiler parse, lower, and build time"},
                {"name": "native_binary_size", "description": "native binary size"},
            ],
        },
        "sources": {
            "exitCriteria": "release/exit_criteria_state.json",
            "plan": "PLAN.md",
            "perfArtifact": "artifacts/bench_corelibs_rust_vs_fzy.json"
        }
    });
    let path = PathBuf::from("artifacts/stability_dashboard.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&dashboard)?)
        .with_context(|| format!("failed writing {}", path.display()))?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "stability-dashboard".to_string()),
            ("artifact", path.display().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "stability-dashboard",
            "artifact": path.display().to_string(),
            "dashboard": dashboard,
        })
        .to_string()),
    }
}

fn chrono_like_now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    name: String,
    status: String,
    detail: String,
    fix: String,
}

fn doctor_project_command(path: &Path, strict: bool, format: Format) -> Result<String> {
    let project_root = if path.is_file() {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        path.to_path_buf()
    };
    if !project_root.is_dir() {
        bail!(
            "doctor project requires a project directory (or file within a project): {}",
            path.display()
        );
    }
    let manifest_path = project_root.join("fozzy.toml");
    let mut checks = Vec::<DoctorCheck>::new();
    let mut errors = 0usize;
    let mut warnings = 0usize;

    let manifest_text = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => {
            checks.push(DoctorCheck {
                name: "manifest".to_string(),
                status: "ok".to_string(),
                detail: format!("loaded {}", manifest_path.display()),
                fix: "n/a".to_string(),
            });
            text
        }
        Err(_) => {
            checks.push(DoctorCheck {
                name: "manifest".to_string(),
                status: "error".to_string(),
                detail: format!("missing {}", manifest_path.display()),
                fix: "add fozzy.toml or run `fz init [path]`".to_string(),
            });
            errors += 1;
            String::new()
        }
    };

    let manifest = if manifest_text.is_empty() {
        None
    } else {
        match manifest::load(&manifest_text)
            .map_err(anyhow::Error::from)
            .and_then(|loaded| loaded.validate().map(|_| loaded).map_err(|e| anyhow!(e)))
        {
            Ok(parsed) => Some(parsed),
            Err(err) => {
                checks.push(DoctorCheck {
                    name: "manifest-validate".to_string(),
                    status: "error".to_string(),
                    detail: err.to_string(),
                    fix: "fix fozzy.toml to satisfy manifest schema".to_string(),
                });
                errors += 1;
                None
            }
        }
    };

    if manifest.is_some() {
        let lock_status = match refresh_lockfile(&project_root) {
            Ok(lock_hash) => DoctorCheck {
                name: "lockfile".to_string(),
                status: "ok".to_string(),
                detail: format!("fozzy.lock validated (hash={lock_hash})"),
                fix: "n/a".to_string(),
            },
            Err(err) => {
                errors += 1;
                DoctorCheck {
                    name: "lockfile".to_string(),
                    status: "error".to_string(),
                    detail: err.to_string(),
                    fix: "run `fz vendor <project-root>` after fixing dependency graph issues"
                        .to_string(),
                }
            }
        };
        checks.push(lock_status);
        let vendor_manifest = project_root.join("vendor/fozzy-vendor.json");
        if vendor_manifest.exists() {
            checks.push(DoctorCheck {
                name: "vendor".to_string(),
                status: "ok".to_string(),
                detail: format!("found {}", vendor_manifest.display()),
                fix: "n/a".to_string(),
            });
        } else {
            warnings += 1;
            checks.push(DoctorCheck {
                name: "vendor".to_string(),
                status: "warn".to_string(),
                detail: "vendor manifest missing".to_string(),
                fix: "run `fz vendor <project-root>` for fully reproducible dependency snapshots"
                    .to_string(),
            });
        }
    }

    if let Ok(resolved) = resolve_source(&project_root) {
        if let Ok(parsed) = parse_program(&resolved.source_path) {
            let mut deprecated_unsafe_meta = 0usize;
            let mut async_unsafe_overlap = 0usize;
            let mut backend_risk_ops = 0usize;
            for module_path in &parsed.module_paths {
                if let Ok(text) = std::fs::read_to_string(module_path) {
                    deprecated_unsafe_meta += text.matches("unsafe_reason(").count();
                    deprecated_unsafe_meta += text.matches("unsafe(").count();
                    if text.contains("async fn") && text.contains("unsafe") {
                        async_unsafe_overlap += 1;
                    }
                    if text.contains("proc.run(") || text.contains("http.poll_next") {
                        backend_risk_ops += 1;
                    }
                }
            }
            if deprecated_unsafe_meta > 0 {
                errors += 1;
                checks.push(DoctorCheck {
                    name: "unsupported-syntax".to_string(),
                    status: "error".to_string(),
                    detail: format!("detected {deprecated_unsafe_meta} removed unsafe metadata syntax use(s)"),
                    fix: "remove inline unsafe metadata and rely on compiler-generated contracts/docs".to_string(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "unsupported-syntax".to_string(),
                    status: "ok".to_string(),
                    detail: "no removed unsafe metadata syntax detected".to_string(),
                    fix: "n/a".to_string(),
                });
            }
            if async_unsafe_overlap > 0 {
                warnings += 1;
                checks.push(DoctorCheck {
                    name: "async-unsafe".to_string(),
                    status: "warn".to_string(),
                    detail: format!(
                        "{async_unsafe_overlap} module(s) combine async and unsafe constructs"
                    ),
                    fix: "audit unsafe invariants in async contexts and keep strict verify enabled"
                        .to_string(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "async-unsafe".to_string(),
                    status: "ok".to_string(),
                    detail: "no async+unsafe overlap detected".to_string(),
                    fix: "n/a".to_string(),
                });
            }
            if backend_risk_ops > 0 {
                warnings += 1;
                checks.push(DoctorCheck {
                    name: "backend-risk".to_string(),
                    status: "warn".to_string(),
                    detail: format!("{backend_risk_ops} backend-risk operation pattern(s) detected"),
                    fix: "prefer host-backed `fozzy run` plus explicit backend in CI for these modules".to_string(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "backend-risk".to_string(),
                    status: "ok".to_string(),
                    detail: "no obvious backend-risk operations detected".to_string(),
                    fix: "n/a".to_string(),
                });
            }
            if let Some(manifest) = manifest.as_ref() {
                let strict_release = manifest.unsafe_policy.enforce_release.unwrap_or(true);
                let strict_verify = manifest.unsafe_policy.enforce_verify.unwrap_or(true);
                if strict_release && strict_verify {
                    checks.push(DoctorCheck {
                        name: "unsafe-posture".to_string(),
                        status: "ok".to_string(),
                        detail: "verify/release unsafe enforcement enabled".to_string(),
                        fix: "n/a".to_string(),
                    });
                } else {
                    warnings += 1;
                    checks.push(DoctorCheck {
                        name: "unsafe-posture".to_string(),
                        status: "warn".to_string(),
                        detail: "unsafe enforcement is relaxed for verify/release".to_string(),
                        fix: "set [unsafe].enforce_verify=true and enforce_release=true"
                            .to_string(),
                    });
                }
            }
        }
    }

    if strict && warnings > 0 {
        errors += warnings;
    }
    let status = if errors > 0 { "error" } else { "ok" };
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", status.to_string()),
            ("mode", "doctor-project".to_string()),
            ("project", project_root.display().to_string()),
            ("errors", errors.to_string()),
            ("warnings", warnings.to_string()),
            (
                "policy",
                policy_summary_text("verify", Some("profile-driven"), Some("compiler"), true),
            ),
            ("checks", doctor_checks_summary_text(&checks)),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": status,
            "mode": "doctor-project",
            "project": project_root.display().to_string(),
            "strict": strict,
            "errors": errors,
            "warnings": warnings,
            "policy": {
                "profile": "verify",
                "unsafeEnforcement": "profile-driven",
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": "present-or-created",
            },
            "checks": checks,
        })
        .to_string()),
    }
}

fn devloop_command(path: &Path, backend: Option<&str>, format: Format) -> Result<String> {
    let verify = verify_file_with_root_guidance(path)?;
    let compile = compile_file_with_backend_with_root_guidance(path, BuildProfile::Dev, backend)?;
    let plan = run_non_scenario_test_plan_with_root_guidance(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: true,
            safe_profile: false,
            scheduler: Some("fifo".to_string()),
            seed: Some(1),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    )?;
    let unsafe_docs = maybe_generate_unsafe_docs(path).map(|value| value.display().to_string());
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", compile.status.to_string()),
            ("mode", "devloop".to_string()),
            ("module", compile.module),
            ("verify_diagnostics", verify.diagnostics.to_string()),
            ("compile_diagnostics", compile.diagnostics.to_string()),
            ("scheduler", plan.scheduler),
            ("executed_tasks", plan.executed_tasks.to_string()),
            ("backend", backend.unwrap_or("cranelift").to_string()),
            (
                "policy",
                policy_summary_text("dev", Some("strict-verify"), backend, true),
            ),
            (
                "unsafe_docs",
                unsafe_docs.unwrap_or_else(|| "<none>".to_string()),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": compile.status,
            "mode": "devloop",
            "module": compile.module,
            "verifyDiagnostics": verify.diagnostics,
            "compileDiagnostics": compile.diagnostics,
            "scheduler": plan.scheduler,
            "executedTasks": plan.executed_tasks,
            "backend": backend.unwrap_or("cranelift"),
            "policy": {
                "profile": "dev",
                "unsafeEnforcement": "strict-verify",
                "memorySafetyMode": "production",
                "backend": backend.unwrap_or("cranelift"),
                "lockfileState": "present-or-created",
            },
            "unsafeDocs": unsafe_docs,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
struct SemanticsOutcome {
    mode: String,
    #[serde(rename = "exitClass")]
    exit_class: String,
    #[serde(rename = "eventKinds")]
    event_kinds: Vec<String>,
    invariants: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct FozzyTestSummary {
    #[serde(rename = "exitClass")]
    exit_class: String,
    passed: u64,
    failed: u64,
}

fn spec_doc_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("FZ_SPEC_PATH") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    PathBuf::from("docs/language-reference-v0.md")
}

#[derive(Debug, Clone, Serialize)]
struct DxIssue {
    level: &'static str,
    file: String,
    message: String,
}

fn dx_check_command(path: &Path, strict: bool, format: Format) -> Result<String> {
    if !path.is_dir() {
        bail!("dx-check requires a project directory: {}", path.display());
    }
    let resolved = resolve_source(path)?;
    let main_path = path.join("src/main.fzy");
    ensure_exists(&main_path)?;
    let main_source = std::fs::read_to_string(&main_path)
        .with_context(|| format!("failed reading {}", main_path.display()))?;
    let main_name = main_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("main");
    let main_ast = parser::parse(&main_source, main_name).map_err(|diagnostics| {
        anyhow!(
            "failed parsing {}: {} diagnostics",
            main_path.display(),
            diagnostics.len()
        )
    })?;
    let mut issues = Vec::<DxIssue>::new();
    let required = vec!["api", "model", "services", "runtime", "cli", "tests"];
    for module in &required {
        if !main_ast.modules.iter().any(|decl| decl == module) {
            issues.push(DxIssue {
                level: "error",
                file: main_path.display().to_string(),
                message: format!("missing `mod {module};` declaration in main.fzy"),
            });
        }
    }
    let observed = main_ast
        .modules
        .iter()
        .filter_map(|decl| {
            let root = decl.split("::").next()?.to_string();
            if required.iter().any(|expected| expected == &root) {
                Some(root)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if observed != required {
        issues.push(DxIssue {
            level: "error",
            file: main_path.display().to_string(),
            message: format!(
                "module declaration order must be `mod api; mod model; mod services; mod runtime; mod cli; mod tests;` (observed: {})",
                observed.join(", ")
            ),
        });
    }
    if main_source
        .lines()
        .any(|line| line.trim_start().starts_with("test \""))
    {
        issues.push(DxIssue {
            level: "error",
            file: main_path.display().to_string(),
            message: "test declarations are forbidden in main.fzy; move tests under src/tests/*"
                .to_string(),
        });
    }
    let main_is_last = matches!(
        main_ast.items.last(),
        Some(ast::Item::Function(function)) if function.name == "main"
    );
    if !main_is_last {
        issues.push(DxIssue {
            level: "error",
            file: main_path.display().to_string(),
            message: "fn main must be the last top-level item in main.fzy".to_string(),
        });
    }
    let required_mod_files = vec![
        path.join("src/api/mod.fzy"),
        path.join("src/model/mod.fzy"),
        path.join("src/services/mod.fzy"),
        path.join("src/runtime/mod.fzy"),
        path.join("src/cli/mod.fzy"),
        path.join("src/tests/mod.fzy"),
    ];
    for mod_file in required_mod_files {
        if !mod_file.exists() {
            issues.push(DxIssue {
                level: "error",
                file: mod_file.display().to_string(),
                message: "missing module entry file (mod.fzy)".to_string(),
            });
        }
    }
    let pre_orchestration_errors = issues.iter().filter(|issue| issue.level == "error").count();
    if pre_orchestration_errors == 0 {
        let combined = parsed_module_source(&resolved.project_root, &resolved.source_path)?;
        for module in ["api", "model", "services", "runtime", "cli"] {
            let needle = format!("{module}.");
            if !combined.contains(&needle) {
                issues.push(DxIssue {
                    level: "warning",
                    file: main_path.display().to_string(),
                    message: format!(
                        "module `{module}` appears declared but not orchestrated from main flow"
                    ),
                });
            }
        }
    }
    if strict && issues.iter().any(|issue| issue.level == "warning") {
        for issue in &mut issues {
            if issue.level == "warning" {
                issue.level = "error";
            }
        }
    }
    let error_count = issues.iter().filter(|issue| issue.level == "error").count();
    if error_count > 0 {
        bail!(
            "dx-check failed for {}: {} issue(s): {}",
            path.display(),
            issues.len(),
            issues
                .iter()
                .map(|issue| format!("[{}] {}", issue.level, issue.message))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "dx-check".to_string()),
            ("project", path.display().to_string()),
            ("strict", strict.to_string()),
            ("issues", issues.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "project": path.display().to_string(),
            "strict": strict,
            "issues": issues,
        })
        .to_string()),
    }
}

fn parsed_module_source(project_root: &Path, source_path: &Path) -> Result<String> {
    let parsed = parse_program(source_path)?;
    let mut combined = String::new();
    for path in parsed.module_paths {
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("failed reading module source: {}", path.display()))?;
        combined.push_str("// ");
        combined.push_str(
            path.strip_prefix(project_root)
                .unwrap_or(&path)
                .display()
                .to_string()
                .as_str(),
        );
        combined.push('\n');
        combined.push_str(&source);
        combined.push('\n');
    }
    Ok(combined)
}

fn spec_check(format: Format) -> Result<String> {
    let path = spec_doc_path();
    ensure_exists(&path)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading spec file: {}", path.display()))?;
    let required = vec![
        "## Evaluation Order",
        "## Integer Overflow",
        "## Error And Panic Semantics",
        "## Async Cancellation Semantics",
        "## Deterministic Scheduling Model",
        "## Capability Semantics",
        "## Memory Safety And UB Model",
    ];
    let missing = required
        .iter()
        .filter(|heading| !text.contains(**heading))
        .map(|heading| heading.to_string())
        .collect::<Vec<_>>();
    let ok = missing.is_empty();
    if !ok {
        bail!(
            "spec-check failed: missing sections in {}: {}",
            path.display(),
            missing.join(", ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "spec-check".to_string()),
            ("path", path.display().to_string()),
            ("sections", required.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": ok,
            "path": path.display().to_string(),
            "requiredSections": required,
            "missingSections": missing,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
struct PlanClaimGate {
    completed: usize,
    checked: usize,
    missing_evidence: Vec<String>,
}

fn validate_plan_claim_accuracy() -> Result<PlanClaimGate> {
    let plan_path = PathBuf::from("PLAN.md");
    if !plan_path.exists() {
        return Ok(PlanClaimGate {
            completed: 0,
            checked: 0,
            missing_evidence: Vec::new(),
        });
    }
    let plan_text = std::fs::read_to_string(&plan_path)
        .with_context(|| format!("failed reading plan file: {}", plan_path.display()))?;
    let mut files = Vec::new();
    collect_files_recursive(Path::new("."), Path::new("."), &mut files)?;
    let corpus = files
        .into_iter()
        .filter(|(rel, _)| rel.ends_with(".rs"))
        .filter_map(|(rel, full)| {
            let text = std::fs::read_to_string(&full).ok()?;
            Some((rel, text))
        })
        .collect::<Vec<_>>();
    Ok(analyze_plan_claim_accuracy(&plan_text, &corpus))
}

fn analyze_plan_claim_accuracy(plan_text: &str, corpus: &[(String, String)]) -> PlanClaimGate {
    let mut completed = 0usize;
    let mut checked = 0usize;
    let mut claims = Vec::<(String, Vec<String>)>::new();
    for line in plan_text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("- [✅]") {
            continue;
        }
        completed += 1;
        let mut tokens = Vec::new();
        let mut rest = trimmed;
        while let Some(start) = rest.find('`') {
            let tail = &rest[(start + 1)..];
            let Some(end) = tail.find('`') else {
                break;
            };
            let token = tail[..end].trim();
            if !token.is_empty() {
                tokens.push(token.to_string());
            }
            rest = &tail[(end + 1)..];
        }
        if !tokens.is_empty() {
            checked += 1;
            claims.push((trimmed.to_string(), tokens));
        }
    }
    let mut missing = Vec::new();
    for (claim, tokens) in claims {
        let mut has_source = false;
        let mut has_test = false;
        for token in &tokens {
            for (rel, text) in corpus {
                if !text.contains(token) {
                    continue;
                }
                if rel.contains("/tests/") || text.contains("#[test]") {
                    has_test = true;
                } else {
                    has_source = true;
                }
                if has_source && has_test {
                    break;
                }
            }
            if has_source && has_test {
                break;
            }
        }
        if !(has_source && has_test) {
            missing.push(claim);
        }
    }
    PlanClaimGate {
        completed,
        checked,
        missing_evidence: missing,
    }
}

fn parity_command(path: &Path, seed: u64, format: Format) -> Result<String> {
    ensure_exists(path)?;
    let resolved = resolve_source(path)?;
    let verifier = verify_file(&resolved.source_path)?;
    let verifier_signature = diagnostic_signature(&verifier.diagnostic_details)?;
    let backend_capabilities = backend_capability_report();
    if resolved
        .manifest
        .as_ref()
        .is_some_and(|manifest| manifest.target.lib.is_some() && manifest.target.bin.is_empty())
    {
        let llvm = compile_library_with_backend(path, BuildProfile::Dev, Some("llvm"))?;
        let cranelift = compile_library_with_backend(path, BuildProfile::Dev, Some("cranelift"))?;
        let llvm_diag = diagnostic_signature(&llvm.diagnostic_details)?;
        let cranelift_diag = diagnostic_signature(&cranelift.diagnostic_details)?;
        let llvm_static = library_exports(
            llvm.static_lib
                .as_deref()
                .ok_or_else(|| anyhow!("llvm library parity output missing static lib"))?,
        )?;
        let cranelift_static = library_exports(
            cranelift
                .static_lib
                .as_deref()
                .ok_or_else(|| anyhow!("cranelift library parity output missing static lib"))?,
        )?;
        let llvm_shared = library_exports(
            llvm.shared_lib
                .as_deref()
                .ok_or_else(|| anyhow!("llvm library parity output missing shared lib"))?,
        )?;
        let cranelift_shared = library_exports(
            cranelift
                .shared_lib
                .as_deref()
                .ok_or_else(|| anyhow!("cranelift library parity output missing shared lib"))?,
        )?;
        let mut issues = Vec::new();
        if llvm.status != cranelift.status {
            issues.push("llvm/cranelift library build status mismatch".to_string());
        }
        if llvm_diag != cranelift_diag {
            issues.push("llvm/cranelift library diagnostic mismatch".to_string());
        }
        if llvm_static != cranelift_static {
            issues.push("llvm/cranelift static export mismatch".to_string());
        }
        if llvm_shared != cranelift_shared {
            issues.push("llvm/cranelift shared export mismatch".to_string());
        }
        let signature = semantic_signature(&serde_json::json!({
            "kind": "backend-library-parity",
            "verifier": verifier_signature,
            "llvm": {
                "status": llvm.status,
                "diagnostics": llvm_diag,
                "static": llvm_static,
                "shared": llvm_shared,
            },
            "cranelift": {
                "status": cranelift.status,
                "diagnostics": cranelift_diag,
                "static": cranelift_static,
                "shared": cranelift_shared,
            },
        }))?;
        if !issues.is_empty() {
            bail!(
                "parity failed for {}: {}",
                path.display(),
                issues.join("; ")
            );
        }
        return match format {
            Format::Text => Ok(render_text_fields(&[
                ("status", "ok".to_string()),
                ("mode", "parity".to_string()),
                ("kind", "library".to_string()),
                ("path", path.display().to_string()),
                ("signature", signature),
            ])),
            Format::Json => Ok(serde_json::json!({
                "ok": true,
                "mode": "parity",
                "kind": "library",
                "path": path.display().to_string(),
                "seed": seed,
                "signature": signature,
                "verifier": {
                    "diagnostics": verifier.diagnostics,
                    "signature": verifier_signature,
                },
                "backendCapabilities": backend_capabilities,
                "backendResults": {
                    "llvm": {
                        "status": llvm.status,
                        "diagnostics": llvm.diagnostics,
                        "diagnosticSignature": llvm_diag,
                        "staticExports": llvm_static,
                        "sharedExports": llvm_shared,
                    },
                    "cranelift": {
                        "status": cranelift.status,
                        "diagnostics": cranelift.diagnostics,
                        "diagnosticSignature": cranelift_diag,
                        "staticExports": cranelift_static,
                        "sharedExports": cranelift_shared,
                    }
                },
                "checks": {
                    "sameVerifierResult": true,
                    "sameBuildStatus": llvm.status == cranelift.status,
                    "sameDiagnosticResult": llvm_diag == cranelift_diag,
                    "sameStaticExports": llvm_static == cranelift_static,
                    "sameSharedExports": llvm_shared == cranelift_shared,
                },
                "issues": issues,
            })
            .to_string()),
        };
    }

    let llvm = compile_file_with_backend(path, BuildProfile::Dev, Some("llvm"))?;
    let cranelift = compile_file_with_backend(path, BuildProfile::Dev, Some("cranelift"))?;
    let llvm_diag = diagnostic_signature(&llvm.diagnostic_details)?;
    let cranelift_diag = diagnostic_signature(&cranelift.diagnostic_details)?;
    let mut issues = Vec::new();
    if llvm.status != cranelift.status {
        issues.push("llvm/cranelift executable build status mismatch".to_string());
    }
    if llvm_diag != cranelift_diag {
        issues.push("llvm/cranelift executable diagnostic mismatch".to_string());
    }
    let runtime_available = llvm.status == "ok" && cranelift.status == "ok";
    let (llvm_runtime, cranelift_runtime) = if runtime_available {
        let llvm_runtime = executable_runtime_result(&llvm)?;
        let cranelift_runtime = executable_runtime_result(&cranelift)?;
        if llvm_runtime.exit_code != cranelift_runtime.exit_code {
            issues.push("llvm/cranelift exit code mismatch".to_string());
        }
        if llvm_runtime.stdout != cranelift_runtime.stdout {
            issues.push("llvm/cranelift stdout mismatch".to_string());
        }
        if llvm_runtime.stderr != cranelift_runtime.stderr {
            issues.push("llvm/cranelift stderr mismatch".to_string());
        }
        (Some(llvm_runtime), Some(cranelift_runtime))
    } else {
        (None, None)
    };
    let signature = semantic_signature(&serde_json::json!({
        "kind": "backend-executable-parity",
        "verifier": verifier_signature,
        "llvm": {
            "status": llvm.status,
            "diagnostics": llvm_diag,
            "exit": llvm_runtime.as_ref().map(|value| value.exit_code),
            "stdout": llvm_runtime.as_ref().map(|value| value.stdout.clone()),
            "stderr": llvm_runtime.as_ref().map(|value| value.stderr.clone()),
        },
        "cranelift": {
            "status": cranelift.status,
            "diagnostics": cranelift_diag,
            "exit": cranelift_runtime.as_ref().map(|value| value.exit_code),
            "stdout": cranelift_runtime.as_ref().map(|value| value.stdout.clone()),
            "stderr": cranelift_runtime.as_ref().map(|value| value.stderr.clone()),
        },
    }))?;
    if !issues.is_empty() {
        bail!(
            "parity failed for {}: {}",
            path.display(),
            issues.join("; ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "parity".to_string()),
            ("kind", "executable".to_string()),
            ("path", path.display().to_string()),
            ("signature", signature),
            (
                "exit_code",
                llvm_runtime
                    .as_ref()
                    .map(|value| value.exit_code.to_string())
                    .unwrap_or_else(|| "<unavailable>".to_string()),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "mode": "parity",
            "kind": "executable",
            "path": path.display().to_string(),
            "seed": seed,
            "signature": signature,
            "verifier": {
                "diagnostics": verifier.diagnostics,
                "signature": verifier_signature,
            },
            "backendCapabilities": backend_capabilities,
            "backendResults": {
                "llvm": {
                    "status": llvm.status,
                    "diagnostics": llvm.diagnostics,
                    "diagnosticSignature": llvm_diag,
                    "exitCode": llvm_runtime.as_ref().map(|value| value.exit_code),
                    "stdout": llvm_runtime.as_ref().map(|value| value.stdout.clone()),
                    "stderr": llvm_runtime.as_ref().map(|value| value.stderr.clone()),
                },
                "cranelift": {
                    "status": cranelift.status,
                    "diagnostics": cranelift.diagnostics,
                    "diagnosticSignature": cranelift_diag,
                    "exitCode": cranelift_runtime.as_ref().map(|value| value.exit_code),
                    "stdout": cranelift_runtime.as_ref().map(|value| value.stdout.clone()),
                    "stderr": cranelift_runtime.as_ref().map(|value| value.stderr.clone()),
                }
            },
            "checks": {
                "sameVerifierResult": true,
                "sameBuildStatus": llvm.status == cranelift.status,
                "sameDiagnosticResult": llvm_diag == cranelift_diag,
                "runtimeAvailable": runtime_available,
                "sameExitCode": llvm_runtime.as_ref().map(|value| value.exit_code)
                    == cranelift_runtime.as_ref().map(|value| value.exit_code),
                "sameStdout": llvm_runtime.as_ref().map(|value| &value.stdout)
                    == cranelift_runtime.as_ref().map(|value| &value.stdout),
                "sameStderr": llvm_runtime.as_ref().map(|value| &value.stderr)
                    == cranelift_runtime.as_ref().map(|value| &value.stderr),
                "sameRuntimeBehavior": llvm_runtime == cranelift_runtime,
            },
            "issues": issues,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableRuntimeResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

fn executable_runtime_result(artifact: &BuildArtifact) -> Result<ExecutableRuntimeResult> {
    let output = artifact
        .output
        .as_deref()
        .ok_or_else(|| anyhow!("native executable parity output missing binary artifact"))?;
    let result = ProcessCommand::new(output)
        .output()
        .with_context(|| format!("native executable parity run failed: {}", output.display()))?;
    Ok(ExecutableRuntimeResult {
        exit_code: result
            .status
            .code()
            .ok_or_else(|| anyhow!("native executable parity run terminated without exit code"))?,
        stdout: String::from_utf8(result.stdout).context("parity stdout should be utf-8")?,
        stderr: String::from_utf8(result.stderr).context("parity stderr should be utf-8")?,
    })
}

fn diagnostic_signature(items: &[diagnostics::Diagnostic]) -> Result<String> {
    let payload = serde_json::Value::Array(
        items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "severity": format!("{:?}", item.severity),
                    "message": item.message,
                    "help": item.help,
                    "code": item.code,
                    "catalogKey": item.catalog_key,
                    "path": item.path,
                })
            })
            .collect::<Vec<_>>(),
    );
    semantic_signature(&payload)
}

fn library_exports(path: &Path) -> Result<Vec<String>> {
    let output = ProcessCommand::new("nm")
        .arg(path)
        .output()
        .with_context(|| format!("failed invoking nm for {}", path.display()))?;
    if !output.status.success() {
        bail!("nm failed for {}", path.display());
    }
    let mut exports = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && (line.contains(" add")
                    || line.ends_with(" add")
                    || line.contains(" mul")
                    || line.ends_with(" mul")
                    || line.contains(" T ")
                    || line.contains(" D ")
                    || line.contains(" S "))
        })
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    exports.sort();
    exports.dedup();
    Ok(exports)
}

fn backend_capability_report() -> serde_json::Value {
    serde_json::json!({
        "llvm": {
            "status": "parity_supported",
            "unsupported": []
        },
        "cranelift": {
            "status": "parity_supported_with_explicit_exceptions",
            "unsupported": [
                {
                    "feature": "async_c_export_surface",
                    "catalogKey": "native.async_c_export_unsupported"
                },
                {
                    "feature": "async_unsafe_native_function",
                    "catalogKey": "native.async_unsafe_function_unsupported"
                }
            ]
        },
        "gpuAdapters": gpu_backend_report_json()
    })
}

fn equivalence_command(path: &Path, seed: u64, format: Format) -> Result<String> {
    ensure_exists(path)?;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let temp_trace =
        std::env::temp_dir().join(format!("fozzylang-equivalence-{suffix}.trace.json"));
    let native_plan = run_non_scenario_test_plan(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: true,
            safe_profile: false,
            scheduler: Some("fifo".to_string()),
            seed: Some(seed),
            record: Some(&temp_trace),
            rich_artifacts: true,
            filter: None,
        },
    )?;
    let artifacts = native_plan
        .artifacts
        .as_ref()
        .ok_or_else(|| anyhow!("equivalence requires deterministic record artifacts"))?;
    let scenario = artifacts
        .primary_scenario_path
        .clone()
        .ok_or_else(|| anyhow!("equivalence could not resolve generated primary scenario"))?;
    let (scenario_step_kinds, scenario_trace_events) = parse_scenario_step_kinds(&scenario)?;
    let scenario_summary = fozzy_test_summary(&scenario, false, true)?;
    let host_summary = fozzy_test_summary(&scenario, true, false)?;

    let mut native = plan_semantics_outcome("native", &native_plan);
    native.event_kinds = normalize_equivalence_event_kinds(&native.event_kinds);
    native.invariants.insert(
        "asyncCheckpoints".to_string(),
        native_plan.async_checkpoint_count.to_string(),
    );
    native.invariants.insert(
        "rpcFrames".to_string(),
        native_plan.rpc_frame_count.to_string(),
    );
    native.invariants.insert(
        "threadSchedules".to_string(),
        native_plan.execution_order.len().to_string(),
    );
    let scenario_outcome = SemanticsOutcome {
        mode: "scenario".to_string(),
        exit_class: scenario_summary.exit_class,
        event_kinds: normalize_equivalence_event_kinds(&scenario_step_kinds),
        invariants: BTreeMap::from([
            (
                "deterministicTests".to_string(),
                scenario_trace_events.to_string(),
            ),
            ("failed".to_string(), scenario_summary.failed.to_string()),
        ]),
    };
    let host_outcome = SemanticsOutcome {
        mode: "host".to_string(),
        exit_class: host_summary.exit_class,
        event_kinds: normalize_equivalence_event_kinds(&scenario_step_kinds),
        invariants: BTreeMap::from([
            (
                "deterministicTests".to_string(),
                scenario_trace_events.to_string(),
            ),
            ("failed".to_string(), host_summary.failed.to_string()),
        ]),
    };
    let outcomes = vec![
        native.clone(),
        scenario_outcome.clone(),
        host_outcome.clone(),
    ];
    let signature = semantic_signature(&serde_json::json!({
        "kind": "native-scenario-host-equivalence",
        "outcomes": outcomes,
    }))?;

    let mut issues = Vec::new();
    if native.exit_class != scenario_outcome.exit_class {
        issues.push("native/scenario exit class mismatch".to_string());
    }
    if scenario_outcome.exit_class != host_outcome.exit_class {
        issues.push("scenario/host exit class mismatch".to_string());
    }
    if native.invariants.get("deterministicTests")
        != scenario_outcome.invariants.get("deterministicTests")
    {
        issues.push("native/scenario deterministic test count mismatch".to_string());
    }
    if native_plan.async_checkpoint_count > 0
        && !native
            .event_kinds
            .iter()
            .any(|kind| kind == "async.checkpoint")
    {
        issues.push("native equivalence model missing async.checkpoint evidence".to_string());
    }
    if native_plan.rpc_frame_count > 0 && !native.event_kinds.iter().any(|kind| kind == "rpc.frame")
    {
        issues.push("native equivalence model missing rpc.frame evidence".to_string());
    }
    let scenario_events_empty = scenario_trace_events == 0
        && scenario_outcome.event_kinds.is_empty()
        && host_outcome.event_kinds.is_empty();
    if !scenario_events_empty
        && !event_kinds_equivalent(&native.event_kinds, &scenario_outcome.event_kinds)
    {
        issues.push("native/scenario normalized event kinds mismatch".to_string());
    }
    if !event_kinds_equivalent(&scenario_outcome.event_kinds, &host_outcome.event_kinds) {
        issues.push("scenario/host normalized event kinds mismatch".to_string());
    }

    if !issues.is_empty() {
        bail!(
            "equivalence failed for {}: {}",
            path.display(),
            issues.join("; ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "equivalence".to_string()),
            ("path", path.display().to_string()),
            ("signature", signature),
            ("scenario", scenario.display().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "path": path.display().to_string(),
            "seed": seed,
            "equivalenceNormalization": {
                "yieldPoints": ["await", "yield", "checkpoint", "spawn", "recv", "timeout", "deadline", "cancel", "pulse"],
                "rule": "trace_event/assert_eq_int are normalized to test-level events; scheduler/rpc categories are preserved when present in engine evidence",
            },
            "signature": signature,
            "scenario": scenario.display().to_string(),
            "outcomes": outcomes,
            "issues": issues,
        })
        .to_string()),
    }
}

fn plan_semantics_outcome(mode: &str, plan: &NonScenarioTestPlan) -> SemanticsOutcome {
    let mut event_kinds = Vec::new();
    if plan.selected_tests > 0 {
        event_kinds.push("test.event".to_string());
        event_kinds.push("test.assert".to_string());
    }
    if plan.async_checkpoint_count > 0 {
        event_kinds.push("async.checkpoint".to_string());
    }
    if plan.rpc_frame_count > 0 {
        event_kinds.push("rpc.frame".to_string());
    }
    if !plan.execution_order.is_empty() {
        event_kinds.push("thread.schedule".to_string());
    }
    event_kinds.sort();
    event_kinds.dedup();

    SemanticsOutcome {
        mode: mode.to_string(),
        exit_class: "pass".to_string(),
        event_kinds,
        invariants: BTreeMap::from([
            (
                "discoveredTests".to_string(),
                plan.discovered_tests.to_string(),
            ),
            ("selectedTests".to_string(), plan.selected_tests.to_string()),
            (
                "deterministicTests".to_string(),
                plan.deterministic_test_names.len().to_string(),
            ),
        ]),
    }
}

fn parse_scenario_step_kinds(path: &Path) -> Result<(Vec<String>, usize)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading scenario file: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("failed parsing scenario file: {}", path.display()))?;
    let steps = value
        .get("steps")
        .and_then(|steps| steps.as_array())
        .cloned()
        .unwrap_or_default();
    let mut kinds = Vec::new();
    let mut trace_event_count = 0usize;
    for step in steps {
        let Some(raw) = step.get("type").and_then(|value| value.as_str()) else {
            continue;
        };
        let normalized = match raw {
            "trace_event" => "test.event",
            "assert_eq_int" => "test.assert",
            _ => raw,
        };
        if normalized == "test.event" {
            trace_event_count += 1;
        }
        kinds.push(normalized.to_string());
    }
    kinds.sort();
    kinds.dedup();
    Ok((kinds, trace_event_count))
}

fn normalize_equivalence_event_kinds(kinds: &[String]) -> Vec<String> {
    let mut out = kinds
        .iter()
        .map(|kind| match kind.as_str() {
            "async.schedule" => "async.checkpoint".to_string(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn event_kinds_equivalent(left: &[String], right: &[String]) -> bool {
    fn canonical(kind: &str) -> String {
        match kind {
            "thread.schedule" | "async.checkpoint" | "rpc.frame" | "test.event" => {
                "test.event".to_string()
            }
            other => other.to_string(),
        }
    }
    let left = left
        .iter()
        .map(|kind| canonical(kind))
        .collect::<BTreeSet<_>>();
    let right = right
        .iter()
        .map(|kind| canonical(kind))
        .collect::<BTreeSet<_>>();
    left == right
}

fn fozzy_test_summary(
    scenario: &Path,
    host_backends: bool,
    deterministic: bool,
) -> Result<FozzyTestSummary> {
    let config = scenario_config_with_backends(host_backends)?;
    let globs = vec![scenario.display().to_string()];
    let run = fzscenario::run_tests(
        &config,
        &globs,
        &fzscenario::RunOptions {
            det: deterministic,
            seed: None,
            timeout: None,
            reporter: fzscenario::Reporter::Json,
            record_trace_to: None,
            filter: None,
            jobs: None,
            fail_fast: false,
            record_collision: fzscenario::RecordCollisionPolicy::Append,
            profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
            proc_backend: config.proc_backend,
            fs_backend: config.fs_backend,
            http_backend: config.http_backend,
            memory: scenario_memory_options(&config),
        },
    )
    .map_err(scenario_error)?;
    let exit_class = format!("{:?}", run.summary.status).to_ascii_lowercase();
    let passed = run
        .summary
        .tests
        .as_ref()
        .map(|tests| tests.passed)
        .unwrap_or(0);
    let failed = run
        .summary
        .tests
        .as_ref()
        .map(|tests| tests.failed)
        .unwrap_or(0);
    Ok(FozzyTestSummary {
        exit_class,
        passed,
        failed,
    })
}

fn semantic_signature(value: &serde_json::Value) -> Result<String> {
    let payload = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

#[derive(Debug, Clone, Serialize)]
struct UnsafeEntry {
    site_id: String,
    kind: String,
    project: String,
    file: String,
    function: String,
    line: usize,
    snippet: String,
    reason: Option<String>,
    invariant: Option<String>,
    owner: Option<String>,
    owner_id: Option<String>,
    scope: Option<String>,
    risk_class: Option<String>,
    proof_ref: Option<String>,
}

fn audit_unsafe_command(path: &Path, workspace: bool, format: Format) -> Result<String> {
    let mut project_roots = if workspace {
        discover_project_roots(path)?
    } else {
        vec![path.to_path_buf()]
    };
    project_roots.sort();
    project_roots.dedup();
    if project_roots.is_empty() {
        bail!(
            "no Fozzy projects discovered under {}; expected at least one fozzy.toml root",
            path.display()
        );
    }
    let mut entries = Vec::new();
    for project_root in &project_roots {
        let module_set = load_resolved_module_set(project_root)?;
        for module in &module_set.modules {
            entries.extend(collect_semantic_unsafe_entries(module, project_root));
        }
    }
    let missing_contract_count = entries
        .iter()
        .filter(|entry| entry.kind != "unsafe_violation_callsite")
        .filter(|entry| {
            entry.reason.as_deref().is_none_or(str::is_empty)
                || entry.invariant.as_deref().is_none_or(str::is_empty)
                || entry.owner.as_deref().is_none_or(str::is_empty)
                || entry.owner_id.as_deref().is_none_or(str::is_empty)
                || entry.scope.as_deref().is_none_or(str::is_empty)
                || entry.risk_class.as_deref().is_none_or(str::is_empty)
                || entry.proof_ref.as_deref().is_none_or(str::is_empty)
        })
        .count();
    let invalid_owner_id_count = entries
        .iter()
        .filter(|entry| {
            entry.owner_id.as_deref().is_some_and(|value| {
                !value.trim().is_empty()
                    && !unsafe_owner_id_valid(
                        entry.function.as_str(),
                        entry.owner.as_deref().unwrap_or_default(),
                        value,
                    )
            })
        })
        .count();
    let invalid_proof_ref_count = entries
        .iter()
        .filter(|entry| {
            entry
                .proof_ref
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty() && !proof_ref_valid(value))
        })
        .count();
    let unsafe_context_violations = entries
        .iter()
        .filter(|entry| entry.kind == "unsafe_violation_callsite")
        .count();

    let out_root = if workspace {
        std::env::current_dir().context("failed to resolve current working directory")?
    } else {
        resolve_source(path)?.project_root
    };
    let out_dir = out_root.join(".fz");
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed creating unsafe audit dir: {}", out_dir.display()))?;
    let unsafe_map = if workspace {
        out_dir.join("unsafe-map.workspace.json")
    } else {
        out_dir.join("unsafe-map.json")
    };
    let by_risk_class = entries
        .iter()
        .fold(BTreeMap::<String, usize>::new(), |mut acc, item| {
            *acc.entry(
                item.risk_class
                    .clone()
                    .unwrap_or_else(|| "missing".to_string()),
            )
            .or_default() += 1;
            acc
        });
    let by_owner = entries
        .iter()
        .fold(BTreeMap::<String, usize>::new(), |mut acc, item| {
            *acc.entry(item.owner.clone().unwrap_or_else(|| "missing".to_string()))
                .or_default() += 1;
            acc
        });
    let by_scope = entries
        .iter()
        .fold(BTreeMap::<String, usize>::new(), |mut acc, item| {
            *acc.entry(item.scope.clone().unwrap_or_else(|| "missing".to_string()))
                .or_default() += 1;
            acc
        });
    let strict_unsafe_audit = strict_unsafe_audit_for_projects(&project_roots);
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.unsafe_map.v3",
        "workspaceMode": workspace,
        "projects": project_roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "entries": entries,
        "missingContractCount": missing_contract_count,
        "invalidOwnerIdCount": invalid_owner_id_count,
        "invalidProofRefCount": invalid_proof_ref_count,
        "unsafeContextViolationCount": unsafe_context_violations,
        "strictUnsafeAudit": strict_unsafe_audit,
        "riskClassCounts": by_risk_class,
        "byOwner": by_owner,
        "byScope": by_scope,
    });
    std::fs::write(&unsafe_map, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing unsafe map: {}", unsafe_map.display()))?;
    let unsafe_docs_json = if workspace {
        out_dir.join("unsafe-docs.workspace.json")
    } else {
        out_dir.join("unsafe-docs.json")
    };
    let unsafe_docs_md = if workspace {
        out_dir.join("unsafe-docs.workspace.md")
    } else {
        out_dir.join("unsafe-docs.md")
    };
    let unsafe_docs_html = if workspace {
        out_dir.join("unsafe-docs.workspace.html")
    } else {
        out_dir.join("unsafe-docs.html")
    };
    std::fs::write(&unsafe_docs_json, serde_json::to_vec_pretty(&payload)?).with_context(|| {
        format!(
            "failed writing unsafe docs json artifact: {}",
            unsafe_docs_json.display()
        )
    })?;
    let mut markdown = String::from("# Unsafe Inventory\n\n");
    let entry_count = payload["entries"].as_array().map(|v| v.len()).unwrap_or(0);
    let compiler_satisfied = missing_contract_count == 0
        && invalid_proof_ref_count == 0
        && unsafe_context_violations == 0;
    if compiler_satisfied {
        markdown.push_str(
            "Compiler status: unsafe-policy checks passed. The current unsafe inventory is accepted by the compiler, but unsafe remains review-worthy and is not itself a proof of semantic safety or correctness.\n\n",
        );
    } else {
        markdown.push_str(
            "Compiler status: unsafe-policy checks require attention. The compiler found contract, proof, or unsafe-context issues in the current unsafe inventory.\n\n",
        );
    }
    markdown.push_str(&format!(
        "- Entries: {}\n- Contract gaps: {}\n- Invalid owner IDs: {}\n- Invalid proof refs: {}\n- Unsafe context violations: {}\n\n",
        entry_count,
        missing_contract_count,
        invalid_owner_id_count,
        invalid_proof_ref_count,
        unsafe_context_violations
    ));
    markdown.push_str(
        "| Site ID | Kind | Function | Snippet | Reason | Owner | Owner ID | Invariant | Scope | Risk | Proof |\n|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    if let Some(entries) = payload["entries"].as_array() {
        for entry in entries {
            let site_id = entry["site_id"].as_str().unwrap_or("missing");
            let kind = entry["kind"].as_str().unwrap_or("unknown");
            let function = entry["function"].as_str().unwrap_or("?");
            let line = entry["line"].as_u64().unwrap_or(0);
            let snippet = entry["snippet"].as_str().unwrap_or("?");
            let reason = entry["reason"].as_str().unwrap_or("contract missing");
            let owner = entry["owner"].as_str().unwrap_or("contract missing");
            let owner_id = entry["owner_id"].as_str().unwrap_or("contract missing");
            let invariant = entry["invariant"].as_str().unwrap_or("contract missing");
            let scope = entry["scope"].as_str().unwrap_or("contract missing");
            let risk = entry["risk_class"].as_str().unwrap_or("contract missing");
            let proof = entry["proof_ref"].as_str().unwrap_or("contract missing");
            markdown.push_str(&format!(
                "| `{site_id}` | {kind} | {function}:{line} | `{snippet}` | {reason} | {owner} | `{owner_id}` | `{invariant}` | `{scope}` | {risk} | `{proof}` |\n"
            ));
        }
    }
    std::fs::write(&unsafe_docs_md, markdown.as_bytes()).with_context(|| {
        format!(
            "failed writing unsafe docs markdown artifact: {}",
            unsafe_docs_md.display()
        )
    })?;
    let html = format!(
        "<html><body><pre>{}</pre></body></html>",
        markdown.replace('&', "&amp;").replace('<', "&lt;")
    );
    std::fs::write(&unsafe_docs_html, html.as_bytes()).with_context(|| {
        format!(
            "failed writing unsafe docs html artifact: {}",
            unsafe_docs_html.display()
        )
    })?;
    if strict_unsafe_audit
        && (missing_contract_count > 0
            || invalid_owner_id_count > 0
            || invalid_proof_ref_count > 0
            || unsafe_context_violations > 0)
    {
        bail!(
            "strict unsafe audit failed (missing={}, invalid_owner_id={}, invalid_proof_ref={}, context_violations={}); map={}",
            missing_contract_count,
            invalid_owner_id_count,
            invalid_proof_ref_count,
            unsafe_context_violations,
            unsafe_map.display()
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "unsafe-audit".to_string()),
            ("workspace", workspace.to_string()),
            (
                "entries",
                payload["entries"]
                    .as_array()
                    .map(|items| items.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "projects",
                payload["projects"]
                    .as_array()
                    .map(|items| items.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "unsafe_context_violations",
                unsafe_context_violations.to_string(),
            ),
            ("map", unsafe_map.display().to_string()),
            ("docs_json", unsafe_docs_json.display().to_string()),
            ("docs_md", unsafe_docs_md.display().to_string()),
            ("docs_html", unsafe_docs_html.display().to_string()),
            ("invalid_owner_id", invalid_owner_id_count.to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "workspace": workspace,
            "entries": payload["entries"],
            "projects": payload["projects"],
            "map": unsafe_map.display().to_string(),
            "docsJson": unsafe_docs_json.display().to_string(),
            "docsMarkdown": unsafe_docs_md.display().to_string(),
            "docsHtml": unsafe_docs_html.display().to_string(),
            "missingContractCount": missing_contract_count,
            "invalidOwnerIdCount": invalid_owner_id_count,
            "invalidProofRefCount": invalid_proof_ref_count,
            "unsafeContextViolationCount": unsafe_context_violations,
            "strictUnsafeAudit": strict_unsafe_audit,
            "riskClassCounts": payload["riskClassCounts"],
            "byOwner": payload["byOwner"],
            "byScope": payload["byScope"],
        })
        .to_string()),
    }
}

fn audit_memory_command(path: &Path, format: Format) -> Result<String> {
    let root = compile_strict_safety_artifacts(path)?;
    let json_path = root.join(".fz/memory-report.json");
    let md_path = root.join(".fz/memory-report.md");
    let payload: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&json_path)
            .with_context(|| format!("failed reading {}", json_path.display()))?,
    )
    .with_context(|| format!("failed parsing {}", json_path.display()))?;
    let owner_count = payload["owners"]
        .as_array()
        .map(|items| items.len())
        .unwrap_or(0);
    let violation_count = payload["violations"]
        .as_array()
        .map(|items| items.len())
        .unwrap_or(0);
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "memory-audit".to_string()),
            ("profile", "strict".to_string()),
            ("owners", owner_count.to_string()),
            ("violations", violation_count.to_string()),
            ("json", json_path.display().to_string()),
            ("markdown", md_path.display().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "mode": "memory-audit",
            "profile": "strict",
            "json": json_path.display().to_string(),
            "markdown": md_path.display().to_string(),
            "owners": owner_count,
            "violations": violation_count,
            "report": payload,
        })
        .to_string()),
    }
}

fn audit_ffi_command(path: &Path, format: Format) -> Result<String> {
    let root = compile_strict_safety_artifacts(path)?;
    let json_path = root.join(".fz/ffi-report.json");
    let md_path = root.join(".fz/ffi-report.md");
    let payload: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&json_path)
            .with_context(|| format!("failed reading {}", json_path.display()))?,
    )
    .with_context(|| format!("failed parsing {}", json_path.display()))?;
    let import_count = payload["imports"]
        .as_array()
        .map(|items| items.len())
        .unwrap_or(0);
    let export_count = payload["exports"]
        .as_array()
        .map(|items| items.len())
        .unwrap_or(0);
    let pointer_contract_violation_count = payload["pointerContractViolationCount"]
        .as_u64()
        .unwrap_or(0);
    let callback_context_anchor_violation_count = payload["callbackContextAnchorViolationCount"]
        .as_u64()
        .unwrap_or(0);
    let ffi_stable_type_violation_count =
        payload["ffiStableTypeViolationCount"].as_u64().unwrap_or(0);
    let async_import_violation_count = payload["asyncImportViolationCount"].as_u64().unwrap_or(0);
    let missing_panic_boundary_count = payload["missingPanicBoundaryCount"].as_u64().unwrap_or(0);
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "ffi-audit".to_string()),
            ("profile", "strict".to_string()),
            ("imports", import_count.to_string()),
            ("exports", export_count.to_string()),
            (
                "pointer_contract_violations",
                pointer_contract_violation_count.to_string(),
            ),
            (
                "callback_anchor_violations",
                callback_context_anchor_violation_count.to_string(),
            ),
            (
                "ffi_stable_type_violations",
                ffi_stable_type_violation_count.to_string(),
            ),
            (
                "async_import_violations",
                async_import_violation_count.to_string(),
            ),
            (
                "missing_panic_boundary_declarations",
                missing_panic_boundary_count.to_string(),
            ),
            ("json", json_path.display().to_string()),
            ("markdown", md_path.display().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "mode": "ffi-audit",
            "profile": "strict",
            "json": json_path.display().to_string(),
            "markdown": md_path.display().to_string(),
            "imports": import_count,
            "exports": export_count,
            "pointerContractViolationCount": pointer_contract_violation_count,
            "callbackContextAnchorViolationCount": callback_context_anchor_violation_count,
            "ffiStableTypeViolationCount": ffi_stable_type_violation_count,
            "asyncImportViolationCount": async_import_violation_count,
            "missingPanicBoundaryCount": missing_panic_boundary_count,
            "report": payload,
        })
        .to_string()),
    }
}

fn compile_strict_safety_artifacts(path: &Path) -> Result<PathBuf> {
    match compile_file_with_backend_with_root_guidance(path, BuildProfile::Strict, None) {
        Ok(artifact) if artifact.status != "error" => {}
        Ok(_) | Err(_) if project_has_c_exports(path).unwrap_or(false) => {
            let artifact =
                compile_library_with_backend_with_root_guidance(path, BuildProfile::Strict, None)?;
            if artifact.status == "error" {
                bail!(
                    "strict safety artifact generation failed for `{}`",
                    path.display()
                );
            }
        }
        Ok(_) => {
            bail!(
                "strict safety artifact generation failed for `{}`",
                path.display()
            );
        }
        Err(error) => return Err(error),
    }
    Ok(resolve_source(path)?.project_root)
}

fn proof_ref_machine_linkable(value: &str) -> bool {
    let value = value.trim();
    let schemes = [
        "trace://", "test://", "rfc://", "gate://", "run://", "ci://",
    ];
    schemes.iter().any(|scheme| value.starts_with(scheme))
}

fn unsafe_owner_id_valid(function_name: &str, owner: &str, owner_id: &str) -> bool {
    let function_name = function_name.trim();
    let owner = owner.trim();
    let owner_id = owner_id.trim();
    if function_name.is_empty() || owner.is_empty() || owner_id.is_empty() {
        return false;
    }
    owner_id == format!("owner::{function_name}::{owner}")
}

fn proof_ref_valid(value: &str) -> bool {
    let value = value.trim();
    if !proof_ref_machine_linkable(value) {
        return false;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if scheme == "gate" || scheme == "rfc" {
        return true;
    }
    if scheme != "trace" && scheme != "test" && scheme != "run" && scheme != "ci" {
        return false;
    }
    let path_part = rest.split('#').next().unwrap_or_default().trim();
    if path_part.is_empty() {
        return false;
    }
    std::path::Path::new(path_part).exists()
}

fn strict_unsafe_audit_for_projects(project_roots: &[PathBuf]) -> bool {
    project_roots.iter().any(|root| {
        let manifest_path = root.join("fozzy.toml");
        let Ok(text) = std::fs::read_to_string(&manifest_path) else {
            return true;
        };
        let Ok(manifest) = manifest::load(&text) else {
            return true;
        };
        manifest.unsafe_policy.enforce_verify.unwrap_or(true)
            || manifest.unsafe_policy.enforce_release.unwrap_or(true)
    })
}

fn generated_unsafe_owner(function: &ast::Function) -> String {
    function
        .params
        .first()
        .map(|param| param.name.clone())
        .unwrap_or_else(|| "scope_root".to_string())
}

fn generated_unsafe_contract(
    kind: &str,
    function_name: &str,
    owner: &str,
    callee: Option<&str>,
) -> (String, String, String, String, String) {
    let reason = match kind {
        "unsafe_import" => format!("compiler-generated: unsafe FFI import `{function_name}`"),
        "unsafe_fn" => format!("compiler-generated: unsafe function `{function_name}`"),
        "unsafe_block" => format!("compiler-generated: unsafe island in `{function_name}`"),
        "unsafe_violation_callsite" => {
            format!("compiler-generated: unsafe callsite violation in `{function_name}`")
        }
        _ => format!("compiler-generated: unsafe site in `{function_name}`"),
    };
    let invariant = format!("owner_live({owner})");
    let scope = format!("{}::{}", function_name, kind);
    let risk_class = if kind == "unsafe_import" || callee.is_some_and(|v| v.contains("c_")) {
        "ffi".to_string()
    } else {
        "memory".to_string()
    };
    (reason, invariant, owner.to_string(), scope, risk_class)
}

fn generated_unsafe_owner_id(function_name: &str, owner: &str) -> String {
    format!("owner::{function_name}::{owner}")
}

fn unsafe_site_id(
    kind: &str,
    project_root: &Path,
    module_path: &Path,
    function_name: &str,
    snippet: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(project_root.display().to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(module_path.display().to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(kind.as_bytes());
    hasher.update(b"|");
    hasher.update(function_name.as_bytes());
    hasher.update(b"|");
    hasher.update(snippet.as_bytes());
    let digest = hasher.finalize();
    let mut id = String::from("usite_");
    for byte in digest.iter().take(12) {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}

fn bind_proof_ref(project_root: &Path, site_id: &str, fallback: &str) -> String {
    let artifact_dir = project_root.join("artifacts");
    if let Ok(entries) = std::fs::read_dir(&artifact_dir) {
        let mut candidates = entries
            .flatten()
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        candidates.sort();
        for path in candidates {
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.ends_with(".trace.fozzy") || name.ends_with(".fozzy") {
                return format!("trace://{}#site={site_id}", path.display());
            }
            if name.ends_with(".trace.json") {
                return format!("run://{}#site={site_id}", path.display());
            }
        }
    }
    format!("{fallback}#site={site_id}")
}

fn collect_semantic_unsafe_entries(
    module: &ResolvedModuleSource,
    project_root: &Path,
) -> Vec<UnsafeEntry> {
    let mut entries = Vec::new();
    let lines = module.source.lines().collect::<Vec<_>>();
    let unsafe_callees = module
        .ast
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) if function.is_unsafe => Some(function.name.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for item in &module.ast.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        let default_owner = generated_unsafe_owner(function);
        if function.is_unsafe {
            let snippet = format!("unsafe fn {}", function.name);
            let site_id = unsafe_site_id(
                "unsafe_fn",
                project_root,
                &module.path,
                &function.name,
                &snippet,
            );
            let (reason, invariant, owner, scope, risk_class) =
                generated_unsafe_contract("unsafe_fn", &function.name, &default_owner, None);
            let proof_ref = bind_proof_ref(
                project_root,
                &site_id,
                &format!("gate://compiler-generated/{}/unsafe_fn", function.name),
            );
            let owner_id = generated_unsafe_owner_id(&function.name, &owner);
            entries.push(UnsafeEntry {
                site_id,
                kind: "unsafe_fn".to_string(),
                project: project_root.display().to_string(),
                file: module.path.display().to_string(),
                function: function.name.clone(),
                line: find_function_decl_line(&lines, function).unwrap_or(0),
                snippet,
                reason: Some(reason),
                invariant: Some(invariant),
                owner: Some(owner),
                owner_id: Some(owner_id),
                scope: Some(scope),
                risk_class: Some(risk_class),
                proof_ref: Some(proof_ref),
            });
        }
        if function.is_extern && function.abi.as_deref() == Some("c") && function.is_unsafe {
            let snippet = format!("ext unsafe c fn {}", function.name);
            let site_id = unsafe_site_id(
                "unsafe_import",
                project_root,
                &module.path,
                &function.name,
                &snippet,
            );
            let (reason, invariant, owner, scope, risk_class) =
                generated_unsafe_contract("unsafe_import", &function.name, &default_owner, None);
            let proof_ref = bind_proof_ref(
                project_root,
                &site_id,
                &format!("gate://compiler-generated/{}/unsafe_import", function.name),
            );
            let owner_id = generated_unsafe_owner_id(&function.name, &owner);
            entries.push(UnsafeEntry {
                site_id,
                kind: "unsafe_import".to_string(),
                project: project_root.display().to_string(),
                file: module.path.display().to_string(),
                function: function.name.clone(),
                line: find_function_decl_line(&lines, function).unwrap_or(0),
                snippet,
                reason: Some(reason),
                invariant: Some(invariant),
                owner: Some(owner),
                owner_id: Some(owner_id),
                scope: Some(scope),
                risk_class: Some(risk_class),
                proof_ref: Some(proof_ref),
            });
        }
        for stmt in &function.body {
            collect_semantic_unsafe_entries_from_stmt(
                stmt,
                &module.path,
                project_root,
                &lines,
                &function.name,
                function.is_unsafe,
                &default_owner,
                &unsafe_callees,
                &mut entries,
            );
        }
    }
    entries
}

fn find_function_decl_line(lines: &[&str], function: &ast::Function) -> Option<usize> {
    let name = function.name.as_str();
    lines
        .iter()
        .position(|line| function_decl_line_matches(line.trim_start(), function, name))
        .map(|idx| idx + 1)
}

fn function_decl_line_matches(line: &str, function: &ast::Function, name: &str) -> bool {
    let line = strip_leading_attributes_inline(line);
    if function.is_extern && function.abi.as_deref() == Some("rpc") {
        return line.starts_with(&format!("rpc {name}("));
    }
    if function.is_extern && function.abi.as_deref() == Some("c") && function.is_unsafe {
        return line.contains(&format!("ext unsafe c fn {name}("));
    }
    if function.is_pubext && function.is_async && function.abi.as_deref() == Some("c") {
        return line.contains(&format!("pubext async c fn {name}("));
    }
    if function.is_pubext && function.abi.as_deref() == Some("c") {
        return line.contains(&format!("pubext c fn {name}("));
    }
    if function.is_async && function.is_unsafe {
        return line.contains(&format!("async unsafe fn {name}("))
            || line.contains(&format!("unsafe async fn {name}("))
            || line.contains(&format!("unsafe fn {name}("));
    }
    if function.is_async {
        return line.contains(&format!("async fn {name}("));
    }
    if function.is_unsafe {
        return line.contains(&format!("unsafe fn {name}("));
    }
    line.contains(&format!("fn {name}("))
}

fn strip_leading_attributes_inline(line: &str) -> &str {
    let mut cursor = line.trim_start();
    while let Some(rest) = cursor.strip_prefix("#[") {
        let Some(close) = rest.find(']') else {
            break;
        };
        cursor = rest[(close + 1)..].trim_start();
    }
    cursor
}

fn find_function_body_end_line(lines: &[&str], start_line: usize) -> usize {
    if start_line == 0 || start_line > lines.len() {
        return start_line;
    }
    let mut seen_body = false;
    let mut brace_depth = 0usize;
    for (idx, line) in lines.iter().enumerate().skip(start_line - 1) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    brace_depth += 1;
                    seen_body = true;
                }
                '}' => {
                    brace_depth = brace_depth.saturating_sub(1);
                    if seen_body && brace_depth == 0 {
                        return idx + 1;
                    }
                }
                _ => {}
            }
        }
        if !seen_body && line.trim_end().ends_with(';') {
            return idx + 1;
        }
    }
    lines.len()
}

fn find_line_in_function(
    lines: &[&str],
    function_name: &str,
    matcher: impl Fn(&str) -> bool,
) -> Option<usize> {
    let function = ast::Function {
        name: function_name.to_string(),
        link_name: None,
        generics: Vec::new(),
        params: Vec::new(),
        return_type: ast::Type::Void,
        body: Vec::new(),
        is_unsafe: false,
        unsafe_meta: None,
        is_async: false,
        is_pub: false,
        is_pubext: false,
        is_extern: false,
        execution_space: ast::ExecutionSpace::Host,
        abi: None,
        ffi_panic: None,
    };
    let start_line = find_function_decl_line(lines, &function)?;
    let end_line = find_function_body_end_line(lines, start_line);
    lines[start_line.saturating_sub(1)..end_line]
        .iter()
        .position(|line| matcher(line.trim_start()))
        .map(|idx| start_line + idx)
}

fn collect_semantic_unsafe_entries_from_stmt(
    stmt: &ast::Stmt,
    module_path: &Path,
    project_root: &Path,
    source_lines: &[&str],
    function_name: &str,
    in_unsafe_context: bool,
    default_owner: &str,
    unsafe_callees: &BTreeSet<String>,
    entries: &mut Vec<UnsafeEntry>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_semantic_unsafe_entries_from_expr(
            value,
            module_path,
            project_root,
            source_lines,
            function_name,
            in_unsafe_context,
            default_owner,
            unsafe_callees,
            entries,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_semantic_unsafe_entries_from_expr(
                    value,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_semantic_unsafe_entries_from_expr(
                condition,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            for nested in then_body {
                collect_semantic_unsafe_entries_from_stmt(
                    nested,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
            for nested in else_body {
                collect_semantic_unsafe_entries_from_stmt(
                    nested,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_semantic_unsafe_entries_from_expr(
                condition,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            for nested in body {
                collect_semantic_unsafe_entries_from_stmt(
                    nested,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_semantic_unsafe_entries_from_stmt(
                    init,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
            if let Some(condition) = condition {
                collect_semantic_unsafe_entries_from_expr(
                    condition,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
            if let Some(step) = step {
                collect_semantic_unsafe_entries_from_stmt(
                    step,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
            for nested in body {
                collect_semantic_unsafe_entries_from_stmt(
                    nested,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_semantic_unsafe_entries_from_expr(
                iterable,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            for nested in body {
                collect_semantic_unsafe_entries_from_stmt(
                    nested,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_semantic_unsafe_entries_from_stmt(
                    nested,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_semantic_unsafe_entries_from_expr(
                scrutinee,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_semantic_unsafe_entries_from_expr(
                        guard,
                        module_path,
                        project_root,
                        source_lines,
                        function_name,
                        in_unsafe_context,
                        default_owner,
                        unsafe_callees,
                        entries,
                    );
                }
                collect_semantic_unsafe_entries_from_expr(
                    &arm.value,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
    }
}

fn collect_semantic_unsafe_entries_from_expr(
    expr: &ast::Expr,
    module_path: &Path,
    project_root: &Path,
    source_lines: &[&str],
    function_name: &str,
    in_unsafe_context: bool,
    default_owner: &str,
    unsafe_callees: &BTreeSet<String>,
    entries: &mut Vec<UnsafeEntry>,
) {
    match expr {
        ast::Expr::UnsafeBlock { body, .. } => {
            let snippet = format!("{function_name}: unsafe {{ ... }}");
            let site_id = unsafe_site_id(
                "unsafe_block",
                project_root,
                module_path,
                function_name,
                &snippet,
            );
            let (reason, invariant, owner, scope, risk_class) =
                generated_unsafe_contract("unsafe_block", function_name, default_owner, None);
            let proof_ref = bind_proof_ref(
                project_root,
                &site_id,
                &format!("gate://compiler-generated/{function_name}/unsafe_block"),
            );
            let owner_id = generated_unsafe_owner_id(function_name, &owner);
            entries.push(UnsafeEntry {
                site_id,
                kind: "unsafe_block".to_string(),
                project: project_root.display().to_string(),
                file: module_path.display().to_string(),
                function: function_name.to_string(),
                line: find_line_in_function(source_lines, function_name, |line| {
                    line.contains("unsafe {")
                })
                .unwrap_or(0),
                snippet,
                reason: Some(reason),
                invariant: Some(invariant),
                owner: Some(owner),
                owner_id: Some(owner_id),
                scope: Some(scope),
                risk_class: Some(risk_class),
                proof_ref: Some(proof_ref),
            });
            for stmt in body {
                collect_semantic_unsafe_entries_from_stmt(
                    stmt,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    true,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Expr::Call { callee, args } => {
            if !in_unsafe_context && unsafe_callees.contains(callee) {
                let snippet = format!("{function_name}: call to unsafe `{callee}`");
                let site_id = unsafe_site_id(
                    "unsafe_violation_callsite",
                    project_root,
                    module_path,
                    function_name,
                    &snippet,
                );
                entries.push(UnsafeEntry {
                    site_id,
                    kind: "unsafe_violation_callsite".to_string(),
                    project: project_root.display().to_string(),
                    file: module_path.display().to_string(),
                    function: function_name.to_string(),
                    line: find_line_in_function(source_lines, function_name, |line| {
                        line.contains(&format!("{callee}("))
                    })
                    .unwrap_or(0),
                    snippet,
                    reason: None,
                    invariant: None,
                    owner: None,
                    owner_id: None,
                    scope: None,
                    risk_class: None,
                    proof_ref: None,
                });
            }
            for arg in args {
                collect_semantic_unsafe_entries_from_expr(
                    arg,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_semantic_unsafe_entries_from_expr(
                base,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_semantic_unsafe_entries_from_expr(
                    value,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_semantic_unsafe_entries_from_expr(
                    value,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_semantic_unsafe_entries_from_expr(
                body,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_semantic_unsafe_entries_from_expr(
                inner,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::Unary { expr, .. } => {
            collect_semantic_unsafe_entries_from_expr(
                expr,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_semantic_unsafe_entries_from_expr(
                try_expr,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            collect_semantic_unsafe_entries_from_expr(
                catch_expr,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_semantic_unsafe_entries_from_expr(
                condition,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            collect_semantic_unsafe_entries_from_expr(
                then_expr,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            collect_semantic_unsafe_entries_from_expr(
                else_expr,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_semantic_unsafe_entries_from_expr(
                left,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            collect_semantic_unsafe_entries_from_expr(
                right,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::Range { start, end, .. } => {
            collect_semantic_unsafe_entries_from_expr(
                start,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            collect_semantic_unsafe_entries_from_expr(
                end,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_semantic_unsafe_entries_from_expr(
                    item,
                    module_path,
                    project_root,
                    source_lines,
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            collect_semantic_unsafe_entries_from_expr(
                base,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
            collect_semantic_unsafe_entries_from_expr(
                index,
                module_path,
                project_root,
                source_lines,
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn vendor_command(path: &Path, format: Format) -> Result<String> {
    if !path.is_dir() {
        bail!("vendor requires a project directory: {}", path.display());
    }
    let manifest_path = path.join("fozzy.toml");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("missing manifest: {}", manifest_path.display()))?;
    let manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
    let lock_hash = refresh_lockfile(path)?;
    let lock_path = path.join("fozzy.lock");
    let lock_text = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("failed reading lockfile: {}", lock_path.display()))?;
    let lock_json: serde_json::Value = serde_json::from_str(&lock_text)
        .with_context(|| format!("failed parsing lockfile: {}", lock_path.display()))?;
    let lock_deps = lock_json
        .get("graph")
        .and_then(|value| value.get("deps"))
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let mut lock_dep_by_name = BTreeMap::new();
    for dep in &lock_deps {
        if let Some(name) = dep.get("name").and_then(|value| value.as_str()) {
            lock_dep_by_name.insert(name.to_string(), dep.clone());
        }
    }
    let vendor_dir = path.join("vendor");
    std::fs::create_dir_all(&vendor_dir)
        .with_context(|| format!("failed creating vendor dir: {}", vendor_dir.display()))?;
    let mut copied = Vec::new();
    for (name, dependency) in &manifest.deps {
        let lock_dep = lock_dep_by_name
            .get(name.as_str())
            .ok_or_else(|| anyhow!("lockfile missing dependency entry for `{name}`"))?;
        match dependency {
            manifest::Dependency::Path { path: dep_path } => {
                let source_dir = path.join(dep_path);
                if !source_dir.exists() {
                    bail!(
                        "path dependency `{}` not found at {}",
                        name,
                        source_dir.display()
                    );
                }
                let target_dir = vendor_dir.join(name);
                if target_dir.exists() {
                    std::fs::remove_dir_all(&target_dir).with_context(|| {
                        format!(
                            "failed cleaning existing vendor target: {}",
                            target_dir.display()
                        )
                    })?;
                }
                copy_dir_recursive(&source_dir, &target_dir)?;
                let source_hash = lock_dep
                    .get("sourceHash")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string();
                let vendor_hash = hash_directory_tree(&target_dir)?;
                if !source_hash.is_empty() && source_hash != vendor_hash {
                    bail!(
                        "vendor copy hash mismatch for `{}`: lock sourceHash={} vendorHash={}",
                        name,
                        source_hash,
                        vendor_hash
                    );
                }
                copied.push(serde_json::json!({
                    "name": name,
                    "sourceType": "path",
                    "source": source_dir.display().to_string(),
                    "target": target_dir.display().to_string(),
                    "sourceHash": source_hash,
                    "vendorHash": vendor_hash,
                    "package": lock_dep.get("package").cloned().unwrap_or(serde_json::json!({})),
                }));
            }
            manifest::Dependency::Version { version, source } => {
                copied.push(serde_json::json!({
                    "name": name,
                    "sourceType": "version",
                    "version": version,
                    "source": source.clone().unwrap_or_else(|| "registry+https://crates.io".to_string()),
                    "sourceHash": lock_dep.get("sourceHash").and_then(|value| value.as_str()).unwrap_or_default(),
                    "vendored": false,
                    "package": lock_dep.get("package").cloned().unwrap_or(serde_json::json!({})),
                }));
            }
            manifest::Dependency::Git { git, rev } => {
                copied.push(serde_json::json!({
                    "name": name,
                    "sourceType": "git",
                    "git": git,
                    "rev": rev,
                    "sourceHash": lock_dep.get("sourceHash").and_then(|value| value.as_str()).unwrap_or_default(),
                    "vendored": false,
                    "package": lock_dep.get("package").cloned().unwrap_or(serde_json::json!({})),
                }));
            }
        }
    }
    let vendor_manifest = vendor_dir.join("fozzy-vendor.json");
    let vendor_payload = serde_json::json!({
        "schemaVersion": "fozzylang.vendor.v0",
        "lockHash": lock_hash,
        "lockfile": lock_path.display().to_string(),
        "dependencies": copied,
    });
    std::fs::write(
        &vendor_manifest,
        serde_json::to_vec_pretty(&vendor_payload)?,
    )
    .with_context(|| {
        format!(
            "failed writing vendor manifest: {}",
            vendor_manifest.display()
        )
    })?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "vendor".to_string()),
            ("dependencies", copied.len().to_string()),
            ("dir", vendor_dir.display().to_string()),
            ("lock_hash", lock_hash.clone()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "vendorDir": vendor_dir.display().to_string(),
            "lockHash": lock_hash,
            "lockfile": lock_path.display().to_string(),
            "vendorManifest": vendor_manifest.display().to_string(),
            "dependencies": copied,
        })
        .to_string()),
    }
}

fn copy_dir_recursive(source: &Path, target: &Path) -> Result<()> {
    std::fs::create_dir_all(target)
        .with_context(|| format!("failed creating directory: {}", target.display()))?;
    for entry in std::fs::read_dir(source)
        .with_context(|| format!("failed reading directory: {}", source.display()))?
    {
        let entry = entry?;
        let src = entry.path();
        let dst = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst).with_context(|| {
                format!(
                    "failed copying file from {} to {}",
                    src.display(),
                    dst.display()
                )
            })?;
        }
    }
    Ok(())
}

fn abi_check_command(current: &Path, baseline: &Path, format: Format) -> Result<String> {
    ensure_exists(current)?;
    ensure_exists(baseline)?;
    let current_text = std::fs::read_to_string(current)
        .with_context(|| format!("failed reading current abi: {}", current.display()))?;
    let baseline_text = std::fs::read_to_string(baseline)
        .with_context(|| format!("failed reading baseline abi: {}", baseline.display()))?;
    let current_json: serde_json::Value = serde_json::from_str(&current_text)
        .with_context(|| format!("failed parsing current abi: {}", current.display()))?;
    let baseline_json: serde_json::Value = serde_json::from_str(&baseline_text)
        .with_context(|| format!("failed parsing baseline abi: {}", baseline.display()))?;
    let current_manifest = parse_abi_manifest(&current_json, current)?;
    let baseline_manifest = parse_abi_manifest(&baseline_json, baseline)?;
    let mut issues = Vec::new();
    if let (Some(current_package), Some(baseline_package)) = (
        current_manifest.package_name.as_deref(),
        baseline_manifest.package_name.as_deref(),
    ) {
        if current_package != baseline_package {
            issues.push(format!(
                "package mismatch: current={} baseline={}",
                current_package, baseline_package
            ));
        }
    }
    if let (Some(current_boundary), Some(baseline_boundary)) = (
        current_manifest.panic_boundary.as_deref(),
        baseline_manifest.panic_boundary.as_deref(),
    ) {
        if current_boundary != baseline_boundary {
            issues.push(format!(
                "panicBoundary mismatch: current={} baseline={}",
                current_boundary, baseline_boundary
            ));
        }
    }
    for (name, baseline_export) in &baseline_manifest.exports {
        let Some(current_export) = current_manifest.exports.get(name) else {
            issues.push(format!(
                "missing export in current ABI: {}",
                baseline_export.signature()
            ));
            continue;
        };
        if current_export.normalized_signature != baseline_export.normalized_signature {
            issues.push(format!(
                "signature changed for export `{}`: current={} baseline={}",
                name, current_export.normalized_signature, baseline_export.normalized_signature
            ));
        }
        if current_export.contract_signature != baseline_export.contract_signature {
            issues.push(format!(
                "contract weakened/changed for export `{}`: current={} baseline={}",
                name, current_export.contract_signature, baseline_export.contract_signature
            ));
        }
        if current_export.symbol_version < baseline_export.symbol_version {
            issues.push(format!(
                "symbolVersion regressed for `{}`: current={} baseline={}",
                name, current_export.symbol_version, baseline_export.symbol_version
            ));
        }
    }
    let mut added_exports = Vec::new();
    for (name, export) in &current_manifest.exports {
        if !baseline_manifest.exports.contains_key(name) {
            added_exports.push(export.signature());
        }
    }
    if !issues.is_empty() {
        bail!(
            "abi-check failed for {} vs {}: {}",
            current.display(),
            baseline.display(),
            issues.join("; ")
        );
    }
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "abi-check".to_string()),
            ("current", current.display().to_string()),
            ("baseline", baseline.display().to_string()),
            (
                "compared_exports",
                baseline_manifest.exports.len().to_string(),
            ),
            ("added_exports", added_exports.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "current": current.display().to_string(),
            "baseline": baseline.display().to_string(),
            "package": current_manifest.package_name,
            "panicBoundary": current_manifest.panic_boundary,
            "comparedExports": baseline_manifest.exports.keys().cloned().collect::<Vec<_>>(),
            "addedExports": added_exports,
            "issues": issues,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone)]
struct AbiManifest {
    package_name: Option<String>,
    panic_boundary: Option<String>,
    exports: BTreeMap<String, AbiExport>,
}

#[derive(Debug, Clone)]
struct AbiExport {
    normalized_signature: String,
    contract_signature: String,
    symbol_version: u64,
}

impl AbiExport {
    fn signature(&self) -> String {
        self.normalized_signature.clone()
    }
}

fn parse_abi_manifest(value: &serde_json::Value, path: &Path) -> Result<AbiManifest> {
    let schema = value
        .get("schemaVersion")
        .and_then(|item| item.as_str())
        .ok_or_else(|| anyhow!("abi manifest missing schemaVersion: {}", path.display()))?;
    if schema != "fozzylang.ffi_abi.v1" {
        bail!(
            "unsupported abi schema `{}` in {}; expected fozzylang.ffi_abi.v1",
            schema,
            path.display()
        );
    }
    let package_name = match value.get("package") {
        Some(serde_json::Value::String(name)) => Some(name.clone()),
        Some(serde_json::Value::Object(obj)) => obj
            .get("name")
            .and_then(|item| item.as_str())
            .map(str::to_string),
        _ => None,
    };
    let panic_boundary = value
        .get("panicBoundary")
        .and_then(|item| item.as_str())
        .map(str::to_string);
    let mut exports = BTreeMap::new();
    let export_items = value
        .get("exports")
        .and_then(|item| item.as_array())
        .cloned()
        .unwrap_or_default();
    for export in export_items {
        let name = export
            .get("name")
            .and_then(|item| item.as_str())
            .unwrap_or("<unknown>")
            .to_string();
        let params = export
            .get("params")
            .and_then(|item| item.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|param| {
                param
                    .get("c")
                    .and_then(|item| item.as_str())
                    .unwrap_or("void*")
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(",");
        let ret = export
            .get("return")
            .and_then(|item| item.get("c"))
            .and_then(|item| item.as_str())
            .unwrap_or("void*");
        let symbol_version = export
            .get("symbolVersion")
            .and_then(|item| item.as_u64())
            .unwrap_or(1);
        let export_mode = if export
            .get("async")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
        {
            "async"
        } else {
            "sync"
        };
        let param_contracts = export
            .get("params")
            .and_then(|item| item.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|param| {
                serde_json::json!({
                    "name": param.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    "contract": param.get("contract").cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>();
        let return_contract = export
            .get("return")
            .and_then(|item| item.get("contract"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let export_contract =
            normalize_abi_export_contract(export.get("contract"), export_mode == "async");
        let contract_signature = serde_json::to_string(&serde_json::json!({
            "params": param_contracts,
            "return": return_contract,
            "export": export_contract,
        }))
        .unwrap_or_else(|_| "{}".to_string());
        exports.insert(
            name.clone(),
            AbiExport {
                normalized_signature: format!("{name}:{export_mode}({params})->{ret}"),
                contract_signature,
                symbol_version,
            },
        );
    }
    Ok(AbiManifest {
        package_name,
        panic_boundary,
        exports,
    })
}

fn normalize_abi_export_contract(
    contract: Option<&serde_json::Value>,
    is_async: bool,
) -> serde_json::Value {
    let mut normalized = match contract {
        Some(serde_json::Value::Object(map)) => map.clone(),
        _ => serde_json::Map::new(),
    };
    normalized
        .entry("callbackBindings".to_string())
        .or_insert_with(|| serde_json::json!([]));
    normalized
        .entry("execution".to_string())
        .or_insert_with(|| {
            serde_json::Value::String(if is_async {
                "async-handle-v1".to_string()
            } else {
                "sync".to_string()
            })
        });
    normalized
        .entry("asyncBoundary".to_string())
        .or_insert(serde_json::Value::Null);
    serde_json::Value::Object(normalized)
}

fn hash_directory_tree(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    let mut hasher = Sha256::new();
    for (rel, full) in files {
        hasher.update(rel.as_bytes());
        let bytes = std::fs::read(&full)
            .with_context(|| format!("failed reading file for hash: {}", full.display()))?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn collect_files_recursive(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(current)
        .with_context(|| format!("failed reading directory: {}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed iterating directory: {}", current.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let full = entry.path();
        let rel = full
            .strip_prefix(root)
            .with_context(|| format!("failed deriving relative path for {}", full.display()))?;
        let rel_str = rel.display().to_string().replace('\\', "/");
        if rel_str.starts_with(".git/")
            || rel_str.starts_with(".fz/")
            || rel_str.starts_with("vendor/")
            || rel_str.starts_with("target/")
        {
            continue;
        }
        if entry
            .file_type()
            .with_context(|| format!("failed reading file type for {}", full.display()))?
            .is_dir()
        {
            collect_files_recursive(root, &full, out)?;
        } else {
            out.push((rel_str, full));
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn debug_check_command(path: &Path, format: Format) -> Result<String> {
    let artifact = compile_file_with_backend(path, BuildProfile::Dev, None)?;
    if artifact.status != "ok" {
        let rendered = render_artifact(Format::Text, artifact, None, None, None);
        bail!("debug-check failed to build module\n{rendered}");
    }
    let binary = artifact
        .output
        .as_ref()
        .ok_or_else(|| anyhow!("debug-check missing verify binary output"))?;
    let file_text = ProcessCommand::new("file")
        .arg(binary)
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
        .unwrap_or_default();
    let debug_symbols = binary.exists()
        && (file_text.contains("not stripped")
            || file_text.contains("with debug_info")
            || file_text.contains("dSYM")
            || !file_text.trim().is_empty());

    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let async_hooks = count_async_hooks_in_module(&parsed.module);
    let async_plan = run_non_scenario_test_plan(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: false,
            safe_profile: false,
            scheduler: Some("fifo".to_string()),
            seed: Some(1),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    )?;
    let async_backtrace_ready = async_hooks == 0 || async_plan.runtime_event_count > 0;
    let plan_claim_gate = validate_plan_claim_accuracy()?;
    let plan_claims_ok = plan_claim_gate.missing_evidence.is_empty();
    let ok = debug_symbols && async_backtrace_ready && plan_claims_ok;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", if ok { "ok" } else { "warn" }.to_string()),
            ("mode", "debug-check".to_string()),
            ("binary", binary.display().to_string()),
            ("debug_symbols", debug_symbols.to_string()),
            ("async_backtrace_ready", async_backtrace_ready.to_string()),
            ("async_hooks", async_hooks.to_string()),
            ("plan_claims_checked", plan_claim_gate.checked.to_string()),
            (
                "plan_claims_missing_evidence",
                plan_claim_gate.missing_evidence.len().to_string(),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": ok,
            "binary": binary.display().to_string(),
            "debugSymbols": debug_symbols,
            "asyncBacktraceReady": async_backtrace_ready,
            "asyncHooks": async_hooks,
            "runtimeEvents": async_plan.runtime_event_count,
            "causalLinks": async_plan.causal_link_count,
            "planClaimGate": {
                "completed": plan_claim_gate.completed,
                "checked": plan_claim_gate.checked,
                "missingEvidence": plan_claim_gate.missing_evidence,
            },
            "fileInfo": file_text.trim(),
        })
        .to_string()),
    }
}

fn lsp_diagnostics_command(path: &Path, format: Format) -> Result<String> {
    let payload = lsp::diagnostics_for_path(path)?;
    let ok = payload
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let module = payload
        .get("module")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let diagnostics = payload
        .get("diagnostics")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    match format {
        Format::Text => {
            let parsed_items = diagnostics
                .iter()
                .filter_map(|value| {
                    serde_json::from_value::<diagnostics::Diagnostic>(value.clone()).ok()
                })
                .collect::<Vec<_>>();
            let details = render_diagnostics_text(&parsed_items);
            let mut rendered = render_text_fields(&[
                ("status", if ok { "ok" } else { "error" }.to_string()),
                ("mode", "lsp-diagnostics".to_string()),
                ("module", module.to_string()),
                ("diagnostics", diagnostics.len().to_string()),
            ]);
            if details.is_empty() {
                Ok(rendered)
            } else {
                rendered.push('\n');
                rendered.push_str(&details);
                Ok(rendered)
            }
        }
        Format::Json => Ok(payload.to_string()),
    }
}

fn lsp_definition_command(path: &Path, symbol: &str, format: Format) -> Result<String> {
    let hit = lsp::definition_for_symbol(path, symbol)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-definition".to_string()),
            ("symbol", symbol.to_string()),
            ("kind", hit.kind.clone()),
            ("file", hit.file.clone()),
            ("line", hit.line.to_string()),
            ("col", hit.col.to_string()),
            ("detail", hit.detail.clone()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "symbol": hit,
        })
        .to_string()),
    }
}

fn lsp_hover_command(path: &Path, symbol: &str, format: Format) -> Result<String> {
    let info = lsp::hover_for_symbol(path, symbol)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-hover".to_string()),
            ("symbol", symbol.to_string()),
            (
                "kind",
                info.get("kind")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            ),
            (
                "signature",
                info.get("signature")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            ),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "hover": info,
        })
        .to_string()),
    }
}

fn lsp_rename_command(path: &Path, from: &str, to: &str, format: Format) -> Result<String> {
    let summary = lsp::rename_on_disk(path, from, to)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-rename".to_string()),
            ("from", summary.from.clone()),
            ("to", summary.to.clone()),
            ("replacements", summary.replacements.to_string()),
            ("files", summary.files.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "from": summary.from,
            "to": summary.to,
            "replacements": summary.replacements,
            "files": summary.files,
        })
        .to_string()),
    }
}

fn lsp_smoke_command(path: &Path, format: Format) -> Result<String> {
    let payload = lsp::smoke(path)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "lsp-smoke".to_string()),
            (
                "symbols",
                payload
                    .get("symbols")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "diagnostics",
                payload
                    .get("diagnostics")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    .to_string(),
            ),
        ])),
        Format::Json => Ok(payload.to_string()),
    }
}

fn ensure_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct NonScenarioTestPlan {
    module: String,
    mode: &'static str,
    scheduler: String,
    diagnostics: usize,
    discovered_tests: usize,
    selected_tests: usize,
    discovered_test_names: Vec<String>,
    selected_test_names: Vec<String>,
    deterministic_test_names: Vec<String>,
    executed_tasks: usize,
    execution_order: Vec<u64>,
    async_checkpoint_count: usize,
    async_execution: Vec<u64>,
    rpc_frame_count: usize,
    rpc_validation_errors: usize,
    thread_findings: usize,
    runtime_event_count: usize,
    causal_link_count: usize,
    coverage_ratio: f64,
    artifacts: Option<NonScenarioTraceArtifacts>,
    telemetry: NonScenarioPlanTelemetry,
}

#[derive(Debug, Clone, Default, Serialize)]
struct NonScenarioPlanTelemetry {
    parse_ms: u64,
    lower_ms: u64,
    verify_ms: u64,
    execute_ms: u64,
    artifact_write_ms: u64,
    total_ms: u64,
    parse_cache_hit: bool,
    lower_cache_hit: bool,
    input_bytes: usize,
}

#[derive(Debug, Clone)]
struct NonScenarioTraceArtifacts {
    trace_path: PathBuf,
    report_path: Option<PathBuf>,
    timeline_path: Option<PathBuf>,
    manifest_path: PathBuf,
    explore_path: Option<PathBuf>,
    shrink_path: Option<PathBuf>,
    scenarios_index_path: Option<PathBuf>,
    primary_scenario_path: Option<PathBuf>,
    goal_trace_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecMode {
    Fast,
    Det,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactDetail {
    Minimal,
    Rich,
}

#[derive(Debug, Clone)]
struct NonScenarioPlanRequest<'a> {
    deterministic: bool,
    strict_verify: bool,
    safe_profile: bool,
    scheduler: Option<String>,
    seed: Option<u64>,
    record: Option<&'a Path>,
    rich_artifacts: bool,
    filter: Option<&'a str>,
}

struct NonScenarioTraceInputs<'a> {
    detail: ArtifactDetail,
    scheduler: &'a str,
    seed: u64,
    discovered_tests: usize,
    discovered_test_names: &'a [String],
    deterministic_test_names: &'a [String],
    async_execution: &'a [u64],
    rpc_frames: &'a [RpcFrameEvent],
    rpc_validation: &'a [RpcValidationFinding],
    execution_order: &'a [u64],
    events: &'a [TaskEvent],
    runtime_events: &'a [RuntimeSemanticEvent],
    causal_links: &'a [CausalLink],
    thread_findings: &'a [serde_json::Value],
}

#[derive(Debug, Clone, Serialize)]
struct RpcFrameEvent {
    #[serde(rename = "event")]
    kind: &'static str,
    method: String,
    #[serde(rename = "taskId")]
    task_id: u64,
}

#[derive(Debug, Clone)]
struct WorkloadShape {
    async_functions: usize,
    spawn_markers: usize,
    yield_markers: usize,
}

#[derive(Debug, Clone)]
struct ExecutionOp {
    kind: &'static str,
    label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeSemanticEvent {
    #[serde(rename = "taskId")]
    task_id: u64,
    phase: String,
    kind: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CausalLink {
    from: u64,
    to: u64,
    relation: String,
}

#[derive(Debug, Clone, Copy)]
enum RpcValidationSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
struct RpcValidationFinding {
    kind: &'static str,
    severity: RpcValidationSeverity,
    message: String,
}

fn run_non_scenario_test_plan(
    path: &Path,
    request: NonScenarioPlanRequest<'_>,
) -> Result<NonScenarioTestPlan> {
    let started = Instant::now();
    let resolved = resolve_source(path)?;
    let parse_started = Instant::now();
    let (parsed, parse_cache_hit) = parse_program_with_metadata(&resolved.source_path)?;
    let parse_ms = parse_started.elapsed().as_millis() as u64;
    let mut discovered_test_names = Vec::new();
    let mut deterministic_test_names = Vec::new();
    for item in &parsed.module.items {
        if let ast::Item::Test(block) = item {
            discovered_test_names.push(block.name.clone());
            if block.deterministic {
                deterministic_test_names.push(block.name.clone());
            }
        }
    }
    let discovered_tests = discovered_test_names.len();
    let selected_test_names = if let Some(filter) = request.filter {
        discovered_test_names
            .iter()
            .filter(|name| name.contains(filter))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        discovered_test_names.clone()
    };
    let workload = analyze_workload_shape(&parsed.module);
    let call_sequence = collect_call_sequence(&parsed.module);
    let rpc_methods = parse_rpc_declarations(parsed.combined_source()).unwrap_or_default();
    let rpc_method_names = rpc_methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<BTreeSet<_>>();
    let rpc_call_count = call_sequence
        .iter()
        .filter(|call| rpc_method_names.contains(call.as_str()))
        .count();
    let async_checkpoint_count = count_async_hooks_in_module(&parsed.module);
    let deterministic_test_names = deterministic_test_names
        .into_iter()
        .filter(|name| selected_test_names.iter().any(|selected| selected == name))
        .collect::<Vec<_>>();
    let selected_tests = selected_test_names.len();
    let execution_plan = build_execution_plan(
        discovered_tests,
        &deterministic_test_names,
        workload.async_functions,
        workload.spawn_markers,
        rpc_call_count,
    );
    let task_count = execution_plan.len().max(1);
    let mode = if request.deterministic {
        ExecMode::Det
    } else {
        ExecMode::Fast
    };
    if request.record.is_some() && mode == ExecMode::Fast {
        bail!("--record requires --det");
    }

    let lower_started = Instant::now();
    let ((typed, fir), lower_cache_hit) = lower_fir_cached_with_metadata(&parsed);
    let lower_ms = lower_started.elapsed().as_millis() as u64;
    let strict_unsafe_contracts = request.strict_verify
        || resolved.manifest.as_ref().is_some_and(|manifest| {
            if request.safe_profile {
                manifest.unsafe_policy.enforce_verify.unwrap_or(true)
            } else {
                manifest.unsafe_policy.enforce_dev.unwrap_or(false)
            }
        });
    let (deny_unsafe_in, allow_unsafe_in) = resolved
        .manifest
        .as_ref()
        .map(|manifest| {
            (
                manifest.unsafe_policy.deny_unsafe_in.clone(),
                manifest.unsafe_policy.allow_unsafe_in.clone(),
            )
        })
        .unwrap_or_default();
    let production_memory_safety = true;
    let verify_started = Instant::now();
    let verify_report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: request.safe_profile,
            production_memory_safety,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );
    let verify_ms = verify_started.elapsed().as_millis() as u64;
    let mut verify_diagnostics = verify_report.diagnostics;
    for diagnostic in &mut verify_diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(resolved.source_path.display().to_string());
        }
    }
    diagnostics::assign_stable_codes(
        &mut verify_diagnostics,
        diagnostics::DiagnosticDomain::Driver,
    );
    let diagnostics = verify_diagnostics.len();
    let has_errors = verify_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let diagnostic_details = render_diagnostics_text(&verify_diagnostics);
    if production_memory_safety && has_errors {
        if diagnostic_details.is_empty() {
            bail!(
                "production memory safety rejected module `{}` with {} diagnostics",
                fir.name,
                diagnostics
            );
        }
        bail!(
            "production memory safety rejected module `{}` with {} diagnostics\n{}",
            fir.name,
            diagnostics,
            diagnostic_details
        );
    }
    if request.strict_verify && has_errors {
        if diagnostic_details.is_empty() {
            bail!(
                "strict verify rejected module `{}` with {} diagnostics",
                fir.name,
                diagnostics
            );
        }
        bail!(
            "strict verify rejected module `{}` with {} diagnostics\n{}",
            fir.name,
            diagnostics,
            diagnostic_details
        );
    }

    let scheduler = if mode == ExecMode::Det {
        parse_scheduler(request.scheduler.as_deref().unwrap_or("fifo"))?
    } else {
        Scheduler::Fifo
    };
    let scheduler_label = if mode == ExecMode::Det {
        scheduler_name(scheduler).to_string()
    } else {
        "fast".to_string()
    };
    let mut execution_order = Vec::new();
    let mut events = Vec::new();
    let mut runtime_events = Vec::new();
    let mut causal_links = Vec::new();
    let execute_started = Instant::now();
    if mode == ExecMode::Det {
        let trace_mode = if request.strict_verify || request.rich_artifacts {
            runtime::TraceMode::Full
        } else {
            runtime::TraceMode::ReplayCritical
        };
        let mut executor = DeterministicExecutor::new_with_trace_mode(trace_mode);
        let mut task_ops = BTreeMap::<u64, ExecutionOp>::new();
        for op in &execution_plan {
            let task_id = executor.spawn(Box::new(|| {
                let mut acc = 0u64;
                for i in 0..256u64 {
                    acc = acc.wrapping_add(i ^ 0x9E37);
                }
                std::hint::black_box(acc);
            }));
            task_ops.insert(task_id, op.clone());
        }
        execution_order =
            executor.run_until_idle_with_scheduler(scheduler, request.seed.unwrap_or(1));
        events = executor.trace().to_vec();
        let (mut derived_runtime_events, mut derived_causal_links) =
            derive_runtime_semantic_evidence(&events, &execution_order, &task_ops);
        let (gpu_runtime_events, gpu_causal_links) =
            derive_gpu_runtime_semantic_evidence(&parsed.module, &typed);
        derived_runtime_events.extend(gpu_runtime_events);
        derived_causal_links.extend(gpu_causal_links);
        runtime_events = derived_runtime_events;
        causal_links = derived_causal_links;
    }
    let execute_ms = execute_started.elapsed().as_millis() as u64;
    let async_execution = if mode == ExecMode::Det {
        plan_async_checkpoints(
            &execution_order,
            scheduler,
            request.seed.unwrap_or(1),
            async_checkpoint_count,
        )
    } else {
        Vec::new()
    };
    let rpc_frames = if mode == ExecMode::Det {
        build_rpc_frame_events(
            parsed.combined_source(),
            &call_sequence,
            &execution_order,
            &rpc_methods,
        )
    } else {
        Vec::new()
    };
    let rpc_validation = validate_rpc_frames(&rpc_frames);
    if strict_unsafe_contracts
        && mode == ExecMode::Det
        && rpc_validation
            .iter()
            .any(|finding| matches!(finding.severity, RpcValidationSeverity::Error))
    {
        bail!("strict verify rejected RPC sequence with validation errors");
    }
    let mut thread_findings = thread_health_findings(
        &events,
        &execution_order,
        task_count,
        &workload,
        &call_sequence,
    );
    thread_findings.extend(unsafe_trace_findings(&fir));
    let artifacts_started = Instant::now();
    let artifacts = if mode == ExecMode::Det {
        let detail = if strict_unsafe_contracts || request.rich_artifacts {
            ArtifactDetail::Rich
        } else {
            ArtifactDetail::Minimal
        };
        request
            .record
            .map(|record| {
                write_non_scenario_trace_artifacts(
                    record,
                    NonScenarioTraceInputs {
                        detail,
                        scheduler: &scheduler_label,
                        seed: request.seed.unwrap_or(1),
                        discovered_tests,
                        discovered_test_names: &selected_test_names,
                        deterministic_test_names: &deterministic_test_names,
                        async_execution: &async_execution,
                        rpc_frames: &rpc_frames,
                        rpc_validation: &rpc_validation,
                        execution_order: &execution_order,
                        events: &events,
                        runtime_events: &runtime_events,
                        causal_links: &causal_links,
                        thread_findings: &thread_findings,
                    },
                )
            })
            .transpose()?
    } else {
        None
    };
    let artifact_write_ms = artifacts_started.elapsed().as_millis() as u64;

    Ok(NonScenarioTestPlan {
        module: fir.name,
        mode: match mode {
            ExecMode::Fast => "fast",
            ExecMode::Det => "det",
        },
        scheduler: scheduler_label,
        diagnostics,
        discovered_tests,
        selected_tests,
        discovered_test_names,
        selected_test_names,
        deterministic_test_names,
        executed_tasks: if mode == ExecMode::Det { task_count } else { 0 },
        execution_order,
        async_checkpoint_count,
        async_execution,
        rpc_frame_count: rpc_frames.len(),
        rpc_validation_errors: rpc_validation
            .iter()
            .filter(|finding| matches!(finding.severity, RpcValidationSeverity::Error))
            .count(),
        thread_findings: thread_findings.len(),
        runtime_event_count: runtime_events.len(),
        causal_link_count: causal_links.len(),
        coverage_ratio: if discovered_tests == 0 {
            1.0
        } else {
            (selected_tests as f64) / (discovered_tests as f64)
        },
        artifacts,
        telemetry: NonScenarioPlanTelemetry {
            parse_ms,
            lower_ms,
            verify_ms,
            execute_ms,
            artifact_write_ms,
            total_ms: started.elapsed().as_millis() as u64,
            parse_cache_hit,
            lower_cache_hit,
            input_bytes: parsed.input_bytes,
        },
    })
}

fn write_non_scenario_trace_artifacts(
    trace_path: &Path,
    inputs: NonScenarioTraceInputs<'_>,
) -> Result<NonScenarioTraceArtifacts> {
    if let Some(parent) = trace_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating trace output directory: {}",
                parent.display()
            )
        })?;
    }
    let base_dir = trace_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = trace_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("trace");

    let timeline_path = base_dir.join(format!("{stem}.timeline.json"));
    let report_path = base_dir.join(format!("{stem}.report.json"));
    let manifest_path = base_dir.join(format!("{stem}.manifest.json"));
    let explore_path = base_dir.join(format!("{stem}.explore.json"));
    let shrink_path = base_dir.join(format!("{stem}.shrink.json"));
    let scenarios_index_path = base_dir.join(format!("{stem}.scenarios.json"));
    let native_trace_path = base_dir.join(format!("{stem}.native.trace.json"));
    let trace_payload = TracePayload {
        schema_version: "fozzylang.thread_trace.v0",
        capability: "thread",
        scheduler: inputs.scheduler,
        seed: inputs.seed,
        execution_order: inputs.execution_order,
        async_schedule: inputs.async_execution,
        rpc_frames: inputs.rpc_frames.to_vec(),
        events: inputs
            .events
            .iter()
            .map(TaskEventRecord::from)
            .collect::<Vec<TaskEventRecord>>(),
        runtime_events: inputs.runtime_events.to_vec(),
        causal_links: inputs.causal_links.to_vec(),
        thread_findings: inputs.thread_findings.to_vec(),
    };
    write_json_file(&native_trace_path, &trace_payload).with_context(|| {
        format!(
            "failed writing thread trace artifact: {}",
            native_trace_path.display()
        )
    })?;

    let mut report_written = None;
    let mut timeline_written = None;
    let mut explore_written = None;
    let mut shrink_written = None;
    let mut scenarios_written = None;
    let mut goal_trace_written = None;
    let (primary_scenario_path, generated_scenarios) =
        generate_language_test_scenarios(&base_dir, stem, inputs.deterministic_test_names)?;
    if let Some(primary_scenario) = &primary_scenario_path {
        ensure_goal_trace_from_scenario(primary_scenario, trace_path, inputs.seed).with_context(
            || {
                format!(
                    "failed generating goal trace from scenario {}",
                    primary_scenario.display()
                )
            },
        )?;
        goal_trace_written = Some(trace_path.to_path_buf());
    }

    if inputs.detail == ArtifactDetail::Rich {
        let mut timeline_entries = Vec::with_capacity(
            inputs.execution_order.len() + inputs.async_execution.len() + inputs.rpc_frames.len(),
        );
        for (index, task_id) in inputs.execution_order.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: index,
                decision: "thread.schedule",
                task_id: *task_id,
                scheduler: inputs.scheduler,
                event: None,
                method: None,
            });
        }
        let thread_steps = timeline_entries.len();
        for (index, task_id) in inputs.async_execution.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: thread_steps + index,
                decision: "async.schedule",
                task_id: *task_id,
                scheduler: inputs.scheduler,
                event: None,
                method: None,
            });
        }
        let async_steps = timeline_entries.len();
        for (index, frame) in inputs.rpc_frames.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: async_steps + index,
                decision: "rpc.frame",
                task_id: frame.task_id,
                scheduler: inputs.scheduler,
                event: Some(frame.kind),
                method: Some(frame.method.clone()),
            });
        }
        write_json_file(
            &timeline_path,
            &TimelinePayload {
                schema_version: "fozzylang.timeline.v0",
                entries: timeline_entries,
            },
        )
        .with_context(|| {
            format!(
                "failed writing timeline artifact: {}",
                timeline_path.display()
            )
        })?;
        timeline_written = Some(timeline_path.clone());

        write_json_file(
            &report_path,
            &ReportPayload {
                schema_version: "fozzylang.report.v0",
                status: "pass",
                capabilities: vec!["thread"],
                scheduler: inputs.scheduler.to_string(),
                seed: inputs.seed,
                discovered_tests: inputs.discovered_tests,
                deterministic_tests: inputs.deterministic_test_names.len(),
                executed_tasks: inputs.execution_order.len(),
                async_checkpoints: inputs.async_execution.len(),
                rpc_frames: inputs.rpc_frames.len(),
                generated_scenarios: generated_scenarios.len(),
                events: inputs.events.len(),
                failure_classes: classify_failure_classes(
                    inputs.rpc_frames,
                    inputs.async_execution,
                    inputs.execution_order,
                ),
                findings: rpc_failure_findings(inputs.rpc_frames),
                rpc_validation: inputs
                    .rpc_validation
                    .iter()
                    .map(rpc_validation_json)
                    .collect::<Vec<_>>(),
                thread_findings: inputs.thread_findings.to_vec(),
            },
        )
        .with_context(|| format!("failed writing report artifact: {}", report_path.display()))?;
        report_written = Some(report_path.clone());

        let scenario_priorities = build_scenario_priorities(
            &generated_scenarios,
            inputs.rpc_frames,
            inputs.async_execution,
        );
        write_json_file(
            &explore_path,
            &ExplorePayload {
                schema_version: "fozzylang.explore.v0",
                schedules: build_schedule_candidates(inputs.execution_order),
                rpc_frame_permutations: build_rpc_frame_permutations(
                    inputs.execution_order,
                    inputs.rpc_frames,
                ),
                scenario_priorities: scenario_priorities.clone(),
                shrink_hints: build_shrink_hints(
                    inputs.discovered_test_names,
                    inputs.execution_order,
                    inputs.rpc_frames,
                    inputs.async_execution,
                ),
                focus: "rpc_failure_repro",
            },
        )
        .with_context(|| {
            format!(
                "failed writing explore artifact: {}",
                explore_path.display()
            )
        })?;
        explore_written = Some(explore_path.clone());

        write_json_file(
            &shrink_path,
            &ShrinkPayload {
                schema_version: "fozzylang.shrink.v0",
                scenario_priorities,
                hints: build_shrink_hints(
                    inputs.discovered_test_names,
                    inputs.execution_order,
                    inputs.rpc_frames,
                    inputs.async_execution,
                ),
                minimal_rpc_repro: minimize_rpc_failure_frames(inputs.rpc_frames),
            },
        )
        .with_context(|| format!("failed writing shrink artifact: {}", shrink_path.display()))?;
        shrink_written = Some(shrink_path.clone());

        write_json_file(
            &scenarios_index_path,
            &ScenariosPayload {
                schema_version: "fozzylang.scenarios.v0",
                primary: primary_scenario_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                items: generated_scenarios
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            },
        )
        .with_context(|| {
            format!(
                "failed writing scenarios index: {}",
                scenarios_index_path.display()
            )
        })?;
        scenarios_written = Some(scenarios_index_path.clone());
    }

    write_json_file(
        &manifest_path,
        &ManifestPayload {
            schema_version: "fozzylang.artifacts.v0",
            trace: native_trace_path.display().to_string(),
            report: report_written
                .as_ref()
                .map(|path| path.display().to_string()),
            timeline: timeline_written
                .as_ref()
                .map(|path| path.display().to_string()),
            explore: explore_written
                .as_ref()
                .map(|path| path.display().to_string()),
            shrink: shrink_written
                .as_ref()
                .map(|path| path.display().to_string()),
            scenarios_index: scenarios_written
                .as_ref()
                .map(|path| path.display().to_string()),
            primary_scenario: primary_scenario_path
                .as_ref()
                .map(|path| path.display().to_string()),
            goal_trace: goal_trace_written
                .as_ref()
                .map(|path| path.display().to_string()),
            detail: match inputs.detail {
                ArtifactDetail::Minimal => "minimal",
                ArtifactDetail::Rich => "rich",
            },
        },
    )
    .with_context(|| {
        format!(
            "failed writing manifest artifact: {}",
            manifest_path.display()
        )
    })?;

    Ok(NonScenarioTraceArtifacts {
        trace_path: trace_path.to_path_buf(),
        report_path: report_written,
        timeline_path: timeline_written,
        manifest_path,
        explore_path: explore_written,
        shrink_path: shrink_written,
        scenarios_index_path: scenarios_written,
        primary_scenario_path,
        goal_trace_path: goal_trace_written,
    })
}

#[derive(Debug, Clone, Serialize)]
struct TaskEventRecord {
    event: &'static str,
    #[serde(rename = "taskId")]
    task_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    detached: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl From<&TaskEvent> for TaskEventRecord {
    fn from(value: &TaskEvent) -> Self {
        match value {
            TaskEvent::Spawned { task_id, detached } => Self {
                event: "spawned",
                task_id: *task_id,
                detached: Some(*detached),
                message: None,
            },
            TaskEvent::Started { task_id } => Self {
                event: "started",
                task_id: *task_id,
                detached: None,
                message: None,
            },
            TaskEvent::Completed { task_id } => Self {
                event: "completed",
                task_id: *task_id,
                detached: None,
                message: None,
            },
            TaskEvent::Panicked { task_id, message } => Self {
                event: "panicked",
                task_id: *task_id,
                detached: None,
                message: Some(message.clone()),
            },
            TaskEvent::PanicRootCause {
                task_id,
                cause_task_id,
            } => Self {
                event: "panic_root_cause",
                task_id: *task_id,
                detached: None,
                message: cause_task_id.map(|id| format!("cause_task_id={id}")),
            },
            TaskEvent::TimedOut {
                task_id,
                timeout_ms,
            } => Self {
                event: "timed_out",
                task_id: *task_id,
                detached: None,
                message: Some(format!("timeout_ms={timeout_ms}")),
            },
            TaskEvent::Cancelled { task_id } => Self {
                event: "cancelled",
                task_id: *task_id,
                detached: None,
                message: None,
            },
            TaskEvent::Backpressure {
                queue_depth,
                capacity,
            } => Self {
                event: "backpressure",
                task_id: 0,
                detached: None,
                message: Some(format!("queue_depth={queue_depth} capacity={capacity}")),
            },
            TaskEvent::JoinWait { waiter, target } => Self {
                event: "join_wait",
                task_id: *waiter,
                detached: None,
                message: Some(format!("target={target}")),
            },
            TaskEvent::JoinCycle { path } => Self {
                event: "join_cycle",
                task_id: path.first().copied().unwrap_or_default(),
                detached: None,
                message: Some(format!("path={path:?}")),
            },
            TaskEvent::Yielded { task_id, reason } => Self {
                event: "yielded",
                task_id: *task_id,
                detached: None,
                message: Some(reason.clone()),
            },
            TaskEvent::IoWait { task_id, key } => Self {
                event: "io_wait",
                task_id: *task_id,
                detached: None,
                message: Some(key.clone()),
            },
            TaskEvent::IoReady { task_id, key } => Self {
                event: "io_ready",
                task_id: *task_id,
                detached: None,
                message: Some(key.clone()),
            },
            TaskEvent::ChannelSend {
                task_id,
                channel,
                bytes,
                payload_hash,
            } => Self {
                event: "channel_send",
                task_id: *task_id,
                detached: None,
                message: Some(format!(
                    "channel={channel} bytes={bytes} payload_hash={payload_hash}"
                )),
            },
            TaskEvent::ChannelRecv {
                task_id,
                channel,
                bytes,
                payload_hash,
            } => Self {
                event: "channel_recv",
                task_id: *task_id,
                detached: None,
                message: Some(format!(
                    "channel={channel} bytes={bytes} payload_hash={payload_hash}"
                )),
            },
            TaskEvent::MemoryPressure {
                task_id,
                bytes,
                level,
            } => Self {
                event: "memory_pressure",
                task_id: *task_id,
                detached: None,
                message: Some(format!("bytes={bytes} level={level}")),
            },
            TaskEvent::ResourceLeak {
                task_id,
                subsystem,
                resource,
            } => Self {
                event: "resource_leak",
                task_id: *task_id,
                detached: None,
                message: Some(format!("subsystem={subsystem} resource={resource}")),
            },
            TaskEvent::Detached { task_id } => Self {
                event: "detached",
                task_id: *task_id,
                detached: None,
                message: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct TracePayload<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    capability: &'static str,
    scheduler: &'a str,
    seed: u64,
    #[serde(rename = "executionOrder")]
    execution_order: &'a [u64],
    #[serde(rename = "asyncSchedule")]
    async_schedule: &'a [u64],
    #[serde(rename = "rpcFrames")]
    rpc_frames: Vec<RpcFrameEvent>,
    events: Vec<TaskEventRecord>,
    #[serde(rename = "runtimeEvents")]
    runtime_events: Vec<RuntimeSemanticEvent>,
    #[serde(rename = "causalLinks")]
    causal_links: Vec<CausalLink>,
    #[serde(rename = "threadFindings")]
    thread_findings: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct TimelinePayload<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    entries: Vec<TimelineEntry<'a>>,
}

#[derive(Debug, Clone, Serialize)]
struct TimelineEntry<'a> {
    step: usize,
    decision: &'a str,
    #[serde(rename = "taskId")]
    task_id: u64,
    scheduler: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReportPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    status: &'static str,
    capabilities: Vec<&'static str>,
    scheduler: String,
    seed: u64,
    #[serde(rename = "discoveredTests")]
    discovered_tests: usize,
    #[serde(rename = "deterministicTests")]
    deterministic_tests: usize,
    #[serde(rename = "executedTasks")]
    executed_tasks: usize,
    #[serde(rename = "asyncCheckpoints")]
    async_checkpoints: usize,
    #[serde(rename = "rpcFrames")]
    rpc_frames: usize,
    #[serde(rename = "generatedScenarios")]
    generated_scenarios: usize,
    events: usize,
    #[serde(rename = "failureClasses")]
    failure_classes: Vec<serde_json::Value>,
    findings: Vec<serde_json::Value>,
    #[serde(rename = "rpcValidation")]
    rpc_validation: Vec<serde_json::Value>,
    #[serde(rename = "threadFindings")]
    thread_findings: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct ExplorePayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    schedules: serde_json::Value,
    #[serde(rename = "rpcFramePermutations")]
    rpc_frame_permutations: serde_json::Value,
    #[serde(rename = "scenarioPriorities")]
    scenario_priorities: serde_json::Value,
    #[serde(rename = "shrinkHints")]
    shrink_hints: serde_json::Value,
    focus: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ShrinkPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    #[serde(rename = "scenarioPriorities")]
    scenario_priorities: serde_json::Value,
    hints: serde_json::Value,
    #[serde(rename = "minimalRpcRepro")]
    minimal_rpc_repro: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
struct ScenariosPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    primary: Option<String>,
    items: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ManifestPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    trace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    explore: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shrink: Option<String>,
    #[serde(rename = "scenariosIndex", skip_serializing_if = "Option::is_none")]
    scenarios_index: Option<String>,
    #[serde(rename = "primaryScenario", skip_serializing_if = "Option::is_none")]
    primary_scenario: Option<String>,
    #[serde(rename = "goalTrace", skip_serializing_if = "Option::is_none")]
    goal_trace: Option<String>,
    detail: &'static str,
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)
        .with_context(|| format!("failed writing json file: {}", path.display()))
}

fn count_async_hooks_in_module(module: &ast::Module) -> usize {
    let mut hooks = 0usize;
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        if function.is_async {
            hooks += 1;
        }
        for stmt in &function.body {
            hooks += count_async_hooks_in_stmt(stmt);
        }
    }
    hooks
}

fn count_async_hooks_in_stmt(stmt: &ast::Stmt) -> usize {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => count_async_hooks_in_expr(value),
        ast::Stmt::Return(value) => value.as_ref().map(count_async_hooks_in_expr).unwrap_or(0),
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            count_async_hooks_in_expr(condition)
                + then_body
                    .iter()
                    .map(count_async_hooks_in_stmt)
                    .sum::<usize>()
                + else_body
                    .iter()
                    .map(count_async_hooks_in_stmt)
                    .sum::<usize>()
        }
        ast::Stmt::While { condition, body } => {
            count_async_hooks_in_expr(condition)
                + body.iter().map(count_async_hooks_in_stmt).sum::<usize>()
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().map(count_async_hooks_in_stmt).unwrap_or(0)
                + condition
                    .as_ref()
                    .map(count_async_hooks_in_expr)
                    .unwrap_or(0)
                + step.as_deref().map(count_async_hooks_in_stmt).unwrap_or(0)
                + body.iter().map(count_async_hooks_in_stmt).sum::<usize>()
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            count_async_hooks_in_expr(iterable)
                + body.iter().map(count_async_hooks_in_stmt).sum::<usize>()
        }
        ast::Stmt::Loop { body } => body.iter().map(count_async_hooks_in_stmt).sum::<usize>(),
        ast::Stmt::Break(_) | ast::Stmt::Continue => 0,
        ast::Stmt::Match { scrutinee, arms } => {
            let mut total = count_async_hooks_in_expr(scrutinee);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    total += count_async_hooks_in_expr(guard);
                }
                total += count_async_hooks_in_expr(&arm.value);
            }
            total
        }
    }
}

fn count_async_hooks_in_expr(expr: &ast::Expr) -> usize {
    match expr {
        ast::Expr::Await(inner) => 1 + count_async_hooks_in_expr(inner),
        ast::Expr::Discard(inner) => count_async_hooks_in_expr(inner),
        ast::Expr::Call { callee, args } => {
            let self_hook = usize::from(matches!(callee.as_str(), "yield" | "checkpoint"));
            self_hook + args.iter().map(count_async_hooks_in_expr).sum::<usize>()
        }
        ast::Expr::UnsafeBlock { .. } => 0,
        ast::Expr::FieldAccess { base, .. } => count_async_hooks_in_expr(base),
        ast::Expr::StructInit { fields, .. } => fields
            .iter()
            .map(|(_, value)| count_async_hooks_in_expr(value))
            .sum(),
        ast::Expr::EnumInit { payload, .. } => payload.iter().map(count_async_hooks_in_expr).sum(),
        ast::Expr::Closure { body, .. } => count_async_hooks_in_expr(body),
        ast::Expr::Group(inner) => count_async_hooks_in_expr(inner),
        ast::Expr::Unary { expr, .. } => count_async_hooks_in_expr(expr),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => count_async_hooks_in_expr(try_expr) + count_async_hooks_in_expr(catch_expr),
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            count_async_hooks_in_expr(condition)
                + count_async_hooks_in_expr(then_expr)
                + count_async_hooks_in_expr(else_expr)
        }
        ast::Expr::Binary { left, right, .. } => {
            count_async_hooks_in_expr(left) + count_async_hooks_in_expr(right)
        }
        ast::Expr::Range { start, end, .. } => {
            count_async_hooks_in_expr(start) + count_async_hooks_in_expr(end)
        }
        ast::Expr::ArrayLiteral(items) => items.iter().map(count_async_hooks_in_expr).sum(),
        ast::Expr::Index { base, index } => {
            count_async_hooks_in_expr(base) + count_async_hooks_in_expr(index)
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => 0,
        _ => 0,
    }
}

fn analyze_workload_shape(module: &ast::Module) -> WorkloadShape {
    let mut async_functions = 0usize;
    let mut spawn_markers = 0usize;
    let mut yield_markers = 0usize;
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        if function.is_async {
            async_functions += 1;
        }
        for stmt in &function.body {
            let (spawns, yields) = analyze_workload_stmt(stmt);
            spawn_markers += spawns;
            yield_markers += yields;
        }
    }
    WorkloadShape {
        async_functions,
        spawn_markers,
        yield_markers,
    }
}

fn analyze_workload_stmt(stmt: &ast::Stmt) -> (usize, usize) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => analyze_workload_expr(value),
        ast::Stmt::Return(value) => value.as_ref().map(analyze_workload_expr).unwrap_or((0, 0)),
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            let mut totals = analyze_workload_expr(condition);
            for stmt in then_body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            for stmt in else_body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::While { condition, body } => {
            let mut totals = analyze_workload_expr(condition);
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            let mut totals = (0usize, 0usize);
            if let Some(init) = init {
                let (spawns, yields) = analyze_workload_stmt(init);
                totals.0 += spawns;
                totals.1 += yields;
            }
            if let Some(condition) = condition {
                let (spawns, yields) = analyze_workload_expr(condition);
                totals.0 += spawns;
                totals.1 += yields;
            }
            if let Some(step) = step {
                let (spawns, yields) = analyze_workload_stmt(step);
                totals.0 += spawns;
                totals.1 += yields;
            }
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            let mut totals = analyze_workload_expr(iterable);
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::Loop { body } => {
            let mut totals = (0usize, 0usize);
            for stmt in body {
                let (spawns, yields) = analyze_workload_stmt(stmt);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => (0, 0),
        ast::Stmt::Match { scrutinee, arms } => {
            let mut totals = analyze_workload_expr(scrutinee);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    let (spawns, yields) = analyze_workload_expr(guard);
                    totals.0 += spawns;
                    totals.1 += yields;
                }
                let (spawns, yields) = analyze_workload_expr(&arm.value);
                totals.0 += spawns;
                totals.1 += yields;
            }
            totals
        }
    }
}

fn analyze_workload_expr(expr: &ast::Expr) -> (usize, usize) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let mut spawns = usize::from(matches!(
                callee.as_str(),
                "spawn" | "spawn_ctx" | "thread.spawn" | "task.group_spawn"
            ));
            let mut yields = usize::from(matches!(
                callee.as_str(),
                "yield" | "checkpoint" | "join" | "task.group_join"
            ));
            for arg in args {
                let (nested_spawns, nested_yields) = analyze_workload_expr(arg);
                spawns += nested_spawns;
                yields += nested_yields;
            }
            (spawns, yields)
        }
        ast::Expr::UnsafeBlock { .. } => (0, 0),
        ast::Expr::Await(inner) | ast::Expr::Group(inner) | ast::Expr::Discard(inner) => {
            analyze_workload_expr(inner)
        }
        ast::Expr::Unary { expr, .. } => analyze_workload_expr(expr),
        ast::Expr::FieldAccess { base, .. } => analyze_workload_expr(base),
        ast::Expr::StructInit { fields, .. } => {
            fields.iter().fold((0, 0), |mut acc, (_, value)| {
                let (spawns, yields) = analyze_workload_expr(value);
                acc.0 += spawns;
                acc.1 += yields;
                acc
            })
        }
        ast::Expr::EnumInit { payload, .. } => payload.iter().fold((0, 0), |mut acc, value| {
            let (spawns, yields) = analyze_workload_expr(value);
            acc.0 += spawns;
            acc.1 += yields;
            acc
        }),
        ast::Expr::Closure { body, .. } => analyze_workload_expr(body),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let (t_spawns, t_yields) = analyze_workload_expr(try_expr);
            let (c_spawns, c_yields) = analyze_workload_expr(catch_expr);
            (t_spawns + c_spawns, t_yields + c_yields)
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let (c_spawns, c_yields) = analyze_workload_expr(condition);
            let (t_spawns, t_yields) = analyze_workload_expr(then_expr);
            let (e_spawns, e_yields) = analyze_workload_expr(else_expr);
            (
                c_spawns + t_spawns + e_spawns,
                c_yields + t_yields + e_yields,
            )
        }
        ast::Expr::Binary { left, right, .. } => {
            let (l_spawns, l_yields) = analyze_workload_expr(left);
            let (r_spawns, r_yields) = analyze_workload_expr(right);
            (l_spawns + r_spawns, l_yields + r_yields)
        }
        ast::Expr::Range { start, end, .. } => {
            let (l_spawns, l_yields) = analyze_workload_expr(start);
            let (r_spawns, r_yields) = analyze_workload_expr(end);
            (l_spawns + r_spawns, l_yields + r_yields)
        }
        ast::Expr::ArrayLiteral(items) => items.iter().fold((0, 0), |mut acc, item| {
            let (spawns, yields) = analyze_workload_expr(item);
            acc.0 += spawns;
            acc.1 += yields;
            acc
        }),
        ast::Expr::Index { base, index } => {
            let (l_spawns, l_yields) = analyze_workload_expr(base);
            let (r_spawns, r_yields) = analyze_workload_expr(index);
            (l_spawns + r_spawns, l_yields + r_yields)
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => (0, 0),
        _ => (0, 0),
    }
}

fn build_execution_plan(
    discovered_tests: usize,
    deterministic_test_names: &[String],
    async_functions: usize,
    spawn_markers: usize,
    rpc_call_count: usize,
) -> Vec<ExecutionOp> {
    let mut plan = Vec::new();
    if discovered_tests == 0 {
        plan.push(ExecutionOp {
            kind: "baseline",
            label: "baseline".to_string(),
        });
    } else {
        for name in deterministic_test_names {
            plan.push(ExecutionOp {
                kind: "test",
                label: name.clone(),
            });
        }
    }
    for index in 0..async_functions {
        plan.push(ExecutionOp {
            kind: "async",
            label: format!("async_fn_{index}"),
        });
    }
    for index in 0..spawn_markers {
        plan.push(ExecutionOp {
            kind: "spawn",
            label: format!("spawn_{index}"),
        });
    }
    for index in 0..rpc_call_count {
        plan.push(ExecutionOp {
            kind: "rpc",
            label: format!("rpc_call_{index}"),
        });
    }
    if plan.is_empty() {
        plan.push(ExecutionOp {
            kind: "baseline",
            label: "baseline".to_string(),
        });
    }
    plan
}

fn derive_runtime_semantic_evidence(
    events: &[TaskEvent],
    execution_order: &[u64],
    task_ops: &BTreeMap<u64, ExecutionOp>,
) -> (Vec<RuntimeSemanticEvent>, Vec<CausalLink>) {
    let mut runtime_events = Vec::new();
    for event in events {
        match event {
            TaskEvent::Started { task_id } => {
                let op = task_ops.get(task_id);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *task_id,
                    phase: "started".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::Completed { task_id }
            | TaskEvent::Panicked { task_id, .. }
            | TaskEvent::TimedOut { task_id, .. }
            | TaskEvent::Cancelled { task_id } => {
                let op = task_ops.get(task_id);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *task_id,
                    phase: "terminal".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::Spawned { task_id, .. }
            | TaskEvent::Detached { task_id }
            | TaskEvent::Yielded { task_id, .. }
            | TaskEvent::IoWait { task_id, .. }
            | TaskEvent::IoReady { task_id, .. }
            | TaskEvent::ChannelSend { task_id, .. }
            | TaskEvent::ChannelRecv { task_id, .. }
            | TaskEvent::MemoryPressure { task_id, .. }
            | TaskEvent::ResourceLeak { task_id, .. } => {
                let op = task_ops.get(task_id);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *task_id,
                    phase: "spawned".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::JoinWait { waiter, .. } => {
                let op = task_ops.get(waiter);
                runtime_events.push(RuntimeSemanticEvent {
                    task_id: *waiter,
                    phase: "wait".to_string(),
                    kind: op
                        .map(|op| op.kind.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    label: op
                        .map(|op| op.label.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    details: None,
                });
            }
            TaskEvent::JoinCycle { .. }
            | TaskEvent::PanicRootCause { .. }
            | TaskEvent::Backpressure { .. } => {}
        }
    }
    let mut causal_links = Vec::new();
    let mut ordered = events
        .iter()
        .filter_map(|event| match event {
            TaskEvent::Started { task_id } => Some(*task_id),
            _ => None,
        })
        .collect::<Vec<_>>();
    if ordered.is_empty() {
        ordered = execution_order.to_vec();
        for task_id in &ordered {
            let op = task_ops.get(task_id);
            runtime_events.push(RuntimeSemanticEvent {
                task_id: *task_id,
                phase: "started".to_string(),
                kind: op
                    .map(|op| op.kind.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                label: op
                    .map(|op| op.label.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                details: None,
            });
            runtime_events.push(RuntimeSemanticEvent {
                task_id: *task_id,
                phase: "terminal".to_string(),
                kind: op
                    .map(|op| op.kind.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                label: op
                    .map(|op| op.label.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                details: None,
            });
        }
    }
    for window in ordered.windows(2) {
        causal_links.push(CausalLink {
            from: window[0],
            to: window[1],
            relation: "schedule.next".to_string(),
        });
    }
    (runtime_events, causal_links)
}

const GPU_TRACE_EVENT_ID_BASE: u64 = 1_000_000_000_000;

#[derive(Debug, Clone)]
enum GpuTraceBinding {
    Device {
        resource_id: String,
        event_id: u64,
    },
    Buffer {
        resource_id: String,
        event_id: u64,
        element_type: &'static str,
        device_resource: Option<String>,
    },
    Slice {
        resource_id: String,
        event_id: u64,
        buffer_resource: String,
        offset: Option<i64>,
        len: Option<i64>,
    },
    Event {
        resource_id: String,
        event_id: u64,
        kernel_name: String,
        launch_event_id: u64,
    },
}

#[derive(Debug, Clone)]
struct GpuLaunchArgTrace {
    slot: usize,
    layout: String,
    detail: serde_json::Value,
    source_event_ids: Vec<u64>,
}

#[derive(Debug, Default)]
struct GpuTraceAnalyzer {
    next_trace_id: u64,
    previous_trace_id: Option<u64>,
    next_device_id: usize,
    next_buffer_id: usize,
    next_slice_id: usize,
    next_event_id: usize,
    runtime_events: Vec<RuntimeSemanticEvent>,
    causal_links: Vec<CausalLink>,
    bindings: HashMap<String, GpuTraceBinding>,
    kernel_layouts: HashMap<String, String>,
}

impl GpuTraceAnalyzer {
    fn new(kernel_layouts: HashMap<String, String>) -> Self {
        Self {
            next_trace_id: GPU_TRACE_EVENT_ID_BASE,
            previous_trace_id: None,
            next_device_id: 1,
            next_buffer_id: 1,
            next_slice_id: 1,
            next_event_id: 1,
            runtime_events: Vec::new(),
            causal_links: Vec::new(),
            bindings: HashMap::new(),
            kernel_layouts,
        }
    }

    fn emit_event(
        &mut self,
        phase: &str,
        kind: &str,
        label: String,
        details: Option<serde_json::Value>,
    ) -> u64 {
        let trace_id = self.next_trace_id;
        self.next_trace_id = self.next_trace_id.saturating_add(1);
        self.runtime_events.push(RuntimeSemanticEvent {
            task_id: trace_id,
            phase: phase.to_string(),
            kind: kind.to_string(),
            label,
            details,
        });
        if let Some(previous) = self.previous_trace_id {
            self.causal_links.push(CausalLink {
                from: previous,
                to: trace_id,
                relation: "gpu.next".to_string(),
            });
        }
        self.previous_trace_id = Some(trace_id);
        trace_id
    }

    fn emit_link(&mut self, from: u64, to: u64, relation: &str) {
        self.causal_links.push(CausalLink {
            from,
            to,
            relation: relation.to_string(),
        });
    }

    fn bind(&mut self, name: &str, binding: GpuTraceBinding) {
        self.bindings.insert(name.to_string(), binding);
    }

    fn resolve_binding(&self, expr: &ast::Expr) -> Option<GpuTraceBinding> {
        match expr {
            ast::Expr::Ident(name) => self.bindings.get(name).cloned(),
            _ => None,
        }
    }

    fn trace_stmt(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                if let Some(binding) = self.trace_expr(value) {
                    self.bind(name, binding);
                }
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Expr(value)
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value) => {
                self.trace_expr(value);
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(binding) = self.trace_expr(value) {
                    self.bind(target, binding);
                }
            }
            ast::Stmt::CompoundAssign { value, .. } => {
                self.trace_expr(value);
            }
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    self.trace_expr(value);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                self.trace_expr(condition);
                for stmt in then_body {
                    self.trace_stmt(stmt);
                }
                for stmt in else_body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::While { condition, body } => {
                self.trace_expr(condition);
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    self.trace_stmt(init);
                }
                if let Some(condition) = condition {
                    self.trace_expr(condition);
                }
                if let Some(step) = step {
                    self.trace_stmt(step);
                }
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                self.trace_expr(iterable);
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::Loop { body } => {
                for stmt in body {
                    self.trace_stmt(stmt);
                }
            }
            ast::Stmt::Match { scrutinee, arms } => {
                self.trace_expr(scrutinee);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        self.trace_expr(guard);
                    }
                    self.trace_expr(&arm.value);
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }

    fn trace_expr(&mut self, expr: &ast::Expr) -> Option<GpuTraceBinding> {
        match expr {
            ast::Expr::Call { callee, args } => self.trace_call(callee, args),
            ast::Expr::Await(inner) | ast::Expr::Group(inner) | ast::Expr::Discard(inner) => {
                self.trace_expr(inner)
            }
            ast::Expr::Unary { expr, .. } => {
                self.trace_expr(expr);
                None
            }
            ast::Expr::FieldAccess { base, .. } => {
                self.trace_expr(base);
                None
            }
            ast::Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    self.trace_expr(value);
                }
                None
            }
            ast::Expr::EnumInit { payload, .. } | ast::Expr::Tuple(payload) => {
                for value in payload {
                    self.trace_expr(value);
                }
                None
            }
            ast::Expr::Closure { body, .. } => {
                self.trace_expr(body);
                None
            }
            ast::Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                self.trace_expr(try_expr);
                self.trace_expr(catch_expr);
                None
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                self.trace_expr(condition);
                self.trace_expr(then_expr);
                self.trace_expr(else_expr);
                None
            }
            ast::Expr::Binary { left, right, .. } => {
                self.trace_expr(left);
                self.trace_expr(right);
                None
            }
            ast::Expr::Range { start, end, .. } => {
                self.trace_expr(start);
                self.trace_expr(end);
                None
            }
            ast::Expr::ArrayLiteral(items) => {
                for item in items {
                    self.trace_expr(item);
                }
                None
            }
            ast::Expr::ObjectLiteral(items) => {
                for (_, value) in items {
                    self.trace_expr(value);
                }
                None
            }
            ast::Expr::Index { base, index } => {
                self.trace_expr(base);
                self.trace_expr(index);
                None
            }
            ast::Expr::UnsafeBlock { body, .. }
            | ast::Expr::While { body, .. }
            | ast::Expr::For { body, .. }
            | ast::Expr::ForIn { body, .. }
            | ast::Expr::Loop { body } => {
                for stmt in body {
                    self.trace_stmt(stmt);
                }
                None
            }
            ast::Expr::Ident(name) => self.bindings.get(name).cloned(),
            ast::Expr::Int(_)
            | ast::Expr::Float { .. }
            | ast::Expr::Char(_)
            | ast::Expr::Bool(_)
            | ast::Expr::Str(_)
            | ast::Expr::Break(_)
            | ast::Expr::Continue
            | ast::Expr::Return(_)
            | ast::Expr::Match { .. } => None,
        }
    }

    fn trace_call(&mut self, callee: &str, args: &[ast::Expr]) -> Option<GpuTraceBinding> {
        for arg in args {
            self.trace_expr(arg);
        }
        let base = callee.split('<').next().unwrap_or(callee);
        match base {
            "gpu.default_device" => Some(self.trace_default_device(callee)),
            "gpu.alloc_f32" => self.trace_alloc_like(callee, args, "f32", "gpu.alloc"),
            "gpu.alloc_i32" => self.trace_alloc_like(callee, args, "i32", "gpu.alloc"),
            "gpu.alloc_u32" => self.trace_alloc_like(callee, args, "u32", "gpu.alloc"),
            "gpu.upload_f32" => self.trace_alloc_like(callee, args, "f32", "gpu.upload"),
            "gpu.upload_i32" => self.trace_alloc_like(callee, args, "i32", "gpu.upload"),
            "gpu.upload_u32" => self.trace_alloc_like(callee, args, "u32", "gpu.upload"),
            "gpu.slice" => self.trace_slice(callee, args),
            "gpu.download_f32" => {
                self.trace_buffer_op(callee, args, "gpu.download", Some("f32"));
                None
            }
            "gpu.download_i32" => {
                self.trace_buffer_op(callee, args, "gpu.download", Some("i32"));
                None
            }
            "gpu.download_u32" => {
                self.trace_buffer_op(callee, args, "gpu.download", Some("u32"));
                None
            }
            "gpu.free" => {
                self.trace_buffer_free(callee, args);
                None
            }
            "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4" => {
                self.trace_launch(callee, args)
            }
            "gpu.wait" | "gpu.wait_async" => {
                self.trace_wait(callee, args);
                None
            }
            _ => None,
        }
    }

    fn trace_default_device(&mut self, callee: &str) -> GpuTraceBinding {
        let resource_id = format!("gpu_device#{}", self.next_device_id);
        self.next_device_id += 1;
        let event_id = self.emit_event(
            "host",
            "gpu.device_select",
            callee.to_string(),
            Some(serde_json::json!({
                "deviceResource": resource_id,
            })),
        );
        GpuTraceBinding::Device {
            resource_id,
            event_id,
        }
    }

    fn trace_alloc_like(
        &mut self,
        callee: &str,
        args: &[ast::Expr],
        element_type: &'static str,
        kind: &str,
    ) -> Option<GpuTraceBinding> {
        let resource_id = format!("gpu_buffer#{}", self.next_buffer_id);
        self.next_buffer_id += 1;
        let device_resource = args
            .first()
            .and_then(|expr| self.resolve_binding(expr))
            .and_then(|binding| match binding {
                GpuTraceBinding::Device { resource_id, .. } => Some(resource_id),
                _ => None,
            });
        let len = args.get(1).and_then(expr_const_i64);
        let event_id = self.emit_event(
            "host",
            kind,
            callee.to_string(),
            Some(serde_json::json!({
                "bufferResource": resource_id,
                "elementType": element_type,
                "deviceResource": device_resource,
                "len": len,
            })),
        );
        Some(GpuTraceBinding::Buffer {
            resource_id,
            event_id,
            element_type,
            device_resource,
        })
    }

    fn trace_slice(&mut self, callee: &str, args: &[ast::Expr]) -> Option<GpuTraceBinding> {
        let Some(GpuTraceBinding::Buffer {
            resource_id: buffer_resource,
            event_id: buffer_event_id,
            ..
        }) = args.first().and_then(|expr| self.resolve_binding(expr))
        else {
            self.emit_gpu_error(
                callee,
                "gpu.slice expected a known GPU buffer binding",
                serde_json::json!({"reason": "unknown_buffer_binding"}),
            );
            return None;
        };
        let resource_id = format!("gpu_slice#{}", self.next_slice_id);
        self.next_slice_id += 1;
        let offset = args.get(1).and_then(expr_const_i64);
        let len = args.get(2).and_then(expr_const_i64);
        let event_id = self.emit_event(
            "host",
            "gpu.slice",
            callee.to_string(),
            Some(serde_json::json!({
                "sliceResource": resource_id,
                "bufferResource": buffer_resource,
                "offset": offset,
                "len": len,
            })),
        );
        self.emit_link(buffer_event_id, event_id, "gpu.buffer.slice_of");
        Some(GpuTraceBinding::Slice {
            resource_id,
            event_id,
            buffer_resource,
            offset,
            len,
        })
    }

    fn trace_buffer_op(
        &mut self,
        callee: &str,
        args: &[ast::Expr],
        kind: &str,
        element_type: Option<&'static str>,
    ) {
        let Some(GpuTraceBinding::Buffer {
            resource_id,
            event_id,
            ..
        }) = args.first().and_then(|expr| self.resolve_binding(expr))
        else {
            self.emit_gpu_error(
                callee,
                "GPU buffer operation expected a known buffer binding",
                serde_json::json!({"reason": "unknown_buffer_binding"}),
            );
            return;
        };
        let op_event_id = self.emit_event(
            "host",
            kind,
            callee.to_string(),
            Some(serde_json::json!({
                "bufferResource": resource_id,
                "elementType": element_type,
            })),
        );
        self.emit_link(event_id, op_event_id, "gpu.buffer.use");
    }

    fn trace_buffer_free(&mut self, callee: &str, args: &[ast::Expr]) {
        let Some(GpuTraceBinding::Buffer {
            resource_id,
            event_id,
            element_type,
            device_resource,
        }) = args.first().and_then(|expr| self.resolve_binding(expr))
        else {
            self.emit_gpu_error(
                callee,
                "gpu.free expected a known GPU buffer binding",
                serde_json::json!({"reason": "unknown_buffer_binding"}),
            );
            return;
        };
        let free_event_id = self.emit_event(
            "host",
            "gpu.free",
            callee.to_string(),
            Some(serde_json::json!({
                "bufferResource": resource_id,
                "elementType": element_type,
                "deviceResource": device_resource,
            })),
        );
        self.emit_link(event_id, free_event_id, "gpu.buffer.lifetime_end");
    }

    fn trace_launch(&mut self, callee: &str, args: &[ast::Expr]) -> Option<GpuTraceBinding> {
        let kernel_name = args
            .first()
            .map(render_expr_brief)
            .unwrap_or_else(|| "unknown_kernel".to_string());
        let grid = args.get(1).and_then(expr_const_i64);
        let block = args.get(2).and_then(expr_const_i64);
        if grid.is_some_and(|value| value <= 0) || block.is_some_and(|value| value <= 0) {
            self.emit_gpu_error(
                callee,
                "gpu.launch uses a non-positive grid or block size",
                serde_json::json!({
                    "kernelName": kernel_name,
                    "grid": grid,
                    "block": block,
                    "reason": "non_positive_launch_dimension",
                }),
            );
        }
        let param_layout = self.kernel_layouts.get(&kernel_name).cloned();
        let launch_args = self.build_launch_arg_trace(param_layout.as_deref(), &args[3..]);
        let event_resource = format!("gpu_event#{}", self.next_event_id);
        self.next_event_id += 1;
        let launch_event_id = self.emit_event(
            "host",
            "gpu.kernel_launch",
            callee.to_string(),
            Some(serde_json::json!({
                "kernelName": kernel_name,
                "grid": grid,
                "block": block,
                "paramLayout": param_layout,
                "eventResource": event_resource,
                "arguments": launch_args.iter().map(|arg| serde_json::json!({
                    "slot": arg.slot,
                    "layout": arg.layout,
                    "binding": arg.detail,
                })).collect::<Vec<_>>(),
            })),
        );
        for arg in &launch_args {
            for source_event_id in &arg.source_event_ids {
                self.emit_link(*source_event_id, launch_event_id, "gpu.kernel.argument");
            }
        }
        Some(GpuTraceBinding::Event {
            resource_id: event_resource,
            event_id: launch_event_id,
            kernel_name,
            launch_event_id,
        })
    }

    fn build_launch_arg_trace(
        &mut self,
        param_layout: Option<&str>,
        args: &[ast::Expr],
    ) -> Vec<GpuLaunchArgTrace> {
        let layouts = param_layout
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["unknown".to_string(); args.len()]);
        args.iter()
            .enumerate()
            .map(|(slot, expr)| {
                let layout = layouts
                    .get(slot)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                let (detail, source_event_ids) = self.describe_launch_arg(expr, &layout);
                GpuLaunchArgTrace {
                    slot,
                    layout,
                    detail,
                    source_event_ids,
                }
            })
            .collect()
    }

    fn describe_launch_arg(&self, expr: &ast::Expr, layout: &str) -> (serde_json::Value, Vec<u64>) {
        match self.resolve_binding(expr) {
            Some(GpuTraceBinding::Slice {
                resource_id,
                event_id,
                buffer_resource,
                offset,
                len,
            }) => (
                serde_json::json!({
                    "kind": "GpuSlice",
                    "sliceResource": resource_id,
                    "bufferResource": buffer_resource,
                    "offset": offset,
                    "len": len,
                }),
                vec![event_id],
            ),
            Some(GpuTraceBinding::Buffer {
                resource_id,
                event_id,
                element_type,
                device_resource,
            }) => (
                serde_json::json!({
                    "kind": "GpuBuffer",
                    "bufferResource": resource_id,
                    "elementType": element_type,
                    "deviceResource": device_resource,
                }),
                vec![event_id],
            ),
            Some(GpuTraceBinding::Device {
                resource_id,
                event_id,
            }) => (
                serde_json::json!({
                    "kind": "GpuDevice",
                    "deviceResource": resource_id,
                }),
                vec![event_id],
            ),
            Some(GpuTraceBinding::Event {
                resource_id,
                event_id,
                kernel_name,
                ..
            }) => (
                serde_json::json!({
                    "kind": "GpuEvent",
                    "eventResource": resource_id,
                    "kernelName": kernel_name,
                }),
                vec![event_id],
            ),
            None => (
                serde_json::json!({
                    "kind": "scalar",
                    "layout": layout,
                    "source": render_expr_brief(expr),
                }),
                Vec::new(),
            ),
        }
    }

    fn trace_wait(&mut self, callee: &str, args: &[ast::Expr]) {
        let Some(binding) = args.first().and_then(|expr| self.resolve_binding(expr)) else {
            self.emit_gpu_error(
                callee,
                "gpu.wait expected a known GPU event binding",
                serde_json::json!({"reason": "unknown_event_binding"}),
            );
            return;
        };
        let GpuTraceBinding::Event {
            resource_id,
            event_id,
            kernel_name,
            launch_event_id,
        } = binding
        else {
            self.emit_gpu_error(
                callee,
                "gpu.wait expected a GPU event binding",
                serde_json::json!({"reason": "non_event_wait_target"}),
            );
            return;
        };
        let wait_event_id = self.emit_event(
            "host",
            "gpu.event_wait",
            callee.to_string(),
            Some(serde_json::json!({
                "eventResource": resource_id,
                "kernelName": kernel_name,
            })),
        );
        self.emit_link(event_id, wait_event_id, "gpu.event.waits_for");
        self.emit_link(launch_event_id, wait_event_id, "gpu.kernel.wait");
        let complete_event_id = self.emit_event(
            "host",
            "gpu.kernel_complete",
            callee.to_string(),
            Some(serde_json::json!({
                "eventResource": resource_id,
                "kernelName": kernel_name,
                "status": "ok",
            })),
        );
        self.emit_link(wait_event_id, complete_event_id, "gpu.event.complete");
    }

    fn emit_gpu_error(&mut self, label: &str, message: &str, details: serde_json::Value) {
        self.emit_event(
            "host",
            "gpu.error",
            label.to_string(),
            Some(serde_json::json!({
                "message": message,
                "detail": details,
            })),
        );
    }
}

fn derive_gpu_runtime_semantic_evidence(
    module: &ast::Module,
    typed: &hir::TypedModule,
) -> (Vec<RuntimeSemanticEvent>, Vec<CausalLink>) {
    let mut analyzer = GpuTraceAnalyzer::new(gpu_kernel_param_layouts(typed));
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            for statement in &function.body {
                analyzer.trace_stmt(statement);
            }
        }
    }
    (analyzer.runtime_events, analyzer.causal_links)
}

fn gpu_kernel_param_layouts(typed: &hir::TypedModule) -> HashMap<String, String> {
    let Ok(module) = kernel_ir::lower(typed) else {
        return HashMap::new();
    };
    let function_map = module
        .functions
        .iter()
        .map(|function| (function.name.clone(), function))
        .collect::<BTreeMap<_, _>>();
    module
        .kernels
        .iter()
        .filter_map(|kernel_name| {
            function_map
                .get(kernel_name)
                .and_then(|function| render_gpu_shared_param_layout(function).ok())
                .map(|layout| (kernel_name.clone(), layout))
        })
        .collect()
}

fn render_gpu_shared_param_layout(function: &kernel_ir::KernelFunction) -> Result<String> {
    let mut parts = Vec::with_capacity(function.params.len());
    for param in &function.params {
        let part = match &param.ty {
            ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
                let element = match &args[0] {
                    ast::Type::Int {
                        signed: true,
                        bits: 32,
                    } => "i32",
                    ast::Type::Int {
                        signed: false,
                        bits: 32,
                    } => "u32",
                    ast::Type::Float { bits: 32 } => "f32",
                    other => bail!("unsupported gpu slice element type in trace layout: {other:?}"),
                };
                let mode = function
                    .slice_access
                    .get(&param.name)
                    .copied()
                    .unwrap_or(kernel_ir::KernelSliceAccessMode::Observe);
                let access = mode.layout_suffix();
                format!("slice_{element}_{access}")
            }
            ast::Type::Int {
                signed: true,
                bits: 32,
            } => "i32".to_string(),
            ast::Type::Int {
                signed: false,
                bits: 32,
            } => "u32".to_string(),
            ast::Type::Float { bits: 32 } => "f32".to_string(),
            other => bail!("unsupported gpu param type in trace layout: {other:?}"),
        };
        parts.push(part);
    }
    Ok(parts.join(","))
}

fn expr_const_i64(expr: &ast::Expr) -> Option<i64> {
    match expr {
        ast::Expr::Int(value) => i64::try_from(*value).ok(),
        _ => None,
    }
}

fn render_expr_brief(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Ident(name) => name.clone(),
        ast::Expr::Int(value) => value.to_string(),
        ast::Expr::Float { value, .. } => value.to_string(),
        ast::Expr::Bool(value) => value.to_string(),
        ast::Expr::Str(value) => value.clone(),
        ast::Expr::Call { callee, .. } => callee.clone(),
        _ => format!("{expr:?}"),
    }
}

fn build_rpc_frame_events(
    _source: &str,
    call_sequence: &[String],
    execution_order: &[u64],
    methods: &[RpcMethod],
) -> Vec<RpcFrameEvent> {
    if execution_order.is_empty() {
        return Vec::new();
    }
    if methods.is_empty() {
        return Vec::new();
    }

    let mut events = Vec::new();
    let rpc_methods = methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<BTreeSet<_>>();

    let mut cursor = 0usize;
    let mut pending = VecDeque::<String>::new();
    for call in call_sequence {
        if rpc_methods.contains(call.as_str()) {
            let task_id = execution_order[cursor % execution_order.len()];
            cursor += 1;
            events.push(RpcFrameEvent {
                kind: "rpc_send",
                method: call.clone(),
                task_id,
            });
            pending.push_back(call.clone());
            continue;
        }

        if (call == "timeout" || call == "deadline") && !pending.is_empty() {
            let method = pending.pop_front().unwrap_or_default();
            events.push(RpcFrameEvent {
                kind: "rpc_deadline",
                method,
                task_id: execution_order[cursor % execution_order.len()],
            });
            cursor += 1;
            continue;
        }
        if call == "cancel" && !pending.is_empty() {
            let method = pending.pop_front().unwrap_or_default();
            events.push(RpcFrameEvent {
                kind: "rpc_cancel",
                method,
                task_id: execution_order[cursor % execution_order.len()],
            });
            cursor += 1;
            continue;
        }
        if call == "recv" && !pending.is_empty() {
            let method = pending.pop_front().unwrap_or_default();
            events.push(RpcFrameEvent {
                kind: "rpc_recv",
                method,
                task_id: execution_order[cursor % execution_order.len()],
            });
            cursor += 1;
        }
    }
    while let Some(method) = pending.pop_front() {
        events.push(RpcFrameEvent {
            kind: "rpc_recv",
            method,
            task_id: execution_order[cursor % execution_order.len()],
        });
        cursor += 1;
    }

    events
}

fn collect_call_sequence(module: &ast::Module) -> Vec<String> {
    let mut call_sequence = Vec::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            for statement in &function.body {
                collect_call_names_from_stmt(statement, &mut call_sequence);
            }
        }
    }
    call_sequence
}

fn collect_call_names_from_stmt(statement: &ast::Stmt, out: &mut Vec<String>) {
    match statement {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_call_names_from_expr(value, out),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_call_names_from_expr(value, out);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_call_names_from_expr(condition, out);
            for stmt in then_body {
                collect_call_names_from_stmt(stmt, out);
            }
            for stmt in else_body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_call_names_from_expr(condition, out);
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_call_names_from_stmt(init, out);
            }
            if let Some(condition) = condition {
                collect_call_names_from_expr(condition, out);
            }
            if let Some(step) = step {
                collect_call_names_from_stmt(step, out);
            }
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_call_names_from_expr(iterable, out);
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::Loop { body } => {
            for stmt in body {
                collect_call_names_from_stmt(stmt, out);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_call_names_from_expr(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_call_names_from_expr(guard, out);
                }
                collect_call_names_from_expr(&arm.value, out);
            }
        }
    }
}

fn collect_call_names_from_expr(expr: &ast::Expr, out: &mut Vec<String>) {
    match expr {
        ast::Expr::Call { callee, args } => {
            out.push(callee.clone());
            for arg in args {
                collect_call_names_from_expr(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => collect_call_names_from_expr(base, out),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_call_names_from_expr(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_call_names_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_call_names_from_expr(body, out),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_call_names_from_expr(try_expr, out);
            collect_call_names_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_call_names_from_expr(condition, out);
            collect_call_names_from_expr(then_expr, out);
            collect_call_names_from_expr(else_expr, out);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_call_names_from_expr(left, out);
            collect_call_names_from_expr(right, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_call_names_from_expr(start, out);
            collect_call_names_from_expr(end, out);
        }
        ast::Expr::Unary { expr, .. } => collect_call_names_from_expr(expr, out),
        ast::Expr::Group(inner) => collect_call_names_from_expr(inner, out),
        ast::Expr::Await(inner) => collect_call_names_from_expr(inner, out),
        ast::Expr::Discard(inner) => collect_call_names_from_expr(inner, out),
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_call_names_from_expr(item, out);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_call_names_from_expr(base, out);
            collect_call_names_from_expr(index, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn rpc_frames_json(frames: &[RpcFrameEvent]) -> Vec<serde_json::Value> {
    frames
        .iter()
        .map(|frame| {
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": frame.task_id,
            })
        })
        .collect()
}

fn rpc_validation_json(finding: &RpcValidationFinding) -> serde_json::Value {
    serde_json::json!({
        "kind": finding.kind,
        "severity": match finding.severity {
            RpcValidationSeverity::Info => "info",
            RpcValidationSeverity::Warning => "warning",
            RpcValidationSeverity::Error => "error",
        },
        "message": finding.message,
    })
}

fn validate_rpc_frames(frames: &[RpcFrameEvent]) -> Vec<RpcValidationFinding> {
    let mut findings = Vec::new();
    let mut pending = BTreeMap::<String, usize>::new();
    for frame in frames {
        match frame.kind {
            "rpc_send" => {
                *pending.entry(frame.method.clone()).or_insert(0) += 1;
            }
            "rpc_recv" => {
                let entry = pending.entry(frame.method.clone()).or_insert(0);
                if *entry == 0 {
                    findings.push(RpcValidationFinding {
                        kind: "rpc_recv_without_send",
                        severity: RpcValidationSeverity::Error,
                        message: format!(
                            "received response for `{}` without matching send",
                            frame.method
                        ),
                    });
                } else {
                    *entry -= 1;
                }
            }
            "rpc_cancel" | "rpc_deadline" => {
                let entry = pending.entry(frame.method.clone()).or_insert(0);
                if *entry == 0 {
                    findings.push(RpcValidationFinding {
                        kind: "rpc_terminal_without_inflight",
                        severity: RpcValidationSeverity::Warning,
                        message: format!(
                            "{} observed for `{}` without in-flight request",
                            frame.kind, frame.method
                        ),
                    });
                } else {
                    *entry -= 1;
                }
            }
            _ => {}
        }
    }
    for (method, inflight) in pending {
        if inflight > 0 {
            findings.push(RpcValidationFinding {
                kind: "rpc_inflight_leak",
                severity: RpcValidationSeverity::Error,
                message: format!(
                    "{inflight} in-flight request(s) for `{method}` did not terminate deterministically"
                ),
            });
        }
    }
    if findings.is_empty() && !frames.is_empty() {
        findings.push(RpcValidationFinding {
            kind: "rpc_sequence_validated",
            severity: RpcValidationSeverity::Info,
            message: "RPC send/recv/cancel/deadline sequencing is deterministic".to_string(),
        });
    }
    findings
}

fn thread_health_findings(
    events: &[TaskEvent],
    execution_order: &[u64],
    expected_tasks: usize,
    workload: &WorkloadShape,
    call_sequence: &[String],
) -> Vec<serde_json::Value> {
    let mut spawned = BTreeSet::<u64>::new();
    let mut completed = BTreeSet::<u64>::new();
    let mut panicked = BTreeSet::<u64>::new();
    for event in events {
        match event {
            TaskEvent::Spawned { task_id, .. } => {
                spawned.insert(*task_id);
            }
            TaskEvent::Completed { task_id } => {
                completed.insert(*task_id);
            }
            TaskEvent::Panicked { task_id, .. } => {
                panicked.insert(*task_id);
            }
            TaskEvent::TimedOut { task_id, .. } => {
                panicked.insert(*task_id);
            }
            TaskEvent::Cancelled { task_id } => {
                completed.insert(*task_id);
            }
            TaskEvent::Started { .. }
            | TaskEvent::Detached { .. }
            | TaskEvent::PanicRootCause { .. }
            | TaskEvent::Backpressure { .. }
            | TaskEvent::JoinWait { .. }
            | TaskEvent::JoinCycle { .. }
            | TaskEvent::Yielded { .. }
            | TaskEvent::IoWait { .. }
            | TaskEvent::IoReady { .. }
            | TaskEvent::ChannelSend { .. }
            | TaskEvent::ChannelRecv { .. }
            | TaskEvent::MemoryPressure { .. }
            | TaskEvent::ResourceLeak { .. } => {}
        }
    }
    let mut findings = Vec::new();
    if spawned.len() < expected_tasks {
        findings.push(serde_json::json!({
            "kind": "thread_spawn_shortfall",
            "severity": "warning",
            "message": format!(
                "expected at least {expected_tasks} deterministic tasks, observed {}",
                spawned.len()
            ),
        }));
    }
    if completed.len() + panicked.len() < spawned.len() {
        findings.push(serde_json::json!({
            "kind": "thread_deadlock_suspect",
            "severity": "error",
            "message": "spawned tasks missing terminal state (possible deadlock)",
        }));
    }
    if workload.spawn_markers > 0 && workload.yield_markers == 0 {
        findings.push(serde_json::json!({
            "kind": "thread_starvation_risk",
            "severity": "warning",
            "message": "spawn observed without yield/checkpoint markers; starvation risk under host scheduler",
        }));
    } else if workload.spawn_markers > (workload.yield_markers.saturating_mul(8)).max(8) {
        findings.push(serde_json::json!({
            "kind": "thread_fairness_pressure",
            "severity": "warning",
            "message": format!(
                "spawn/yield ratio is high (spawns={} yields={}); add join/checkpoint boundaries to reduce scheduler unfairness risk",
                workload.spawn_markers, workload.yield_markers
            ),
        }));
    }
    let lock_calls = call_sequence
        .iter()
        .filter(|call| call.as_str() == "lock")
        .count();
    let unlock_calls = call_sequence
        .iter()
        .filter(|call| call.as_str() == "unlock")
        .count();
    if lock_calls > unlock_calls {
        findings.push(serde_json::json!({
            "kind": "lock_unbalanced",
            "severity": "warning",
            "message": "lock/unlock imbalance detected; potential deadlock path",
            "locks": lock_calls,
            "unlocks": unlock_calls,
        }));
    }
    if execution_order.is_empty() {
        findings.push(serde_json::json!({
            "kind": "no_thread_schedule",
            "severity": "error",
            "message": "deterministic execution produced no scheduled tasks",
        }));
    }
    findings
}

fn unsafe_trace_findings(fir: &fir::FirModule) -> Vec<serde_json::Value> {
    let sites = fir
        .unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .collect::<Vec<_>>();
    if sites.is_empty() {
        return Vec::new();
    }
    let mut contract_lines = sites
        .iter()
        .filter(|site| {
            site.reason.as_deref().is_some_and(|v| !v.is_empty())
                && site.invariant.as_deref().is_some_and(|v| !v.is_empty())
                && site.owner.as_deref().is_some_and(|v| !v.is_empty())
                && site.scope.as_deref().is_some_and(|v| !v.is_empty())
                && site.risk_class.as_deref().is_some_and(|v| !v.is_empty())
                && site.proof_ref.as_deref().is_some_and(|v| !v.is_empty())
        })
        .map(|site| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                site.site_id,
                site.kind,
                site.reason.as_deref().unwrap_or_default(),
                site.invariant.as_deref().unwrap_or_default(),
                site.owner.as_deref().unwrap_or_default(),
                site.scope.as_deref().unwrap_or_default(),
                site.risk_class.as_deref().unwrap_or_default(),
                site.proof_ref.as_deref().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    contract_lines.sort();
    let metadata_sites = contract_lines.len();
    let contract_hash = if contract_lines.is_empty() {
        None
    } else {
        let mut hasher = Sha256::new();
        for line in &contract_lines {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        Some(
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
    };
    vec![serde_json::json!({
        "kind": "unsafe_site_accounting",
        "severity": "info",
        "message": format!("unsafe enter/exit accounting: enters={} exits={} metadata_sites={}", sites.len(), sites.len(), metadata_sites),
        "unsafeEnters": sites.len(),
        "unsafeExits": sites.len(),
        "metadataSites": metadata_sites,
        "contractHash": contract_hash,
    })]
}

fn rpc_failure_findings(frames: &[RpcFrameEvent]) -> Vec<serde_json::Value> {
    let has_deadline = frames.iter().any(|frame| frame.kind == "rpc_deadline");
    let has_cancel = frames.iter().any(|frame| frame.kind == "rpc_cancel");
    let recv_by_method = frames
        .iter()
        .filter(|frame| frame.kind == "rpc_recv")
        .map(|frame| frame.method.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let mut findings = Vec::new();
    if has_deadline {
        findings.push(serde_json::json!({
            "kind": "rpc_deadline",
            "severity": "warning",
            "message": "deadline event observed; verify timeout semantics are deterministic",
        }));
    }
    if has_cancel {
        findings.push(serde_json::json!({
            "kind": "rpc_cancel",
            "severity": "warning",
            "message": "cancellation event observed; verify cancellation propagation and cleanup",
        }));
    }
    if has_cancel && !recv_by_method.is_empty() {
        findings.push(serde_json::json!({
            "kind": "rpc_partial_response_after_cancel",
            "severity": "info",
            "message": "received response frames alongside cancellation; inspect partial-response handling",
            "methods": recv_by_method.into_iter().collect::<Vec<_>>(),
        }));
    }
    findings
}

fn build_schedule_candidates(execution_order: &[u64]) -> serde_json::Value {
    if execution_order.is_empty() {
        return serde_json::json!([]);
    }
    let fifo = execution_order.to_vec();
    let reversed = execution_order.iter().copied().rev().collect::<Vec<_>>();
    let rotated = execution_order
        .iter()
        .copied()
        .cycle()
        .skip(1)
        .take(execution_order.len())
        .collect::<Vec<_>>();
    serde_json::json!([
        { "name": "fifo", "order": fifo },
        { "name": "reverse", "order": reversed },
        { "name": "rotate_1", "order": rotated },
    ])
}

fn build_rpc_frame_permutations(
    execution_order: &[u64],
    frames: &[RpcFrameEvent],
) -> serde_json::Value {
    if frames.is_empty() || execution_order.is_empty() {
        return serde_json::json!([]);
    }
    let canonical = rpc_frames_json(frames);
    let mut task_index = 0usize;
    let rotated = frames
        .iter()
        .map(|frame| {
            let task_id = execution_order[task_index % execution_order.len()];
            task_index += 1;
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": task_id,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!([
        { "name": "canonical", "frames": canonical },
        { "name": "task_rotated", "frames": rotated },
    ])
}

fn build_shrink_hints(
    discovered_test_names: &[String],
    execution_order: &[u64],
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
) -> serde_json::Value {
    let mut hints = Vec::new();
    for name in discovered_test_names {
        hints.push(serde_json::json!({
            "kind": "single_test",
            "tests": [name],
        }));
    }
    for pair in discovered_test_names.windows(2) {
        hints.push(serde_json::json!({
            "kind": "test_pair",
            "tests": [pair[0].clone(), pair[1].clone()],
        }));
    }
    if !rpc_frames.is_empty() {
        let methods = rpc_frames
            .iter()
            .map(|frame| frame.method.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        hints.push(serde_json::json!({
            "kind": "rpc_methods",
            "methods": methods,
        }));
    }
    if !async_execution.is_empty() {
        hints.push(serde_json::json!({
            "kind": "async_checkpoint_focus",
            "taskIds": async_execution,
        }));
    }
    if !execution_order.is_empty() {
        hints.push(serde_json::json!({
            "kind": "task_order",
            "order": execution_order,
        }));
    }
    serde_json::json!(hints)
}

fn minimize_rpc_failure_frames(frames: &[RpcFrameEvent]) -> serde_json::Value {
    if frames.is_empty() {
        return serde_json::json!([]);
    }
    let pivot = frames
        .iter()
        .find(|frame| frame.kind == "rpc_deadline" || frame.kind == "rpc_cancel")
        .map(|frame| frame.method.clone());
    let Some(method) = pivot else {
        return serde_json::json!(rpc_frames_json(frames));
    };
    let minimal = frames
        .iter()
        .filter(|frame| frame.method == method)
        .map(|frame| {
            serde_json::json!({
                "event": frame.kind,
                "method": frame.method,
                "taskId": frame.task_id,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!(minimal)
}

fn classify_failure_classes(
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
    execution_order: &[u64],
) -> Vec<serde_json::Value> {
    let mut classes = Vec::new();
    if rpc_frames.iter().any(|frame| frame.kind == "rpc_deadline") {
        classes.push(serde_json::json!({
            "id": "rpc_timeout",
            "priority": 1,
            "signal": "rpc_deadline",
        }));
    }
    if rpc_frames.iter().any(|frame| frame.kind == "rpc_cancel") {
        classes.push(serde_json::json!({
            "id": "rpc_cancel_race",
            "priority": 2,
            "signal": "rpc_cancel",
        }));
    }
    if !async_execution.is_empty() {
        classes.push(serde_json::json!({
            "id": "async_schedule_interleaving",
            "priority": 3,
            "signal": "async.schedule",
        }));
    }
    if execution_order.len() > 1 {
        classes.push(serde_json::json!({
            "id": "thread_interleaving",
            "priority": 4,
            "signal": "thread.schedule",
        }));
    }
    if classes.is_empty() {
        classes.push(serde_json::json!({
            "id": "baseline",
            "priority": 9,
            "signal": "deterministic",
        }));
    }
    classes
}

fn build_scenario_priorities(
    generated_scenarios: &[PathBuf],
    rpc_frames: &[RpcFrameEvent],
    async_execution: &[u64],
) -> serde_json::Value {
    let mut items = Vec::new();
    for path in generated_scenarios {
        let mut score = 100i32;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if name == "all.fozzy.json" {
            score -= 30;
        }
        if !rpc_frames.is_empty() {
            score -= 20;
        }
        if !async_execution.is_empty() {
            score -= 10;
        }
        items.push(serde_json::json!({
            "scenario": path.display().to_string(),
            "score": score,
        }));
    }
    items.sort_by_key(|item| item.get("score").and_then(|v| v.as_i64()).unwrap_or(999));
    serde_json::json!(items)
}

fn generate_language_test_scenarios(
    base_dir: &Path,
    stem: &str,
    deterministic_test_names: &[String],
) -> Result<(Option<PathBuf>, Vec<PathBuf>)> {
    let scenarios_dir = base_dir.join(format!("{stem}.scenarios"));
    std::fs::create_dir_all(&scenarios_dir).with_context(|| {
        format!(
            "failed creating language test scenarios dir: {}",
            scenarios_dir.display()
        )
    })?;

    let combined_path = scenarios_dir.join("all.fozzy.json");
    let combined_steps = deterministic_test_names
        .iter()
        .map(|name| serde_json::json!({ "type": "trace_event", "name": format!("test:{name}") }))
        .collect::<Vec<_>>();
    let combined_payload = serde_json::json!({
        "version": 1,
        "name": "language-tests-all",
        "steps": combined_steps,
    });
    std::fs::write(
        &combined_path,
        serde_json::to_vec_pretty(&combined_payload)?,
    )
    .with_context(|| {
        format!(
            "failed writing combined scenario: {}",
            combined_path.display()
        )
    })?;

    let mut generated = vec![combined_path.clone()];
    for test_name in deterministic_test_names {
        let safe_name = sanitize_file_component(test_name);
        let scenario_path = scenarios_dir.join(format!("{safe_name}.fozzy.json"));
        let payload = serde_json::json!({
            "version": 1,
            "name": format!("language-test-{safe_name}"),
            "steps": [
                { "type": "trace_event", "name": format!("test:{test_name}") },
                { "type": "assert_eq_int", "a": 1, "b": 1 }
            ],
        });
        std::fs::write(&scenario_path, serde_json::to_vec_pretty(&payload)?).with_context(
            || {
                format!(
                    "failed writing scenario for test `{}`: {}",
                    test_name,
                    scenario_path.display()
                )
            },
        )?;
        generated.push(scenario_path);
    }
    for pair in deterministic_test_names.windows(2) {
        let left = sanitize_file_component(&pair[0]);
        let right = sanitize_file_component(&pair[1]);
        let scenario_path = scenarios_dir.join(format!("{left}__{right}.fozzy.json"));
        let payload = serde_json::json!({
            "version": 1,
            "name": format!("language-test-pair-{left}-{right}"),
            "steps": [
                { "type": "trace_event", "name": format!("test:{}", pair[0]) },
                { "type": "trace_event", "name": format!("test:{}", pair[1]) },
                { "type": "assert_eq_int", "a": 1, "b": 1 }
            ],
        });
        std::fs::write(&scenario_path, serde_json::to_vec_pretty(&payload)?).with_context(
            || {
                format!(
                    "failed writing pair scenario for tests `{}` + `{}`: {}",
                    pair[0],
                    pair[1],
                    scenario_path.display()
                )
            },
        )?;
        generated.push(scenario_path);
    }

    let primary = generated.first().cloned();
    Ok((primary, generated))
}

fn sanitize_file_component(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "test".to_string()
    } else {
        out
    }
}

fn sanitize_c_identifier(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn parse_scheduler(input: &str) -> Result<Scheduler> {
    match input {
        "fifo" | "default" | "host" => Ok(Scheduler::Fifo),
        "random" => Ok(Scheduler::Random),
        "coverage_guided" => Ok(Scheduler::CoverageGuided),
        other => bail!(
            "unknown scheduler `{}`; expected one of: fifo, random, coverage_guided",
            other
        ),
    }
}

fn scheduler_name(scheduler: Scheduler) -> &'static str {
    match scheduler {
        Scheduler::Fifo => "fifo",
        Scheduler::Random => "random",
        Scheduler::CoverageGuided => "coverage_guided",
    }
}

fn persist_runtime_threads_config(path: &Path, threads: Option<u16>) -> Result<Option<PathBuf>> {
    let Some(threads) = threads else {
        return Ok(None);
    };
    if threads == 0 {
        bail!("--threads must be greater than zero");
    }
    let root = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let config_path = root.join(".fz").join("runtime.json");
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating runtime config directory: {}",
                parent.display()
            )
        })?;
    }
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.runtime.v0",
        "threads": threads,
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing runtime config: {}", config_path.display()))?;
    Ok(Some(config_path))
}

fn replay_like(command: &str, target: &Path, strict: bool, format: Format) -> Result<String> {
    scenario_replay_like(command, target, strict, format)
}

#[derive(Debug, Clone, Deserialize)]
struct NativeTracePayloadOwned {
    #[serde(rename = "executionOrder")]
    execution_order: Vec<u64>,
    #[serde(rename = "asyncSchedule")]
    async_schedule: Vec<u64>,
    #[serde(rename = "rpcFrames")]
    rpc_frames: Vec<RpcFrameEventOwned>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcFrameEventOwned {
    #[serde(rename = "event")]
    kind: String,
    method: String,
    #[serde(rename = "taskId")]
    task_id: u64,
}

fn is_native_trace_or_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".trace.json") || name.ends_with(".manifest.json"))
        .unwrap_or(false)
}

fn render_c_header(
    package_name: &str,
    module: &ast::Module,
    exports: &[&ast::Function],
    repr_c_aliases: &BTreeMap<String, String>,
    callback_types: &[interop::CallbackTypeDef],
) -> String {
    let guard = format!("FOZZY_{}_H", package_name.to_ascii_uppercase());
    let mut header = String::new();
    header.push_str("#ifndef ");
    header.push_str(&guard);
    header.push_str("\n#define ");
    header.push_str(&guard);
    header.push_str("\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <sys/types.h>\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    header.push_str("typedef int32_t (*fz_callback_i32_v0)(int32_t arg);\n");
    header.push_str("int32_t fz_host_init(void);\n");
    header.push_str("int32_t fz_host_shutdown(void);\n");
    header.push_str("int32_t fz_host_cleanup(void);\n");
    header.push_str("int32_t fz_host_last_error_code(void);\n");
    header.push_str("int32_t fz_host_last_error_class(void);\n");
    header.push_str("const char* fz_host_last_error_message(void);\n");
    header
        .push_str("int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb);\n");
    header.push_str("int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg);\n\n");
    if exports.iter().any(|function| function.is_async) {
        header.push_str("typedef uint64_t fz_async_handle_t;\n\n");
    }
    header.push_str(&render_callback_type_defs(callback_types, repr_c_aliases));
    header.push_str(&render_repr_c_type_defs(module, repr_c_aliases));
    if !header.ends_with("\n\n") {
        header.push('\n');
    }
    for function in exports {
        let symbol = ffi_symbol_name(function);
        if function.is_async {
            let params = render_c_params(function, repr_c_aliases, callback_types);
            let start_params = if params == "void" {
                "fz_async_handle_t* handle_out".to_string()
            } else {
                format!("{params}, fz_async_handle_t* handle_out")
            };
            header.push_str(&format!(
                "/* {} uses an eager synchronous start shim and stores the result in an async handle. */\n",
                symbol
            ));
            header.push_str(&format!(
                "int32_t {}_async_start({});\n",
                symbol, start_params
            ));
            header.push_str(&format!(
                "int32_t {}_async_poll(fz_async_handle_t handle, int32_t* done_out);\n",
                symbol
            ));
            header.push_str(&format!(
                "int32_t {}_async_await(fz_async_handle_t handle, int32_t* result_out);\n",
                symbol
            ));
            header.push_str(&format!(
                "int32_t {}_async_drop(fz_async_handle_t handle);\n",
                symbol
            ));
        } else {
            header.push_str(&format!(
                "{} {}({});\n",
                render_c_surface_type(&function.return_type, repr_c_aliases, callback_types),
                symbol,
                render_c_params(function, repr_c_aliases, callback_types)
            ));
        }
    }
    if exports.is_empty() {
        header.push_str("/* no exported extern \"C\" functions found */\n");
    }
    header.push_str("\n#ifdef __cplusplus\n}\n#endif\n\n#endif\n");
    header
}

fn render_repr_c_type_defs(
    module: &ast::Module,
    repr_c_aliases: &BTreeMap<String, String>,
) -> String {
    let mut out = String::new();
    for item in &module.items {
        match item {
            ast::Item::Struct(item) if is_repr_c(item.repr.as_deref()) => {
                let c_name = repr_c_aliases
                    .get(&item.name)
                    .cloned()
                    .unwrap_or_else(|| sanitize_c_identifier(&item.name));
                out.push_str(&format!("typedef struct {} {{\n", c_name));
                for field in &item.fields {
                    out.push_str(&format!(
                        "    {} {};\n",
                        render_c_surface_type(&field.ty, repr_c_aliases, &[]),
                        field.name
                    ));
                }
                out.push_str(&format!("}} {};\n\n", c_name));
            }
            ast::Item::Enum(item) if is_repr_c(item.repr.as_deref()) => {
                let c_name = repr_c_aliases
                    .get(&item.name)
                    .cloned()
                    .unwrap_or_else(|| sanitize_c_identifier(&item.name));
                out.push_str(&format!("typedef enum {} {{\n", c_name));
                for (idx, variant) in item.variants.iter().enumerate() {
                    out.push_str(&format!("    {}_{} = {},\n", c_name, variant.name, idx));
                }
                out.push_str(&format!("}} {};\n\n", c_name));
            }
            _ => {}
        }
    }
    out
}

fn validate_ffi_contracts(
    module: &ast::Module,
    imports: &[&ast::Function],
    exports: &[&ast::Function],
    repr_c_names: &BTreeSet<String>,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let has_c_symbols = module.items.iter().any(|item| {
        matches!(
            item,
            ast::Item::Function(function)
                if function.is_extern
                    && function
                        .abi
                        .as_deref()
                        .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        )
    });
    let project_default = manifest
        .and_then(|value| value.ffi.panic_boundary.as_deref())
        .filter(|mode| *mode == "abort" || *mode == "error");
    if has_c_symbols && manifest.is_some() && project_default.is_none() {
        bail!(
            "project defines C interop symbols but fozzy.toml is missing [ffi] panic_boundary = \"abort\"|\"error\""
        );
    }
    let mut panic_mode: Option<&str> = None;
    for function in exports {
        let symbol = ffi_symbol_name(function);
        let mode = function.ffi_panic.as_deref().or(project_default).ok_or_else(|| {
            anyhow!(
                "ffi panic contract missing on export `{}`: set [ffi].panic_boundary in fozzy.toml or add #[ffi_panic(...)] override",
                symbol
            )
        })?;
        if mode != "abort" && mode != "error" {
            bail!(
                "invalid ffi panic mode `{}` on export `{}`; expected `abort` or `error`",
                mode,
                symbol
            );
        }
        if let Some(expected) = panic_mode {
            if expected != mode {
                bail!(
                    "ffi panic contract mismatch across exports: expected `{}` but `{}` uses `{}`",
                    expected,
                    symbol,
                    mode
                );
            }
        } else {
            panic_mode = Some(mode);
        }
    }
    for (function, kind) in imports
        .iter()
        .map(|function| (*function, "import"))
        .chain(exports.iter().map(|function| (*function, "export")))
    {
        let symbol = ffi_symbol_name(function);
        if function.is_async && kind == "export" {
            if function.body.is_empty() {
                bail!(
                    "extern async export `{}` must define a body; declaration-only async exports are not allowed",
                    symbol
                );
            }
            if !is_i32_type(&function.return_type) {
                bail!(
                    "extern async export `{}` must return `i32` for async-handle-v1 ABI",
                    symbol
                );
            }
        }
        if function.is_async && kind == "import" {
            bail!(
                "extern C import `{}` cannot be async; async-handle ABI is export-only in native ship v0",
                symbol
            );
        }
        if !is_ffi_stable_type(&function.return_type, repr_c_names) {
            bail!(
                "extern {kind} `{}` uses unstable return type `{}`",
                symbol,
                function.return_type
            );
        }
        for param in &function.params {
            if !is_ffi_stable_type(&param.ty, repr_c_names) {
                bail!(
                    "extern {kind} `{}` param `{}` uses unstable type `{}`",
                    symbol,
                    param.name,
                    param.ty
                );
            }
            if matches!(param.ty, ast::Type::Ptr { .. }) {
                let tagged = param.name.ends_with("_owned")
                    || param.name.ends_with("_borrowed")
                    || param.name.ends_with("_out")
                    || param.name.ends_with("_inout");
                let ctx_param = param.name.ends_with("_ctx") || param.name.ends_with("_context");
                if !tagged && !ctx_param {
                    bail!(
                        "extern {kind} `{}` pointer param `{}` must declare ownership transfer tag suffix (`_owned`, `_borrowed`, `_out`, `_inout`)",
                        symbol,
                        param.name
                    );
                }
                if !ctx_param && !has_len_pair(function, &param.name) {
                    bail!(
                        "extern {kind} `{}` pointer param `{}` must declare paired length parameter (`{}_len` or `len`)",
                        symbol,
                        param.name,
                        pointer_base_name(&param.name),
                    );
                }
            }
            if matches!(param.ty, ast::Type::Function { .. }) {
                let prev_is_anchor = function
                    .params
                    .iter()
                    .position(|candidate| candidate.name == param.name)
                    .and_then(|index| index.checked_sub(1))
                    .and_then(|index| function.params.get(index))
                    .is_some_and(|candidate| {
                        candidate.name.ends_with("_ctx") || candidate.name.ends_with("_context")
                    });
                let next_is_anchor = function
                    .params
                    .iter()
                    .position(|candidate| candidate.name == param.name)
                    .and_then(|index| function.params.get(index + 1))
                    .is_some_and(|candidate| {
                        candidate.name.ends_with("_ctx") || candidate.name.ends_with("_context")
                    });
                if !(prev_is_anchor || next_is_anchor) {
                    bail!(
                        "extern {kind} `{}` callback param `{}` requires adjacent `*_ctx` or `*_context` anchor",
                        symbol,
                        param.name
                    );
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ReprCLayout {
    name: String,
    kind: &'static str,
    size: usize,
    align: usize,
    fields: Vec<ReprCFieldLayout>,
    variants: Vec<ReprCVariantLayout>,
    storage: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct ReprCFieldLayout {
    name: String,
    ty: ast::Type,
    offset: usize,
    size: usize,
    align: usize,
}

#[derive(Debug, Clone)]
struct ReprCVariantLayout {
    name: String,
    value: u64,
}

fn collect_repr_c_layouts(module: &ast::Module) -> Result<Vec<ReprCLayout>> {
    let mut layouts = Vec::new();
    for item in &module.items {
        match item {
            ast::Item::Struct(item) if is_repr_c(item.repr.as_deref()) => {
                let mut offset = 0usize;
                let mut struct_align = 1usize;
                let mut fields = Vec::with_capacity(item.fields.len());
                for field in &item.fields {
                    let (size, align) = ffi_type_layout(&field.ty).ok_or_else(|| {
                        anyhow!(
                            "repr(C) struct `{}` field `{}` uses unsupported layout type `{}`",
                            item.name,
                            field.name,
                            field.ty
                        )
                    })?;
                    let field_offset = align_up(offset, align);
                    fields.push(ReprCFieldLayout {
                        name: field.name.clone(),
                        ty: field.ty.clone(),
                        offset: field_offset,
                        size,
                        align,
                    });
                    offset = field_offset + size;
                    struct_align = struct_align.max(align);
                }
                let size = align_up(offset, struct_align);
                layouts.push(ReprCLayout {
                    name: item.name.clone(),
                    kind: "struct",
                    size,
                    align: struct_align,
                    fields,
                    variants: Vec::new(),
                    storage: None,
                });
            }
            ast::Item::Enum(item) if is_repr_c(item.repr.as_deref()) => {
                if item
                    .variants
                    .iter()
                    .any(|variant| !variant.payload.is_empty())
                {
                    bail!(
                        "repr(C) enum `{}` has payload variants; only C-style fieldless enums are supported",
                        item.name
                    );
                }
                layouts.push(ReprCLayout {
                    name: item.name.clone(),
                    kind: "enum",
                    size: 4,
                    align: 4,
                    fields: Vec::new(),
                    variants: item
                        .variants
                        .iter()
                        .enumerate()
                        .map(|(index, variant)| ReprCVariantLayout {
                            name: variant.name.clone(),
                            value: index as u64,
                        })
                        .collect(),
                    storage: Some("int32_t"),
                });
            }
            _ => {}
        }
    }
    Ok(layouts)
}

fn is_repr_c(repr: Option<&str>) -> bool {
    repr.is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
}

fn abi_identity_fields() -> (String, String, String) {
    let target_triple = std::env::var("TARGET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}-unknown-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            )
        });
    let data_layout_descriptor = format!(
        "target={target_triple};endian={};ptr_width={};usize={};usize_align={}",
        if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        },
        std::mem::size_of::<usize>() * 8,
        std::mem::size_of::<usize>(),
        std::mem::align_of::<usize>()
    );
    let compiler_descriptor = ProcessCommand::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "rustc:unknown".to_string());
    (
        target_triple,
        sha256_hex(data_layout_descriptor.as_bytes()),
        sha256_hex(compiler_descriptor.as_bytes()),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize().as_slice())
}

fn ffi_type_layout(ty: &ast::Type) -> Option<(usize, usize)> {
    match ty {
        ast::Type::Void => Some((0, 1)),
        ast::Type::Bool => Some((1, 1)),
        ast::Type::Char => Some((4, 4)),
        ast::Type::ISize | ast::Type::USize => {
            Some((std::mem::size_of::<usize>(), std::mem::align_of::<usize>()))
        }
        ast::Type::Int { bits, .. } => {
            let bytes = (*bits as usize) / 8;
            Some((bytes.max(1), bytes.max(1)))
        }
        ast::Type::Float { bits } => {
            let bytes = (*bits as usize) / 8;
            Some((bytes.max(1), bytes.max(1)))
        }
        ast::Type::Ptr { .. } => {
            Some((std::mem::size_of::<usize>(), std::mem::align_of::<usize>()))
        }
        _ => None,
    }
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn detect_ffi_panic_boundary(
    exports: &[&ast::Function],
    manifest: Option<&manifest::Manifest>,
) -> Result<&'static str> {
    let project_default = manifest
        .and_then(|value| value.ffi.panic_boundary.as_deref())
        .filter(|mode| *mode == "abort" || *mode == "error");
    if let Some(mode) = project_default {
        return Ok(if mode == "error" { "error" } else { "abort" });
    }
    for function in exports {
        if let Some(mode) = function.ffi_panic.as_deref() {
            if mode == "abort" {
                return Ok("abort");
            }
            if mode == "error" {
                return Ok("error");
            }
        }
    }
    Ok("abort-or-translate")
}

fn pointer_base_name(name: &str) -> String {
    for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

fn has_len_pair(function: &ast::Function, pointer_param_name: &str) -> bool {
    let base = pointer_base_name(pointer_param_name);
    let expected = format!("{base}_len");
    function.params.iter().any(|candidate| {
        matches!(candidate.ty, ast::Type::USize)
            && (candidate.name == "len"
                || candidate.name == expected
                || candidate.name == format!("{base}_bytes"))
    })
}

fn is_i32_type(ty: &ast::Type) -> bool {
    matches!(
        ty,
        ast::Type::Int {
            signed: true,
            bits: 32
        }
    )
}

fn callback_typedef_for<'a>(
    ty: &ast::Type,
    callback_types: &'a [interop::CallbackTypeDef],
) -> Option<&'a str> {
    let key = ty.to_string();
    callback_types
        .iter()
        .find(|candidate| candidate.signature_key == key)
        .map(|candidate| candidate.typedef_name.as_str())
}

fn render_callback_type_defs(
    callback_types: &[interop::CallbackTypeDef],
    repr_c_aliases: &BTreeMap<String, String>,
) -> String {
    let mut out = String::new();
    for callback in callback_types {
        let ast::Type::Function { params, ret } = &callback.ty else {
            continue;
        };
        let rendered_params = if params.is_empty() {
            "void".to_string()
        } else {
            params
                .iter()
                .enumerate()
                .map(|(index, param)| {
                    format!(
                        "{} arg{}",
                        render_c_surface_type(param, repr_c_aliases, callback_types),
                        index
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "typedef {} (*{})({});\n",
            render_c_surface_type(ret.as_ref(), repr_c_aliases, callback_types),
            callback.typedef_name,
            rendered_params
        ));
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

fn render_c_surface_type(
    ty: &ast::Type,
    repr_c_aliases: &BTreeMap<String, String>,
    callback_types: &[interop::CallbackTypeDef],
) -> String {
    match ty {
        ast::Type::Function { .. } => callback_typedef_for(ty, callback_types)
            .map(str::to_string)
            .unwrap_or_else(|| "void*".to_string()),
        ast::Type::Named { name, .. } => repr_c_aliases
            .get(name)
            .cloned()
            .unwrap_or_else(|| sanitize_c_identifier(name)),
        ast::Type::Ptr { mutable, to } => {
            let rendered = render_c_surface_type(to, repr_c_aliases, callback_types);
            if *mutable {
                format!("{rendered}*")
            } else {
                format!("const {rendered}*")
            }
        }
        _ => to_c_type(ty),
    }
}

fn render_c_params(
    function: &ast::Function,
    repr_c_aliases: &BTreeMap<String, String>,
    callback_types: &[interop::CallbackTypeDef],
) -> String {
    let params = function
        .params
        .iter()
        .map(|param| {
            format!(
                "{} {}",
                render_c_surface_type(&param.ty, repr_c_aliases, callback_types),
                param.name
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    if params.is_empty() {
        "void".to_string()
    } else {
        params
    }
}

fn ffi_ownership_kind(name: &str) -> &'static str {
    if name.ends_with("_owned") {
        "owned"
    } else if name.ends_with("_out") {
        "out"
    } else if name.ends_with("_inout") {
        "inout"
    } else {
        "borrowed"
    }
}

fn ffi_param_contract(
    function: &ast::Function,
    param: &ast::Param,
    callback_types: &[interop::CallbackTypeDef],
) -> serde_json::Value {
    let mut lifetime_anchor = serde_json::Value::Null;
    let mut ownership = "value";
    let mut nullability = "n/a";
    let mut mutability = "const";
    let mut view = serde_json::Value::Null;
    let mut callback = serde_json::Value::Null;
    if let ast::Type::Ptr { mutable, .. } = &param.ty {
        ownership = ffi_ownership_kind(&param.name);
        nullability = if param.name.contains("_nullable") {
            "nullable"
        } else {
            "non_null"
        };
        mutability = if *mutable { "mut" } else { "const" };
        let base = pointer_base_name(&param.name);
        lifetime_anchor = serde_json::json!(format!("loan:{base}"));
        let len_name = format!("{base}_len");
        if function.params.iter().any(|p| p.name == len_name) {
            view = serde_json::json!({
                "kind": "ptr_len",
                "lengthParam": len_name,
            });
        } else if function.params.iter().any(|p| p.name == "len") {
            view = serde_json::json!({
                "kind": "ptr_len",
                "lengthParam": "len",
            });
        }
    } else if matches!(param.ty, ast::Type::Function { .. }) {
        ownership = "callback";
        nullability = "non_null";
        callback = serde_json::json!({
            "typedef": callback_typedef_for(&param.ty, callback_types).unwrap_or("unsupported_callback"),
            "signature": param.ty.to_string(),
        });
    }
    serde_json::json!({
        "ownership": ownership,
        "nullability": nullability,
        "mutability": mutability,
        "lifetimeAnchor": lifetime_anchor,
        "view": view,
        "callback": callback,
    })
}

fn ffi_return_contract(ty: &ast::Type) -> serde_json::Value {
    let (ownership, nullability, mutability) = match ty {
        ast::Type::Ptr { mutable, .. } => {
            ("owned", "non_null", if *mutable { "mut" } else { "const" })
        }
        _ => ("value", "n/a", "const"),
    };
    serde_json::json!({
        "ownership": ownership,
        "nullability": nullability,
        "mutability": mutability,
    })
}

fn ffi_callback_bindings(
    function: &ast::Function,
    callback_types: &[interop::CallbackTypeDef],
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for param in &function.params {
        if !matches!(param.ty, ast::Type::Function { .. }) {
            continue;
        }
        let base = param
            .name
            .trim_end_matches("_callback")
            .trim_end_matches("_cb")
            .trim_end_matches("_handler")
            .trim_end_matches("_fn");
        let context_name = function
            .params
            .iter()
            .find(|candidate| {
                candidate.name == format!("{base}_ctx")
                    || candidate.name == format!("{base}_context")
                    || candidate.name == "cb_ctx"
                    || candidate.name == "callback_ctx"
            })
            .map(|candidate| candidate.name.clone())
            .unwrap_or_else(|| "missing_ctx".to_string());
        out.push(serde_json::json!({
            "callbackParam": param.name,
            "contextParam": context_name,
            "bindingId": format!("cbctx:{base}"),
            "typedef": callback_typedef_for(&param.ty, callback_types).unwrap_or("unsupported_callback"),
            "signature": param.ty.to_string(),
            "obligation": "context_outlives_callback_registration",
        }));
    }
    out
}

fn ffi_async_contract(function: &ast::Function) -> serde_json::Value {
    if !function.is_async {
        return serde_json::Value::Null;
    }
    let symbol = ffi_symbol_name(function);
    serde_json::json!({
        "model": "async-handle-sync-start-v1",
        "startSymbol": format!("{}_async_start", symbol),
        "pollSymbol": format!("{}_async_poll", symbol),
        "awaitSymbol": format!("{}_async_await", symbol),
        "dropSymbol": format!("{}_async_drop", symbol),
        "resultType": to_c_type(&function.return_type),
        "startMode": "synchronous-execute-then-store",
    })
}

fn ffi_symbol_name(function: &ast::Function) -> &str {
    function
        .link_name
        .as_deref()
        .unwrap_or(function.name.as_str())
}

fn is_ffi_stable_type(ty: &ast::Type, repr_c_names: &BTreeSet<String>) -> bool {
    match ty {
        ast::Type::Never
        | ast::Type::Void
        | ast::Type::Bool
        | ast::Type::Char
        | ast::Type::Float { .. }
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. } => true,
        ast::Type::Ptr { to, .. } => is_ffi_stable_type(to, repr_c_names),
        ast::Type::Named { name, args } => args.is_empty() && repr_c_names.contains(name),
        ast::Type::Function { params, ret } => {
            params
                .iter()
                .all(|param| is_ffi_stable_type(param, repr_c_names))
                && is_ffi_stable_type(ret, repr_c_names)
        }
        ast::Type::BigInt
        | ast::Type::BigUint
        | ast::Type::Decimal128
        | ast::Type::Str
        | ast::Type::Bytes
        | ast::Type::Uuid
        | ast::Type::DynTrait(_)
        | ast::Type::Map { .. }
        | ast::Type::Set(_)
        | ast::Type::Deque(_)
        | ast::Type::Ring(_)
        | ast::Type::Slice(_)
        | ast::Type::Result { .. }
        | ast::Type::Option(_)
        | ast::Type::Vec(_)
        | ast::Type::Future(_)
        | ast::Type::Path
        | ast::Type::PathBuf
        | ast::Type::Url
        | ast::Type::SocketAddr
        | ast::Type::Duration
        | ast::Type::Instant
        | ast::Type::Decimal
        | ast::Type::DateTimeTz
        | ast::Type::ExitStatus
        | ast::Type::SimdVector(_)
        | ast::Type::SimdMask(_)
        | ast::Type::Tuple(_)
        | ast::Type::Ref { .. }
        | ast::Type::Array { .. }
        | ast::Type::TypeVar(_) => false,
    }
}

fn to_c_type(ty: &ast::Type) -> String {
    match ty {
        ast::Type::Ptr { mutable, to } => {
            if *mutable {
                format!("{}*", to_c_type(to))
            } else {
                format!("const {}*", to_c_type(to))
            }
        }
        ast::Type::Void => "void".to_string(),
        ast::Type::Bool => "bool".to_string(),
        ast::Type::ISize => "ssize_t".to_string(),
        ast::Type::USize => "size_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 8,
        } => "int8_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 16,
        } => "int16_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 32,
        } => "int32_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 64,
        } => "int64_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 128,
        } => "__int128_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 8,
        } => "uint8_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 16,
        } => "uint16_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 32,
        } => "uint32_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 64,
        } => "uint64_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 128,
        } => "__uint128_t".to_string(),
        ast::Type::Float { bits: 32 } => "float".to_string(),
        ast::Type::Float { bits: 64 } => "double".to_string(),
        ast::Type::Char => "uint32_t".to_string(),
        ast::Type::Str => "const char*".to_string(),
        ast::Type::Named { name, .. } => name.clone(),
        _ => "void*".to_string(),
    }
}

#[derive(Debug, Clone)]
struct RpcMethod {
    name: String,
}

fn parse_rpc_declarations(source: &str) -> Result<Vec<RpcMethod>> {
    let mut methods = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("rpc ") {
            continue;
        }
        let declaration = trimmed
            .strip_prefix("rpc ")
            .ok_or_else(|| anyhow!("invalid rpc declaration on line {}", line_index + 1))?;
        let open = declaration.find('(').ok_or_else(|| {
            anyhow!(
                "invalid rpc declaration on line {}: missing `(`",
                line_index + 1
            )
        })?;
        let close = declaration.rfind(')').ok_or_else(|| {
            anyhow!(
                "invalid rpc declaration on line {}: missing `)`",
                line_index + 1
            )
        })?;
        if close < open {
            bail!(
                "invalid rpc declaration on line {}: malformed arguments",
                line_index + 1
            );
        }

        let name = declaration[..open].trim();
        if name.is_empty() {
            bail!(
                "invalid rpc declaration on line {}: missing method name",
                line_index + 1
            );
        }
        let after = declaration[(close + 1)..].trim();
        let response = after
            .strip_prefix("->")
            .map(str::trim)
            .ok_or_else(|| {
                anyhow!(
                    "invalid rpc declaration on line {}: missing `->`",
                    line_index + 1
                )
            })?
            .trim_end_matches(';')
            .trim()
            .to_string();
        if response.is_empty() {
            bail!(
                "invalid rpc declaration on line {}: missing response type",
                line_index + 1
            );
        }

        methods.push(RpcMethod {
            name: name.to_string(),
        });
    }
    if methods.is_empty() {
        bail!("no `rpc` declarations found in source");
    }
    Ok(methods)
}

fn scenario_error(err: impl fmt::Display) -> anyhow::Error {
    anyhow!(err.to_string())
}

fn scenario_config() -> Result<fzscenario::Config> {
    let cwd = std::env::current_dir().context("failed to resolve current working directory")?;
    let config_path = cwd.join("fozzy.toml");
    fzscenario::Config::load_optional_checked(&config_path).map_err(scenario_error)
}

fn scenario_config_with_backends(host_backends: bool) -> Result<fzscenario::Config> {
    let mut config = scenario_config()?;
    if host_backends {
        config.proc_backend = fzscenario::ProcBackend::Host;
        config.fs_backend = fzscenario::FsBackend::Host;
        config.http_backend = fzscenario::HttpBackend::Host;
    }
    Ok(config)
}

fn scenario_memory_options(config: &fzscenario::Config) -> fzscenario::MemoryOptions {
    fzscenario::MemoryOptions {
        track: config.mem_track,
        limit_mb: config.mem_limit_mb,
        fail_after_allocs: config.mem_fail_after,
        fail_on_leak: config.fail_on_leak,
        leak_budget_bytes: config.leak_budget,
        fragmentation_seed: config.mem_fragmentation_seed,
        pressure_wave: config.mem_pressure_wave.clone(),
        artifacts: config.mem_artifacts,
    }
}

fn scenario_reporter(format: Format) -> fzscenario::Reporter {
    match format {
        Format::Text => fzscenario::Reporter::Pretty,
        Format::Json => fzscenario::Reporter::Json,
    }
}

fn parse_scenario_reporter(raw: &str) -> Result<fzscenario::Reporter> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pretty" => Ok(fzscenario::Reporter::Pretty),
        "json" => Ok(fzscenario::Reporter::Json),
        "junit" => Ok(fzscenario::Reporter::Junit),
        "html" => Ok(fzscenario::Reporter::Html),
        other => bail!("unsupported report format `{other}`"),
    }
}

fn parse_topology_profile(raw: &str) -> Result<fzscenario::TopologyProfile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "balanced" => Ok(fzscenario::TopologyProfile::Balanced),
        "pedantic" => Ok(fzscenario::TopologyProfile::Pedantic),
        "overkill" => Ok(fzscenario::TopologyProfile::Overkill),
        other => bail!("unsupported topology profile `{other}`"),
    }
}

fn scenario_exit_code(status: fzscenario::ExitStatus) -> i32 {
    match status {
        fzscenario::ExitStatus::Pass => 0,
        fzscenario::ExitStatus::Fail => 1,
        fzscenario::ExitStatus::Error => 2,
        fzscenario::ExitStatus::Timeout => 3,
        fzscenario::ExitStatus::Crash => 4,
    }
}

fn strict_checker_failure(summary: &fzscenario::RunSummary) -> bool {
    summary.status == fzscenario::ExitStatus::Pass
        && summary
            .findings
            .iter()
            .any(|finding| finding.kind == fzscenario::FindingKind::Checker)
}

fn render_value_output(value_format: Format, value: &impl Serialize) -> Result<String> {
    match value_format {
        Format::Text => Ok(serde_json::to_string_pretty(value)?),
        Format::Json => Ok(serde_json::to_string(value)?),
    }
}

fn render_report_show_output(
    format: Format,
    reporter: fzscenario::Reporter,
    value: serde_json::Value,
) -> Result<String> {
    match (format, reporter) {
        (Format::Text, fzscenario::Reporter::Pretty)
        | (Format::Text, fzscenario::Reporter::Junit)
        | (Format::Text, fzscenario::Reporter::Html) => Ok(value
            .get("content")
            .and_then(|content| content.as_str())
            .unwrap_or_default()
            .to_string()),
        _ => render_value_output(format, &value),
    }
}

fn native_usage_doc() -> serde_json::Value {
    serde_json::json!({
        "title": "FZ CLI usage",
        "items": [
            {
                "command": "fz map suites",
                "when": "Start production validation with hotspot coverage mapping.",
                "how": "fz map suites --root . --scenario-root tests --profile pedantic --json"
            },
            {
                "command": "fz doctor",
                "when": "Audit determinism and environment behavior for a scenario.",
                "how": "fz doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 123 --json"
            },
            {
                "command": "fz test",
                "when": "Run strict deterministic scenario suites or bridge native tests into scenario execution.",
                "how": "fz test tests/example.fozzy.json --det --strict-verify --json"
            },
            {
                "command": "fz run",
                "when": "Run a single scenario or native source target with production runtime checks.",
                "how": "fz run tests/example.fozzy.json --det --record artifacts/example.trace.fozzy --json"
            },
            {
                "command": "fz fuzz",
                "when": "Coverage-fuzz a scenario target natively through the local scenario engine.",
                "how": "fz fuzz tests/example.fozzy.json --json"
            },
            {
                "command": "fz explore",
                "when": "Explore distributed schedules deterministically.",
                "how": "fz explore tests/distributed.pass.fozzy.json --json"
            },
            {
                "command": "fz replay | shrink | ci",
                "when": "Validate recorded traces, replay them, shrink them, and run the CI bundle locally.",
                "how": "fz trace verify artifacts/example.trace.fozzy --strict --json && fz replay artifacts/example.trace.fozzy --json && fz ci artifacts/example.trace.fozzy --json"
            },
            {
                "command": "fz artifacts ls latest | fz report show latest",
                "when": "Inspect the most recent run artifacts and rendered report output.",
                "how": "fz artifacts ls latest --json && fz report show latest --format pretty"
            },
            {
                "command": "fz env | schema | validate",
                "when": "Inspect execution capabilities, authoring schema, and scenario validity.",
                "how": "fz env --json && fz schema --json && fz validate tests/example.fozzy.json --json"
            },
            {
                "command": "fz inspect surface | artifacts | embedding",
                "when": "Explain what is builtin vs `use core.*`, inspect emitted interop artifacts, and read the embedding contract without spelunking generated files.",
                "how": "fz inspect surface --json && fz inspect artifacts examples/fullstack --release --json && fz inspect embedding examples/fullstack --json"
            },
            {
                "command": "fz inspect stdlib <module>",
                "when": "Dump the embedded core stdlib source the compiler merges for `use core.*` facades and confirm it parses on the active toolchain.",
                "how": "fz inspect stdlib process --json"
            }
        ]
    })
}

fn native_usage_text() -> String {
    let items = native_usage_doc()
        .get("items")
        .and_then(|items| items.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = String::from("FZ CLI usage\n\n");
    for item in items {
        let command = item
            .get("command")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let when = item
            .get("when")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let how = item
            .get("how")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        out.push_str(&format!("{command}:\n  when: {when}\n  how:  {how}\n\n"));
    }
    out.trim_end().to_string()
}

fn render_scenario_run_result(
    format: Format,
    run: fzscenario::RunResult,
    strict: bool,
) -> Result<String> {
    let status = run.summary.status;
    let strict_failure = strict && strict_checker_failure(&run.summary);
    let rendered = match format {
        Format::Text => run.summary.pretty(),
        Format::Json => serde_json::to_string(&run.summary)?,
    };
    if status != fzscenario::ExitStatus::Pass || strict_failure {
        return Err(CommandFailure {
            exit_code: if strict_failure {
                1
            } else {
                scenario_exit_code(status)
            },
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

fn render_host_bridge_test_result(
    format: Format,
    source: &Path,
    scenario: &Path,
    prepare_trace_path: &Path,
    requested_record: Option<&Path>,
    run: fzscenario::RunResult,
    strict: bool,
) -> Result<String> {
    materialize_requested_bridge_record(requested_record, prepare_trace_path)?;
    let status = run.summary.status;
    let strict_failure = strict && strict_checker_failure(&run.summary);
    let recorded_trace = run.summary.identity.trace_path.clone();
    let rendered = match format {
        Format::Text => {
            let mut out = run.summary.pretty();
            out.push_str(&format!(
                "\nbridge_source={}\nbridge_scenario={}\nbridge_prepare_trace={}",
                source.display(),
                scenario.display(),
                prepare_trace_path.display()
            ));
            if let Some(recorded_trace) = &recorded_trace {
                out.push_str(&format!("\nbridge_recorded_trace={recorded_trace}"));
            }
            out
        }
        Format::Json => serde_json::to_string(&serde_json::json!({
            "bridge": {
                "source": source.display().to_string(),
                "scenario": scenario.display().to_string(),
                "prepareTrace": prepare_trace_path.display().to_string(),
                "recordedTrace": recorded_trace,
            },
            "summary": &run.summary,
        }))?,
    };
    if status != fzscenario::ExitStatus::Pass || strict_failure {
        return Err(CommandFailure {
            exit_code: if strict_failure {
                1
            } else {
                scenario_exit_code(status)
            },
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

fn render_host_bridge_run_result(
    format: Format,
    source: &Path,
    scenario: &Path,
    prepare_trace_path: &Path,
    requested_record: Option<&Path>,
    run: fzscenario::RunResult,
    strict: bool,
    deterministic_requested: bool,
) -> Result<String> {
    materialize_requested_bridge_record(requested_record, prepare_trace_path)?;
    let status = run.summary.status;
    let strict_failure = strict && strict_checker_failure(&run.summary);
    let recorded_trace = run.summary.identity.trace_path.clone();
    let rendered = match format {
        Format::Text => {
            let mut out = run.summary.pretty();
            out.push_str(&format!(
                "\nbridge_source={}\nbridge_scenario={}\nbridge_prepare_trace={}\nrouting=host-backed-scenario-bridge\ndeterministic_requested={}",
                source.display(),
                scenario.display(),
                prepare_trace_path.display(),
                deterministic_requested
            ));
            if let Some(recorded_trace) = &recorded_trace {
                out.push_str(&format!("\nbridge_recorded_trace={recorded_trace}"));
            }
            out
        }
        Format::Json => serde_json::to_string(&serde_json::json!({
            "bridge": {
                "source": source.display().to_string(),
                "scenario": scenario.display().to_string(),
                "prepareTrace": prepare_trace_path.display().to_string(),
                "recordedTrace": recorded_trace,
                "routing": "host-backed-scenario-bridge",
                "deterministicRequested": deterministic_requested,
            },
            "summary": &run.summary,
        }))?,
    };
    if status != fzscenario::ExitStatus::Pass || strict_failure {
        return Err(CommandFailure {
            exit_code: if strict_failure {
                1
            } else {
                scenario_exit_code(status)
            },
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

fn materialize_requested_bridge_record(
    requested_record: Option<&Path>,
    bridge_trace_path: &Path,
) -> Result<()> {
    let Some(requested_record) = requested_record else {
        return Ok(());
    };
    if requested_record == bridge_trace_path || requested_record.exists() {
        return Ok(());
    }
    let parent = requested_record.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed creating requested record directory: {}",
            parent.display()
        )
    })?;
    std::fs::copy(bridge_trace_path, requested_record).with_context(|| {
        format!(
            "failed materializing requested record {} from bridge trace {}",
            requested_record.display(),
            bridge_trace_path.display()
        )
    })?;
    Ok(())
}

fn render_doctor_report(
    format: Format,
    report: fzscenario::DoctorReport,
    strict: bool,
) -> Result<String> {
    let rendered = render_value_output(format, &report)?;
    if strict && !report.ok {
        return Err(CommandFailure {
            exit_code: 1,
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

fn render_trace_verify_report(
    format: Format,
    report: fzscenario::TraceVerifyReport,
    strict: bool,
) -> Result<String> {
    let rendered = render_value_output(format, &report)?;
    if !report.ok || (strict && !report.warnings.is_empty()) {
        return Err(CommandFailure {
            exit_code: 1,
            output: rendered,
        }
        .into());
    }
    Ok(rendered)
}

fn validate_scenario_file(path: &Path) -> Result<()> {
    let scenario_path = fzscenario::ScenarioPath::new(path.to_path_buf());
    let file = fzscenario::Scenario::load_file(&scenario_path).map_err(scenario_error)?;
    match file {
        fzscenario::ScenarioFile::Steps(_) => {
            let scenario = fzscenario::Scenario::load(&scenario_path).map_err(scenario_error)?;
            scenario.validate().map_err(scenario_error)?;
        }
        fzscenario::ScenarioFile::Suites(_) => {}
        fzscenario::ScenarioFile::Distributed(distributed) => {
            distributed.validate().map_err(scenario_error)?;
        }
    }
    Ok(())
}

fn scenario_fuzz(target: &Path, format: Format) -> Result<String> {
    ensure_exists(target)?;
    let config = scenario_config()?;
    let target_spec = format!("scenario:{}", target.display());
    let parsed_target: fzscenario::FuzzTarget = target_spec.parse().map_err(scenario_error)?;
    let corpus_name = target
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| {
            stem.chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
                .collect::<String>()
        })
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| "scenario".to_string());
    let corpus_dir = config.corpora_dir().join("native-fz").join(corpus_name);
    let run = fzscenario::fuzz(
        &config,
        &parsed_target,
        &fzscenario::FuzzOptions {
            det: true,
            mode: fzscenario::FuzzMode::Coverage,
            seed: Some(1),
            time: None,
            runs: Some(16),
            max_input_bytes: 4096,
            corpus_dir: Some(corpus_dir),
            mutator: None,
            shrink: false,
            record_trace_to: None,
            reporter: scenario_reporter(format),
            crash_only: false,
            minimize: false,
            record_collision: fzscenario::RecordCollisionPolicy::Append,
            profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
            memory: scenario_memory_options(&config),
        },
    )
    .map_err(scenario_error)?;
    render_scenario_run_result(format, run, true)
}

fn scenario_explore(target: &Path, format: Format) -> Result<String> {
    ensure_exists(target)?;
    let config = scenario_config()?;
    let run = fzscenario::explore(
        &config,
        fzscenario::ScenarioPath::new(target.to_path_buf()),
        &fzscenario::ExploreOptions {
            seed: Some(1),
            time: None,
            steps: Some(200),
            nodes: None,
            faults: None,
            schedule: fzscenario::ScheduleStrategy::CoverageGuided,
            checker: None,
            record_trace_to: None,
            shrink: true,
            minimize: true,
            reporter: scenario_reporter(format),
            record_collision: fzscenario::RecordCollisionPolicy::Append,
            profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
            memory: scenario_memory_options(&config),
        },
    )
    .map_err(scenario_error)?;
    render_scenario_run_result(format, run, true)
}

fn scenario_replay_like(
    command: &str,
    target: &Path,
    strict: bool,
    format: Format,
) -> Result<String> {
    let config = scenario_config()?;
    let replay_target = resolve_replay_target(target)?;
    match command {
        "replay" => {
            let run = fzscenario::replay_trace(
                &config,
                fzscenario::TracePath::new(replay_target.clone()),
                &fzscenario::ReplayOptions {
                    step: false,
                    until: None,
                    dump_events: false,
                    profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
                    reporter: scenario_reporter(format),
                },
            )
            .map_err(scenario_error)?;
            render_scenario_run_result(format, run, true)
        }
        "shrink" => {
            let result = fzscenario::shrink_trace(
                &config,
                fzscenario::TracePath::new(replay_target.clone()),
                &fzscenario::ShrinkOptions {
                    out_trace_path: None,
                    budget: Some(Duration::from_secs(30)),
                    aggressive: false,
                    minimize: fzscenario::ShrinkMinimize::All,
                },
            )
            .map_err(scenario_error)?;
            let status = result.result.summary.status;
            let rendered = match format {
                Format::Text => format!(
                    "{}\nout_trace={}",
                    result.result.summary.pretty(),
                    result.out_trace_path
                ),
                Format::Json => serde_json::to_string(&serde_json::json!({
                    "outTrace": &result.out_trace_path,
                    "summary": &result.result.summary,
                }))?,
            };
            if status != fzscenario::ExitStatus::Pass {
                return Err(CommandFailure {
                    exit_code: scenario_exit_code(status),
                    output: rendered,
                }
                .into());
            }
            Ok(rendered)
        }
        "ci" => {
            let report = fzscenario::ci_evaluate(
                &config,
                &fzscenario::CiOptions {
                    trace: replay_target.clone(),
                    flake_runs: Vec::new(),
                    flake_budget_pct: None,
                    perf_baseline: None,
                    max_p99_delta_pct: None,
                    strict,
                },
            )
            .map_err(scenario_error)?;
            let rendered = render_value_output(format, &report)?;
            if !report.ok {
                return Err(CommandFailure {
                    exit_code: 1,
                    output: rendered,
                }
                .into());
            }
            Ok(rendered)
        }
        other => bail!("unsupported replay-like command `{other}`"),
    }
}

pub(super) fn record_goal_trace_from_scenario(
    primary_scenario: &Path,
    goal_trace_path: &Path,
    seed: u64,
) -> Result<()> {
    let config = scenario_config()?;
    let run = fzscenario::run_scenario(
        &config,
        fzscenario::ScenarioPath::new(primary_scenario.to_path_buf()),
        &fzscenario::RunOptions {
            det: true,
            seed: Some(seed),
            timeout: None,
            reporter: fzscenario::Reporter::Json,
            record_trace_to: Some(goal_trace_path.to_path_buf()),
            filter: None,
            jobs: None,
            fail_fast: false,
            record_collision: fzscenario::RecordCollisionPolicy::Overwrite,
            profile_capture: fzscenario::ProfileCaptureLevel::Baseline,
            proc_backend: config.proc_backend,
            fs_backend: config.fs_backend,
            http_backend: config.http_backend,
            memory: scenario_memory_options(&config),
        },
    )
    .map_err(scenario_error)?;
    if run.summary.status != fzscenario::ExitStatus::Pass {
        return Err(CommandFailure {
            exit_code: scenario_exit_code(run.summary.status),
            output: run.summary.pretty(),
        }
        .into());
    }
    Ok(())
}

fn is_fozzy_scenario(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".fozzy.json"))
        .unwrap_or(false)
}

fn fmt_command(targets: &[PathBuf], check: bool, format: Format) -> Result<String> {
    let effective_targets = if targets.is_empty() {
        vec![std::env::current_dir().context("failed to resolve current working directory")?]
    } else {
        targets.to_vec()
    };
    for target in &effective_targets {
        ensure_exists(target)?;
    }
    let mut changed_files = Vec::<PathBuf>::new();
    for target in &effective_targets {
        changed_files.extend(format_source_target(target, check)?);
    }
    changed_files.sort();
    changed_files.dedup();

    let status = if check && !changed_files.is_empty() {
        "error"
    } else {
        "ok"
    };
    match format {
        Format::Text => {
            let mut out = render_text_fields(&[
                ("status", status.to_string()),
                ("mode", "fmt".to_string()),
                ("check", check.to_string()),
                ("targets", effective_targets.len().to_string()),
                ("changed_files", changed_files.len().to_string()),
            ]);
            for file in changed_files {
                out.push('\n');
                out.push_str(&format!("file: {}", file.display()));
            }
            Ok(out)
        }
        Format::Json => Ok(serde_json::json!({
            "status": status,
            "mode": "fmt",
            "check": check,
            "targets": effective_targets.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "changedFiles": changed_files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
struct DocItem {
    kind: String,
    name: String,
    signature: String,
    module: String,
    path: String,
    line: usize,
    docs: String,
}

#[derive(Debug, Clone)]
struct DocArtifacts {
    mode: String,
    output_format: String,
    item_count: usize,
    output_path: Option<PathBuf>,
    reference_path: Option<PathBuf>,
    rendered: String,
}

const DOC_REF_START: &str = "<!-- fozzydoc:api:start -->";
const DOC_REF_END: &str = "<!-- fozzydoc:api:end -->";

fn generate_doc_artifacts(
    path: &Path,
    output_format: &str,
    out: Option<&Path>,
    reference: Option<&Path>,
) -> Result<DocArtifacts> {
    let module_set = load_resolved_module_set(path)?;
    let mut items = Vec::<DocItem>::new();
    for module in &module_set.modules {
        items.extend(extract_doc_items_from_module(module));
    }
    items.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    let rendered = match output_format.trim().to_ascii_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&serde_json::json!({
            "schemaVersion": "fozzylang.doc.v1",
            "source": module_set.resolved.source_path.display().to_string(),
            "projectRoot": module_set.resolved.project_root.display().to_string(),
            "items": items,
        }))?,
        "markdown" | "md" => render_docs_markdown(&items),
        "html" => render_docs_html(&items),
        other => bail!("unsupported doc format `{other}` (expected json|html|markdown)"),
    };

    if let Some(reference_path) = reference {
        integrate_doc_reference(reference_path, &items)?;
    }
    if let Some(out_path) = out {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        std::fs::write(out_path, rendered.as_bytes())
            .with_context(|| format!("failed writing {}", out_path.display()))?;
    }

    Ok(DocArtifacts {
        mode: "doc-gen".to_string(),
        output_format: output_format.to_ascii_lowercase(),
        item_count: items.len(),
        output_path: out.map(Path::to_path_buf),
        reference_path: reference.map(Path::to_path_buf),
        rendered,
    })
}

fn render_doc_artifacts(format: Format, artifacts: DocArtifacts) -> String {
    match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", artifacts.mode),
            ("format", artifacts.output_format),
            ("items", artifacts.item_count.to_string()),
            (
                "out",
                artifacts
                    .output_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<stdout>".to_string()),
            ),
            (
                "reference",
                artifacts
                    .reference_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
            ),
        ]),
        Format::Json => serde_json::json!({
            "status": "ok",
            "mode": artifacts.mode,
            "format": artifacts.output_format,
            "items": artifacts.item_count,
            "outputPath": artifacts.output_path.map(|p| p.display().to_string()),
            "referencePath": artifacts.reference_path.map(|p| p.display().to_string()),
            "rendered": artifacts.rendered,
        })
        .to_string(),
    }
}

fn surface_always_available_groups() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "controlFlow",
            vec![
                "spawn",
                "spawn_ctx",
                "join",
                "yield",
                "checkpoint",
                "timeout",
                "cancel",
                "pulse",
            ],
        ),
        (
            "string",
            vec![
                "str.concat",
                "str.from_i32",
                "str.from_bool",
                "str.len",
                "str.slice",
                "str.trim",
                "str.upper_ascii",
                "str.lower_ascii",
            ],
        ),
        (
            "data",
            vec![
                "json.object",
                "json.array",
                "json.parse",
                "json.get_str",
                "list.new",
                "list.push",
                "map.new",
                "map.set",
            ],
        ),
        (
            "hostIntrinsic",
            vec![
                "env.get",
                "proc.argv_count",
                "proc.argv_get",
                "term.read_line",
                "term.write",
                "term.write_err",
                "route.match",
                "route.write_404",
                "route.write_405",
            ],
        ),
    ]
}

fn surface_core_modules() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("text", "stdlib facade", "no explicit capability"),
        ("io", "stdlib facade", "no explicit capability"),
        ("path", "stdlib facade", "no explicit capability"),
        (
            "process",
            "stdlib facade over `proc.*`",
            "no explicit capability",
        ),
        (
            "term",
            "stdlib facade over `term.*`",
            "no explicit capability",
        ),
        ("gpu", "stdlib facade", "implies `gpu`"),
        ("thread", "stdlib facade", "implies `thread`"),
        ("log", "stdlib facade", "implies `log`"),
        ("http", "stdlib facade", "implies `http`"),
        ("security", "stdlib facade", "implies `rng`"),
        (
            "env",
            "builtin namespace marker only",
            "always available as `env.*`",
        ),
        (
            "str",
            "builtin namespace marker only",
            "always available as `str.*`",
        ),
    ]
}

fn surface_capabilities() -> Vec<&'static str> {
    vec![
        "time", "rng", "fs", "http", "proc", "mem", "thread", "log", "error", "gpu",
    ]
}

fn render_surface_inspection(format: Format) -> String {
    let groups = surface_always_available_groups();
    let modules = surface_core_modules();
    let capabilities = surface_capabilities();
    match format {
        Format::Text => {
            let mut lines = vec![
                "status: ok".to_string(),
                "mode: inspect-surface".to_string(),
                "summary: builtins are always callable by namespace; `use core.*` imports facades and may imply capabilities".to_string(),
                "always_available:".to_string(),
            ];
            for (group, names) in groups {
                lines.push(format!("  {group}: {}", names.join(", ")));
            }
            lines.push("core_modules:".to_string());
            for (name, kind, behavior) in modules {
                lines.push(format!("  {name}: {kind}; {behavior}"));
            }
            lines.push(format!(
                "capability_gated: {}",
                capabilities.join(", ")
            ));
            lines.push("notes: `env.*`, `str.*`, `json.*`, `list.*`, `map.*`, and `route.*` are builtin namespaces; do not import them as ordinary modules".to_string());
            lines.join("\n")
        }
        Format::Json => serde_json::json!({
            "status": "ok",
            "mode": "inspect-surface",
            "summary": "Builtins are always callable by namespace. `use core.*` imports stdlib facades and may imply capability contracts.",
            "alwaysAvailable": groups.into_iter().map(|(group, names)| {
                serde_json::json!({
                    "group": group,
                    "names": names,
                })
            }).collect::<Vec<_>>(),
            "coreModules": modules.into_iter().map(|(name, kind, behavior)| {
                serde_json::json!({
                    "name": name,
                    "kind": kind,
                    "behavior": behavior,
                })
            }).collect::<Vec<_>>(),
            "capabilityGated": capabilities,
            "notes": [
                "`env.*`, `str.*`, `json.*`, `list.*`, `map.*`, and `route.*` are builtin namespaces.",
                "`use core.env;` and `use core.str;` are markers for the builtin namespaces rather than ordinary imported modules.",
            ],
        })
        .to_string(),
    }
}

fn inspect_stdlib_command(module: &str, format: Format) -> Result<String> {
    let Some(source) = embedded_core_stdlib_module_source(module) else {
        let available = surface_core_modules()
            .into_iter()
            .map(|(name, _, _)| name)
            .filter(|name| embedded_core_stdlib_module_source(name).is_some())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("unknown embedded core stdlib module `{module}` (available: {available})");
    };
    let parsed = parser::parse(source, module)
        .map_err(|diagnostics| anyhow!("{}", render_diagnostics_text(&diagnostics)))?;
    let line_count = source.lines().count();
    let source_path = format!("<embedded-core-stdlib:{module}>");
    match format {
        Format::Text => {
            let mut out = render_text_fields(&[
                ("status", "ok".to_string()),
                ("mode", "inspect-stdlib".to_string()),
                ("module", module.to_string()),
                ("source_path", source_path),
                ("lines", line_count.to_string()),
                ("nodes", parsed.items.len().to_string()),
                ("parse", "ok".to_string()),
            ]);
            out.push_str("\nsource:\n");
            out.push_str(source);
            Ok(out)
        }
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "inspect-stdlib",
            "module": module,
            "sourcePath": source_path,
            "lines": line_count,
            "nodes": parsed.items.len(),
            "parse": "ok",
            "source": source,
        })
        .to_string()),
    }
}

fn inspect_artifacts_command(
    path: &Path,
    release: bool,
    backend_override: Option<&str>,
    format: Format,
) -> Result<String> {
    let profile = if release {
        BuildProfile::Release
    } else {
        BuildProfile::Dev
    };
    let resolved = resolve_source(path)?;
    let native = compile_file_with_backend_with_root_guidance(path, profile, backend_override)?;
    let interop = if project_has_c_exports(path)? {
        let library =
            compile_library_with_backend_with_root_guidance(path, profile, backend_override)?;
        let headers = generate_c_headers(path, None)?;
        Some(finalize_build_interop_artifacts(path, &library, headers)?)
    } else {
        None
    };

    match format {
        Format::Text => {
            let mut fields = vec![
                ("status", "ok".to_string()),
                ("mode", "inspect-artifacts".to_string()),
                ("source", resolved.source_path.display().to_string()),
                ("project_root", resolved.project_root.display().to_string()),
                ("profile", if release { "release" } else { "dev" }.to_string()),
                (
                    "native_output",
                    native
                        .output
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
            ];
            if let Some(interop) = interop {
                fields.push((
                    "static_lib",
                    interop
                        .library
                        .static_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ));
                fields.push((
                    "shared_lib",
                    interop
                        .library
                        .shared_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ));
                fields.push(("header", interop.headers.path.display().to_string()));
                fields.push((
                    "abi_manifest",
                    interop.headers.abi_manifest.display().to_string(),
                ));
                fields.push((
                    "artifact_manifest",
                    interop.artifact_manifest.display().to_string(),
                ));
                fields.push(("exports", interop.export_symbols.join(", ")));
            } else {
                fields.push(("interop", "no C exports detected".to_string()));
            }
            Ok(render_text_fields(&fields))
        }
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "inspect-artifacts",
            "source": resolved.source_path.display().to_string(),
            "projectRoot": resolved.project_root.display().to_string(),
            "profile": if release { "release" } else { "dev" },
            "nativeOutput": native.output.as_ref().map(|path| path.display().to_string()),
            "interop": interop.map(|value| serde_json::json!({
                "staticLib": value.library.static_lib.as_ref().map(|path| path.display().to_string()),
                "sharedLib": value.library.shared_lib.as_ref().map(|path| path.display().to_string()),
                "header": value.headers.path.display().to_string(),
                "abiManifest": value.headers.abi_manifest.display().to_string(),
                "artifactManifest": value.artifact_manifest.display().to_string(),
                "exports": value.export_symbols,
            })),
        }).to_string()),
    }
}

fn inspect_embedding_command(path: &Path, format: Format) -> Result<String> {
    if !project_has_c_exports(path)? {
        bail!(
            "no exported `pubext c fn` surface found at `{}`; embedding inspection requires a C-exporting target",
            path.display()
        );
    }
    let resolved = resolve_source(path)?;
    let headers = generate_c_headers(path, None)?;
    let export_symbols = read_abi_export_symbols(&headers.abi_manifest)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "inspect-embedding".to_string()),
            ("source", resolved.source_path.display().to_string()),
            ("project_root", resolved.project_root.display().to_string()),
            ("header", headers.path.display().to_string()),
            ("abi_manifest", headers.abi_manifest.display().to_string()),
            ("exports", export_symbols.join(", ")),
            ("host_init", "mandatory before callback registration or exported host-driven calls".to_string()),
            ("host_shutdown", "marks runtime unavailable for further callback registration".to_string()),
            ("host_cleanup", "clears callback slots and transient host state; safe during teardown".to_string()),
            ("last_error", "read immediately after failing call via code/class/message trio".to_string()),
            ("concurrency", "callback registry is process-global and guarded by a mutex; lifecycle state is shared across threads".to_string()),
            ("callback_slots", "64 typed i32 callback slots are currently available".to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "inspect-embedding",
            "source": resolved.source_path.display().to_string(),
            "projectRoot": resolved.project_root.display().to_string(),
            "header": headers.path.display().to_string(),
            "abiManifest": headers.abi_manifest.display().to_string(),
            "exports": export_symbols,
            "lifecycle": {
                "init": {
                    "symbol": "fz_host_init",
                    "contract": "Call before registering callbacks or issuing exported calls from an in-process host.",
                },
                "shutdown": {
                    "symbol": "fz_host_shutdown",
                    "contract": "Marks the shared host runtime unavailable for further callback registration.",
                },
                "cleanup": {
                    "symbol": "fz_host_cleanup",
                    "contract": "Clears registered callbacks and transient host state during teardown.",
                },
            },
            "lastError": {
                "code": "fz_host_last_error_code",
                "class": "fz_host_last_error_class",
                "message": "fz_host_last_error_message",
                "contract": "Read immediately after a failing exported call or callback operation.",
            },
            "concurrency": {
                "scope": "process-global",
                "callbackRegistry": "mutex-guarded",
                "callbackSlots": 64,
            },
        }).to_string()),
    }
}

fn extract_doc_items_from_module(module: &ResolvedModuleSource) -> Vec<DocItem> {
    let mut items = Vec::new();
    let lines = module.source.lines().collect::<Vec<_>>();
    for item in &module.ast.items {
        if let Some(doc_item) = doc_item_from_ast(module, &lines, item) {
            items.push(doc_item);
        }
    }
    items
}

fn doc_item_from_ast(
    module: &ResolvedModuleSource,
    lines: &[&str],
    item: &ast::Item,
) -> Option<DocItem> {
    match item {
        ast::Item::Function(function) => {
            let line = find_function_decl_line(lines, function).unwrap_or(0);
            Some(DocItem {
                kind: doc_function_kind(function).to_string(),
                name: function.name.clone(),
                signature: render_doc_function_signature(function),
                module: module.module_name.clone(),
                path: module.path.display().to_string(),
                line,
                docs: docs_before_line(lines, line),
            })
        }
        ast::Item::Struct(item) => Some(doc_named_item(
            module,
            lines,
            "struct",
            &item.name,
            line_starts_with(lines, "struct", &item.name),
            render_named_signature("struct", &item.name),
        )),
        ast::Item::Enum(item) => Some(doc_named_item(
            module,
            lines,
            "enum",
            &item.name,
            line_starts_with(lines, "enum", &item.name),
            render_named_signature("enum", &item.name),
        )),
        ast::Item::Trait(item) => Some(doc_named_item(
            module,
            lines,
            "trait",
            &item.name,
            line_starts_with(lines, "trait", &item.name),
            render_named_signature("trait", &item.name),
        )),
        ast::Item::TypeAlias(item) => Some(doc_named_item(
            module,
            lines,
            "type",
            &item.name,
            line_starts_with(lines, "type", &item.name),
            format!("type {} = {};", item.name, item.ty),
        )),
        ast::Item::NewType(item) => Some(doc_named_item(
            module,
            lines,
            "newtype",
            &item.name,
            line_starts_with(lines, "newtype", &item.name),
            format!("newtype {} = {};", item.name, item.inner),
        )),
        ast::Item::Const(item) => Some(doc_named_item(
            module,
            lines,
            "const",
            &item.name,
            line_starts_with(lines, "const", &item.name),
            format!("const {}: {};", item.name, item.ty),
        )),
        ast::Item::Static(item) => Some(doc_named_item(
            module,
            lines,
            "static",
            &item.name,
            line_starts_with(lines, "static", &item.name),
            format!("static {}: {};", item.name, item.ty),
        )),
        ast::Item::Impl(item) => Some(doc_named_item(
            module,
            lines,
            "impl",
            &item.for_type.to_string(),
            line_starts_with(lines, "impl", &item.for_type.to_string()),
            render_impl_signature(item),
        )),
        ast::Item::Test(item) => Some(doc_named_item(
            module,
            lines,
            "test",
            &item.name,
            find_test_line(lines, &item.name),
            format!("test \"{}\"", item.name),
        )),
    }
}

fn doc_named_item(
    module: &ResolvedModuleSource,
    lines: &[&str],
    kind: &str,
    name: &str,
    line: Option<usize>,
    signature: String,
) -> DocItem {
    let line = line.unwrap_or(0);
    DocItem {
        kind: kind.to_string(),
        name: name.to_string(),
        signature,
        module: module.module_name.clone(),
        path: module.path.display().to_string(),
        line,
        docs: docs_before_line(lines, line),
    }
}

fn doc_function_kind(function: &ast::Function) -> &'static str {
    if function.is_extern && function.abi.as_deref() == Some("rpc") {
        "rpc"
    } else if function.is_pubext && function.abi.as_deref() == Some("c") {
        "ffi-export"
    } else if function.is_extern && function.abi.as_deref() == Some("c") {
        "ffi-import"
    } else if function.is_unsafe {
        "unsafe-fn"
    } else {
        "fn"
    }
}

fn render_doc_function_signature(function: &ast::Function) -> String {
    let params = function
        .params
        .iter()
        .map(|param| format!("{}: {}", param.name, param.ty))
        .collect::<Vec<_>>()
        .join(", ");
    if function.is_extern && function.abi.as_deref() == Some("rpc") {
        return format!(
            "rpc {}({}) -> {};",
            function.name, params, function.return_type
        );
    }
    let mut signature = String::new();
    if function.is_pubext {
        signature.push_str("pubext ");
    } else if function.is_pub {
        signature.push_str("pub ");
    }
    if function.is_async {
        signature.push_str("async ");
    }
    if function.is_extern && function.abi.as_deref() == Some("c") && !function.is_pubext {
        signature.push_str("ext ");
    }
    if function.is_unsafe {
        signature.push_str("unsafe ");
    }
    if function.is_extern {
        signature.push_str("c fn ");
    } else {
        signature.push_str("fn ");
    }
    signature.push_str(&function.name);
    signature.push('(');
    signature.push_str(&params);
    signature.push(')');
    if !matches!(function.return_type, ast::Type::Void) {
        signature.push_str(" -> ");
        signature.push_str(&function.return_type.to_string());
    }
    if function.body.is_empty() {
        signature.push(';');
    }
    signature
}

fn render_named_signature(kind: &str, name: &str) -> String {
    format!("{kind} {name}")
}

fn render_impl_signature(item: &ast::Impl) -> String {
    match &item.trait_name {
        Some(trait_name) => format!("impl {} for {}", trait_name, item.for_type),
        None => format!("impl {}", item.for_type),
    }
}

fn line_starts_with(lines: &[&str], keyword: &str, name: &str) -> Option<usize> {
    lines
        .iter()
        .position(|line| {
            let line = strip_leading_attributes_inline(line);
            line.starts_with(&format!("{keyword} {name}"))
                || line.starts_with(&format!("pub {keyword} {name}"))
                || (keyword == "static" && line.starts_with(&format!("static mut {name}")))
        })
        .map(|idx| idx + 1)
}

fn find_test_line(lines: &[&str], name: &str) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.trim_start().starts_with(&format!("test \"{name}\"")))
        .map(|idx| idx + 1)
}

fn docs_before_line(lines: &[&str], line: usize) -> String {
    if line <= 1 || line > lines.len() {
        return String::new();
    }
    let mut cursor = line - 1;
    while cursor > 0 && lines[cursor - 1].trim().is_empty() {
        cursor -= 1;
    }
    if cursor == 0 {
        return String::new();
    }
    if lines[cursor - 1].trim_start().starts_with("///") {
        let mut docs = Vec::new();
        let mut idx = cursor - 1;
        loop {
            let line = lines[idx].trim_start();
            if let Some(doc) = line.strip_prefix("///") {
                docs.push(doc.trim().to_string());
            } else {
                break;
            }
            if idx == 0 {
                break;
            }
            idx -= 1;
        }
        docs.reverse();
        return docs.join("\n");
    }
    if lines[cursor - 1].trim_end().ends_with("*/") {
        let mut docs = Vec::new();
        let mut idx = cursor - 1;
        loop {
            let line = lines[idx].trim();
            let cleaned = line
                .trim_end_matches("*/")
                .trim_start_matches("/**")
                .trim_start_matches('*')
                .trim();
            if !cleaned.is_empty() {
                docs.push(cleaned.to_string());
            }
            if line.contains("/**") || idx == 0 {
                break;
            }
            idx -= 1;
        }
        docs.reverse();
        return docs.join("\n");
    }
    String::new()
}

fn render_docs_markdown(items: &[DocItem]) -> String {
    if items.is_empty() {
        return "# API Documentation\n\n_No documented items found._\n".to_string();
    }
    let mut out = String::from("# API Documentation\n\n");
    for item in items {
        out.push_str(&format!(
            "## `{}` `{}`\n\n- module: `{}`\n- path: `{}`:{}\n- signature: `{}`\n\n",
            item.kind, item.name, item.module, item.path, item.line, item.signature
        ));
        if item.docs.is_empty() {
            out.push_str("_No docs provided._\n\n");
        } else {
            out.push_str(&format!("{}\n\n", item.docs));
        }
    }
    out
}

fn render_docs_html(items: &[DocItem]) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>fz doc</title></head><body>",
    );
    out.push_str("<h1>API Documentation</h1>");
    if items.is_empty() {
        out.push_str("<p><em>No documented items found.</em></p>");
    } else {
        for item in items {
            out.push_str(&format!(
                "<section><h2><code>{}</code> <code>{}</code></h2><ul><li>module: <code>{}</code></li><li>path: <code>{}:{}</code></li><li>signature: <code>{}</code></li></ul><pre>{}</pre></section>",
                html_escape(&item.kind),
                html_escape(&item.name),
                html_escape(&item.module),
                html_escape(&item.path),
                item.line,
                html_escape(&item.signature),
                html_escape(&item.docs),
            ));
        }
    }
    out.push_str("</body></html>");
    out
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn integrate_doc_reference(reference_path: &Path, items: &[DocItem]) -> Result<()> {
    let source = std::fs::read_to_string(reference_path)
        .with_context(|| format!("failed reading {}", reference_path.display()))?;
    let start = source
        .find(DOC_REF_START)
        .ok_or_else(|| anyhow!("reference marker missing: {}", DOC_REF_START))?;
    let end = source
        .find(DOC_REF_END)
        .ok_or_else(|| anyhow!("reference marker missing: {}", DOC_REF_END))?;
    if end <= start {
        bail!(
            "invalid reference markers ordering in {}",
            reference_path.display()
        );
    }
    let replacement = format!(
        "{DOC_REF_START}\n\n{}\n{DOC_REF_END}",
        render_docs_markdown(items).trim_end()
    );
    let mut updated = String::new();
    updated.push_str(&source[..start]);
    updated.push_str(&replacement);
    updated.push_str(&source[(end + DOC_REF_END.len())..]);
    std::fs::write(reference_path, updated.as_bytes())
        .with_context(|| format!("failed writing {}", reference_path.display()))?;
    Ok(())
}

fn format_source_file(path: &Path) -> Result<bool> {
    let original = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading file for formatting: {}", path.display()))?;
    let formatted = format_source(&original);

    if formatted != original {
        std::fs::write(path, formatted)
            .with_context(|| format!("failed writing formatted file: {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn format_source_target(path: &Path, check: bool) -> Result<Vec<PathBuf>> {
    let mut changed = Vec::<PathBuf>::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path).with_context(|| {
            format!(
                "failed reading directory for formatting: {}",
                path.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed reading directory entry for formatting: {}",
                    path.display()
                )
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                changed.extend(format_source_target(&entry_path, check)?);
                continue;
            }
            if entry_path.is_file()
                && is_fzy_source_path(&entry_path)
                && (if check {
                    let original = std::fs::read_to_string(&entry_path).with_context(|| {
                        format!(
                            "failed reading file for formatting: {}",
                            entry_path.display()
                        )
                    })?;
                    format_source(&original) != original
                } else {
                    format_source_file(&entry_path)?
                })
            {
                changed.push(entry_path);
            }
        }
        return Ok(changed);
    }

    if !is_fzy_source_path(path) {
        return Ok(changed);
    }
    if check {
        let original = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading file for formatting: {}", path.display()))?;
        if format_source(&original) != original {
            changed.push(path.to_path_buf());
        }
        return Ok(changed);
    }
    if format_source_file(path)? {
        changed.push(path.to_path_buf());
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use super::*;

    fn run_check_text(source: &str, suffix: &str) -> String {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-diag-{suffix}-{unique}.fzy"));
        std::fs::write(&path, source).expect("source should be written");
        let output = run(Command::Check { path: path.clone() }, Format::Text)
            .expect("check command should run");
        let _ = std::fs::remove_file(path);
        output
    }

    #[test]
    fn version_command_reports_identity_and_compatibility() {
        let output = run(Command::Version, Format::Text).expect("version command should run");
        assert!(output.contains("version:"));
        assert!(output.contains("trace_schema_version:"));
    }

    #[test]
    fn version_command_json_includes_compatibility() {
        let output = run(Command::Version, Format::Json).expect("version command should run");
        let value: serde_json::Value = serde_json::from_str(&output).expect("json should parse");
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            value["compatibility"]["traceSchemaVersion"],
            "fozzy-trace.v4"
        );
    }

    #[test]
    fn inspect_stdlib_process_reports_embedded_source() {
        let output = run(
            Command::InspectStdlib {
                module: "process".to_string(),
            },
            Format::Json,
        )
        .expect("inspect stdlib should run");
        let value: serde_json::Value = serde_json::from_str(&output).expect("json should parse");
        assert_eq!(value["module"], "process");
        assert_eq!(value["parse"], "ok");
        assert!(value["source"]
            .as_str()
            .is_some_and(|source| source.contains("fn argv_or")));
    }

    #[test]
    fn detects_scenario_paths() {
        assert!(is_fozzy_scenario(Path::new("tests/example.fozzy.json")));
        assert!(!is_fozzy_scenario(Path::new("examples/main.fzy")));
    }

    #[test]
    fn parity_and_equivalence_cover_primitive_control_flow_fixture() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/primitive_parity/main.fzy");
        let parity = parity_command(&source, 4242, Format::Json).expect("parity should run");
        let parity_json: serde_json::Value =
            serde_json::from_str(&parity).expect("parity json should parse");
        assert_eq!(parity_json["ok"], true);
        assert_eq!(parity_json["kind"], "executable");
        assert_eq!(parity_json["checks"]["sameExitCode"], true);
        assert_eq!(parity_json["checks"]["sameStdout"], true);
        assert_eq!(parity_json["checks"]["sameStderr"], true);
        assert_eq!(parity_json["checks"]["sameVerifierResult"], true);
        assert!(parity_json["backendResults"]["llvm"]["exitCode"].is_number());
        assert!(parity_json["backendResults"]["cranelift"]["exitCode"].is_number());
        assert_eq!(
            parity_json["backendCapabilities"]["cranelift"]["unsupported"][0]["feature"],
            "async_c_export_surface"
        );

        let equivalence =
            equivalence_command(&source, 4242, Format::Json).expect("equivalence should run");
        let equivalence_json: serde_json::Value =
            serde_json::from_str(&equivalence).expect("equivalence json should parse");
        assert_eq!(equivalence_json["ok"], true);
    }

    #[test]
    fn parity_command_covers_library_exports_across_backends() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-parity-lib-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"parity_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"parity_lib\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n\n#[ffi_panic(abort)]\npubext c fn mul(left: i32, right: i32) -> i32 {\n    return left * right\n}\n",
        )
        .expect("source should be written");

        let parity = parity_command(&root, 7, Format::Json).expect("library parity should run");
        let parity_json: serde_json::Value =
            serde_json::from_str(&parity).expect("parity json should parse");
        assert_eq!(parity_json["ok"], true);
        assert_eq!(parity_json["kind"], "library");
        assert_eq!(parity_json["checks"]["sameStaticExports"], true);
        assert_eq!(parity_json["checks"]["sameSharedExports"], true);
        assert!(parity_json["backendResults"]["llvm"]["staticExports"].is_array());
        assert!(parity_json["backendResults"]["cranelift"]["sharedExports"].is_array());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_and_verify_accept_lib_only_project_roots() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-check-lib-only-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"check_lib_only\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"check_lib_only\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "pub fn helper(value: i32) -> i32 {\n    return value + 1\n}\n",
        )
        .expect("source should be written");

        let check = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("check should succeed for lib-only project");
        let check_json: serde_json::Value =
            serde_json::from_str(&check).expect("check output should parse");
        assert_eq!(check_json["errors"].as_u64(), Some(0));
        assert_eq!(check_json["module"].as_str(), Some("lib"));

        let verify = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should succeed for lib-only project");
        let verify_json: serde_json::Value =
            serde_json::from_str(&verify).expect("verify output should parse");
        assert_eq!(verify_json["errors"].as_u64(), Some(0));
        assert_eq!(verify_json["module"].as_str(), Some("lib"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parity_canary_builds_fzweb_project_with_both_backends() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frameworklib/fzweb");
        let parity = parity_command(&project, 11, Format::Json).expect("fzweb parity should run");
        let parity_json: serde_json::Value =
            serde_json::from_str(&parity).expect("parity json should parse");
        assert_eq!(parity_json["ok"], true);
        assert_eq!(parity_json["kind"], "executable");
        assert_eq!(parity_json["checks"]["sameBuildStatus"], true);
        assert_eq!(parity_json["checks"]["sameVerifierResult"], true);
        assert_eq!(parity_json["checks"]["sameRuntimeBehavior"], true);
    }

    #[test]
    fn formatter_rewrites_trailing_whitespace() {
        let file_name = format!(
            "fozzylang-fmt-{}.fzy",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() {   \n\n\n  return 0   \n}   ")
            .expect("temp source should be written");

        let changed = format_source_file(&path).expect("formatter should run");
        assert!(changed);
        let content = std::fs::read_to_string(&path).expect("formatted file should be readable");
        assert!(!content.contains("   \n"));
        assert!(content.ends_with('\n'));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn formatter_accepts_directory_targets() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-fmt-dir-{suffix}"));
        std::fs::create_dir_all(root.join("nested")).expect("directory should be created");
        let first = root.join("main.fzy");
        let second = root.join("nested/lib.fzy");
        std::fs::write(&first, "fn main() -> i32 {   \n    return 0\n}\n")
            .expect("first source should be written");
        std::fs::write(&second, "fn helper() -> i32 {   \n    return 0\n}\n")
            .expect("second source should be written");

        let changed = format_source_target(&root, false).expect("directory format should succeed");
        assert_eq!(changed.len(), 2);
        let first_content = std::fs::read_to_string(&first).expect("first source should be read");
        let second_content =
            std::fs::read_to_string(&second).expect("second source should be read");
        assert!(!first_content.contains("   \n"));
        assert!(!second_content.contains("   \n"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_unsafe_uses_semantic_calls_not_lexical_substrings() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-audit-semantic-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let note: str = \"unsafe(\\\"fake\\\")\"\n    // unsafe(\"comment\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::AuditUnsafe {
                path: source.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect("audit should succeed");
        assert!(output.contains("\"entries\":[]"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn audit_unsafe_generates_contract_for_unsafe_block() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-audit-missing-reason-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    unsafe {\n        return 0\n    }\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::AuditUnsafe {
                path: source.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect("audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("unsafe audit should emit json");
        assert_eq!(payload["missingContractCount"].as_u64(), Some(0));
        assert_eq!(payload["invalidOwnerIdCount"].as_u64(), Some(0));
        assert_eq!(payload["strictUnsafeAudit"].as_bool(), Some(true));
        let entries = payload["entries"]
            .as_array()
            .expect("entries should be an array");
        assert!(!entries.is_empty());
        let block = entries
            .iter()
            .find(|entry| entry["kind"] == "unsafe_block")
            .expect("unsafe block entry should exist");
        assert_eq!(block["line"].as_u64(), Some(2));
        assert_eq!(block["owner_id"].as_str(), Some("owner::main::scope_root"));
        let docs_markdown = payload["docsMarkdown"]
            .as_str()
            .expect("markdown artifact should be reported");
        let docs = std::fs::read_to_string(docs_markdown).expect("markdown artifact should exist");
        assert!(docs.contains("Owner ID"));
        assert!(docs.contains("owner::main::scope_root"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn audit_unsafe_collects_generated_contract_from_semantic_call() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-audit-reasoned-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn lang_id(v: i32) -> i32 {\n    return v\n}\nunsafe fn lang_unsafe_id(v: i32) -> i32 {\n    return v\n}\nfn main() -> i32 {\n    let routed = lang_id(7)\n    discard lang_unsafe_id\n    unsafe {\n        discard lang_id(routed)\n    }\n    return routed\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::AuditUnsafe {
                path: source.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect("audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("unsafe audit should emit json");
        assert_eq!(payload["missingContractCount"].as_u64(), Some(0));
        assert_eq!(payload["invalidOwnerIdCount"].as_u64(), Some(0));
        assert_eq!(payload["strictUnsafeAudit"].as_bool(), Some(true));
        let entries = payload["entries"]
            .as_array()
            .expect("entries should be an array");
        assert!(entries
            .iter()
            .all(|entry| entry["line"].as_u64().unwrap_or(0) > 0));
        assert!(entries.iter().any(|entry| {
            entry["kind"] == "unsafe_fn"
                && entry["owner_id"].as_str() == Some("owner::lang_unsafe_id::v")
        }));
        assert!(entries.iter().any(|entry| {
            entry["kind"] == "unsafe_block"
                && entry["owner_id"].as_str() == Some("owner::main::scope_root")
        }));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn audit_unsafe_fails_for_callsite_outside_unsafe_under_strict_policy() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-unsafe-violation-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_unsafe_violation\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_unsafe_violation\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "unsafe fn risky(v: i32) -> i32 {\n    return v\n}\n\nfn main() -> i32 {\n    return risky(7)\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::AuditUnsafe {
                path: root.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect_err("strict unsafe audit should fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("strict unsafe audit failed"));
        assert!(rendered.contains("context_violations=1"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_memory_emits_strict_artifact_paths() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-memory-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_memory\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_memory\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let p = alloc(16)\n    defer free(p)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::AuditMemory { path: root.clone() }, Format::Json)
            .expect("memory audit should succeed");
        assert!(output.contains("\"mode\":\"memory-audit\""));
        assert!(output.contains("\"profile\":\"strict\""));
        assert!(output.contains("\"owners\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_memory_includes_path_dependency_library_functions() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-memory-dep-{suffix}"));
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_memory_dep\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_memory_dep\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use util;\nfn main() -> i32 {\n    let score = util.score()\n    if score == 7 {\n        return 0\n    }\n    return 91\n}\n",
        )
        .expect("source should be written");
        std::fs::write(
            dep_dir.join("fozzy.toml"),
            "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"util\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("dep manifest should be written");
        std::fs::write(
            dep_dir.join("src/lib.fzy"),
            "pub fn score() -> i32 {\n    return 7\n}\n",
        )
        .expect("dep lib source should be written");

        let output = run(Command::AuditMemory { path: root.clone() }, Format::Json)
            .expect("memory audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("memory audit should emit json");
        let function_names = payload["report"]["functions"]
            .as_array()
            .expect("report functions should be present")
            .iter()
            .filter_map(|value| value["name"].as_str())
            .collect::<Vec<_>>();
        assert!(function_names.contains(&"util.score"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_ffi_emits_import_and_export_inventory() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-ffi-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_ffi\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_ffi\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "#[repr(C)]\nstruct Packet {\n    value: i32,\n}\n\next unsafe c fn host_apply(cb_ctx: *mut u8, cb: fn(i32) -> i32, buf_borrowed: *u8, buf_len: usize) -> *u8;\n#[ffi_panic(abort)]\npubext c fn dispatch(packet: Packet, out_owned: *u8, out_len: usize) -> Packet {\n    discard host_apply\n    discard out_owned\n    discard out_len\n    return packet\n}\n\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::AuditFfi { path: root.clone() }, Format::Json)
            .expect("ffi audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("ffi audit should emit json");
        assert_eq!(payload["mode"].as_str(), Some("ffi-audit"));
        assert_eq!(payload["imports"].as_u64(), Some(1));
        assert_eq!(payload["exports"].as_u64(), Some(1));
        assert_eq!(payload["pointerContractViolationCount"].as_u64(), Some(0));
        assert_eq!(
            payload["callbackContextAnchorViolationCount"].as_u64(),
            Some(0)
        );
        assert_eq!(payload["asyncImportViolationCount"].as_u64(), Some(0));
        assert_eq!(payload["missingPanicBoundaryCount"].as_u64(), Some(0));
        let report = &payload["report"];
        assert_eq!(
            report["schemaVersion"].as_str(),
            Some("fozzylang.ffi_report.v2")
        );
        let import = report["imports"]
            .as_array()
            .and_then(|items| items.first())
            .expect("one import should be present");
        assert_eq!(import["name"].as_str(), Some("host_apply"));
        assert_eq!(import["pointerContractOk"].as_bool(), Some(true));
        assert_eq!(import["callbackContextAnchorOk"].as_bool(), Some(true));
        assert_eq!(import["ffiStableOk"].as_bool(), Some(true));
        let export = report["exports"]
            .as_array()
            .and_then(|items| items.first())
            .expect("one export should be present");
        assert_eq!(export["name"].as_str(), Some("dispatch"));
        assert_eq!(export["panicBoundaryDeclared"].as_bool(), Some(true));
        assert_eq!(export["ffiStableOk"].as_bool(), Some(true));
        let markdown_path = payload["markdown"]
            .as_str()
            .expect("markdown path should be reported");
        let markdown =
            std::fs::read_to_string(markdown_path).expect("ffi markdown artifact should exist");
        assert!(markdown.contains("pointer_contract_ok=true"));
        assert!(markdown.contains("panic_boundary_declared=true"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_ffi_fails_for_missing_pointer_contract_metadata() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-ffi-invalid-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_ffi_invalid\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_ffi_invalid\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "ext unsafe c fn host_touch(buf: *u8, len: usize) -> i32;\nfn main() -> i32 {\n    discard host_touch\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = run(Command::AuditFfi { path: root.clone() }, Format::Json)
            .expect_err("ffi audit should fail when pointer contracts are invalid");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("strict safety artifact generation failed")
                || rendered.contains("pointer parameters require ownership suffix")
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_unsafe_non_project_root_reports_target_guidance() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-root-guidance-{suffix}"));
        let nested = root.join("app");
        let nested_src = nested.join("src");
        std::fs::create_dir_all(&nested_src).expect("nested project tree should be created");
        std::fs::write(
            nested.join("fozzy.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"app\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            nested_src.join("main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let err = run(
            Command::AuditUnsafe {
                path: root.clone(),
                workspace: false,
            },
            Format::Text,
        )
        .expect_err("audit should fail for non-project root path");
        let msg = err.to_string();
        assert!(msg.contains("not a Fozzy project root"));
        assert!(msg.contains("detected nested project(s)"));
        assert!(msg.contains(&nested.display().to_string()));
        assert!(msg.contains("fz audit unsafe <project-path>"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn headers_command_generates_c_header_for_exports() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.h"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32;\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        assert!(output.contains("mode: headers"));
        assert!(output.contains("abi_manifest:"));
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("int32_t add(int32_t left, int32_t right);"));
        assert!(header_text.contains("int32_t fz_host_init(void);"));
        assert!(header_text.contains("int32_t fz_host_last_error_code(void);"));
        assert!(header_text.contains("const char* fz_host_last_error_message(void);"));
        assert!(header_text.contains("fz_host_register_callback_i32"));
        let abi_path = header.with_extension("abi.json");
        assert!(abi_path.exists());

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn headers_command_generates_async_export_handle_api() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-async-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-async-{suffix}.h"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext async c fn flush(code: i32) -> i32 {\n    return code\n}\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("typedef uint64_t fz_async_handle_t;"));
        assert!(header_text
            .contains("int32_t flush_async_start(int32_t code, fz_async_handle_t* handle_out);"));
        assert!(header_text
            .contains("int32_t flush_async_poll(fz_async_handle_t handle, int32_t* done_out);"));
        assert!(header_text
            .contains("int32_t flush_async_await(fz_async_handle_t handle, int32_t* result_out);"));
        assert!(header_text.contains("int32_t flush_async_drop(fz_async_handle_t handle);"));
        assert!(!header_text.contains("int32_t flush(int32_t code);"));

        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        assert!(abi_text.contains("\"async\": true"));
        assert!(abi_text.contains("\"execution\": \"async-handle-sync-start-v1\""));
        assert!(abi_text.contains("\"startSymbol\": \"flush_async_start\""));
        assert!(abi_text.contains("\"startMode\": \"synchronous-execute-then-store\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn headers_command_rejects_async_export_without_i32_return() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-async-ret-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext async c fn flush(code: i32) -> i64 {\n    return code\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::Headers {
                path: source.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers command should reject non-i32 async return");
        assert!(error.to_string().contains("must return `i32`"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn headers_command_maps_pointer_sized_ints_to_size_t_semantics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-psize-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-psize-{suffix}.h"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn span(len: usize, delta: isize) -> usize;\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("size_t span(size_t len, ssize_t delta);"));

        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        assert!(abi_text.contains("\"fzy\": \"usize\""));
        assert!(abi_text.contains("\"fzy\": \"isize\""));
        assert!(abi_text.contains("\"c\": \"size_t\""));
        assert!(abi_text.contains("\"c\": \"ssize_t\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn headers_command_rejects_pointer_without_length_contract() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-nolen-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn write(buf_borrowed: *u8) -> i32;\n",
        )
        .expect("source should be written");
        let error = run(
            Command::Headers {
                path: source.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers command should reject pointer without len");
        assert!(error.to_string().contains("paired length parameter"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn headers_command_emits_typed_callback_typedefs_and_import_contracts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-callback-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-callback-{suffix}.h"));
        std::fs::write(
            &source,
            "ext unsafe c fn host_apply(cb: fn(i32) -> i32, cb_ctx: *mut u8, buf_borrowed: *u8, buf_len: usize) -> i32;\n#[ffi_panic(abort)]\npubext c fn run(cb: fn(i32) -> i32, cb_ctx: *mut u8, value: i32) -> i32;\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("typedef int32_t (*fz_callback_sig0_v0)(int32_t arg0);"));
        assert!(header_text.contains("int32_t run(fz_callback_sig0_v0 cb,"));
        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        assert!(abi_text.contains("\"imports\""));
        assert!(abi_text.contains("\"callbackAbi\": \"signature-typed-v1\""));
        assert!(abi_text.contains("\"signature\": \"fn(i32) -> i32\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn check_rejects_pointer_like_extern_c_import_without_pointer_contract_suffix() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-extern-c-contract-missing-{suffix}.fzy"));
        std::fs::write(
            &source,
            "ext unsafe c fn c_read(buf: *u8, len: usize) -> i32;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Check {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("check command should return diagnostics");
        assert!(output.contains("must declare ownership suffix and paired length/context contract"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn headers_command_reports_repr_c_alignment_sensitive_layouts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-layout-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-layout-{suffix}.h"));
        std::fs::write(
            &source,
            "#[repr(C)]\nstruct PackedLike { a: u8, b: u64, c: u16 }\n#[repr(C)]\nenum Mode { Ready, Busy }\n#[ffi_panic(abort)]\npubext c fn touch(v: u64) -> u64;\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        let abi: serde_json::Value =
            serde_json::from_str(&abi_text).expect("abi manifest should be valid json");
        let layouts = abi["reprCLayouts"]
            .as_array()
            .expect("reprCLayouts should be an array");
        let packed = layouts
            .iter()
            .find(|layout| layout["name"] == "PackedLike")
            .expect("PackedLike layout should exist");
        assert_eq!(packed["size"].as_u64(), Some(24));
        assert_eq!(packed["align"].as_u64(), Some(8));
        let fields = packed["fields"]
            .as_array()
            .expect("PackedLike fields should be emitted");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0]["name"].as_str(), Some("a"));
        assert_eq!(fields[0]["c"].as_str(), Some("uint8_t"));
        assert_eq!(fields[0]["offset"].as_u64(), Some(0));
        assert_eq!(fields[1]["name"].as_str(), Some("b"));
        assert_eq!(fields[1]["c"].as_str(), Some("uint64_t"));
        assert_eq!(fields[1]["offset"].as_u64(), Some(8));
        assert_eq!(fields[2]["name"].as_str(), Some("c"));
        assert_eq!(fields[2]["c"].as_str(), Some("uint16_t"));
        assert_eq!(fields[2]["offset"].as_u64(), Some(16));
        let mode = layouts
            .iter()
            .find(|layout| layout["name"] == "Mode")
            .expect("Mode layout should exist");
        assert_eq!(mode["size"].as_u64(), Some(4));
        assert_eq!(mode["align"].as_u64(), Some(4));
        assert_eq!(mode["storage"].as_str(), Some("int32_t"));
        let variants = mode["variants"]
            .as_array()
            .expect("Mode variants should be emitted");
        assert_eq!(variants.len(), 2);
        assert_eq!(variants[0]["name"].as_str(), Some("Ready"));
        assert_eq!(variants[0]["value"].as_u64(), Some(0));
        assert_eq!(variants[1]["name"].as_str(), Some("Busy"));
        assert_eq!(variants[1]["value"].as_u64(), Some(1));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn build_lib_abi_manifest_includes_repr_c_return_field_metadata() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-lib-layout-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[repr(C)]\nstruct BridgeClickResult {\n    input_count: i32,\n    js_doubled: i32,\n    callback_total: i32,\n    handshake_score: i32,\n}\n\n#[ffi_panic(abort)]\npubext c fn bridge_click(count: i32) -> BridgeClickResult {\n    return BridgeClickResult {\n        input_count: count,\n        js_doubled: count,\n        callback_total: count,\n        handshake_score: count,\n    }\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                lib: true,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build --lib should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let abi_path = std::path::PathBuf::from(
            payload["abiManifest"]
                .as_str()
                .expect("abi manifest path should be present"),
        );
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be readable");
        let abi: serde_json::Value =
            serde_json::from_str(&abi_text).expect("abi manifest should be valid json");
        let layout = abi["reprCLayouts"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|layout| layout["name"] == "BridgeClickResult")
            })
            .expect("BridgeClickResult layout should exist");
        let fields = layout["fields"]
            .as_array()
            .expect("BridgeClickResult fields should be emitted");
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["name"].as_str(), Some("input_count"));
        assert_eq!(fields[0]["c"].as_str(), Some("int32_t"));
        assert_eq!(fields[1]["name"].as_str(), Some("js_doubled"));
        assert_eq!(fields[2]["name"].as_str(), Some("callback_total"));
        assert_eq!(fields[3]["name"].as_str(), Some("handshake_score"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn build_lib_project_root_abi_manifest_includes_repr_c_return_field_metadata() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-build-lib-root-layout-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"reprc_root_layout\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"reprc_root_layout\"\npath=\"src/lib.fzy\"\n\n[ffi]\npanic_boundary=\"abort\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[repr(C)]\nstruct BridgeClickResult {\n    input_count: i32,\n    js_doubled: i32,\n    callback_total: i32,\n    handshake_score: i32,\n}\n\n#[ffi_panic(abort)]\npubext c fn bridge_click(count: i32) -> BridgeClickResult {\n    return BridgeClickResult {\n        input_count: count,\n        js_doubled: count,\n        callback_total: count,\n        handshake_score: count,\n    }\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                lib: true,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build --lib should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let abi_path = std::path::PathBuf::from(
            payload["abiManifest"]
                .as_str()
                .expect("abi manifest path should be present"),
        );
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be readable");
        let abi: serde_json::Value =
            serde_json::from_str(&abi_text).expect("abi manifest should be valid json");
        let layout = abi["reprCLayouts"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|layout| layout["name"] == "BridgeClickResult")
            })
            .expect("BridgeClickResult layout should exist");
        let fields = layout["fields"]
            .as_array()
            .expect("BridgeClickResult fields should be emitted");
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["name"].as_str(), Some("input_count"));
        assert_eq!(fields[1]["name"].as_str(), Some("js_doubled"));
        assert_eq!(fields[2]["name"].as_str(), Some("callback_total"));
        assert_eq!(fields[3]["name"].as_str(), Some("handshake_score"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn headers_command_collects_exports_from_declared_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-headers-project-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"headers_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"headers_project\"\npath=\"src/main.fzy\"\n\n[ffi]\npanic_boundary=\"abort\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod ffi;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/ffi.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32;\n",
        )
        .expect("ffi source should be written");

        let output = run(
            Command::Headers {
                path: root.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        assert!(output.contains("exports: 1"));
        let header = root.join("include/headers_project.h");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("int32_t add(int32_t left, int32_t right);"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn vendor_command_refreshes_lock_and_writes_vendor_manifest() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-vendor-{suffix}"));
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"vendor_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"vendor_project\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            dep_dir.join("fozzy.toml"),
            "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"util\"\npath=\"src/main.fzy\"\n",
        )
        .expect("dep manifest should be written");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("dep source should be written");
        std::fs::write(
            root.join("fozzy.lock"),
            "{\"schemaVersion\":\"fozzylang.lock.v0\",\"dependencyGraphHash\":\"stale\",\"graph\":{\"deps\":[]}}",
        )
        .expect("stale lock should be written");

        let output = run(Command::Vendor { path: root.clone() }, Format::Json)
            .expect("vendor command should succeed");
        assert!(output.contains("\"ok\":true"));
        assert!(output.contains("\"lockHash\""));
        let vendor_manifest = root.join("vendor/fozzy-vendor.json");
        assert!(vendor_manifest.exists());
        let vendor_manifest_text =
            std::fs::read_to_string(&vendor_manifest).expect("vendor manifest should be readable");
        assert!(vendor_manifest_text.contains("\"schemaVersion\": \"fozzylang.vendor.v0\""));
        assert!(vendor_manifest_text.contains("\"sourceHash\""));
        assert!(root.join("vendor/util/src/main.fzy").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn vendor_command_records_remote_deps_without_path_copy() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-vendor-remote-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"vendor_remote\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"vendor_remote\"\npath=\"src/main.fzy\"\n\n[deps]\nserde={version=\"1.0.0\",source=\"registry+https://registry.example.test\"}\nparser={git=\"https://github.com/example/parser.git\",rev=\"abc123\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");

        let output = run(Command::Vendor { path: root.clone() }, Format::Json)
            .expect("vendor command should succeed");
        assert!(output.contains("\"ok\":true"));
        let vendor_manifest = root.join("vendor/fozzy-vendor.json");
        let vendor_manifest_text =
            std::fs::read_to_string(&vendor_manifest).expect("vendor manifest should be readable");
        assert!(vendor_manifest_text.contains("\"sourceType\": \"version\""));
        assert!(vendor_manifest_text.contains("\"sourceType\": \"git\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rpc_gen_command_emits_schema_and_stubs() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-rpc-{suffix}.fzy"));
        let out_dir = std::env::temp_dir().join(format!("fozzylang-rpc-out-{suffix}"));
        std::fs::write(
            &source,
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Stream(stream<PingReq>) -> stream<PingRes>;\n",
        )
        .expect("source should be written");

        let output = run(
            Command::RpcGen {
                path: source.clone(),
                out_dir: Some(out_dir.clone()),
            },
            Format::Json,
        )
        .expect("rpc gen should succeed");
        assert!(output.contains("\"methods\":2"));
        assert!(output.contains("\"schema\":\""));
        assert!(out_dir.join("rpc.schema.json").exists());
        assert!(out_dir.join("rpc.client.fzy").exists());
        assert!(out_dir.join("rpc.server.fzy").exists());
        let schema = std::fs::read_to_string(out_dir.join("rpc.schema.json"))
            .expect("rpc schema should be readable");
        let client = std::fs::read_to_string(out_dir.join("rpc.client.fzy"))
            .expect("rpc client should be readable");
        let server = std::fs::read_to_string(out_dir.join("rpc.server.fzy"))
            .expect("rpc server should be readable");
        assert!(!client.contains("TODO"));
        assert!(!server.contains("TODO"));
        assert!(schema.contains("\"schemaVersion\": \"fozzylang.rpc.v1\""));
        assert!(schema.contains("\"mode\": \"unary\""));
        assert!(schema.contains("\"mode\": \"bidirectional_streaming\""));
        assert!(schema.contains("\"clientStreaming\": true"));
        assert!(client.contains("deadline("));
        assert!(client.contains("cancel()"));
        assert!(client.contains("return Ping(req)"));
        assert!(client.contains("return Stream(arg0)"));
        assert!(!client.contains("transport_send"));
        assert!(server.contains("deadline("));
        assert!(server.contains("prepare_ping_handler"));
        assert!(server.contains("prepare_stream_handler"));
        assert!(!server.contains("transport_recv"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn abi_check_allows_added_exports_with_stable_existing_signatures() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline = std::env::temp_dir().join(format!("fozzylang-abi-baseline-{suffix}.json"));
        let current = std::env::temp_dir().join(format!("fozzylang-abi-current-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    },
                    {
                        "name":"sub",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("current abi should be written");

        let output = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Json,
        )
        .expect("abi-check should pass for additive exports");
        assert!(output.contains("\"ok\":true"));
        assert!(output.contains("sub:sync(int32_t,int32_t)->int32_t"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn abi_check_rejects_changed_signature_for_existing_export() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline =
            std::env::temp_dir().join(format!("fozzylang-abi-baseline-sig-{suffix}.json"));
        let current = std::env::temp_dir().join(format!("fozzylang-abi-current-sig-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":2,
                        "params":[{"name":"left","fzy":"i64","c":"int64_t"},{"name":"right","fzy":"i64","c":"int64_t"}],
                        "return":{"fzy":"i64","c":"int64_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("current abi should be written");

        let error = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Text,
        )
        .expect_err("abi-check should fail for signature changes");
        assert!(error
            .to_string()
            .contains("signature changed for export `add`"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn abi_check_rejects_contract_weakening() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline =
            std::env::temp_dir().join(format!("fozzylang-abi-baseline-contract-{suffix}.json"));
        let current =
            std::env::temp_dir().join(format!("fozzylang-abi-current-contract-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"consume",
                    "symbolVersion":1,
                    "params":[{"name":"buf_borrowed","fzy":"*u8","c":"uint8_t*","contract":{"ownership":"borrowed","nullability":"non_null","mutability":"mut","lifetimeAnchor":"loan:buf","view":{"kind":"ptr_len","lengthParam":"buf_len"}}},{"name":"buf_len","fzy":"usize","c":"size_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const","lifetimeAnchor":null,"view":null}}],
                    "return":{"fzy":"i32","c":"int32_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const"}},
                    "contract":{"callbackBindings":[]}
                }]
            }).to_string(),
        ).expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"consume",
                    "symbolVersion":1,
                    "params":[{"name":"buf_borrowed","fzy":"*u8","c":"uint8_t*","contract":{"ownership":"borrowed","nullability":"nullable","mutability":"mut","lifetimeAnchor":"loan:buf","view":{"kind":"ptr_len","lengthParam":"buf_len"}}},{"name":"buf_len","fzy":"usize","c":"size_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const","lifetimeAnchor":null,"view":null}}],
                    "return":{"fzy":"i32","c":"int32_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const"}},
                    "contract":{"callbackBindings":[]}
                }]
            }).to_string(),
        ).expect("current abi should be written");
        let error = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Text,
        )
        .expect_err("abi-check should fail for weakened contracts");
        assert!(error
            .to_string()
            .contains("contract weakened/changed for export `consume`"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn abi_check_rejects_sync_to_async_mode_change() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline =
            std::env::temp_dir().join(format!("fozzylang-abi-baseline-async-mode-{suffix}.json"));
        let current =
            std::env::temp_dir().join(format!("fozzylang-abi-current-async-mode-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"flush",
                    "async": false,
                    "symbolVersion":1,
                    "params":[{"name":"code","fzy":"i32","c":"int32_t"}],
                    "return":{"fzy":"i32","c":"int32_t"},
                    "contract":{"execution":"sync","callbackBindings":[]}
                }]
            })
            .to_string(),
        )
        .expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"flush",
                    "async": true,
                    "symbolVersion":1,
                    "params":[{"name":"code","fzy":"i32","c":"int32_t"}],
                    "return":{"fzy":"i32","c":"int32_t"},
                    "contract":{"execution":"async-handle-v1","callbackBindings":[]}
                }]
            })
            .to_string(),
        )
        .expect("current abi should be written");

        let error = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Text,
        )
        .expect_err("abi-check should fail for async mode changes");
        assert!(error
            .to_string()
            .contains("signature changed for export `flush`"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn rpc_gen_command_reads_declarations_from_declared_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-rpc-project-{suffix}"));
        let out_dir = std::env::temp_dir().join(format!("fozzylang-rpc-project-out-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"rpc_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_project\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod rpc_api;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/rpc_api.fzy"),
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Stream(stream<PingReq>) -> stream<PingRes>;\n",
        )
        .expect("rpc source should be written");

        let output = run(
            Command::RpcGen {
                path: root.clone(),
                out_dir: Some(out_dir.clone()),
            },
            Format::Json,
        )
        .expect("rpc gen should succeed");
        assert!(output.contains("\"methods\":2"));
        assert!(out_dir.join("rpc.schema.json").exists());
        let server = std::fs::read_to_string(out_dir.join("rpc.server.fzy"))
            .expect("rpc server should be readable");
        assert!(server.contains("apply_rpc_handler_contract"));
        assert!(server.contains("prepare_ping_handler"));

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn doc_gen_includes_rpc_and_ffi_surfaces_from_semantic_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-doc-project-{suffix}"));
        std::fs::create_dir_all(root.join("src/api")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"doc_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"doc_project\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod api;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/api/mod.fzy"), "mod ffi;\nmod rpc;\n")
            .expect("api module should be written");
        std::fs::write(
            root.join("src/api/ffi.fzy"),
            "/// Hash bytes for the host boundary.\npubext c fn hash32(ptr_borrowed: *u8, len: usize) -> u32;\n",
        )
        .expect("ffi source should be written");
        std::fs::write(
            root.join("src/api/rpc.fzy"),
            "/// Ping the service edge.\nrpc Ping(req: PingReq) -> PingRes;\n",
        )
        .expect("rpc source should be written");

        let output = run(
            Command::DocGen {
                path: root.clone(),
                format: "json".to_string(),
                out: None,
                reference: None,
            },
            Format::Json,
        )
        .expect("doc gen should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("doc gen json should parse");
        let rendered = payload["rendered"]
            .as_str()
            .expect("rendered docs should be present");
        let rendered_json: serde_json::Value =
            serde_json::from_str(rendered).expect("rendered docs payload should parse");
        assert_eq!(rendered_json["schemaVersion"], "fozzylang.doc.v1");
        let items = rendered_json["items"]
            .as_array()
            .expect("doc items should be an array");
        assert!(items.iter().any(|item| {
            item["kind"] == "ffi-export"
                && item["signature"]
                    .as_str()
                    .is_some_and(|value| value.contains("pubext c fn hash32"))
                && item["docs"]
                    .as_str()
                    .is_some_and(|value| value.contains("Hash bytes for the host boundary."))
        }));
        assert!(items.iter().any(|item| {
            item["kind"] == "rpc"
                && item["signature"]
                    .as_str()
                    .is_some_and(|value| value.contains("rpc Ping(req: PingReq) -> PingRes;"))
                && item["docs"]
                    .as_str()
                    .is_some_and(|value| value.contains("Ping the service edge."))
        }));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_threads_persists_runtime_config() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-threads-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                lib: false,
                threads: Some(3),
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed");
        assert!(output.contains("\"threads\":3"));
        let runtime_config = source
            .parent()
            .expect("temp source should have parent")
            .join(".fz/runtime.json");
        assert!(runtime_config.exists());
        let runtime_text =
            std::fs::read_to_string(&runtime_config).expect("runtime config should be readable");
        assert!(runtime_text.contains("\"threads\": 3"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(runtime_config);
    }

    #[test]
    fn build_command_emits_runnable_binary_named_after_target() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-build-binary-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo_binary\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo_binary\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 7\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                lib: false,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let artifact = std::path::PathBuf::from(
            payload["output"]
                .as_str()
                .expect("build output should include artifact path"),
        );
        assert_eq!(
            artifact.file_name().and_then(|name| name.to_str()),
            Some("demo_binary")
        );
        assert!(artifact.exists());
        let status = std::process::Command::new(&artifact)
            .status()
            .expect("native artifact should execute");
        assert_eq!(status.code(), Some(7));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_lib_emits_static_shared_and_headers() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-lib-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                lib: true,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build --lib should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        assert_eq!(payload["buildMode"].as_str(), Some("lib"));
        assert!(payload
            .get("staticLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(payload
            .get("sharedLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(payload
            .get("header")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(payload
            .get("abiManifest")
            .and_then(|value| value.as_str())
            .is_some());
        let artifact_manifest = std::path::PathBuf::from(
            payload["artifactManifest"]
                .as_str()
                .expect("artifact manifest should be present"),
        );
        let artifact_payload: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&artifact_manifest).expect("artifact manifest should be readable"),
        )
        .expect("artifact manifest should be valid json");
        for key in [
            "source",
            "projectRoot",
            "staticLib",
            "sharedLib",
            "header",
            "abiManifest",
            "artifactManifest",
        ] {
            let value = artifact_payload[key]
                .as_str()
                .unwrap_or_else(|| panic!("artifact manifest field `{key}` should be a string"));
            assert!(
                !std::path::Path::new(value).is_absolute(),
                "artifact manifest field `{key}` should be relative: {value}"
            );
        }

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn build_binary_with_c_exports_also_reports_interop_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-interop-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n\nfn main() -> i32 {\n    return add(2, 5)\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                lib: false,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let interop = payload
            .get("interop")
            .expect("interop metadata should be present for c exports");
        assert_eq!(
            interop.get("buildMode").and_then(|value| value.as_str()),
            Some("lib")
        );
        assert!(interop
            .get("staticLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(interop
            .get("sharedLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(interop
            .get("header")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(interop
            .get("abiManifest")
            .and_then(|value| value.as_str())
            .is_some());
        assert_eq!(
            interop
                .get("hostLifecycle")
                .and_then(|value| value.get("lastErrorMessage"))
                .and_then(|value| value.as_str()),
            Some("fz_host_last_error_message")
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn generate_c_headers_reuses_cached_outputs_when_inputs_are_unchanged() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-header-cache-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"header_cache\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"header_cache\"\npath=\"src/lib.fzy\"\n\n[ffi]\npanic_boundary=\"abort\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
        )
        .expect("source should be written");

        let first = generate_c_headers(&root, None).expect("header generation should succeed");
        let cache_path = first.path.with_extension("header.cache.json");
        assert!(cache_path.exists(), "cache stamp should be written");
        let header_mtime = std::fs::metadata(&first.path)
            .and_then(|meta| meta.modified())
            .expect("header mtime");
        let abi_mtime = std::fs::metadata(&first.abi_manifest)
            .and_then(|meta| meta.modified())
            .expect("abi mtime");
        let cache_mtime = std::fs::metadata(&cache_path)
            .and_then(|meta| meta.modified())
            .expect("cache mtime");

        std::thread::sleep(std::time::Duration::from_millis(20));
        let second =
            generate_c_headers(&root, None).expect("cached header generation should succeed");
        assert_eq!(second.exports, 1);
        assert_eq!(
            std::fs::metadata(&second.path)
                .and_then(|meta| meta.modified())
                .expect("header mtime"),
            header_mtime
        );
        assert_eq!(
            std::fs::metadata(&second.abi_manifest)
                .and_then(|meta| meta.modified())
                .expect("abi mtime"),
            abi_mtime
        );
        assert_eq!(
            std::fs::metadata(&cache_path)
                .and_then(|meta| meta.modified())
                .expect("cache mtime"),
            cache_mtime
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unsafe_docs_cache_hit_tracks_input_fingerprint() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-unsafe-docs-cache-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"unsafe_docs\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"unsafe_docs\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "unsafe fn risky() -> i32 {\n    return 7\n}\n\nfn main() -> i32 {\n    unsafe {\n        return risky()\n    }\n}\n",
        )
        .expect("source should be written");

        let docs = root.join(".fz/unsafe-docs.md");
        std::fs::create_dir_all(docs.parent().expect("docs parent")).expect("docs dir");
        std::fs::write(&docs, "# unsafe docs\n").expect("write docs");
        std::fs::write(docs.with_extension("json"), b"{}").expect("write docs json");
        std::fs::write(docs.with_extension("html"), b"<p>unsafe docs</p>")
            .expect("write docs html");
        write_unsafe_docs_cache_stamp(&root, &docs).expect("write cache stamp");
        let stamp = unsafe_docs_cache_path(&docs);
        assert!(stamp.exists(), "unsafe docs stamp should be written");
        assert!(
            unsafe_docs_cache_hit(&root, &docs).expect("cache hit should evaluate"),
            "fresh cache stamp should match inputs"
        );
        let docs_mtime = std::fs::metadata(&docs)
            .and_then(|meta| meta.modified())
            .expect("docs mtime");
        let stamp_mtime = std::fs::metadata(&stamp)
            .and_then(|meta| meta.modified())
            .expect("stamp mtime");

        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(
            std::fs::metadata(&docs)
                .and_then(|meta| meta.modified())
                .expect("docs mtime"),
            docs_mtime
        );
        assert_eq!(
            std::fs::metadata(&stamp)
                .and_then(|meta| meta.modified())
                .expect("stamp mtime"),
            stamp_mtime
        );
        std::fs::write(
            root.join("src/main.fzy"),
            "unsafe fn risky() -> i32 {\n    return 9\n}\n\nfn main() -> i32 {\n    unsafe {\n        return risky()\n    }\n}\n",
        )
        .expect("rewrite source");
        assert!(
            !unsafe_docs_cache_hit(&root, &docs).expect("cache hit should re-evaluate"),
            "cache stamp should miss after source changes"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn non_scenario_test_uses_scheduler_for_deterministic_execution() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-sched-{suffix}.fzy"));
        std::fs::write(
            &source,
            "test \"a\" {}\ntest \"b\" {}\ntest \"c\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(9),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: Some("coverage_guided".to_string()),
                rich_artifacts: false,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"scheduler\":\"coverage_guided\""));
        assert!(output.contains("\"executedTasks\":3"));
        assert!(output.contains("\"executionOrder\":[0,2,1]"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_command_executes_native_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-run-native-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 7\n}\n")
            .expect("source should be written");

        let error = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect_err("run command should fail with child exit code");
        let command_error = error
            .downcast_ref::<CommandFailure>()
            .expect("expected command failure payload");
        assert_eq!(command_error.exit_code, 7);
        assert!(command_error.output.contains("\"exitCode\":7"));
        assert!(command_error.output.contains("\"binary\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_spawn_executes_worker_side_effect() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-spawn-native-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-spawn-native-{suffix}.txt"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    proc.run(\"/bin/sh -lc 'echo spawned > {quoted_out}'\")\n    return 0\n}}\n\nfn main() -> i32 {{\n    spawn(worker)\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run command should succeed for spawn worker side effect");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            out_path.exists(),
            "spawned worker side effect output should exist at {}",
            out_path.display()
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn run_task_group_spawn_n_executes_all_worker_side_effects() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-group-native-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-group-native-{suffix}.txt"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo grouped >> {quoted_out}'\")\n}}\n\nfn main() -> i32 {{\n    let group = task.group_begin()\n    discard task.group_spawn_n(group, worker, 3)\n    return task.group_join_all(group)\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run command should succeed for grouped worker side effects");
        assert!(output.contains("\"exitCode\":0"));
        let content =
            std::fs::read_to_string(&out_path).expect("group worker output should be readable");
        assert_eq!(
            content.lines().count(),
            3,
            "expected three worker side effects"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn run_task_group_join_all_propagates_worker_failure() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-group-failure-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\nuse core.thread;\n\nfn worker() -> i32 {\n    return proc.run(\"/bin/sh -lc 'exit 7'\")\n}\n\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    return task.group_join_all(group)\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect_err("group worker failure should surface as command failure");
        let command_error = error
            .downcast_ref::<CommandFailure>()
            .expect("expected command failure payload");
        assert_eq!(command_error.exit_code, 7);
        assert!(command_error.output.contains("\"exitCode\":7"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_spawned_worker_preserves_json_object_payloads() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-spawn-json-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-spawn-json-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.thread;\n\nfn worker() -> i32 {{\n    let payload = map.new()\n    discard map.set(payload, \"status\", json.str(\"ok\"))\n    discard map.set(payload, \"probe\", json.raw(\"7\"))\n    let doc = json.object(payload)\n    fs.write_file(\"{quoted_out}\", doc)\n    return 0\n}}\n\nfn main() -> i32 {{\n    let handle = spawn(worker)\n    return join(handle)\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("spawned json worker should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let content =
            std::fs::read_to_string(&out_path).expect("spawned json output should be readable");
        assert_ne!(
            content.trim(),
            "{}",
            "spawned json payload should not collapse to empty object"
        );
        assert!(
            content.contains("\"status\":\"ok\""),
            "spawned json payload should preserve string field"
        );
        assert!(
            content.contains("\"probe\":7"),
            "spawned json payload should preserve raw numeric field"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn run_spawned_worker_preserves_proc_result_json_payloads() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-spawn-proc-json-{suffix}.fzy"));
        let out_path =
            std::env::temp_dir().join(format!("fozzylang-spawn-proc-json-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"printf ok\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    discard proc.wait(handle, 1000)\n    let stdout = proc.stdout(handle)\n    let stderr = proc.stderr(handle)\n    discard proc.close(handle)\n    let payload = map.new()\n    discard map.set(payload, \"exit\", json.str(\"0\"))\n    discard map.set(payload, \"stdout\", json.str(stdout))\n    discard map.set(payload, \"stderr\", json.str(stderr))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    return 0\n}}\n\nfn main() -> i32 {{\n    let handle = spawn(worker)\n    return join(handle)\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("spawned proc json worker should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let content = std::fs::read_to_string(&out_path)
            .expect("spawned proc json output should be readable");
        assert_ne!(
            content.trim(),
            "{}",
            "spawned proc json payload should not collapse to empty object"
        );
        assert!(content.contains("\"exit\":\"0\""));
        assert!(content.contains("\"stdout\":\"ok\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn proc_wait_drains_large_child_output_without_stalling() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-proc-wait-backpressure-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\n\nfn main() -> i32 {\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"/usr/bin/python3 -c 'import sys; sys.stdout.write(\\\"o\\\" * 300000); sys.stdout.flush(); sys.stderr.write(\\\"e\\\" * 300000); sys.stderr.flush()'\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    let waited = proc.wait(handle, 10000)\n    let stdout = proc.stdout(handle)\n    let stderr = proc.stderr(handle)\n    let exit_code = proc.exit_code(handle)\n    discard proc.close(handle)\n    if waited == 0 && exit_code == 0 && str.len(stdout) == 300000 && str.len(stderr) == 300000 {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("large-output proc wait should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn deferred_proc_close_does_not_clobber_returned_exit_code() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-proc-defer-return-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\n\nfn status_of() -> i32 {\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"exit 0\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    discard proc.wait(handle, 1000)\n    return proc.exit_code(handle)\n}\n\nfn main() -> i32 {\n    if status_of() == 0 {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("deferred proc close should preserve exit code");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn proc_poll_reports_running_then_completion_without_consuming_handle() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-proc-poll-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\n\nfn main() -> i32 {\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 0.2; printf ready\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    let first = proc.poll(handle)\n    let waited = proc.wait(handle, 1000)\n    let second = proc.poll(handle)\n    let exit_code = proc.exit_code(handle)\n    let stdout = proc.stdout(handle)\n    discard proc.close(handle)\n    if first == 0 && waited == 0 && second == 1 && exit_code == 0 && stdout == \"ready\" {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("proc poll should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn host_backed_atomic_write_and_storage_atomic_append_persist_expected_bytes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-atomic-runtime-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        let atomic_path = root.join("state.txt");
        let append_path = root.join("audit.log");
        let atomic_quoted = atomic_path.to_string_lossy().replace('\"', "\\\"");
        let append_quoted = append_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"atomic_runtime\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"atomic_runtime\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            format!(
                "use core.fs;\nuse core.storage;\n\nfn main() -> i32 {{\n    discard fs.atomic_write(\"{atomic_quoted}\", \"alpha\")\n    discard storage.atomic_append(\"{append_quoted}\", \"first\")\n    discard storage.atomic_append(\"{append_quoted}\", \"second\")\n    let state = fs.read_file(\"{atomic_quoted}\")\n    let audit = fs.read_file(\"{append_quoted}\")\n    if state == \"alpha\" && audit == \"first\\nsecond\\n\" {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backed atomic write and append should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        assert_eq!(
            std::fs::read_to_string(&atomic_path).expect("atomic file should exist"),
            "alpha"
        );
        assert_eq!(
            std::fs::read_to_string(&append_path).expect("append log should exist"),
            "first\nsecond\n"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn crypto_runtime_surface_supports_hash_hmac_base64_and_secure_compare() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-crypto-runtime-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.crypto;\nuse core.error;\nuse core.security;\n\nfn main() -> i32 {\n    let digest = crypto.sha256(\"abc\")\n    let mac = crypto.hmac_sha256(\"key\", \"The quick brown fox jumps over the lazy dog\")\n    let encoded = crypto.base64_encode(\"fozzy\")\n    let decoded = crypto.base64_decode(encoded)\n    let crypto_url = crypto.base64_url_encode(\"ok\")\n    let crypto_roundtrip = crypto.base64_url_decode(crypto_url)\n    let url = security.base64_url_encode(\"ok\")\n    let roundtrip = security.base64_url_decode(url)\n    let hex_token = crypto.random_hex(16)\n    let b64_token = crypto.random_base64(16)\n    if digest != \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\" {\n        return 11\n    }\n    if mac != \"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8\" {\n        return 13\n    }\n    if encoded != \"Zm96enk=\" || decoded != \"fozzy\" {\n        return 17\n    }\n    if crypto_url != \"b2s\" || crypto_roundtrip != \"ok\" {\n        return 18\n    }\n    if url != \"b2s\" || roundtrip != \"ok\" {\n        return 19\n    }\n    if str.len(hex_token) != 32 || str.len(b64_token) != 24 {\n        return 23\n    }\n    if crypto.constant_time_eq(digest, digest) != 1 {\n        return 29\n    }\n    if crypto.constant_time_eq(digest, mac) != 0 {\n        return 31\n    }\n    if security.verify_value(\"key\", \"The quick brown fox jumps over the lazy dog\", mac) != 1 {\n        return 37\n    }\n    if crypto.base64_decode(\"A===\") != \"\" {\n        return 41\n    }\n    if error.code() == 0 || error.message() == \"\" {\n        return 43\n    }\n    if security.base64_url_decode(\"A\") != \"\" {\n        return 47\n    }\n    if error.code() == 0 || error.message() == \"\" {\n        return 49\n    }\n    if crypto.base64_decode(encoded) != \"fozzy\" {\n        return 53\n    }\n    if error.code() != 0 || error.message() != \"\" {\n        return 59\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .unwrap_or_else(|err| {
            if let Some(command_failure) = err.downcast_ref::<CommandFailure>() {
                panic!(
                    "crypto runtime should succeed: {}\noutput:\n{}",
                    command_failure, command_failure.output
                );
            }
            panic!("crypto runtime should succeed: {err}");
        });
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_lib_host_callback_can_read_borrowed_string_payload_bytes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-borrowed-payload-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        let input_path = root.join("control.input.json");
        let echoed_path = root.join("control.echo.json");
        std::fs::write(&input_path, "{\"status\":\"ok\",\"control_plane\":\"fzy\"}")
            .expect("input payload should be written");
        std::fs::write(
            root.join("fozzy.toml"),
            format!(
                "[package]\nname=\"ffi_borrowed_payload\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_borrowed_payload\"\npath=\"src/main.fzy\"\n\n[ffi]\npanic_boundary=\"error\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n"
            ),
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            format!(
                "use core.fs;\n\next unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;\n\n#[ffi_panic(error)]\npubext c fn dispatch() -> i32 {{\n    let raw = fs.read_file(\"{}\")\n    unsafe {{\n        return host_touch(raw, str.len(raw))\n    }}\n}}\n",
                input_path.display()
            ),
        )
        .expect("source should be written");

        for backend in ["llvm", "cranelift"] {
            let output = run(
                Command::Build {
                    path: root.clone(),
                    release: false,
                    strict: false,
                    lib: true,
                    threads: None,
                    backend: Some(backend.to_string()),
                    pgo_generate: false,
                    pgo_use: None,
                    link_libs: Vec::new(),
                    link_search: Vec::new(),
                    frameworks: Vec::new(),
                },
                Format::Json,
            )
            .expect("build --lib should succeed");
            let payload_json: serde_json::Value =
                serde_json::from_str(&output).expect("build output should be valid json");
            let shared_lib = PathBuf::from(
                payload_json["sharedLib"]
                    .as_str()
                    .expect("sharedLib should be present"),
            );
            let header_path = PathBuf::from(
                payload_json["header"]
                    .as_str()
                    .expect("header should be present"),
            );
            let include_dir = header_path
                .parent()
                .expect("header should have parent directory");
            let probe_source = root.join(format!("probe-{backend}.c"));
            let probe_binary = root.join(format!("probe-{backend}"));
            std::fs::write(
                &probe_source,
                format!(
                    "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include \"ffi_borrowed_payload.h\"\n\nstatic uint8_t captured[256];\nstatic size_t captured_len = 0;\n\nint32_t host_touch(const uint8_t* ptr, size_t len) {{\n  if (ptr == NULL) return 91;\n  if (len > sizeof(captured)) return 92;\n  memcpy(captured, ptr, len);\n  captured_len = len;\n  FILE* f = fopen(\"{}\", \"wb\");\n  if (f == NULL) return 93;\n  if (len > 0) fwrite(ptr, 1, len, f);\n  fclose(f);\n  return 0;\n}}\n\nint main(void) {{\n  if (fz_host_init() != 0) return 101;\n  char expected[256];\n  for (int i = 0; i < 512; i++) {{\n    FILE* input = fopen(\"{}\", \"wb\");\n    if (input == NULL) return 106;\n    int written = snprintf(expected, sizeof(expected), \"{{\\\"status\\\":\\\"ok\\\",\\\"control_plane\\\":\\\"fzy\\\",\\\"seq\\\":%d}}\", i);\n    if (written < 0 || (size_t)written >= sizeof(expected)) {{\n      fclose(input);\n      return 107;\n    }}\n    fwrite(expected, 1, (size_t)written, input);\n    fclose(input);\n    int32_t rc = dispatch();\n    if (rc != 0) return rc;\n    if (captured_len != (size_t)written) return 104;\n    if (memcmp(captured, expected, (size_t)written) != 0) return 105;\n  }}\n  int32_t shutdown_rc = fz_host_shutdown();\n  int32_t cleanup_rc = fz_host_cleanup();\n  if (shutdown_rc != 0) return 102;\n  if (cleanup_rc != 0) return 103;\n  return 0;\n}}\n",
                    echoed_path.display(),
                    input_path.display()
                ),
            )
            .expect("probe source should be written");
            let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
            let rpath_flag = format!(
                "-Wl,-rpath,{}",
                shared_lib
                    .parent()
                    .expect("shared lib should have parent")
                    .display()
            );
            let status = ProcessCommand::new(&cc)
                .arg(&probe_source)
                .arg(&shared_lib)
                .arg("-I")
                .arg(include_dir)
                .arg(&rpath_flag)
                .arg("-o")
                .arg(&probe_binary)
                .status()
                .expect("C probe should compile");
            assert!(
                status.success(),
                "C probe compile should succeed for backend {backend}"
            );
            let status = ProcessCommand::new(&probe_binary)
                .status()
                .expect("C probe should execute");
            assert_eq!(
                status.code(),
                Some(0),
                "C probe should observe borrowed payload bytes for backend {backend}"
            );
            let echoed =
                std::fs::read_to_string(&echoed_path).expect("echoed payload should exist");
            assert!(
                echoed.contains("\"seq\":511"),
                "final echoed payload should match the last borrowed callback payload"
            );
            let _ = std::fs::remove_file(&probe_source);
            let _ = std::fs::remove_file(&probe_binary);
            let _ = std::fs::remove_file(&echoed_path);
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn portable_simd_surface_runs_via_fz_run_with_llvm_backend() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-simd-runtime-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.simd;\n\nfn main() -> i32 {\n    let ints = simd.i32x4_add(simd.i32x4_load([1, 2, 3, 4]), simd.i32x4_splat(2))\n    let uint_source = simd.u32x4_store(simd.u32x4_new(1, 2, 3, 4))\n    let float_source = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let shifted = simd.i32x4_shl(ints, 1)\n    let bounded = simd.i32x4_max(shifted, simd.i32x4_new(7, 1, 11, 1))\n    let lane = 5\n    let shuffled = simd.i32x4_shuffle(ints, shifted, 0, lane, 2, 7)\n    let zip_lo = simd.i32x4_zip_lo(ints, shifted)\n    let zip_hi = simd.i32x4_zip_hi(ints, shifted)\n    let unzipped_left = simd.i32x4_unzip_left(zip_lo, zip_hi)\n    let unzipped_right = simd.i32x4_unzip_right(zip_lo, zip_hi)\n    let mask = simd.i32x4_gt(ints, simd.i32x4_splat(4))\n    let stored_ints = simd.i32x4_store(ints)\n    let picked = simd.i32x4_select(mask, ints, simd.i32x4_splat(0))\n    let sum = simd.i32x4_reduce_add(picked)\n    let signed_sat = simd.i32x4_saturating_add(simd.i32x4_new(2147483640, -2147483640, 100, -100), simd.i32x4_new(20, -20, -250, 250))\n    let signed_sat_back = simd.i32x4_saturating_sub(signed_sat, simd.i32x4_new(100, -100, -100, 100))\n    let bitmask = simd.mask32x4_bitmask(mask)\n    let signed_bits = simd.f32x4_bitcast_i32x4(simd.f32x4_new(1.0, -2.0, 0.0, 4.0))\n    let signed_roundtrip = simd.i32x4_bitcast_f32x4(signed_bits)\n    let alias_roundtrip = simd.i32x4_as_u32x4(simd.u32x4_as_i32x4(simd.u32x4_new(9, 11, 13, 15)))\n    let unsigned_sat = simd.u32x4_saturating_add(simd.i32x4_as_u32x4(simd.i32x4_new(-1, -5, 10, 0)), simd.i32x4_as_u32x4(simd.i32x4_new(1, 10, 20, -1)))\n    let unsigned_sat_back = simd.u32x4_saturating_sub(unsigned_sat, simd.u32x4_new(1, 5, 100, 0))\n    let uints_ok = simd.mask32x4_all(simd.u32x4_eq(simd.u32x4_max(simd.u32x4_shr(simd.u32x4_shl(simd.u32x4_load(uint_source), 2), 1), simd.u32x4_new(0, 4, 0, 8)), simd.u32x4_new(2, 4, 6, 8)))\n    let stored_uints = simd.u32x4_store(alias_roundtrip)\n    let floats = simd.f32x4_min(simd.f32x4_mul(simd.f32x4_splat(1.5f32), simd.f32x4_load(float_source)), simd.f32x4_max(simd.f32x4_new(1.0, 3.0, 4.0, 5.0), simd.f32x4_new(1.5, 2.5, 4.5, 6.0)))\n    let stored_floats = simd.f32x4_store(floats)\n    let stored_mask = simd.mask32x4_store(mask)\n    let floats_ok = simd.mask32x4_all(simd.f32x4_eq(floats, simd.f32x4_new(1.5, 3.0, 4.5, 6.0)))\n    if simd.mask32x4_any(mask) == false {\n        return 11\n    }\n    if simd.mask32x4_none(mask) == true {\n        return 13\n    }\n    if uints_ok == false {\n        return 17\n    }\n    if floats_ok == false {\n        return 19\n    }\n    if simd.i32x4_lane0(bounded) != 7 {\n        return 21\n    }\n    if simd.i32x4_lane2(ints) != 5 {\n        return 23\n    }\n    if simd.i32x4_lane1(shuffled) != 8 {\n        return 25\n    }\n    if bitmask != 12 {\n        return 27\n    }\n    if sum != 11 {\n        return 29\n    }\n    if simd.i32x4_reduce_min(signed_sat) != simd.i32x4_lane1(signed_sat) {\n        return 30\n    }\n    if simd.i32x4_reduce_max(signed_sat) != simd.i32x4_lane0(signed_sat) {\n        return 31\n    }\n    if simd.i32x4_lane3(zip_hi) != 12 {\n        return 33\n    }\n    if stored_ints[3] != 6 {\n        return 34\n    }\n    if simd.mask32x4_all(simd.i32x4_eq(unzipped_left, ints)) == false {\n        return 35\n    }\n    if simd.mask32x4_all(simd.i32x4_eq(unzipped_right, shifted)) == false {\n        return 37\n    }\n    if stored_mask[0] != false || stored_mask[2] != true {\n        return 38\n    }\n    if simd.mask32x4_all(simd.f32x4_eq(signed_roundtrip, simd.f32x4_new(1.0, -2.0, 0.0, 4.0))) == false {\n        return 39\n    }\n    if simd.mask32x4_all(simd.f32x4_eq(simd.f32x4_load(stored_floats), floats)) == false {\n        return 41\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(alias_roundtrip, simd.u32x4_new(9, 11, 13, 15))) == false {\n        return 43\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(simd.u32x4_load(stored_uints), alias_roundtrip)) == false {\n        return 45\n    }\n    if simd.i32x4_lane2(signed_sat) != -150 || simd.i32x4_lane3(signed_sat) != 150 {\n        return 47\n    }\n    if simd.i32x4_lane0(signed_sat_back) != 2147483547 || simd.i32x4_lane1(signed_sat_back) != -2147483548 {\n        return 49\n    }\n    if simd.i32x4_lane2(signed_sat_back) != -50 || simd.i32x4_lane3(signed_sat_back) != 50 {\n        return 50\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(unsigned_sat, simd.i32x4_as_u32x4(simd.i32x4_new(-1, -1, 30, -1)))) == false {\n        return 51\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(unsigned_sat_back, simd.i32x4_as_u32x4(simd.i32x4_new(-2, -6, 0, -1)))) == false {\n        return 53\n    }\n    if simd.u32x4_reduce_min(alias_roundtrip) != simd.u32x4_lane0(alias_roundtrip) || simd.u32x4_reduce_max(alias_roundtrip) != simd.u32x4_lane3(alias_roundtrip) {\n        return 55\n    }\n    if simd.f32x4_reduce_min(floats) != simd.f32x4_lane0(floats) || simd.f32x4_reduce_max(floats) != simd.f32x4_lane3(floats) {\n        return 57\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("llvm".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .unwrap_or_else(|err| {
            if let Some(command_failure) = err.downcast_ref::<CommandFailure>() {
                panic!(
                    "SIMD runtime should succeed: {}\noutput:\n{}",
                    command_failure, command_failure.output
                );
            }
            panic!("SIMD runtime should succeed: {err}");
        });
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn portable_simd_surface_runs_via_fz_run_with_cranelift_backend() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-simd-runtime-cranelift-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        let fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/simd_portable/main.fzy"),
        )
        .expect("portable simd fixture should be readable");
        std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .unwrap_or_else(|err| {
            if let Some(command_failure) = err.downcast_ref::<CommandFailure>() {
                panic!(
                    "SIMD runtime should succeed on cranelift: {}\noutput:\n{}",
                    command_failure, command_failure.output
                );
            }
            panic!("SIMD runtime should succeed on cranelift: {err}");
        });
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_http_post_json_applies_headers_and_preserves_raw_json_values() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should resolve");
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = Arc::clone(&captured);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept connection");
            let mut buf = Vec::<u8>::new();
            let mut header_end = None;
            let mut content_length = 0usize;
            loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).expect("server read should succeed");
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if header_end.is_none() {
                    if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                        let end_index = end + 4;
                        header_end = Some(end_index);
                        let header_text = String::from_utf8_lossy(&buf[..end_index]).to_string();
                        for line in header_text.lines() {
                            let lower = line.to_ascii_lowercase();
                            if let Some(value) = lower.strip_prefix("content-length:") {
                                content_length = value.trim().parse::<usize>().unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(end_index) = header_end {
                    if buf.len() >= end_index + content_length {
                        break;
                    }
                }
            }
            *captured_clone.lock().expect("capture lock should succeed") =
                String::from_utf8_lossy(&buf).to_string();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                )
                .expect("server response should write");
        });

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-http-json-{suffix}.fzy"));
        std::fs::write(
            &source,
            format!(
                "use core.http;\n\nfn main() -> i32 {{\n    discard http.header_set(\"x-demo\", \"sentinel\")\n    let inner = map.new()\n    discard map.set(inner, \"status\", json.raw(\"true\"))\n    discard map.set(inner, \"msg\", json.str(\"ok\"))\n    let items = list.new()\n    discard list.push(items, json.raw(\"1\"))\n    discard list.push(items, json.object(inner))\n    let payload = map.new()\n    discard map.set(payload, \"outer\", json.object(inner))\n    discard map.set(payload, \"items\", json.array(items))\n    discard http.post_json_capture(\"http://127.0.0.1:{}/echo\", json.object(payload))\n    let status = http.last_status()\n    if status != 200 {{\n        return status\n    }}\n    return 0\n}}\n",
                addr.port()
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("http json runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"));

        server.join().expect("server thread should finish");
        let request = captured
            .lock()
            .expect("capture lock should succeed")
            .clone();
        assert!(
            request.to_ascii_lowercase().contains("x-demo: sentinel"),
            "expected outbound custom header in request: {request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "expected JSON content-type header in request: {request}"
        );
        assert!(
            request.contains("\"outer\":{\"status\":true,\"msg\":\"ok\"}"),
            "expected raw nested JSON object in request body: {request}"
        );
        assert!(
            request.contains("\"items\":[1,{\"status\":true,\"msg\":\"ok\"}]"),
            "expected raw JSON array values in request body: {request}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_http_request_stream_reads_sse_events_incrementally() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should resolve");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept connection");
            let mut buf = Vec::<u8>::new();
            let mut header_end = None;
            let mut content_length = 0usize;
            loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).expect("server read should succeed");
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if header_end.is_none() {
                    if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                        let end_index = end + 4;
                        header_end = Some(end_index);
                        let header_text = String::from_utf8_lossy(&buf[..end_index]).to_string();
                        for line in header_text.lines() {
                            let lower = line.to_ascii_lowercase();
                            if let Some(value) = lower.strip_prefix("content-length:") {
                                content_length = value.trim().parse::<usize>().unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(end_index) = header_end {
                    if buf.len() >= end_index + content_length {
                        break;
                    }
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .expect("server headers should write");
            stream
                .write_all(b"event: message_start\n\n")
                .expect("message_start should write");
            stream.flush().expect("message_start flush should succeed");
            std::thread::sleep(std::time::Duration::from_millis(10));
            stream
                .write_all(b"event: content_block_delta\ndata: {\"type\":\"text_delta\",\"text\":\"hi\"}\n\n")
                .expect("content block should write");
            stream.flush().expect("content block flush should succeed");
            std::thread::sleep(std::time::Duration::from_millis(10));
            stream
                .write_all(b"event: message_stop\n\n")
                .expect("message_stop should write");
            stream.flush().expect("message_stop flush should succeed");
        });

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-http-stream-{suffix}.fzy"));
        std::fs::write(
            &source,
            format!(
                "use core.http;\n\nfn read_event_type(stream: HttpStreamHandle) -> str {{\n    loop {{\n        let line = http.stream_read_line(stream)\n        if line == \"\" {{\n            if http.stream_eof(stream) == 1 {{\n                return \"\"\n            }}\n            continue\n        }}\n        if str.starts_with(line, \"event:\") == 1 {{\n            let value = str.slice(line, 6, str.len(line))\n            if str.starts_with(value, \" \") == 1 {{\n                return str.slice(value, 1, str.len(value))\n            }}\n            return value\n        }}\n    }}\n}}\n\nfn read_event_data(stream: HttpStreamHandle) -> str {{\n    loop {{\n        let line = http.stream_read_line(stream)\n        if line == \"\" {{\n            if http.stream_eof(stream) == 1 {{\n                return \"\"\n            }}\n            continue\n        }}\n        if str.starts_with(line, \"data:\") == 1 {{\n            let value = str.slice(line, 5, str.len(line))\n            if str.starts_with(value, \" \") == 1 {{\n                return str.slice(value, 1, str.len(value))\n            }}\n            return value\n        }}\n    }}\n}}\n\nfn main() -> i32 {{\n    discard http.header_set(\"accept\", \"text/event-stream\")\n    let stream = http.post_json_stream(\"http://127.0.0.1:{}/sse\", \"{{\\\"stream\\\":true}}\")\n    let status = http.stream_status(stream)\n    if status != 200 {{\n        discard http.stream_close(stream)\n        return status\n    }}\n    let first = read_event_type(stream)\n    let second = read_event_type(stream)\n    let second_data = read_event_data(stream)\n    let third = read_event_type(stream)\n    discard http.stream_close(stream)\n    if first == \"message_start\" && second == \"content_block_delta\" && second_data == \"{{\\\"type\\\":\\\"text_delta\\\",\\\"text\\\":\\\"hi\\\"}}\" && third == \"message_stop\" {{\n        return 0\n    }}\n    return 17\n}}\n",
                addr.port()
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("http streaming runtime program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        server.join().expect("server thread should finish");
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn cancel_task_runs_worker_cleanup_and_closes_proc_handle() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-cancel-task-cleanup-{suffix}.fzy"));
        let started_path =
            std::env::temp_dir().join(format!("fozzylang-cancel-task-started-{suffix}.txt"));
        let cleanup_path =
            std::env::temp_dir().join(format!("fozzylang-cancel-task-cleanup-{suffix}.txt"));
        let quoted_started = started_path.to_string_lossy().replace('\"', "\\\"");
        let quoted_cleanup = cleanup_path.to_string_lossy().replace('\"', "\\\"");
        let _ = std::fs::remove_file(&started_path);
        let _ = std::fs::remove_file(&cleanup_path);
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 5\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    fs.write_file(\"{quoted_started}\", \"started\")\n    loop {{\n        if recv() != 0 {{\n            fs.write_file(\"{quoted_cleanup}\", \"cancelled\")\n            return 0\n        }}\n        checkpoint()\n    }}\n}}\n\nfn main() -> i32 {{\n    let task = spawn(worker)\n    while fs.exists(\"{quoted_started}\") == 0 {{\n        checkpoint()\n    }}\n    discard cancel_task(task)\n    if fs.read_file(\"{quoted_cleanup}\") == \"cancelled\" {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("cancel_task runtime program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        assert_eq!(
            std::fs::read_to_string(&cleanup_path).expect("cleanup file should exist"),
            "cancelled"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(started_path);
        let _ = std::fs::remove_file(cleanup_path);
    }

    #[test]
    fn task_group_cancel_runs_worker_cleanup_and_closes_proc_handles() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-cleanup-{suffix}.fzy"));
        let left_started =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-left-started-{suffix}.txt"));
        let right_started =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-right-started-{suffix}.txt"));
        let left_cleanup =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-left-cleanup-{suffix}.txt"));
        let right_cleanup =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-right-cleanup-{suffix}.txt"));
        let quoted_left_started = left_started.to_string_lossy().replace('\"', "\\\"");
        let quoted_right_started = right_started.to_string_lossy().replace('\"', "\\\"");
        let quoted_left_cleanup = left_cleanup.to_string_lossy().replace('\"', "\\\"");
        let quoted_right_cleanup = right_cleanup.to_string_lossy().replace('\"', "\\\"");
        let _ = std::fs::remove_file(&left_started);
        let _ = std::fs::remove_file(&right_started);
        let _ = std::fs::remove_file(&left_cleanup);
        let _ = std::fs::remove_file(&right_cleanup);
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn left_worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 5\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    fs.write_file(\"{quoted_left_started}\", \"started\")\n    loop {{\n        if recv() != 0 {{\n            fs.write_file(\"{quoted_left_cleanup}\", \"cancelled\")\n            return 0\n        }}\n        checkpoint()\n    }}\n}}\n\nfn right_worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 5\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    fs.write_file(\"{quoted_right_started}\", \"started\")\n    loop {{\n        if recv() != 0 {{\n            fs.write_file(\"{quoted_right_cleanup}\", \"cancelled\")\n            return 0\n        }}\n        checkpoint()\n    }}\n}}\n\nfn main() -> i32 {{\n    let group = task.group_begin()\n    discard task.group_spawn(group, left_worker)\n    discard task.group_spawn(group, right_worker)\n    while fs.exists(\"{quoted_left_started}\") == 0 || fs.exists(\"{quoted_right_started}\") == 0 {{\n        checkpoint()\n    }}\n    discard task.group_cancel(group)\n    if fs.read_file(\"{quoted_left_cleanup}\") == \"cancelled\" && fs.read_file(\"{quoted_right_cleanup}\") == \"cancelled\" {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("task.group_cancel runtime program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        assert_eq!(
            std::fs::read_to_string(&left_cleanup).expect("left cleanup file should exist"),
            "cancelled"
        );
        assert_eq!(
            std::fs::read_to_string(&right_cleanup).expect("right cleanup file should exist"),
            "cancelled"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(left_started);
        let _ = std::fs::remove_file(right_started);
        let _ = std::fs::remove_file(left_cleanup);
        let _ = std::fs::remove_file(right_cleanup);
    }

    #[test]
    fn http_stream_read_line_respects_task_local_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should resolve");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).expect("server read should succeed");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .expect("server headers should write");
            stream.flush().expect("headers flush should succeed");
            std::thread::sleep(std::time::Duration::from_millis(150));
            stream
                .write_all(b"event: message_start\n\n")
                .expect("event write should succeed");
            stream.flush().expect("event flush should succeed");
        });

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-http-stream-timeout-{suffix}.fzy"));
        std::fs::write(
            &source,
            format!(
                "use core.http;\nuse core.thread;\n\nfn main() -> i32 {{\n    discard http.header_set(\"accept\", \"text/event-stream\")\n    timeout(25)\n    let stream = http.post_json_stream(\"http://127.0.0.1:{}/sse\", \"{{\\\"stream\\\":true}}\")\n    defer http.stream_close(stream)\n    if http.stream_status(stream) != 200 {{\n        return http.stream_status(stream)\n    }}\n    let line = http.stream_read_line(stream)\n    let err = http.stream_error(stream)\n    if line == \"\" && (http.stream_eof(stream) == 1 || str.len(err) > 0) {{\n        return 0\n    }}\n    return 17\n}}\n",
                addr.port()
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("http stream timeout program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        server.join().expect("server thread should finish");
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn request_handler_spawns_preserve_join_results_and_json_response() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-spawn-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_spawn\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_spawn\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.http;\nuse core.proc;\nuse core.thread;\n\nfn probe_worker() -> i32 {{\n    return 7\n}}\n\nfn left_worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'exit 0'\")\n}}\n\nfn right_worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'exit 0'\")\n}}\n\nfn write_response(conn: HttpHandle) -> i32 {{\n    let probe = spawn(probe_worker)\n    let left = spawn(left_worker)\n    let right = spawn(right_worker)\n    let probe_result = join(probe)\n    let left_result = join(left)\n    let right_result = join(right)\n    if probe_result == 7 && left_result == 0 && right_result == 0 {{\n        let payload = map.new()\n        discard map.set(payload, \"probe_result\", json.str(\"7\"))\n        discard map.set(payload, \"left_result\", json.str(\"0\"))\n        discard map.set(payload, \"right_result\", json.str(\"0\"))\n        http.write_json(conn, 200, json.object(payload))\n        return 0\n    }}\n    let err = map.new()\n    discard map.set(err, \"probe_result\", json.str(\"bad\"))\n    discard map.set(err, \"left_result\", json.str(\"bad\"))\n    discard map.set(err, \"right_result\", json.str(\"bad\"))\n    http.write_json(conn, 500, json.object(err))\n    return 13\n}}\n\nfn main() -> i32 {{\n    let listener = http.bind()\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let conn = http.accept()\n    http.read(conn)\n    let method = http.method(conn)\n    let path = http.path(conn)\n    if method == \"POST\" && path == \"/tools/parallel_bash/run\" {{\n        return write_response(conn)\n    }}\n    http.write_json(conn, 404, \"{{}}\")\n    return 0\n}}\n",
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(
            artifact.status,
            "ok",
            "request-path spawn repro should compile cleanly: diagnostics={:#?}, root={}",
            artifact.diagnostic_details,
            root.display()
        );
        let binary = artifact.output.unwrap_or_else(|| {
            panic!(
                "build artifact should include output path: root={}",
                root.display()
            )
        });

        let mut child = std::process::Command::new(&binary)
            .env("AGENT_HOST", "127.0.0.1")
            .env("AGENT_PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        use std::io::{Read as _, Write as _};
        stream
            .write_all(
                b"POST /tools/parallel_bash/run HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.contains("\"probe_result\":\"7\""),
            "response should preserve probe result json: {response}"
        );
        assert!(
            response.contains("\"left_result\":\"0\""),
            "response should preserve left result json: {response}"
        );
        assert!(
            response.contains("\"right_result\":\"0\""),
            "response should preserve right result json: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn host_backed_http_read_succeeds_after_poll_registration() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-read-poll-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_read_poll\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_read_poll\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            "use core.http;\n\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    if http.listen(listener) != 0 {\n        return 21\n    }\n    let conn = http.accept()\n    if http.poll_register(conn) != 0 {\n        discard http.close(conn)\n        return 23\n    }\n    discard http.poll_next()\n    let read_status = http.read(conn)\n    if read_status != 0 {\n        http.write(conn, 503, \"{\\\"error\\\":\\\"read_failed\\\"}\")\n        return 25\n    }\n    http.write(conn, 200, \"ok\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .env("AGENT_HOST", "127.0.0.1")
            .env("AGENT_PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.ends_with("ok"),
            "response body should be ok: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn request_handler_body_json_stays_stable_under_repeated_json_churn() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-body-json-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_body_json\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_body_json\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            "use core.http;\n\nfn write_echo(conn: HttpHandle, body: JsonHandle) -> i32 {\n    let message = json.get_str(body, \"message\")\n    let tag = json.get_str(body, \"tag\")\n    let meta = map.new()\n    discard map.set(meta, \"message\", json.str(message))\n    discard map.set(meta, \"tag\", json.str(tag))\n    discard map.set(meta, \"kind\", json.str(\"body_json\"))\n    let items = list.new()\n    discard list.push(items, json.str(message))\n    discard list.push(items, json.str(tag))\n    discard list.push(items, json.object(meta))\n    let payload = map.new()\n    discard map.set(payload, \"ok\", json.raw(\"true\"))\n    discard map.set(payload, \"message\", json.str(message))\n    discard map.set(payload, \"tag\", json.str(tag))\n    discard map.set(payload, \"echo\", json.object(meta))\n    discard map.set(payload, \"items\", json.array(items))\n    return http.write_json(conn, 200, json.object(payload))\n}\n\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    if http.listen(listener) != 0 {\n        return 21\n    }\n    let mut served = 0\n    while served < 12 {\n        let conn = http.accept()\n        http.read(conn)\n        let method = http.method(conn)\n        let path = http.path(conn)\n        if method == \"POST\" && path == \"/echo\" {\n            let body = http.body_json(conn)\n            discard write_echo(conn, body)\n        } else {\n            http.write_json(conn, 404, \"{}\")\n        }\n        served = served + 1\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .env("AGENT_HOST", "127.0.0.1")
            .env("AGENT_PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        for idx in 0..12 {
            let start = std::time::Instant::now();
            let mut stream = loop {
                match std::net::TcpStream::connect(("127.0.0.1", port)) {
                    Ok(stream) => break stream,
                    Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(error) => {
                        let _ = child.kill();
                        panic!("request should connect: {error}");
                    }
                }
            };
            let body = format!(
                "{{\"message\":\"msg-{idx}\",\"tag\":\"tag-{idx}\",\"meta\":{{\"slot\":\"{idx}\"}}}}"
            );
            let request = format!(
                "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(request.as_bytes())
                .expect("request should write");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("response should read");
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "response was: {response}"
            );
            assert!(
                response.contains(&format!("\"message\":\"msg-{idx}\"")),
                "response should preserve message field: {response}"
            );
            assert!(
                response.contains(&format!("\"tag\":\"tag-{idx}\"")),
                "response should preserve tag field: {response}"
            );
            assert!(
                response.contains("\"ok\":true"),
                "response should preserve raw boolean field: {response}"
            );
            assert!(
                response.contains("\"kind\":\"body_json\""),
                "response should preserve nested echo metadata: {response}"
            );
            assert!(
                !response.trim_end().ends_with("{}"),
                "response should not collapse to an empty json object: {response}"
            );
        }

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn host_backed_http_read_preserves_prefetched_content_length_body() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-prefetched-body-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_prefetched_body\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_prefetched_body\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            "use core.http;\n\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    if http.listen(listener) != 0 {\n        return 21\n    }\n    let conn = http.accept()\n    if http.read(conn) != 0 {\n        discard http.close(conn)\n        return 23\n    }\n    let body = http.body(conn)\n    discard http.write_response(conn, 200, \"application/json; charset=utf-8\", body, 1)\n    if body == \"{\\\"ok\\\":true}\" {\n        return 0\n    }\n    return 25\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .env("AGENT_HOST", "127.0.0.1")
            .env("AGENT_PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        let body = "{\"ok\":true}";
        let request = format!(
            "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.contains("{\"ok\":true}"),
            "prefetched request body should survive http.read buffering: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn storage_kv_roundtrips_and_closes_handles_cleanly() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-storage-roundtrip-{suffix}"));
        let source = root.join("src/main.fzy");
        let out_path = root.join("out.txt");
        let store_path = root.join("store.kv");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"storage_roundtrip\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"storage_roundtrip\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.storage;\n\nfn main() -> i32 {{\n    let left = storage.kv_open(\"{}\")\n    discard storage.kv_put(left, \"session:key\", \"value\")\n    let right = storage.kv_open(\"{}\")\n    discard fs.write_file(\"{}\", storage.kv_get(right, \"session:key\"))\n    discard storage.kv_close(left)\n    discard storage.kv_close(right)\n    return 0\n}}\n",
                store_path.display(),
                store_path.display(),
                out_path.display(),
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("storage roundtrip should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        let persisted = std::fs::read_to_string(&out_path).expect("roundtrip output should exist");
        assert_eq!(persisted, "value");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fz_run_matches_direct_binary_for_child_process_build_orchestration() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-run-parity-{suffix}"));
        let source = root.join("src/main.fzy");
        let fixture_root = root.join("fixture-project");
        let report_path = fixture_root.join("configure.report.json");
        let config_path = fixture_root.join("demo.toml");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::create_dir_all(&fixture_root).expect("fixture root should be created");
        std::fs::write(&config_path, "name = \"demo\"\n").expect("config should be written");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"run_parity\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"run_parity\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            r#"use core.fs;
use core.proc;
use core.process;

fn find_flag(args: ListHandle, name: str) -> str {
    let mut idx = 0
    while idx < list.len(args) {
        if list.get(args, idx) == name {
            if idx + 1 < list.len(args) {
                return list.get(args, idx + 1)
            }
            return ""
        }
        idx += 1
    }
    return ""
}

fn argv_list() -> ListHandle {
    let out = list.new()
    let mut idx = 0
    while idx < process.argv_count() {
        discard list.push(out, process.argv_or(idx, ""))
        idx += 1
    }
    return out
}

fn run_build(project_root: str) -> i32 {
    let env_map = proc.env_new()
    let argv = proc.argv_new()
    let report = str.concat(project_root, "/configure.report.json")
    let command = str.concat("printf '{\"status\":\"0\",\"stdout\":\"configured\",\"stderr\":\"\"}' > ", report)
    discard proc.argv_push(argv, "-lc")
    discard proc.argv_push(argv, command)
    let handle = proc.spawn_cmd("/bin/sh", argv, env_map, "")
    discard proc.wait(handle, 5000)
    let exit_code = proc.exit_code(handle)
    discard proc.stdout(handle)
    discard proc.stderr(handle)
    discard proc.close(handle)
    let payload = fs.read_file(report)
    if exit_code == 0 && str.contains(payload, "\"status\":\"0\"") == 1 {
        return 0
    }
    return 1
}

fn main() -> i32 {
    let args = argv_list()
    let command = process.argv_or(1, "")
    let project_root = find_flag(args, "--project")
    discard find_flag(args, "--config")
    if command == "build" && project_root != "" {
        return run_build(project_root)
    }
    return 64
}
"#,
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .clone()
            .expect("build artifact should include output path");

        let direct = std::process::Command::new(&binary)
            .args([
                "build",
                "--project",
                fixture_root.to_string_lossy().as_ref(),
                "--config",
                config_path.to_string_lossy().as_ref(),
            ])
            .output()
            .expect("direct binary should run");
        assert_eq!(direct.status.code(), Some(0));
        assert!(std::fs::read_to_string(&report_path)
            .expect("report should exist after direct run")
            .contains("\"status\":\"0\""));

        let _ = std::fs::remove_file(&report_path);
        let wrapped = run(
            Command::Run {
                path: root.clone(),
                args: vec![
                    "build".to_string(),
                    "--project".to_string(),
                    fixture_root.display().to_string(),
                    "--config".to_string(),
                    config_path.display().to_string(),
                ],
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("wrapped run should succeed");
        assert!(
            wrapped.contains("\"exitCode\":0"),
            "unexpected wrapped output: {wrapped}"
        );
        assert!(std::fs::read_to_string(&report_path)
            .expect("report should exist after wrapped run")
            .contains("\"status\":\"0\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn response_headers_support_custom_and_repeated_set_cookie_values() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-response-headers-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_response_headers\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_response_headers\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            "use core.http;\n\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    if http.listen(listener) != 0 {\n        return 21\n    }\n    let conn = http.accept()\n    if http.read(conn) != 0 {\n        discard http.close(conn)\n        return 23\n    }\n    discard http.response_header_set(conn, \"X-Test\", \"present\")\n    discard http.response_header_add(conn, \"Set-Cookie\", \"sid=abc; Path=/; HttpOnly\")\n    discard http.response_header_add(conn, \"Set-Cookie\", \"pref=dark; Path=/; Secure\")\n    discard http.write_response(conn, 200, \"text/plain; charset=utf-8\", \"ok\", 1)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .env("AGENT_HOST", "127.0.0.1")
            .env("AGENT_PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.contains("X-Test: present"),
            "custom header missing from response: {response}"
        );
        assert!(
            response.contains("Set-Cookie: sid=abc; Path=/; HttpOnly"),
            "first set-cookie missing from response: {response}"
        );
        assert!(
            response.contains("Set-Cookie: pref=dark; Path=/; Secure"),
            "second set-cookie missing from response: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn request_body_streaming_reads_chunked_uploads_incrementally() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-body-stream-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_body_stream\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_body_stream\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            "use core.http;\n\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    if http.listen(listener) != 0 {\n        return 21\n    }\n    let conn = http.accept()\n    if http.read_headers(conn) != 0 {\n        discard http.close(conn)\n        return 23\n    }\n    let mut body = \"\"\n    while http.body_eof(conn) == 0 {\n        body = str.concat(body, http.body_read(conn, 4))\n    }\n    discard http.write_response(conn, 200, \"text/plain; charset=utf-8\", body, 1)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .env("AGENT_HOST", "127.0.0.1")
            .env("AGENT_PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("request should connect: {error}");
                }
            }
        };
        stream
            .write_all(
                b"POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nstre\r\n4\r\namin\r\n2\r\ng!\r\n0\r\n\r\n",
            )
            .expect("chunked request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.ends_with("streaming!"),
            "streamed body should round-trip through response: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn websocket_upgrade_supports_text_frame_round_trip() {
        fn read_http_headers(stream: &mut std::net::TcpStream) -> String {
            use std::io::Read as _;
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 256];
                let read = stream.read(&mut chunk).expect("header read should succeed");
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            String::from_utf8_lossy(&buf).to_string()
        }

        fn write_masked_text_frame(stream: &mut std::net::TcpStream, text: &str) {
            use std::io::Write as _;
            let payload = text.as_bytes();
            let mask = [0x11u8, 0x22, 0x33, 0x44];
            let mut frame = Vec::new();
            frame.push(0x81u8);
            frame.push(0x80u8 | payload.len() as u8);
            frame.extend_from_slice(&mask);
            for (idx, byte) in payload.iter().enumerate() {
                frame.push(byte ^ mask[idx % 4]);
            }
            stream.write_all(&frame).expect("frame should write");
        }

        fn read_ws_frame(stream: &mut std::net::TcpStream) -> (u8, Vec<u8>) {
            use std::io::Read as _;
            let mut hdr = [0u8; 2];
            stream
                .read_exact(&mut hdr)
                .expect("frame header should read");
            let opcode = hdr[0] & 0x0f;
            let mut len = (hdr[1] & 0x7f) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                stream
                    .read_exact(&mut ext)
                    .expect("extended len should read");
                len = u16::from_be_bytes(ext) as usize;
            }
            let mut payload = vec![0u8; len];
            if len > 0 {
                stream
                    .read_exact(&mut payload)
                    .expect("payload should read");
            }
            (opcode, payload)
        }

        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-websocket-upgrade-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"websocket_upgrade\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"websocket_upgrade\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            "use core.http;\n\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    if http.listen(listener) != 0 {\n        return 21\n    }\n    let conn = http.accept()\n    defer close(conn)\n    if http.read_headers(conn) != 0 {\n        return 23\n    }\n    let ws = http.websocket_accept(conn)\n    let message = http.websocket_read(ws, 256)\n    let kind = http.websocket_kind(ws)\n    if kind != \"text\" || message != \"hello\" {\n        discard http.websocket_close(ws, 1002, \"protocol\")\n        return 25\n    }\n    discard http.websocket_write_text(ws, \"world\")\n    discard http.websocket_close(ws, 1000, \"bye\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .env("AGENT_HOST", "127.0.0.1")
            .env("AGENT_PORT", port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::Write as _;
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("request should connect: {error}");
                }
            }
        };
        stream
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .expect("websocket upgrade should write");
        let response = read_http_headers(&mut stream);
        assert!(
            response.starts_with("HTTP/1.1 101"),
            "upgrade response was: {response}"
        );
        assert!(
            response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "accept hash missing from response: {response}"
        );

        write_masked_text_frame(&mut stream, "hello");
        let (opcode, payload) = read_ws_frame(&mut stream);
        assert_eq!(opcode, 0x1, "expected text frame opcode");
        assert_eq!(String::from_utf8_lossy(&payload), "world");
        let (close_opcode, close_payload) = read_ws_frame(&mut stream);
        assert_eq!(close_opcode, 0x8, "expected close frame opcode");
        assert!(close_payload.len() >= 2, "close payload missing code");
        assert_eq!(
            u16::from_be_bytes([close_payload[0], close_payload[1]]),
            1000
        );

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn run_supports_same_function_name_in_sibling_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-module-collision-{suffix}"));
        std::fs::create_dir_all(&root).expect("root should be created");
        let main = root.join("main.fzy");
        std::fs::write(
            &main,
            "mod a;\nmod b;\nfn main() -> i32 {\n    let sum: i32 = a.ping() + b.ping()\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("a.fzy"), "fn ping() -> i32 {\n    return 1\n}\n")
            .expect("a module should be written");
        std::fs::write(root.join("b.fzy"), "fn ping() -> i32 {\n    return 2\n}\n")
            .expect("b module should be written");

        let check = run(Command::Check { path: main.clone() }, Format::Json)
            .expect("check should succeed for sibling name collisions");
        assert!(check.contains("\"errors\":0"));
        let run_output = run(
            Command::Run {
                path: main.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run should succeed for sibling name collisions");
        assert!(run_output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compiler_phase_fixture_check_verify_build_and_parity_stay_aligned() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/compiler_phase_lockin");

        let check = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("check should succeed for compiler phase fixture");
        let check_payload: serde_json::Value =
            serde_json::from_str(&check).expect("check output should be valid json");
        assert_eq!(check_payload["errors"].as_u64(), Some(0));
        assert_eq!(check_payload["module"].as_str(), Some("main"));

        let verify = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should succeed for compiler phase fixture");
        let verify_payload: serde_json::Value =
            serde_json::from_str(&verify).expect("verify output should be valid json");
        assert_eq!(verify_payload["errors"].as_u64(), Some(0));
        assert_eq!(verify_payload["warnings"].as_u64(), Some(0));

        let build = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed for compiler phase fixture");
        let build_payload: serde_json::Value =
            serde_json::from_str(&build).expect("build output should be valid json");
        assert_eq!(build_payload["status"].as_str(), Some("ok"));
        assert!(build_payload["dependencyGraphHash"].is_string());
        assert_eq!(
            build_payload["policy"]["lockfileState"].as_str(),
            Some("present")
        );

        let parity = run(
            Command::Parity {
                path: root.clone(),
                seed: Some(4242),
            },
            Format::Json,
        )
        .expect("parity should succeed for compiler phase fixture");
        let parity_payload: serde_json::Value =
            serde_json::from_str(&parity).expect("parity output should be valid json");
        assert_eq!(parity_payload["ok"].as_bool(), Some(true));
        assert_eq!(
            parity_payload["checks"]["sameVerifierResult"].as_bool(),
            Some(true)
        );
        assert_eq!(
            parity_payload["checks"]["sameExitCode"].as_bool(),
            Some(true)
        );
        assert_eq!(parity_payload["checks"]["sameStdout"].as_bool(), Some(true));
        assert_eq!(
            parity_payload["checks"]["sameRuntimeBehavior"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn compiler_phase_commands_invalidate_import_cache_and_recover_after_fix() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-command-cache-{suffix}"));
        std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"compiler_cache\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"compiler_cache\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.term;\nmod services;\nfn main() -> i32 {\n    discard term.write(\"cache-check\\n\")\n    return services.boot()\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("service source should be written");

        let first = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("first check should succeed");
        let first_payload: serde_json::Value =
            serde_json::from_str(&first).expect("first check should be valid json");
        assert_eq!(first_payload["errors"].as_u64(), Some(0));

        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn renamed() -> i32 {\n    return 0\n}\n",
        )
        .expect("service source should mutate");

        let broken_check = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("broken check should return diagnostics");
        let broken_check_payload: serde_json::Value =
            serde_json::from_str(&broken_check).expect("broken check should be valid json");
        assert!(broken_check_payload["errors"].as_u64().unwrap_or(0) > 0);
        let broken_messages = broken_check_payload["items"]
            .as_array()
            .expect("diagnostic items should be an array")
            .iter()
            .filter_map(|item| item["message"].as_str())
            .collect::<Vec<_>>();
        assert!(broken_messages
            .iter()
            .any(|message| message.contains("unresolved call target `services.boot`")));

        let broken_verify = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("broken verify should return diagnostics");
        let broken_verify_payload: serde_json::Value =
            serde_json::from_str(&broken_verify).expect("broken verify should be valid json");
        assert!(broken_verify_payload["errors"].as_u64().unwrap_or(0) > 0);

        let broken_build = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("broken build should return diagnostics");
        let broken_build_payload: serde_json::Value =
            serde_json::from_str(&broken_build).expect("broken build should be valid json");
        assert_eq!(broken_build_payload["status"].as_str(), Some("error"));

        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("service source should be restored");

        let repaired_build = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("repaired build should succeed");
        let repaired_build_payload: serde_json::Value =
            serde_json::from_str(&repaired_build).expect("repaired build should be valid json");
        assert_eq!(repaired_build_payload["status"].as_str(), Some("ok"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compiler_phase_fixture_host_backed_run_stays_warning_free() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/compiler_phase_lockin");

        let output = run(
            Command::Run {
                path: root,
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backed run should succeed for compiler phase fixture");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("run output should be valid json");
        assert_eq!(payload["status"].as_str(), Some("ok"));
        assert_eq!(payload["diagnostics"].as_u64(), Some(0));
        assert_eq!(payload["exitCode"].as_i64(), Some(0));
    }

    #[test]
    fn compiler_phase_invalid_programs_emit_diagnostics_not_panics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-command-invalid-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"compiler_invalid\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"compiler_invalid\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main( -> i32 {\n    return 0\n}\n",
        )
        .expect("invalid source should be written");

        for output in [
            run(Command::Check { path: root.clone() }, Format::Json)
                .expect("check should return diagnostics"),
            run(Command::Verify { path: root.clone() }, Format::Json)
                .expect("verify should return diagnostics"),
        ] {
            assert!(
                !output.contains("panicked at"),
                "compiler command should emit diagnostics instead of panicking: {output}"
            );
            let payload: serde_json::Value =
                serde_json::from_str(&output).expect("command output should be valid json");
            let errors = payload["errors"]
                .as_u64()
                .unwrap_or_else(|| payload["diagnostics"].as_u64().unwrap_or(0));
            assert!(
                errors > 0,
                "invalid source should produce errors: {payload}"
            );
        }

        let build_error = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect_err("build should fail cleanly for invalid source");
        assert!(
            !build_error.to_string().contains("panicked at"),
            "build should fail with diagnostics, not panic: {build_error}"
        );
        assert!(
            build_error.to_string().contains("parse failed"),
            "build failure should preserve parser diagnostics: {build_error}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_run_host_backends_preserves_live_run_semantics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-backend-flag-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native host backend run should stay on the live run path");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        assert!(!output.contains("\"bridge\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_preserves_cli_args_and_terminal_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-term-args-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.process;\nuse core.term;\n\nfn main() -> i32 {\n    let argc = process.argv_count()\n    let cmd = process.command_name()\n    let mode = process.argv_or(1, \"\")\n    let flag = process.argv_or(2, \"\")\n    discard term.print_line(str.concat(\"argc=\", str.from_i32(argc)))\n    discard term.print_line(str.concat(\"cmd=\", cmd))\n    discard term.print_line(str.concat(\"mode=\", mode))\n    discard term.eprint_line(str.concat(\"flag=\", flag))\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: vec!["serve".to_string(), "--json".to_string()],
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native run with cli args should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("argc=3"), "output was: {output}");
        assert!(output.contains("mode=serve"), "output was: {output}");
        assert!(output.contains("flag=--json"), "output was: {output}");
        assert!(output.contains("\"stdout\":\""), "output was: {output}");
        assert!(output.contains("\"stderr\":\""), "output was: {output}");

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_host_backends_preserves_cli_args_and_terminal_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-term-host-args-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.process;\nuse core.term;\n\nfn main() -> i32 {\n    discard term.print_line(str.concat(\"argc=\", str.from_i32(process.argv_count())))\n    discard term.print_line(str.concat(\"mode=\", process.argv_or(1, \"\")))\n    discard term.eprint_line(str.concat(\"flag=\", process.argv_or(2, \"\")))\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: vec!["serve".to_string(), "--json".to_string()],
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: Some(10),
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native host backend run with cli args should succeed");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("argc=3"), "output was: {output}");
        assert!(output.contains("mode=serve"), "output was: {output}");
        assert!(output.contains("flag=--json"), "output was: {output}");

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_core_log_policy_routes_and_filters_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-log-policy-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.log;\n\nfn main() -> i32 {\n    let hidden = map.new()\n    let shown = map.new()\n    discard map.set(hidden, \"phase\", \"hidden\")\n    discard map.set(shown, \"phase\", \"shown\")\n    discard log.set_enabled(1)\n    discard log.set_sink_name(\"stderr\")\n    discard log.set_level_name(\"warn\")\n    discard log.info(\"hidden-info\", log.fields(hidden))\n    discard log.warn(\"shown-warn\", log.fields(shown))\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native log policy run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("shown-warn"), "output was: {output}");
        assert!(!output.contains("hidden-info"), "output was: {output}");
        assert!(output.contains("\"stderr\":\""), "output was: {output}");

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_core_text_and_transcript_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-core-text-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-core-text-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.term;\nuse core.text;\n\nfn main() -> i32 {{\n    let payload = map.new()\n    discard map.set(payload, \"left\", json.str(text.pad_left(\"7\", 3)))\n    discard map.set(payload, \"right\", json.str(text.pad_right(\"ok\", 4)))\n    discard map.set(payload, \"indented\", json.str(text.indent(\"a\\nb\", \"> \")))\n    discard map.set(payload, \"ansi_width\", json.str(str.from_i32(text.visible_len_ansi(\"\\x1b[31mred\\x1b[0m\"))))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    discard term.transcript_kv(\"mode\", \"chat\", 8)\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("core text helpers run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("mode     chat"), "output was: {output}");
        let content =
            std::fs::read_to_string(&out_path).expect("core text helper output should exist");
        assert!(
            content.contains("\"left\":\"  7\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"right\":\"ok  \""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"ansi_width\":\"3\""),
            "content was: {content}"
        );
        assert!(content.contains("> a\\n> b"), "content was: {content}");

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_string_slice_and_ascii_case_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-str-slice-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-str-slice-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.text;\n\nfn main() -> i32 {{\n    let payload = map.new()\n    discard map.set(payload, \"0\", json.str(str.slice(\"name\", 0, 1)))\n    discard map.set(payload, \"1\", json.str(str.slice(\"name\", 1, 2)))\n    discard map.set(payload, \"2\", json.str(str.slice(\"name\", 2, 3)))\n    discard map.set(payload, \"3\", json.str(str.slice(\"name\", 3, 4)))\n    discard map.set(payload, \"upper\", json.str(text.upper_ascii(\"tool_arg_name\")))\n    discard map.set(payload, \"lower\", json.str(text.lower_ascii(\"TOOL_ARG_NAME\")))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("string slice/case runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");
        let content =
            std::fs::read_to_string(&out_path).expect("string slice/case output should exist");
        assert!(content.contains("\"0\":\"n\""), "content was: {content}");
        assert!(content.contains("\"1\":\"a\""), "content was: {content}");
        assert!(content.contains("\"2\":\"m\""), "content was: {content}");
        assert!(content.contains("\"3\":\"e\""), "content was: {content}");
        assert!(
            content.contains("\"upper\":\"TOOL_ARG_NAME\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"lower\":\"tool_arg_name\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_mutable_string_accumulation_persists_concat_results() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-str-accumulate-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-str-accumulate-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn upper_char(ch: str) -> str {{\n    if ch == \"a\" {{ return \"A\" }}\n    if ch == \"n\" {{ return \"N\" }}\n    if ch == \"m\" {{ return \"M\" }}\n    if ch == \"e\" {{ return \"E\" }}\n    return ch\n}}\n\nfn main() -> i32 {{\n    let payload = map.new()\n    let mut serial = \"\"\n    serial = str.concat(serial, \"N\")\n    serial = str.concat(serial, \"A\")\n    serial = str.concat(serial, \"M\")\n    serial = str.concat(serial, \"E\")\n    let mut from_slice = \"\"\n    let value = \"name\"\n    let mut idx: i32 = 0\n    while idx < str.len(value) {{\n        from_slice = str.concat(from_slice, upper_char(str.slice(value, idx, idx + 1)))\n        idx += 1\n    }}\n    discard map.set(payload, \"direct\", json.str(str.concat(\"A\", \"B\")))\n    discard map.set(payload, \"serial\", json.str(serial))\n    discard map.set(payload, \"slice_loop\", json.str(from_slice))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("mutable string accumulation runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");
        let content = std::fs::read_to_string(&out_path)
            .expect("mutable string accumulation output should exist");
        assert!(
            content.contains("\"direct\":\"AB\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"serial\":\"NAME\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"slice_loop\":\"NAME\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_core_io_and_path_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-core-io-{suffix}"));
        let nested = root.join("custom_tools");
        std::fs::create_dir_all(&nested).expect("nested directory should be created");
        std::fs::write(nested.join("tool.json"), "{\"name\":\"demo\"}")
            .expect("probe file should be created");
        let source = std::env::temp_dir().join(format!("fozzylang-core-io-{suffix}.fzy"));
        let quoted_root = root.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.io;\nuse core.path;\n\nfn main() -> i32 {{\n    let dir = path.join(\"{quoted_root}\", \"custom_tools\")\n    let entries = io.list_dir(dir)\n    if list.len(entries) != 1 {{\n        return 11\n    }}\n    if list.get(entries, 0) != \"tool.json\" {{\n        return 12\n    }}\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("core io/path helpers run should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_binary_reads_piped_stdin_and_reports_non_tty_mode() {
        use std::io::Write as _;

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-term-stdin-{suffix}"));
        let source = root.join("src/main.fzy");
        let out_path = std::env::temp_dir().join(format!("fozzylang-term-stdin-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"term_stdin\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"term_stdin\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.term;\n\nfn main() -> i32 {{\n    let line = term.read_line()\n    let eof_before = term.stdin_eof()\n    let second = term.read_line()\n    let eof_after = term.stdin_eof()\n    let payload = map.new()\n    discard map.set(payload, \"line\", json.str(line))\n    discard map.set(payload, \"second\", json.str(second))\n    discard map.set(payload, \"eof_before\", json.str(str.from_i32(eof_before)))\n    discard map.set(payload, \"eof_after\", json.str(str.from_i32(eof_after)))\n    discard map.set(payload, \"stdin_tty\", json.str(str.from_i32(term.stdin_is_tty())))\n    discard map.set(payload, \"stdout_tty\", json.str(str.from_i32(term.stdout_is_tty())))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    discard term.print(\"prompt> \")\n    discard term.eprint_line(\"warn\")\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("binary should spawn");
        child
            .stdin
            .take()
            .expect("stdin pipe should exist")
            .write_all(b"hello world\n")
            .expect("stdin should write");
        let output = child.wait_with_output().expect("child should exit");
        assert_eq!(output.status.code(), Some(0));

        let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
        let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
        assert!(stdout.contains("prompt> "), "stdout was: {stdout}");
        assert!(stderr.contains("warn"), "stderr was: {stderr}");

        let content =
            std::fs::read_to_string(&out_path).expect("stdin runtime output should exist");
        assert!(
            content.contains("\"line\":\"hello world\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"second\":\"\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"eof_before\":\"0\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"eof_after\":\"1\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"stdin_tty\":\"0\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"stdout_tty\":\"0\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_json_array_traversal_and_raw_extraction_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-json-array-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-json-array-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn main() -> i32 {{\n    let parsed = json.parse(\"{{\\\"content\\\":[{{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"hi\\\"}},{{\\\"type\\\":\\\"tool_use\\\",\\\"name\\\":\\\"bash\\\",\\\"input\\\":{{\\\"command\\\":\\\"printf ok\\\"}}}}]}}\")\n    let content = json.get(parsed, \"content\")\n    let block0 = json.get(content, \"0\")\n    let block1 = json.get(content, \"1\")\n    let input = json.get(block1, \"input\")\n    let out = map.new()\n    discard map.set(out, \"content_raw\", json.str(json.get_str(content, \"raw\")))\n    discard map.set(out, \"block0_type\", json.str(json.get_str(block0, \"type\")))\n    discard map.set(out, \"block0_text\", json.str(json.get_str(block0, \"text\")))\n    discard map.set(out, \"block1_type\", json.str(json.get_str(block1, \"type\")))\n    discard map.set(out, \"block1_name\", json.str(json.get_str(block1, \"name\")))\n    discard map.set(out, \"input_raw\", json.str(json.get_str(input, \"raw\")))\n    fs.write_file(\"{quoted_out}\", json.object(out))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("json array traversal runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let content =
            std::fs::read_to_string(&out_path).expect("json array traversal output should exist");
        assert!(
            content.contains("\"block0_type\":\"text\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"block0_text\":\"hi\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"block1_type\":\"tool_use\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"block1_name\":\"bash\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\\\"command\\\":\\\"printf ok\\\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\\\"type\\\":\\\"text\\\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_json_object_key_iteration_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-json-keys-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-json-keys-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn main() -> i32 {{\n    let parsed = json.parse(\"{{\\\"message\\\":\\\"hi\\\",\\\"count\\\":\\\"2\\\"}}\")\n    let keys = json.keys(parsed)\n    let child = json.get(parsed, list.get(keys, 0))\n    let as_map = json.to_map(parsed)\n    let out = map.new()\n    discard map.set(out, \"keys_len\", json.str(str.from_i32(list.len(keys))))\n    discard map.set(out, \"first_key\", json.str(list.get(keys, 0)))\n    discard map.set(out, \"first_raw\", json.str(json.get_str(child, \"raw\")))\n    discard map.set(out, \"map_keys_len\", json.str(str.from_i32(list.len(map.keys(as_map)))))\n    fs.write_file(\"{quoted_out}\", json.object(out))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("json object key iteration runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");
        let content =
            std::fs::read_to_string(&out_path).expect("json key iteration output should exist");
        assert!(
            content.contains("\"keys_len\":\"2\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"map_keys_len\":\"2\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"first_key\":\"message\"")
                || content.contains("\"first_key\":\"count\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"first_raw\":\"\\\"hi\\\"\"")
                || content.contains("\"first_raw\":\"\\\"2\\\"\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_host_backends_preserves_fs_side_effects_for_json_array_traversal() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-json-array-host-{suffix}"));
        let source = root.join("src/main.fzy");
        let out_path =
            std::env::temp_dir().join(format!("fozzylang-json-array-host-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"json_array_host\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"json_array_host\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn main() -> i32 {{\n    let parsed = json.parse(\"{{\\\"content\\\":[{{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"hi\\\"}},{{\\\"type\\\":\\\"tool_use\\\",\\\"name\\\":\\\"bash\\\",\\\"input\\\":{{\\\"command\\\":\\\"printf ok\\\"}}}}]}}\")\n    let content = json.get(parsed, \"content\")\n    let block1 = json.get(content, \"1\")\n    let input = json.get(block1, \"input\")\n    let out = map.new()\n    discard map.set(out, \"mode\", json.str(json.get_str(block1, \"type\")))\n    discard map.set(out, \"input_raw\", json.str(json.get_str(input, \"raw\")))\n    fs.write_file(\"{quoted_out}\", json.object(out))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: Some(10),
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backend json array traversal program should succeed");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        let content = std::fs::read_to_string(&out_path)
            .expect("host-backed runtime should preserve absolute fs side effect output");
        assert!(
            content.contains("\"mode\":\"tool_use\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\\\"command\\\":\\\"printf ok\\\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_variadic_str_concat_executes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-str-concat-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let value = str.concat(\"svc/\", \"tenant/\", \"sessions/\", \"abc\", \"/latest\")\n    if str.len(value) == 30 && str.starts_with(value, \"svc/\") == 1 && str.ends_with(value, \"/latest\") == 1 {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("variadic str.concat run should succeed");
        assert!(output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_string_conversion_and_path_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-path-format-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let rendered = str.concat(\"port=\", str.from_i32(8080), \", enabled=\", str.from_bool(true))\n    let joined = path.join(\"/srv/app\", \"config/runtime.json\")\n    if rendered != \"port=8080, enabled=true\" then return 11\n    if path.dirname(joined) != \"/srv/app/config\" then return 12\n    if path.basename(joined) != \"runtime.json\" then return 13\n    if path.stem(joined) != \"runtime\" then return 14\n    if path.extension(joined) != \"json\" then return 15\n    if path.normalize(\"/srv//app/config/\") != \"/srv/app/config\" then return 16\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("path/conversion run should succeed");
        assert!(output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_terminal_hex_and_unicode_escapes_preserve_ansi_bytes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-ansi-escape-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    discard term.write(\"\\x1b[31mred\\u001b[0m\\033\\n\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("ansi escape run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            output.contains("\\u001b[31mred\\u001b[0m\\u001b\\n")
                || output.contains("\u{001b}[31mred\u{001b}[0m\u{001b}\n"),
            "output was: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_project_root_host_backends_preserves_live_run_semantics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-host-project-run-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"host_project_run\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"host_project_run\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("project-root host backend run should stay on the live run path");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        assert!(!output.contains("\"bridge\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_run_host_backends_keeps_deterministic_bridge_mode() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-det-reject-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");

        let error = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native host-backed deterministic run should use the scenario bridge");
        assert!(error.contains("\"routing\":\"host-backed-scenario-bridge\""));
        assert!(error.contains("\"deterministicRequested\":true"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_project_root_host_backends_keeps_deterministic_bridge_mode() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-host-project-det-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"host_project_det\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"host_project_det\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("project-root host-backed deterministic run should use the scenario bridge");
        assert!(output.contains("\"routing\":\"host-backed-scenario-bridge\""));
        assert!(output.contains("\"deterministicRequested\":true"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_test_host_backends_materializes_requested_record_path() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-record-{suffix}.fzy"));
        let record =
            std::env::temp_dir().join(format!("fozzylang-host-record-{suffix}.trace.fozzy"));
        std::fs::write(
            &source,
            "test \"probe\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&record);

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: true,
                safe_profile: false,
                seed: Some(4242),
                record: Some(record.clone()),
                host_backends: true,
                backend: None,
                scheduler: None,
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("host-backed native test should materialize requested record path");
        assert!(output.contains("\"bridge\""));
        assert!(record.exists(), "requested record path should exist");
        let verify = fzscenario::verify_trace_file(&record).expect("trace should verify");
        assert!(
            verify.ok,
            "recorded trace should round-trip through current CLI"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(record);
    }

    #[test]
    fn host_backed_run_reports_prepare_and_recorded_trace_paths() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-run-{suffix}.fzy"));
        let record = std::env::temp_dir().join(format!("fozzylang-host-run-{suffix}.trace.fozzy"));
        std::fs::write(
            &source,
            "test \"probe\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&record);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: true,
                safe_profile: false,
                seed: Some(4242),
                record: Some(record.clone()),
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backed native run should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("host-backed run json should parse");
        assert_eq!(
            payload["bridge"]["recordedTrace"].as_str(),
            Some(record.to_string_lossy().as_ref())
        );
        assert!(
            payload["bridge"]["prepareTrace"]
                .as_str()
                .is_some_and(|path| path != record.to_string_lossy()),
            "prepare trace should refer to the bridge preflight artifact"
        );
        let verify = fzscenario::verify_trace_file(&record).expect("trace should verify");
        assert!(verify.ok, "recorded trace should verify");

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(record);
    }

    #[test]
    fn run_cranelift_module_qualified_spawn_executes_nested_worker() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-module-spawn-{suffix}"));
        let output_path = std::env::temp_dir().join(format!("fozzylang-module-spawn-{suffix}.txt"));
        let quoted_out = output_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"module_spawn\"\nversion = \"0.1.0\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\n\nfn main() -> i32 {\n    return services.tools.run_probe()\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod tools;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/tools.fzy"),
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo nested > {quoted_out}'\")\n}}\n\nfn run_probe() -> i32 {{\n    let handle = spawn(worker)\n    let result = join(handle)\n    if result == 0 && fs.exists(\"{quoted_out}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("tools source should be written");
        let _ = std::fs::remove_file(&output_path);

        let output = run(
            Command::Run {
                path: root.join("src/main.fzy"),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("cranelift module-qualified spawn should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            output_path.exists(),
            "nested worker should create output file"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn run_cranelift_nested_module_spawns_complete_from_spawned_coordinator() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-nested-module-spawn-{suffix}"));
        let left_path =
            std::env::temp_dir().join(format!("fozzylang-nested-module-spawn-left-{suffix}.txt"));
        let right_path =
            std::env::temp_dir().join(format!("fozzylang-nested-module-spawn-right-{suffix}.txt"));
        let quoted_left = left_path.to_string_lossy().replace('\"', "\\\"");
        let quoted_right = right_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"nested_module_spawn\"\nversion = \"0.1.0\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nuse core.thread;\n\nfn main() -> i32 {\n    let handle = spawn(services.tools.run_probe)\n    return join(handle)\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod tools;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/tools.fzy"),
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker_left() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo left > {quoted_left}'\")\n}}\n\nfn worker_right() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo right > {quoted_right}'\")\n}}\n\nfn run_probe() -> i32 {{\n    let left = spawn(worker_left)\n    let right = spawn(worker_right)\n    let left_result = join(left)\n    let right_result = join(right)\n    if left_result == 0 && right_result == 0 && fs.exists(\"{quoted_left}\") == 1 && fs.exists(\"{quoted_right}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("tools source should be written");
        let _ = std::fs::remove_file(&left_path);
        let _ = std::fs::remove_file(&right_path);

        let output = run(
            Command::Run {
                path: root.join("src/main.fzy"),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("nested module-qualified spawns should succeed from spawned coordinator");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            left_path.exists(),
            "left nested worker should create output file"
        );
        assert!(
            right_path.exists(),
            "right nested worker should create output file"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
    }

    #[test]
    fn run_cranelift_live_shape_spawns_preserve_proc_json_payloads() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-live-shape-spawn-{suffix}"));
        let left_path =
            std::env::temp_dir().join(format!("fozzylang-live-shape-left-{suffix}.json"));
        let right_path =
            std::env::temp_dir().join(format!("fozzylang-live-shape-right-{suffix}.json"));
        let quoted_left = left_path.to_string_lossy().replace('\"', "\\\"");
        let quoted_right = right_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"live_shape_spawn\"\nversion = \"0.1.0\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\n\nfn main() -> i32 {\n    return services.tools.run_probe()\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod tools;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/tools.fzy"),
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn shell_payload(command: str, out_path: str) -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, command)\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    discard proc.wait(handle, 1000)\n    let stdout = proc.stdout(handle)\n    let stderr = proc.stderr(handle)\n    discard proc.close(handle)\n    let payload = map.new()\n    discard map.set(payload, \"status\", json.str(\"ok\"))\n    discard map.set(payload, \"stdout\", json.str(stdout))\n    discard map.set(payload, \"stderr\", json.str(stderr))\n    fs.write_file(out_path, json.object(payload))\n    return 0\n}}\n\nfn worker_left() -> i32 {{\n    return shell_payload(\"printf left\", \"{quoted_left}\")\n}}\n\nfn worker_right() -> i32 {{\n    return shell_payload(\"printf right\", \"{quoted_right}\")\n}}\n\nfn probe_worker() -> i32 {{\n    return 7\n}}\n\nfn run_probe() -> i32 {{\n    let probe = spawn(probe_worker)\n    let probe_result = join(probe)\n    let left = spawn(worker_left)\n    let right = spawn(worker_right)\n    let left_result = join(left)\n    let right_result = join(right)\n    if probe_result == 7 && left_result == 0 && right_result == 0 && fs.exists(\"{quoted_left}\") == 1 && fs.exists(\"{quoted_right}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("tools source should be written");
        let _ = std::fs::remove_file(&left_path);
        let _ = std::fs::remove_file(&right_path);

        let output = run(
            Command::Run {
                path: root.join("src/main.fzy"),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("live-shape nested spawns should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let left_content =
            std::fs::read_to_string(&left_path).expect("left payload should be readable");
        let right_content =
            std::fs::read_to_string(&right_path).expect("right payload should be readable");
        assert_ne!(left_content.trim(), "{}");
        assert_ne!(right_content.trim(), "{}");
        assert!(left_content.contains("\"stdout\":\"left\""));
        assert!(right_content.contains("\"stdout\":\"right\""));

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
    }

    #[test]
    fn run_spawn_ctx_workers_preserve_string_payloads_under_concurrency() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-string-race-{suffix}"));
        let one = std::env::temp_dir().join(format!("fozzylang-string-race-one-{suffix}.json"));
        let two = std::env::temp_dir().join(format!("fozzylang-string-race-two-{suffix}.json"));
        let three = std::env::temp_dir().join(format!("fozzylang-string-race-three-{suffix}.json"));
        let four = std::env::temp_dir().join(format!("fozzylang-string-race-four-{suffix}.json"));
        let quoted_one = one.to_string_lossy().replace('\"', "\\\"");
        let quoted_two = two.to_string_lossy().replace('\"', "\\\"");
        let quoted_three = three.to_string_lossy().replace('\"', "\\\"");
        let quoted_four = four.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"string_race\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"string_race\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            format!(
                "use core.fs;\nuse core.thread;\n\nfn json_obj4(k1: str, v1: str, k2: str, v2: str, k3: str, v3: str, k4: str, v4: str) -> str {{\n    let obj = map.new()\n    discard map.set(obj, k1, v1)\n    discard map.set(obj, k2, v2)\n    discard map.set(obj, k3, v3)\n    discard map.set(obj, k4, v4)\n    return json.object(obj)\n}}\n\nfn worker_one() -> i32 {{\n    fs.write_file(\"{quoted_one}\", json_obj4(\"slot\", json.str(\"one\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn worker_two() -> i32 {{\n    fs.write_file(\"{quoted_two}\", json_obj4(\"slot\", json.str(\"two\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn worker_three() -> i32 {{\n    fs.write_file(\"{quoted_three}\", json_obj4(\"slot\", json.str(\"three\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn worker_four() -> i32 {{\n    fs.write_file(\"{quoted_four}\", json_obj4(\"slot\", json.str(\"four\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn main() -> i32 {{\n    let one = spawn_ctx(worker_one, 1)\n    let two = spawn_ctx(worker_two, 2)\n    let three = spawn_ctx(worker_three, 3)\n    let four = spawn_ctx(worker_four, 4)\n    let r1 = join(one)\n    let r2 = join(two)\n    let r3 = join(three)\n    let r4 = join(four)\n    if r1 == 0 && r2 == 0 && r3 == 0 && r4 == 0 && fs.exists(\"{quoted_one}\") == 1 && fs.exists(\"{quoted_two}\") == 1 && fs.exists(\"{quoted_three}\") == 1 && fs.exists(\"{quoted_four}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&one);
        let _ = std::fs::remove_file(&two);
        let _ = std::fs::remove_file(&three);
        let _ = std::fs::remove_file(&four);

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("concurrent spawn_ctx writers should preserve payload strings");
        assert!(output.contains("\"exitCode\":0"));
        for (path, slot, ctx_id) in [
            (&one, "one", "1"),
            (&two, "two", "2"),
            (&three, "three", "3"),
            (&four, "four", "4"),
        ] {
            let content = std::fs::read_to_string(path).expect("worker payload should be readable");
            assert_ne!(content.trim(), "", "worker payload should not be empty");
            assert!(content.contains(&format!("\"slot\":\"{slot}\"")));
            assert!(content.contains("\"status\":\"ok\""));
            assert!(content.contains(&format!("\"ctx\":\"{ctx_id}\"")));
        }

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(one);
        let _ = std::fs::remove_file(two);
        let _ = std::fs::remove_file(three);
        let _ = std::fs::remove_file(four);
    }

    #[test]
    fn scenario_routing_keeps_det_for_host_backends() {
        let routing = scenario_run_routing(true, true);
        assert!(routing.deterministic_applied);
        assert_eq!(routing.mode, "host-backed-deterministic-scenario");
        assert!(routing.reason.contains("deterministic"));
    }

    #[test]
    fn anthropic_probe_steps_include_concrete_proc_events() {
        let steps = build_live_http_probe_steps("call anthropic provider", false);
        assert!(!steps.is_empty());
        let rendered = serde_json::to_string(&steps).expect("steps should serialize");
        assert!(rendered.contains("\"type\":\"proc_when\""));
        assert!(rendered.contains("\"type\":\"proc_spawn\""));
        assert!(rendered.contains("http.request.anthropic.start"));
    }

    #[test]
    fn host_backed_anthropic_probe_skips_proc_stubs() {
        let steps = build_live_http_probe_steps("anthropic", true);
        let rendered = serde_json::to_string(&steps).expect("steps should serialize");
        assert!(rendered.contains("\"type\":\"proc_spawn\""));
        assert!(!rendered.contains("\"type\":\"proc_when\""));
    }

    #[test]
    fn run_command_routes_det_through_language_async_model() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-run-det-route-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.fs;\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fozzylang-run-det-route.txt\")\n    defer fs.close(file)\n    discard fs.write(file, \"route=det\\n\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(5),
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("deterministic run should succeed");
        assert!(output.contains("\"deterministic-language-async-model\""));
        assert!(output.contains("\"asyncCheckpointCount\""));
        assert!(output.contains("\"routing\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_async_intrinsics_timeout_deadline_cancel_recv_compile_and_run() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-native-async-intrinsics-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.thread;\nfn main() -> i32 {\n    timeout(10)\n    let _d: i32 = deadline(1000)\n    let _c: i32 = cancel()\n    let _r: i32 = recv()\n    return 0\n}\n",
        )
        .expect("source should be written");
        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn non_scenario_test_record_writes_thread_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "test \"a\" {}\ntest \"b\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("random".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"artifacts\""));
        let trace_text = std::fs::read_to_string(&trace).expect("goal trace should be written");
        assert!(trace_text.contains(&format!("\"format\":\"{FOZZY_TRACE_FORMAT}\"")));
        assert!(trace_text.contains(&format!("\"version\":{FOZZY_TRACE_VERSION}")));
        assert!(trace_text.contains("\"events\":["));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace = base.join(format!("{stem}.native.trace.json"));
        let native_trace_text =
            std::fs::read_to_string(&native_trace).expect("native trace should be written");
        assert!(native_trace_text.contains("\"schemaVersion\": \"fozzylang.thread_trace.v0\""));
        assert!(native_trace_text.contains("\"capability\": \"thread\""));
        assert!(native_trace_text.contains("\"scheduler\": \"random\""));
        assert!(base.join(format!("{stem}.timeline.json")).exists());
        assert!(base.join(format!("{stem}.report.json")).exists());
        assert!(base.join(format!("{stem}.manifest.json")).exists());
        assert!(base.join(format!("{stem}.explore.json")).exists());
        assert!(base.join(format!("{stem}.shrink.json")).exists());
        assert!(base.join(format!("{stem}.scenarios.json")).exists());
        assert!(base.join(format!("{stem}.scenarios")).exists());

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn counts_async_hooks_from_semantic_ast() {
        let source = r#"
            async fn worker() -> i32 { return 0 }
            async fn io_next() -> i32 { return 1 }
            fn main() -> i32 {
                let x = await io_next()
                yield()
                checkpoint()
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("source should parse");
        assert_eq!(count_async_hooks_in_module(&module), 5);
    }

    #[test]
    fn non_scenario_test_record_writes_async_schedule_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-async-record-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-async-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "use core.thread;\nasync fn worker() -> i32 {\n    return 0\n}\ntest \"a\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(5),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"asyncCheckpointCount\":1"));
        assert!(output.contains("\"asyncExecution\":[0]"));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be readable");
        assert!(native_trace_text.contains("\"asyncSchedule\": ["));
        let timeline = std::fs::read_to_string(base.join(format!("{stem}.timeline.json")))
            .expect("timeline should be readable");
        assert!(timeline.contains("\"decision\": \"async.schedule\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_test_record_writes_rpc_frame_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-rpc-record-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-rpc-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "use core.thread;\nuse core.http;\nrpc Ping(req: i32) -> i32;\nrpc Chat(req: i32) -> i32;\nfn main() -> i32 {\n    Ping(0)\n    Chat(0)\n    timeout(10)\n    cancel()\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(8),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("random".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"rpcFrameCount\":4"));
        assert!(output.contains("\"rpcValidationErrors\":0"));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be written");
        assert!(native_trace_text.contains("\"rpcFrames\": ["));
        assert!(native_trace_text.contains("\"event\": \"rpc_send\""));
        assert!(!native_trace_text.contains("\"event\": \"rpc_recv\""));
        assert!(native_trace_text.contains("\"event\": \"rpc_deadline\""));
        assert!(native_trace_text.contains("\"event\": \"rpc_cancel\""));
        let timeline = std::fs::read_to_string(base.join(format!("{stem}.timeline.json")))
            .expect("timeline should be readable");
        assert!(timeline.contains("\"decision\": \"rpc.frame\""));
        let report = std::fs::read_to_string(base.join(format!("{stem}.report.json")))
            .expect("report should be readable");
        assert!(report.contains("\"kind\": \"rpc_deadline\""));
        assert!(report.contains("\"kind\": \"rpc_cancel\""));
        assert!(report.contains("\"rpcValidation\""));
        assert!(report.contains("\"threadFindings\""));
        assert!(report.contains("\"failureClasses\""));
        assert!(report.contains("\"id\": \"rpc_timeout\""));
        let explore = std::fs::read_to_string(base.join(format!("{stem}.explore.json")))
            .expect("explore should be readable");
        assert!(explore.contains("\"schemaVersion\": \"fozzylang.explore.v0\""));
        assert!(explore.contains("\"rpcFramePermutations\""));
        assert!(explore.contains("\"scenarioPriorities\""));
        let shrink = std::fs::read_to_string(base.join(format!("{stem}.shrink.json")))
            .expect("shrink should be readable");
        assert!(shrink.contains("\"schemaVersion\": \"fozzylang.shrink.v0\""));
        assert!(shrink.contains("\"kind\": \"rpc_methods\""));
        assert!(shrink.contains("\"minimalRpcRepro\""));
        assert!(shrink.contains("\"scenarioPriorities\""));
        let scenarios_index = std::fs::read_to_string(base.join(format!("{stem}.scenarios.json")))
            .expect("scenarios index should be readable");
        assert!(scenarios_index.contains("\"schemaVersion\": \"fozzylang.scenarios.v0\""));
        assert!(scenarios_index.contains(".fozzy.json"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_test_record_writes_gpu_runtime_events() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-gpu-record-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-gpu-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "use core.gpu;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\ntest \"gpu trace\" {}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 4)\n    defer gpu.free(output)\n    let first = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    gpu.wait(first)\n    let second = gpu.launch3(copy, 2, 32, gpu.slice(output, 0, 4), gpu.slice(input, 0, 4), 4)\n    gpu.wait(second)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(13),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"runtimeEventCount\":"));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be written");
        let native_trace: serde_json::Value =
            serde_json::from_str(&native_trace_text).expect("native trace should parse");
        let runtime_events = native_trace["runtimeEvents"]
            .as_array()
            .expect("runtimeEvents should be an array");
        let launch_events = runtime_events
            .iter()
            .filter(|event| event["kind"].as_str() == Some("gpu.kernel_launch"))
            .collect::<Vec<_>>();
        assert_eq!(launch_events.len(), 2);
        assert_eq!(
            launch_events[0]["details"]["kernelName"].as_str(),
            Some("copy")
        );
        assert_eq!(launch_events[0]["details"]["grid"].as_i64(), Some(1));
        assert_eq!(launch_events[0]["details"]["block"].as_i64(), Some(64));
        assert_eq!(
            launch_events[0]["details"]["paramLayout"].as_str(),
            Some("slice_f32_ro,slice_f32_wo,i32")
        );
        assert_eq!(launch_events[1]["details"]["grid"].as_i64(), Some(2));
        assert_eq!(launch_events[1]["details"]["block"].as_i64(), Some(32));
        let causal_links = native_trace["causalLinks"]
            .as_array()
            .expect("causalLinks should be array");
        assert!(causal_links
            .iter()
            .any(|link| { link["relation"].as_str() == Some("gpu.buffer.lifetime_end") }));
        assert!(causal_links
            .iter()
            .any(|link| { link["relation"].as_str() == Some("gpu.event.complete") }));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_test_record_writes_gpu_upload_runtime_events() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-test-gpu-upload-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!(
            "fozzylang-test-gpu-upload-record-{suffix}.trace.json"
        ));
        std::fs::write(
            &source,
            "use core.gpu;\nuse core.simd;\ntest \"gpu upload trace\" {}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let buf: GpuBuffer<f32> = gpu.upload_f32(dev, values)\n    let window: GpuSlice<f32> = gpu.slice(buf, 1, 2)\n    discard window\n    gpu.free(buf)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(17),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"runtimeEventCount\":"));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be written");
        assert!(native_trace_text.contains("\"kind\": \"gpu.device_select\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.upload\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.slice\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.free\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_test_record_writes_gpu_download_runtime_events() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-test-gpu-download-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!(
            "fozzylang-test-gpu-download-record-{suffix}.trace.json"
        ));
        std::fs::write(
            &source,
            "use core.gpu;\nuse core.simd;\ntest \"gpu download trace\" {}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let buf: GpuBuffer<f32> = gpu.upload_f32(dev, values)\n    let downloaded: Vec<f32> = gpu.download_f32(buf)\n    gpu.free(buf)\n    if downloaded[0] != values[0] {\n        return 11\n    }\n    if downloaded[3] != values[3] {\n        return 12\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(23),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"runtimeEventCount\":"));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be written");
        assert!(native_trace_text.contains("\"kind\": \"gpu.device_select\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.upload\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.download\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.free\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_test_record_writes_gpu_async_runtime_events() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-test-gpu-async-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!(
            "fozzylang-test-gpu-async-record-{suffix}.trace.json"
        ));
        std::fs::write(
            &source,
            "use core.gpu;\nuse core.thread;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\ntest \"gpu async trace\" {}\nasync host fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 4)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    await gpu.wait_async(event)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(19),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"runtimeEventCount\":"));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be written");
        assert!(native_trace_text.contains("\"kind\": \"gpu.device_select\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.slice\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.kernel_launch\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.event_wait\""));
        assert!(native_trace_text.contains("\"kind\": \"gpu.kernel_complete\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_trace_records_gpu_error_events() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-test-gpu-error-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!(
            "fozzylang-test-gpu-error-record-{suffix}.trace.json"
        ));
        std::fs::write(
            &source,
            "use core.gpu;\ntest \"gpu error trace\" {}\nhost fn flush(event: GpuEvent) -> void {\n    gpu.wait(event)\n}\nhost fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(29),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be written");
        let native_trace: serde_json::Value =
            serde_json::from_str(&native_trace_text).expect("native trace should parse");
        let error_event = native_trace["runtimeEvents"]
            .as_array()
            .expect("runtimeEvents should be an array")
            .iter()
            .find(|event| event["kind"].as_str() == Some("gpu.error"))
            .expect("gpu.error event should be present");
        assert_eq!(
            error_event["details"]["detail"]["reason"].as_str(),
            Some("unknown_event_binding")
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_test_record_preserves_rpc_frame_order() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-rpc-order-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-rpc-order-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "use core.thread;\nrpc Ping(req: i32) -> i32;\nrpc Pong(req: i32) -> i32;\nfn main() -> i32 {\n    Ping(0)\n    Pong(0)\n    timeout(10)\n    cancel()\n    return 0\n}\n",
        )
        .expect("source should be written");

        run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(12),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_text =
            std::fs::read_to_string(base.join(format!("{stem}.native.trace.json")))
                .expect("native trace should be readable");
        let native_trace: serde_json::Value =
            serde_json::from_str(&native_trace_text).expect("native trace should parse");
        let events = native_trace["rpcFrames"]
            .as_array()
            .expect("rpcFrames should be array")
            .iter()
            .filter_map(|frame| frame["event"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            events,
            vec!["rpc_send", "rpc_send", "rpc_deadline", "rpc_cancel"]
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn non_scenario_trace_includes_unsafe_site_accounting() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-unsafe-trace-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-unsafe-trace-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "fn lang_id(v: i32) -> i32 {\n    return v\n}\nunsafe fn lang_unsafe_id(v: i32) -> i32 {\n    return v\n}\nfn main() -> i32 {\n    let routed = lang_id(7)\n    discard lang_unsafe_id\n    unsafe {\n        discard lang_id(routed)\n    }\n    return routed\n}\n",
        )
        .expect("source should be written");

        run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(9),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let report = std::fs::read_to_string(base.join(format!("{stem}.report.json")))
            .expect("report should be readable");
        assert!(report.contains("\"kind\": \"unsafe_site_accounting\""));
        assert!(report.contains("\"contractHash\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn headers_command_rejects_ffi_when_panic_contract_missing() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-ffi-panic-{suffix}.fzy"));
        std::fs::write(
            &source,
            "pubext c fn add(left: i32, right: i32) -> i32;\nfn main() -> i32 {\n    panic(err)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::Headers {
                path: source.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers command should fail");
        assert!(error.to_string().contains("ffi panic contract missing"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn non_scenario_test_filter_selects_named_tests() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-filter-{suffix}.fzy"));
        std::fs::write(
            &source,
            "test \"alpha\" {}\ntest \"beta\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(1),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: false,
                filter: Some("alpha".to_string()),
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"selectedTests\":1"));
        assert!(output.contains("\"selectedTestNames\":[\"alpha\"]"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn replay_command_routes_native_trace_through_goal_bridge() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-replay-{suffix}.trace.json"));
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "fifo",
                "seed": 7,
                "executionOrder": [0, 1],
                "asyncSchedule": [1],
                "rpcFrames": [
                    {"event":"rpc_send","method":"Ping","taskId":0},
                    {"event":"rpc_recv","method":"Ping","taskId":1}
                ],
                "events": [{"event":"completed","taskId":0}],
            })
            .to_string(),
        )
        .expect("trace should be written");

        let error = run(
            Command::Replay {
                trace: trace.clone(),
            },
            Format::Text,
        )
        .expect_err("replay should require a goal-trace bridge for native traces");
        assert!(error.to_string().contains(".manifest.json"));

        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn explore_command_uses_native_engine_for_native_manifest() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("fozzylang-native-explore-{suffix}"));
        std::fs::create_dir_all(&base).expect("base should be created");
        let trace = base.join("demo.trace.json");
        let manifest = base.join("demo.trace.manifest.json");
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "random",
                "seed": 9,
                "executionOrder": [0, 2, 1],
                "asyncSchedule": [2, 0],
                "rpcFrames": [],
                "events": [],
            })
            .to_string(),
        )
        .expect("trace should be written");
        std::fs::write(
            &manifest,
            serde_json::json!({
                "schemaVersion": "fozzylang.artifacts.v0",
                "trace": trace.display().to_string(),
            })
            .to_string(),
        )
        .expect("manifest should be written");

        let output = run(
            Command::Explore {
                target: manifest.clone(),
            },
            Format::Json,
        )
        .expect("explore should succeed");
        assert!(output.contains("\"schemaVersion\":\"fozzylang.native_explore.v0\""));
        assert!(output.contains("\"engine\":\"fozzylang-native\""));
        assert!(output.contains("\"schedules\""));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn explore_command_accepts_steps_scenarios() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let scenario =
            std::env::temp_dir().join(format!("fozzylang-steps-explore-{suffix}.fozzy.json"));
        std::fs::write(
            &scenario,
            serde_json::json!({
                "version": 1,
                "name": "steps-explore",
                "steps": [
                    {"type": "trace_event", "name": "boot"},
                    {"type": "assert_eq_int", "a": 1, "b": 1}
                ]
            })
            .to_string(),
        )
        .expect("scenario should be written");

        let output = run(
            Command::Explore {
                target: scenario.clone(),
            },
            Format::Json,
        )
        .expect("explore should succeed for steps scenarios");
        assert!(output.contains("\"mode\":\"explore\""));
        assert!(output.contains("\"status\":\"pass\""));

        let _ = std::fs::remove_file(scenario);
    }

    #[test]
    fn ci_command_routes_native_trace_through_goal_bridge() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-ci-fail-{suffix}.trace.json"));
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "fifo",
                "seed": 3,
                "executionOrder": [0],
                "asyncSchedule": [],
                "rpcFrames": [
                    {"event":"rpc_recv","method":"Ping","taskId":0}
                ],
                "events": [],
            })
            .to_string(),
        )
        .expect("trace should be written");

        let error = run(
            Command::Ci {
                trace: trace.clone(),
                strict: false,
            },
            Format::Text,
        )
        .expect_err("ci should require a goal-trace bridge for native traces");
        assert!(error.to_string().contains(".manifest.json"));

        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn shrink_command_routes_native_trace_through_goal_bridge() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-shrink-{suffix}.trace.json"));
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "fifo",
                "seed": 11,
                "executionOrder": [0, 1],
                "asyncSchedule": [1],
                "rpcFrames": [
                    {"event":"rpc_send","method":"Ping","taskId":0},
                    {"event":"rpc_deadline","method":"Ping","taskId":1}
                ],
                "events": [],
            })
            .to_string(),
        )
        .expect("trace should be written");

        let error = run(
            Command::Shrink {
                trace: trace.clone(),
            },
            Format::Text,
        )
        .expect_err("shrink should require a goal-trace bridge for native traces");
        assert!(error.to_string().contains(".manifest.json"));

        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn async_workload_uses_structured_task_model() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-async-workload-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.thread;\nuse core.http;\nrpc Ping(req: i32) -> i32;\nasync fn worker() -> i32 {\n    return 0\n}\ntest \"flow\" {}\nfn main() -> i32 {\n    spawn(worker)\n    Ping(0)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(3),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: false,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"executedTasks\":4"));
        assert!(output.contains("\"asyncCheckpointCount\":1"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn resolve_replay_target_prefers_manifest_goal_trace() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("fozzylang-replay-resolve-{suffix}"));
        std::fs::create_dir_all(&base).expect("base dir should be created");
        let goal_trace = base.join("goal.fozzy");
        let manifest = base.join("trace.manifest.json");
        std::fs::write(&goal_trace, "{\"version\":3}").expect("goal trace should be written");
        std::fs::write(
            &manifest,
            serde_json::json!({
                "schemaVersion": "fozzylang.artifacts.v0",
                "goalTrace": goal_trace.display().to_string()
            })
            .to_string(),
        )
        .expect("manifest should be written");

        let resolved = resolve_replay_target(&manifest).expect("target should resolve");
        assert_eq!(resolved, goal_trace);

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn trace_native_command_converts_fozzy_trace_to_native_schema() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("fozzylang-trace-native-{suffix}"));
        std::fs::create_dir_all(&base).expect("base dir should be created");
        let goal_trace = base.join("goal.fozzy");
        std::fs::write(
            &goal_trace,
            serde_json::json!({
                "format": FOZZY_TRACE_FORMAT,
                "version": FOZZY_TRACE_VERSION,
                "decisions": [
                    {"kind":"scheduler_pick","task_id":1,"label":"rpc_send"},
                    {"kind":"rpc_send","task_id":1,"method":"Ping"}
                ],
                "events": [{"name":"ping","time_ms":0,"fields":{}}],
                "summary": {"identity":{"seed":99}}
            })
            .to_string(),
        )
        .expect("goal trace should be written");

        let output = run(
            Command::TraceNative {
                trace: goal_trace.clone(),
                output: None,
            },
            Format::Json,
        )
        .expect("trace-native should succeed");
        assert!(output.contains("\"seed\":99"));
        assert!(output.contains("\"rpcFrames\":1"));

        let native_trace = base.join("goal.trace.json");
        let native_manifest = base.join("goal.trace.manifest.json");
        let trace_text =
            std::fs::read_to_string(&native_trace).expect("native trace should be written");
        assert!(trace_text.contains("\"schemaVersion\": \"fozzylang.thread_trace.v0\""));
        assert!(trace_text.contains("\"compatibility\""));
        assert!(trace_text.contains("\"checkpointCount\": 0"));
        assert!(trace_text.contains("\"event\": \"rpc_send\""));
        let manifest_text =
            std::fs::read_to_string(&native_manifest).expect("native manifest should be written");
        assert!(manifest_text.contains("\"compatibility\""));
        assert!(manifest_text.contains("\"goalTrace\""));
        assert!(manifest_text.contains("goal.fozzy"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn trace_verify_reports_compatibility_and_replay_contract_checks() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let scenario =
            std::env::temp_dir().join(format!("fozzylang-trace-verify-compat-{suffix}.fozzy.json"));
        let trace = std::env::temp_dir().join(format!(
            "fozzylang-trace-verify-compat-{suffix}.trace.fozzy"
        ));
        std::fs::write(
            &scenario,
            serde_json::json!({
                "version": 1,
                "name": "trace-verify-compat",
                "steps": [
                    {"type": "trace_event", "name": "boot"},
                    {"type": "memory_checkpoint", "name": "after_boot"},
                    {"type": "assert_eq_int", "a": 1, "b": 1}
                ]
            })
            .to_string(),
        )
        .expect("scenario should be written");

        let run_output = run(
            Command::Run {
                path: scenario.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run should record trace");
        assert!(run_output.contains("\"status\":\"pass\""));

        let verify_output = run(
            Command::TraceVerify {
                trace: trace.clone(),
                strict: true,
            },
            Format::Json,
        )
        .expect("trace verify should succeed");
        assert!(verify_output.contains("\"compatibility\""));
        assert!(verify_output.contains("\"traceSchemaVersion\":\"fozzy-trace.v4\""));
        assert!(verify_output.contains("\"name\":\"compatibility_set\""));
        assert!(verify_output.contains("\"name\":\"checkpoint_count_match\""));

        let _ = std::fs::remove_file(scenario);
        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn debug_check_command_reports_readiness() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-debug-check-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.thread;\nasync fn worker() -> i32 {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        let output = run(
            Command::DebugCheck {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("debug-check should succeed");
        assert!(output.contains("\"debugSymbols\""));
        assert!(output.contains("\"asyncBacktraceReady\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn plan_claim_accuracy_gate_detects_missing_evidence() {
        let plan = "- [✅] Added `lsp_rename`\n- [✅] Updated docs\n";
        let corpus = vec![(
            "crates/driver/src/lsp.rs".to_string(),
            "fn lsp_rename() {}".to_string(),
        )];
        let gate = analyze_plan_claim_accuracy(plan, &corpus);
        assert_eq!(gate.completed, 2);
        assert_eq!(gate.checked, 1);
        assert_eq!(gate.missing_evidence.len(), 1);
        assert!(gate.missing_evidence[0].contains("`lsp_rename`"));
    }

    #[test]
    fn lsp_commands_smoke_for_workspace_file() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-smoke-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn helper() -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    return helper()\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("\"ok\":true"));
        let definition = run(
            Command::LspDefinition {
                path: source.clone(),
                symbol: "helper".to_string(),
            },
            Format::Json,
        )
        .expect("lsp definition should succeed");
        assert!(definition.contains("\"kind\":\"function\""));
        let hover = run(
            Command::LspHover {
                path: source.clone(),
                symbol: "main".to_string(),
            },
            Format::Json,
        )
        .expect("lsp hover should succeed");
        assert!(hover.contains("\"signature\""));
        let rename = run(
            Command::LspRename {
                path: source.clone(),
                from: "helper".to_string(),
                to: "helper2".to_string(),
            },
            Format::Json,
        )
        .expect("lsp rename should succeed");
        assert!(rename.contains("\"replacements\""));
        let smoke = run(
            Command::LspSmoke {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("lsp smoke should succeed");
        assert!(smoke.contains("\"features\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_diagnostics_json_includes_snippet_and_labels() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-diagnostics-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let payload: str = \"unterminated\n    return 0\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("\"snippet\""));
        assert!(diagnostics.contains("\"labels\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_diagnostics_text_includes_full_diagnostic_body() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-diag-text-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    missing_call()\n    return 0\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("mode: lsp-diagnostics"));
        assert!(diagnostics.contains("error["));
        assert!(diagnostics.contains("help:"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_diagnostics_text_uses_human_grouped_type_notes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-grouped-notes-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let value: i32 = \"oops\"\n    missing_symbol(1)\n    return value\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("additional grouped root cause: unresolved call target"));
        assert!(!diagnostics.contains("type_error_count="));
        assert!(diagnostics.contains("explain: fz explain verifier.grouped_type_error"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_commands_reject_non_fzy_files() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-foreign-{suffix}.rs"));
        std::fs::write(&source, "fn main() {}\n").expect("source should be written");

        let error = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect_err("non-fzy diagnostics input should be rejected");
        assert!(
            error
                .to_string()
                .contains("expected a `.fzy` source file or a project directory"),
            "unexpected error: {error}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn diagnostics_regression_unresolved_call_and_field_variant_resolution() {
        let unresolved = run_check_text(
            "fn main() -> i32 {\n    return missing_symbol()\n}\n",
            "unresolved-call",
        );
        assert!(unresolved.contains("unresolved call target"));

        let field = run_check_text(
            "struct User { id: i32 }\nfn main() -> i32 {\n    let user = User { id: 1 }\n    return user.missing\n}\n",
            "field-resolution",
        );
        assert!(field.contains("has no field `missing`"));

        let variant = run_check_text(
            "enum Status { Ok }\nfn main() -> i32 {\n    discard Status::Err\n    return 0\n}\n",
            "variant-resolution",
        );
        assert!(variant.contains("has no variant `Err`"));

        let unqualified_pattern = run_check_text(
            "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let m = Maybe::Some(1)\n    match m {\n        Some(v) => v,\n        _ => 0,\n    }\n}\n",
            "variant-pattern-qualification",
        );
        assert!(unqualified_pattern.contains("unqualified enum variant pattern"));
    }

    #[test]
    fn diagnostics_regression_match_capability_and_ffi_boundary() {
        let match_unreachable = run_check_text(
            "fn main() -> i32 {\n    match 1 {\n        _ => 0,\n        1 => 1,\n    }\n}\n",
            "match-unreachable",
        );
        assert!(match_unreachable.contains("unreachable"));

        let capability = run_check_text(
            "fn main() -> i32 {\n    let listener = http.bind()\n    return listener\n}\n",
            "capability-violation",
        );
        assert!(capability.contains("missing required capability"));

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-diag-ffi-boundary-{unique}.fzy"));
        std::fs::write(&path, "pubext c fn exported() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");
        let ffi = run(
            Command::Headers {
                path: path.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers should fail without ffi_panic attribute")
        .to_string();
        assert!(ffi.contains("ffi panic contract missing"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn dx_check_accepts_convention_project() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-dx-ok-{suffix}"));
        std::fs::create_dir_all(root.join("src/api")).expect("api dir should be created");
        std::fs::create_dir_all(root.join("src/model")).expect("model dir should be created");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::create_dir_all(root.join("src/runtime")).expect("runtime dir should be created");
        std::fs::create_dir_all(root.join("src/cli")).expect("cli dir should be created");
        std::fs::create_dir_all(root.join("src/tests")).expect("tests dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"dx_ok\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"dx_ok\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod api;\nmod model;\nmod services;\nmod runtime;\nmod cli;\nmod tests;\n\nfn main() -> i32 {\n    model.preflight()\n    cli.boot()\n    services.boot_all()\n    runtime.start()\n    api.touch()\n    return 0\n}\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/api/mod.fzy"),
            "fn touch() -> i32 {\n    return 0\n}\n",
        )
        .expect("api mod should be written");
        std::fs::write(
            root.join("src/model/mod.fzy"),
            "fn preflight() -> i32 {\n    return 0\n}\n",
        )
        .expect("model mod should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "fn boot_all() -> i32 {\n    return 0\n}\n",
        )
        .expect("services mod should be written");
        std::fs::write(
            root.join("src/runtime/mod.fzy"),
            "fn start() -> i32 {\n    return 0\n}\n",
        )
        .expect("runtime mod should be written");
        std::fs::write(
            root.join("src/cli/mod.fzy"),
            "fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("cli mod should be written");
        std::fs::write(root.join("src/tests/mod.fzy"), "mod smoke;\n")
            .expect("tests mod should be written");
        std::fs::write(root.join("src/tests/smoke.fzy"), "test \"det\" {}\n")
            .expect("smoke test should be written");

        let output = run(
            Command::DxCheck {
                path: root.clone(),
                strict: true,
            },
            Format::Json,
        )
        .expect("dx-check should pass");
        assert!(output.contains("\"ok\":true"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dx_check_rejects_tests_declared_in_main() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-dx-bad-{suffix}"));
        std::fs::create_dir_all(root.join("src/api")).expect("api dir should be created");
        std::fs::create_dir_all(root.join("src/model")).expect("model dir should be created");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::create_dir_all(root.join("src/runtime")).expect("runtime dir should be created");
        std::fs::create_dir_all(root.join("src/cli")).expect("cli dir should be created");
        std::fs::create_dir_all(root.join("src/tests")).expect("tests dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"dx_bad\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"dx_bad\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod api;\nmod model;\nmod services;\nmod runtime;\nmod cli;\nmod tests;\ntest \"bad\" {}\nfn main() -> i32 { return 0 }\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/api/mod.fzy"),
            "fn touch() -> i32 {\n    return 0\n}\n",
        )
        .expect("api mod should be written");
        std::fs::write(
            root.join("src/model/mod.fzy"),
            "fn preflight() -> i32 {\n    return 0\n}\n",
        )
        .expect("model mod should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "fn boot_all() -> i32 {\n    return 0\n}\n",
        )
        .expect("services mod should be written");
        std::fs::write(
            root.join("src/runtime/mod.fzy"),
            "fn start() -> i32 {\n    return 0\n}\n",
        )
        .expect("runtime mod should be written");
        std::fs::write(
            root.join("src/cli/mod.fzy"),
            "fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("cli mod should be written");
        std::fs::write(root.join("src/tests/mod.fzy"), "mod smoke;\n")
            .expect("tests mod should be written");
        std::fs::write(root.join("src/tests/smoke.fzy"), "test \"det\" {}\n")
            .expect("smoke test should be written");

        let error = run(
            Command::DxCheck {
                path: root.clone(),
                strict: true,
            },
            Format::Text,
        )
        .expect_err("dx-check should fail");
        assert!(!error.to_string().trim().is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn proof_ref_valid_accepts_existing_trace_artifact() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-proof-ref-{suffix}.fozzy"));
        std::fs::write(&path, "{}").expect("trace file should be written");
        let proof_ref = format!("trace://{}#site=usite_demo", path.display());
        assert!(super::proof_ref_valid(&proof_ref));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proof_ref_valid_rejects_missing_trace_artifact() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-proof-ref-missing-{suffix}.fozzy"));
        let proof_ref = format!("trace://{}#site=usite_demo", path.display());
        assert!(!super::proof_ref_valid(&proof_ref));
    }

    #[test]
    fn check_rejects_pointer_like_safe_extern_c_import() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-safe-extern-c-{suffix}.fzy"));
        std::fs::write(
            &source,
            "ext c fn c_read(buf_owned: *u8) -> i32;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Check {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("check command should return diagnostics");
        assert!(output.contains("must be declared `ext unsafe c fn`"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn verify_accepts_documented_safe_wrapper_over_unsafe_import() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-wrapper-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"ffi_wrapper\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_wrapper\"\npath=\"src/main.fzy\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "ext unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;\n\nfn abi_touch(s: str) -> i32 {\n    unsafe {\n        return host_touch(s, str.len(s))\n    }\n}\n\nfn safe_touch(s: str) -> i32 {\n    return abi_touch(s)\n}\n\nfn main() -> i32 {\n    return safe_touch(\"ok\")\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should return diagnostics");
        assert!(output.contains("\"errors\":0"));
        assert!(!output.contains("call edge `abi_touch -> host_touch` reaches unsafe code"));
        assert!(!output.contains("call edge `safe_touch -> abi_touch` reaches unsafe code"));
        assert!(output.contains("structural unsafe contract metadata is present"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_accepts_unsafe_import_wrapper_bound_through_let() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-wrapper-let-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"ffi_wrapper_let\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_wrapper_let\"\npath=\"src/main.fzy\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "ext unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;\n\nfn abi_touch(s: str) -> i32 {\n    let code = unsafe {\n        host_touch(s, str.len(s))\n    }\n    return code\n}\n\nfn safe_touch(s: str) -> i32 {\n    return abi_touch(s)\n}\n\nfn main() -> i32 {\n    return safe_touch(\"ok\")\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should return diagnostics");
        assert!(output.contains("\"errors\":0"));
        assert!(!output.contains("return type mismatch: expected `i32`, got `void`"));
        assert!(output.contains("structural unsafe contract metadata is present"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_accepts_zero_arg_file_backed_unsafe_import_wrapper() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-zero-arg-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"ffi_zero_arg\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_zero_arg\"\npath=\"src/main.fzy\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.fs;\n\next unsafe c fn host_dispatch() -> i32;\n\nfn abi_dispatch(raw: str) -> i32 {\n    discard fs.write_file(\"/tmp/in.json\", raw)\n    return safe_dispatch()\n}\n\nfn safe_dispatch() -> i32 {\n    return raw_dispatch()\n}\n\nfn raw_dispatch() -> i32 {\n    unsafe {\n        return host_dispatch()\n    }\n}\n\nfn main() -> i32 {\n    return abi_dispatch(\"{}\")\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should return diagnostics");
        assert!(
            output.contains("\"errors\":0"),
            "unexpected output: {output}"
        );
        assert!(!output.contains("call edge `safe_dispatch -> raw_dispatch` reaches unsafe code"));
        assert!(!output.contains("call edge `raw_dispatch -> host_dispatch` reaches unsafe code"));
        assert!(output.contains("structural unsafe contract metadata is present"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explain_catalog_returns_entries() {
        let output = run(
            Command::Explain {
                diag_code: "catalog".to_string(),
            },
            Format::Json,
        )
        .expect("catalog explain should succeed");
        assert!(output.contains("\"schemaVersion\":\"fozzylang.diagnostic_catalog.v1\""));
        assert!(output.contains("\"code_prefix\":\"E-HIR-\""));
    }

    #[test]
    fn explain_json_schema_for_grouped_type_error_is_snapshot_stable() {
        let output = run(
            Command::Explain {
                diag_code: "verifier.grouped_type_error".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("explain json should parse");
        assert_eq!(payload["schemaVersion"], DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION);
        assert_eq!(payload["catalogKey"], "verifier.grouped_type_error");
        assert_eq!(payload["family"], "verifier");
        assert_eq!(payload["nextCommand"], "fz verify <path> --json");
        assert_eq!(
            payload["explainCommand"],
            "fz explain verifier.grouped_type_error"
        );
        assert_eq!(
            payload["catalog"]["production_risk"],
            "High: grouped type errors indicate the program is not semantically stable enough for trusted lowering."
        );
    }

    #[test]
    fn explain_json_schema_for_native_backend_capability_is_snapshot_stable() {
        let output = run(
            Command::Explain {
                diag_code: "native.cranelift_async_unsafe_unsupported".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("explain json should parse");
        assert_eq!(payload["schemaVersion"], DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION);
        assert_eq!(
            payload["catalogKey"],
            "native.cranelift_async_unsafe_unsupported"
        );
        assert_eq!(payload["family"], "native-lowering");
        assert_eq!(
            payload["likelyFix"],
            "Switch to LLVM or refactor unsafe operations outside the async function boundary."
        );
        assert_eq!(
            payload["nextCommand"],
            "fz build <path> --backend llvm --json"
        );
    }

    #[test]
    fn explain_json_schema_for_ffi_contract_diagnostic_is_snapshot_stable() {
        let output = run(
            Command::Explain {
                diag_code: "verifier.extern_c_pointer_requires_contract".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("explain json should parse");
        assert_eq!(payload["schemaVersion"], DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION);
        assert_eq!(
            payload["catalogKey"],
            "verifier.extern_c_pointer_requires_contract"
        );
        assert_eq!(payload["family"], "verifier");
        assert_eq!(
            payload["explainCommand"],
            "fz explain verifier.extern_c_pointer_requires_contract"
        );
        assert!(payload["rootCause"]
            .as_str()
            .is_some_and(|value| value.contains("ownership contract")));
    }

    #[test]
    fn explain_text_includes_production_action_fields() {
        let output = run(
            Command::Explain {
                diag_code: "E-VER-DEADBEEF".to_string(),
            },
            Format::Text,
        )
        .expect("explain should succeed");
        assert!(output.contains("common_triggers"));
        assert!(output.contains("production_action"));
        assert!(output.contains("production_risk"));
        assert!(output.contains("explain_command"));
    }

    #[test]
    fn explain_accepts_exact_catalog_key() {
        let output = run(
            Command::Explain {
                diag_code: "verifier.grouped_type_error".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        assert!(output.contains("\"catalogKey\":\"verifier.grouped_type_error\""));
        assert!(output.contains("collapsed multiple related type-check failures"));
    }

    #[test]
    fn explain_accepts_rendered_catalog_keys() {
        for key in [
            "verifier.missing_explicit_capabilities",
            "parser.syntax_error",
            "verifier.function_missing_required_capability",
            "native.cranelift_async_unsafe_unsupported",
        ] {
            let output = run(
                Command::Explain {
                    diag_code: key.to_string(),
                },
                Format::Json,
            )
            .expect("explain should succeed");
            assert!(output.contains(&format!("\"catalogKey\":\"{key}\"")));
            assert!(!output.contains("\"family\":\"unknown\""));
        }
    }

    #[test]
    fn lint_command_supports_tiers() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lint-tier-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");
        let output = run(
            Command::Lint {
                path: source.clone(),
                tier: "production".to_string(),
            },
            Format::Json,
        )
        .expect("lint should succeed");
        assert!(output.contains("\"mode\":\"lint\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn perf_command_reports_real_workload_summary() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let artifact = std::env::temp_dir().join(format!("fozzylang-perf-{suffix}.json"));
        std::fs::write(
            &artifact,
            serde_json::json!({
                "benches": [
                    {"bench": "cli_startup", "ratio_fzy_over_rust": 1.25},
                    {"bench": "http_throughput", "ratio_fzy_over_rust": 0.95},
                    {"bench": "compiler_parse_lower_build", "ratio_fzy_over_rust": 1.75}
                ]
            })
            .to_string(),
        )
        .expect("benchmark artifact should be written");

        let output = run(
            Command::Perf {
                artifact: Some(artifact.clone()),
            },
            Format::Json,
        )
        .expect("perf command should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("perf output should be valid json");
        assert_eq!(payload["mode"], "perf");
        assert_eq!(payload["benchCount"], 3);
        assert_eq!(payload["worstKernel"], "compiler_parse_lower_build");
        assert_eq!(payload["worstRatioFzyOverRust"], 1.75);
        let avg = payload["averageRatioFzyOverRust"]
            .as_f64()
            .expect("average ratio should be numeric");
        assert!((avg - 1.3166666666666667).abs() < 1e-12, "{avg}");

        let _ = std::fs::remove_file(artifact);
    }

    #[test]
    fn stability_dashboard_reports_compatibility_and_perf_sources() {
        let output = run(Command::StabilityDashboard, Format::Json)
            .expect("stability dashboard should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("stability dashboard should emit json");
        assert_eq!(payload["mode"], "stability-dashboard");
        assert_eq!(
            payload["dashboard"]["schemaVersion"],
            "fozzylang.stability_dashboard.v1"
        );
        assert_eq!(
            payload["dashboard"]["compatibility"]["traceSchemaVersion"],
            "fozzy-trace.v4"
        );
        assert_eq!(
            payload["dashboard"]["performance"]["artifact"],
            "artifacts/bench_corelibs_rust_vs_fzy.json"
        );
        assert!(payload["dashboard"]["performance"]["workloads"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["name"] == "cli_startup")));
    }

    #[test]
    fn init_command_scaffolds_buildable_project_with_runtime_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-init-e2e-{suffix}"));
        let output = run(
            Command::Init {
                path: root.clone(),
                package_name: Some("demo_init".to_string()),
                template: Some("rust".to_string()),
                with: vec!["run".to_string(), "memory".to_string(), "host".to_string()],
                force: false,
            },
            Format::Json,
        )
        .expect("init should succeed");
        assert!(output.contains("\"initialized project\""));
        assert!(root.join("fozzy.toml").exists());
        assert!(root.join("src/main.fzy").exists());
        assert!(root.join("tests/run.pass.fozzy.json").exists());
        assert!(root.join("tests/memory.pass.fozzy.json").exists());
        assert!(root.join("tests/host.pass.fozzy.json").exists());
        assert!(root.join("tests/INIT_GUIDE.md").exists());
        assert!(root.join(".fozzy/runs").exists());
        assert!(root.join(".fozzy/corpora").exists());

        let artifact = compile_file_with_backend_with_root_guidance(&root, BuildProfile::Dev, None)
            .expect("scaffolded project should compile");
        assert_eq!(artifact.status, "ok");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn init_command_supports_current_directory_bootstrap() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-init-cwd-{suffix}"));
        std::fs::create_dir_all(&root).expect("root should be created");
        let prev = std::env::current_dir().expect("cwd should resolve");
        std::env::set_current_dir(&root).expect("cwd should switch");
        let result = run(
            Command::Init {
                path: root.clone(),
                package_name: None,
                template: Some("minimal".to_string()),
                with: vec!["all".to_string()],
                force: false,
            },
            Format::Text,
        );
        std::env::set_current_dir(prev).expect("cwd should restore");
        result.expect("init in current directory should succeed");
        assert!(root.join("fozzy.toml").exists());
        assert!(root.join("src/main.fzy").exists());
        assert!(root.join("tests/example.fozzy.json").exists());
        assert!(root.join(".fozzy/corpora").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn init_command_requires_force_when_scaffold_paths_exist() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-init-collision-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src should be created");
        std::fs::write(root.join("src/main.fzy"), "fn main() -> i32 { return 7 }\n")
            .expect("main should be written");

        let err = run(
            Command::Init {
                path: root.clone(),
                package_name: Some("collision".to_string()),
                template: None,
                with: Vec::new(),
                force: false,
            },
            Format::Text,
        )
        .expect_err("init should reject existing scaffold paths");
        assert!(err.to_string().contains("scaffold-managed paths"));

        let _ = std::fs::remove_dir_all(root);
    }
}
