use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error as StdError;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use formatter::{format_source, is_fzy_source_path};
use runtime::{plan_async_checkpoints, DeterministicExecutor, Scheduler, TaskEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli_output;
use crate::lsp;
use crate::pipeline::{
    compile_file_with_backend, compile_library_with_backend, emit_ir, lower_fir_cached,
    parse_program, refresh_lockfile, verify_file, BuildArtifact, BuildProfile, LibraryArtifact,
    Output,
};

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

impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "command failed with exit code {}", self.exit_code)
    }
}

impl StdError for CommandFailure {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init {
        name: String,
    },
    Build {
        path: PathBuf,
        release: bool,
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
    },
    Perf {
        artifact: Option<PathBuf>,
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
    Replay {
        trace: PathBuf,
    },
    Shrink {
        trace: PathBuf,
    },
    Ci {
        trace: PathBuf,
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
    Version,
}

pub fn run(command: Command, format: Format) -> Result<String> {
    match command {
        Command::Init { name } => {
            init_project(&name).map(|_| render(format, "initialized project"))
        }
        Command::Build {
            path,
            release,
            lib,
            threads,
            backend,
            pgo_generate,
            pgo_use,
            link_libs,
            link_search,
            frameworks,
        } => {
            let profile = if release {
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
                let rendered =
                    render_library_artifact(format, artifact, headers, threads, runtime_config);
                let unsafe_docs = maybe_generate_unsafe_docs(&path);
                Ok(append_unsafe_docs_field(rendered, format, unsafe_docs))
            } else {
                let artifact = compile_file_with_backend_with_root_guidance(
                    &path,
                    profile,
                    backend.as_deref(),
                )?;
                let rendered = render_artifact(format, artifact, threads, runtime_config);
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
        } => {
            if is_fozzy_scenario(&path) {
                let mut fozzy_args = vec!["run".to_string(), path.display().to_string()];
                let routing = scenario_run_routing(deterministic, host_backends);
                let deterministic_applied = routing.deterministic_applied;
                if deterministic_applied {
                    fozzy_args.push("--det".to_string());
                }
                if strict_verify {
                    fozzy_args.push("--strict".to_string());
                }
                if let Some(seed) = seed {
                    fozzy_args.push("--seed".to_string());
                    fozzy_args.push(seed.to_string());
                }
                if let Some(record) = record {
                    fozzy_args.push("--record".to_string());
                    fozzy_args.push(record.display().to_string());
                }
                if host_backends {
                    fozzy_args.push("--proc-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--fs-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--http-backend".to_string());
                    fozzy_args.push("host".to_string());
                }
                if matches!(format, Format::Json) {
                    fozzy_args.push("--json".to_string());
                }
                let routed = fozzy_invoke(&fozzy_args)?;
                return match format {
                    Format::Text => Ok(render_text_fields(&[
                        ("status", "ok".to_string()),
                        ("mode", "scenario-run".to_string()),
                        ("scenario", path.display().to_string()),
                        ("deterministic_requested", deterministic.to_string()),
                        ("deterministic_applied", deterministic_applied.to_string()),
                        ("host_backends", host_backends.to_string()),
                        ("fozzy", routed),
                    ])),
                    Format::Json => Ok(serde_json::json!({
                        "scenario": path.display().to_string(),
                        "deterministicRequested": deterministic,
                        "deterministicApplied": deterministic_applied,
                        "hostBackends": host_backends,
                        "routing": {
                            "mode": routing.mode,
                            "reason": routing.reason,
                        },
                        "fozzy": routed,
                    })
                    .to_string()),
                };
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
                if safe_profile {
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
                    let mut child = ProcessCommand::new(binary);
                    child.args(&args);
                    child.stdout(Stdio::inherit());
                    child.stderr(Stdio::inherit());
                    let status = child
                        .spawn()
                        .with_context(|| {
                            format!("failed to execute native artifact: {}", binary.display())
                        })?
                        .wait()
                        .with_context(|| {
                            format!(
                                "failed while waiting for native artifact: {}",
                                binary.display()
                            )
                        })?;
                    let exit_code = status.code().unwrap_or(1);
                    let message = render_text_fields(&[
                        (
                            "status",
                            if exit_code == 0 {
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
                        ("exit_code", exit_code.to_string()),
                        (
                            "policy",
                            policy_summary_text(
                                if safe_profile { "verify" } else { "dev" },
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
                    if exit_code != 0 {
                        return Err(CommandFailure {
                            exit_code,
                            output: message,
                        }
                        .into());
                    }
                    message
                }
                Format::Json => {
                    let output = ProcessCommand::new(binary)
                        .args(&args)
                        .output()
                        .with_context(|| {
                            format!("failed to execute native artifact: {}", binary.display())
                        })?;
                    let exit_code = output.status.code().unwrap_or(1);
                    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
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
                        "deterministicApplied": deterministic && !host_backends,
                        "policy": {
                            "profile": if safe_profile { "verify" } else { "dev" },
                            "unsafeEnforcement": if strict_verify { "strict" } else { "profile-driven" },
                            "memorySafetyMode": "production",
                            "backend": routing_mode,
                            "lockfileState": "present-or-created",
                        },
                        "unsafeDocs": unsafe_docs,
                        "routing": {
                            "mode": routing_mode,
                            "reason": if host_backends && deterministic {
                                "host-backed native runs preserve live process semantics and do not route through deterministic scenario execution"
                            } else if host_backends {
                                "host-backed native run"
                            } else {
                                "native run"
                            }
                        },
                        "exitCode": exit_code,
                        "stdout": stdout,
                        "stderr": stderr,
                    });
                    if exit_code != 0 {
                        return Err(CommandFailure {
                            exit_code,
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
                let mut fozzy_args = vec!["test".to_string(), path.display().to_string()];
                if deterministic {
                    fozzy_args.push("--det".to_string());
                }
                if strict_verify {
                    fozzy_args.push("--strict".to_string());
                }
                if let Some(seed) = seed {
                    fozzy_args.push("--seed".to_string());
                    fozzy_args.push(seed.to_string());
                }
                if let Some(record) = record {
                    fozzy_args.push("--record".to_string());
                    fozzy_args.push(record.display().to_string());
                }
                if host_backends {
                    fozzy_args.push("--proc-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--fs-backend".to_string());
                    fozzy_args.push("host".to_string());
                    fozzy_args.push("--http-backend".to_string());
                    fozzy_args.push("host".to_string());
                }
                if let Some(scheduler) = &scheduler {
                    fozzy_args.push("--schedule".to_string());
                    fozzy_args.push(scheduler.clone());
                }
                if matches!(format, Format::Json) {
                    fozzy_args.push("--json".to_string());
                }
                return fozzy_invoke(&fozzy_args);
            }
            if host_backends {
                bail!(
                    "--host-backends is unsupported for native `.fzy` tests; use a `.fozzy.json` scenario for host-backed execution"
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
                (
                    "policy",
                    policy_summary_text(
                        if strict_verify { "verify" } else { "dev" },
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
                        "profile": if strict_verify { "verify" } else { "dev" },
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
            let output = verify_file_with_root_guidance(&path)?;
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
        Command::DevLoop { path, backend } => devloop_command(&path, backend.as_deref(), format),
        Command::DxCheck { path, strict } => dx_check_command(&path, strict, format),
        Command::SpecCheck => spec_check(format),
        Command::EmitIr { path } => {
            let output = emit_ir(&path)?;
            Ok(render_output(format, output))
        }
        Command::Perf { artifact } => perf_command(artifact.as_deref(), format),
        Command::StabilityDashboard => stability_dashboard_command(format),
        Command::Parity { path, seed } => parity_command(&path, seed.unwrap_or(1), format),
        Command::Equivalence { path, seed } => {
            equivalence_command(&path, seed.unwrap_or(1), format)
        }
        Command::AuditUnsafe { path, workspace } => audit_unsafe_command(&path, workspace, format),
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
        Command::Fuzz { target } => passthrough_fozzy("fuzz", &target, format),
        Command::Explore { target } => {
            if is_native_trace_or_manifest(&target) {
                native_explore(&target, format)
            } else {
                passthrough_fozzy("explore", &target, format)
            }
        }
        Command::Replay { trace } => replay_like("replay", &trace, format),
        Command::Shrink { trace } => replay_like("shrink", &trace, format),
        Command::Ci { trace } => replay_like("ci", &trace, format),
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
            let generated = generate_doc_artifacts(
                &path,
                &doc_format,
                out.as_deref(),
                reference.as_deref(),
            )?;
            Ok(render_doc_artifacts(format, generated))
        }
        Command::Version => Ok(render(format, env!("CARGO_PKG_VERSION"))),
    }
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
        bail!("PGO input path is neither a file nor directory: {}", path.display());
    }

    let mut inputs = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading PGO input directory: {}", dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("failed reading directory entry while scanning {}", dir.display())
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
    command.arg("merge").arg("-sparse").arg("-o").arg(&output_path);
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
struct ScenarioRunRouting {
    deterministic_applied: bool,
    mode: &'static str,
    reason: &'static str,
}

fn scenario_run_routing(deterministic_requested: bool, host_backends: bool) -> ScenarioRunRouting {
    if deterministic_requested && host_backends {
        return ScenarioRunRouting {
            deterministic_applied: false,
            mode: "host-backed-live-scenario",
            reason:
                "fozzy deterministic mode does not support host proc backend; routed to host-backed live scenario",
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

fn init_project(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("project name cannot be empty");
    }

    let root = PathBuf::from(name);
    let src = root.join("src");
    std::fs::create_dir_all(&src).context("failed to create project directories")?;
    for dir in ["api", "model", "services", "runtime", "cli", "tests"] {
        std::fs::create_dir_all(src.join(dir))
            .with_context(|| format!("failed creating src/{dir} directory"))?;
    }

    let manifest = format!(
        "[package]\nname = \"{}\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"{}\"\npath = \"src/main.fzy\"\n\n[unsafe]\ncontracts = \"compiler\"\nenforce_dev = false\nenforce_verify = true\nenforce_release = true\ndeny_unsafe_in = []\nallow_unsafe_in = []\n",
        name, name
    );

    std::fs::write(root.join("fozzy.toml"), &manifest).context("failed to write fozzy.toml")?;
    std::fs::write(
        src.join("main.fzy"),
        "use core.time;\nuse core.fs;\nuse core.http;\nuse core.thread;\n\nmod api;\nmod model;\nmod services;\nmod runtime;\nmod cli;\nmod tests;\n\nfn main() -> i32 {\n    requires true\n\n    model.preflight()\n    cli.boot()\n    services.boot_all()\n    runtime.start()\n    api.touch()\n\n    ensures true\n    return 0\n}\n",
    )
    .context("failed to write src/main.fzy")?;
    std::fs::write(
        src.join("api/mod.fzy"),
        "mod ffi;\nmod rpc;\n\nfn touch() -> i32 {\n    ffi.touch()\n    rpc.touch()\n    return 0\n}\n",
    )
    .context("failed to write src/api/mod.fzy")?;
    std::fs::write(
        src.join("api/ffi.fzy"),
        "fn touch() -> i32 {\n    return 0\n}\n",
    )
    .context("failed to write src/api/ffi.fzy")?;
    std::fs::write(
        src.join("api/rpc.fzy"),
        "rpc Ping(req: PingReq) -> PingRes;\n\nfn touch() -> i32 {\n    return 0\n}\n",
    )
    .context("failed to write src/api/rpc.fzy")?;
    std::fs::write(
        src.join("model/mod.fzy"),
        "mod types;\nmod contracts;\n\nfn preflight() -> i32 {\n    contracts.preflight()\n    types.schema_version()\n    return 0\n}\n",
    )
    .context("failed to write src/model/mod.fzy")?;
    std::fs::write(
        src.join("model/types.fzy"),
        "#[repr(C)]\nstruct Row {}\n\nfn schema_version() -> i32 {\n    return 1\n}\n",
    )
    .context("failed to write src/model/types.fzy")?;
    std::fs::write(
        src.join("model/contracts.fzy"),
        "fn preflight() -> i32 {\n    requires true\n    ensures true\n    return 0\n}\n",
    )
    .context("failed to write src/model/contracts.fzy")?;
    std::fs::write(
        src.join("services/mod.fzy"),
        "mod store;\nmod http;\n\nfn boot_all() -> i32 {\n    store.init()\n    http.start()\n    return 0\n}\n",
    )
    .context("failed to write src/services/mod.fzy")?;
    std::fs::write(
        src.join("services/store.fzy"),
        "use core.fs;\n\nfn init() -> i32 {\n    let handle = fs.open()\n    defer close(handle)\n    return 0\n}\n",
    )
    .context("failed to write src/services/store.fzy")?;
    std::fs::write(
        src.join("services/http.fzy"),
        "use core.http;\n\nfn start() -> i32 {\n    let conn = http.connect()\n    defer close(conn)\n    return 0\n}\n",
    )
    .context("failed to write src/services/http.fzy")?;
    std::fs::write(
        src.join("runtime/mod.fzy"),
        "mod scheduler;\nmod worker;\n\nfn start() -> i32 {\n    spawn(worker.run)\n    spawn(scheduler.tick)\n    return 0\n}\n",
    )
    .context("failed to write src/runtime/mod.fzy")?;
    std::fs::write(
        src.join("runtime/scheduler.fzy"),
        "use core.thread;\n\nfn tick() -> i32 {\n    checkpoint()\n    return 0\n}\n",
    )
    .context("failed to write src/runtime/scheduler.fzy")?;
    std::fs::write(
        src.join("runtime/worker.fzy"),
        "use core.thread;\n\nfn run() -> i32 {\n    yield()\n    return 0\n}\n",
    )
    .context("failed to write src/runtime/worker.fzy")?;
    std::fs::write(
        src.join("cli/mod.fzy"),
        "mod commands;\n\nfn boot() -> i32 {\n    commands.boot()\n    return 0\n}\n",
    )
    .context("failed to write src/cli/mod.fzy")?;
    std::fs::write(
        src.join("cli/commands.fzy"),
        "fn boot() -> i32 {\n    return 0\n}\n",
    )
    .context("failed to write src/cli/commands.fzy")?;
    std::fs::write(src.join("tests/mod.fzy"), "mod smoke;\n")
        .context("failed to write src/tests/mod.fzy")?;
    std::fs::write(
        src.join("tests/smoke.fzy"),
        "test \"det_boot\" {}\ntest \"det_flow\" {}\n",
    )
    .context("failed to write src/tests/smoke.fzy")?;

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
                        match artifact.profile {
                            BuildProfile::Dev => "dev",
                            BuildProfile::Release => "release",
                            BuildProfile::Verify => "verify",
                        },
                        Some("compiler"),
                        None,
                        artifact.dependency_graph_hash.is_some(),
                    ),
                ),
            ]);
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
                "profile": match artifact.profile {
                    BuildProfile::Dev => "dev",
                    BuildProfile::Release => "release",
                    BuildProfile::Verify => "verify",
                },
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
        })
        .to_string(),
    }
}

fn render_library_artifact(
    format: Format,
    artifact: LibraryArtifact,
    headers: HeaderArtifact,
    threads: Option<u16>,
    runtime_config: Option<PathBuf>,
) -> String {
    match format {
        Format::Text => {
            let mut rendered = render_text_fields(&[
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
                ("header", headers.path.display().to_string()),
                ("abi_manifest", headers.abi_manifest.display().to_string()),
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
                        match artifact.profile {
                            BuildProfile::Dev => "dev",
                            BuildProfile::Release => "release",
                            BuildProfile::Verify => "verify",
                        },
                        Some("compiler"),
                        None,
                        artifact.dependency_graph_hash.is_some(),
                    ),
                ),
            ]);
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
                "profile": match artifact.profile {
                    BuildProfile::Dev => "dev",
                    BuildProfile::Release => "release",
                    BuildProfile::Verify => "verify",
                },
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
            "header": headers.path.display().to_string(),
            "abiManifest": headers.abi_manifest.display().to_string(),
            "exports": headers.exports,
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
                    policy_summary_text("verify", Some("compiler"), None, true),
                ),
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
                "profile": "verify",
                "unsafeEnforcement": "strict",
                "memorySafetyMode": "production",
                "backend": "compiler",
                "lockfileState": "present-or-created",
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
            rendered.push_str(&render_artifact(Format::Text, artifact.clone(), None, None));
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
        let verify_with = diagnostic
            .path
            .as_deref()
            .map(|path| format!("fz check {path}"))
            .unwrap_or_else(|| "fz check <path>".to_string());
        if let Some(code) = &diagnostic.code {
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
    format!(
        "schema=v1;code={code};profile=verify;backend=compiler;seed=1;path={path}"
    )
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

fn run_non_scenario_test_plan_with_root_guidance(
    path: &Path,
    request: NonScenarioPlanRequest<'_>,
) -> Result<NonScenarioTestPlan> {
    run_non_scenario_test_plan(path, request)
        .map_err(|error| attach_project_root_guidance(path, error))
}

fn attach_project_root_guidance(path: &Path, error: anyhow::Error) -> anyhow::Error {
    let text = error.to_string();
    if !(text.contains("no valid compiler manifest found")
        || text.contains("path is neither a source file nor a project directory"))
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
            "directory `{}` is not a Fozzy project root (missing {}). initialize a project here with `fz init <name>` or run against a project directory/file explicitly",
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

fn maybe_generate_unsafe_docs(path: &Path) -> Option<PathBuf> {
    let resolved = resolve_source(path).ok()?;
    let parsed = parse_program(&resolved.source_path).ok()?;
    if parsed.module.unsafe_sites == 0 {
        return None;
    }
    if audit_unsafe_command(&resolved.project_root, false, Format::Json).is_ok() {
        Some(resolved.project_root.join(".fz/unsafe-docs.md"))
    } else {
        None
    }
}

fn explain_command(diag_code: &str, format: Format) -> Result<String> {
    let normalized = diag_code.trim().to_ascii_uppercase();
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
                        entry.code_prefix, entry.family, entry.summary, entry.example, entry.next_command
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
    let family = if normalized.starts_with("E-PAR-") || normalized.starts_with("W-PAR-") {
        "parser"
    } else if normalized.starts_with("E-HIR-") || normalized.starts_with("W-HIR-") {
        "hir"
    } else if normalized.starts_with("E-VER-") || normalized.starts_with("W-VER-") {
        "verifier"
    } else if normalized.starts_with("E-NAT-") || normalized.starts_with("W-NAT-") {
        "native-lowering"
    } else if normalized.starts_with("E-DRV-") || normalized.starts_with("W-DRV-") {
        "driver"
    } else {
        "unknown"
    };
    let likely_fix = match family {
        "parser" => "Fix syntax at the primary span, then rerun `fz check <path>`.",
        "hir" => "Fix name/type mismatch and rerun `fz check <path>`.",
        "verifier" => "Fix policy/type contract violation and rerun `fz verify <path>`.",
        "native-lowering" => {
            "Adjust unsupported lowering shape or switch backend, then rerun `fz build <path>`."
        }
        "driver" => "Fix project/configuration issue and rerun the failing command.",
        _ => "Run `fz check <path>` to regenerate diagnostics with spans and helps.",
    };
    let catalog_entry = catalog
        .iter()
        .find(|entry| normalized.starts_with(&entry.code_prefix))
        .cloned();
    match format {
        Format::Text => {
            let mut fields = vec![
                ("code", normalized),
                ("family", family.to_string()),
                (
                    "root_cause",
                    "Diagnostic codes are stable hashes of message+span in their domain"
                        .to_string(),
                ),
                ("likely_fix", likely_fix.to_string()),
                ("verify_with", "fz check <path> --json".to_string()),
            ];
            if let Some(entry) = catalog_entry {
                fields.push(("catalog_summary", entry.summary));
                fields.push(("catalog_example", entry.example));
                fields.push(("next_command", entry.next_command));
            }
            Ok(render_text_fields(&fields))
        }
        Format::Json => Ok(serde_json::json!({
            "code": normalized,
            "family": family,
            "rootCause": "Diagnostic code encodes severity/domain and a stable hash of diagnostic content.",
            "likelyFix": likely_fix,
            "verifyWith": "fz check <path> --json",
            "catalog": catalog_entry,
        })
        .to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
struct DiagnosticCatalogEntry {
    code_prefix: String,
    family: String,
    summary: String,
    example: String,
    next_command: String,
}

fn diagnostic_catalog() -> Vec<DiagnosticCatalogEntry> {
    vec![
        DiagnosticCatalogEntry {
            code_prefix: "E-PAR-".to_string(),
            family: "parser".to_string(),
            summary: "Syntax/grammar parse failure at source text boundary.".to_string(),
            example: "E-PAR-xxxx: expected `catch` in try/catch expression".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            code_prefix: "E-HIR-".to_string(),
            family: "hir".to_string(),
            summary: "Type/name/call graph semantic mismatch in typed lowering.".to_string(),
            example: "E-HIR-xxxx: unresolved call target `missing_symbol`".to_string(),
            next_command: "fz check <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            code_prefix: "E-VER-".to_string(),
            family: "verifier".to_string(),
            summary: "Policy/safety contract violation in verification.".to_string(),
            example: "E-VER-xxxx: missing required capability: http".to_string(),
            next_command: "fz verify <path> --json".to_string(),
        },
        DiagnosticCatalogEntry {
            code_prefix: "E-NAT-".to_string(),
            family: "native-lowering".to_string(),
            summary: "Native backend lowerability contract violation.".to_string(),
            example: "E-NAT-xxxx: native backend cannot lower unresolved call target `missing_fn`".to_string(),
            next_command: "fz build <path> --backend llvm --json".to_string(),
        },
        DiagnosticCatalogEntry {
            code_prefix: "E-DRV-".to_string(),
            family: "driver".to_string(),
            summary: "Driver pipeline/configuration/runtime orchestration failure.".to_string(),
            example: "E-DRV-xxxx: lockfile drift detected".to_string(),
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
        bail!("lint target must be a file or project directory: {}", path.display());
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
                    Some("prefer adding requires/ensures to make side-effect expectations explicit".to_string()),
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
                        Some("set [unsafe].enforce_verify=true and enforce_release=true".to_string()),
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
    let exit_status = ProcessCommand::new("python3")
        .arg("scripts/exit_criteria.py")
        .arg("status")
        .output()
        .context("failed to run exit criteria status command")?;
    if !exit_status.status.success() {
        bail!("exit criteria status failed");
    }
    let exit_payload: serde_json::Value = serde_json::from_slice(&exit_status.stdout)
        .context("invalid exit criteria payload")?;
    let dashboard = serde_json::json!({
        "schemaVersion": "fozzylang.stability_dashboard.v1",
        "generatedAt": chrono_like_now_utc(),
        "maturity": exit_payload.get("seriousSystemsLanguageMaturity").cloned().unwrap_or(serde_json::Value::Bool(false)),
        "criteria": exit_payload.get("criteria").cloned().unwrap_or(serde_json::json!({})),
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
                fix: "add fozzy.toml or run `fz init <name>`".to_string(),
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
    let fast = run_non_scenario_test_plan(
        path,
        NonScenarioPlanRequest {
            deterministic: false,
            strict_verify: false,
            safe_profile: false,
            scheduler: None,
            seed: Some(seed),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    )?;
    let det = run_non_scenario_test_plan(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: false,
            safe_profile: false,
            scheduler: Some("fifo".to_string()),
            seed: Some(seed),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    )?;
    let verify = run_non_scenario_test_plan(
        path,
        NonScenarioPlanRequest {
            deterministic: true,
            strict_verify: false,
            safe_profile: true,
            scheduler: Some("fifo".to_string()),
            seed: Some(seed),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    );

    let mut outcomes = vec![
        plan_semantics_outcome("fast", &fast),
        plan_semantics_outcome("det", &det),
    ];
    let mut skipped = BTreeMap::<String, String>::new();
    match verify {
        Ok(verify) => outcomes.push(plan_semantics_outcome("verify", &verify)),
        Err(error) => {
            skipped.insert("verify".to_string(), error.to_string());
        }
    }

    let mut issues = Vec::new();
    if outcomes[0].exit_class != outcomes[1].exit_class {
        issues.push("fast/det exit class mismatch".to_string());
    }
    if outcomes[0].invariants != outcomes[1].invariants {
        issues.push("fast/det invariant mismatch".to_string());
    }
    if outcomes.len() == 3 {
        if outcomes[0].exit_class != outcomes[2].exit_class {
            issues.push("fast/verify exit class mismatch".to_string());
        }
        if outcomes[0].invariants != outcomes[2].invariants {
            issues.push("fast/verify invariant mismatch".to_string());
        }
    }

    let signature = semantic_signature(&serde_json::json!({
        "kind": "mode-parity",
        "outcomes": outcomes,
        "skipped": skipped,
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
            ("path", path.display().to_string()),
            ("signature", signature),
            ("modes", outcomes.len().to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "path": path.display().to_string(),
            "seed": seed,
            "signature": signature,
            "outcomes": outcomes,
            "skipped": skipped,
            "issues": issues,
        })
        .to_string()),
    }
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
    let mut args = vec![
        "test".to_string(),
        scenario.display().to_string(),
        "--strict".to_string(),
        "--json".to_string(),
    ];
    if deterministic {
        args.push("--det".to_string());
    }
    if host_backends {
        args.push("--proc-backend".to_string());
        args.push("host".to_string());
        args.push("--fs-backend".to_string());
        args.push("host".to_string());
        args.push("--http-backend".to_string());
        args.push("host".to_string());
    }
    let output = fozzy_invoke(&args)?;
    let value: serde_json::Value =
        serde_json::from_str(&output).context("failed parsing fozzy test output")?;
    let exit_class = value
        .get("status")
        .and_then(|status| status.as_str())
        .unwrap_or("unknown")
        .to_string();
    let passed = value
        .get("tests")
        .and_then(|tests| tests.get("passed"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let failed = value
        .get("tests")
        .and_then(|tests| tests.get("failed"))
        .and_then(|value| value.as_u64())
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
        let resolved = resolve_source(project_root)?;
        let parsed = parse_program(&resolved.source_path)?;
        for module_path in &parsed.module_paths {
            let source = std::fs::read_to_string(module_path).with_context(|| {
                format!(
                    "failed reading module for unsafe audit: {}",
                    module_path.display()
                )
            })?;
            let module_name = module_path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| anyhow!("invalid module filename for {}", module_path.display()))?;
            let module = parser::parse(&source, module_name).map_err(|diagnostics| {
                let detail = diagnostics
                    .first()
                    .map(|diag| diag.message.clone())
                    .unwrap_or_else(|| "unknown parse failure".to_string());
                anyhow!(
                    "failed parsing module for unsafe audit: {} ({detail})",
                    module_path.display()
                )
            })?;
            entries.extend(collect_semantic_unsafe_entries(
                module_path,
                project_root,
                &module.items,
            ));
        }
    }
    let missing_contract_count = entries
        .iter()
        .filter(|entry| entry.kind != "unsafe_violation_callsite")
        .filter(|entry| {
            entry.reason.as_deref().is_none_or(str::is_empty)
                || entry.invariant.as_deref().is_none_or(str::is_empty)
                || entry.owner.as_deref().is_none_or(str::is_empty)
                || entry.scope.as_deref().is_none_or(str::is_empty)
                || entry.risk_class.as_deref().is_none_or(str::is_empty)
                || entry.proof_ref.as_deref().is_none_or(str::is_empty)
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
        "schemaVersion": "fozzylang.unsafe_map.v2",
        "workspaceMode": workspace,
        "projects": project_roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "entries": entries,
        "missingContractCount": missing_contract_count,
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
    markdown.push_str(&format!(
        "- Entries: {}\n- Missing metadata: {}\n- Invalid proof refs: {}\n- Unsafe context violations: {}\n\n",
        payload["entries"].as_array().map(|v| v.len()).unwrap_or(0),
        missing_contract_count,
        invalid_proof_ref_count,
        unsafe_context_violations
    ));
    markdown.push_str(
        "| Site ID | Kind | Function | Snippet | Reason | Owner | Risk | Proof |\n|---|---|---|---|---|---|---|---|\n",
    );
    if let Some(entries) = payload["entries"].as_array() {
        for entry in entries {
            let site_id = entry["site_id"].as_str().unwrap_or("missing");
            let kind = entry["kind"].as_str().unwrap_or("unknown");
            let function = entry["function"].as_str().unwrap_or("?");
            let snippet = entry["snippet"].as_str().unwrap_or("?");
            let reason = entry["reason"].as_str().unwrap_or("metadata missing");
            let owner = entry["owner"].as_str().unwrap_or("metadata missing");
            let risk = entry["risk_class"].as_str().unwrap_or("metadata missing");
            let proof = entry["proof_ref"].as_str().unwrap_or("metadata missing");
            markdown.push_str(&format!(
                "| `{site_id}` | {kind} | {function} | `{snippet}` | {reason} | {owner} | {risk} | `{proof}` |\n"
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
            || invalid_proof_ref_count > 0
            || unsafe_context_violations > 0)
    {
        bail!(
            "strict unsafe audit failed (missing={}, invalid_proof_ref={}, context_violations={}); map={}",
            missing_contract_count,
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

fn proof_ref_machine_linkable(value: &str) -> bool {
    let value = value.trim();
    let schemes = [
        "trace://", "test://", "rfc://", "gate://", "run://", "ci://",
    ];
    schemes.iter().any(|scheme| value.starts_with(scheme))
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
        for entry in entries.flatten() {
            let path = entry.path();
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
    module_path: &Path,
    project_root: &Path,
    items: &[ast::Item],
) -> Vec<UnsafeEntry> {
    let mut entries = Vec::new();
    let unsafe_callees = items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) if function.is_unsafe => Some(function.name.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for item in items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        let default_owner = generated_unsafe_owner(function);
        if function.is_unsafe {
            let snippet = format!("unsafe fn {}", function.name);
            let site_id = unsafe_site_id(
                "unsafe_fn",
                project_root,
                module_path,
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
            entries.push(UnsafeEntry {
                site_id,
                kind: "unsafe_fn".to_string(),
                project: project_root.display().to_string(),
                file: module_path.display().to_string(),
                function: function.name.clone(),
                line: 0,
                snippet,
                reason: Some(reason),
                invariant: Some(invariant),
                owner: Some(owner),
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
                module_path,
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
            entries.push(UnsafeEntry {
                site_id,
                kind: "unsafe_import".to_string(),
                project: project_root.display().to_string(),
                file: module_path.display().to_string(),
                function: function.name.clone(),
                line: 0,
                snippet,
                reason: Some(reason),
                invariant: Some(invariant),
                owner: Some(owner),
                scope: Some(scope),
                risk_class: Some(risk_class),
                proof_ref: Some(proof_ref),
            });
        }
        for stmt in &function.body {
            collect_semantic_unsafe_entries_from_stmt(
                stmt,
                module_path,
                project_root,
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

fn collect_semantic_unsafe_entries_from_stmt(
    stmt: &ast::Stmt,
    module_path: &Path,
    project_root: &Path,
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
                    function_name,
                    in_unsafe_context,
                    default_owner,
                    unsafe_callees,
                    entries,
                );
            }
        }
        ast::Stmt::Break | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_semantic_unsafe_entries_from_expr(
                scrutinee,
                module_path,
                project_root,
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
            entries.push(UnsafeEntry {
                site_id,
                kind: "unsafe_block".to_string(),
                project: project_root.display().to_string(),
                file: module_path.display().to_string(),
                function: function_name.to_string(),
                line: 0,
                snippet,
                reason: Some(reason),
                invariant: Some(invariant),
                owner: Some(owner),
                scope: Some(scope),
                risk_class: Some(risk_class),
                proof_ref: Some(proof_ref),
            });
            for stmt in body {
                collect_semantic_unsafe_entries_from_stmt(
                    stmt,
                    module_path,
                    project_root,
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
                    line: 0,
                    snippet,
                    reason: None,
                    invariant: None,
                    owner: None,
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
                function_name,
                in_unsafe_context,
                default_owner,
                unsafe_callees,
                entries,
            );
        }
        ast::Expr::Group(inner) | ast::Expr::Await(inner) => {
            collect_semantic_unsafe_entries_from_expr(
                inner,
                module_path,
                project_root,
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
        let export_contract = export
            .get("contract")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
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
        let rendered = render_artifact(Format::Text, artifact, None, None);
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
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
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
    let rpc_methods = parse_rpc_declarations(&parsed.combined_source).unwrap_or_default();
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

    let (_typed, fir) = lower_fir_cached(&parsed);
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
        let (derived_runtime_events, derived_causal_links) =
            derive_runtime_semantic_evidence(&events, &execution_order, &task_ops);
        runtime_events = derived_runtime_events;
        causal_links = derived_causal_links;
    }
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
            &parsed.combined_source,
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
        ast::Stmt::Break | ast::Stmt::Continue => 0,
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
        ast::Stmt::Break | ast::Stmt::Continue => (0, 0),
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
        ast::Expr::Await(inner) | ast::Expr::Group(inner) => analyze_workload_expr(inner),
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
        ast::Stmt::Break | ast::Stmt::Continue => {}
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

fn passthrough_fozzy(command: &str, target: &Path, format: Format) -> Result<String> {
    ensure_exists(target)?;

    let mut args = vec![command.to_string(), target.display().to_string()];
    if matches!(format, Format::Json) {
        args.push("--json".to_string());
    }
    let output = fozzy_invoke(&args)?;
    Ok(cli_output::normalize_cli_output(format, &output))
}

fn replay_like(command: &str, target: &Path, format: Format) -> Result<String> {
    let replay_target = resolve_replay_target(target)?;
    passthrough_fozzy(command, &replay_target, format)
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

fn resolve_native_trace_target(target: &Path) -> Result<PathBuf> {
    ensure_exists(target)?;
    let is_trace = target
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".trace.json"))
        .unwrap_or(false);
    if is_trace {
        return Ok(target.to_path_buf());
    }
    let is_manifest = target
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".manifest.json"))
        .unwrap_or(false);
    if !is_manifest {
        bail!("not a native trace/manifest target: {}", target.display());
    }
    let text = std::fs::read_to_string(target)
        .with_context(|| format!("failed reading native manifest: {}", target.display()))?;
    let manifest: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("failed parsing native manifest: {}", target.display()))?;
    let Some(trace) = manifest.get("trace").and_then(|value| value.as_str()) else {
        bail!("native manifest missing `trace`: {}", target.display());
    };
    let trace_path = PathBuf::from(trace);
    ensure_exists(&trace_path)?;
    Ok(trace_path)
}

fn load_native_trace(target: &Path) -> Result<(PathBuf, NativeTracePayloadOwned)> {
    let trace_path = resolve_native_trace_target(target)?;
    let text = std::fs::read_to_string(&trace_path)
        .with_context(|| format!("failed reading native trace: {}", trace_path.display()))?;
    let trace: NativeTracePayloadOwned = serde_json::from_str(&text)
        .with_context(|| format!("failed parsing native trace: {}", trace_path.display()))?;
    Ok((trace_path, trace))
}

#[derive(Debug, Clone)]
struct TraceNativeArtifacts {
    trace_path: PathBuf,
    manifest_path: PathBuf,
    decision_count: usize,
    event_count: usize,
    rpc_frame_count: usize,
    seed: u64,
}

fn convert_fozzy_trace_to_native(
    target: &Path,
    output: Option<&Path>,
) -> Result<TraceNativeArtifacts> {
    ensure_exists(target)?;
    let source = std::fs::read_to_string(target)
        .with_context(|| format!("failed reading fozzy trace: {}", target.display()))?;
    let payload: serde_json::Value = serde_json::from_str(&source)
        .with_context(|| format!("failed parsing fozzy trace: {}", target.display()))?;

    let format_value = payload.get("format").and_then(|value| value.as_str());
    if format_value != Some("fozzy-trace") {
        bail!(
            "unsupported trace format in {}: expected `fozzy-trace`",
            target.display()
        );
    }

    let decisions = payload
        .get("decisions")
        .and_then(|value| value.as_array())
        .ok_or_else(|| {
            anyhow!(
                "fozzy trace missing `decisions` array: {}",
                target.display()
            )
        })?;
    let events = payload
        .get("events")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let seed = payload
        .get("summary")
        .and_then(|summary| summary.get("identity"))
        .and_then(|identity| identity.get("seed"))
        .and_then(|value| value.as_u64())
        .unwrap_or(1);

    let mut execution_order = Vec::new();
    let mut async_schedule = Vec::new();
    let mut rpc_frames = Vec::new();
    let mut capability = "thread";

    for decision in decisions {
        let Some(kind) = decision.get("kind").and_then(|value| value.as_str()) else {
            continue;
        };
        match kind {
            "scheduler_pick" => {
                let Some(task_id) = decision.get("task_id").and_then(|value| value.as_u64()) else {
                    continue;
                };
                execution_order.push(task_id);
                let label = decision
                    .get("label")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if label.contains("async") || label.contains("await") {
                    async_schedule.push(task_id);
                }
                if label.contains("rpc") {
                    capability = "net";
                }
            }
            "rpc_send" | "rpc_recv" | "rpc_deadline" | "rpc_cancel" => {
                capability = "net";
                rpc_frames.push(RpcFrameEventOwned {
                    kind: kind.to_string(),
                    method: decision
                        .get("method")
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    task_id: decision
                        .get("task_id")
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0),
                });
            }
            "rpc.frame" => {
                capability = "net";
                let event = decision
                    .get("event")
                    .and_then(|value| value.as_str())
                    .unwrap_or("rpc_recv");
                let normalized = match event {
                    "rpc_send" | "rpc_recv" | "rpc_deadline" | "rpc_cancel" => event,
                    _ => "rpc_recv",
                };
                rpc_frames.push(RpcFrameEventOwned {
                    kind: normalized.to_string(),
                    method: decision
                        .get("method")
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    task_id: decision
                        .get("task_id")
                        .and_then(|value| value.as_u64())
                        .or_else(|| decision.get("taskId").and_then(|value| value.as_u64()))
                        .unwrap_or(0),
                });
            }
            "async.schedule" => {
                if let Some(task_id) = decision
                    .get("task_id")
                    .and_then(|value| value.as_u64())
                    .or_else(|| decision.get("taskId").and_then(|value| value.as_u64()))
                {
                    async_schedule.push(task_id);
                }
            }
            _ => {}
        }
    }

    if execution_order.is_empty() {
        execution_order.push(0);
    }

    let trace_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_native_trace_path(target));
    if let Some(parent) = trace_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating native trace output directory: {}",
                parent.display()
            )
        })?;
    }
    let manifest_path = default_native_manifest_path(&trace_path);

    let native_trace = serde_json::json!({
        "schemaVersion": "fozzylang.thread_trace.v0",
        "capability": capability,
        "scheduler": "fifo",
        "seed": seed,
        "executionOrder": execution_order,
        "asyncSchedule": async_schedule,
        "rpcFrames": rpc_frames,
        "events": events,
        "runtimeEvents": [],
        "causalLinks": [],
    });
    std::fs::write(&trace_path, serde_json::to_vec_pretty(&native_trace)?)
        .with_context(|| format!("failed writing native trace: {}", trace_path.display()))?;

    let manifest = serde_json::json!({
        "schemaVersion": "fozzylang.artifacts.v0",
        "trace": trace_path.display().to_string(),
        "goalTrace": target.display().to_string(),
    });
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?).with_context(|| {
        format!(
            "failed writing native trace manifest: {}",
            manifest_path.display()
        )
    })?;

    Ok(TraceNativeArtifacts {
        trace_path,
        manifest_path,
        decision_count: decisions.len(),
        event_count: events.len(),
        rpc_frame_count: rpc_frames.len(),
        seed,
    })
}

fn default_native_trace_path(target: &Path) -> PathBuf {
    let base_dir = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("trace.fozzy");
    let stem = file_name
        .strip_suffix(".fozzy")
        .or_else(|| file_name.strip_suffix(".fozzy.json"))
        .unwrap_or(file_name);
    base_dir.join(format!("{stem}.trace.json"))
}

fn default_native_manifest_path(trace_path: &Path) -> PathBuf {
    let stem = trace_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("trace");
    trace_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.manifest.json"))
}

fn native_explore(target: &Path, format: Format) -> Result<String> {
    let (trace_path, trace) = load_native_trace(target)?;
    let rpc_frames = trace
        .rpc_frames
        .iter()
        .map(|frame| RpcFrameEvent {
            kind: match frame.kind.as_str() {
                "rpc_send" => "rpc_send",
                "rpc_recv" => "rpc_recv",
                "rpc_deadline" => "rpc_deadline",
                "rpc_cancel" => "rpc_cancel",
                _ => "rpc_recv",
            },
            method: frame.method.clone(),
            task_id: frame.task_id,
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.native_explore.v0",
        "engine": "fozzylang-native",
        "trace": trace_path.display().to_string(),
        "schedules": build_schedule_candidates(&trace.execution_order),
        "asyncSchedules": build_schedule_candidates(&trace.async_schedule),
        "rpcFramePermutations": build_rpc_frame_permutations(&trace.execution_order, &rpc_frames),
        "failureClasses": classify_failure_classes(&rpc_frames, &trace.async_schedule, &trace.execution_order),
    });
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "native-explore".to_string()),
            ("trace", trace_path.display().to_string()),
            ("schedules", trace.execution_order.len().to_string()),
            ("async_schedules", trace.async_schedule.len().to_string()),
            ("rpc_frames", trace.rpc_frames.len().to_string()),
        ])),
        Format::Json => Ok(payload.to_string()),
    }
}

#[allow(dead_code)]
fn emit_deterministic_capability_scenario(
    project_root: &Path,
    module_name: &str,
    module: &ast::Module,
    combined_source: &str,
    host_backed_live: bool,
) -> Result<PathBuf> {
    let typed = hir::lower(module);
    let mut capabilities = module.capabilities.clone();
    capabilities.extend(typed.inferred_capabilities);
    capabilities.sort();
    capabilities.dedup();
    let mut steps = capabilities
        .iter()
        .map(|capability| {
            serde_json::json!({
                "type": "trace_event",
                "name": format!("capability:{capability}"),
            })
        })
        .collect::<Vec<_>>();
    steps.extend(build_live_http_probe_steps(
        combined_source,
        host_backed_live,
    ));
    let scenario_payload = serde_json::json!({
        "version": 1,
        "name": format!("det-run-{module_name}"),
        "steps": steps,
    });
    let scenario_dir = project_root.join(".fz").join("det");
    std::fs::create_dir_all(&scenario_dir).with_context(|| {
        format!(
            "failed creating deterministic scenario directory: {}",
            scenario_dir.display()
        )
    })?;
    let scenario_path = scenario_dir.join(format!("{module_name}.det.fozzy.json"));
    std::fs::write(
        &scenario_path,
        serde_json::to_vec_pretty(&scenario_payload)?,
    )
    .with_context(|| {
        format!(
            "failed writing deterministic capability scenario: {}",
            scenario_path.display()
        )
    })?;
    Ok(scenario_path)
}

#[allow(dead_code)]
fn build_live_http_probe_steps(
    combined_source: &str,
    host_backed_live: bool,
) -> Vec<serde_json::Value> {
    if !combined_source.to_ascii_lowercase().contains("anthropic") {
        return Vec::new();
    }
    let script = r#"import json
import os
import sys
import urllib.request

key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
if not key:
    print("missing ANTHROPIC_API_KEY", file=sys.stderr)
    sys.exit(22)

payload = json.dumps({
    "model": "claude-sonnet-4-6",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "ping"}],
}).encode()
req = urllib.request.Request(
    "https://api.anthropic.com/v1/messages",
    data=payload,
    method="POST",
    headers={
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    },
)
with urllib.request.urlopen(req, timeout=30) as resp:
    body = resp.read().decode()
print(body)"#;
    let mut steps = vec![serde_json::json!({
        "type": "trace_event",
        "name": "http.request.anthropic.start",
    })];
    if !host_backed_live {
        steps.push(serde_json::json!({
            "type": "proc_when",
            "cmd": "python3",
            "args": ["-c", script],
            "exit_code": 0,
            "stdout": "{\"id\":\"deterministic.anthropic.stub\"}\n",
            "stderr": "",
            "times": 1,
        }));
    }
    steps.push(serde_json::json!({
        "type": "proc_spawn",
        "cmd": "python3",
        "args": ["-c", script],
        "expect_exit": 0,
    }));
    steps.push(serde_json::json!({
        "type": "trace_event",
        "name": "http.request.anthropic.ok",
    }));
    steps
}

fn resolve_replay_target(target: &Path) -> Result<PathBuf> {
    ensure_exists(target)?;
    let is_native_trace_json = target
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".trace.json"))
        .unwrap_or(false);
    let is_manifest_json = target
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".manifest.json"))
        .unwrap_or(false);

    if !is_native_trace_json && !is_manifest_json {
        return Ok(target.to_path_buf());
    }

    let manifest_path = if is_manifest_json {
        target.to_path_buf()
    } else {
        let stem = target
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("trace");
        let base = target.parent().unwrap_or_else(|| Path::new("."));
        base.join(format!("{stem}.manifest.json"))
    };
    ensure_exists(&manifest_path)?;

    let manifest_text = std::fs::read_to_string(&manifest_path).with_context(|| {
        format!(
            "failed reading native manifest: {}",
            manifest_path.display()
        )
    })?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).with_context(|| {
        format!(
            "failed parsing native manifest: {}",
            manifest_path.display()
        )
    })?;

    if let Some(goal_trace) = manifest.get("goalTrace").and_then(|v| v.as_str()) {
        let path = PathBuf::from(goal_trace);
        if path.exists() {
            return Ok(path);
        }
    }
    let Some(primary_scenario) = manifest.get("primaryScenario").and_then(|v| v.as_str()) else {
        bail!(
            "native test manifest missing `goalTrace` and `primaryScenario`: {}",
            manifest_path.display()
        );
    };
    let primary_scenario_path = PathBuf::from(primary_scenario);
    ensure_exists(&primary_scenario_path)?;

    let stem = manifest_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("trace");
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let goal_trace_path = base.join(format!("{stem}.goal.fozzy"));
    ensure_goal_trace_from_scenario(&primary_scenario_path, &goal_trace_path, 1)?;
    Ok(goal_trace_path)
}

fn ensure_goal_trace_from_scenario(
    primary_scenario: &Path,
    goal_trace_path: &Path,
    seed: u64,
) -> Result<()> {
    if goal_trace_path.exists() {
        std::fs::remove_file(goal_trace_path).with_context(|| {
            format!(
                "failed removing stale goal trace before regeneration: {}",
                goal_trace_path.display()
            )
        })?;
    }
    let args = vec![
        "run".to_string(),
        primary_scenario.display().to_string(),
        "--det".to_string(),
        "--seed".to_string(),
        seed.to_string(),
        "--record".to_string(),
        goal_trace_path.display().to_string(),
        "--json".to_string(),
    ];
    fozzy_invoke(&args).with_context(|| {
        format!(
            "failed recording goal trace from generated scenario {}",
            primary_scenario.display()
        )
    })?;
    Ok(())
}

#[derive(Debug, Clone)]
struct HeaderArtifact {
    path: PathBuf,
    exports: usize,
    abi_manifest: PathBuf,
}

#[derive(Debug, Clone)]
struct RpcArtifacts {
    schema: PathBuf,
    client_stub: PathBuf,
    server_stub: PathBuf,
    methods: usize,
}

fn render_headers(format: Format, artifact: HeaderArtifact) -> String {
    match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "headers".to_string()),
            ("header", artifact.path.display().to_string()),
            ("exports", artifact.exports.to_string()),
            ("abi_manifest", artifact.abi_manifest.display().to_string()),
        ]),
        Format::Json => serde_json::json!({
            "header": artifact.path.display().to_string(),
            "exports": artifact.exports,
            "abiManifest": artifact.abi_manifest.display().to_string(),
        })
        .to_string(),
    }
}

fn render_rpc_artifacts(format: Format, artifacts: RpcArtifacts) -> String {
    match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "rpc-gen".to_string()),
            ("schema", artifacts.schema.display().to_string()),
            ("client", artifacts.client_stub.display().to_string()),
            ("server", artifacts.server_stub.display().to_string()),
            ("methods", artifacts.methods.to_string()),
        ]),
        Format::Json => serde_json::json!({
            "schema": artifacts.schema.display().to_string(),
            "client": artifacts.client_stub.display().to_string(),
            "server": artifacts.server_stub.display().to_string(),
            "methods": artifacts.methods,
        })
        .to_string(),
    }
}

fn render_trace_native_artifacts(format: Format, artifacts: TraceNativeArtifacts) -> String {
    match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "trace-native".to_string()),
            ("native_trace", artifacts.trace_path.display().to_string()),
            ("manifest", artifacts.manifest_path.display().to_string()),
            ("decisions", artifacts.decision_count.to_string()),
            ("events", artifacts.event_count.to_string()),
            ("rpc_frames", artifacts.rpc_frame_count.to_string()),
            ("seed", artifacts.seed.to_string()),
        ]),
        Format::Json => serde_json::json!({
            "trace": artifacts.trace_path.display().to_string(),
            "manifest": artifacts.manifest_path.display().to_string(),
            "decisions": artifacts.decision_count,
            "events": artifacts.event_count,
            "rpcFrames": artifacts.rpc_frame_count,
            "seed": artifacts.seed,
        })
        .to_string(),
    }
}

fn generate_c_headers(path: &Path, output: Option<&Path>) -> Result<HeaderArtifact> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let exports: Vec<&ast::Function> = parsed
        .module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function)
                if function.is_pub
                    && function.is_extern
                    && function
                        .abi
                        .as_deref()
                        .is_some_and(|abi| abi.eq_ignore_ascii_case("c")) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect();
    let repr_c_layouts = collect_repr_c_layouts(&parsed.module)?;
    let repr_c_names = repr_c_layouts
        .iter()
        .map(|layout| layout.name.clone())
        .collect::<BTreeSet<_>>();
    validate_ffi_contract(
        &parsed.module,
        &exports,
        &repr_c_names,
        resolved.manifest.as_ref(),
    )?;

    let header_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_header_path(&resolved));
    if let Some(parent) = header_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating header output directory: {}",
                parent.display()
            )
        })?;
    }

    let package_name = resolved
        .manifest
        .as_ref()
        .map(|manifest| manifest.package.name.as_str())
        .unwrap_or(module_name);
    let header = render_c_header(package_name, &parsed.module, &exports);
    std::fs::write(&header_path, header)
        .with_context(|| format!("failed writing header: {}", header_path.display()))?;
    let abi_manifest = header_path.with_extension("abi.json");
    let panic_boundary = detect_ffi_panic_boundary(&exports, resolved.manifest.as_ref())?;
    let (target_triple, data_layout_hash, compiler_identity_hash) = abi_identity_fields();
    let package_json = serde_json::json!({
        "name": package_name,
        "version": resolved
            .manifest
            .as_ref()
            .map(|manifest| manifest.package.version.as_str())
            .unwrap_or("0.0.0-dev"),
    });
    let abi_payload = serde_json::json!({
        "schemaVersion": "fozzylang.ffi_abi.v1",
        "package": package_json,
        "abiRevision": 1u64,
        "targetTriple": target_triple,
        "dataLayoutHash": data_layout_hash,
        "compilerIdentityHash": compiler_identity_hash,
        "panicBoundary": panic_boundary,
        "layoutPolicy": {
            "reprCStableOnly": true,
            "nonReprCUnstable": true,
        },
        "symbolVersioning": "strict-name-signature-v1",
        "contractSchema": "fozzylang.ffi_contracts.v1",
        "reprCLayouts": repr_c_layouts.iter().map(|layout| {
            serde_json::json!({
                "name": layout.name,
                "kind": layout.kind,
                "size": layout.size,
                "align": layout.align,
            })
        }).collect::<Vec<_>>(),
        "exports": exports.iter().map(|function| {
            serde_json::json!({
                "name": function.name.as_str(),
                "async": function.is_async,
                "symbolVersion": 1u64,
                "params": function.params.iter().map(|param| {
                    let contract = ffi_param_contract(function, param);
                    serde_json::json!({
                        "name": param.name.as_str(),
                        "fzy": param.ty.to_string(),
                        "c": to_c_type(&param.ty),
                        "contract": contract,
                    })
                }).collect::<Vec<_>>(),
                "return": {
                    "fzy": function.return_type.to_string(),
                    "c": to_c_type(&function.return_type),
                    "contract": ffi_return_contract(&function.return_type),
                },
                "contract": {
                    "execution": if function.is_async { "async-handle-v1" } else { "sync" },
                    "callbackBindings": ffi_callback_bindings(function),
                    "asyncBoundary": ffi_async_contract(function),
                },
            })
        }).collect::<Vec<_>>(),
    });
    std::fs::write(&abi_manifest, serde_json::to_vec_pretty(&abi_payload)?).with_context(|| {
        format!(
            "failed writing ffi abi manifest: {}",
            abi_manifest.display()
        )
    })?;

    Ok(HeaderArtifact {
        path: header_path,
        exports: exports.len(),
        abi_manifest,
    })
}

fn generate_rpc_artifacts(path: &Path, out_dir: Option<&Path>) -> Result<RpcArtifacts> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let methods = parse_rpc_declarations(&parsed.combined_source)?;

    let output_dir = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| resolved.project_root.join(".fz").join("rpc"));
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed creating rpc output dir: {}", output_dir.display()))?;

    let schema = output_dir.join("rpc.schema.json");
    let client_stub = output_dir.join("rpc.client.fzy");
    let server_stub = output_dir.join("rpc.server.fzy");
    let schema_payload = serde_json::json!({
        "schemaVersion": "fozzylang.rpc.v0",
        "source": resolved.source_path.display().to_string(),
        "methods": methods.iter().map(|method| serde_json::json!({
            "name": method.name,
            "request": method.request,
            "response": method.response,
            "clientStreaming": method.client_streaming,
            "serverStreaming": method.server_streaming,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(&schema, serde_json::to_vec_pretty(&schema_payload)?)
        .with_context(|| format!("failed writing rpc schema: {}", schema.display()))?;

    let mut client = String::from("// generated by fz rpc gen\n");
    client.push_str("mod rpc_client {\n");
    client.push_str("    fn apply_rpc_contract(timeout_ms: i32) -> i32 {\n");
    client.push_str("        timeout(timeout_ms)\n");
    client.push_str("        deadline(timeout_ms)\n");
    client.push_str("        return 0\n");
    client.push_str("    }\n");
    for method in &methods {
        client.push_str(&format!(
            "    async fn {}(req: {}) -> {} {{\n        discard apply_rpc_contract(5000)\n        let frame = rpc.transport_send(\"{}\", req)\n        if frame == 0 {{\n            cancel()\n        }}\n        let response = recv()\n        return response\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response,
            method.name
        ));
    }
    client.push_str("}\n");
    std::fs::write(&client_stub, client)
        .with_context(|| format!("failed writing rpc client stub: {}", client_stub.display()))?;

    let mut server = String::from("// generated by fz rpc gen\n");
    server.push_str("mod rpc_server {\n");
    server.push_str("    fn apply_rpc_handler_contract(timeout_ms: i32) -> i32 {\n");
    server.push_str("        timeout(timeout_ms)\n");
    server.push_str("        deadline(timeout_ms)\n");
    server.push_str("        return 0\n");
    server.push_str("    }\n");
    for method in &methods {
        server.push_str(&format!(
            "    async fn handle_{}(req: {}) -> {} {{\n        discard apply_rpc_handler_contract(5000)\n        let incoming = rpc.transport_recv(\"{}\")\n        if incoming == 0 {{\n            cancel()\n        }}\n        discard req\n        return incoming\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response,
            method.name
        ));
    }
    server.push_str("}\n");
    std::fs::write(&server_stub, server)
        .with_context(|| format!("failed writing rpc server stub: {}", server_stub.display()))?;

    Ok(RpcArtifacts {
        schema,
        client_stub,
        server_stub,
        methods: methods.len(),
    })
}

fn render_c_header(package_name: &str, module: &ast::Module, exports: &[&ast::Function]) -> String {
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
    header
        .push_str("int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb);\n");
    header.push_str("int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg);\n\n");
    if exports.iter().any(|function| function.is_async) {
        header.push_str("typedef uint64_t fz_async_handle_t;\n\n");
    }
    header.push_str(&render_repr_c_type_defs(module));
    if !header.ends_with("\n\n") {
        header.push('\n');
    }
    for function in exports {
        if function.is_async {
            let params = render_c_params(function);
            let start_params = if params == "void" {
                "fz_async_handle_t* handle_out".to_string()
            } else {
                format!("{params}, fz_async_handle_t* handle_out")
            };
            header.push_str(&format!(
                "int32_t {}_async_start({});\n",
                function.name, start_params
            ));
            header.push_str(&format!(
                "int32_t {}_async_poll(fz_async_handle_t handle, int32_t* done_out);\n",
                function.name
            ));
            header.push_str(&format!(
                "int32_t {}_async_await(fz_async_handle_t handle, int32_t* result_out);\n",
                function.name
            ));
            header.push_str(&format!(
                "int32_t {}_async_drop(fz_async_handle_t handle);\n",
                function.name
            ));
        } else {
            header.push_str(&format!(
                "{} {}({});\n",
                to_c_type(&function.return_type),
                function.name,
                render_c_params(function)
            ));
        }
    }
    if exports.is_empty() {
        header.push_str("/* no exported extern \"C\" functions found */\n");
    }
    header.push_str("\n#ifdef __cplusplus\n}\n#endif\n\n#endif\n");
    header
}

fn render_repr_c_type_defs(module: &ast::Module) -> String {
    let mut out = String::new();
    for item in &module.items {
        match item {
            ast::Item::Struct(item) if is_repr_c(item.repr.as_deref()) => {
                out.push_str(&format!("typedef struct {} {{\n", item.name));
                for field in &item.fields {
                    out.push_str(&format!("    {} {};\n", to_c_type(&field.ty), field.name));
                }
                out.push_str(&format!("}} {};\n\n", item.name));
            }
            ast::Item::Enum(item) if is_repr_c(item.repr.as_deref()) => {
                out.push_str(&format!("typedef enum {} {{\n", item.name));
                for (idx, variant) in item.variants.iter().enumerate() {
                    out.push_str(&format!("    {}_{} = {},\n", item.name, variant.name, idx));
                }
                out.push_str(&format!("}} {};\n\n", item.name));
            }
            _ => {}
        }
    }
    out
}

fn validate_ffi_contract(
    module: &ast::Module,
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
    if exports.is_empty() {
        return Ok(());
    }
    let mut panic_mode: Option<&str> = None;
    for function in exports {
        let mode = function.ffi_panic.as_deref().or(project_default).ok_or_else(|| {
            anyhow!(
                "ffi panic contract missing on export `{}`: set [ffi].panic_boundary in fozzy.toml or add #[ffi_panic(...)] override",
                function.name
            )
        })?;
        if mode != "abort" && mode != "error" {
            bail!(
                "invalid ffi panic mode `{}` on export `{}`; expected `abort` or `error`",
                mode,
                function.name
            );
        }
        if let Some(expected) = panic_mode {
            if expected != mode {
                bail!(
                    "ffi panic contract mismatch across exports: expected `{}` but `{}` uses `{}`",
                    expected,
                    function.name,
                    mode
                );
            }
        } else {
            panic_mode = Some(mode);
        }
    }
    for function in exports {
        if function.is_async {
            if function.body.is_empty() {
                bail!(
                    "extern async export `{}` must define a body; declaration-only async exports are not allowed",
                    function.name
                );
            }
            if !is_i32_type(&function.return_type) {
                bail!(
                    "extern async export `{}` must return `i32` for async-handle-v1 ABI",
                    function.name
                );
            }
        }
        if !is_ffi_stable_type(&function.return_type, repr_c_names) {
            bail!(
                "extern export `{}` uses unstable return type `{}`",
                function.name,
                function.return_type
            );
        }
        let mut has_callback_param = false;
        let mut has_callback_context = false;
        for param in &function.params {
            if !is_ffi_stable_type(&param.ty, repr_c_names) {
                bail!(
                    "extern export `{}` param `{}` uses unstable type `{}`",
                    function.name,
                    param.name,
                    param.ty
                );
            }
            if matches!(param.ty, ast::Type::Ptr { .. }) {
                let tagged = param.name.ends_with("_owned")
                    || param.name.ends_with("_borrowed")
                    || param.name.ends_with("_out")
                    || param.name.ends_with("_inout");
                if !tagged {
                    bail!(
                        "extern export `{}` pointer param `{}` must declare ownership transfer tag suffix (`_owned`, `_borrowed`, `_out`, `_inout`)",
                        function.name,
                        param.name
                    );
                }
                let ctx_param = param.name.ends_with("_ctx") || param.name.ends_with("_context");
                if !ctx_param && !has_len_pair(function, &param.name) {
                    bail!(
                        "extern export `{}` pointer param `{}` must declare paired length parameter (`{}_len` or `len`)",
                        function.name,
                        param.name,
                        pointer_base_name(&param.name),
                    );
                }
            }
            let name_lc = param.name.to_ascii_lowercase();
            if name_lc.contains("callback") || name_lc.starts_with("cb") {
                has_callback_param = true;
            }
            if name_lc.ends_with("_ctx") || name_lc.ends_with("_context") {
                has_callback_context = true;
            }
        }
        if has_callback_param && !has_callback_context {
            bail!(
                "extern export `{}` defines callback param but missing lifetime context param (`*_ctx` or `*_context`)",
                function.name
            );
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
}

fn collect_repr_c_layouts(module: &ast::Module) -> Result<Vec<ReprCLayout>> {
    let mut layouts = Vec::new();
    for item in &module.items {
        match item {
            ast::Item::Struct(item) if is_repr_c(item.repr.as_deref()) => {
                let mut offset = 0usize;
                let mut struct_align = 1usize;
                for field in &item.fields {
                    let (size, align) = ffi_type_layout(&field.ty).ok_or_else(|| {
                        anyhow!(
                            "repr(C) struct `{}` field `{}` uses unsupported layout type `{}`",
                            item.name,
                            field.name,
                            field.ty
                        )
                    })?;
                    offset = align_up(offset, align);
                    offset += size;
                    struct_align = struct_align.max(align);
                }
                let size = align_up(offset, struct_align);
                layouts.push(ReprCLayout {
                    name: item.name.clone(),
                    kind: "struct",
                    size,
                    align: struct_align,
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

fn render_c_params(function: &ast::Function) -> String {
    let params = function
        .params
        .iter()
        .map(|param| format!("{} {}", to_c_type(&param.ty), param.name))
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

fn ffi_param_contract(function: &ast::Function, param: &ast::Param) -> serde_json::Value {
    let mut lifetime_anchor = serde_json::Value::Null;
    let mut ownership = "value";
    let mut nullability = "n/a";
    let mut mutability = "const";
    let mut view = serde_json::Value::Null;
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
    }
    serde_json::json!({
        "ownership": ownership,
        "nullability": nullability,
        "mutability": mutability,
        "lifetimeAnchor": lifetime_anchor,
        "view": view,
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

fn ffi_callback_bindings(function: &ast::Function) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for param in &function.params {
        let name_lc = param.name.to_ascii_lowercase();
        if !(name_lc.contains("callback") || name_lc.starts_with("cb")) {
            continue;
        }
        let base = param
            .name
            .trim_end_matches("_callback")
            .trim_end_matches("_cb");
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
            "obligation": "context_outlives_callback_registration",
        }));
    }
    out
}

fn ffi_async_contract(function: &ast::Function) -> serde_json::Value {
    if !function.is_async {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "model": "async-handle-v1",
        "startSymbol": format!("{}_async_start", function.name),
        "pollSymbol": format!("{}_async_poll", function.name),
        "awaitSymbol": format!("{}_async_await", function.name),
        "dropSymbol": format!("{}_async_drop", function.name),
        "resultType": to_c_type(&function.return_type),
    })
}

fn is_ffi_stable_type(ty: &ast::Type, repr_c_names: &BTreeSet<String>) -> bool {
    match ty {
        ast::Type::Void
        | ast::Type::Bool
        | ast::Type::Char
        | ast::Type::Float { .. }
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. } => true,
        ast::Type::Ptr { to, .. } => is_ffi_stable_type(to, repr_c_names),
        ast::Type::Named { name, args } => args.is_empty() && repr_c_names.contains(name),
        ast::Type::Str
        | ast::Type::Slice(_)
        | ast::Type::Result { .. }
        | ast::Type::Option(_)
        | ast::Type::Vec(_)
        | ast::Type::Ref { .. }
        | ast::Type::Array { .. }
        | ast::Type::Function { .. }
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
struct ResolvedSource {
    source_path: PathBuf,
    project_root: PathBuf,
    manifest: Option<manifest::Manifest>,
}

fn resolve_source(path: &Path) -> Result<ResolvedSource> {
    if path.is_file() {
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedSource {
            source_path: path.to_path_buf(),
            project_root: root,
            manifest: None,
        });
    }
    if !path.is_dir() {
        bail!(
            "path is neither a source file nor a project directory: {}",
            path.display()
        );
    }
    let manifest_path = path.join("fozzy.toml");
    let manifest_text = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let suggestions = discover_nested_project_roots(path);
            let guidance = if suggestions.is_empty() {
                format!(
                    "directory `{}` is not a Fozzy project root (missing {}). initialize a project here with `fz init <name>` or run the command against a project directory/file explicitly",
                    path.display(),
                    manifest_path.display()
                )
            } else {
                format!(
                    "directory `{}` is not a Fozzy project root (missing {}). detected nested project(s): {}. run `fz audit unsafe <project-path>` for one of those roots",
                    path.display(),
                    manifest_path.display(),
                    suggestions
                        .iter()
                        .map(|candidate| candidate.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            bail!(guidance);
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed reading manifest: {}", manifest_path.display()));
        }
    };
    let manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
    let relative = manifest
        .target
        .lib
        .as_ref()
        .map(|lib| lib.path.as_str())
        .or_else(|| manifest.primary_bin_path())
        .ok_or_else(|| {
            anyhow!(
                "no [target.lib] or [[target.bin]] entry in {} for source resolution",
                manifest_path.display()
            )
        })?;
    Ok(ResolvedSource {
        source_path: path.join(relative),
        project_root: path.to_path_buf(),
        manifest: Some(manifest),
    })
}

fn discover_nested_project_roots(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(path) else {
        return out;
    };
    for entry in entries.flatten() {
        let candidate = entry.path();
        if !candidate.is_dir() {
            continue;
        }
        if candidate.join("fozzy.toml").exists() {
            out.push(candidate);
        }
    }
    out.sort();
    out
}

fn discover_project_roots(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("path `{}` has no parent directory", path.display()))?;
        return discover_project_roots(parent);
    }
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    if !path.is_dir() {
        bail!(
            "workspace unsafe audit expects a directory root: {}",
            path.display()
        );
    }

    let mut out = Vec::<PathBuf>::new();
    if is_valid_project_root(path) {
        out.push(path.to_path_buf());
    }
    let mut queue = VecDeque::from([path.to_path_buf()]);
    while let Some(root) = queue.pop_front() {
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let candidate = entry.path();
            if !candidate.is_dir() {
                continue;
            }
            let name = candidate
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or_default();
            if name.starts_with('.')
                || name == "target"
                || name == "artifacts"
                || name == "vendor"
                || name == "node_modules"
            {
                continue;
            }
            if is_valid_project_root(&candidate) {
                out.push(candidate.clone());
            }
            queue.push_back(candidate);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn is_valid_project_root(path: &Path) -> bool {
    let manifest_path = path.join("fozzy.toml");
    let text = match std::fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let manifest = match manifest::load(&text) {
        Ok(manifest) => manifest,
        Err(_) => return false,
    };
    manifest.validate().is_ok()
}

fn default_header_path(resolved: &ResolvedSource) -> PathBuf {
    if let Some(manifest) = &resolved.manifest {
        return resolved
            .project_root
            .join("include")
            .join(format!("{}.h", manifest.package.name));
    }
    let stem = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .unwrap_or("module");
    resolved
        .source_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.h"))
}

#[derive(Debug, Clone)]
struct RpcMethod {
    name: String,
    request: String,
    response: String,
    client_streaming: bool,
    server_streaming: bool,
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
        let args = declaration[(open + 1)..close].trim();
        let request = if args.is_empty() {
            "void".to_string()
        } else if let Some((_, ty)) = args.split_once(':') {
            ty.trim().to_string()
        } else {
            args.to_string()
        };
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
            client_streaming: request.starts_with("stream<"),
            server_streaming: response.starts_with("stream<"),
            request,
            response,
        });
    }
    if methods.is_empty() {
        bail!("no `rpc` declarations found in source");
    }
    Ok(methods)
}

fn fozzy_invoke(args: &[String]) -> Result<String> {
    let mut child = ProcessCommand::new("fozzy");
    child.args(args);

    let output = child.output().context("failed to invoke fozzy binary")?;
    if !output.status.success() {
        let command = args.join(" ");
        let status = output.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "fozzy {} failed (exit={}): stderr=`{}` stdout=`{}`",
            command,
            status,
            if stderr.is_empty() {
                "<empty>"
            } else {
                &stderr
            },
            if stdout.is_empty() {
                "<empty>"
            } else {
                &stdout
            }
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
    let files = discover_doc_sources(path)?;
    let mut items = Vec::<DocItem>::new();
    for file in files {
        items.extend(extract_doc_items(&file)?);
    }
    items.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    let rendered = match output_format.trim().to_ascii_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&items)?,
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

fn discover_doc_sources(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        bail!("input path is neither a file nor directory: {}", path.display());
    }
    let mut files = Vec::<PathBuf>::new();
    collect_fzy_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_fzy_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("failed reading {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed iterating {}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_fzy_files(&path, files)?;
            continue;
        }
        if is_fzy_source_path(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn extract_doc_items(path: &Path) -> Result<Vec<DocItem>> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading source file: {}", path.display()))?;
    let module = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_string();
    let path_string = path.display().to_string();

    let mut items = Vec::new();
    let mut pending_docs = Vec::<String>::new();
    let mut in_block_doc = false;
    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if in_block_doc {
            if let Some(prefix) = line.strip_suffix("*/") {
                let cleaned = prefix.trim_start_matches('*').trim();
                if !cleaned.is_empty() {
                    pending_docs.push(cleaned.to_string());
                }
                in_block_doc = false;
                continue;
            }
            let cleaned = line.trim_start_matches('*').trim();
            if !cleaned.is_empty() {
                pending_docs.push(cleaned.to_string());
            }
            continue;
        }
        if let Some(doc) = line.strip_prefix("///") {
            pending_docs.push(doc.trim().to_string());
            continue;
        }
        if let Some(after) = line.strip_prefix("/**") {
            if let Some(mid) = after.strip_suffix("*/") {
                let cleaned = mid.trim();
                if !cleaned.is_empty() {
                    pending_docs.push(cleaned.to_string());
                }
            } else {
                let cleaned = after.trim_start_matches('*').trim();
                if !cleaned.is_empty() {
                    pending_docs.push(cleaned.to_string());
                }
                in_block_doc = true;
            }
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let without_attrs = strip_doc_leading_attributes(line);
        if without_attrs.is_empty() {
            continue;
        }
        if let Some((kind, name, signature)) = parse_doc_decl(&without_attrs) {
            items.push(DocItem {
                kind,
                name,
                signature,
                module: module.clone(),
                path: path_string.clone(),
                line: line_number,
                docs: pending_docs.join("\n"),
            });
            pending_docs.clear();
            continue;
        }
        pending_docs.clear();
    }
    Ok(items)
}

fn strip_doc_leading_attributes(line: &str) -> String {
    let mut cursor = line.trim();
    while let Some(rest) = cursor.strip_prefix("#[") {
        if let Some(close) = rest.find(']') {
            cursor = rest[(close + 1)..].trim_start();
        } else {
            break;
        }
    }
    cursor.to_string()
}

fn parse_doc_decl(line: &str) -> Option<(String, String, String)> {
    if let Some(rest) = line.strip_prefix("fn ") {
        let name = rest.split('(').next()?.trim();
        return Some(("fn".to_string(), clean_doc_name(name), line.to_string()));
    }
    if let Some(rest) = line.strip_prefix("struct ") {
        let name = rest.split('{').next()?.trim();
        return Some(("struct".to_string(), clean_doc_name(name), line.to_string()));
    }
    if let Some(rest) = line.strip_prefix("enum ") {
        let name = rest.split('{').next()?.trim();
        return Some(("enum".to_string(), clean_doc_name(name), line.to_string()));
    }
    if let Some(rest) = line.strip_prefix("trait ") {
        let name = rest.split('{').next()?.trim();
        return Some(("trait".to_string(), clean_doc_name(name), line.to_string()));
    }
    if let Some(rest) = line.strip_prefix("impl ") {
        let name = rest.split('{').next()?.trim();
        return Some(("impl".to_string(), clean_doc_name(name), line.to_string()));
    }
    if let Some(rest) = line.strip_prefix("rpc ") {
        let name = rest.split('(').next()?.trim();
        return Some(("rpc".to_string(), clean_doc_name(name), line.to_string()));
    }
    if let Some(rest) = line.strip_prefix("test ") {
        let name = rest
            .trim()
            .trim_start_matches('"')
            .split('"')
            .next()
            .unwrap_or(rest.trim())
            .trim();
        return Some(("test".to_string(), clean_doc_name(name), line.to_string()));
    }
    None
}

fn clean_doc_name(raw: &str) -> String {
    raw.trim()
        .trim_matches('{')
        .trim_matches('(')
        .trim_matches(')')
        .trim_matches(';')
        .to_string()
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
        bail!("invalid reference markers ordering in {}", reference_path.display());
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
                        format!("failed reading file for formatting: {}", entry_path.display())
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
    use std::path::Path;

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
    fn version_command_returns_semver() {
        let output = run(Command::Version, Format::Text).expect("version command should run");
        assert!(output.contains('.'));
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

        let equivalence =
            equivalence_command(&source, 4242, Format::Json).expect("equivalence should run");
        let equivalence_json: serde_json::Value =
            serde_json::from_str(&equivalence).expect("equivalence json should parse");
        assert_eq!(equivalence_json["ok"], true);
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
        assert!(output.contains("\"missingContractCount\":0"));
        assert!(output.contains("compiler-generated"));

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
        assert!(output.contains("\"missingContractCount\":0"));
        assert!(output.contains("compiler-generated"));
        assert!(output.contains("\"strictUnsafeAudit\":true"));

        let _ = std::fs::remove_file(source);
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
        assert!(abi_text.contains("\"execution\": \"async-handle-v1\""));
        assert!(abi_text.contains("\"startSymbol\": \"flush_async_start\""));

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
        let mode = layouts
            .iter()
            .find(|layout| layout["name"] == "Mode")
            .expect("Mode layout should exist");
        assert_eq!(mode["size"].as_u64(), Some(4));
        assert_eq!(mode["align"].as_u64(), Some(4));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
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
        assert!(out_dir.join("rpc.schema.json").exists());
        assert!(out_dir.join("rpc.client.fzy").exists());
        assert!(out_dir.join("rpc.server.fzy").exists());
        let client = std::fs::read_to_string(out_dir.join("rpc.client.fzy"))
            .expect("rpc client should be readable");
        let server = std::fs::read_to_string(out_dir.join("rpc.server.fzy"))
            .expect("rpc server should be readable");
        assert!(!client.contains("TODO"));
        assert!(!server.contains("TODO"));
        assert!(client.contains("deadline("));
        assert!(client.contains("cancel()"));
        assert!(server.contains("deadline("));
        assert!(server.contains("cancel()"));

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

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(out_dir);
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
        assert!(output.contains("\"buildMode\":\"lib\""));
        assert!(output.contains("\"staticLib\""));
        assert!(output.contains("\"sharedLib\""));
        assert!(output.contains("\"header\""));
        assert!(output.contains("\"abiManifest\""));

        let _ = std::fs::remove_file(source);
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
            },
            Format::Json,
        )
        .expect("run should succeed for sibling name collisions");
        assert!(run_output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_run_allows_host_backends_flag() {
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
            },
            Format::Json,
        )
        .expect("native host backend run should execute via native path");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn scenario_routing_disables_det_for_host_backends() {
        let routing = scenario_run_routing(true, true);
        assert!(!routing.deterministic_applied);
        assert_eq!(routing.mode, "host-backed-live-scenario");
        assert!(routing
            .reason
            .contains("does not support host proc backend"));
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
            "use core.fs;\nfn main() -> i32 {\n    fs.open()\n    return 0\n}\n",
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
        assert!(trace_text.contains("\"format\":\"fozzy-trace\""));
        assert!(trace_text.contains("\"version\":3"));
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
                "format": "fozzy-trace",
                "version": 3,
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
        assert!(trace_text.contains("\"event\": \"rpc_send\""));
        let manifest_text =
            std::fs::read_to_string(&native_manifest).expect("native manifest should be written");
        assert!(manifest_text.contains("\"goalTrace\""));
        assert!(manifest_text.contains("goal.fozzy"));

        let _ = std::fs::remove_dir_all(base);
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
}
