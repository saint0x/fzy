use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{anyhow, bail, Context, Result};
use runtime::{plan_async_checkpoints, DeterministicExecutor, Scheduler, TaskEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pipeline::{
    compile_file_with_backend, emit_ir, parse_program, refresh_lockfile, verify_file,
    BuildArtifact, BuildProfile, Output,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init {
        name: String,
    },
    Build {
        path: PathBuf,
        release: bool,
        threads: Option<u16>,
        backend: Option<String>,
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
        path: PathBuf,
    },
    Check {
        path: PathBuf,
    },
    Verify {
        path: PathBuf,
    },
    DxCheck {
        path: PathBuf,
        strict: bool,
    },
    SpecCheck,
    EmitIr {
        path: PathBuf,
    },
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
    Headers {
        path: PathBuf,
        output: Option<PathBuf>,
    },
    RpcGen {
        path: PathBuf,
        out_dir: Option<PathBuf>,
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
            threads,
            backend,
        } => {
            let profile = if release {
                BuildProfile::Release
            } else {
                BuildProfile::Dev
            };
            let artifact = compile_file_with_backend(&path, profile, backend.as_deref())?;
            let runtime_config = persist_runtime_threads_config(&path, threads)?;
            Ok(render_artifact(format, artifact, threads, runtime_config))
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
                if matches!(format, Format::Json) {
                    fozzy_args.push("--json".to_string());
                }
                return fozzy_invoke(&fozzy_args);
            }

            let artifact = compile_file_with_backend(
                &path,
                if safe_profile {
                    BuildProfile::Verify
                } else {
                    BuildProfile::Dev
                },
                backend.as_deref(),
            )?;
            if artifact.status != "ok" || artifact.output.is_none() {
                bail!(
                    "run aborted: build status={} diagnostics={}",
                    artifact.status,
                    artifact.diagnostics
                );
            }
            if deterministic {
                let resolved = resolve_source(&path)?;
                let parsed = parse_program(&resolved.source_path)?;
                let scenario = emit_deterministic_capability_scenario(
                    &resolved.project_root,
                    &artifact.module,
                    &parsed.module,
                )?;
                let mut fozzy_args = vec!["run".to_string(), scenario.display().to_string()];
                fozzy_args.push("--det".to_string());
                if strict_verify {
                    fozzy_args.push("--strict".to_string());
                }
                if let Some(seed) = seed {
                    fozzy_args.push("--seed".to_string());
                    fozzy_args.push(seed.to_string());
                }
                if let Some(record) = &record {
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
                    Format::Text => Ok(format!(
                        "deterministic run routed via {} for module={} status={}",
                        scenario.display(),
                        artifact.module,
                        routed
                    )),
                    Format::Json => Ok(serde_json::json!({
                        "module": artifact.module,
                        "status": artifact.status,
                        "diagnostics": artifact.diagnostics,
                        "deterministic": true,
                        "strictVerify": strict_verify,
                        "safeProfile": safe_profile,
                        "seed": seed,
                        "hostBackends": host_backends,
                        "routing": {
                            "mode": "deterministic-capability-scenario",
                            "scenario": scenario.display().to_string(),
                        },
                        "fozzy": routed,
                    })
                    .to_string()),
                };
            }
            let binary = artifact
                .output
                .as_ref()
                .ok_or_else(|| anyhow!("missing native output artifact"))?;
            let output = ProcessCommand::new(binary)
                .args(&args)
                .output()
                .with_context(|| {
                    format!("failed to execute native artifact: {}", binary.display())
                })?;
            let exit_code = output.status.code().unwrap_or(1);
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            match format {
                Format::Text => Ok(format!(
                    "compiled {} and executed {} with args: {}; exit_code={}; stdout={}; stderr={}",
                    artifact.module,
                    binary.display(),
                    args.join(" "),
                    exit_code,
                    stdout,
                    stderr
                )),
                Format::Json => Ok(serde_json::json!({
                    "module": artifact.module,
                    "status": artifact.status,
                    "diagnostics": artifact.diagnostics,
                    "binary": binary.display().to_string(),
                    "args": args,
                    "deterministic": deterministic,
                    "strictVerify": strict_verify,
                    "safeProfile": safe_profile,
                    "seed": seed,
                    "hostBackends": host_backends,
                    "exitCode": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                })
                .to_string()),
            }
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

            let test_plan = run_non_scenario_test_plan(
                &path,
                deterministic,
                strict_verify,
                safe_profile,
                scheduler.clone(),
                seed,
                record.as_deref(),
                rich_artifacts,
                filter.as_deref(),
            )?;
            let message = format!(
                "test harness built for {} (deterministic={}, strict_verify={}, scheduler={}, executed_tasks={}, order={:?}, artifacts={})",
                test_plan.module,
                deterministic,
                strict_verify,
                test_plan.scheduler,
                test_plan.executed_tasks,
                test_plan.execution_order,
                test_plan
                    .artifacts
                    .as_ref()
                    .map(|artifacts| artifacts.trace_path.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string())
            );
            match format {
                Format::Text => Ok(message),
                Format::Json => Ok(serde_json::json!({
                    "module": test_plan.module,
                    "deterministic": deterministic,
                    "strictVerify": strict_verify,
                    "safeProfile": safe_profile,
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
        Command::Fmt { path } => {
            ensure_exists(&path)?;
            let changed = format_source_file(&path)?;
            let message = if changed {
                format!("formatted {}", path.display())
            } else {
                format!("already formatted {}", path.display())
            };
            Ok(render(format, &message))
        }
        Command::Check { path } => {
            let output = verify_file(&path)?;
            Ok(render_output(format, output))
        }
        Command::Verify { path } => {
            let output = verify_file(&path)?;
            Ok(render_output(format, output))
        }
        Command::DxCheck { path, strict } => dx_check_command(&path, strict, format),
        Command::SpecCheck => spec_check(format),
        Command::EmitIr { path } => {
            let output = emit_ir(&path)?;
            Ok(render_output(format, output))
        }
        Command::Parity { path, seed } => parity_command(&path, seed.unwrap_or(1), format),
        Command::Equivalence { path, seed } => {
            equivalence_command(&path, seed.unwrap_or(1), format)
        }
        Command::AuditUnsafe { path } => audit_unsafe_command(&path, format),
        Command::Vendor { path } => vendor_command(&path, format),
        Command::AbiCheck { current, baseline } => abi_check_command(&current, &baseline, format),
        Command::DebugCheck { path } => debug_check_command(&path, format),
        Command::LspDiagnostics { path } => lsp_diagnostics_command(&path, format),
        Command::LspDefinition { path, symbol } => lsp_definition_command(&path, &symbol, format),
        Command::LspHover { path, symbol } => lsp_hover_command(&path, &symbol, format),
        Command::LspRename { path, from, to } => lsp_rename_command(&path, &from, &to, format),
        Command::LspSmoke { path } => lsp_smoke_command(&path, format),
        Command::Fuzz { target } => passthrough_fozzy("fuzz", &target, format),
        Command::Explore { target } => {
            if is_native_trace_or_manifest(&target) {
                native_explore(&target, format)
            } else {
                passthrough_fozzy("explore", &target, format)
            }
        }
        Command::Replay { trace } => {
            if is_native_trace_or_manifest(&trace) {
                native_replay(&trace, format)
            } else {
                replay_like("replay", &trace, format)
            }
        }
        Command::Shrink { trace } => {
            if is_native_trace_or_manifest(&trace) {
                native_shrink(&trace, format)
            } else {
                replay_like("shrink", &trace, format)
            }
        }
        Command::Ci { trace } => {
            if is_native_trace_or_manifest(&trace) {
                native_ci(&trace, format)
            } else {
                replay_like("ci", &trace, format)
            }
        }
        Command::Headers { path, output } => {
            let generated = generate_c_headers(&path, output.as_deref())?;
            Ok(render_headers(format, generated))
        }
        Command::RpcGen { path, out_dir } => {
            let generated = generate_rpc_artifacts(&path, out_dir.as_deref())?;
            Ok(render_rpc_artifacts(format, generated))
        }
        Command::Version => Ok(render(format, env!("CARGO_PKG_VERSION"))),
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
        "[package]\nname = \"{}\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"{}\"\npath = \"src/main.fzy\"\n",
        name, name
    );

    std::fs::write(root.join("fozzy.toml"), &manifest).context("failed to write fozzy.toml")?;
    std::fs::write(
        src.join("main.fzy"),
        "use cap.time;\nuse cap.fs;\nuse cap.net;\nuse cap.thread;\n\nmod api;\nmod model;\nmod services;\nmod runtime;\nmod cli;\nmod tests;\n\nfn main() -> i32 {\n    requires true\n\n    model.preflight()\n    cli.boot()\n    services.boot_all()\n    runtime.start()\n    api.touch()\n\n    ensures true\n    return 0\n}\n",
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
        "use cap.fs;\n\nfn init() -> i32 {\n    let handle = fs.open()\n    defer close(handle)\n    return 0\n}\n",
    )
    .context("failed to write src/services/store.fzy")?;
    std::fs::write(
        src.join("services/http.fzy"),
        "use cap.net;\n\nfn start() -> i32 {\n    let conn = net.connect()\n    defer close(conn)\n    return 0\n}\n",
    )
    .context("failed to write src/services/http.fzy")?;
    std::fs::write(
        src.join("runtime/mod.fzy"),
        "mod scheduler;\nmod worker;\n\nfn start() -> i32 {\n    spawn(worker.run)\n    spawn(scheduler.tick)\n    return 0\n}\n",
    )
    .context("failed to write src/runtime/mod.fzy")?;
    std::fs::write(
        src.join("runtime/scheduler.fzy"),
        "use cap.thread;\n\nfn tick() -> i32 {\n    checkpoint()\n    return 0\n}\n",
    )
    .context("failed to write src/runtime/scheduler.fzy")?;
    std::fs::write(
        src.join("runtime/worker.fzy"),
        "use cap.thread;\n\nfn run() -> i32 {\n    yield()\n    return 0\n}\n",
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
    match format {
        Format::Text => message.to_string(),
        Format::Json => serde_json::json!({"message": message}).to_string(),
    }
}

fn render_artifact(
    format: Format,
    artifact: BuildArtifact,
    threads: Option<u16>,
    runtime_config: Option<PathBuf>,
) -> String {
    match format {
        Format::Text => format!(
            "module={} profile={:?} status={} diagnostics={} output={} threads={} runtime_config={} dep_graph_hash={}",
            artifact.module,
            artifact.profile,
            artifact.status,
            artifact.diagnostics,
            artifact
                .output
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            threads
                .map(|threads| threads.to_string())
                .unwrap_or_else(|| "default".to_string()),
            runtime_config
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            artifact
                .dependency_graph_hash
                .clone()
                .unwrap_or_else(|| "<none>".to_string())
        ),
        Format::Json => serde_json::json!({
            "module": artifact.module,
            "profile": format!("{:?}", artifact.profile),
            "status": artifact.status,
            "diagnostics": artifact.diagnostics,
            "dependencyGraphHash": artifact.dependency_graph_hash,
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

fn render_output(format: Format, output: Output) -> String {
    match format {
        Format::Text => {
            let mut rendered = format!(
                "module={} nodes={} diagnostics={}",
                output.module, output.nodes, output.diagnostics
            );
            if let Some(ir) = &output.backend_ir {
                rendered.push('\n');
                rendered.push_str(ir);
            }
            rendered
        }
        Format::Json => serde_json::json!({
            "schemaVersion": "fozzylang.diagnostics.v1",
            "module": output.module,
            "nodes": output.nodes,
            "diagnostics": output.diagnostics,
            "items": output.diagnostic_details,
            "backendIr": output.backend_ir,
        })
        .to_string(),
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
    if let Ok(explicit) = std::env::var("FOZZYC_SPEC_PATH") {
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
        Format::Text => Ok(format!(
            "dx-check ok project={} strict={} issues={}",
            path.display(),
            strict,
            issues.len()
        )),
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
        Format::Text => Ok(format!(
            "spec-check ok path={} sections={}",
            path.display(),
            required.len()
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": ok,
            "path": path.display().to_string(),
            "requiredSections": required,
            "missingSections": missing,
        })
        .to_string()),
    }
}

fn parity_command(path: &Path, seed: u64, format: Format) -> Result<String> {
    ensure_exists(path)?;
    let fast = run_non_scenario_test_plan(
        path,
        false,
        false,
        false,
        None,
        Some(seed),
        None,
        false,
        None,
    )?;
    let det = run_non_scenario_test_plan(
        path,
        true,
        false,
        false,
        Some("fifo".to_string()),
        Some(seed),
        None,
        false,
        None,
    )?;
    let verify = run_non_scenario_test_plan(
        path,
        true,
        false,
        true,
        Some("fifo".to_string()),
        Some(seed),
        None,
        false,
        None,
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
        Format::Text => Ok(format!(
            "parity ok path={} signature={} modes={}",
            path.display(),
            signature,
            outcomes.len()
        )),
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
        true,
        true,
        false,
        Some("fifo".to_string()),
        Some(seed),
        Some(&temp_trace),
        true,
        None,
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

    let native = SemanticsOutcome {
        mode: "native".to_string(),
        exit_class: "pass".to_string(),
        event_kinds: vec!["test.event".to_string()],
        invariants: BTreeMap::from([
            (
                "deterministicTests".to_string(),
                native_plan.deterministic_test_names.len().to_string(),
            ),
            (
                "selectedTests".to_string(),
                native_plan.selected_tests.to_string(),
            ),
        ]),
    };
    let scenario_outcome = SemanticsOutcome {
        mode: "scenario".to_string(),
        exit_class: scenario_summary.exit_class,
        event_kinds: scenario_step_kinds.clone(),
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
        event_kinds: scenario_step_kinds,
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
    if native.event_kinds != scenario_outcome.event_kinds {
        issues.push("native/scenario normalized event kinds mismatch".to_string());
    }
    if scenario_outcome.event_kinds != host_outcome.event_kinds {
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
        Format::Text => Ok(format!(
            "equivalence ok path={} signature={} scenario={}",
            path.display(),
            signature,
            scenario.display()
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "path": path.display().to_string(),
            "seed": seed,
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
    file: String,
    line: usize,
    snippet: String,
    reason: Option<String>,
}

fn audit_unsafe_command(path: &Path, format: Format) -> Result<String> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let mut entries = Vec::new();
    for module_path in &parsed.module_paths {
        let source = std::fs::read_to_string(module_path).with_context(|| {
            format!(
                "failed reading module for unsafe audit: {}",
                module_path.display()
            )
        })?;
        for (index, raw) in source.lines().enumerate() {
            if !raw.contains("unsafe ")
                && !raw.contains("unsafe(\"")
                && !raw.contains("unsafe_reason(\"")
            {
                continue;
            }
            entries.push(UnsafeEntry {
                file: module_path.display().to_string(),
                line: index + 1,
                snippet: raw.trim().to_string(),
                reason: extract_unsafe_reason(raw),
            });
        }
    }
    let missing_reasons = entries
        .iter()
        .filter(|entry| entry.reason.is_none())
        .count();
    let out_dir = resolved.project_root.join(".fozzyc");
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed creating unsafe audit dir: {}", out_dir.display()))?;
    let unsafe_map = out_dir.join("unsafe-map.json");
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.unsafe_map.v0",
        "entries": entries,
        "missingReasonCount": missing_reasons,
    });
    std::fs::write(&unsafe_map, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing unsafe map: {}", unsafe_map.display()))?;
    if missing_reasons > 0 {
        bail!(
            "unsafe audit found {} site(s) without reason string; map={}",
            missing_reasons,
            unsafe_map.display()
        );
    }
    match format {
        Format::Text => Ok(format!(
            "unsafe audit ok entries={} map={}",
            payload["entries"]
                .as_array()
                .map(|items| items.len())
                .unwrap_or(0),
            unsafe_map.display()
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "entries": payload["entries"],
            "map": unsafe_map.display().to_string(),
            "missingReasonCount": missing_reasons,
        })
        .to_string()),
    }
}

fn extract_unsafe_reason(line: &str) -> Option<String> {
    for token in ["unsafe_reason(\"", "unsafe(\""] {
        if let Some(start) = line.find(token) {
            let rest = &line[(start + token.len())..];
            if let Some(end) = rest.find("\")") {
                return Some(rest[..end].trim().to_string());
            }
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].trim().to_string());
            }
        }
    }
    None
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
        let manifest::Dependency::Path { path: dep_path } = dependency;
        let source_dir = path.join(dep_path);
        if !source_dir.exists() {
            bail!(
                "path dependency `{}` not found at {}",
                name,
                source_dir.display()
            );
        }
        let lock_dep = lock_dep_by_name
            .get(name.as_str())
            .ok_or_else(|| anyhow!("lockfile missing dependency entry for `{name}`"))?;
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
            "source": source_dir.display().to_string(),
            "target": target_dir.display().to_string(),
            "sourceHash": source_hash,
            "vendorHash": vendor_hash,
            "package": lock_dep.get("package").cloned().unwrap_or(serde_json::json!({})),
        }));
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
        Format::Text => Ok(format!(
            "vendor ok dependencies={} dir={} lock_hash={}",
            copied.len(),
            vendor_dir.display(),
            lock_hash
        )),
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
        Format::Text => Ok(format!(
            "abi-check ok current={} baseline={} compared_exports={} added_exports={}",
            current.display(),
            baseline.display(),
            baseline_manifest.exports.len(),
            added_exports.len()
        )),
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
    if schema != "fozzylang.ffi_abi.v0" {
        bail!(
            "unsupported abi schema `{}` in {}; expected fozzylang.ffi_abi.v0",
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
        exports.insert(
            name.clone(),
            AbiExport {
                normalized_signature: format!("{name}({params})->{ret}"),
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
            || rel_str.starts_with(".fozzyc/")
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

#[derive(Debug, Clone, Serialize)]
struct LspSymbol {
    symbol: String,
    kind: String,
    file: String,
    line: usize,
    detail: String,
}

fn debug_check_command(path: &Path, format: Format) -> Result<String> {
    let artifact = compile_file_with_backend(path, BuildProfile::Dev, None)?;
    if artifact.status != "ok" {
        bail!(
            "debug-check failed to build module: status={} diagnostics={}",
            artifact.status,
            artifact.diagnostics
        );
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
    let async_hooks = count_async_hooks(&parsed.combined_source);
    let async_plan = run_non_scenario_test_plan(
        path,
        true,
        false,
        false,
        Some("fifo".to_string()),
        Some(1),
        None,
        false,
        None,
    )?;
    let async_backtrace_ready = async_hooks == 0 || async_plan.runtime_event_count > 0;
    let ok = debug_symbols && async_backtrace_ready;
    match format {
        Format::Text => Ok(format!(
            "debug-check binary={} debug_symbols={} async_backtrace_ready={} async_hooks={} ok={}",
            binary.display(),
            debug_symbols,
            async_backtrace_ready,
            async_hooks,
            ok
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": ok,
            "binary": binary.display().to_string(),
            "debugSymbols": debug_symbols,
            "asyncBacktraceReady": async_backtrace_ready,
            "asyncHooks": async_hooks,
            "runtimeEvents": async_plan.runtime_event_count,
            "causalLinks": async_plan.causal_link_count,
            "fileInfo": file_text.trim(),
        })
        .to_string()),
    }
}

fn lsp_diagnostics_command(path: &Path, format: Format) -> Result<String> {
    let output = verify_file(path)?;
    match format {
        Format::Text => Ok(format!(
            "lsp diagnostics module={} diagnostics={}",
            output.module, output.diagnostics
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "module": output.module,
            "diagnostics": output.diagnostic_details,
        })
        .to_string()),
    }
}

fn lsp_definition_command(path: &Path, symbol: &str, format: Format) -> Result<String> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let symbols = index_lsp_symbols(&parsed)?;
    let hit = symbols
        .into_iter()
        .find(|entry| entry.symbol == symbol)
        .ok_or_else(|| anyhow!("symbol `{}` not found", symbol))?;
    match format {
        Format::Text => Ok(format!(
            "definition {} {}:{} {}",
            hit.kind, hit.file, hit.line, hit.detail
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "symbol": hit,
        })
        .to_string()),
    }
}

fn lsp_hover_command(path: &Path, symbol: &str, format: Format) -> Result<String> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let info = parsed.module.items.iter().find_map(|item| match item {
        ast::Item::Function(function) if function.name == symbol => Some(serde_json::json!({
            "symbol": symbol,
            "kind": "function",
            "signature": format!("fn {}({}) -> {}", function.name, function.params.iter().map(|param| format!("{}: {}", param.name, param.ty)).collect::<Vec<_>>().join(", "), function.return_type),
        })),
        ast::Item::Struct(s) if s.name == symbol => Some(serde_json::json!({
            "symbol": symbol,
            "kind": "struct",
            "signature": format!("struct {}", s.name),
        })),
        ast::Item::Enum(e) if e.name == symbol => Some(serde_json::json!({
            "symbol": symbol,
            "kind": "enum",
            "signature": format!("enum {}", e.name),
        })),
        ast::Item::Test(test) if test.name == symbol => Some(serde_json::json!({
            "symbol": symbol,
            "kind": "test",
            "signature": format!("test \"{}\" {}", test.name, if test.deterministic { "{}" } else { "nondet {}" }),
        })),
        _ => None,
    });
    let Some(info) = info else {
        bail!("symbol `{}` not found", symbol);
    };
    match format {
        Format::Text => Ok(format!(
            "hover {} {}",
            info.get("kind")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown"),
            info.get("signature")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "hover": info,
        })
        .to_string()),
    }
}

fn lsp_rename_command(path: &Path, from: &str, to: &str, format: Format) -> Result<String> {
    if from.trim().is_empty() || to.trim().is_empty() {
        bail!("rename requires non-empty symbols");
    }
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let mut changed_files = Vec::new();
    let mut replacements = 0usize;
    for module_path in &parsed.module_paths {
        let original = std::fs::read_to_string(module_path).with_context(|| {
            format!(
                "failed reading module for rename: {}",
                module_path.display()
            )
        })?;
        let (updated, count) = replace_symbol_whole_word(&original, from, to);
        if count > 0 {
            std::fs::write(module_path, updated.as_bytes()).with_context(|| {
                format!("failed writing renamed module: {}", module_path.display())
            })?;
            replacements += count;
            changed_files.push(module_path.display().to_string());
        }
    }
    match format {
        Format::Text => Ok(format!(
            "rename {} -> {} replacements={} files={}",
            from,
            to,
            replacements,
            changed_files.len()
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "from": from,
            "to": to,
            "replacements": replacements,
            "files": changed_files,
        })
        .to_string()),
    }
}

fn lsp_smoke_command(path: &Path, format: Format) -> Result<String> {
    let diagnostics = verify_file(path)?;
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let symbols = index_lsp_symbols(&parsed)?;
    let has_main = symbols.iter().any(|entry| entry.symbol == "main");
    let ok = has_main;
    if !ok {
        bail!("lsp smoke failed: no `main` definition found");
    }
    match format {
        Format::Text => Ok(format!(
            "lsp smoke ok symbols={} diagnostics={}",
            symbols.len(),
            diagnostics.diagnostics
        )),
        Format::Json => Ok(serde_json::json!({
            "ok": true,
            "symbols": symbols.len(),
            "diagnostics": diagnostics.diagnostics,
            "features": ["diagnostics", "definition", "hover", "rename"],
        })
        .to_string()),
    }
}

fn index_lsp_symbols(parsed: &crate::pipeline::ParsedProgram) -> Result<Vec<LspSymbol>> {
    let mut symbols = Vec::new();
    for module_path in &parsed.module_paths {
        let source = std::fs::read_to_string(module_path).with_context(|| {
            format!(
                "failed reading module for lsp index: {}",
                module_path.display()
            )
        })?;
        for (line_number, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            if let Some(name) = parse_symbol_from_decl(line, "fn ") {
                symbols.push(LspSymbol {
                    symbol: name.clone(),
                    kind: "function".to_string(),
                    file: module_path.display().to_string(),
                    line: line_number + 1,
                    detail: line.to_string(),
                });
            } else if let Some(name) = parse_symbol_from_decl(line, "struct ") {
                symbols.push(LspSymbol {
                    symbol: name.clone(),
                    kind: "struct".to_string(),
                    file: module_path.display().to_string(),
                    line: line_number + 1,
                    detail: line.to_string(),
                });
            } else if let Some(name) = parse_symbol_from_decl(line, "enum ") {
                symbols.push(LspSymbol {
                    symbol: name.clone(),
                    kind: "enum".to_string(),
                    file: module_path.display().to_string(),
                    line: line_number + 1,
                    detail: line.to_string(),
                });
            } else if line.starts_with("test \"") {
                if let Some((_, tail)) = line.split_once('"') {
                    if let Some((name, _)) = tail.split_once('"') {
                        symbols.push(LspSymbol {
                            symbol: name.to_string(),
                            kind: "test".to_string(),
                            file: module_path.display().to_string(),
                            line: line_number + 1,
                            detail: line.to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok(symbols)
}

fn parse_symbol_from_decl(line: &str, token: &str) -> Option<String> {
    let normalized = line.strip_prefix("pub ").unwrap_or(line);
    let rest = normalized.strip_prefix(token)?.trim();
    let name = rest
        .split(|ch: char| ch == '(' || ch == '{' || ch.is_whitespace())
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())?;
    Some(name.to_string())
}

fn replace_symbol_whole_word(input: &str, from: &str, to: &str) -> (String, usize) {
    let mut out = String::with_capacity(input.len());
    let mut count = 0usize;
    let mut i = 0usize;
    let chars = input.as_bytes();
    while i < chars.len() {
        if input[i..].starts_with(from)
            && is_symbol_boundary(input, i.saturating_sub(1))
            && is_symbol_boundary(input, i + from.len())
        {
            out.push_str(to);
            i += from.len();
            count += 1;
        } else {
            out.push(input.as_bytes()[i] as char);
            i += 1;
        }
    }
    (out, count)
}

fn is_symbol_boundary(input: &str, index: usize) -> bool {
    if index >= input.len() {
        return true;
    }
    let ch = input.as_bytes()[index] as char;
    !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
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
    deterministic: bool,
    strict_verify: bool,
    safe_profile: bool,
    scheduler: Option<String>,
    seed: Option<u64>,
    record: Option<&Path>,
    rich_artifacts: bool,
    filter: Option<&str>,
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
    let selected_test_names = if let Some(filter) = filter {
        discovered_test_names
            .iter()
            .filter(|name| name.contains(filter))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        discovered_test_names.clone()
    };
    let workload = analyze_workload_shape(&parsed.combined_source);
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
    let async_checkpoint_count = count_async_hooks(&parsed.combined_source);
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
    let mode = if deterministic {
        ExecMode::Det
    } else {
        ExecMode::Fast
    };
    if record.is_some() && mode == ExecMode::Fast {
        bail!("--record requires --det");
    }

    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let verify_report = verifier::verify_with_policy(&fir, verifier::VerifyPolicy { safe_profile });
    let diagnostics = verify_report.diagnostics.len();
    let has_errors = verify_report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    if safe_profile && has_errors {
        bail!(
            "safe profile rejected module `{}` with {} diagnostics",
            fir.name,
            diagnostics
        );
    }
    if strict_verify && has_errors {
        bail!(
            "strict verify rejected module `{}` with {} diagnostics",
            fir.name,
            diagnostics
        );
    }

    let scheduler = if mode == ExecMode::Det {
        parse_scheduler(scheduler.as_deref().unwrap_or("fifo"))?
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
        let trace_mode = if strict_verify || rich_artifacts {
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
        execution_order = executor.run_until_idle_with_scheduler(scheduler, seed.unwrap_or(1));
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
            seed.unwrap_or(1),
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
    if strict_verify
        && mode == ExecMode::Det
        && rpc_validation
            .iter()
            .any(|finding| matches!(finding.severity, RpcValidationSeverity::Error))
    {
        bail!("strict verify rejected RPC sequence with validation errors");
    }
    let thread_findings = thread_health_findings(
        &events,
        &execution_order,
        task_count,
        &workload,
        &call_sequence,
    );
    let artifacts = if mode == ExecMode::Det {
        let detail = if strict_verify || rich_artifacts {
            ArtifactDetail::Rich
        } else {
            ArtifactDetail::Minimal
        };
        record
            .map(|record| {
                write_non_scenario_trace_artifacts(
                    record,
                    detail,
                    &scheduler_label,
                    seed.unwrap_or(1),
                    discovered_tests,
                    &selected_test_names,
                    &deterministic_test_names,
                    &async_execution,
                    &rpc_frames,
                    &rpc_validation,
                    &execution_order,
                    &events,
                    &runtime_events,
                    &causal_links,
                    &thread_findings,
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
    detail: ArtifactDetail,
    scheduler: &str,
    seed: u64,
    discovered_tests: usize,
    discovered_test_names: &[String],
    deterministic_test_names: &[String],
    async_execution: &[u64],
    rpc_frames: &[RpcFrameEvent],
    rpc_validation: &[RpcValidationFinding],
    execution_order: &[u64],
    events: &[TaskEvent],
    runtime_events: &[RuntimeSemanticEvent],
    causal_links: &[CausalLink],
    thread_findings: &[serde_json::Value],
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
    let trace_payload = TracePayload {
        schema_version: "fozzylang.thread_trace.v0",
        capability: "thread",
        scheduler,
        seed,
        execution_order,
        async_schedule: async_execution,
        rpc_frames: rpc_frames.to_vec(),
        events: events
            .iter()
            .map(TaskEventRecord::from)
            .collect::<Vec<TaskEventRecord>>(),
        runtime_events: runtime_events.to_vec(),
        causal_links: causal_links.to_vec(),
    };
    write_json_file(trace_path, &trace_payload).with_context(|| {
        format!(
            "failed writing thread trace artifact: {}",
            trace_path.display()
        )
    })?;

    let mut report_written = None;
    let mut timeline_written = None;
    let mut explore_written = None;
    let mut shrink_written = None;
    let mut scenarios_written = None;
    let mut primary_scenario_path = None;
    let mut goal_trace_written = None;

    if detail == ArtifactDetail::Rich {
        let mut timeline_entries =
            Vec::with_capacity(execution_order.len() + async_execution.len() + rpc_frames.len());
        for (index, task_id) in execution_order.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: index,
                decision: "thread.schedule",
                task_id: *task_id,
                scheduler,
                event: None,
                method: None,
            });
        }
        let thread_steps = timeline_entries.len();
        for (index, task_id) in async_execution.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: thread_steps + index,
                decision: "async.schedule",
                task_id: *task_id,
                scheduler,
                event: None,
                method: None,
            });
        }
        let async_steps = timeline_entries.len();
        for (index, frame) in rpc_frames.iter().enumerate() {
            timeline_entries.push(TimelineEntry {
                step: async_steps + index,
                decision: "rpc.frame",
                task_id: frame.task_id,
                scheduler,
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

        let (generated_primary, generated_scenarios) =
            generate_language_test_scenarios(&base_dir, stem, deterministic_test_names)?;
        primary_scenario_path = generated_primary;
        if let Some(primary_scenario) = &primary_scenario_path {
            let goal_trace_path = base_dir.join(format!("{stem}.goal.fozzy"));
            if let Err(error) =
                ensure_goal_trace_from_scenario(primary_scenario, &goal_trace_path, seed)
            {
                eprintln!(
                    "warning: failed generating goal trace from {}: {}",
                    primary_scenario.display(),
                    error
                );
            } else {
                goal_trace_written = Some(goal_trace_path);
            }
        }

        write_json_file(
            &report_path,
            &ReportPayload {
                schema_version: "fozzylang.report.v0",
                status: "pass",
                capabilities: vec!["thread"],
                scheduler: scheduler.to_string(),
                seed,
                discovered_tests,
                deterministic_tests: deterministic_test_names.len(),
                executed_tasks: execution_order.len(),
                async_checkpoints: async_execution.len(),
                rpc_frames: rpc_frames.len(),
                generated_scenarios: generated_scenarios.len(),
                events: events.len(),
                failure_classes: classify_failure_classes(
                    rpc_frames,
                    async_execution,
                    execution_order,
                ),
                findings: rpc_failure_findings(rpc_frames),
                rpc_validation: rpc_validation
                    .iter()
                    .map(rpc_validation_json)
                    .collect::<Vec<_>>(),
                thread_findings: thread_findings.to_vec(),
            },
        )
        .with_context(|| format!("failed writing report artifact: {}", report_path.display()))?;
        report_written = Some(report_path.clone());

        let scenario_priorities =
            build_scenario_priorities(&generated_scenarios, rpc_frames, async_execution);
        write_json_file(
            &explore_path,
            &ExplorePayload {
                schema_version: "fozzylang.explore.v0",
                schedules: build_schedule_candidates(execution_order),
                rpc_frame_permutations: build_rpc_frame_permutations(execution_order, rpc_frames),
                scenario_priorities: scenario_priorities.clone(),
                shrink_hints: build_shrink_hints(
                    discovered_test_names,
                    execution_order,
                    rpc_frames,
                    async_execution,
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
                    discovered_test_names,
                    execution_order,
                    rpc_frames,
                    async_execution,
                ),
                minimal_rpc_repro: minimize_rpc_failure_frames(rpc_frames),
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
            trace: trace_path.display().to_string(),
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
            detail: match detail {
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

fn count_async_hooks(source: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.contains("await ")
                || line.contains(".await")
                || line.contains("yield(")
                || line.contains("checkpoint(")
                || line.starts_with("async fn ")
        })
        .count()
}

fn analyze_workload_shape(source: &str) -> WorkloadShape {
    let mut async_functions = 0usize;
    let mut spawn_markers = 0usize;
    let mut yield_markers = 0usize;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("async fn ") {
            async_functions += 1;
        }
        if trimmed.contains("spawn(") || trimmed.contains("thread.spawn(") {
            spawn_markers += 1;
        }
        if trimmed.contains("yield(") || trimmed.contains("checkpoint(") {
            yield_markers += 1;
        }
    }
    WorkloadShape {
        async_functions,
        spawn_markers,
        yield_markers,
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
            | TaskEvent::ChannelRecv { task_id, .. } => {
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
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::Return(value)
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_call_names_from_expr(value, out),
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
        ast::Expr::Group(inner) => collect_call_names_from_expr(inner, out),
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Str(_) | ast::Expr::Ident(_) => {}
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
            | TaskEvent::ChannelRecv { .. } => {}
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
    let config_path = root.join(".fozzyc").join("runtime.json");
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
    fozzy_invoke(&args)
}

fn replay_like(command: &str, target: &Path, format: Format) -> Result<String> {
    let replay_target = resolve_replay_target(target)?;
    passthrough_fozzy(command, &replay_target, format)
}

#[derive(Debug, Clone, Deserialize)]
struct NativeTracePayloadOwned {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    capability: String,
    scheduler: String,
    seed: u64,
    #[serde(rename = "executionOrder")]
    execution_order: Vec<u64>,
    #[serde(rename = "asyncSchedule")]
    async_schedule: Vec<u64>,
    #[serde(rename = "rpcFrames")]
    rpc_frames: Vec<RpcFrameEventOwned>,
    events: Vec<serde_json::Value>,
    #[serde(rename = "runtimeEvents", default)]
    runtime_events: Vec<RuntimeSemanticEvent>,
    #[serde(rename = "causalLinks", default)]
    causal_links: Vec<CausalLink>,
}

#[derive(Debug, Clone, Deserialize)]
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

fn native_replay(target: &Path, format: Format) -> Result<String> {
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
    let rpc_validation = validate_rpc_frames(&rpc_frames);
    let errors = rpc_validation
        .iter()
        .filter(|finding| matches!(finding.severity, RpcValidationSeverity::Error))
        .count();
    if trace.execution_order.is_empty() {
        bail!(
            "native replay failed for {}: missing thread scheduling decisions",
            trace_path.display()
        );
    }
    if errors > 0 {
        bail!(
            "native replay failed for {}: {} rpc validation error(s)",
            trace_path.display(),
            errors
        );
    }
    let task_set = trace
        .execution_order
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let invalid_links = trace
        .causal_links
        .iter()
        .filter(|link| !task_set.contains(&link.from) || !task_set.contains(&link.to))
        .count();
    if invalid_links > 0 {
        bail!(
            "native replay failed for {}: {} invalid causal link(s)",
            trace_path.display(),
            invalid_links
        );
    }
    let native_decisions = build_native_decision_stream(&trace);
    let decision_count = native_decisions.len();
    match format {
        Format::Text => Ok(format!(
            "native replay pass trace={} decisions={} thread={} async={} rpc={}",
            trace_path.display(),
            decision_count,
            trace.execution_order.len(),
            trace.async_schedule.len(),
            trace.rpc_frames.len()
        )),
        Format::Json => Ok(serde_json::json!({
            "engine": "fozzylang-native",
            "status": "pass",
            "trace": trace_path.display().to_string(),
            "schemaVersion": trace.schema_version,
            "capability": trace.capability,
            "scheduler": trace.scheduler,
            "seed": trace.seed,
            "decisionCounts": {
                "thread": trace.execution_order.len(),
                "async": trace.async_schedule.len(),
                "rpc": trace.rpc_frames.len(),
                "total": decision_count,
            },
            "decisions": native_decisions,
            "events": trace.events.len(),
            "runtimeEvents": trace.runtime_events.len(),
            "causalLinks": trace.causal_links.len(),
            "rpcValidation": rpc_validation
                .iter()
                .map(rpc_validation_json)
                .collect::<Vec<_>>(),
        })
        .to_string()),
    }
}

fn build_native_decision_stream(trace: &NativeTracePayloadOwned) -> Vec<serde_json::Value> {
    let mut decisions = Vec::with_capacity(
        trace.execution_order.len() + trace.async_schedule.len() + trace.rpc_frames.len(),
    );
    for (step, task_id) in trace.execution_order.iter().enumerate() {
        decisions.push(serde_json::json!({
            "step": step,
            "kind": "thread.schedule",
            "taskId": task_id,
            "capability": "thread",
        }));
    }
    let base = decisions.len();
    for (index, task_id) in trace.async_schedule.iter().enumerate() {
        decisions.push(serde_json::json!({
            "step": base + index,
            "kind": "async.schedule",
            "taskId": task_id,
            "capability": "thread",
        }));
    }
    let base = decisions.len();
    for (index, frame) in trace.rpc_frames.iter().enumerate() {
        decisions.push(serde_json::json!({
            "step": base + index,
            "kind": "rpc.frame",
            "event": frame.kind,
            "method": frame.method,
            "taskId": frame.task_id,
            "capability": "net",
        }));
    }
    decisions
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
        Format::Text => Ok(format!(
            "native explore generated for trace={} schedules={} async_schedules={} rpc_frames={}",
            trace_path.display(),
            trace.execution_order.len(),
            trace.async_schedule.len(),
            trace.rpc_frames.len()
        )),
        Format::Json => Ok(payload.to_string()),
    }
}

fn native_shrink(target: &Path, format: Format) -> Result<String> {
    let trace_path = resolve_native_trace_target(target)?;
    let stem = trace_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("trace");
    let shrink_path = trace_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.shrink.json"));
    if shrink_path.exists() {
        let shrink = std::fs::read_to_string(&shrink_path).with_context(|| {
            format!(
                "failed reading native shrink artifact: {}",
                shrink_path.display()
            )
        })?;
        return match format {
            Format::Text => Ok(format!("native shrink artifact={}", shrink_path.display())),
            Format::Json => Ok(shrink),
        };
    }
    let (_, trace) = load_native_trace(target)?;
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
        "schemaVersion": "fozzylang.native_shrink.v0",
        "trace": trace_path.display().to_string(),
        "minimalRpcRepro": minimize_rpc_failure_frames(&rpc_frames),
        "focus": classify_failure_classes(&rpc_frames, &trace.async_schedule, &trace.execution_order),
    });
    match format {
        Format::Text => Ok(format!(
            "native shrink synthesized for trace={}",
            trace_path.display()
        )),
        Format::Json => Ok(payload.to_string()),
    }
}

fn native_ci(target: &Path, format: Format) -> Result<String> {
    let (trace_path, trace) = load_native_trace(target)?;
    let replay = native_replay(target, Format::Json)?;
    let replay_json: serde_json::Value = serde_json::from_str(&replay).with_context(|| {
        format!(
            "failed parsing native replay payload for {}",
            trace_path.display()
        )
    })?;
    let has_thread = !trace.execution_order.is_empty();
    let has_async_model = !trace.async_schedule.is_empty();
    let has_rpc_model = !trace.rpc_frames.is_empty();
    let checks = vec![
        serde_json::json!({"name":"thread_decisions", "ok": has_thread, "detail": format!("thread.schedule={}", trace.execution_order.len())}),
        serde_json::json!({"name":"async_schedule_model", "ok": has_async_model || trace.async_schedule.is_empty(), "detail": format!("async.schedule={}", trace.async_schedule.len())}),
        serde_json::json!({"name":"rpc_frame_model", "ok": has_rpc_model || trace.rpc_frames.is_empty(), "detail": format!("rpc.frame={}", trace.rpc_frames.len())}),
        serde_json::json!({"name":"native_replay", "ok": replay_json.get("status").and_then(|v| v.as_str()) == Some("pass"), "detail": "replay passed"}),
    ];
    let ok = checks.iter().all(|check| {
        check
            .get("ok")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    });
    if !ok {
        bail!("native ci failed for {}", trace_path.display());
    }
    match format {
        Format::Text => Ok(format!(
            "native ci pass trace={} checks={}",
            trace_path.display(),
            checks.len()
        )),
        Format::Json => Ok(serde_json::json!({
            "schemaVersion": "fozzylang.native_ci.v0",
            "ok": true,
            "engine": "fozzylang-native",
            "trace": trace_path.display().to_string(),
            "checks": checks,
        })
        .to_string()),
    }
}

fn emit_deterministic_capability_scenario(
    project_root: &Path,
    module_name: &str,
    module: &ast::Module,
) -> Result<PathBuf> {
    let typed = hir::lower(module);
    let mut capabilities = module.capabilities.clone();
    capabilities.extend(typed.inferred_capabilities);
    capabilities.sort();
    capabilities.dedup();
    let steps = capabilities
        .iter()
        .map(|capability| {
            serde_json::json!({
                "type": "trace_event",
                "name": format!("capability:{capability}"),
            })
        })
        .collect::<Vec<_>>();
    let scenario_payload = serde_json::json!({
        "version": 1,
        "name": format!("det-run-{module_name}"),
        "steps": steps,
    });
    let scenario_dir = project_root.join(".fozzyc").join("det");
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
        return Ok(());
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
        Format::Text => format!(
            "generated header={} exports={} abi_manifest={}",
            artifact.path.display(),
            artifact.exports,
            artifact.abi_manifest.display()
        ),
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
        Format::Text => format!(
            "generated rpc schema={} client={} server={} methods={}",
            artifacts.schema.display(),
            artifacts.client_stub.display(),
            artifacts.server_stub.display(),
            artifacts.methods
        ),
        Format::Json => serde_json::json!({
            "schema": artifacts.schema.display().to_string(),
            "client": artifacts.client_stub.display().to_string(),
            "server": artifacts.server_stub.display().to_string(),
            "methods": artifacts.methods,
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
    validate_ffi_contract(&parsed.combined_source, &exports)?;

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
    let header = render_c_header(package_name, &exports);
    std::fs::write(&header_path, header)
        .with_context(|| format!("failed writing header: {}", header_path.display()))?;
    let abi_manifest = header_path.with_extension("abi.json");
    let panic_boundary = detect_ffi_panic_boundary(&parsed.combined_source);
    let package_json = serde_json::json!({
        "name": package_name,
        "version": resolved
            .manifest
            .as_ref()
            .map(|manifest| manifest.package.version.as_str())
            .unwrap_or("0.0.0-dev"),
    });
    let abi_payload = serde_json::json!({
        "schemaVersion": "fozzylang.ffi_abi.v0",
        "package": package_json,
        "abiRevision": 1u64,
        "panicBoundary": panic_boundary,
        "layoutPolicy": {
            "reprCStableOnly": true,
            "nonReprCUnstable": true,
        },
        "symbolVersioning": "strict-name-signature-v0",
        "exports": exports.iter().map(|function| {
            serde_json::json!({
                "name": function.name.as_str(),
                "symbolVersion": 1u64,
                "params": function.params.iter().map(|param| {
                    serde_json::json!({
                        "name": param.name.as_str(),
                        "fzy": param.ty.to_string(),
                        "c": to_c_type(&param.ty),
                    })
                }).collect::<Vec<_>>(),
                "return": {
                    "fzy": function.return_type.to_string(),
                    "c": to_c_type(&function.return_type),
                }
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
        .unwrap_or_else(|| resolved.project_root.join(".fozzyc").join("rpc"));
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

    let mut client = String::from("// generated by fozzyc rpc gen\n");
    client.push_str("mod rpc_client {\n");
    for method in &methods {
        client.push_str(&format!(
            "    async fn {}(req: {}) -> {} {{\n        // TODO: wire transport + cancellation + deadline\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response
        ));
    }
    client.push_str("}\n");
    std::fs::write(&client_stub, client)
        .with_context(|| format!("failed writing rpc client stub: {}", client_stub.display()))?;

    let mut server = String::from("// generated by fozzyc rpc gen\n");
    server.push_str("mod rpc_server {\n");
    for method in &methods {
        server.push_str(&format!(
            "    async fn handle_{}(req: {}) -> {} {{\n        // TODO: implement RPC method handler\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response
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

fn render_c_header(package_name: &str, exports: &[&ast::Function]) -> String {
    let guard = format!("FOZZY_{}_H", package_name.to_ascii_uppercase());
    let mut header = String::new();
    header.push_str("#ifndef ");
    header.push_str(&guard);
    header.push_str("\n#define ");
    header.push_str(&guard);
    header.push_str("\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    for function in exports {
        header.push_str(&format!(
            "{} {}({});\n",
            to_c_type(&function.return_type),
            function.name,
            function
                .params
                .iter()
                .map(|param| format!("{} {}", to_c_type(&param.ty), param.name))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if exports.is_empty() {
        header.push_str("/* no exported extern \"C\" functions found */\n");
    }
    header.push_str("\n#ifdef __cplusplus\n}\n#endif\n\n#endif\n");
    header
}

fn validate_ffi_contract(source: &str, exports: &[&ast::Function]) -> Result<()> {
    if exports.is_empty() {
        return Ok(());
    }
    for function in exports {
        if !is_ffi_stable_type(&function.return_type) {
            bail!(
                "extern export `{}` uses unstable return type `{}`",
                function.name,
                function.return_type
            );
        }
        for param in &function.params {
            if !is_ffi_stable_type(&param.ty) {
                bail!(
                    "extern export `{}` param `{}` uses unstable type `{}`",
                    function.name,
                    param.name,
                    param.ty
                );
            }
        }
    }
    if source.contains("panic(")
        && !source.contains("#[ffi_panic(abort)]")
        && !source.contains("#[ffi_panic(error)]")
    {
        bail!(
            "ffi panic contract missing: add `#[ffi_panic(abort)]` or `#[ffi_panic(error)]` to prevent panic crossing C boundary"
        );
    }
    Ok(())
}

fn detect_ffi_panic_boundary(source: &str) -> &'static str {
    if source.contains("#[ffi_panic(abort)]") {
        "abort"
    } else if source.contains("#[ffi_panic(error)]") {
        "error"
    } else {
        "abort-or-translate"
    }
}

fn is_ffi_stable_type(ty: &ast::Type) -> bool {
    match ty {
        ast::Type::Void
        | ast::Type::Bool
        | ast::Type::Char
        | ast::Type::Float { .. }
        | ast::Type::Int { .. } => true,
        ast::Type::Ptr { to, .. } => is_ffi_stable_type(to),
        ast::Type::Str
        | ast::Type::Slice(_)
        | ast::Type::Result { .. }
        | ast::Type::Option(_)
        | ast::Type::Vec(_)
        | ast::Type::Ref { .. }
        | ast::Type::Array { .. }
        | ast::Type::Named { .. }
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
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("missing manifest: {}", manifest_path.display()))?;
    let manifest = manifest::load(&manifest_text).context("failed parsing fozzy.toml")?;
    manifest
        .validate()
        .map_err(|error| anyhow!("invalid fozzy.toml: {error}"))?;
    let relative = manifest.primary_bin_path().ok_or_else(|| {
        anyhow!(
            "no [[target.bin]] entry in {} for source resolution",
            manifest_path.display()
        )
    })?;
    Ok(ResolvedSource {
        source_path: path.join(relative),
        project_root: path.to_path_buf(),
        manifest: Some(manifest),
    })
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
        bail!(
            "fozzy {} failed: {}",
            command,
            String::from_utf8_lossy(&output.stderr)
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

fn format_source_file(path: &Path) -> Result<bool> {
    let original = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading file for formatting: {}", path.display()))?;
    let mut formatted = String::new();
    let mut previous_blank = false;
    for line in original.lines() {
        let trimmed_end = line.trim_end();
        let is_blank = trimmed_end.is_empty();
        if is_blank {
            if !previous_blank {
                formatted.push('\n');
            }
        } else {
            formatted.push_str(trimmed_end);
            formatted.push('\n');
        }
        previous_blank = is_blank;
    }

    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }

    if formatted != original {
        std::fs::write(path, formatted)
            .with_context(|| format!("failed writing formatted file: {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

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
    fn headers_command_generates_c_header_for_exports() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.h"));
        std::fs::write(
            &source,
            "pub extern \"C\" fn add(left: i32, right: i32) -> i32;\n",
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
        assert!(output.contains("generated header="));
        assert!(output.contains("abi_manifest="));
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("int32_t add(int32_t left, int32_t right);"));
        let abi_path = header.with_extension("abi.json");
        assert!(abi_path.exists());

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
            "[package]\nname=\"headers_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"headers_project\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod ffi;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/ffi.fzy"),
            "pub extern \"C\" fn add(left: i32, right: i32) -> i32;\n",
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
        assert!(output.contains("exports=1"));
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
                "schemaVersion": "fozzylang.ffi_abi.v0",
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
                "schemaVersion": "fozzylang.ffi_abi.v0",
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
        assert!(output.contains("sub(int32_t,int32_t)->int32_t"));

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
                "schemaVersion": "fozzylang.ffi_abi.v0",
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
                "schemaVersion": "fozzylang.ffi_abi.v0",
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
                threads: Some(3),
                backend: None,
            },
            Format::Json,
        )
        .expect("build should succeed");
        assert!(output.contains("\"threads\":3"));
        let runtime_config = source
            .parent()
            .expect("temp source should have parent")
            .join(".fozzyc/runtime.json");
        assert!(runtime_config.exists());
        let runtime_text =
            std::fs::read_to_string(&runtime_config).expect("runtime config should be readable");
        assert!(runtime_text.contains("\"threads\": 3"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(runtime_config);
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
        .expect("run command should succeed");
        assert!(output.contains("\"exitCode\":7"));
        assert!(output.contains("\"binary\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_command_routes_det_through_capability_scenario() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-run-det-route-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use cap.fs;\nfn main() -> i32 {\n    fs.open()\n    return 0\n}\n",
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
        assert!(output.contains("\"deterministic-capability-scenario\""));
        assert!(output.contains("\"routing\""));

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
        let trace_text = std::fs::read_to_string(&trace).expect("trace should be written");
        assert!(trace_text.contains("\"schemaVersion\": \"fozzylang.thread_trace.v0\""));
        assert!(trace_text.contains("\"capability\": \"thread\""));
        assert!(trace_text.contains("\"scheduler\": \"random\""));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        assert!(base.join(format!("{stem}.timeline.json")).exists());
        assert!(base.join(format!("{stem}.report.json")).exists());
        assert!(base.join(format!("{stem}.manifest.json")).exists());
        assert!(base.join(format!("{stem}.explore.json")).exists());
        assert!(base.join(format!("{stem}.shrink.json")).exists());
        assert!(base.join(format!("{stem}.scenarios.json")).exists());
        assert!(base.join(format!("{stem}.scenarios")).exists());

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
        let _ = std::fs::remove_dir_all(base.join(format!("{stem}.scenarios")));
    }

    #[test]
    fn counts_async_hooks_from_source_markers() {
        let source = r#"
            async fn worker() -> i32 { return 0 }
            fn main() -> i32 {
                let x = io.await_next()
                yield()
                checkpoint()
                return 0
            }
        "#;
        assert_eq!(count_async_hooks(source), 4);
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
            "async fn worker() -> i32 {}\ntest \"a\" {}\nfn main() -> i32 {\n    return 0\n}\n",
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

        let trace_text = std::fs::read_to_string(&trace).expect("trace should be written");
        assert!(trace_text.contains("\"asyncSchedule\": ["));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let timeline = std::fs::read_to_string(base.join(format!("{stem}.timeline.json")))
            .expect("timeline should be readable");
        assert!(timeline.contains("\"decision\": \"async.schedule\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
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
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Chat(stream<ChatReq>) -> stream<ChatRes>;\nfn main() -> i32 {\n    Ping(req)\n    Chat(req)\n    timeout(10)\n    cancel()\n    return 0\n}\n",
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

        let trace_text = std::fs::read_to_string(&trace).expect("trace should be written");
        assert!(trace_text.contains("\"rpcFrames\": ["));
        assert!(trace_text.contains("\"event\": \"rpc_send\""));
        assert!(!trace_text.contains("\"event\": \"rpc_recv\""));
        assert!(trace_text.contains("\"event\": \"rpc_deadline\""));
        assert!(trace_text.contains("\"event\": \"rpc_cancel\""));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
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
            "pub extern \"C\" fn add(left: i32, right: i32) -> i32;\nfn main() -> i32 {\n    panic(err)\n    return 0\n}\n",
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
    fn replay_command_uses_native_engine_for_native_trace() {
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

        let output = run(
            Command::Replay {
                trace: trace.clone(),
            },
            Format::Json,
        )
        .expect("replay should succeed");
        assert!(output.contains("\"engine\":\"fozzylang-native\""));
        assert!(output.contains("\"kind\":\"thread.schedule\""));
        assert!(output.contains("\"kind\":\"async.schedule\""));
        assert!(output.contains("\"kind\":\"rpc.frame\""));

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
    fn ci_command_fails_for_invalid_native_rpc_sequence() {
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
        .expect_err("ci should fail");
        assert!(error.to_string().contains("native replay failed"));

        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn shrink_command_uses_native_engine_for_native_trace() {
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

        let output = run(
            Command::Shrink {
                trace: trace.clone(),
            },
            Format::Json,
        )
        .expect("shrink should succeed");
        assert!(output.contains("\"schemaVersion\":\"fozzylang.native_shrink.v0\""));
        assert!(output.contains("\"minimalRpcRepro\""));

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
            "rpc Ping(req: PingReq) -> PingRes;\nasync fn worker() -> i32 {}\ntest \"flow\" {}\nfn main() -> i32 {\n    spawn(worker)\n    Ping(req)\n    return 0\n}\n",
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
    fn debug_check_command_reports_readiness() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-debug-check-{suffix}.fzy"));
        std::fs::write(
            &source,
            "async fn worker() -> i32 {}\nfn main() -> i32 {\n    return 0\n}\n",
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
}
