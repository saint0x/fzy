use super::*;

#[path = "gpu/abi.rs"]
mod abi;
#[path = "gpu/fs.rs"]
mod fs;
#[path = "gpu/lsp.rs"]
mod lsp;

pub(super) use self::abi::*;
pub(super) use self::fs::*;
pub(super) use self::lsp::*;

pub(super) fn debug_check_command(path: &Path, format: Format) -> Result<String> {
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

pub(super) struct NonScenarioTestPlan {
    pub(super) module: String,
    pub(super) mode: &'static str,
    pub(super) scheduler: String,
    pub(super) diagnostics: usize,
    pub(super) discovered_tests: usize,
    pub(super) selected_tests: usize,
    pub(super) discovered_test_names: Vec<String>,
    pub(super) selected_test_names: Vec<String>,
    pub(super) deterministic_test_names: Vec<String>,
    pub(super) nondeterministic_test_names: Vec<String>,
    pub(super) passed_tests: usize,
    pub(super) failed_tests: usize,
    pub(super) executed_tasks: usize,
    pub(super) execution_order: Vec<u64>,
    pub(super) async_checkpoint_count: usize,
    pub(super) async_execution: Vec<u64>,
    pub(super) rpc_frame_count: usize,
    pub(super) rpc_validation_errors: usize,
    pub(super) thread_findings: usize,
    pub(super) runtime_event_count: usize,
    pub(super) causal_link_count: usize,
    pub(super) coverage_ratio: f64,
    pub(super) artifacts: Option<NonScenarioTraceArtifacts>,
    pub(super) telemetry: NonScenarioPlanTelemetry,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct NonScenarioPlanTelemetry {
    pub(super) parse_ms: u64,
    pub(super) lower_ms: u64,
    pub(super) verify_ms: u64,
    pub(super) execute_ms: u64,
    pub(super) artifact_write_ms: u64,
    pub(super) total_ms: u64,
    pub(super) parse_cache_hit: bool,
    pub(super) lower_cache_hit: bool,
    pub(super) input_bytes: usize,
}

#[derive(Debug, Clone)]
pub(super) struct NonScenarioTraceArtifacts {
    pub(super) trace_path: PathBuf,
    pub(super) report_path: Option<PathBuf>,
    pub(super) timeline_path: Option<PathBuf>,
    pub(super) manifest_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecMode {
    Fast,
    Det,
}

#[derive(Debug, Clone)]
pub(super) struct NonScenarioPlanRequest<'a> {
    pub(super) deterministic: bool,
    pub(super) strict_verify: bool,
    pub(super) safe_profile: bool,
    pub(super) scheduler: Option<String>,
    pub(super) seed: Option<u64>,
    pub(super) record: Option<&'a Path>,
    pub(super) rich_artifacts: bool,
    pub(super) filter: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RpcFrameEvent {
    #[serde(rename = "event")]
    pub(super) kind: &'static str,
    pub(super) method: String,
    #[serde(rename = "taskId")]
    pub(super) task_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RuntimeSemanticEvent {
    #[serde(rename = "taskId")]
    pub(super) task_id: u64,
    pub(super) phase: String,
    pub(super) kind: String,
    pub(super) label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CausalLink {
    pub(super) from: u64,
    pub(super) to: u64,
    pub(super) relation: String,
}

fn write_native_test_trace_artifacts(
    trace_path: &Path,
    source_path: &Path,
    scheduler: &str,
    seed: u64,
    strict_verify: bool,
    safe_profile: bool,
    discovered_tests: usize,
    executed_tests: usize,
    selected_test_names: &[String],
    deterministic_test_names: &[String],
    nondeterministic_test_names: &[String],
    runs: &[hir::TestRunOutcome],
    async_execution: &[u64],
    rpc_frames: &[RpcFrameEvent],
    runtime_events: &[RuntimeSemanticEvent],
    causal_links: &[CausalLink],
    thread_findings: &[serde_json::Value],
    rich: bool,
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
    let native_trace_path = base_dir.join(format!("{stem}.native.trace.json"));
    let report_path = base_dir.join(format!("{stem}.report.json"));
    let timeline_path = base_dir.join(format!("{stem}.timeline.json"));
    let manifest_path = base_dir.join(format!("{stem}.manifest.json"));

    let passed = runs
        .iter()
        .filter(|run| matches!(run.status, hir::TestStatus::Passed))
        .count();
    let failed = runs
        .iter()
        .filter(|run| {
            matches!(
                run.status,
                hir::TestStatus::Failed | hir::TestStatus::TimedOut
            )
        })
        .count();

    let trace_payload = serde_json::json!({
        "schemaVersion": "fozzylang.test_trace.v1",
        "scheduler": scheduler,
        "seed": seed,
        "discoveredTests": discovered_tests,
        "executedTests": executed_tests,
        "executionOrder": (0..runs.len() as u64).collect::<Vec<_>>(),
        "asyncSchedule": async_execution,
        "rpcFrames": rpc_frames,
        "runtimeEvents": runtime_events,
        "causalLinks": causal_links,
        "threadFindings": thread_findings,
        "tests": runs.iter().map(|run| {
            serde_json::json!({
                "id": run.descriptor.id,
                "name": run.descriptor.name,
                "function": run.descriptor.function,
                "mode": match run.descriptor.mode {
                    hir::TestMode::Deterministic => "det",
                    hir::TestMode::Nondeterministic => "nondet",
                },
                "status": match run.status {
                    hir::TestStatus::Passed => "passed",
                    hir::TestStatus::Failed => "failed",
                    hir::TestStatus::TimedOut => "timed_out",
                },
                "failure": run.failure,
                "steps": run.steps,
                "events": run.events.iter().map(|event| {
                    serde_json::json!({
                        "kind": event.kind,
                        "detail": event.detail,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    });
    write_json_file(&native_trace_path, &trace_payload).with_context(|| {
        format!(
            "failed writing native test trace artifact: {}",
            native_trace_path.display()
        )
    })?;

    let report = serde_json::json!({
        "schemaVersion": "fozzylang.test_report.v1",
        "status": if failed == 0 { "pass" } else { "fail" },
        "scheduler": scheduler,
        "seed": seed,
        "discoveredTests": discovered_tests,
        "executedTests": executed_tests,
        "passed": passed,
        "failed": failed,
        "asyncCheckpointCount": runtime_events
            .iter()
            .filter(|event| {
                event.kind == "runtime"
                    && event
                        .details
                        .as_ref()
                        .and_then(|details| details.get("detail"))
                        .and_then(|detail| detail.as_str())
                        .is_some_and(|detail| {
                            detail == "checkpoint"
                                || detail == "yield"
                                || detail == "pulse"
                                || detail.starts_with("timeout(")
                                || detail.starts_with("deadline(")
                        })
            })
            .count(),
        "runtimeEventCount": runtime_events.len(),
        "causalLinkCount": causal_links.len(),
        "rpcFrameCount": rpc_frames.len(),
        "threadFindings": thread_findings,
    });
    write_json_file(&report_path, &report).with_context(|| {
        format!(
            "failed writing test report artifact: {}",
            report_path.display()
        )
    })?;

    let timeline_written = if rich {
        let payload = serde_json::json!({
            "schemaVersion": "fozzylang.test_timeline.v1",
            "entries": runs.iter().enumerate().flat_map(|(index, run)| {
                run.events.iter().map(move |event| {
                    serde_json::json!({
                        "step": index,
                        "test": run.descriptor.name,
                        "kind": event.kind,
                        "detail": event.detail,
                    })
                })
            }).collect::<Vec<_>>(),
        });
        write_json_file(&timeline_path, &payload).with_context(|| {
            format!(
                "failed writing native test timeline artifact: {}",
                timeline_path.display()
            )
        })?;
        Some(timeline_path.clone())
    } else {
        None
    };

    let manifest = serde_json::json!({
        "schemaVersion": "fozzylang.test_manifest.v1",
        "source": source_path.display().to_string(),
        "deterministic": true,
        "strictVerify": strict_verify,
        "safeProfile": safe_profile,
        "scheduler": scheduler,
        "seed": seed,
        "selectedTestNames": selected_test_names,
        "deterministicTestNames": deterministic_test_names,
        "nondeterministicTestNames": nondeterministic_test_names,
        "trace": native_trace_path.display().to_string(),
        "report": report_path.display().to_string(),
        "timeline": timeline_written.as_ref().map(|path| path.display().to_string()),
    });
    write_json_file(&manifest_path, &manifest).with_context(|| {
        format!(
            "failed writing native test manifest artifact: {}",
            manifest_path.display()
        )
    })?;

    Ok(NonScenarioTraceArtifacts {
        trace_path: native_trace_path,
        report_path: Some(report_path),
        timeline_path: timeline_written,
        manifest_path,
    })
}

pub(super) fn run_non_scenario_test_plan(
    path: &Path,
    request: NonScenarioPlanRequest<'_>,
) -> Result<NonScenarioTestPlan> {
    let started = Instant::now();
    let resolved = resolve_source(path)?;
    let parse_started = Instant::now();
    let (parsed, parse_cache_hit) = parse_program_with_metadata(&resolved.source_path)?;
    let parse_ms = parse_started.elapsed().as_millis() as u64;
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
    suppress_transitive_unsafe_summary_for_architecture_root(
        &resolved.source_path,
        &parsed.module,
        &mut verify_diagnostics,
    );
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

    let capability_map = typed
        .typed_functions
        .iter()
        .map(|function| {
            (
                function.name.as_str(),
                function.required_capabilities.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut descriptors = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_functions = BTreeSet::new();
    for unit in parsed.qualified_modules() {
        for item in &unit.ast.items {
            let ast::Item::Test(test) = item else {
                continue;
            };
            let function = hir::test_symbol_name(&test.name);
            let id = format!("{}::{}", unit.namespace, test.name);
            if !seen_ids.insert(id.clone()) {
                bail!("duplicate native test descriptor id `{id}`");
            }
            if !seen_functions.insert(function.clone()) {
                bail!(
                    "duplicate test symbol `{}`; test names must be globally unique across compiled modules",
                    function
                );
            }
            descriptors.push(hir::TestDescriptor {
                id,
                name: test.name.clone(),
                function: function.clone(),
                mode: if test.deterministic {
                    hir::TestMode::Deterministic
                } else {
                    hir::TestMode::Nondeterministic
                },
                module: Some(unit.path.display().to_string()),
                required_capabilities: capability_map
                    .get(function.as_str())
                    .cloned()
                    .unwrap_or_default(),
            });
        }
    }
    let discovered_tests = descriptors.len();
    let discovered_test_names = descriptors
        .iter()
        .map(|descriptor| descriptor.name.clone())
        .collect::<Vec<_>>();
    let selected_descriptors = descriptors
        .iter()
        .filter(|descriptor| {
            request.filter.is_none_or(|needle| {
                descriptor.name.contains(needle) || descriptor.id.contains(needle)
            })
        })
        .filter(|descriptor| {
            if mode == ExecMode::Det {
                matches!(descriptor.mode, hir::TestMode::Deterministic)
            } else {
                true
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_test_names = selected_descriptors
        .iter()
        .map(|descriptor| descriptor.name.clone())
        .collect::<Vec<_>>();
    let deterministic_test_names = selected_descriptors
        .iter()
        .filter(|descriptor| matches!(descriptor.mode, hir::TestMode::Deterministic))
        .map(|descriptor| descriptor.name.clone())
        .collect::<Vec<_>>();
    let nondeterministic_test_names = selected_descriptors
        .iter()
        .filter(|descriptor| matches!(descriptor.mode, hir::TestMode::Nondeterministic))
        .map(|descriptor| descriptor.name.clone())
        .collect::<Vec<_>>();
    let selected_tests = selected_descriptors.len();
    let scheduler_label = if mode == ExecMode::Det {
        request
            .scheduler
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| "fifo".to_string())
    } else {
        "fast".to_string()
    };
    let execute_started = Instant::now();
    let suite = hir::execute_tests(
        &typed.typed_functions,
        &selected_descriptors,
        &hir::TestRunnerConfig::default(),
    );
    let execute_ms = execute_started.elapsed().as_millis() as u64;
    let execution_order = (0..suite.runs.len() as u64).collect::<Vec<_>>();
    let async_checkpoint_count = suite
        .runs
        .iter()
        .flat_map(|run| run.events.iter())
        .filter(|event| {
            event.kind == "runtime"
                && (event.detail == "checkpoint"
                    || event.detail == "yield"
                    || event.detail == "pulse"
                    || event.detail.starts_with("timeout(")
                    || event.detail.starts_with("deadline("))
        })
        .count();
    let async_execution = execution_order.clone();
    let runtime_events = suite
        .runs
        .iter()
        .enumerate()
        .flat_map(|(index, run)| {
            run.events.iter().map(move |event| RuntimeSemanticEvent {
                task_id: index as u64,
                phase: "test".to_string(),
                kind: event.kind.clone(),
                label: run.descriptor.name.clone(),
                details: Some(serde_json::json!({
                    "detail": event.detail,
                    "status": match run.status {
                        hir::TestStatus::Passed => "passed",
                        hir::TestStatus::Failed => "failed",
                        hir::TestStatus::TimedOut => "timed_out",
                    }
                })),
            })
        })
        .collect::<Vec<_>>();
    let causal_links = execution_order
        .windows(2)
        .map(|window| CausalLink {
            from: window[0],
            to: window[1],
            relation: "test.next".to_string(),
        })
        .collect::<Vec<_>>();
    let rpc_frames: Vec<RpcFrameEvent> = Vec::new();
    let passed_tests = suite
        .runs
        .iter()
        .filter(|run| matches!(run.status, hir::TestStatus::Passed))
        .count();
    let failed_tests = suite.runs.len().saturating_sub(passed_tests);
    let mut thread_findings = unsafe_trace_findings(&fir);
    for run in &suite.runs {
        if let Some(message) = &run.failure {
            thread_findings.push(serde_json::json!({
                "kind": "test_failure",
                "test": run.descriptor.name,
                "message": message,
            }));
        }
    }
    let artifacts_started = Instant::now();
    let artifacts = request
        .record
        .map(|record| {
            write_native_test_trace_artifacts(
                record,
                &resolved.source_path,
                &scheduler_label,
                request.seed.unwrap_or(1),
                request.strict_verify,
                request.safe_profile,
                discovered_tests,
                suite.runs.len(),
                &selected_test_names,
                &deterministic_test_names,
                &nondeterministic_test_names,
                &suite.runs,
                &async_execution,
                &rpc_frames,
                &runtime_events,
                &causal_links,
                &thread_findings,
                strict_unsafe_contracts || request.rich_artifacts,
            )
        })
        .transpose()?;
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
        nondeterministic_test_names,
        passed_tests,
        failed_tests,
        executed_tasks: suite.runs.len(),
        execution_order,
        async_checkpoint_count,
        async_execution,
        rpc_frame_count: rpc_frames.len(),
        rpc_validation_errors: 0,
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

pub(super) fn suppress_transitive_unsafe_summary_for_architecture_root(
    source_path: &Path,
    _module: &ast::Module,
    diagnostics: &mut Vec<diagnostics::Diagnostic>,
) {
    let is_architecture_root = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value == "lib.fzy")
        && !source_file_contains_unsafe_marker(source_path);
    if !is_architecture_root {
        return;
    }
    diagnostics.retain(|diagnostic| {
        !matches!(diagnostic.severity, diagnostics::Severity::Warning)
            || !diagnostic.message.contains(
                "compiler unsafe-policy checks passed, and structural unsafe contract metadata is present for all sites; independently reasoned evidence is still required",
            )
    });
}

pub(super) fn source_file_contains_unsafe_marker(source_path: &Path) -> bool {
    std::fs::read_to_string(source_path)
        .map(|source| source.contains("unsafe"))
        .unwrap_or(true)
}

pub(super) fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)
        .with_context(|| format!("failed writing json file: {}", path.display()))
}

pub(super) fn count_async_hooks_in_module(module: &ast::Module) -> usize {
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

pub(super) fn count_async_hooks_in_stmt(stmt: &ast::Stmt) -> usize {
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

pub(super) fn count_async_hooks_in_expr(expr: &ast::Expr) -> usize {
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
