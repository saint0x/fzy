use super::*;

#[derive(Debug, Clone)]
pub(super) struct TraceNativeArtifacts {
    pub(super) trace_path: PathBuf,
    pub(super) manifest_path: PathBuf,
    pub(super) decision_count: usize,
    pub(super) event_count: usize,
    pub(super) rpc_frame_count: usize,
    pub(super) seed: u64,
}

pub(super) const FOZZY_TRACE_FORMAT: &str = "fozzy-trace";
#[cfg(test)]
pub(super) const FOZZY_TRACE_VERSION: u64 = 4;

#[derive(Debug, Clone, Deserialize)]
struct NativeTestManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    source: String,
    deterministic: bool,
    #[serde(rename = "strictVerify")]
    strict_verify: bool,
    #[serde(rename = "safeProfile")]
    safe_profile: bool,
    scheduler: String,
    seed: u64,
    #[serde(rename = "selectedTestNames", default)]
    selected_test_names: Vec<String>,
    #[serde(rename = "deterministicTestNames", default)]
    deterministic_test_names: Vec<String>,
    #[serde(rename = "nondeterministicTestNames", default)]
    nondeterministic_test_names: Vec<String>,
    trace: String,
    report: String,
    timeline: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct NativeTestTracePayload {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    scheduler: String,
    seed: u64,
    #[serde(rename = "discoveredTests")]
    discovered_tests: usize,
    #[serde(rename = "executedTests")]
    executed_tests: usize,
    #[serde(rename = "executionOrder")]
    execution_order: Vec<u64>,
    #[serde(rename = "asyncSchedule")]
    async_schedule: Vec<u64>,
    tests: Vec<NativeTestTraceRun>,
}

#[derive(Debug, Clone, Deserialize)]
struct NativeTestTraceRun {
    name: String,
    mode: String,
    status: String,
    #[serde(default)]
    events: Vec<NativeTestTraceEvent>,
}

#[derive(Debug, Clone, Deserialize)]
struct NativeTestTraceEvent {
    kind: String,
    detail: String,
}

#[derive(Debug, Clone, Deserialize)]
struct NativeTestReportPayload {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    status: String,
    scheduler: String,
    seed: u64,
    #[serde(rename = "discoveredTests")]
    discovered_tests: usize,
    #[serde(rename = "executedTests")]
    executed_tests: usize,
    passed: usize,
    failed: usize,
    #[serde(rename = "runtimeEventCount")]
    runtime_event_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct NativeArtifactCheck {
    name: String,
    ok: bool,
    detail: String,
}

fn native_test_manifest_for_target(target: &Path) -> Result<Option<PathBuf>> {
    let Some(name) = target.file_name().and_then(|value| value.to_str()) else {
        return Ok(None);
    };
    if name.ends_with(".manifest.json") {
        let text = std::fs::read_to_string(target)
            .with_context(|| format!("failed reading native manifest: {}", target.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("failed parsing native manifest: {}", target.display()))?;
        if value
            .get("schemaVersion")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value == "fozzylang.test_manifest.v1")
        {
            return Ok(Some(target.to_path_buf()));
        }
        return Ok(None);
    }
    if let Some(prefix) = name.strip_suffix(".native.trace.json") {
        let manifest = target
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("{prefix}.manifest.json"));
        if manifest.exists() {
            let text = std::fs::read_to_string(&manifest).with_context(|| {
                format!("failed reading native test manifest: {}", manifest.display())
            })?;
            let value: serde_json::Value = serde_json::from_str(&text).with_context(|| {
                format!("failed parsing native test manifest: {}", manifest.display())
            })?;
            if value
                .get("schemaVersion")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value == "fozzylang.test_manifest.v1")
            {
                return Ok(Some(manifest));
            }
        }
    }
    Ok(None)
}

pub(super) fn is_native_test_artifact_target(target: &Path) -> Result<bool> {
    Ok(native_test_manifest_for_target(target)?.is_some())
}

fn load_native_test_manifest(target: &Path) -> Result<(PathBuf, NativeTestManifest)> {
    let manifest_path = native_test_manifest_for_target(target)?.ok_or_else(|| {
        anyhow!(
            "native test artifact target requires a `.manifest.json` file: {}",
            target.display()
        )
    })?;
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed reading native test manifest: {}", manifest_path.display()))?;
    let manifest: NativeTestManifest = serde_json::from_str(&text)
        .with_context(|| format!("failed parsing native test manifest: {}", manifest_path.display()))?;
    if manifest.schema_version != "fozzylang.test_manifest.v1" {
        bail!(
            "unsupported native test manifest schema `{}` in {}",
            manifest.schema_version,
            manifest_path.display()
        );
    }
    Ok((manifest_path, manifest))
}

fn load_native_test_artifacts(
    target: &Path,
) -> Result<(
    PathBuf,
    NativeTestManifest,
    PathBuf,
    NativeTestTracePayload,
    PathBuf,
    NativeTestReportPayload,
)> {
    let (manifest_path, manifest) = load_native_test_manifest(target)?;
    let trace_path = PathBuf::from(&manifest.trace);
    ensure_exists(&trace_path)?;
    let trace_text = std::fs::read_to_string(&trace_path)
        .with_context(|| format!("failed reading native test trace: {}", trace_path.display()))?;
    let trace: NativeTestTracePayload = serde_json::from_str(&trace_text)
        .with_context(|| format!("failed parsing native test trace: {}", trace_path.display()))?;
    let report_path = PathBuf::from(&manifest.report);
    ensure_exists(&report_path)?;
    let report_text = std::fs::read_to_string(&report_path)
        .with_context(|| format!("failed reading native test report: {}", report_path.display()))?;
    let report: NativeTestReportPayload = serde_json::from_str(&report_text)
        .with_context(|| format!("failed parsing native test report: {}", report_path.display()))?;
    Ok((manifest_path, manifest, trace_path, trace, report_path, report))
}

pub(super) fn verify_native_test_artifacts(target: &Path) -> Result<serde_json::Value> {
    let (manifest_path, manifest, trace_path, trace, report_path, report) =
        load_native_test_artifacts(target)?;
    let mut checks = Vec::<NativeArtifactCheck>::new();
    checks.push(NativeArtifactCheck {
        name: "manifest_schema".to_string(),
        ok: manifest.schema_version == "fozzylang.test_manifest.v1",
        detail: manifest.schema_version.clone(),
    });
    checks.push(NativeArtifactCheck {
        name: "trace_schema".to_string(),
        ok: trace.schema_version == "fozzylang.test_trace.v1",
        detail: trace.schema_version.clone(),
    });
    checks.push(NativeArtifactCheck {
        name: "report_schema".to_string(),
        ok: report.schema_version == "fozzylang.test_report.v1",
        detail: report.schema_version.clone(),
    });
    checks.push(NativeArtifactCheck {
        name: "scheduler_match".to_string(),
        ok: manifest.scheduler == trace.scheduler && trace.scheduler == report.scheduler,
        detail: format!(
            "manifest={} trace={} report={}",
            manifest.scheduler, trace.scheduler, report.scheduler
        ),
    });
    checks.push(NativeArtifactCheck {
        name: "seed_match".to_string(),
        ok: manifest.seed == trace.seed && trace.seed == report.seed,
        detail: format!(
            "manifest={} trace={} report={}",
            manifest.seed, trace.seed, report.seed
        ),
    });
    checks.push(NativeArtifactCheck {
        name: "executed_tests_match".to_string(),
        ok: trace.executed_tests == trace.tests.len() && trace.executed_tests == report.executed_tests,
        detail: format!(
            "trace.executed={} tests.len={} report.executed={}",
            trace.executed_tests,
            trace.tests.len(),
            report.executed_tests
        ),
    });
    checks.push(NativeArtifactCheck {
        name: "discovered_tests_match".to_string(),
        ok: trace.discovered_tests == report.discovered_tests && trace.discovered_tests >= trace.executed_tests,
        detail: format!(
            "trace.discovered={} report.discovered={} executed={}",
            trace.discovered_tests, report.discovered_tests, trace.executed_tests
        ),
    });
    checks.push(NativeArtifactCheck {
        name: "execution_order_match".to_string(),
        ok: trace.execution_order.len() == trace.executed_tests,
        detail: format!(
            "order.len={} executed={}",
            trace.execution_order.len(),
            trace.executed_tests
        ),
    });
    checks.push(NativeArtifactCheck {
        name: "async_schedule_range".to_string(),
        ok: trace
            .async_schedule
            .iter()
            .all(|task_id| (*task_id as usize) < trace.executed_tests),
        detail: format!(
            "asyncSchedule.len={} executed={}",
            trace.async_schedule.len(),
            trace.executed_tests
        ),
    });
    let passed = trace
        .tests
        .iter()
        .filter(|run| run.status == "passed")
        .count();
    let failed = trace.tests.len().saturating_sub(passed);
    checks.push(NativeArtifactCheck {
        name: "status_counts_match".to_string(),
        ok: passed == report.passed && failed == report.failed,
        detail: format!(
            "trace passed={} failed={} report passed={} failed={}",
            passed, failed, report.passed, report.failed
        ),
    });
    checks.push(NativeArtifactCheck {
        name: "selected_test_names_match".to_string(),
        ok: manifest.selected_test_names
            == trace.tests.iter().map(|run| run.name.clone()).collect::<Vec<_>>(),
        detail: format!("selected={}", manifest.selected_test_names.join(",")),
    });
    checks.push(NativeArtifactCheck {
        name: "deterministic_modes_match".to_string(),
        ok: trace.tests.iter().all(|run| run.mode == "det")
            && manifest.selected_test_names == manifest.deterministic_test_names
            && manifest.nondeterministic_test_names.is_empty(),
        detail: format!(
            "modes={} nondet={}",
            trace
                .tests
                .iter()
                .map(|run| run.mode.clone())
                .collect::<Vec<_>>()
                .join(","),
            manifest.nondeterministic_test_names.join(",")
        ),
    });
    if let Some(timeline) = &manifest.timeline {
        let timeline_path = PathBuf::from(timeline);
        checks.push(NativeArtifactCheck {
            name: "timeline_present".to_string(),
            ok: timeline_path.exists(),
            detail: timeline_path.display().to_string(),
        });
    }
    let ok = checks.iter().all(|check| check.ok);
    Ok(serde_json::json!({
        "schemaVersion": "fozzylang.native_test_trace_verify.v1",
        "ok": ok,
        "manifest": manifest_path.display().to_string(),
        "trace": trace_path.display().to_string(),
        "report": report_path.display().to_string(),
        "source": manifest.source,
        "strictVerify": manifest.strict_verify,
        "safeProfile": manifest.safe_profile,
        "runtimeEventCount": report.runtime_event_count,
        "reportStatus": report.status,
        "checks": checks,
    }))
}

fn compare_native_test_plan_against_recorded(
    manifest: &NativeTestManifest,
    trace: &NativeTestTracePayload,
    report: &NativeTestReportPayload,
    plan: &NonScenarioTestPlan,
) -> Vec<NativeArtifactCheck> {
    let replayed_names = plan.selected_test_names.clone();
    let recorded_names = manifest.selected_test_names.clone();
    let replayed_passed = plan.passed_tests;
    let replayed_failed = plan.failed_tests;
    let replayed_status = if replayed_failed == 0 { "pass" } else { "fail" };
    let replayed_async_events = plan.async_checkpoint_count;
    let recorded_async_events = trace
        .tests
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
    vec![
        NativeArtifactCheck {
            name: "selected_tests_match".to_string(),
            ok: recorded_names == replayed_names,
            detail: format!("recorded={} replayed={}", recorded_names.join(","), replayed_names.join(",")),
        },
        NativeArtifactCheck {
            name: "scheduler_match".to_string(),
            ok: manifest.scheduler == plan.scheduler,
            detail: format!("recorded={} replayed={}", manifest.scheduler, plan.scheduler),
        },
        NativeArtifactCheck {
            name: "passed_failed_match".to_string(),
            ok: report.passed == replayed_passed && report.failed == replayed_failed,
            detail: format!(
                "recorded passed={} failed={} replayed passed={} failed={}",
                report.passed, report.failed, replayed_passed, replayed_failed
            ),
        },
        NativeArtifactCheck {
            name: "report_status_match".to_string(),
            ok: report.status == replayed_status,
            detail: format!("recorded={} replayed={}", report.status, replayed_status),
        },
        NativeArtifactCheck {
            name: "async_checkpoint_match".to_string(),
            ok: recorded_async_events == replayed_async_events,
            detail: format!(
                "recorded={} replayed={}",
                recorded_async_events, replayed_async_events
            ),
        },
        NativeArtifactCheck {
            name: "deterministic_filter_contract".to_string(),
            ok: manifest.deterministic
                && manifest.nondeterministic_test_names.is_empty()
                && manifest.selected_test_names == manifest.deterministic_test_names,
            detail: format!(
                "deterministic={} nondet={} selected={} det={}",
                manifest.deterministic,
                manifest.nondeterministic_test_names.join(","),
                manifest.selected_test_names.join(","),
                manifest.deterministic_test_names.join(",")
            ),
        },
    ]
}

pub(super) fn replay_native_test_artifacts(
    target: &Path,
    strict: bool,
    format: Format,
) -> Result<String> {
    let (manifest_path, manifest, _, trace, _, report) = load_native_test_artifacts(target)?;
    let source_path = PathBuf::from(&manifest.source);
    ensure_exists(&source_path)?;
    let plan = run_non_scenario_test_plan_with_root_guidance(
        &source_path,
        NonScenarioPlanRequest {
            deterministic: manifest.deterministic,
            strict_verify: manifest.strict_verify,
            safe_profile: manifest.safe_profile,
            scheduler: Some(manifest.scheduler.clone()),
            seed: Some(manifest.seed),
            record: None,
            rich_artifacts: false,
            filter: None,
        },
    )?;
    let checks = compare_native_test_plan_against_recorded(&manifest, &trace, &report, &plan);
    let ok = checks.iter().all(|check| check.ok);
    let rendered = render_value_output(
        format,
        &serde_json::json!({
            "schemaVersion": "fozzylang.native_test_replay.v1",
            "ok": ok,
            "manifest": manifest_path.display().to_string(),
            "source": manifest.source,
            "recorded": {
                "selectedTestNames": manifest.selected_test_names,
                "passed": report.passed,
                "failed": report.failed,
                "asyncCheckpointCount": trace.tests.iter().flat_map(|run| run.events.iter()).filter(|event| event.kind == "runtime").count(),
            },
            "replayed": {
                "selectedTestNames": plan.selected_test_names,
                "passed": plan.passed_tests,
                "failed": plan.failed_tests,
                "asyncCheckpointCount": plan.async_checkpoint_count,
            },
            "checks": checks,
        }),
    )?;
    if !ok || strict {
        if !ok {
            return Err(CommandFailure {
                exit_code: 1,
                output: rendered,
            }
            .into());
        }
    }
    Ok(rendered)
}

pub(super) fn ci_native_test_artifacts(
    target: &Path,
    strict: bool,
    format: Format,
) -> Result<String> {
    let verify = verify_native_test_artifacts(target)?;
    let replay_output = replay_native_test_artifacts(target, false, Format::Json)?;
    let replay: serde_json::Value =
        serde_json::from_str(&replay_output).context("failed parsing native test replay report")?;
    let verify_ok = verify.get("ok").and_then(|value| value.as_bool()).unwrap_or(false);
    let replay_ok = replay.get("ok").and_then(|value| value.as_bool()).unwrap_or(false);
    let ok = verify_ok && replay_ok;
    let rendered = render_value_output(
        format,
        &serde_json::json!({
            "schemaVersion": "fozzylang.native_test_ci.v1",
            "ok": ok,
            "strict": strict,
            "verify": verify,
            "replay": replay,
        }),
    )?;
    if !ok || strict {
        if !ok {
            return Err(CommandFailure {
                exit_code: 1,
                output: rendered,
            }
            .into());
        }
    }
    Ok(rendered)
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

pub(super) fn load_native_trace(target: &Path) -> Result<(PathBuf, NativeTracePayloadOwned)> {
    let trace_path = resolve_native_trace_target(target)?;
    let text = std::fs::read_to_string(&trace_path)
        .with_context(|| format!("failed reading native trace: {}", trace_path.display()))?;
    let trace: NativeTracePayloadOwned = serde_json::from_str(&text)
        .with_context(|| format!("failed parsing native trace: {}", trace_path.display()))?;
    Ok((trace_path, trace))
}

pub(super) fn convert_fozzy_trace_to_native(
    target: &Path,
    output: Option<&Path>,
) -> Result<TraceNativeArtifacts> {
    ensure_exists(target)?;
    let source = std::fs::read_to_string(target)
        .with_context(|| format!("failed reading fozzy trace: {}", target.display()))?;
    let payload: serde_json::Value = serde_json::from_str(&source)
        .with_context(|| format!("failed parsing fozzy trace: {}", target.display()))?;

    let format_value = payload.get("format").and_then(|value| value.as_str());
    if format_value != Some(FOZZY_TRACE_FORMAT) {
        bail!(
            "unsupported trace format in {}: expected `{}`",
            target.display(),
            FOZZY_TRACE_FORMAT
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
    let mut runtime_event_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut capability = "thread";
    let mut capability_set = std::collections::BTreeSet::<String>::new();
    let mut checkpoint_count = 0usize;

    for event in &events {
        if let Some(name) = event.get("name").and_then(|value| value.as_str()) {
            *runtime_event_counts.entry(name.to_string()).or_insert(0) += 1;
            if name == "memory_checkpoint" {
                checkpoint_count += 1;
            }
            if let Some(capability_name) = name.strip_prefix("capability_") {
                capability_set.insert(capability_name.to_string());
            }
        }
    }

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
                    capability_set.insert("net".to_string());
                }
            }
            "rpc_send" | "rpc_recv" | "rpc_deadline" | "rpc_cancel" => {
                capability = "net";
                capability_set.insert("net".to_string());
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
                capability_set.insert("net".to_string());
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

    let runtime_events = runtime_event_counts
        .into_iter()
        .map(|(name, count)| {
            serde_json::json!({
                "name": name,
                "count": count,
            })
        })
        .collect::<Vec<_>>();
    let mut causal_links = Vec::new();
    for window in execution_order.windows(2) {
        causal_links.push(serde_json::json!({
            "from": format!("task:{}", window[0]),
            "to": format!("task:{}", window[1]),
            "relation": "schedule.next",
        }));
    }
    for window in rpc_frames.windows(2) {
        causal_links.push(serde_json::json!({
            "from": format!("rpc:{}:{}:{}", window[0].kind, window[0].method, window[0].task_id),
            "to": format!("rpc:{}:{}:{}", window[1].kind, window[1].method, window[1].task_id),
            "relation": "rpc.frame.order",
        }));
    }
    let compatibility = fzscenario::compatibility_info();

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
        "compatibility": compatibility,
        "capability": capability,
        "scheduler": "fifo",
        "seed": seed,
        "executionOrder": execution_order,
        "asyncSchedule": async_schedule,
        "rpcFrames": rpc_frames,
        "events": events,
        "runtimeEvents": runtime_events,
        "causalLinks": causal_links,
        "capabilitySet": capability_set.into_iter().collect::<Vec<_>>(),
        "checkpointCount": checkpoint_count,
    });
    std::fs::write(&trace_path, serde_json::to_vec_pretty(&native_trace)?)
        .with_context(|| format!("failed writing native trace: {}", trace_path.display()))?;

    let manifest = serde_json::json!({
        "schemaVersion": "fozzylang.artifacts.v0",
        "compatibility": fzscenario::compatibility_info(),
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

pub(super) fn render_trace_native_artifacts(
    format: Format,
    artifacts: TraceNativeArtifacts,
) -> String {
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

pub(super) fn native_explore(target: &Path, format: Format) -> Result<String> {
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

#[cfg(test)]
pub(super) fn build_live_http_probe_steps(
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

pub(super) fn resolve_replay_target(target: &Path) -> Result<PathBuf> {
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
    let schema_version = manifest
        .get("schemaVersion")
        .and_then(|value| value.as_str())
        .unwrap_or_default();

    if let Some(goal_trace) = manifest.get("goalTrace").and_then(|v| v.as_str()) {
        let path = PathBuf::from(goal_trace);
        if path.exists() {
            return Ok(path);
        }
    }
    if schema_version == "fozzylang.test_manifest.v1" {
        bail!(
            "native test manifests are not replay targets; rerun `fz test` from source and inspect the emitted native trace/report artifacts directly: {}",
            manifest_path.display()
        );
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

pub(super) fn ensure_goal_trace_from_scenario(
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
    super::record_goal_trace_from_scenario(primary_scenario, goal_trace_path, seed).with_context(
        || {
            format!(
                "failed recording goal trace from generated scenario {}",
                primary_scenario.display()
            )
        },
    )?;
    Ok(())
}
