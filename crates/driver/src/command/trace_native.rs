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
