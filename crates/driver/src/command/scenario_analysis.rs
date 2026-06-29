use super::*;

pub(super) fn rpc_frames_json(frames: &[RpcFrameEvent]) -> Vec<serde_json::Value> {
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

pub(super) fn unsafe_trace_findings(fir: &fir::FirModule) -> Vec<serde_json::Value> {
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

pub(super) fn build_schedule_candidates(execution_order: &[u64]) -> serde_json::Value {
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

pub(super) fn build_rpc_frame_permutations(
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

pub(super) fn classify_failure_classes(
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

pub(super) fn sanitize_c_identifier(raw: &str) -> String {
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

pub(super) fn persist_runtime_threads_config(
    path: &Path,
    threads: Option<u16>,
) -> Result<Option<PathBuf>> {
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

pub(super) fn replay_like(
    command: &str,
    target: &Path,
    strict: bool,
    format: Format,
) -> Result<String> {
    scenario_replay_like(command, target, strict, format)
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct NativeTracePayloadOwned {
    #[serde(rename = "executionOrder")]
    pub(super) execution_order: Vec<u64>,
    #[serde(rename = "asyncSchedule")]
    pub(super) async_schedule: Vec<u64>,
    #[serde(rename = "rpcFrames")]
    pub(super) rpc_frames: Vec<RpcFrameEventOwned>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RpcFrameEventOwned {
    #[serde(rename = "event")]
    pub(super) kind: String,
    pub(super) method: String,
    #[serde(rename = "taskId")]
    pub(super) task_id: u64,
}

pub(super) fn is_native_trace_or_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".trace.json") || name.ends_with(".manifest.json"))
        .unwrap_or(false)
}
