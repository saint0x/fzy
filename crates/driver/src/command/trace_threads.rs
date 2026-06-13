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
    let standalone_prefix = if !workspace && path.is_file() {
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("source");
        Some(format!("unsafe-{stem}"))
    } else {
        None
    };
    let unsafe_map = if let Some(prefix) = &standalone_prefix {
        out_dir.join(format!("{prefix}.map.json"))
    } else if workspace {
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
    let unsafe_docs_json = if let Some(prefix) = &standalone_prefix {
        out_dir.join(format!("{prefix}.docs.json"))
    } else if workspace {
        out_dir.join("unsafe-docs.workspace.json")
    } else {
        out_dir.join("unsafe-docs.json")
    };
    let unsafe_docs_md = if let Some(prefix) = &standalone_prefix {
        out_dir.join(format!("{prefix}.docs.md"))
    } else if workspace {
        out_dir.join("unsafe-docs.workspace.md")
    } else {
        out_dir.join("unsafe-docs.md")
    };
    let unsafe_docs_html = if let Some(prefix) = &standalone_prefix {
        out_dir.join(format!("{prefix}.docs.html"))
    } else if workspace {
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
