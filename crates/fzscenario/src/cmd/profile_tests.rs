use super::*;
use crate::{ExitStatus, RunIdentity, RunMode, RunSummary, ScenarioV1Steps, Step, TraceEvent};
use std::path::PathBuf;

fn sample_trace() -> TraceFile {
    TraceFile {
        format: "fozzy-trace".to_string(),
        version: crate::CURRENT_TRACE_VERSION,
        engine: crate::version_info(),
        mode: RunMode::Run,
        scenario_path: None,
        scenario: Some(ScenarioV1Steps {
            version: 1,
            name: "no-heap".to_string(),
            steps: vec![
                Step::TraceEvent {
                    name: "setup".to_string(),
                    fields: serde_json::Map::new(),
                },
                Step::TraceEvent {
                    name: "teardown".to_string(),
                    fields: serde_json::Map::new(),
                },
            ],
        }),
        fuzz: None,
        explore: None,
        memory: None,
        decisions: Vec::new(),
        events: vec![
            TraceEvent {
                time_ms: 1,
                name: "http_request".to_string(),
                fields: serde_json::Map::new(),
            },
            TraceEvent {
                time_ms: 4,
                name: "memory_alloc".to_string(),
                fields: serde_json::Map::from_iter([
                    ("alloc_id".to_string(), serde_json::json!(1)),
                    ("bytes".to_string(), serde_json::json!(64)),
                    (
                        "callsite_hash".to_string(),
                        serde_json::json!("step:memory_alloc"),
                    ),
                ]),
            },
            TraceEvent {
                time_ms: 8,
                name: "memory_free".to_string(),
                fields: serde_json::Map::from_iter([(
                    "alloc_id".to_string(),
                    serde_json::json!(1),
                )]),
            },
        ],
        summary: RunSummary {
            status: ExitStatus::Pass,
            mode: RunMode::Run,
            identity: RunIdentity {
                run_id: "r1".to_string(),
                seed: 7,
                trace_path: None,
                report_path: None,
                artifacts_dir: None,
            },
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:00Z".to_string(),
            duration_ms: 10,
            duration_ns: 10_000_000,
            tests: None,
            memory: None,
            findings: Vec::new(),
        },
        checksum: None,
    }
}

fn sample_trace_without_heap() -> TraceFile {
    TraceFile {
        format: "fozzy-trace".to_string(),
        version: crate::CURRENT_TRACE_VERSION,
        engine: crate::version_info(),
        mode: RunMode::Run,
        scenario_path: None,
        scenario: Some(ScenarioV1Steps {
            version: 1,
            name: "no-heap".to_string(),
            steps: vec![
                Step::TraceEvent {
                    name: "setup".to_string(),
                    fields: serde_json::Map::new(),
                },
                Step::TraceEvent {
                    name: "teardown".to_string(),
                    fields: serde_json::Map::new(),
                },
            ],
        }),
        fuzz: None,
        explore: None,
        memory: None,
        decisions: Vec::new(),
        events: vec![
            TraceEvent {
                time_ms: 1,
                name: "setup".to_string(),
                fields: serde_json::Map::new(),
            },
            TraceEvent {
                time_ms: 5,
                name: "work".to_string(),
                fields: serde_json::Map::new(),
            },
            TraceEvent {
                time_ms: 9,
                name: "teardown".to_string(),
                fields: serde_json::Map::new(),
            },
        ],
        summary: RunSummary {
            status: ExitStatus::Pass,
            mode: RunMode::Run,
            identity: RunIdentity {
                run_id: "r-no-heap".to_string(),
                seed: 9,
                trace_path: None,
                report_path: None,
                artifacts_dir: None,
            },
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:00Z".to_string(),
            duration_ms: 1,
            duration_ns: 1_000_000,
            tests: None,
            memory: None,
            findings: Vec::new(),
        },
        checksum: None,
    }
}

#[test]
fn timeline_builds_required_fields() {
    let trace = sample_trace();
    let timeline = build_profile_timeline(&trace);
    assert_eq!(timeline.len(), 3);
    assert_eq!(timeline[0].run_id, "r1");
    assert_eq!(timeline[0].seed, 7);
}

#[test]
fn diff_is_deterministic() {
    let trace = sample_trace();
    let timeline = build_profile_timeline(&trace);
    let cpu = build_cpu_profile(&trace, &timeline);
    let heap = build_heap_profile(&trace, &timeline);
    let latency = build_latency_profile(&trace, &timeline);
    let metrics = build_profile_metrics(&trace, &timeline, &cpu, &heap, &latency);
    let diff_a = compute_diff(
        "a",
        "b",
        &["latency".to_string(), "heap".to_string()],
        &metrics,
        &metrics,
        Some(&heap),
        Some(&heap),
        &HashMap::new(),
        &HashMap::new(),
        1,
        1,
    );
    let diff_b = compute_diff(
        "a",
        "b",
        &["latency".to_string(), "heap".to_string()],
        &metrics,
        &metrics,
        Some(&heap),
        Some(&heap),
        &HashMap::new(),
        &HashMap::new(),
        1,
        1,
    );
    assert_eq!(
        serde_json::to_string(&diff_a).expect("json"),
        serde_json::to_string(&diff_b).expect("json")
    );
}

#[test]
fn profile_event_schema_roundtrip_and_compatibility() {
    let trace = sample_trace();
    let timeline = build_profile_timeline(&trace);
    let event = timeline.first().expect("event");
    let encoded = serde_json::to_vec(event).expect("encode");
    let decoded: ProfileEvent = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.t_virtual, event.t_virtual);
    assert_eq!(decoded.kind, event.kind);
    assert_eq!(decoded.run_id, event.run_id);
    assert_eq!(decoded.seed, event.seed);
    assert_eq!(decoded.thread, event.thread);
    assert_eq!(decoded.span_id, event.span_id);

    let compat_json = serde_json::json!({
        "t_virtual": 42,
        "kind": "io",
        "run_id": "compat-run",
        "seed": 99,
        "thread": "main",
        "span_id": "s-1",
        "cost": {"duration_ms": 3},
        "unknown_field": "ignored"
    });
    let compat: ProfileEvent = serde_json::from_value(compat_json).expect("compat decode");
    assert_eq!(compat.t_virtual, 42);
    assert_eq!(compat.kind, ProfileEventKind::Io);
    assert_eq!(compat.t_mono, None);
    assert_eq!(compat.task, None);
    assert!(compat.tags.is_empty());
    assert_eq!(compat.cost.duration_ms, Some(3));
}

#[test]
fn folded_stack_aggregation_is_correct_and_stable() {
    let mut trace = sample_trace();
    trace.events = vec![
        TraceEvent {
            time_ms: 1,
            name: "sample".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "stack".to_string(),
                    serde_json::json!("fozzy::runtime;step::a"),
                ),
                ("weight_ms".to_string(), serde_json::json!(3)),
            ]),
        },
        TraceEvent {
            time_ms: 2,
            name: "sample".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "stack".to_string(),
                    serde_json::json!("fozzy::runtime;step::a"),
                ),
                ("weight_ms".to_string(), serde_json::json!(2)),
            ]),
        },
        TraceEvent {
            time_ms: 3,
            name: "sample".to_string(),
            fields: serde_json::Map::from_iter([
                (
                    "stack".to_string(),
                    serde_json::json!("fozzy::runtime;step::b"),
                ),
                ("weight_ms".to_string(), serde_json::json!(5)),
            ]),
        },
    ];
    let timeline = build_profile_timeline(&trace);
    let cpu = build_cpu_profile(&trace, &timeline);
    assert_eq!(cpu.folded_stacks.len(), 2);
    assert_eq!(cpu.folded_stacks[0].stack, "fozzy::runtime;step::a");
    assert_eq!(cpu.folded_stacks[0].weight, 5);
    assert_eq!(cpu.folded_stacks[1].stack, "fozzy::runtime;step::b");
    assert_eq!(cpu.folded_stacks[1].weight, 5);
}

#[test]
fn latency_critical_path_extraction_is_correct() {
    let mut trace = sample_trace();
    trace.events = vec![
        TraceEvent {
            time_ms: 0,
            name: "span_start".to_string(),
            fields: serde_json::Map::from_iter([("span".to_string(), serde_json::json!("root"))]),
        },
        TraceEvent {
            time_ms: 1,
            name: "span_start".to_string(),
            fields: serde_json::Map::from_iter([
                ("span".to_string(), serde_json::json!("db")),
                ("parent_span".to_string(), serde_json::json!("root")),
            ]),
        },
        TraceEvent {
            time_ms: 4,
            name: "http_request".to_string(),
            fields: serde_json::Map::from_iter([
                ("span".to_string(), serde_json::json!("io-1")),
                ("parent_span".to_string(), serde_json::json!("root")),
            ]),
        },
        TraceEvent {
            time_ms: 7,
            name: "span_end".to_string(),
            fields: serde_json::Map::from_iter([("span".to_string(), serde_json::json!("db"))]),
        },
        TraceEvent {
            time_ms: 10,
            name: "span_end".to_string(),
            fields: serde_json::Map::from_iter([("span".to_string(), serde_json::json!("root"))]),
        },
    ];
    let timeline = build_profile_timeline(&trace);
    let latency = build_latency_profile(&trace, &timeline);
    assert!(
        !latency.critical_path.is_empty(),
        "expected critical path edges"
    );
    assert_eq!(latency.critical_path[0].to_span, "root");
    assert_eq!(latency.critical_path[0].reason, "io");
}

#[test]
fn heap_callsite_and_lifetime_histogram_aggregation_is_correct() {
    let mut trace = sample_trace();
    trace.events = vec![
        TraceEvent {
            time_ms: 1,
            name: "memory_alloc".to_string(),
            fields: serde_json::Map::from_iter([
                ("alloc_id".to_string(), serde_json::json!(1)),
                ("bytes".to_string(), serde_json::json!(64)),
                ("callsite_hash".to_string(), serde_json::json!("cs:A")),
            ]),
        },
        TraceEvent {
            time_ms: 2,
            name: "memory_alloc".to_string(),
            fields: serde_json::Map::from_iter([
                ("alloc_id".to_string(), serde_json::json!(2)),
                ("bytes".to_string(), serde_json::json!(32)),
                ("callsite_hash".to_string(), serde_json::json!("cs:A")),
            ]),
        },
        TraceEvent {
            time_ms: 4,
            name: "memory_free".to_string(),
            fields: serde_json::Map::from_iter([("alloc_id".to_string(), serde_json::json!(1))]),
        },
        TraceEvent {
            time_ms: 20,
            name: "memory_free".to_string(),
            fields: serde_json::Map::from_iter([("alloc_id".to_string(), serde_json::json!(2))]),
        },
        TraceEvent {
            time_ms: 30,
            name: "memory_alloc".to_string(),
            fields: serde_json::Map::from_iter([
                ("alloc_id".to_string(), serde_json::json!(3)),
                ("bytes".to_string(), serde_json::json!(16)),
                ("callsite_hash".to_string(), serde_json::json!("cs:B")),
            ]),
        },
    ];
    trace.summary.duration_ms = 30;
    let timeline = build_profile_timeline(&trace);
    let heap = build_heap_profile(&trace, &timeline);
    let cs_a = heap
        .hotspots
        .iter()
        .find(|h| h.callsite_hash == "cs:A")
        .expect("cs:A");
    let cs_b = heap
        .hotspots
        .iter()
        .find(|h| h.callsite_hash == "cs:B")
        .expect("cs:B");
    assert_eq!(cs_a.alloc_count, 2);
    assert_eq!(cs_a.alloc_bytes, 96);
    assert_eq!(cs_a.in_use_bytes, 0);
    assert_eq!(cs_b.alloc_count, 1);
    assert_eq!(cs_b.in_use_bytes, 16);
    assert!(
        heap.lifetime_histogram
            .iter()
            .any(|b| b.bucket == "2-10ms" && b.count == 1)
    );
    assert!(
        heap.lifetime_histogram
            .iter()
            .any(|b| b.bucket == "11-100ms" && b.count == 1)
    );
}

#[test]
fn diff_tie_breaking_is_deterministic() {
    let trace = sample_trace();
    let timeline = build_profile_timeline(&trace);
    let cpu = build_cpu_profile(&trace, &timeline);
    let heap = build_heap_profile(&trace, &timeline);
    let latency = build_latency_profile(&trace, &timeline);
    let mut left = build_profile_metrics(&trace, &timeline, &cpu, &heap, &latency);
    let mut right = left.clone();
    left.io_ops = 0;
    left.sched_ops = 0;
    right.io_ops = 1;
    right.sched_ops = 1;
    let diff = compute_diff(
        "left",
        "right",
        &["io".to_string(), "sched".to_string()],
        &left,
        &right,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
        1,
        1,
    );
    let metrics = diff
        .regressions
        .iter()
        .map(|r| r.metric.clone())
        .collect::<Vec<_>>();
    assert_eq!(metrics, vec!["io_ops".to_string(), "sched_ops".to_string()]);
}

fn temp_workspace(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fozzy-profile-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("workspace");
    dir
}

#[test]
fn resolve_profile_trace_supports_run_with_report_trace_path() {
    let ws = temp_workspace("resolve-report-trace");
    let base_dir = ws.join(".fozzy");
    let run_id = "run-1";
    let run_dir = base_dir.join("runs").join(run_id);
    std::fs::create_dir_all(&run_dir).expect("run dir");

    let mut trace = sample_trace();
    trace.summary.identity.run_id = run_id.to_string();
    let external_trace = ws.join("external.trace.fozzy");
    std::fs::write(
        &external_trace,
        serde_json::to_vec_pretty(&trace).expect("trace bytes"),
    )
    .expect("write trace");

    let mut summary = trace.summary.clone();
    summary.identity.trace_path = Some(external_trace.to_string_lossy().to_string());
    std::fs::write(
        run_dir.join("report.json"),
        serde_json::to_vec_pretty(&summary).expect("summary bytes"),
    )
    .expect("write report");

    let cfg = Config {
        base_dir: base_dir.clone(),
        ..Config::default()
    };
    let cmd = ProfileCommand::Top {
        run: run_id.to_string(),
        cpu: false,
        heap: true,
        latency: false,
        io: false,
        sched: false,
        limit: 5,
    };
    let out = profile_command(&cfg, &cmd, true).expect("profile top");
    assert_eq!(out.get("run").and_then(|v| v.as_str()), Some(run_id));
}

#[test]
fn profile_commands_support_run_id_with_profile_artifacts_only() {
    let ws = temp_workspace("artifacts-only-run");
    let base_dir = ws.join(".fozzy");
    let run_id = "run-artifacts-only";
    let run_dir = base_dir.join("runs").join(run_id);
    std::fs::create_dir_all(&run_dir).expect("run dir");

    let mut trace = sample_trace();
    trace.summary.identity.run_id = run_id.to_string();
    write_profile_artifacts_from_trace(&trace, &run_dir).expect("profile artifacts");
    std::fs::write(
        run_dir.join("report.json"),
        serde_json::to_vec_pretty(&trace.summary).expect("summary bytes"),
    )
    .expect("write report");

    let cfg = Config {
        base_dir: base_dir.clone(),
        ..Config::default()
    };
    let cmd = ProfileCommand::Top {
        run: run_id.to_string(),
        cpu: false,
        heap: true,
        latency: false,
        io: false,
        sched: false,
        limit: 5,
    };
    let out = profile_command(&cfg, &cmd, true).expect("profile top");
    assert_eq!(out.get("run").and_then(|v| v.as_str()), Some(run_id));
}

#[test]
fn explain_diff_keeps_primary_run_as_run_field() {
    let trace = sample_trace();
    let timeline = build_profile_timeline(&trace);
    let cpu = build_cpu_profile(&trace, &timeline);
    let heap = build_heap_profile(&trace, &timeline);
    let latency = build_latency_profile(&trace, &timeline);
    let metrics = build_profile_metrics(&trace, &timeline, &cpu, &heap, &latency);
    let explain = explain_from_diff("primary", "baseline", &metrics, &metrics);
    assert_eq!(explain.run, "primary");
}

#[test]
fn timeline_json_out_matches_stdout_schema() {
    let ws = temp_workspace("timeline-schema");
    let trace = ws.join("trace.fozzy");
    std::fs::write(
        &trace,
        serde_json::to_vec_pretty(&sample_trace()).expect("trace bytes"),
    )
    .expect("write trace");
    let out_file = ws.join("timeline.json");

    let cfg = Config::default();
    let cmd = ProfileCommand::Timeline {
        run: trace.to_string_lossy().to_string(),
        out: Some(out_file.clone()),
        format: ProfileTimelineFormat::Json,
    };
    let stdout_doc = profile_command(&cfg, &cmd, true).expect("timeline");
    let file_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_file).expect("read timeline"))
            .expect("parse timeline");
    assert_eq!(stdout_doc, file_doc);
}

#[test]
fn shrink_missing_trace_is_invalid_argument() {
    let cfg = Config::default();
    let cmd = ProfileCommand::Shrink {
        run: "missing.fozzy".to_string(),
        metric: ProfileMetric::P99Latency,
        direction: ProfileDirection::Increase,
        budget: None,
        minimize: ShrinkMinimize::All,
    };
    let err = profile_command(&cfg, &cmd, true).expect_err("must fail");
    match err {
        FozzyError::InvalidArgument(msg) => {
            assert!(msg.contains("no trace.fozzy found"), "message: {msg}");
        }
        other => panic!("expected invalid argument, got {other:?}"),
    }
}

#[test]
fn format_metric_value_normalizes_negative_zero() {
    assert_eq!(format_metric_value(-0.0), "0");
    assert_eq!(format_metric_value(8.0), "8");
    assert_eq!(format_metric_value(8.125), "8.125");
}

#[test]
fn shrink_contract_miss_returns_no_feasible_status() {
    let ws = temp_workspace("shrink-contract-miss");
    let trace = ws.join("c.trace.fozzy");
    std::fs::write(
        &trace,
        serde_json::to_vec_pretty(&sample_trace_without_heap()).expect("trace bytes"),
    )
    .expect("trace");

    let cfg = Config::default();
    let cmd = ProfileCommand::Shrink {
        run: trace.to_string_lossy().to_string(),
        metric: ProfileMetric::CpuTime,
        direction: ProfileDirection::Increase,
        budget: Some(crate::FozzyDuration(std::time::Duration::from_secs(1))),
        minimize: ShrinkMinimize::All,
    };
    let out = profile_command(&cfg, &cmd, true).expect("shrink output");
    assert_eq!(
        out.get("status").and_then(|v| v.as_str()),
        Some("no_feasible_shrink_found")
    );
    assert_eq!(out.get("preserved").and_then(|v| v.as_bool()), Some(false));
}

#[test]
fn flame_reports_empty_domain_reason() {
    let ws = temp_workspace("flame-empty");
    let trace = ws.join("noheap.trace.fozzy");
    std::fs::write(
        &trace,
        serde_json::to_vec_pretty(&sample_trace_without_heap()).expect("trace bytes"),
    )
    .expect("trace");
    let out_file = ws.join("heap.folded.txt");

    let cfg = Config::default();
    let cmd = ProfileCommand::Flame {
        run: trace.to_string_lossy().to_string(),
        cpu: false,
        heap: true,
        out: Some(out_file.clone()),
        format: ProfileFlameFormat::Folded,
    };
    let out = profile_command(&cfg, &cmd, true).expect("flame");
    assert_eq!(out.get("empty").and_then(|v| v.as_bool()), Some(true));
    assert!(
        out.get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("no heap samples")
    );
    let written = std::fs::read_to_string(out_file).expect("read output");
    assert!(!written.trim().is_empty());
}

#[test]
fn profile_env_reports_schema_and_domains() {
    let cfg = Config::default();
    let out = profile_command(&cfg, &ProfileCommand::Env, true).expect("env");
    assert_eq!(
        out.get("schemaVersion").and_then(|v| v.as_str()),
        Some("fozzy.profile_env.v3")
    );
    assert!(out.get("domains").is_some());
}

#[test]
fn strict_mode_allows_cpu_domain() {
    let ws = temp_workspace("cpu-strict");
    let trace = ws.join("trace.fozzy");
    std::fs::write(
        &trace,
        serde_json::to_vec_pretty(&sample_trace()).expect("trace bytes"),
    )
    .expect("trace");
    let cfg = Config::default();
    let cmd = ProfileCommand::Top {
        run: trace.to_string_lossy().to_string(),
        cpu: true,
        heap: false,
        latency: false,
        io: false,
        sched: false,
        limit: 5,
    };
    let out = profile_command(&cfg, &cmd, true).expect("top");
    assert!(
        out.get("cpu").is_some(),
        "cpu domain should be available in strict mode"
    );
}

#[test]
fn heap_budget_findings_emitted() {
    let trace = sample_trace();
    let findings = heap_budget_findings_from_trace(
        &trace,
        &HeapBudgetPolicy {
            alloc_bytes_budget: Some(32),
            in_use_bytes_budget: Some(0),
        },
    );
    assert!(
        findings.iter().any(|f| f.title == "heap_alloc_budget"),
        "expected heap_alloc_budget finding"
    );
}

#[test]
fn heap_diff_includes_callsite_metrics() {
    let left = sample_trace();
    let mut right = sample_trace();
    if let Some(event) = right.events.get_mut(1) {
        event
            .fields
            .insert("bytes".to_string(), serde_json::json!(256u64));
    }
    let left_timeline = build_profile_timeline(&left);
    let right_timeline = build_profile_timeline(&right);
    let left_cpu = build_cpu_profile(&left, &left_timeline);
    let right_cpu = build_cpu_profile(&right, &right_timeline);
    let left_heap = build_heap_profile(&left, &left_timeline);
    let right_heap = build_heap_profile(&right, &right_timeline);
    let left_latency = build_latency_profile(&left, &left_timeline);
    let right_latency = build_latency_profile(&right, &right_timeline);
    let left_metrics =
        build_profile_metrics(&left, &left_timeline, &left_cpu, &left_heap, &left_latency);
    let right_metrics = build_profile_metrics(
        &right,
        &right_timeline,
        &right_cpu,
        &right_heap,
        &right_latency,
    );
    let diff = compute_diff(
        "left",
        "right",
        &["heap".to_string()],
        &left_metrics,
        &right_metrics,
        Some(&left_heap),
        Some(&right_heap),
        &HashMap::new(),
        &HashMap::new(),
        1,
        1,
    );
    assert!(
        diff.regressions
            .iter()
            .any(|r| r.metric.contains("callsite:") && r.metric.contains("alloc_bytes")),
        "expected callsite alloc_bytes regression"
    );
}

#[test]
fn profile_doctor_reports_schema() {
    let ws = temp_workspace("profile-doctor");
    let trace = ws.join("trace.fozzy");
    std::fs::write(
        &trace,
        serde_json::to_vec_pretty(&sample_trace()).expect("trace bytes"),
    )
    .expect("trace");

    let cfg = Config::default();
    let cmd = ProfileCommand::Doctor {
        run: trace.to_string_lossy().to_string(),
        deep: false,
    };
    let out = profile_command(&cfg, &cmd, true).expect("doctor");
    assert_eq!(
        out.get("schemaVersion").and_then(|v| v.as_str()),
        Some("fozzy.profile_doctor.v1")
    );
    assert!(out.get("checks").and_then(|v| v.as_array()).is_some());
}

#[test]
fn relaxed_mode_returns_warning_for_missing_profile_inputs() {
    let cfg = Config::default();
    let cmd = ProfileCommand::Top {
        run: "missing.fozzy".to_string(),
        cpu: false,
        heap: true,
        latency: false,
        io: false,
        sched: false,
        limit: 5,
    };
    let out = profile_command(&cfg, &cmd, false).expect("relaxed warning");
    assert_eq!(
        out.get("schemaVersion").and_then(|v| v.as_str()),
        Some("fozzy.profile_contract_warning.v1")
    );
    assert_eq!(out.get("status").and_then(|v| v.as_str()), Some("warn"));
}

#[test]
fn relaxed_mode_emits_cpu_warning() {
    let ws = temp_workspace("cpu-warn");
    let trace = ws.join("trace.fozzy");
    std::fs::write(
        &trace,
        serde_json::to_vec_pretty(&sample_trace()).expect("trace bytes"),
    )
    .expect("trace");
    let cfg = Config::default();
    let cmd = ProfileCommand::Top {
        run: trace.to_string_lossy().to_string(),
        cpu: true,
        heap: false,
        latency: false,
        io: false,
        sched: false,
        limit: 5,
    };
    let out = profile_command(&cfg, &cmd, false).expect("top");
    let warnings = out
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!warnings.is_empty(), "expected warnings");
}
