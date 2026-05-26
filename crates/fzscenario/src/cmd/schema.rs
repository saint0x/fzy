//! Scenario/schema introspection for automation and authoring.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct SchemaDoc {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "fileVariants")]
    pub file_variants: Vec<FileVariant>,
    #[serde(rename = "stepTypes")]
    pub step_types: Vec<&'static str>,
    #[serde(rename = "distributedStepTypes")]
    pub distributed_step_types: Vec<&'static str>,
    #[serde(rename = "distributedInvariantTypes")]
    pub distributed_invariant_types: Vec<&'static str>,
    #[serde(rename = "stepSchemas")]
    pub step_schemas: BTreeMap<&'static str, StepSchema>,
    #[serde(rename = "distributedStepSchemas")]
    pub distributed_step_schemas: BTreeMap<&'static str, StepSchema>,
    #[serde(rename = "distributedInvariantSchemas")]
    pub distributed_invariant_schemas: BTreeMap<&'static str, StepSchema>,
    #[serde(rename = "profileOutputSchemas")]
    pub profile_output_schemas: BTreeMap<&'static str, ProfileOutputSchema>,
    #[serde(rename = "profileArtifactSchemas")]
    pub profile_artifact_schemas: BTreeMap<&'static str, ProfileArtifactSchema>,
    #[serde(rename = "profileCompatibilityPolicy")]
    pub profile_compatibility_policy: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileVariant {
    pub name: &'static str,
    #[serde(rename = "requiredTopLevelKeys")]
    pub required_top_level_keys: Vec<&'static str>,
    #[serde(rename = "minimalExample")]
    pub minimal_example: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepSchema {
    #[serde(rename = "requiredFields")]
    pub required_fields: Vec<&'static str>,
    #[serde(rename = "optionalFields")]
    pub optional_fields: Vec<&'static str>,
    pub example: serde_json::Value,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileOutputSchema {
    #[serde(rename = "schemaVersion")]
    pub schema_version: &'static str,
    #[serde(rename = "requiredFields")]
    pub required_fields: Vec<&'static str>,
    #[serde(rename = "optionalFields")]
    pub optional_fields: Vec<&'static str>,
    pub example: serde_json::Value,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileArtifactSchema {
    #[serde(rename = "schemaVersion")]
    pub schema_version: &'static str,
    #[serde(rename = "requiredFields")]
    pub required_fields: Vec<&'static str>,
    #[serde(rename = "optionalFields")]
    pub optional_fields: Vec<&'static str>,
    pub example: serde_json::Value,
    pub notes: String,
}

pub fn schema_doc() -> SchemaDoc {
    let step_types = vec![
        "trace_event",
        "rand_u64",
        "assert_ok",
        "assert_eq_int",
        "assert_ne_int",
        "assert_eq_str",
        "assert_ne_str",
        "sleep",
        "advance",
        "freeze",
        "unfreeze",
        "set_kv",
        "get_kv_assert",
        "fs_write",
        "fs_read_assert",
        "fs_snapshot",
        "fs_restore",
        "http_when",
        "http_request",
        "proc_when",
        "proc_spawn",
        "net_partition",
        "net_heal",
        "net_set_drop_rate",
        "net_set_reorder",
        "net_send",
        "net_deliver_one",
        "net_recv_assert",
        "memory_alloc",
        "memory_free",
        "memory_limit_mb",
        "memory_fail_after_allocs",
        "memory_fragmentation",
        "memory_pressure_wave",
        "memory_checkpoint",
        "memory_assert_in_use_bytes",
        "assert_throws",
        "assert_rejects",
        "assert_eventually_kv",
        "assert_never_kv",
        "fail",
        "panic",
    ];
    let distributed_step_types = vec![
        "client_put",
        "client_get_assert",
        "partition",
        "heal",
        "crash",
        "restart",
        "tick",
    ];
    let distributed_invariant_types = vec!["kv_all_equal", "kv_present_on_all", "kv_node_equals"];

    let mut step_schemas = BTreeMap::<&'static str, StepSchema>::new();
    step_schemas.insert(
        "proc_when",
        StepSchema {
            required_fields: vec!["type", "cmd", "exit_code"],
            optional_fields: vec!["args", "stdout", "stderr", "times"],
            example: serde_json::json!({
                "type": "proc_when",
                "cmd": "git",
                "args": ["status", "--porcelain"],
                "exit_code": 0,
                "stdout": "",
                "times": 1
            }),
            notes: "Use `exit_code` (not `exit`). `times` defaults to unlimited when omitted."
                .to_string(),
        },
    );
    step_schemas.insert(
        "proc_spawn",
        StepSchema {
            required_fields: vec!["type", "cmd"],
            optional_fields: vec![
                "args",
                "expect_exit",
                "expect_stdout",
                "expect_stderr",
                "save_stdout_as",
            ],
            example: serde_json::json!({
                "type": "proc_spawn",
                "cmd": "echo",
                "args": ["hello"],
                "expect_exit": 0,
                "expect_stdout": "hello\n"
            }),
            notes:
                "Assertions are optional; omitted expectations mean \"do not assert that field\"."
                    .to_string(),
        },
    );
    step_schemas.insert(
        "http_when",
        StepSchema {
            required_fields: vec!["type", "method", "path", "status"],
            optional_fields: vec!["headers", "body", "json", "delay", "times"],
            example: serde_json::json!({
                "type": "http_when",
                "method": "GET",
                "path": "/healthz",
                "status": 200,
                "json": {"ok": true},
                "times": 1
            }),
            notes: "Set at most one of `body` or `json`.".to_string(),
        },
    );
    step_schemas.insert(
        "http_request",
        StepSchema {
            required_fields: vec!["type", "method", "path"],
            optional_fields: vec![
                "headers",
                "body",
                "expect_status",
                "expect_headers",
                "expect_body",
                "expect_json",
                "save_body_as",
            ],
            example: serde_json::json!({
                "type": "http_request",
                "method": "GET",
                "path": "/healthz",
                "expect_status": 200,
                "expect_json": {"ok": true}
            }),
            notes: "Response assertions are optional.".to_string(),
        },
    );
    step_schemas.insert(
        "memory_free",
        StepSchema {
            required_fields: vec!["type"],
            optional_fields: vec!["alloc_id", "key"],
            example: serde_json::json!({
                "type": "memory_free",
                "key": "buf"
            }),
            notes: "Set exactly one of `alloc_id` or `key`.".to_string(),
        },
    );
    for step in &step_types {
        step_schemas.entry(step).or_insert_with(|| StepSchema {
            required_fields: vec!["type"],
            optional_fields: vec![],
            example: serde_json::json!({ "type": step }),
            notes: "Step-specific fields are defined by the runtime DSL; this entry is intentionally minimal."
                .to_string(),
        });
    }

    let mut distributed_step_schemas = BTreeMap::<&'static str, StepSchema>::new();
    distributed_step_schemas.insert(
        "client_put",
        StepSchema {
            required_fields: vec!["type", "node", "key", "value"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "client_put",
                "node": "n0",
                "key": "k",
                "value": "v"
            }),
            notes: "Node must exist in distributed nodes list or generated node_count set."
                .to_string(),
        },
    );
    distributed_step_schemas.insert(
        "tick",
        StepSchema {
            required_fields: vec!["type", "duration"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "tick",
                "duration": "10ms"
            }),
            notes: "Duration accepts the same parser as `sleep`/`advance`.".to_string(),
        },
    );
    for step in &distributed_step_types {
        distributed_step_schemas
            .entry(step)
            .or_insert_with(|| StepSchema {
                required_fields: vec!["type"],
                optional_fields: vec![],
                example: serde_json::json!({ "type": step }),
                notes: "Distributed step-specific fields are required as defined by the DSL."
                    .to_string(),
            });
    }

    let mut distributed_invariant_schemas = BTreeMap::<&'static str, StepSchema>::new();
    distributed_invariant_schemas.insert(
        "kv_present_on_all",
        StepSchema {
            required_fields: vec!["type", "key"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "kv_present_on_all",
                "key": "k"
            }),
            notes: "Fails if any live node is missing `key`.".to_string(),
        },
    );
    distributed_invariant_schemas.insert(
        "kv_node_equals",
        StepSchema {
            required_fields: vec!["type", "node", "key", "equals"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "kv_node_equals",
                "node": "n1",
                "key": "k",
                "equals": "v"
            }),
            notes: "Node must exist in the distributed topology.".to_string(),
        },
    );
    for inv in &distributed_invariant_types {
        distributed_invariant_schemas
            .entry(inv)
            .or_insert_with(|| StepSchema {
                required_fields: vec!["type"],
                optional_fields: vec![],
                example: serde_json::json!({ "type": inv }),
                notes: "Invariant-specific fields are required as defined by the DSL.".to_string(),
            });
    }

    let mut profile_output_schemas = BTreeMap::<&'static str, ProfileOutputSchema>::new();
    profile_output_schemas.insert(
        "top",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_top.v1",
            required_fields: vec!["schemaVersion", "run", "limit", "metrics", "emptyDomains"],
            optional_fields: vec!["cpu", "heap", "latency", "io", "sched", "warnings"],
            example: serde_json::json!({
                "schemaVersion": "fozzy.profile_top.v1",
                "run": "run-id-or-trace",
                "limit": 10,
                "heap": [],
                "metrics": {"schemaVersion": "fozzy.profile_metrics.v2"},
                "emptyDomains": [{"domain":"heap","empty":true,"reason":"no heap samples in trace"}]
            }),
            notes: "Domain arrays may be empty; inspect emptyDomains for explicit reasons."
                .to_string(),
        },
    );
    profile_output_schemas.insert(
        "diff",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_diff.v2",
            required_fields: vec![
                "schemaVersion",
                "left",
                "right",
                "leftSamples",
                "rightSamples",
                "domains",
                "summary",
                "regressions",
            ],
            optional_fields: vec!["warnings"],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_diff.v2",
                "left":"left-run",
                "right":"right-run",
                "leftSamples":2,
                "rightSamples":2,
                "domains":["heap"],
                "summary":{"verdict":"regression_detected","regressionCount":1,"improvementCount":0,"significantRegressionCount":1,"topRegressionMetric":"cpu_time_ms"},
                "regressions":[{"domain":"cpu","metric":"cpu_time_ms","left":10.0,"right":12.0,"delta":2.0,"deltaPct":20.0,"classification":"regression","isRegression":true,"isSignificant":true,"severity":"high","analysis":"host-time change 2 at confidence 0.81","timeDomain":"host_monotonic_time","confidence":0.81,"confidenceMeta":{"method":"effect_size_over_pooled_stderr"}}]
            }),
            notes: "Diff is an analyzer output with significance classification, severity, and rollup verdict."
                .to_string(),
        },
    );
    profile_output_schemas.insert(
        "explain",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_explain.v1",
            required_fields: vec![
                "schemaVersion",
                "run",
                "regressionStatement",
                "topShiftedPath",
                "likelyCauseDomain",
                "evidencePointers",
            ],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_explain.v1",
                "run":"run-id-or-trace",
                "regressionStatement":"...",
                "topShiftedPath":"metric::io_ops",
                "likelyCauseDomain":"io",
                "evidencePointers":["profile.metrics.json"]
            }),
            notes: "run always points to the primary run argument.".to_string(),
        },
    );
    profile_output_schemas.insert(
        "timeline",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_timeline.v1",
            required_fields: vec!["schemaVersion", "run", "format", "timeDomains"],
            optional_fields: vec!["events", "content"],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_timeline.v1",
                "run":"run-id-or-trace",
                "format":"json",
                "timeDomains":{"virtualTime":"deterministic","hostMonotonicTime":"non-deterministic"},
                "events":[]
            }),
            notes: "stdout and --out JSON share the same object schema.".to_string(),
        },
    );
    profile_output_schemas.insert(
        "export",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_export_result.v1",
            required_fields: vec!["schemaVersion", "run", "format", "out"],
            optional_fields: vec!["warnings"],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_export_result.v1",
                "run":"run-id-or-trace",
                "format":"speedscope",
                "out":"/tmp/profile.speedscope.json"
            }),
            notes: "This is export command status, not exported payload schema.".to_string(),
        },
    );
    profile_output_schemas.insert(
        "shrink",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_shrink.v1",
            required_fields: vec![
                "schemaVersion",
                "status",
                "run",
                "trace",
                "outTrace",
                "metric",
                "direction",
                "minimize",
                "baseline",
                "after",
                "preserved",
                "contract",
            ],
            optional_fields: vec!["reason"],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_shrink.v1",
                "status":"no_feasible_shrink_found",
                "run":"run-id-or-trace",
                "trace":"/tmp/in.trace.fozzy",
                "outTrace":"/tmp/in.min.fozzy",
                "metric":"cpu_time",
                "direction":"increase",
                "minimize":"all",
                "baseline":8.0,
                "after":0.0,
                "preserved":false,
                "contract":{"expected":"after >= baseline","direction":"increase"},
                "reason":"no feasible shrink found..."
            }),
            notes: "Contract misses are non-error with status=no_feasible_shrink_found."
                .to_string(),
        },
    );
    profile_output_schemas.insert(
        "env",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_env.v3",
            required_fields: vec![
                "schemaVersion",
                "strict",
                "determinismContract",
                "host",
                "backends",
                "domains",
            ],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_env.v3",
                "strict":true,
                "determinismContract":{"replayBoundTo":"deterministic_decisions_and_virtual_events"},
                "host":{"os":"macos","arch":"aarch64"},
                "backends":{"proc":"scripted","fs":"virtual","http":"scripted"},
                "domains":{"cpu":{"available":true,"quality":"degraded","activeCollector":"in_process_sampler","diagnostics":[]}}
            }),
            notes: "Describes profiler domain capability/quality by host + backend setup."
                .to_string(),
        },
    );
    profile_output_schemas.insert(
        "doctor",
        ProfileOutputSchema {
            schema_version: "fozzy.profile_doctor.v1",
            required_fields: vec!["schemaVersion", "run", "ok", "checks", "issues"],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_doctor.v1",
                "run":"run-id-or-trace",
                "ok":true,
                "checks":[{"name":"load_bundle","ok":true,"status":"pass","detail":"..."}],
                "issues":[]
            }),
            notes: "One-shot sanity gate across top/flame/timeline/diff/explain/export/shrink readiness.".to_string(),
        },
    );

    let mut profile_artifact_schemas = BTreeMap::<&'static str, ProfileArtifactSchema>::new();
    profile_artifact_schemas.insert(
        "profile.timeline.json",
        ProfileArtifactSchema {
            schema_version: "fozzy.profile_timeline_artifact.v3",
            required_fields: vec!["schemaVersion", "runId", "timeDomains", "events"],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_timeline_artifact.v3",
                "runId":"run-id",
                "timeDomains":{"virtualTime":"deterministic","hostMonotonicTime":"non-deterministic"},
                "events":[
                    {
                        "t_virtual":1,
                        "t_mono":0,
                        "kind":"event",
                        "run_id":"run-id",
                        "seed":7,
                        "thread":"main",
                        "task":"step",
                        "span_id":"e-0",
                        "parent_span_id":null,
                        "tags":{"name":"trace_event"},
                        "cost":{"duration_ms":1,"bytes":null,"count":1}
                    }
                ]
            }),
            notes: "Canonical event model with stable event ordering and explicit event-kind taxonomy."
                .to_string(),
        },
    );
    profile_artifact_schemas.insert(
        "profile.cpu.json",
        ProfileArtifactSchema {
            schema_version: "fozzy.profile_cpu.v2",
            required_fields: vec![
                "schemaVersion",
                "runId",
                "collector",
                "samplePeriodMs",
                "sampleCount",
                "samples",
                "foldedStacks",
                "symbolsRef",
            ],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_cpu.v2",
                "runId":"run-id",
                "collector":{"domain":"host_time","primaryCollector":"perf_event_open","activeCollector":"in_process_sampler","diagnostics":[]},
                "samplePeriodMs":10,
                "sampleCount":1,
                "samples":[{"thread":"main","stack":["fozzy::runtime"],"weightMs":1}],
                "foldedStacks":[{"stack":"fozzy::runtime","weight":1}],
                "symbolsRef":"symbols.json"
            }),
            notes: "CPU profile payload; folded stacks are deterministically sorted."
                .to_string(),
        },
    );
    profile_artifact_schemas.insert(
        "profile.heap.json",
        ProfileArtifactSchema {
            schema_version: "fozzy.profile_heap.v2",
            required_fields: vec![
                "schemaVersion",
                "runId",
                "totalAllocBytes",
                "inUseBytes",
                "allocRatePerSec",
                "hotspots",
                "lifetimeHistogram",
                "retentionSuspects",
            ],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_heap.v2",
                "runId":"run-id",
                "totalAllocBytes":0,
                "inUseBytes":0,
                "allocRatePerSec":0.0,
                "hotspots":[{"callsiteHash":"abc","allocCount":1,"allocBytes":128,"inUseBytes":64,"allocRatePerSec":12.8}],
                "lifetimeHistogram":[],
                "retentionSuspects":[{"allocId":7,"callsiteHash":"abc","bytes":64,"ageMs":20,"graphAnchor":"alloc:7"}]
            }),
            notes: "Heap profile payload; hotspots and suspects are deterministically ordered."
                .to_string(),
        },
    );
    profile_artifact_schemas.insert(
        "profile.latency.json",
        ProfileArtifactSchema {
            schema_version: "fozzy.profile_latency.v1",
            required_fields: vec![
                "schemaVersion",
                "runId",
                "distribution",
                "dependencyGraph",
                "criticalPath",
                "waitReasons",
                "tailAmplificationSuspects",
            ],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_latency.v1",
                "runId":"run-id",
                "distribution":{"count":0,"p50Ms":0,"p95Ms":0,"p99Ms":0,"maxMs":0,"variance":0.0},
                "dependencyGraph":[],
                "criticalPath":[],
                "waitReasons":[],
                "tailAmplificationSuspects":[]
            }),
            notes: "Latency profile payload; critical path rows are deterministically sorted."
                .to_string(),
        },
    );
    profile_artifact_schemas.insert(
        "profile.metrics.json",
        ProfileArtifactSchema {
            schema_version: "fozzy.profile_metrics.v2",
            required_fields: vec![
                "schemaVersion",
                "runId",
                "timeDomains",
                "virtualTimeMs",
                "hostTimeMs",
                "cpuTimeMs",
                "allocBytes",
                "inUseBytes",
                "p50LatencyMs",
                "p95LatencyMs",
                "p99LatencyMs",
                "maxLatencyMs",
                "ioOps",
                "schedOps",
            ],
            optional_fields: vec!["confidence"],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_metrics.v2",
                "runId":"run-id",
                "timeDomains":{"virtualTime":"deterministic","hostMonotonicTime":"non-deterministic"},
                "virtualTimeMs":1,
                "hostTimeMs":1,
                "cpuTimeMs":1,
                "allocBytes":0,
                "inUseBytes":0,
                "p50LatencyMs":0,
                "p95LatencyMs":0,
                "p99LatencyMs":0,
                "maxLatencyMs":0,
                "ioOps":0,
                "schedOps":0,
                "confidence":0.8
            }),
            notes: "Aggregate metrics consumed by top/diff/explain/shrink flows."
                .to_string(),
        },
    );
    profile_artifact_schemas.insert(
        "symbols.json",
        ProfileArtifactSchema {
            schema_version: "fozzy.profile_symbols.v1",
            required_fields: vec!["schemaVersion", "runId", "modules"],
            optional_fields: vec![],
            example: serde_json::json!({
                "schemaVersion":"fozzy.profile_symbols.v1",
                "runId":"run-id",
                "modules":[{"name":"fozzy-runtime","buildId":"0.1.0-dev","symbols":["trace_event"]}]
            }),
            notes:
                "Symbol map for profile exports; module/symbol lists are deterministically ordered."
                    .to_string(),
        },
    );

    SchemaDoc {
        schema_version: "fozzy.schema_doc.v4".to_string(),
        file_variants: vec![
            FileVariant {
                name: "steps",
                required_top_level_keys: vec!["version", "name", "steps"],
                minimal_example: serde_json::json!({
                    "version": 1,
                    "name": "example",
                    "steps": [
                        { "type": "trace_event", "name": "setup" },
                        { "type": "assert_eq_int", "a": 1, "b": 1 }
                    ]
                }),
            },
            FileVariant {
                name: "distributed",
                required_top_level_keys: vec!["version", "name", "distributed"],
                minimal_example: serde_json::json!({
                    "version": 1,
                    "name": "distributed-example",
                    "distributed": {
                        "node_count": 3,
                        "steps": [
                            { "type": "client_put", "node": "n0", "key": "k", "value": "v" },
                            { "type": "tick", "duration": "10ms" }
                        ],
                        "invariants": [
                            { "type": "kv_present_on_all", "key": "k" }
                        ]
                    }
                }),
            },
            FileVariant {
                name: "suites",
                required_top_level_keys: vec!["version", "name", "suites"],
                minimal_example: serde_json::json!({
                    "version": 1,
                    "name": "suites-placeholder",
                    "suites": {}
                }),
            },
        ],
        step_types,
        distributed_step_types,
        distributed_invariant_types,
        step_schemas,
        distributed_step_schemas,
        distributed_invariant_schemas,
        profile_output_schemas,
        profile_artifact_schemas,
        profile_compatibility_policy: "No backwards compatibility: profiler artifact consumers must require exact schemaVersion matches and reject unknown/older versions in production.".to_string(),
    }
}
