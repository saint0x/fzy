use super::*;

#[derive(Debug, Clone, serde::Serialize)]
struct CompatibilityVersions {
    #[serde(rename = "languageVersion")]
    language_version: String,
    #[serde(rename = "traceSchemaVersion")]
    trace_schema_version: String,
    #[serde(rename = "manifestSchemaVersion")]
    manifest_schema_version: String,
    #[serde(rename = "runtimeAbiVersion")]
    runtime_abi_version: String,
    #[serde(rename = "nativeImportTableVersion")]
    native_import_table_version: String,
    #[serde(rename = "diagnosticCatalogVersion")]
    diagnostic_catalog_version: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AsyncSafetyStrictRequirements {
    #[serde(rename = "spawnOwnedSendSafe")]
    spawn_owned_send_safe: bool,
    #[serde(rename = "taskHandleTerminalPolicy")]
    task_handle_terminal_policy: bool,
    #[serde(rename = "taskGroupTerminalPolicy")]
    task_group_terminal_policy: bool,
    #[serde(rename = "gpuEventTerminalPolicy")]
    gpu_event_terminal_policy: bool,
    #[serde(rename = "taskResultAfterTerminal")]
    task_result_after_terminal: bool,
    #[serde(rename = "cancelledTasksCleanResources")]
    cancelled_tasks_clean_resources: bool,
    #[serde(rename = "boundedRuntimeWaits")]
    bounded_runtime_waits: bool,
    #[serde(rename = "timeoutDeadlineScope")]
    timeout_deadline_scope: &'static str,
    #[serde(rename = "referencesAcrossTaskBoundary")]
    references_across_task_boundary: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AsyncSafetyCancellationModel {
    #[serde(rename = "timeoutDeadlineScope")]
    timeout_deadline_scope: &'static str,
    #[serde(rename = "cancelTaskCleanup")]
    cancel_task_cleanup: &'static str,
    #[serde(rename = "taskGroupCancelCleanup")]
    task_group_cancel_cleanup: &'static str,
    #[serde(rename = "gpuEventCancellation")]
    gpu_event_cancellation: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct TaskResultPolicy {
    #[serde(rename = "beforeTerminal")]
    before_terminal: &'static str,
    #[serde(rename = "afterTerminal")]
    after_terminal: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AsyncSafetyStateMachine {
    #[serde(rename = "taskHandleStates")]
    task_handle_states: Vec<&'static str>,
    #[serde(rename = "taskGroupStates")]
    task_group_states: Vec<&'static str>,
    #[serde(rename = "gpuEventStates")]
    gpu_event_states: Vec<&'static str>,
    #[serde(rename = "taskHandleTerminalOperations")]
    task_handle_terminal_operations: Vec<&'static str>,
    #[serde(rename = "taskGroupTerminalOperations")]
    task_group_terminal_operations: Vec<&'static str>,
    #[serde(rename = "gpuEventTerminalOperations")]
    gpu_event_terminal_operations: Vec<&'static str>,
    #[serde(rename = "taskResultPolicy")]
    task_result_policy: TaskResultPolicy,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AwaitBoundaryRecord {
    function: String,
    awaits: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BorrowCrossingRecord {
    detail: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct TaskGroupFindingRecord {
    function: String,
    #[serde(rename = "group")]
    binding: String,
    kind: &'static str,
    severity: &'static str,
    message: String,
    help: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct TaskHandleFindingRecord {
    function: String,
    handle: String,
    kind: &'static str,
    severity: &'static str,
    message: String,
    help: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct GpuEventFindingRecord {
    function: String,
    event: String,
    kind: &'static str,
    severity: &'static str,
    message: String,
    help: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AsyncSafetyReport {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    versions: CompatibilityVersions,
    #[serde(rename = "strictRequirements")]
    strict_requirements: AsyncSafetyStrictRequirements,
    #[serde(rename = "cancellationModel")]
    cancellation_model: AsyncSafetyCancellationModel,
    #[serde(rename = "stateMachine")]
    state_machine: AsyncSafetyStateMachine,
    async_functions: Vec<String>,
    await_boundaries: Vec<AwaitBoundaryRecord>,
    task_transfers: Vec<TaskTransferEvent>,
    borrow_crossings: Vec<BorrowCrossingRecord>,
    runtime_wait_policies: Vec<AsyncRuntimeWaitPolicy>,
    gpu_event_policies: Vec<GpuEventPolicyRecord>,
    gpu_event_findings: Vec<GpuEventFindingRecord>,
    task_handle_policies: Vec<TaskHandlePolicyRecord>,
    task_handle_findings: Vec<TaskHandleFindingRecord>,
    task_group_policies: Vec<TaskGroupPolicyRecord>,
    task_group_findings: Vec<TaskGroupFindingRecord>,
}

fn compatibility_versions() -> CompatibilityVersions {
    let compatibility = fzscenario::compatibility_info();
    CompatibilityVersions {
        language_version: compatibility.language_version,
        trace_schema_version: compatibility.trace_schema_version,
        manifest_schema_version: compatibility.manifest_schema_version,
        runtime_abi_version: compatibility.runtime_abi_version,
        native_import_table_version: compatibility.native_import_table_version,
        diagnostic_catalog_version: compatibility.diagnostic_catalog_version,
    }
}

fn strict_requirements() -> AsyncSafetyStrictRequirements {
    AsyncSafetyStrictRequirements {
        spawn_owned_send_safe: true,
        task_handle_terminal_policy: true,
        task_group_terminal_policy: true,
        gpu_event_terminal_policy: true,
        task_result_after_terminal: false,
        cancelled_tasks_clean_resources: true,
        bounded_runtime_waits: true,
        timeout_deadline_scope: "task_local",
        references_across_task_boundary: "forbidden",
    }
}

fn cancellation_model() -> AsyncSafetyCancellationModel {
    AsyncSafetyCancellationModel {
        timeout_deadline_scope: "task_local",
        cancel_task_cleanup: "join_and_cleanup",
        task_group_cancel_cleanup: "join_and_cleanup",
        gpu_event_cancellation: "deadline_bound_wait_then_cleanup",
    }
}

fn state_machine() -> AsyncSafetyStateMachine {
    AsyncSafetyStateMachine {
        task_handle_states: vec![
            "active",
            "joined",
            "detached",
            "cancelled",
            "invalid_multiple_terminal",
            "invalid_result_after_terminal",
            "missing_terminal",
        ],
        task_group_states: vec![
            "active",
            "joined",
            "joined_all",
            "cancelled",
            "invalid_multiple_terminal",
            "missing_terminal",
        ],
        gpu_event_states: vec![
            "pending",
            "waited",
            "invalid_multiple_terminal",
            "missing_terminal",
        ],
        task_handle_terminal_operations: vec!["join", "detach", "cancel_task"],
        task_group_terminal_operations: vec![
            "task.group_join",
            "task.group_join_all",
            "task.group_cancel",
        ],
        gpu_event_terminal_operations: vec!["gpu.wait", "gpu.wait_async"],
        task_result_policy: TaskResultPolicy {
            before_terminal: "allowed",
            after_terminal: "forbidden",
        },
    }
}

fn build_async_safety_report(fir: &fir::FirModule) -> AsyncSafetyReport {
    let async_functions = fir
        .typed_functions
        .iter()
        .filter(|function| function.is_async)
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();
    let await_boundaries = fir
        .typed_functions
        .iter()
        .filter_map(|function| {
            let count = count_awaits_in_stmts(&function.body);
            (count > 0).then(|| AwaitBoundaryRecord {
                function: function.name.clone(),
                awaits: count,
            })
        })
        .collect::<Vec<_>>();
    let task_transfers = fir
        .typed_functions
        .iter()
        .flat_map(collect_task_transfer_events)
        .collect::<Vec<_>>();
    let borrow_crossings = fir
        .reference_lifetime_violations
        .iter()
        .filter(|detail| detail.contains("await"))
        .map(|detail| BorrowCrossingRecord {
            detail: detail.clone(),
        })
        .collect::<Vec<_>>();
    let task_group_terminal_param_summaries = fir
        .typed_functions
        .iter()
        .filter_map(summarize_task_group_terminal_params)
        .collect::<BTreeMap<_, _>>();
    let task_handle_terminal_param_summaries = fir
        .typed_functions
        .iter()
        .filter_map(summarize_task_handle_terminal_params)
        .collect::<BTreeMap<_, _>>();
    let gpu_event_terminal_param_summaries = fir
        .typed_functions
        .iter()
        .filter_map(summarize_gpu_event_terminal_params)
        .collect::<BTreeMap<_, _>>();
    let task_group_policies = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_task_group_policy_records(function, &task_group_terminal_param_summaries)
        })
        .collect::<Vec<_>>();
    let task_group_findings = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_task_group_findings(function, &task_group_terminal_param_summaries)
        })
        .map(|finding| TaskGroupFindingRecord {
            function: finding.function,
            binding: finding.binding,
            kind: finding.kind,
            severity: "error",
            message: finding.message,
            help: finding.help,
        })
        .collect::<Vec<_>>();
    let task_handle_policies = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_task_handle_policy_events(function, &task_handle_terminal_param_summaries)
        })
        .collect::<Vec<_>>();
    let task_handle_findings = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_task_handle_findings(function, &task_handle_terminal_param_summaries)
        })
        .map(|finding| TaskHandleFindingRecord {
            function: finding.function,
            handle: finding.handle,
            kind: finding.kind,
            severity: "error",
            message: finding.message,
            help: finding.help,
        })
        .collect::<Vec<_>>();
    let runtime_wait_policies = fir
        .typed_functions
        .iter()
        .flat_map(collect_async_runtime_wait_policies)
        .collect::<Vec<_>>();
    let gpu_event_policies = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_gpu_event_policy_records(function, &gpu_event_terminal_param_summaries)
        })
        .collect::<Vec<_>>();
    let gpu_event_findings = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_gpu_event_findings(function, &gpu_event_terminal_param_summaries)
        })
        .map(|finding| GpuEventFindingRecord {
            function: finding.function,
            event: finding.event,
            kind: finding.kind,
            severity: "error",
            message: finding.message,
            help: finding.help,
        })
        .collect::<Vec<_>>();

    AsyncSafetyReport {
        schema_version: "fozzylang.async_safety.v1",
        versions: compatibility_versions(),
        strict_requirements: strict_requirements(),
        cancellation_model: cancellation_model(),
        state_machine: state_machine(),
        async_functions,
        await_boundaries,
        task_transfers,
        borrow_crossings,
        runtime_wait_policies,
        gpu_event_policies,
        gpu_event_findings,
        task_handle_policies,
        task_handle_findings,
        task_group_policies,
        task_group_findings,
    }
}

pub(super) fn build_async_safety_json(fir: &fir::FirModule) -> serde_json::Value {
    serde_json::to_value(build_async_safety_report(fir))
        .expect("async safety report should serialize")
}
