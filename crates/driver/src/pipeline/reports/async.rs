use super::*;

pub(super) fn build_async_safety_json(fir: &fir::FirModule) -> serde_json::Value {
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
            (count > 0).then(|| {
                serde_json::json!({
                    "function": function.name,
                    "awaits": count,
                })
            })
        })
        .collect::<Vec<_>>();
    let task_transfers = fir
        .typed_functions
        .iter()
        .flat_map(|function| collect_task_transfer_events(function))
        .collect::<Vec<_>>();
    let borrow_crossings = fir
        .reference_lifetime_violations
        .iter()
        .filter(|detail| detail.contains("await"))
        .map(|detail| serde_json::json!({ "detail": detail }))
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
            collect_task_group_policy_events(function, &task_group_terminal_param_summaries)
        })
        .collect::<Vec<_>>();
    let task_group_findings = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_task_group_findings(function, &task_group_terminal_param_summaries)
        })
        .map(|finding| {
            serde_json::json!({
                "function": finding.function,
                "group": finding.binding,
                "kind": finding.kind,
                "severity": "error",
                "message": finding.message,
                "help": finding.help,
            })
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
        .map(|finding| {
            serde_json::json!({
                "function": finding.function,
                "handle": finding.handle,
                "kind": finding.kind,
                "severity": "error",
                "message": finding.message,
                "help": finding.help,
            })
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
            collect_gpu_event_policy_events(function, &gpu_event_terminal_param_summaries)
        })
        .collect::<Vec<_>>();
    let gpu_event_findings = fir
        .typed_functions
        .iter()
        .flat_map(|function| {
            collect_gpu_event_findings(function, &gpu_event_terminal_param_summaries)
        })
        .map(|finding| {
            serde_json::json!({
                "function": finding.function,
                "event": finding.event,
                "kind": finding.kind,
                "severity": "error",
                "message": finding.message,
                "help": finding.help,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "schemaVersion": "fozzylang.async_safety.v1",
        "versions": super::compat::compatibility_versions_json(),
        "strictRequirements": {
            "spawnOwnedSendSafe": true,
            "taskHandleTerminalPolicy": true,
            "taskGroupTerminalPolicy": true,
            "gpuEventTerminalPolicy": true,
            "taskResultAfterTerminal": false,
            "cancelledTasksCleanResources": true,
            "boundedRuntimeWaits": true,
            "timeoutDeadlineScope": "task_local",
            "referencesAcrossTaskBoundary": "forbidden",
        },
        "cancellationModel": {
            "timeoutDeadlineScope": "task_local",
            "cancelTaskCleanup": "join_and_cleanup",
            "taskGroupCancelCleanup": "join_and_cleanup",
            "gpuEventCancellation": "deadline_bound_wait_then_cleanup",
        },
        "stateMachine": {
            "taskHandleStates": ["active", "joined", "detached", "cancelled", "invalid_multiple_terminal", "invalid_result_after_terminal", "missing_terminal"],
            "taskGroupStates": ["active", "joined", "joined_all", "cancelled", "invalid_multiple_terminal", "missing_terminal"],
            "gpuEventStates": ["pending", "waited", "invalid_multiple_terminal", "missing_terminal"],
            "taskHandleTerminalOperations": ["join", "detach", "cancel_task"],
            "taskGroupTerminalOperations": ["task.group_join", "task.group_join_all", "task.group_cancel"],
            "gpuEventTerminalOperations": ["gpu.wait", "gpu.wait_async"],
            "taskResultPolicy": {
                "beforeTerminal": "allowed",
                "afterTerminal": "forbidden",
            },
        },
        "async_functions": async_functions,
        "await_boundaries": await_boundaries,
        "task_transfers": task_transfers,
        "borrow_crossings": borrow_crossings,
        "runtime_wait_policies": runtime_wait_policies,
        "gpu_event_policies": gpu_event_policies,
        "gpu_event_findings": gpu_event_findings,
        "task_handle_policies": task_handle_policies,
        "task_handle_findings": task_handle_findings,
        "task_group_policies": task_group_policies,
        "task_group_findings": task_group_findings,
    })
}
