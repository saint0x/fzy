use super::*;

pub(crate) fn collect_gpu_event_findings(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<GpuEventFinding> {
    let mut started = BTreeMap::<String, String>::new();
    let mut terminal = BTreeMap::<String, Vec<String>>::new();
    let mut wait_bounds = BTreeMap::<String, Vec<bool>>::new();
    let mut findings = Vec::new();
    let mut timeout_active = false;
    for stmt in &function.body {
        crate::pipeline::task::event::finding::stmt::collect_gpu_event_finding_stmt(
            stmt,
            function,
            &mut started,
            &mut terminal,
            &mut wait_bounds,
            &mut findings,
            &mut timeout_active,
            terminal_param_summaries,
        );
    }
    for (event, origin) in started {
        match terminal.get(&event) {
            None => findings.push(GpuEventFinding {
                function: function.name.clone(),
                event: event.clone(),
                kind: "gpu_event_missing_terminal",
                message: format!(
                    "gpu event `{event}` is created by `{origin}` and exits `{}` without `gpu.wait` or `gpu.wait_async`",
                    function.name
                ),
                help: "Terminate every GPU launch event exactly once with `gpu.wait(...)` or `await gpu.wait_async(...)` before the function exits."
                    .to_string(),
            }),
            Some(ops) if ops.len() > 1 => findings.push(GpuEventFinding {
                function: function.name.clone(),
                event: event.clone(),
                kind: "gpu_event_double_terminal",
                message: format!(
                    "gpu event `{event}` is already terminated by `{}` and later consumed again by `{}`",
                    ops[0], ops[1]
                ),
                help: "Consume each GPU event exactly once and remove the later wait."
                    .to_string(),
            }),
            Some(_) if function_requires_bounded_runtime_waits(function)
                && wait_bounds
                    .get(&event)
                    .is_some_and(|bounds| bounds.iter().any(|bounded| !bounded)) =>
            {
                findings.push(GpuEventFinding {
                    function: function.name.clone(),
                    event: event.clone(),
                    kind: "gpu_event_unbounded_wait",
                    message: format!(
                        "gpu event `{event}` in `{}` reaches `gpu.wait`/`gpu.wait_async` without a task-local timeout/deadline bound",
                        function.name
                    ),
                    help: "Add `timeout(...)` or `deadline(...)` before waiting on the GPU event so async cancellation and pending launch cleanup stay bounded."
                        .to_string(),
                });
            }
            _ => {}
        }
    }
    findings
}
