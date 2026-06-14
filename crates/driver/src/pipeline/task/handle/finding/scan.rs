use super::*;

pub(crate) fn collect_task_handle_findings(
    function: &hir::TypedFunction,
    terminal_param_summaries: &BTreeMap<String, BTreeMap<usize, String>>,
) -> Vec<TaskHandleFinding> {
    let mut started = BTreeMap::<String, String>::new();
    let mut terminal = BTreeMap::<String, Vec<String>>::new();
    let mut findings = Vec::new();
    for stmt in &function.body {
        super::stmt::collect_task_handle_finding_stmt(
            stmt,
            &function.name,
            &mut started,
            &mut terminal,
            &mut findings,
            terminal_param_summaries,
        );
    }
    for (handle, origin) in started {
        if !terminal.contains_key(&handle) {
            findings.push(TaskHandleFinding {
                function: function.name.clone(),
                handle: handle.clone(),
                kind: "task_handle_missing_terminal",
                message: format!(
                    "task handle `{handle}` is created by `{origin}` and exits `{}` without `join`, `detach`, or `cancel_task`",
                    function.name
                ),
                help: "Terminate every task handle exactly once with `join`, `detach`, or `cancel_task` before the function exits."
                    .to_string(),
            });
        }
    }
    findings
}
