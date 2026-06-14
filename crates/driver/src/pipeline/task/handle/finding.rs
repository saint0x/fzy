use super::*;

#[derive(Debug, Clone)]
pub(crate) struct TaskHandleFinding {
    pub(crate) function: String,
    pub(crate) handle: String,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
    pub(crate) help: String,
}

#[path = "finding/expr.rs"]
mod expr;
#[path = "finding/scan.rs"]
mod scan;
#[path = "finding/stmt.rs"]
mod stmt;

pub(crate) use self::scan::collect_task_handle_findings;
