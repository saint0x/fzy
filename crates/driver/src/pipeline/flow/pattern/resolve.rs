use super::*;

#[path = "resolve/solve.rs"]
mod solve;
#[path = "resolve/template.rs"]
mod template;

pub(crate) use self::solve::resolve_pattern_source_expr;
