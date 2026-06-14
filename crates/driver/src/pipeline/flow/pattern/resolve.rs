use super::*;

#[path = "resolve/template.rs"]
mod template;
#[path = "resolve/solve.rs"]
mod solve;

pub(crate) use self::solve::resolve_pattern_source_expr;
