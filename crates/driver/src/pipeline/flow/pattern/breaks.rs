pub(crate) fn body_contains_break_at_depth(body: &[ast::Stmt], depth: usize) -> bool {
    body.iter()
        .any(|stmt| stmt_contains_break_at_depth(stmt, depth))
}

pub(crate) fn stmt_contains_break_at_depth(stmt: &ast::Stmt, depth: usize) -> bool {
    match stmt {
        ast::Stmt::Break(_) => depth == 0,
        ast::Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_contains_break_at_depth(then_body, depth)
                || body_contains_break_at_depth(else_body, depth)
        }
        ast::Stmt::While { body, .. }
        | ast::Stmt::For { body, .. }
        | ast::Stmt::ForIn { body, .. }
        | ast::Stmt::Loop { body } => body_contains_break_at_depth(body, depth + 1),
        ast::Stmt::Match { .. }
        | ast::Stmt::Continue
        | ast::Stmt::Return(_)
        | ast::Stmt::Defer(_)
        | ast::Stmt::Requires(_)
        | ast::Stmt::Ensures(_)
        | ast::Stmt::Expr(_)
        | ast::Stmt::Let { .. }
        | ast::Stmt::LetPattern { .. }
        | ast::Stmt::Assign { .. }
        | ast::Stmt::CompoundAssign { .. } => false,
    }
}
