use super::*;

pub(super) fn extract_terminal_return_expr(body: &[ast::Stmt]) -> Option<&ast::Expr> {
    body.iter().rev().find_map(|stmt| match stmt {
        ast::Stmt::Return(Some(expr)) => Some(expr),
        _ => None,
    })
}

pub(super) fn substitute_pattern_source_template(
    expr: &ast::Expr,
    bindings: &HashMap<String, ast::Expr>,
) -> ast::Expr {
    match expr {
        ast::Expr::Ident(name) => bindings
            .get(name)
            .cloned()
            .unwrap_or_else(|| ast::Expr::Ident(name.clone())),
        ast::Expr::Call { callee, args } => ast::Expr::Call {
            callee: callee.clone(),
            args: args
                .iter()
                .map(|arg| substitute_pattern_source_template(arg, bindings))
                .collect(),
        },
        ast::Expr::FieldAccess { base, field } => ast::Expr::FieldAccess {
            base: Box::new(substitute_pattern_source_template(base, bindings)),
            field: field.clone(),
        },
        ast::Expr::StructInit { name, fields } => ast::Expr::StructInit {
            name: name.clone(),
            fields: fields
                .iter()
                .map(|(field, value)| {
                    (
                        field.clone(),
                        substitute_pattern_source_template(value, bindings),
                    )
                })
                .collect(),
        },
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => ast::Expr::EnumInit {
            enum_name: enum_name.clone(),
            variant: variant.clone(),
            payload: payload
                .iter()
                .map(|value| substitute_pattern_source_template(value, bindings))
                .collect(),
            named_payload: named_payload
                .iter()
                .map(|(field, value)| {
                    (
                        field.clone(),
                        substitute_pattern_source_template(value, bindings),
                    )
                })
                .collect(),
        },
        ast::Expr::Group(inner) => ast::Expr::Group(Box::new(substitute_pattern_source_template(
            inner, bindings,
        ))),
        ast::Expr::Tuple(items) => ast::Expr::Tuple(
            items
                .iter()
                .map(|item| substitute_pattern_source_template(item, bindings))
                .collect(),
        ),
        ast::Expr::Await(inner) => ast::Expr::Await(Box::new(substitute_pattern_source_template(
            inner, bindings,
        ))),
        ast::Expr::Discard(inner) => ast::Expr::Discard(Box::new(
            substitute_pattern_source_template(inner, bindings),
        )),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => ast::Expr::TryCatch {
            try_expr: Box::new(substitute_pattern_source_template(try_expr, bindings)),
            catch_expr: Box::new(substitute_pattern_source_template(catch_expr, bindings)),
        },
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => ast::Expr::If {
            condition: Box::new(substitute_pattern_source_template(condition, bindings)),
            then_expr: Box::new(substitute_pattern_source_template(then_expr, bindings)),
            else_expr: Box::new(substitute_pattern_source_template(else_expr, bindings)),
        },
        ast::Expr::Match { scrutinee, arms } => ast::Expr::Match {
            scrutinee: Box::new(substitute_pattern_source_template(scrutinee, bindings)),
            arms: arms
                .iter()
                .map(|arm| ast::MatchArm {
                    pattern: arm.pattern.clone(),
                    guard: arm
                        .guard
                        .as_ref()
                        .map(|guard| substitute_pattern_source_template(guard, bindings)),
                    returns: arm.returns,
                    value: substitute_pattern_source_template(&arm.value, bindings),
                })
                .collect(),
        },
        ast::Expr::Range {
            start,
            end,
            inclusive,
        } => ast::Expr::Range {
            start: Box::new(substitute_pattern_source_template(start, bindings)),
            end: Box::new(substitute_pattern_source_template(end, bindings)),
            inclusive: *inclusive,
        },
        ast::Expr::ArrayLiteral(items) => ast::Expr::ArrayLiteral(
            items
                .iter()
                .map(|item| substitute_pattern_source_template(item, bindings))
                .collect(),
        ),
        ast::Expr::ObjectLiteral(fields) => ast::Expr::ObjectLiteral(
            fields
                .iter()
                .map(|(field, value)| {
                    (
                        field.clone(),
                        substitute_pattern_source_template(value, bindings),
                    )
                })
                .collect(),
        ),
        ast::Expr::Index { base, index } => ast::Expr::Index {
            base: Box::new(substitute_pattern_source_template(base, bindings)),
            index: Box::new(substitute_pattern_source_template(index, bindings)),
        },
        ast::Expr::Unary { op, expr } => ast::Expr::Unary {
            op: *op,
            expr: Box::new(substitute_pattern_source_template(expr, bindings)),
        },
        ast::Expr::Binary { op, left, right } => ast::Expr::Binary {
            op: *op,
            left: Box::new(substitute_pattern_source_template(left, bindings)),
            right: Box::new(substitute_pattern_source_template(right, bindings)),
        },
        ast::Expr::Closure {
            params,
            return_type,
            body,
        } => ast::Expr::Closure {
            params: params.clone(),
            return_type: return_type.clone(),
            body: body.clone(),
        },
        ast::Expr::UnsafeBlock { body, meta } => ast::Expr::UnsafeBlock {
            body: body.clone(),
            meta: meta.clone(),
        },
        ast::Expr::While { condition, body } => ast::Expr::While {
            condition: Box::new(substitute_pattern_source_template(condition, bindings)),
            body: body.clone(),
        },
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => ast::Expr::For {
            init: init.clone(),
            condition: condition
                .as_ref()
                .map(|value| Box::new(substitute_pattern_source_template(value, bindings))),
            step: step.clone(),
            body: body.clone(),
        },
        ast::Expr::ForIn {
            binding,
            iterable,
            body,
        } => ast::Expr::ForIn {
            binding: binding.clone(),
            iterable: Box::new(substitute_pattern_source_template(iterable, bindings)),
            body: body.clone(),
        },
        ast::Expr::Loop { body } => ast::Expr::Loop { body: body.clone() },
        ast::Expr::Break(value) => ast::Expr::Break(
            value
                .as_ref()
                .map(|value| Box::new(substitute_pattern_source_template(value, bindings))),
        ),
        ast::Expr::Return(value) => ast::Expr::Return(
            value
                .as_ref()
                .map(|value| Box::new(substitute_pattern_source_template(value, bindings))),
        ),
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Continue => expr.clone(),
    }
}
