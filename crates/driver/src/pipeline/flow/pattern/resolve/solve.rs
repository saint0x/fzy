use super::template::{extract_terminal_return_expr, substitute_pattern_source_template};
use super::*;

pub(crate) fn resolve_pattern_source_expr(
    expr: &ast::Expr,
    known_values: &HashMap<String, ast::Expr>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
    variant_tags: &HashMap<String, i32>,
) -> Option<ast::Expr> {
    resolve_inner(
        expr,
        known_values,
        pattern_source_functions,
        variant_tags,
        0,
    )
}

fn resolve_pattern_source_function_call(
    function: &PatternSourceFunction,
    args: &[ast::Expr],
    known_values: &HashMap<String, ast::Expr>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
    variant_tags: &HashMap<String, i32>,
    depth: usize,
) -> Option<ast::Expr> {
    if function.params.len() != args.len() || depth > 32 {
        return None;
    }
    let mut env = function
        .params
        .iter()
        .cloned()
        .zip(args.iter().cloned())
        .collect::<HashMap<_, _>>();
    for stmt in &function.body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                let expanded = substitute_pattern_source_template(value, &env);
                env.insert(name.clone(), expanded);
            }
            ast::Stmt::Assign { target, value } => {
                let expanded = substitute_pattern_source_template(value, &env);
                env.insert(target.clone(), expanded);
            }
            ast::Stmt::Return(Some(expr)) => {
                let expanded = substitute_pattern_source_template(expr, &env);
                return Some(expanded);
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let expanded_condition = substitute_pattern_source_template(condition, &env);
                let condition = eval_resolved_scalar_expr(
                    &expanded_condition,
                    &env,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                let branch = match condition {
                    ast::Expr::Bool(true) => then_body,
                    ast::Expr::Bool(false) => else_body,
                    ast::Expr::Int(value) => {
                        if value != 0 {
                            then_body
                        } else {
                            else_body
                        }
                    }
                    _ => return None,
                };
                if let Some(value) = resolve_pattern_source_stmt_branch(
                    branch,
                    &env,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                ) {
                    return Some(value);
                }
            }
            _ => {}
        }
    }
    extract_terminal_return_expr(&function.body)
        .map(|expr| substitute_pattern_source_template(expr, &env))
        .and_then(|expr| {
            resolve_inner(
                &expr,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
            .or(Some(expr))
        })
}

fn resolve_pattern_source_stmt_branch(
    body: &[ast::Stmt],
    parent_env: &HashMap<String, ast::Expr>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
    variant_tags: &HashMap<String, i32>,
    depth: usize,
) -> Option<ast::Expr> {
    if depth > 32 {
        return None;
    }
    let mut env = parent_env.clone();
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                env.insert(
                    name.clone(),
                    substitute_pattern_source_template(value, &env),
                );
            }
            ast::Stmt::Assign { target, value } => {
                env.insert(
                    target.clone(),
                    substitute_pattern_source_template(value, &env),
                );
            }
            ast::Stmt::Return(Some(expr)) => {
                return Some(substitute_pattern_source_template(expr, &env));
            }
            ast::Stmt::Expr(expr) => {
                if let Some(resolved) = resolve_inner(
                    &substitute_pattern_source_template(expr, &env),
                    &env,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                ) {
                    if matches!(
                        resolved,
                        ast::Expr::Tuple(_)
                            | ast::Expr::StructInit { .. }
                            | ast::Expr::EnumInit { .. }
                    ) {
                        return Some(resolved);
                    }
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let condition = substitute_pattern_source_template(condition, &env);
                let condition = eval_resolved_scalar_expr(
                    &condition,
                    &env,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                let branch = match condition {
                    ast::Expr::Bool(true) => then_body,
                    ast::Expr::Bool(false) => else_body,
                    ast::Expr::Int(value) => {
                        if value != 0 {
                            then_body
                        } else {
                            else_body
                        }
                    }
                    _ => return None,
                };
                return resolve_pattern_source_stmt_branch(
                    branch,
                    &env,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                );
            }
            _ => return None,
        }
    }
    None
}

fn eval_resolved_scalar_expr(
    expr: &ast::Expr,
    known_values: &HashMap<String, ast::Expr>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
    variant_tags: &HashMap<String, i32>,
    depth: usize,
) -> Option<ast::Expr> {
    if depth > 32 {
        return None;
    }
    match expr {
        ast::Expr::Int(_) | ast::Expr::Bool(_) => Some(expr.clone()),
        ast::Expr::Group(inner) => eval_resolved_scalar_expr(
            inner,
            known_values,
            pattern_source_functions,
            variant_tags,
            depth + 1,
        ),
        ast::Expr::Ident(name) => {
            let value = known_values.get(name)?;
            eval_resolved_scalar_expr(
                value,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
        }
        ast::Expr::Call { callee, args } => {
            let function = pattern_source_functions.get(callee)?;
            if function.params.len() != args.len() {
                return None;
            }
            if let Some(resolved) = resolve_pattern_source_function_call(
                function,
                args,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            ) {
                return eval_resolved_scalar_expr(
                    &resolved,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                );
            }
            let params = &function.params;
            let template = extract_terminal_return_expr(&function.body)?;
            let bindings = params
                .iter()
                .cloned()
                .zip(args.iter().cloned())
                .collect::<HashMap<_, _>>();
            let expanded = substitute_pattern_source_template(template, &bindings);
            eval_resolved_scalar_expr(
                &expanded,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
        }
        ast::Expr::FieldAccess { base, field } => {
            let resolved_base = resolve_inner(
                base,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            let field_expr = resolve_field_expr(&resolved_base, field)?;
            eval_resolved_scalar_expr(
                &field_expr,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
        }
        ast::Expr::Unary { op, expr } => {
            let value = eval_resolved_scalar_expr(
                expr,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            match (op, value) {
                (ast::UnaryOp::Not, ast::Expr::Bool(value)) => Some(ast::Expr::Bool(!value)),
                (ast::UnaryOp::Not, ast::Expr::Int(value)) => Some(ast::Expr::Bool(value == 0)),
                (ast::UnaryOp::Neg, ast::Expr::Int(value)) => Some(ast::Expr::Int(-value)),
                (ast::UnaryOp::Plus, ast::Expr::Int(value)) => Some(ast::Expr::Int(value)),
                _ => None,
            }
        }
        ast::Expr::Binary { op, left, right } => {
            let left = eval_resolved_scalar_expr(
                left,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            let right = eval_resolved_scalar_expr(
                right,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            match (op, left, right) {
                (ast::BinaryOp::Add, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Int(a + b))
                }
                (ast::BinaryOp::Sub, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Int(a - b))
                }
                (ast::BinaryOp::Mul, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Int(a * b))
                }
                (ast::BinaryOp::Div, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    (b != 0).then_some(ast::Expr::Int(a / b))
                }
                (ast::BinaryOp::Mod, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    (b != 0).then_some(ast::Expr::Int(a % b))
                }
                (ast::BinaryOp::Eq, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Bool(a == b))
                }
                (ast::BinaryOp::Neq, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Bool(a != b))
                }
                (ast::BinaryOp::Lt, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Bool(a < b))
                }
                (ast::BinaryOp::Lte, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Bool(a <= b))
                }
                (ast::BinaryOp::Gt, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Bool(a > b))
                }
                (ast::BinaryOp::Gte, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                    Some(ast::Expr::Bool(a >= b))
                }
                (ast::BinaryOp::Eq, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                    Some(ast::Expr::Bool(a == b))
                }
                (ast::BinaryOp::Neq, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                    Some(ast::Expr::Bool(a != b))
                }
                (ast::BinaryOp::And, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                    Some(ast::Expr::Bool(a && b))
                }
                (ast::BinaryOp::Or, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                    Some(ast::Expr::Bool(a || b))
                }
                _ => None,
            }
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let condition = eval_resolved_scalar_expr(
                condition,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            match condition {
                ast::Expr::Bool(true) => eval_resolved_scalar_expr(
                    then_expr,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                ),
                ast::Expr::Bool(false) => eval_resolved_scalar_expr(
                    else_expr,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                ),
                ast::Expr::Int(value) => {
                    let branch = if value != 0 { then_expr } else { else_expr };
                    eval_resolved_scalar_expr(
                        branch,
                        known_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    )
                }
                _ => None,
            }
        }
        ast::Expr::Match { scrutinee, arms } => {
            let resolved_scrutinee = resolve_inner(
                scrutinee,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
            .or_else(|| {
                eval_resolved_scalar_expr(
                    scrutinee,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            })?;
            for arm in arms {
                if !pattern_matches_resolved_scrutinee(
                    &arm.pattern,
                    &resolved_scrutinee,
                    variant_tags,
                ) {
                    continue;
                }
                let mut guard_values = known_values.clone();
                if let Ok(binding_stmts) =
                    bindings_for_match_arm_pattern(&arm.pattern, &resolved_scrutinee, variant_tags)
                {
                    for stmt in binding_stmts {
                        if let ast::Stmt::Let { name, value, .. } = stmt {
                            guard_values.insert(name, value);
                        }
                    }
                }
                if let Some(guard) = &arm.guard {
                    let Some(guard_value) = eval_resolved_scalar_expr(
                        guard,
                        &guard_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    ) else {
                        continue;
                    };
                    match guard_value {
                        ast::Expr::Bool(true) => {}
                        ast::Expr::Int(value) if value != 0 => {}
                        _ => continue,
                    }
                }
                return eval_resolved_scalar_expr(
                    &arm.value,
                    &guard_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                );
            }
            None
        }
        _ => None,
    }
}

fn resolve_inner(
    expr: &ast::Expr,
    known_values: &HashMap<String, ast::Expr>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
    variant_tags: &HashMap<String, i32>,
    depth: usize,
) -> Option<ast::Expr> {
    if depth > 32 {
        return None;
    }
    match expr {
        ast::Expr::EnumInit { .. } | ast::Expr::StructInit { .. } | ast::Expr::Tuple(_) => {
            Some(expr.clone())
        }
        ast::Expr::Group(inner) => resolve_inner(
            inner,
            known_values,
            pattern_source_functions,
            variant_tags,
            depth + 1,
        ),
        ast::Expr::Ident(name) => known_values.get(name).and_then(|value| {
            resolve_inner(
                value,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
        }),
        ast::Expr::Call { callee, args } => {
            let function = pattern_source_functions.get(callee)?;
            let resolved = resolve_pattern_source_function_call(
                function,
                args,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            resolve_inner(
                &resolved,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
        }
        ast::Expr::FieldAccess { base, field } => {
            let resolved_base = resolve_inner(
                base,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            let field_expr = resolve_field_expr(&resolved_base, field)?;
            resolve_inner(
                &field_expr,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
            .or(Some(field_expr))
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let condition = eval_resolved_scalar_expr(
                condition,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )?;
            let branch = match condition {
                ast::Expr::Bool(true) => then_expr,
                ast::Expr::Bool(false) => else_expr,
                ast::Expr::Int(value) => {
                    if value != 0 {
                        then_expr
                    } else {
                        else_expr
                    }
                }
                _ => return None,
            };
            resolve_inner(
                branch,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
        }
        ast::Expr::Match { scrutinee, arms } => {
            let resolved_scrutinee = resolve_inner(
                scrutinee,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            )
            .or_else(|| {
                eval_resolved_scalar_expr(
                    scrutinee,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            })?;
            for arm in arms {
                if !pattern_matches_resolved_scrutinee(
                    &arm.pattern,
                    &resolved_scrutinee,
                    variant_tags,
                ) {
                    continue;
                }
                let mut arm_values = known_values.clone();
                if let Ok(binding_stmts) =
                    bindings_for_match_arm_pattern(&arm.pattern, &resolved_scrutinee, variant_tags)
                {
                    for stmt in binding_stmts {
                        if let ast::Stmt::Let { name, value, .. } = stmt {
                            arm_values.insert(name, value);
                        }
                    }
                }
                if let Some(guard) = &arm.guard {
                    let guard = eval_resolved_scalar_expr(
                        guard,
                        &arm_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    )?;
                    match guard {
                        ast::Expr::Bool(true) => {}
                        ast::Expr::Int(value) if value != 0 => {}
                        _ => continue,
                    }
                }
                return resolve_inner(
                    &arm.value,
                    &arm_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                );
            }
            None
        }
        _ => None,
    }
}
