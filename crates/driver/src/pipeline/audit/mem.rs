use super::*;

pub(crate) fn build_handle_contracts_json() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "fozzylang.handle_contracts.v1",
        "versions": compatibility_versions_json(),
        "handles": hir::runtime_handle_contracts().iter().map(|contract| {
            serde_json::json!({
                "name": contract.name,
                "copy": contract.copy,
                "owned": contract.owned,
                "linear": contract.linear,
                "closable": contract.closable,
                "sendSafe": contract.send_safe,
                "asyncStable": contract.async_stable,
                "producerIntrinsics": contract.producer_intrinsics,
                "consumerIntrinsics": contract.consumer_intrinsics,
                "observerIntrinsics": contract.observer_intrinsics,
            })
        }).collect::<Vec<_>>(),
    })
}

pub(crate) fn collect_function_owner_artifacts(
    function: &hir::TypedFunction,
    out: &mut Vec<MemoryOwnerArtifact>,
) {
    fn create_owner(
        function_name: &str,
        binding: &str,
        created_at: String,
        next_owner_id: &mut usize,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut Vec<MemoryOwnerArtifact>,
    ) {
        let owner_id = *next_owner_id;
        *next_owner_id += 1;
        owners.insert(binding.to_string(), rows.len());
        rows.push(MemoryOwnerArtifact {
            function: function_name.to_string(),
            name: binding.to_string(),
            owner_id,
            created_at,
            terminal_state: "Owned".to_string(),
            terminal_at: None,
            transfer_edges: Vec::new(),
        });
    }

    fn mark_terminal(
        binding: &str,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut [MemoryOwnerArtifact],
        state: &str,
        at: String,
    ) {
        if let Some(index) = owners.remove(binding) {
            rows[index].terminal_state = state.to_string();
            rows[index].terminal_at = Some(at);
        }
    }

    fn scan_expr(
        function: &hir::TypedFunction,
        expr: &ast::Expr,
        next_owner_id: &mut usize,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut Vec<MemoryOwnerArtifact>,
    ) {
        match expr {
            ast::Expr::UnsafeBlock { body, .. } => {
                scan_stmts(function, body, next_owner_id, owners, rows);
            }
            ast::Expr::If {
                then_expr,
                else_expr,
                ..
            } => {
                scan_expr(function, then_expr, next_owner_id, owners, rows);
                scan_expr(function, else_expr, next_owner_id, owners, rows);
            }
            ast::Expr::Match { arms, .. } => {
                for arm in arms {
                    scan_expr(function, &arm.value, next_owner_id, owners, rows);
                }
            }
            ast::Expr::While { body, .. }
            | ast::Expr::ForIn { body, .. }
            | ast::Expr::Loop { body } => {
                scan_stmts(function, body, next_owner_id, owners, rows);
            }
            ast::Expr::For { body, .. } => {
                scan_stmts(function, body, next_owner_id, owners, rows);
            }
            _ => {}
        }
    }

    fn scan_stmts(
        function: &hir::TypedFunction,
        body: &[ast::Stmt],
        next_owner_id: &mut usize,
        owners: &mut BTreeMap<String, usize>,
        rows: &mut Vec<MemoryOwnerArtifact>,
    ) {
        for stmt in body {
            match stmt {
                ast::Stmt::Let {
                    name, value, ty, ..
                } => {
                    if let ast::Expr::Ident(from) = value {
                        if let Some(index) = owners.remove(from) {
                            rows[index]
                                .transfer_edges
                                .push(format!("let {name} = {from}"));
                            rows[index].name = name.clone();
                            owners.insert(name.clone(), index);
                            continue;
                        }
                    }
                    let binding_ty = ty.as_ref().or_else(|| function.local_types.get(name));
                    if binding_ty.is_some_and(memory_report_is_linear_type)
                        || memory_report_is_alloc_like(value)
                    {
                        create_owner(
                            &function.name,
                            name,
                            memory_report_expr_origin(value),
                            next_owner_id,
                            owners,
                            rows,
                        );
                    }
                    scan_expr(function, value, next_owner_id, owners, rows);
                }
                ast::Stmt::Assign { target, value } => {
                    if let ast::Expr::Ident(from) = value {
                        if let Some(index) = owners.remove(from) {
                            rows[index]
                                .transfer_edges
                                .push(format!("{target} = {from}"));
                            rows[index].name = target.clone();
                            owners.insert(target.clone(), index);
                        }
                    }
                    scan_expr(function, value, next_owner_id, owners, rows);
                }
                ast::Stmt::Defer(expr) => {
                    if let Some((binding, at)) = memory_report_terminal_call(expr) {
                        mark_terminal(&binding, owners, rows, "Deferred", at);
                    }
                    scan_expr(function, expr, next_owner_id, owners, rows);
                }
                ast::Stmt::Return(Some(ast::Expr::Ident(name))) => {
                    mark_terminal(name, owners, rows, "Returned", "return".to_string());
                }
                ast::Stmt::Return(Some(expr)) => {
                    scan_expr(function, expr, next_owner_id, owners, rows);
                }
                ast::Stmt::Expr(expr) => {
                    if let Some((binding, at)) = memory_report_terminal_call(expr) {
                        let state = if at.starts_with("task.group_") {
                            "Consumed"
                        } else {
                            "Consumed"
                        };
                        mark_terminal(&binding, owners, rows, state, at);
                    }
                    scan_expr(function, expr, next_owner_id, owners, rows);
                }
                ast::Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    scan_stmts(function, then_body, next_owner_id, owners, rows);
                    scan_stmts(function, else_body, next_owner_id, owners, rows);
                }
                ast::Stmt::While { body, .. }
                | ast::Stmt::ForIn { body, .. }
                | ast::Stmt::Loop { body } => {
                    scan_stmts(function, body, next_owner_id, owners, rows);
                }
                ast::Stmt::For { body, .. } => {
                    scan_stmts(function, body, next_owner_id, owners, rows);
                }
                ast::Stmt::Match { arms, .. } => {
                    for arm in arms {
                        scan_expr(function, &arm.value, next_owner_id, owners, rows);
                    }
                }
                ast::Stmt::LetPattern { value, .. }
                | ast::Stmt::CompoundAssign { value, .. }
                | ast::Stmt::Requires(value)
                | ast::Stmt::Ensures(value) => {
                    scan_expr(function, value, next_owner_id, owners, rows);
                }
                ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => {}
            }
        }
    }

    let mut next_owner_id = 1usize;
    let mut active = BTreeMap::<String, usize>::new();
    let start = out.len();
    scan_stmts(
        function,
        &function.body,
        &mut next_owner_id,
        &mut active,
        out,
    );
    for index in active.into_values() {
        if out[index].terminal_state == "Owned" {
            out[index].terminal_at = Some("function_exit".to_string());
        }
    }
    for row in &mut out[start..] {
        if row.terminal_state == "Owned"
            && row.transfer_edges.iter().any(|edge| edge.contains(" = "))
        {
            row.terminal_state = "TransferredToCaller".to_string();
        }
    }
}

pub(crate) fn memory_report_is_alloc_like(expr: &ast::Expr) -> bool {
    matches!(expr, ast::Expr::Call { callee, .. } if is_memory_phase_alloc_like_callee(callee) || callee == "task.group_begin")
}

pub(crate) fn memory_report_expr_origin(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Call { callee, .. } => callee.clone(),
        ast::Expr::Ident(name) => name.clone(),
        _ => "<expr>".to_string(),
    }
}

pub(crate) fn memory_report_is_linear_type(ty: &ast::Type) -> bool {
    match ty {
        ast::Type::Ptr { .. } => true,
        ast::Type::Named { name, .. } => {
            hir::runtime_handle_contract(name).is_some_and(|contract| contract.linear)
                || matches!(name.as_str(), "Linear" | "Resource" | "Ptr")
        }
        _ => false,
    }
}

pub(crate) fn memory_report_is_owned_handle_type(ty: &ast::Type) -> bool {
    match ty {
        ast::Type::Named { name, .. } => hir::runtime_handle_contract(name)
            .is_some_and(|contract| contract.owned && !contract.linear),
        _ => false,
    }
}

pub(crate) fn memory_report_terminal_call(expr: &ast::Expr) -> Option<(String, String)> {
    let ast::Expr::Call { callee, args } = expr else {
        return None;
    };
    let binding = match args.first() {
        Some(ast::Expr::Ident(name)) => name.clone(),
        Some(ast::Expr::Group(inner)) => match inner.as_ref() {
            ast::Expr::Ident(name) => name.clone(),
            _ => return None,
        },
        _ => return None,
    };
    let terminal = match callee.as_str() {
        "free"
        | "close"
        | "join"
        | "detach"
        | "cancel_task"
        | "http.stream_close"
        | "task.group_join"
        | "task.group_join_all"
        | "task.group_cancel" => Some(callee.clone()),
        _ if callee.ends_with(".free")
            || callee.ends_with(".close")
            || callee.ends_with("_close") =>
        {
            Some(callee.clone())
        }
        _ => None,
    }?;
    Some((binding, terminal))
}

pub(crate) fn count_awaits_in_stmts(body: &[ast::Stmt]) -> usize {
    body.iter().map(count_awaits_in_stmt).sum()
}

pub(crate) fn count_awaits_in_stmt(stmt: &ast::Stmt) -> usize {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Return(Some(value))
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => count_awaits_in_expr(value),
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            count_awaits_in_expr(condition)
                + count_awaits_in_stmts(then_body)
                + count_awaits_in_stmts(else_body)
        }
        ast::Stmt::While { condition, body } => {
            count_awaits_in_expr(condition) + count_awaits_in_stmts(body)
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + condition.as_ref().map(count_awaits_in_expr).unwrap_or(0)
                + step.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + count_awaits_in_stmts(body)
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            count_awaits_in_expr(iterable) + count_awaits_in_stmts(body)
        }
        ast::Stmt::Loop { body } => count_awaits_in_stmts(body),
        ast::Stmt::Match { scrutinee, arms } => {
            count_awaits_in_expr(scrutinee)
                + arms
                    .iter()
                    .map(|arm| {
                        arm.guard.as_ref().map(count_awaits_in_expr).unwrap_or(0)
                            + count_awaits_in_expr(&arm.value)
                    })
                    .sum::<usize>()
        }
        ast::Stmt::Return(None) | ast::Stmt::Break(_) | ast::Stmt::Continue => 0,
    }
}

pub(crate) fn count_awaits_in_expr(expr: &ast::Expr) -> usize {
    match expr {
        ast::Expr::Await(inner) => 1 + count_awaits_in_expr(inner),
        ast::Expr::Call { args, .. } => args.iter().map(count_awaits_in_expr).sum(),
        ast::Expr::UnsafeBlock { body, .. } => count_awaits_in_stmts(body),
        ast::Expr::FieldAccess { base, .. }
        | ast::Expr::Group(base)
        | ast::Expr::Discard(base)
        | ast::Expr::Unary { expr: base, .. } => count_awaits_in_expr(base),
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => fields
            .iter()
            .map(|(_, value)| count_awaits_in_expr(value))
            .sum(),
        ast::Expr::EnumInit { payload, .. }
        | ast::Expr::Tuple(payload)
        | ast::Expr::ArrayLiteral(payload) => payload.iter().map(count_awaits_in_expr).sum(),
        ast::Expr::Closure { body, .. } => count_awaits_in_expr(body),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => count_awaits_in_expr(try_expr) + count_awaits_in_expr(catch_expr),
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            count_awaits_in_expr(condition)
                + count_awaits_in_expr(then_expr)
                + count_awaits_in_expr(else_expr)
        }
        ast::Expr::Match { scrutinee, arms } => {
            count_awaits_in_expr(scrutinee)
                + arms
                    .iter()
                    .map(|arm| {
                        arm.guard.as_ref().map(count_awaits_in_expr).unwrap_or(0)
                            + count_awaits_in_expr(&arm.value)
                    })
                    .sum::<usize>()
        }
        ast::Expr::While { condition, body } => {
            count_awaits_in_expr(condition) + count_awaits_in_stmts(body)
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + condition.as_deref().map(count_awaits_in_expr).unwrap_or(0)
                + step.as_deref().map(count_awaits_in_stmt).unwrap_or(0)
                + count_awaits_in_stmts(body)
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            count_awaits_in_expr(iterable) + count_awaits_in_stmts(body)
        }
        ast::Expr::Loop { body } => count_awaits_in_stmts(body),
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            value.as_deref().map(count_awaits_in_expr).unwrap_or(0)
        }
        ast::Expr::Binary { left, right, .. } => {
            count_awaits_in_expr(left) + count_awaits_in_expr(right)
        }
        ast::Expr::Range { start, end, .. } => {
            count_awaits_in_expr(start) + count_awaits_in_expr(end)
        }
        ast::Expr::Index { base, index } => {
            count_awaits_in_expr(base) + count_awaits_in_expr(index)
        }
        ast::Expr::Continue
        | ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => 0,
    }
}

