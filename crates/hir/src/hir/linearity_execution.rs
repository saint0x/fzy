use crate::*;

pub(crate) fn analyze_send_sync_contracts(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        let requires_thread = function.is_async
            || function
                .required_capabilities
                .iter()
                .any(|cap| cap == "thread");
        if !requires_thread {
            continue;
        }
        for param in &function.params {
            if matches!(param.ty, Type::Ptr { mutable: true, .. } | Type::Ref { .. }) {
                violations.push(format!(
                    "function `{}` parameter `{}` requires Send/Sync-safe wrapper before thread crossing",
                    function.name, param.name
                ));
            }
        }
        if matches!(function.return_type, Type::Ref { .. }) {
            violations.push(format!(
                "function `{}` returns borrowed reference across thread-capable boundary; return owned/Send-safe handle instead",
                function.name
            ));
        }
        violations.extend(analyze_spawn_borrow_escapes(function));
    }
    violations
}

pub(crate) fn analyze_spawn_borrow_escapes(function: &TypedFunction) -> Vec<String> {
    let mut violations = Vec::new();
    let mut closure_bindings = BTreeMap::<String, Expr>::new();
    let binding_types = function.local_types.clone();
    for stmt in &function.body {
        analyze_spawn_borrow_escapes_stmt(
            stmt,
            function,
            &binding_types,
            &closure_bindings,
            &mut violations,
        );
        record_closure_binding_stmt(stmt, &mut closure_bindings);
    }
    violations
}

pub(crate) fn analyze_spawn_borrow_escapes_stmt(
    stmt: &Stmt,
    function: &TypedFunction,
    binding_types: &BTreeMap<String, Type>,
    closure_bindings: &BTreeMap<String, Expr>,
    violations: &mut Vec<String>,
) {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => analyze_spawn_borrow_escapes_expr(
            value,
            function,
            binding_types,
            closure_bindings,
            violations,
        ),
        Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => {}
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            analyze_spawn_borrow_escapes_expr(
                condition,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            for nested in then_body {
                analyze_spawn_borrow_escapes_stmt(
                    nested,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
            for nested in else_body {
                analyze_spawn_borrow_escapes_stmt(
                    nested,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Stmt::While { condition, body } => {
            analyze_spawn_borrow_escapes_expr(
                condition,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            for nested in body {
                analyze_spawn_borrow_escapes_stmt(
                    nested,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init.as_deref() {
                analyze_spawn_borrow_escapes_stmt(
                    init,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
            if let Some(condition) = condition.as_ref() {
                analyze_spawn_borrow_escapes_expr(
                    condition,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
            for nested in body {
                analyze_spawn_borrow_escapes_stmt(
                    nested,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
            if let Some(step) = step.as_deref() {
                analyze_spawn_borrow_escapes_stmt(
                    step,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Stmt::ForIn { iterable, body, .. } => {
            analyze_spawn_borrow_escapes_expr(
                iterable,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            for nested in body {
                analyze_spawn_borrow_escapes_stmt(
                    nested,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Stmt::Loop { body } => {
            for nested in body {
                analyze_spawn_borrow_escapes_stmt(
                    nested,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Stmt::Match { scrutinee, arms } => {
            analyze_spawn_borrow_escapes_expr(
                scrutinee,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            for arm in arms {
                if let Some(guard) = arm.guard.as_ref() {
                    analyze_spawn_borrow_escapes_expr(
                        guard,
                        function,
                        binding_types,
                        closure_bindings,
                        violations,
                    );
                }
                analyze_spawn_borrow_escapes_expr(
                    &arm.value,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
    }
}

pub(crate) fn analyze_spawn_borrow_escapes_expr(
    expr: &Expr,
    function: &TypedFunction,
    binding_types: &BTreeMap<String, Type>,
    closure_bindings: &BTreeMap<String, Expr>,
    violations: &mut Vec<String>,
) {
    match expr {
        Expr::Call { callee, args } => {
            if let Some(task_fn_arg_index) = spawn_callable_arg_index(callee) {
                if let Some(task_fn) = args.get(task_fn_arg_index) {
                    if let Some(closure_expr) =
                        resolve_spawn_closure_expr(task_fn, closure_bindings)
                    {
                        let captures = collect_spawn_closure_captures(closure_expr, binding_types);
                        for capture in captures {
                            let Some(ty) = binding_types.get(&capture) else {
                                continue;
                            };
                            if let Type::Ref { mutable, .. } = ty {
                                let borrow_kind = if *mutable { "mutable" } else { "shared" };
                                violations.push(format!(
                                    "function `{}` {} captures {} borrowed reference `{}` across thread boundary",
                                    function.name, callee, borrow_kind, capture
                                ));
                            } else if let Type::Named { name, .. } = ty {
                                if runtime_handle_contract(name)
                                    .is_some_and(|contract| !contract.send_safe)
                                {
                                    violations.push(format!(
                                        "function `{}` {} captures non-Send-safe handle `{}` ({}) across thread boundary",
                                        function.name, callee, capture, name
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            for arg in args {
                analyze_spawn_borrow_escapes_expr(
                    arg,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::Discard(inner)
        | Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Unary { expr: inner, .. }
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Return(Some(inner))
        | Expr::Break(Some(inner)) => analyze_spawn_borrow_escapes_expr(
            inner,
            function,
            binding_types,
            closure_bindings,
            violations,
        ),
        Expr::Return(None)
        | Expr::Break(None)
        | Expr::Continue
        | Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Ident(_) => {}
        Expr::UnsafeBlock { body, .. } | Expr::Loop { body } => {
            for stmt in body {
                analyze_spawn_borrow_escapes_stmt(
                    stmt,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                analyze_spawn_borrow_escapes_expr(
                    value,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::EnumInit { payload, .. } | Expr::Tuple(payload) | Expr::ArrayLiteral(payload) => {
            for value in payload {
                analyze_spawn_borrow_escapes_expr(
                    value,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::Closure { body, .. } => analyze_spawn_borrow_escapes_expr(
            body,
            function,
            binding_types,
            closure_bindings,
            violations,
        ),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            analyze_spawn_borrow_escapes_expr(
                try_expr,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            analyze_spawn_borrow_escapes_expr(
                catch_expr,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            analyze_spawn_borrow_escapes_expr(
                condition,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            analyze_spawn_borrow_escapes_expr(
                then_expr,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            analyze_spawn_borrow_escapes_expr(
                else_expr,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
        }
        Expr::Match { scrutinee, arms } => {
            analyze_spawn_borrow_escapes_expr(
                scrutinee,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            for arm in arms {
                if let Some(guard) = arm.guard.as_ref() {
                    analyze_spawn_borrow_escapes_expr(
                        guard,
                        function,
                        binding_types,
                        closure_bindings,
                        violations,
                    );
                }
                analyze_spawn_borrow_escapes_expr(
                    &arm.value,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::While { condition, body } => {
            analyze_spawn_borrow_escapes_expr(
                condition,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            for stmt in body {
                analyze_spawn_borrow_escapes_stmt(
                    stmt,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init.as_deref() {
                analyze_spawn_borrow_escapes_stmt(
                    init,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
            if let Some(condition) = condition.as_ref() {
                analyze_spawn_borrow_escapes_expr(
                    condition,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
            for stmt in body {
                analyze_spawn_borrow_escapes_stmt(
                    stmt,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
            if let Some(step) = step.as_deref() {
                analyze_spawn_borrow_escapes_stmt(
                    step,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            analyze_spawn_borrow_escapes_expr(
                iterable,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            for stmt in body {
                analyze_spawn_borrow_escapes_stmt(
                    stmt,
                    function,
                    binding_types,
                    closure_bindings,
                    violations,
                );
            }
        }
        Expr::Binary { left, right, .. }
        | Expr::Range {
            start: left,
            end: right,
            ..
        } => {
            analyze_spawn_borrow_escapes_expr(
                left,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            analyze_spawn_borrow_escapes_expr(
                right,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
        }
        Expr::Index { base, index } => {
            analyze_spawn_borrow_escapes_expr(
                base,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
            analyze_spawn_borrow_escapes_expr(
                index,
                function,
                binding_types,
                closure_bindings,
                violations,
            );
        }
    }
}

pub(crate) fn spawn_callable_arg_index(callee: &str) -> Option<usize> {
    match callee {
        "spawn" | "thread.spawn" | "spawn_ctx" | "thread.spawn_ctx" => Some(0),
        "task.group_spawn" | "task.group_spawn_n" | "task.parallel_map" => Some(1),
        _ => None,
    }
}

pub(crate) fn resolve_spawn_closure_expr<'a>(
    expr: &'a Expr,
    closure_bindings: &'a BTreeMap<String, Expr>,
) -> Option<&'a Expr> {
    match expr {
        Expr::Closure { .. } => Some(expr),
        Expr::Ident(name) => closure_bindings.get(name),
        _ => None,
    }
}

pub(crate) fn record_closure_binding_stmt(
    stmt: &Stmt,
    closure_bindings: &mut BTreeMap<String, Expr>,
) {
    match stmt {
        Stmt::Let { name, value, .. } => record_closure_binding(name, value, closure_bindings),
        Stmt::Assign { target, value } => record_closure_binding(target, value, closure_bindings),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            for nested in then_body {
                record_closure_binding_stmt(nested, closure_bindings);
            }
            for nested in else_body {
                record_closure_binding_stmt(nested, closure_bindings);
            }
        }
        Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::ForIn { body, .. } => {
            for nested in body {
                record_closure_binding_stmt(nested, closure_bindings);
            }
        }
        Stmt::For {
            init, step, body, ..
        } => {
            if let Some(init) = init.as_deref() {
                record_closure_binding_stmt(init, closure_bindings);
            }
            for nested in body {
                record_closure_binding_stmt(nested, closure_bindings);
            }
            if let Some(step) = step.as_deref() {
                record_closure_binding_stmt(step, closure_bindings);
            }
        }
        Stmt::Match { .. }
        | Stmt::LetPattern { .. }
        | Stmt::CompoundAssign { .. }
        | Stmt::Return(_)
        | Stmt::Break(_)
        | Stmt::Continue
        | Stmt::Defer(_)
        | Stmt::Requires(_)
        | Stmt::Ensures(_)
        | Stmt::Expr(_) => {}
    }
}

pub(crate) fn record_closure_binding(
    name: &str,
    value: &Expr,
    closure_bindings: &mut BTreeMap<String, Expr>,
) {
    if let Expr::Closure { .. } = value {
        closure_bindings.insert(name.to_string(), value.clone());
    }
}

pub(crate) fn collect_spawn_closure_captures(
    closure_expr: &Expr,
    binding_types: &BTreeMap<String, Type>,
) -> BTreeSet<String> {
    let Expr::Closure { params, body, .. } = closure_expr else {
        return BTreeSet::new();
    };
    let mut scopes = vec![params
        .iter()
        .map(|param| param.name.clone())
        .collect::<BTreeSet<_>>()];
    let mut captures = BTreeSet::new();
    collect_expr_free_idents(body, &mut scopes, binding_types, &mut captures);
    captures
}

pub(crate) fn collect_stmt_free_idents(
    stmt: &Stmt,
    scopes: &mut Vec<BTreeSet<String>>,
    binding_types: &BTreeMap<String, Type>,
    captures: &mut BTreeSet<String>,
) {
    match stmt {
        Stmt::Let { name, value, .. } => {
            collect_expr_free_idents(value, scopes, binding_types, captures);
            if let Some(scope) = scopes.last_mut() {
                scope.insert(name.clone());
            }
        }
        Stmt::LetPattern { pattern, value, .. } => {
            collect_expr_free_idents(value, scopes, binding_types, captures);
            let mut bindings = BTreeSet::new();
            collect_pattern_bindings(pattern, &mut bindings);
            if let Some(scope) = scopes.last_mut() {
                scope.extend(bindings);
            }
        }
        Stmt::Assign { target, value } | Stmt::CompoundAssign { target, value, .. } => {
            if !scopes.iter().rev().any(|scope| scope.contains(target))
                && binding_types.contains_key(target)
            {
                captures.insert(target.clone());
            }
            collect_expr_free_idents(value, scopes, binding_types, captures);
        }
        Stmt::Return(Some(value))
        | Stmt::Break(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => collect_expr_free_idents(value, scopes, binding_types, captures),
        Stmt::Return(None) | Stmt::Break(None) | Stmt::Continue => {}
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_expr_free_idents(condition, scopes, binding_types, captures);
            scopes.push(BTreeSet::new());
            for nested in then_body {
                collect_stmt_free_idents(nested, scopes, binding_types, captures);
            }
            scopes.pop();
            scopes.push(BTreeSet::new());
            for nested in else_body {
                collect_stmt_free_idents(nested, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Stmt::While { condition, body } => {
            collect_expr_free_idents(condition, scopes, binding_types, captures);
            scopes.push(BTreeSet::new());
            for nested in body {
                collect_stmt_free_idents(nested, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            scopes.push(BTreeSet::new());
            if let Some(init) = init.as_deref() {
                collect_stmt_free_idents(init, scopes, binding_types, captures);
            }
            if let Some(condition) = condition {
                collect_expr_free_idents(condition, scopes, binding_types, captures);
            }
            for nested in body {
                collect_stmt_free_idents(nested, scopes, binding_types, captures);
            }
            if let Some(step) = step.as_deref() {
                collect_stmt_free_idents(step, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Stmt::ForIn {
            binding,
            iterable,
            body,
        } => {
            collect_expr_free_idents(iterable, scopes, binding_types, captures);
            scopes.push(BTreeSet::from([binding.clone()]));
            for nested in body {
                collect_stmt_free_idents(nested, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Stmt::Loop { body } => {
            scopes.push(BTreeSet::new());
            for nested in body {
                collect_stmt_free_idents(nested, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Stmt::Match { scrutinee, arms } => {
            collect_expr_free_idents(scrutinee, scopes, binding_types, captures);
            for arm in arms {
                scopes.push(BTreeSet::new());
                let mut bindings = BTreeSet::new();
                collect_pattern_bindings(&arm.pattern, &mut bindings);
                if let Some(scope) = scopes.last_mut() {
                    scope.extend(bindings);
                }
                if let Some(guard) = arm.guard.as_ref() {
                    collect_expr_free_idents(guard, scopes, binding_types, captures);
                }
                collect_expr_free_idents(&arm.value, scopes, binding_types, captures);
                scopes.pop();
            }
        }
    }
}

pub(crate) fn collect_expr_free_idents(
    expr: &Expr,
    scopes: &mut Vec<BTreeSet<String>>,
    binding_types: &BTreeMap<String, Type>,
    captures: &mut BTreeSet<String>,
) {
    match expr {
        Expr::Ident(name) => {
            if scopes.iter().rev().any(|scope| scope.contains(name)) {
                return;
            }
            if binding_types.contains_key(name) {
                captures.insert(name.clone());
            }
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_free_idents(arg, scopes, binding_types, captures);
            }
        }
        Expr::Discard(inner)
        | Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Unary { expr: inner, .. }
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Return(Some(inner))
        | Expr::Break(Some(inner)) => {
            collect_expr_free_idents(inner, scopes, binding_types, captures);
        }
        Expr::Return(None)
        | Expr::Break(None)
        | Expr::Continue
        | Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_) => {}
        Expr::UnsafeBlock { body, .. } | Expr::Loop { body } => {
            scopes.push(BTreeSet::new());
            for stmt in body {
                collect_stmt_free_idents(stmt, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_expr_free_idents(value, scopes, binding_types, captures);
            }
        }
        Expr::EnumInit { payload, .. } | Expr::Tuple(payload) | Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_expr_free_idents(value, scopes, binding_types, captures);
            }
        }
        Expr::Closure { params, body, .. } => {
            scopes.push(
                params
                    .iter()
                    .map(|param| param.name.clone())
                    .collect::<BTreeSet<_>>(),
            );
            collect_expr_free_idents(body, scopes, binding_types, captures);
            scopes.pop();
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_expr_free_idents(try_expr, scopes, binding_types, captures);
            collect_expr_free_idents(catch_expr, scopes, binding_types, captures);
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_expr_free_idents(condition, scopes, binding_types, captures);
            collect_expr_free_idents(then_expr, scopes, binding_types, captures);
            collect_expr_free_idents(else_expr, scopes, binding_types, captures);
        }
        Expr::Match { scrutinee, arms } => {
            collect_expr_free_idents(scrutinee, scopes, binding_types, captures);
            for arm in arms {
                scopes.push(BTreeSet::new());
                let mut bindings = BTreeSet::new();
                collect_pattern_bindings(&arm.pattern, &mut bindings);
                if let Some(scope) = scopes.last_mut() {
                    scope.extend(bindings);
                }
                if let Some(guard) = arm.guard.as_ref() {
                    collect_expr_free_idents(guard, scopes, binding_types, captures);
                }
                collect_expr_free_idents(&arm.value, scopes, binding_types, captures);
                scopes.pop();
            }
        }
        Expr::While { condition, body } => {
            collect_expr_free_idents(condition, scopes, binding_types, captures);
            scopes.push(BTreeSet::new());
            for stmt in body {
                collect_stmt_free_idents(stmt, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            scopes.push(BTreeSet::new());
            if let Some(init) = init.as_deref() {
                collect_stmt_free_idents(init, scopes, binding_types, captures);
            }
            if let Some(condition) = condition {
                collect_expr_free_idents(condition, scopes, binding_types, captures);
            }
            for stmt in body {
                collect_stmt_free_idents(stmt, scopes, binding_types, captures);
            }
            if let Some(step) = step.as_deref() {
                collect_stmt_free_idents(step, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Expr::ForIn {
            binding,
            iterable,
            body,
        } => {
            collect_expr_free_idents(iterable, scopes, binding_types, captures);
            scopes.push(BTreeSet::from([binding.clone()]));
            for stmt in body {
                collect_stmt_free_idents(stmt, scopes, binding_types, captures);
            }
            scopes.pop();
        }
        Expr::Binary { left, right, .. }
        | Expr::Range {
            start: left,
            end: right,
            ..
        } => {
            collect_expr_free_idents(left, scopes, binding_types, captures);
            collect_expr_free_idents(right, scopes, binding_types, captures);
        }
        Expr::Index { base, index } => {
            collect_expr_free_idents(base, scopes, binding_types, captures);
            collect_expr_free_idents(index, scopes, binding_types, captures);
        }
    }
}

pub(crate) fn function_body_has_await(body: &[Stmt]) -> bool {
    body.iter().any(stmt_has_await)
}

pub(crate) fn stmt_has_await(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_has_await(value),
        Stmt::Return(None) => false,
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_has_await(condition)
                || then_body.iter().any(stmt_has_await)
                || else_body.iter().any(stmt_has_await)
        }
        Stmt::While { condition, body } => {
            expr_has_await(condition) || body.iter().any(stmt_has_await)
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().is_some_and(stmt_has_await)
                || condition.as_ref().is_some_and(expr_has_await)
                || step.as_deref().is_some_and(stmt_has_await)
                || body.iter().any(stmt_has_await)
        }
        Stmt::ForIn { iterable, body, .. } => {
            expr_has_await(iterable) || body.iter().any(stmt_has_await)
        }
        Stmt::Loop { body } => body.iter().any(stmt_has_await),
        Stmt::Break(_) | Stmt::Continue => false,
        Stmt::Match { scrutinee, arms } => {
            expr_has_await(scrutinee)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(expr_has_await) || expr_has_await(&arm.value)
                })
        }
    }
}

pub(crate) fn expr_has_await(expr: &Expr) -> bool {
    match expr {
        Expr::Await(_) => true,
        Expr::Discard(inner) => expr_has_await(inner),
        Expr::Call { args, .. } => args.iter().any(expr_has_await),
        Expr::UnsafeBlock { body, .. } => body.iter().any(stmt_has_await),
        Expr::FieldAccess { base, .. } => expr_has_await(base),
        Expr::StructInit { fields, .. } => fields.iter().any(|(_, value)| expr_has_await(value)),
        Expr::EnumInit { payload, .. } => payload.iter().any(expr_has_await),
        Expr::Tuple(items) => items.iter().any(expr_has_await),
        Expr::Closure { body, .. } => expr_has_await(body),
        Expr::Group(inner) => expr_has_await(inner),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => expr_has_await(try_expr) || expr_has_await(catch_expr),
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => expr_has_await(condition) || expr_has_await(then_expr) || expr_has_await(else_expr),
        Expr::Match { scrutinee, arms } => {
            expr_has_await(scrutinee)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(expr_has_await) || expr_has_await(&arm.value)
                })
        }
        Expr::While { condition, body } => {
            expr_has_await(condition) || body.iter().any(stmt_has_await)
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_ref().is_some_and(|stmt| stmt_has_await(stmt))
                || condition.as_ref().is_some_and(|expr| expr_has_await(expr))
                || step.as_ref().is_some_and(|stmt| stmt_has_await(stmt))
                || body.iter().any(stmt_has_await)
        }
        Expr::ForIn { iterable, body, .. } => {
            expr_has_await(iterable) || body.iter().any(stmt_has_await)
        }
        Expr::Loop { body } => body.iter().any(stmt_has_await),
        Expr::Return(value) | Expr::Break(value) => {
            value.as_ref().is_some_and(|expr| expr_has_await(expr))
        }
        Expr::Continue => false,
        Expr::Binary { left, right, .. } => expr_has_await(left) || expr_has_await(right),
        Expr::Range { start, end, .. } => expr_has_await(start) || expr_has_await(end),
        Expr::ArrayLiteral(items) => items.iter().any(expr_has_await),
        Expr::ObjectLiteral(fields) => fields.iter().any(|(_, value)| expr_has_await(value)),
        Expr::Index { base, index } => expr_has_await(base) || expr_has_await(index),
        Expr::Unary { expr, .. } => expr_has_await(expr),
        Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Ident(_) => false,
    }
}

pub(crate) fn analyze_linear_types(functions: &[TypedFunction]) -> Vec<String> {
    let ownership_summaries = build_function_ownership_summaries(functions);
    let mut violations = Vec::new();
    for function in functions {
        let mut linear_owned = ownership_summaries
            .get(&function.name)
            .into_iter()
            .flat_map(|consumed| consumed.iter().copied())
            .filter_map(|index| function.params.get(index))
            .filter(|param| is_linear_type(&param.ty))
            .map(|param| param.name.clone())
            .collect::<BTreeSet<_>>();
        let mut linear_freed = BTreeSet::<String>::new();
        struct Collector<'a> {
            function: &'a TypedFunction,
            linear_owned: &'a mut BTreeSet<String>,
            linear_freed: &'a mut BTreeSet<String>,
            violations: &'a mut Vec<String>,
            ownership_summaries: &'a BTreeMap<String, BTreeSet<usize>>,
        }
        impl AstVisitor for Collector<'_> {
            fn visit_stmt(&mut self, stmt: &Stmt) {
                if let Stmt::Let {
                    name, ty, value, ..
                } = stmt
                {
                    if let Some(resource_ty) =
                        binding_resource_type(self.function, name, ty.as_ref(), value)
                    {
                        if is_linear_type(resource_ty) {
                            self.linear_owned.insert(name.clone());
                        }
                    }
                }
                if let Stmt::Return(Some(expr)) = stmt {
                    for name in terminal_return_identity_names_on_all_paths(expr) {
                        if self.linear_owned.contains(&name) {
                            self.linear_freed.insert(name);
                        }
                    }
                }
                ast::walk_stmt(self, stmt);
            }

            fn visit_expr(&mut self, expr: &Expr) {
                if let Expr::Call { callee, args } = expr {
                    for name in consumed_arg_identity_names(callee, args, self.ownership_summaries)
                    {
                        if !self.linear_owned.contains(name) {
                            self.violations.push(format!(
                                "function `{}` frees non-linear value `{}` as linear resource",
                                self.function.name, name
                            ));
                        }
                        self.linear_freed.insert(name.to_string());
                    }
                }
                ast::walk_expr(self, expr);
            }
        }
        let mut collector = Collector {
            function,
            linear_owned: &mut linear_owned,
            linear_freed: &mut linear_freed,
            violations: &mut violations,
            ownership_summaries: &ownership_summaries,
        };
        for stmt in &function.body {
            collector.visit_stmt(stmt);
        }
        for name in linear_owned {
            if !linear_freed.contains(&name) {
                violations.push(format!(
                    "function `{}` linear value `{}` was not consumed/freed",
                    function.name, name
                ));
            }
        }
    }
    violations
}

pub(crate) fn is_linear_type(ty: &Type) -> bool {
    match ty {
        Type::Ptr { .. } => true,
        Type::Named { name, .. } if is_linear_runtime_handle(name) => true,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeHandleContract {
    pub name: &'static str,
    pub copy: bool,
    pub owned: bool,
    pub linear: bool,
    pub closable: bool,
    pub send_safe: bool,
    pub async_stable: bool,
    pub producer_intrinsics: &'static [&'static str],
    pub consumer_intrinsics: &'static [&'static str],
    pub observer_intrinsics: &'static [&'static str],
}

const RUNTIME_HANDLE_CONTRACTS: &[RuntimeHandleContract] = &[
    RuntimeHandleContract {
        name: "HttpHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &["http.bind", "http.accept", "http.connect", "http.poll_next"],
        consumer_intrinsics: &[
            "close",
            "http.close",
            "http.write",
            "http.write_json",
            "http.write_response",
            "http.websocket_accept",
            "route.write_404",
            "route.write_405",
        ],
        observer_intrinsics: &[
            "http.listen",
            "http.read",
            "http.read_headers",
            "http.method",
            "http.path",
            "http.body",
            "http.body_read",
            "http.body_eof",
            "http.body_discard",
            "http.body_json",
            "http.body_bind",
            "http.header",
            "http.query",
            "http.param",
            "http.headers",
            "http.request_id",
            "http.remote_addr",
            "http.response_header_set",
            "http.response_header_add",
            "http.response_header_clear",
            "route.match",
        ],
    },
    RuntimeHandleContract {
        name: "HttpStreamHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &["http.request_stream", "http.post_json_stream"],
        consumer_intrinsics: &["http.stream_close"],
        observer_intrinsics: &[
            "http.stream_read",
            "http.stream_read_line",
            "http.stream_eof",
            "http.stream_status",
            "http.stream_error",
        ],
    },
    RuntimeHandleContract {
        name: "WebSocketHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &["http.websocket_accept"],
        consumer_intrinsics: &["http.websocket_close"],
        observer_intrinsics: &[
            "http.websocket_read",
            "http.websocket_kind",
            "http.websocket_error",
            "http.websocket_close_code",
            "http.websocket_write_text",
            "http.websocket_write_binary",
            "http.websocket_ping",
            "http.websocket_pong",
        ],
    },
    RuntimeHandleContract {
        name: "ProcessHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &[
            "proc.spawn",
            "proc.spawnl",
            "proc.spawn_cmd",
            "proc.run_cmd",
        ],
        consumer_intrinsics: &["proc.close"],
        observer_intrinsics: &[
            "proc.exec_timeout",
            "proc.wait",
            "proc.poll",
            "proc.event",
            "proc.read_stdout",
            "proc.read_stderr",
            "proc.stdout",
            "proc.stderr",
            "proc.exit_code",
        ],
    },
    RuntimeHandleContract {
        name: "ProcessArgv",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: false,
        async_stable: false,
        producer_intrinsics: &["proc.argv_new"],
        consumer_intrinsics: &["proc.spawnl", "proc.spawn_cmd", "proc.runl", "proc.run_cmd"],
        observer_intrinsics: &["proc.argv_push"],
    },
    RuntimeHandleContract {
        name: "ProcessEnv",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: false,
        async_stable: false,
        producer_intrinsics: &["proc.env_new"],
        consumer_intrinsics: &["proc.spawnl", "proc.spawn_cmd", "proc.runl", "proc.run_cmd"],
        observer_intrinsics: &["proc.env_set"],
    },
    RuntimeHandleContract {
        name: "TaskHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &[
            "spawn",
            "thread.spawn",
            "spawn_ctx",
            "thread.spawn_ctx",
            "task.group_spawn",
        ],
        consumer_intrinsics: &["join", "detach", "cancel_task"],
        observer_intrinsics: &["task_result", "ctx.deadline"],
    },
    RuntimeHandleContract {
        name: "TaskGroupHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &["task.group_begin"],
        consumer_intrinsics: &[
            "task.group_join",
            "task.group_join_all",
            "task.group_cancel",
        ],
        observer_intrinsics: &[
            "task.group_spawn",
            "task.group_spawn_n",
            "task.parallel_map",
        ],
    },
    RuntimeHandleContract {
        name: "TaskGroup",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &[],
        consumer_intrinsics: &[],
        observer_intrinsics: &[],
    },
    RuntimeHandleContract {
        name: "FileHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &["fs.open"],
        consumer_intrinsics: &["fs.close"],
        observer_intrinsics: &["fs.write", "fs.read", "fs.flush", "fs.fsync", "fs.lock"],
    },
    RuntimeHandleContract {
        name: "JsonHandle",
        copy: false,
        owned: true,
        linear: false,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &[
            "json.parse",
            "http.body_json",
            "http.body_bind",
            "json.get",
            "json.path",
        ],
        consumer_intrinsics: &[],
        observer_intrinsics: &[
            "json.get_str",
            "json.has",
            "json.to_list",
            "json.to_map",
            "json.keys",
        ],
    },
    RuntimeHandleContract {
        name: "ListHandle",
        copy: false,
        owned: true,
        linear: false,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &["list.new", "json.to_list", "json.keys", "fs.listdir"],
        consumer_intrinsics: &[],
        observer_intrinsics: &[
            "list.push",
            "list.pop",
            "list.len",
            "list.get",
            "list.set",
            "list.clear",
            "list.join",
        ],
    },
    RuntimeHandleContract {
        name: "MapHandle",
        copy: false,
        owned: true,
        linear: false,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &["map.new", "http.headers", "json.to_map"],
        consumer_intrinsics: &[],
        observer_intrinsics: &[
            "map.set",
            "map.get",
            "map.has",
            "map.delete",
            "map.keys",
            "map.len",
        ],
    },
    RuntimeHandleContract {
        name: "BytesHandle",
        copy: false,
        owned: true,
        linear: false,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &["fs.read_bytes", "bytes.slice"],
        consumer_intrinsics: &[],
        observer_intrinsics: &[
            "fs.write_bytes",
            "bytes.len",
            "bytes.at",
            "bytes.read_u16_le",
            "bytes.read_u32_le",
            "bytes.read_u64_le",
            "bytes.read_f32_le",
            "bytes.read_f16_le",
            "bytes.as_str",
        ],
    },
    RuntimeHandleContract {
        name: "KvStoreHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &["storage.kv_open"],
        consumer_intrinsics: &["storage.kv_close"],
        observer_intrinsics: &["storage.kv_get", "storage.kv_put"],
    },
    RuntimeHandleContract {
        name: "ChannelHandle",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &[],
        consumer_intrinsics: &[],
        observer_intrinsics: &["channel.send", "channel.recv"],
    },
    RuntimeHandleContract {
        name: "RpcFrame",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: false,
        async_stable: false,
        producer_intrinsics: &[],
        consumer_intrinsics: &[],
        observer_intrinsics: &[],
    },
    RuntimeHandleContract {
        name: "GpuDevice",
        copy: true,
        owned: false,
        linear: false,
        closable: false,
        send_safe: true,
        async_stable: true,
        producer_intrinsics: &["gpu.default_device"],
        consumer_intrinsics: &[],
        observer_intrinsics: &["gpu.device_name", "gpu.device_memory_bytes"],
    },
    RuntimeHandleContract {
        name: "GpuBuffer",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &[
            "gpu.alloc_f32",
            "gpu.alloc_i32",
            "gpu.alloc_u32",
            "gpu.upload_f32",
            "gpu.upload_i32",
            "gpu.upload_u32",
        ],
        consumer_intrinsics: &["gpu.free"],
        observer_intrinsics: &[
            "gpu.slice",
            "gpu.download_f32",
            "gpu.download_i32",
            "gpu.download_u32",
        ],
    },
    RuntimeHandleContract {
        name: "GpuSlice",
        copy: true,
        owned: false,
        linear: false,
        closable: false,
        send_safe: false,
        async_stable: false,
        producer_intrinsics: &["gpu.slice"],
        consumer_intrinsics: &[],
        observer_intrinsics: &[
            "gpu.slice_len",
            "gpu.load_f32",
            "gpu.load_i32",
            "gpu.load_u32",
            "gpu.store_f32",
            "gpu.store_i32",
            "gpu.store_u32",
        ],
    },
    RuntimeHandleContract {
        name: "GpuEvent",
        copy: false,
        owned: true,
        linear: true,
        closable: true,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &[
            "gpu.launch0",
            "gpu.launch1",
            "gpu.launch2",
            "gpu.launch3",
            "gpu.launch4",
        ],
        consumer_intrinsics: &["gpu.wait", "gpu.wait_async"],
        observer_intrinsics: &[],
    },
    RuntimeHandleContract {
        name: "GpuStream",
        copy: false,
        owned: true,
        linear: true,
        closable: false,
        send_safe: false,
        async_stable: true,
        producer_intrinsics: &[],
        consumer_intrinsics: &[],
        observer_intrinsics: &[],
    },
];

pub fn runtime_handle_contracts() -> &'static [RuntimeHandleContract] {
    RUNTIME_HANDLE_CONTRACTS
}

pub fn runtime_handle_contract(name: &str) -> Option<&'static RuntimeHandleContract> {
    runtime_handle_contracts()
        .iter()
        .find(|contract| contract.name == name)
}

pub(crate) fn is_linear_runtime_handle(name: &str) -> bool {
    matches!(name, "Linear" | "Resource" | "Ptr")
        || runtime_handle_contract(name).is_some_and(|contract| contract.linear)
}

pub(crate) fn binding_resource_type<'a>(
    function: &'a TypedFunction,
    name: &str,
    explicit_ty: Option<&'a Type>,
    value: &'a Expr,
) -> Option<&'a Type> {
    explicit_ty
        .or_else(|| function.local_types.get(name))
        .or_else(|| {
            is_alloc_expr(value)
                .then(|| function.local_types.get(name))
                .flatten()
        })
}

pub(crate) fn binding_creates_owned_resource(
    function: &TypedFunction,
    name: &str,
    ty: Option<&Type>,
    value: &Expr,
) -> bool {
    binding_resource_type(function, name, ty, value).is_some_and(is_linear_type)
        || is_alloc_expr(value)
}

pub(crate) fn compute_function_capabilities(
    functions: &[TypedFunction],
) -> Vec<FunctionCapabilityRequirement> {
    let mut local = BTreeMap::<String, BTreeSet<String>>::new();
    let mut calls = BTreeMap::<String, BTreeSet<String>>::new();

    for function in functions {
        let mut local_caps = BTreeSet::<String>::new();
        let mut local_calls = BTreeSet::<String>::new();
        collect_function_caps_and_calls(function, &mut local_caps, &mut local_calls);
        local.insert(function.name.clone(), local_caps);
        calls.insert(function.name.clone(), local_calls);
    }

    let known = functions
        .iter()
        .map(|f| f.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut changed = true;
    while changed {
        changed = false;
        for function in functions {
            let mut next = local.get(&function.name).cloned().unwrap_or_default();
            for callee in calls
                .get(&function.name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
            {
                if !known.contains(callee.as_str()) {
                    continue;
                }
                if let Some(callee_caps) = local.get(&callee) {
                    let before = next.len();
                    next.extend(callee_caps.iter().cloned());
                    if next.len() != before {
                        changed = true;
                    }
                }
            }
            local.insert(function.name.clone(), next);
        }
    }

    functions
        .iter()
        .map(|function| FunctionCapabilityRequirement {
            function: function.name.clone(),
            required: local
                .get(&function.name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect(),
        })
        .collect()
}

pub(crate) fn collect_function_caps_and_calls(
    function: &TypedFunction,
    caps: &mut BTreeSet<String>,
    calls: &mut BTreeSet<String>,
) {
    if function.is_async {
        caps.insert("thread".to_string());
    }
    struct Collector<'a> {
        caps: &'a mut BTreeSet<String>,
        calls: &'a mut BTreeSet<String>,
    }
    impl AstVisitor for Collector<'_> {
        fn visit_expr(&mut self, expr: &Expr) {
            if let Expr::Call { callee, .. } = expr {
                self.calls.insert(callee.clone());
                if let Some((prefix, _)) = callee.split_once('.') {
                    match prefix {
                        "time" | "std.time" => {
                            self.caps.insert("time".to_string());
                        }
                        "rng" | "random" | "std.rand" | "crypto" => {
                            self.caps.insert("rng".to_string());
                        }
                        "fs" | "file" | "std.io" => {
                            self.caps.insert("fs".to_string());
                        }
                        "storage" => {
                            self.caps.insert("storage".to_string());
                        }
                        "http" | "socket" | "std.http" => {
                            self.caps.insert("http".to_string());
                        }
                        "proc" | "process" | "syscall" | "std.proc" => {
                            self.caps.insert("proc".to_string());
                        }
                        "alloc" | "std.alloc" => {
                            self.caps.insert("mem".to_string());
                        }
                        "thread" | "task" | "std.thread" => {
                            self.caps.insert("thread".to_string());
                        }
                        "log" | "logger" | "std.log" => {
                            self.caps.insert("log".to_string());
                        }
                        "error" | "err" | "std.error" => {
                            self.caps.insert("error".to_string());
                        }
                        "gpu" => {
                            self.caps.insert("gpu".to_string());
                        }
                        _ => {}
                    }
                }
                if is_thread_capability_callee(callee) {
                    self.caps.insert("thread".to_string());
                }
            } else if matches!(expr, Expr::Await(_)) {
                self.caps.insert("thread".to_string());
            }
            ast::walk_expr(self, expr);
        }
    }

    let mut collector = Collector { caps, calls };
    for stmt in &function.body {
        collector.visit_stmt(stmt);
    }

    if function.execution_space != ast::ExecutionSpace::Host {
        caps.remove("gpu");
    }
}

pub(crate) fn infer_default_pure_functions(
    functions: &mut [TypedFunction],
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) {
    loop {
        let function_map = functions
            .iter()
            .map(|function| (function.name.as_str(), function))
            .collect::<BTreeMap<_, _>>();
        let candidates = functions
            .iter()
            .enumerate()
            .filter_map(|(index, function)| {
                if function.execution_space != ast::ExecutionSpace::Host
                    || function.is_async
                    || function.is_extern
                    || function.name.starts_with("simd.")
                    || !is_pure_safe_type(&function.return_type, struct_defs, enum_defs)
                    || function
                        .params
                        .iter()
                        .any(|param| !is_pure_safe_type(&param.ty, struct_defs, enum_defs))
                    || function
                        .local_types
                        .values()
                        .any(|ty| !is_pure_safe_type(ty, struct_defs, enum_defs))
                {
                    return None;
                }
                function
                    .body
                    .iter()
                    .all(|stmt| {
                        stmt_is_default_pure_candidate(stmt, function.name.as_str(), &function_map)
                    })
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            break;
        }
        for index in candidates {
            functions[index].execution_space = ast::ExecutionSpace::Pure;
        }
    }
}

pub(crate) fn stmt_is_default_pure_candidate(
    stmt: &Stmt,
    function_name: &str,
    function_map: &BTreeMap<&str, &TypedFunction>,
) -> bool {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_is_default_pure_candidate(value, function_name, function_map),
        Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => true,
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_is_default_pure_candidate(condition, function_name, function_map)
                && then_body
                    .iter()
                    .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map))
                && else_body
                    .iter()
                    .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map))
        }
        Stmt::While { condition, body } => {
            expr_is_default_pure_candidate(condition, function_name, function_map)
                && body
                    .iter()
                    .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map))
        }
        Stmt::Loop { body } => body
            .iter()
            .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map)),
        Stmt::ForIn { iterable, body, .. } => {
            expr_is_default_pure_candidate(iterable, function_name, function_map)
                && body
                    .iter()
                    .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map))
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().is_none_or(|stmt| {
                stmt_is_default_pure_candidate(stmt, function_name, function_map)
            }) && condition.as_ref().is_none_or(|expr| {
                expr_is_default_pure_candidate(expr, function_name, function_map)
            }) && step.as_deref().is_none_or(|stmt| {
                stmt_is_default_pure_candidate(stmt, function_name, function_map)
            }) && body
                .iter()
                .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map))
        }
        Stmt::Match { scrutinee, arms } => {
            expr_is_default_pure_candidate(scrutinee, function_name, function_map)
                && arms.iter().all(|arm| {
                    arm.guard.as_ref().is_none_or(|guard| {
                        expr_is_default_pure_candidate(guard, function_name, function_map)
                    }) && expr_is_default_pure_candidate(&arm.value, function_name, function_map)
                })
        }
    }
}

pub(crate) fn expr_is_default_pure_candidate(
    expr: &Expr,
    function_name: &str,
    function_map: &BTreeMap<&str, &TypedFunction>,
) -> bool {
    match expr {
        Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Bool(_)
        | Expr::Char(_)
        | Expr::Str(_)
        | Expr::Ident(_) => true,
        Expr::Group(inner) | Expr::Discard(inner) | Expr::Await(inner) => {
            expr_is_default_pure_candidate(inner, function_name, function_map)
        }
        Expr::Unary { expr, .. } => {
            expr_is_default_pure_candidate(expr, function_name, function_map)
        }
        Expr::Binary { left, right, .. } => {
            expr_is_default_pure_candidate(left, function_name, function_map)
                && expr_is_default_pure_candidate(right, function_name, function_map)
        }
        Expr::Tuple(items) | Expr::ArrayLiteral(items) => items
            .iter()
            .all(|item| expr_is_default_pure_candidate(item, function_name, function_map)),
        Expr::Index { base, index } => {
            expr_is_default_pure_candidate(base, function_name, function_map)
                && expr_is_default_pure_candidate(index, function_name, function_map)
        }
        Expr::FieldAccess { base, .. } => {
            expr_is_default_pure_candidate(base, function_name, function_map)
        }
        Expr::StructInit { fields, .. } => fields
            .iter()
            .all(|(_, value)| expr_is_default_pure_candidate(value, function_name, function_map)),
        Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            payload
                .iter()
                .all(|value| expr_is_default_pure_candidate(value, function_name, function_map))
                && named_payload.iter().all(|(_, value)| {
                    expr_is_default_pure_candidate(value, function_name, function_map)
                })
        }
        Expr::UnsafeBlock { body, .. } => body
            .iter()
            .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map)),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            expr_is_default_pure_candidate(try_expr, function_name, function_map)
                && expr_is_default_pure_candidate(catch_expr, function_name, function_map)
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            expr_is_default_pure_candidate(condition, function_name, function_map)
                && expr_is_default_pure_candidate(then_expr, function_name, function_map)
                && expr_is_default_pure_candidate(else_expr, function_name, function_map)
        }
        Expr::Match { scrutinee, arms } => {
            expr_is_default_pure_candidate(scrutinee, function_name, function_map)
                && arms.iter().all(|arm| {
                    arm.guard.as_ref().is_none_or(|guard| {
                        expr_is_default_pure_candidate(guard, function_name, function_map)
                    }) && expr_is_default_pure_candidate(&arm.value, function_name, function_map)
                })
        }
        Expr::While { condition, body } => {
            expr_is_default_pure_candidate(condition, function_name, function_map)
                && body
                    .iter()
                    .all(|stmt| stmt_is_default_pure_candidate(stmt, function_name, function_map))
        }
        Expr::For { .. }
        | Expr::ForIn { .. }
        | Expr::Loop { .. }
        | Expr::Break(_)
        | Expr::Continue
        | Expr::Return(_)
        | Expr::Range { .. }
        | Expr::ObjectLiteral(_)
        | Expr::Closure { .. } => false,
        Expr::Call { callee, args } => {
            let resolved = callee.split('<').next().unwrap_or(callee);
            if resolved == "__index_assign" {
                return args
                    .iter()
                    .all(|arg| expr_is_default_pure_candidate(arg, function_name, function_map));
            }
            if !args
                .iter()
                .all(|arg| expr_is_default_pure_candidate(arg, function_name, function_map))
            {
                return false;
            }
            if resolved.starts_with("simd.") {
                return true;
            }
            if let Some(target) = function_map.get(resolved) {
                return target.name == function_name
                    || matches!(
                        target.execution_space,
                        ast::ExecutionSpace::Pure | ast::ExecutionSpace::Device
                    );
            }
            false
        }
    }
}

pub(crate) fn analyze_execution_spaces(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    let function_map = functions
        .iter()
        .map(|function| (function.name.as_str(), function))
        .collect::<BTreeMap<_, _>>();

    for function in functions {
        validate_execution_space_function_shape(function, &mut violations);
        for stmt in &function.body {
            analyze_execution_space_stmt(function, stmt, &function_map, &mut violations);
        }
    }

    violations
}

pub(crate) fn validate_execution_space_function_shape(
    function: &TypedFunction,
    violations: &mut Vec<String>,
) {
    let execution = function.execution_space;
    if execution != ast::ExecutionSpace::Host && function.is_async {
        violations.push(format!(
            "{} function `{}` cannot be async",
            execution.as_str(),
            function.name
        ));
    }
    if execution != ast::ExecutionSpace::Host && function.is_extern {
        violations.push(format!(
            "{} function `{}` cannot use an extern ABI boundary",
            execution.as_str(),
            function.name
        ));
    }
    if execution == ast::ExecutionSpace::Kernel && function.return_type != Type::Void {
        violations.push(format!(
            "kernel function `{}` must return `void`, found `{}`",
            function.name, function.return_type
        ));
    }
}

pub(crate) fn analyze_execution_space_stmt(
    function: &TypedFunction,
    stmt: &Stmt,
    function_map: &BTreeMap<&str, &TypedFunction>,
    violations: &mut Vec<String>,
) {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => {
            analyze_execution_space_expr(function, value, function_map, violations);
        }
        Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => {}
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            analyze_execution_space_expr(function, condition, function_map, violations);
            for stmt in then_body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
            for stmt in else_body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Stmt::While { condition, body } => {
            analyze_execution_space_expr(function, condition, function_map, violations);
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                analyze_execution_space_stmt(function, init, function_map, violations);
            }
            if let Some(condition) = condition {
                analyze_execution_space_expr(function, condition, function_map, violations);
            }
            if let Some(step) = step {
                analyze_execution_space_stmt(function, step, function_map, violations);
            }
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Stmt::ForIn { iterable, body, .. } => {
            analyze_execution_space_expr(function, iterable, function_map, violations);
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Stmt::Loop { body } => {
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Stmt::Match { scrutinee, arms } => {
            analyze_execution_space_expr(function, scrutinee, function_map, violations);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    analyze_execution_space_expr(function, guard, function_map, violations);
                }
                analyze_execution_space_expr(function, &arm.value, function_map, violations);
            }
        }
    }
}

pub(crate) fn analyze_execution_space_expr(
    function: &TypedFunction,
    expr: &Expr,
    function_map: &BTreeMap<&str, &TypedFunction>,
    violations: &mut Vec<String>,
) {
    match expr {
        Expr::Call { callee, args } => {
            validate_execution_space_call(function, callee, function_map, violations);
            for arg in args {
                analyze_execution_space_expr(function, arg, function_map, violations);
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Expr::FieldAccess { base, .. } => {
            analyze_execution_space_expr(function, base, function_map, violations);
        }
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                analyze_execution_space_expr(function, value, function_map, violations);
            }
        }
        Expr::EnumInit { payload, .. } | Expr::Tuple(payload) | Expr::ArrayLiteral(payload) => {
            for value in payload {
                analyze_execution_space_expr(function, value, function_map, violations);
            }
        }
        Expr::Closure { body, .. } | Expr::Group(body) | Expr::Discard(body) => {
            analyze_execution_space_expr(function, body, function_map, violations);
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            analyze_execution_space_expr(function, try_expr, function_map, violations);
            analyze_execution_space_expr(function, catch_expr, function_map, violations);
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            analyze_execution_space_expr(function, condition, function_map, violations);
            analyze_execution_space_expr(function, then_expr, function_map, violations);
            analyze_execution_space_expr(function, else_expr, function_map, violations);
        }
        Expr::Match { scrutinee, arms } => {
            analyze_execution_space_expr(function, scrutinee, function_map, violations);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    analyze_execution_space_expr(function, guard, function_map, violations);
                }
                analyze_execution_space_expr(function, &arm.value, function_map, violations);
            }
        }
        Expr::While { condition, body } => {
            analyze_execution_space_expr(function, condition, function_map, violations);
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                analyze_execution_space_stmt(function, init, function_map, violations);
            }
            if let Some(condition) = condition {
                analyze_execution_space_expr(function, condition, function_map, violations);
            }
            if let Some(step) = step {
                analyze_execution_space_stmt(function, step, function_map, violations);
            }
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            analyze_execution_space_expr(function, iterable, function_map, violations);
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Expr::Loop { body } => {
            for stmt in body {
                analyze_execution_space_stmt(function, stmt, function_map, violations);
            }
        }
        Expr::Return(Some(value)) | Expr::Break(Some(value)) => {
            analyze_execution_space_expr(function, value, function_map, violations);
        }
        Expr::Return(None) | Expr::Break(None) | Expr::Continue => {}
        Expr::Range { start, end, .. } => {
            analyze_execution_space_expr(function, start, function_map, violations);
            analyze_execution_space_expr(function, end, function_map, violations);
        }
        Expr::Index { base, index } => {
            analyze_execution_space_expr(function, base, function_map, violations);
            analyze_execution_space_expr(function, index, function_map, violations);
        }
        Expr::Await(inner) => {
            if function.execution_space != ast::ExecutionSpace::Host {
                violations.push(format!(
                    "{} function `{}` cannot use `await`",
                    function.execution_space.as_str(),
                    function.name
                ));
            }
            analyze_execution_space_expr(function, inner, function_map, violations);
        }
        Expr::Unary { expr, .. } => {
            analyze_execution_space_expr(function, expr, function_map, violations);
        }
        Expr::Binary { left, right, .. } => {
            analyze_execution_space_expr(function, left, function_map, violations);
            analyze_execution_space_expr(function, right, function_map, violations);
        }
        Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Ident(_) => {}
    }
}

pub(crate) fn validate_execution_space_call(
    function: &TypedFunction,
    callee: &str,
    function_map: &BTreeMap<&str, &TypedFunction>,
    violations: &mut Vec<String>,
) {
    let caller_space = function.execution_space;
    if caller_space == ast::ExecutionSpace::Host {
        if callee == "__index_assign" {
            return;
        }
        if is_gpu_device_intrinsic(callee) {
            violations.push(format!(
                "host function `{}` cannot call device-only GPU intrinsic `{}`",
                function.name, callee
            ));
            return;
        }
        if let Some(target) = function_map.get(callee) {
            if target.execution_space == ast::ExecutionSpace::Kernel {
                violations.push(format!(
                    "host function `{}` cannot call kernel function `{}` directly; launch it from a GPU runtime API instead",
                    function.name, callee
                ));
            }
        }
        return;
    }

    if callee == "__index_assign" {
        return;
    }

    if let Some(target) = function_map.get(callee) {
        if callee.starts_with("simd.") {
            return;
        }
        let allowed = match caller_space {
            ast::ExecutionSpace::Pure => target.execution_space == ast::ExecutionSpace::Pure,
            ast::ExecutionSpace::Device => matches!(
                target.execution_space,
                ast::ExecutionSpace::Pure | ast::ExecutionSpace::Device
            ),
            ast::ExecutionSpace::Kernel => matches!(
                target.execution_space,
                ast::ExecutionSpace::Pure | ast::ExecutionSpace::Device
            ),
            ast::ExecutionSpace::Host => true,
        };
        if !allowed {
            violations.push(format!(
                "{} function `{}` cannot call {} function `{}`",
                caller_space.as_str(),
                function.name,
                target.execution_space.as_str(),
                callee
            ));
        }
        return;
    }

    if execution_space_allows_intrinsic_call(caller_space, callee) {
        return;
    }

    if caller_space == ast::ExecutionSpace::Pure && callee.starts_with("gpu.") {
        violations.push(format!(
            "pure function `{}` cannot call GPU API `{}`",
            function.name, callee
        ));
        return;
    }

    if callee_looks_host_only(callee) {
        violations.push(format!(
            "{} function `{}` calls host-only API `{}`",
            caller_space.as_str(),
            function.name,
            callee
        ));
    }
}

pub(crate) fn execution_space_allows_intrinsic_call(
    execution_space: ast::ExecutionSpace,
    callee: &str,
) -> bool {
    match execution_space {
        ast::ExecutionSpace::Host => !is_gpu_device_intrinsic(callee),
        ast::ExecutionSpace::Pure => callee.starts_with("simd."),
        ast::ExecutionSpace::Device | ast::ExecutionSpace::Kernel => {
            is_gpu_device_intrinsic(callee) || callee.starts_with("simd.")
        }
    }
}

pub(crate) fn is_gpu_device_intrinsic(callee: &str) -> bool {
    matches!(
        callee,
        "gpu.global_id_x"
            | "gpu.global_id_y"
            | "gpu.global_id_z"
            | "gpu.thread_id_x"
            | "gpu.thread_id_y"
            | "gpu.thread_id_z"
            | "gpu.block_id_x"
            | "gpu.block_id_y"
            | "gpu.block_id_z"
            | "gpu.block_dim_x"
            | "gpu.block_dim_y"
            | "gpu.block_dim_z"
            | "gpu.grid_dim_x"
            | "gpu.grid_dim_y"
            | "gpu.grid_dim_z"
            | "gpu.barrier"
            | "gpu.load_f32"
            | "gpu.load_i32"
            | "gpu.load_u32"
            | "gpu.store_f32"
            | "gpu.store_i32"
            | "gpu.store_u32"
            | "gpu.slice_len"
    )
}

pub(crate) fn callee_looks_host_only(callee: &str) -> bool {
    callee.starts_with("fs.")
        || callee.starts_with("http.")
        || callee.starts_with("proc.")
        || callee.starts_with("task.")
        || callee.starts_with("thread.")
        || callee.starts_with("log.")
        || callee.starts_with("storage.")
        || callee.starts_with("json.")
        || callee.starts_with("list.")
        || callee.starts_with("map.")
        || callee.starts_with("error.")
        || callee.starts_with("alloc.")
        || callee.starts_with("env.")
        || (callee.starts_with("gpu.") && !is_gpu_device_intrinsic(callee))
}

pub(crate) fn analyze_device_safe_types(
    functions: &[TypedFunction],
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        match function.execution_space {
            ast::ExecutionSpace::Host => {}
            ast::ExecutionSpace::Pure => {
                for param in &function.params {
                    if !is_pure_safe_type(&param.ty, struct_defs, enum_defs) {
                        violations.push(format!(
                            "pure function `{}` parameter `{}` uses unsupported pure/device type `{}`",
                            function.name, param.name, param.ty
                        ));
                    }
                }
                if !is_pure_safe_type(&function.return_type, struct_defs, enum_defs) {
                    violations.push(format!(
                        "pure function `{}` returns unsupported pure/device type `{}`",
                        function.name, function.return_type
                    ));
                }
                for (name, ty) in &function.local_types {
                    if !is_pure_safe_type(ty, struct_defs, enum_defs) {
                        violations.push(format!(
                            "pure function `{}` local `{}` uses unsupported pure/device type `{}`",
                            function.name, name, ty
                        ));
                    }
                }
            }
            ast::ExecutionSpace::Device | ast::ExecutionSpace::Kernel => {
                for param in &function.params {
                    if !is_device_safe_type(&param.ty, struct_defs, enum_defs) {
                        violations.push(format!(
                            "{} function `{}` parameter `{}` uses unsupported device type `{}`",
                            function.execution_space.as_str(),
                            function.name,
                            param.name,
                            param.ty
                        ));
                    }
                }
                if !is_device_safe_type(&function.return_type, struct_defs, enum_defs) {
                    violations.push(format!(
                        "{} function `{}` returns unsupported device type `{}`",
                        function.execution_space.as_str(),
                        function.name,
                        function.return_type
                    ));
                }
                for (name, ty) in &function.local_types {
                    if !is_device_safe_type(ty, struct_defs, enum_defs) {
                        violations.push(format!(
                            "{} function `{}` local `{}` uses unsupported device type `{}`",
                            function.execution_space.as_str(),
                            function.name,
                            name,
                            ty
                        ));
                    }
                }
            }
        }
    }
    violations
}

pub(crate) fn is_pure_safe_type(
    ty: &Type,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    is_device_scalar_type(ty)
        || matches!(ty, Type::Ptr { to, .. } if is_pure_safe_type(to, struct_defs, enum_defs))
        || matches!(ty, Type::Array { elem, .. } if is_pure_safe_type(elem, struct_defs, enum_defs))
        || matches!(ty, Type::Named { name, .. } if is_named_device_aggregate(name, struct_defs, enum_defs, true))
}

pub(crate) fn is_device_safe_type(
    ty: &Type,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    if is_device_scalar_type(ty) {
        return true;
    }
    match ty {
        Type::Ptr { to, .. } => is_device_safe_type(to, struct_defs, enum_defs),
        Type::Array { elem, .. } => is_device_safe_type(elem, struct_defs, enum_defs),
        Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
            is_pure_safe_type(&args[0], struct_defs, enum_defs)
        }
        Type::Named { name, .. } => is_named_device_aggregate(name, struct_defs, enum_defs, false),
        _ => false,
    }
}

pub(crate) fn is_named_device_aggregate(
    name: &str,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    pure_mode: bool,
) -> bool {
    if let Some(struct_def) = struct_defs.get(name) {
        return struct_def.fields.iter().all(|field| {
            if pure_mode {
                is_pure_safe_type(&field.ty, struct_defs, enum_defs)
            } else {
                is_device_safe_type(&field.ty, struct_defs, enum_defs)
            }
        });
    }
    if let Some(enum_def) = enum_defs.get(name) {
        return enum_def.variants.iter().all(|variant| {
            variant.payload.iter().all(|payload| {
                if pure_mode {
                    is_pure_safe_type(payload, struct_defs, enum_defs)
                } else {
                    is_device_safe_type(payload, struct_defs, enum_defs)
                }
            }) && variant.named_payload.iter().all(|field| {
                if pure_mode {
                    is_pure_safe_type(&field.ty, struct_defs, enum_defs)
                } else {
                    is_device_safe_type(&field.ty, struct_defs, enum_defs)
                }
            })
        });
    }
    false
}

pub(crate) fn is_device_scalar_type(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Void
            | Type::Bool
            | Type::SimdVector(_)
            | Type::SimdMask(_)
            | Type::TypeVar(_)
            | Type::Int {
                signed: true,
                bits: 32
            }
            | Type::Int {
                signed: false,
                bits: 32
            }
            | Type::Float { bits: 32 }
    )
}
