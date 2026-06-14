use super::*;

pub(crate) fn canonicalize_call_targets(module: &mut ast::Module) {
    let known_functions = collect_defined_function_names(module);
    let known_values = collect_defined_value_names(module);
    let reexported_functions = collect_reexported_function_aliases(module);
    for item in &mut module.items {
        if let ast::Item::Function(function) = item {
            let namespace = function
                .name
                .rsplit_once('.')
                .map(|(prefix, _)| prefix)
                .unwrap_or("");
            for stmt in &mut function.body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    &known_functions,
                    &known_values,
                    &reexported_functions,
                );
            }
        }
    }
}

pub(crate) fn collect_defined_function_names(module: &ast::Module) -> HashSet<String> {
    let mut out = HashSet::<String>::new();
    for item in &module.items {
        match item {
            ast::Item::Function(function) => {
                out.insert(function.name.clone());
            }
            ast::Item::Impl(item) => {
                let receiver = item.for_type.to_string();
                for method in &item.methods {
                    out.insert(format!("{receiver}.{}", method.name));
                }
            }
            _ => {}
        }
    }
    out
}

pub(crate) fn collect_reexported_function_aliases(module: &ast::Module) -> HashMap<String, String> {
    let known_functions = collect_defined_function_names(module);
    let mut out = HashMap::new();
    for import in &module.imports {
        if !import.is_pub || import.wildcard || import.path.is_empty() {
            continue;
        }
        let canonical = import.path.join(".");
        if !known_functions.contains(&canonical) {
            continue;
        }
        let alias = import.alias.clone().unwrap_or_else(|| {
            import
                .path
                .last()
                .cloned()
                .unwrap_or_else(|| canonical.clone())
        });
        out.insert(alias, canonical);
    }
    out
}

pub(crate) fn collect_defined_value_names(module: &ast::Module) -> HashSet<String> {
    let mut out = HashSet::<String>::new();
    for item in &module.items {
        match item {
            ast::Item::Const(item) => {
                out.insert(item.name.clone());
            }
            ast::Item::Static(item) => {
                out.insert(item.name.clone());
            }
            _ => {}
        }
    }
    out
}

pub(crate) fn canonicalize_stmt_calls(
    stmt: &mut ast::Stmt,
    namespace: &str,
    known_functions: &HashSet<String>,
    known_values: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => canonicalize_expr_calls(
            value,
            namespace,
            known_functions,
            known_values,
            reexported_functions,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for nested in then_body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            for nested in else_body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                canonicalize_stmt_calls(
                    init,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(condition) = condition {
                canonicalize_expr_calls(
                    condition,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(step) = step {
                canonicalize_stmt_calls(
                    step,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            canonicalize_expr_calls(
                iterable,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                canonicalize_stmt_calls(
                    nested,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            canonicalize_expr_calls(
                scrutinee,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    canonicalize_expr_calls(
                        guard,
                        namespace,
                        known_functions,
                        known_values,
                        reexported_functions,
                    );
                }
                canonicalize_expr_calls(
                    &mut arm.value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
    }
}

pub(crate) fn canonicalize_expr_calls(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
    known_values: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            *callee = canonicalize_callee(callee, namespace, known_functions, reexported_functions);
            if matches!(
                callee.as_str(),
                "spawn" | "thread.spawn" | "spawn_ctx" | "thread.spawn_ctx" | "task.group_spawn"
            ) {
                if let Some(task_ref) = args.first_mut() {
                    canonicalize_task_ref_expr(
                        task_ref,
                        namespace,
                        known_functions,
                        reexported_functions,
                    );
                }
            }
            for arg in args {
                canonicalize_expr_calls(
                    arg,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            canonicalize_expr_calls(
                base,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            if let Some(value_ref) = expr_path_name(expr) {
                let canonical = canonicalize_value_ref(&value_ref, namespace, known_values);
                if canonical != value_ref {
                    *expr = ast::Expr::Ident(canonical);
                }
            }
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            canonicalize_expr_calls(
                body,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Group(inner) => {
            canonicalize_expr_calls(
                inner,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Tuple(items) => {
            for item in items {
                canonicalize_expr_calls(
                    item,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            canonicalize_expr_calls(
                inner,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            canonicalize_expr_calls(
                try_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                catch_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                then_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                else_expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Match { scrutinee, arms } => {
            canonicalize_expr_calls(
                scrutinee,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    canonicalize_expr_calls(
                        guard,
                        namespace,
                        known_functions,
                        known_values,
                        reexported_functions,
                    );
                }
                canonicalize_expr_calls(
                    &mut arm.value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::While { condition, body } => {
            canonicalize_expr_calls(
                condition,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                canonicalize_stmt_calls(
                    init,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(condition) = condition {
                canonicalize_expr_calls(
                    condition,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            if let Some(step) = step {
                canonicalize_stmt_calls(
                    step,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            canonicalize_expr_calls(
                iterable,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                canonicalize_stmt_calls(
                    stmt,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Break(value) | ast::Expr::Return(value) => {
            if let Some(value) = value {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Continue => {}
        ast::Expr::Range { start, end, .. } => {
            canonicalize_expr_calls(
                start,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                end,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                canonicalize_expr_calls(
                    item,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                canonicalize_expr_calls(
                    value,
                    namespace,
                    known_functions,
                    known_values,
                    reexported_functions,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            canonicalize_expr_calls(
                base,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                index,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Unary { expr, .. } => {
            canonicalize_expr_calls(
                expr,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            canonicalize_expr_calls(
                left,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
            canonicalize_expr_calls(
                right,
                namespace,
                known_functions,
                known_values,
                reexported_functions,
            );
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
    }
}

pub(crate) fn expr_path_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::Group(inner) => expr_path_name(inner),
        ast::Expr::FieldAccess { base, field } => {
            let mut base_name = expr_path_name(base)?;
            base_name.push('.');
            base_name.push_str(field);
            Some(base_name)
        }
        _ => None,
    }
}

pub(crate) fn canonicalize_value_ref(
    value_ref: &str,
    namespace: &str,
    known_values: &HashSet<String>,
) -> String {
    if known_values.contains(value_ref) {
        return value_ref.to_string();
    }
    if value_ref.contains('.') {
        let mut scope = Some(namespace);
        while let Some(current) = scope {
            if !current.is_empty() {
                let candidate = format!("{current}.{value_ref}");
                if known_values.contains(&candidate) {
                    return candidate;
                }
            }
            scope = current.rsplit_once('.').map(|(parent, _)| parent);
        }
    } else {
        let candidate = qualify_name(namespace, value_ref);
        if known_values.contains(&candidate) {
            return candidate;
        }
    }
    value_ref.to_string()
}

pub(crate) fn canonicalize_callee(
    callee: &str,
    namespace: &str,
    known_functions: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    if let Some(target) = reexported_functions.get(base) {
        return format!("{target}{generic_suffix}");
    }
    if known_functions.contains(base) {
        return callee.to_string();
    }
    if base.contains('.') {
        let mut scope = Some(namespace);
        while let Some(current) = scope {
            if !current.is_empty() {
                let candidate = format!("{current}.{base}");
                if known_functions.contains(&candidate) {
                    return format!("{candidate}{generic_suffix}");
                }
            }
            scope = current.rsplit_once('.').map(|(parent, _)| parent);
        }
    } else {
        let candidate = qualify_name(namespace, base);
        if known_functions.contains(&candidate) {
            return format!("{candidate}{generic_suffix}");
        }
    }
    callee.to_string()
}

pub(crate) fn canonicalize_task_ref_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
    reexported_functions: &HashMap<String, String>,
) {
    let Some(task_ref) = expr_task_ref_name(expr) else {
        return;
    };
    let canonical =
        canonicalize_callee(&task_ref, namespace, known_functions, reexported_functions);
    if canonical == task_ref {
        return;
    }
    *expr = task_ref_expr_from_name(&canonical);
}

pub(crate) fn task_ref_expr_from_name(name: &str) -> ast::Expr {
    let mut segments = name.split('.');
    let head = segments.next().unwrap_or_default().to_string();
    let mut expr = ast::Expr::Ident(head);
    for segment in segments {
        expr = ast::Expr::FieldAccess {
            base: Box::new(expr),
            field: segment.to_string(),
        };
    }
    expr
}

