fn analyze_ownership(
    functions: &[TypedFunction],
    call_graph: &[(String, String)],
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let summaries = build_function_memory_summaries(functions);
    let ownership_summaries = build_function_ownership_summaries(functions);
    violations.extend(analyze_alias_and_provenance(functions));
    violations.extend(analyze_gpu_kernel_contracts(functions));
    violations.extend(analyze_atomic_ordering_claims(functions));
    violations.extend(analyze_live_borrow_consumption(functions));
    for function in functions {
        let seeded_owners = if function.is_extern {
            BTreeMap::new()
        } else {
            ownership_summaries
                .get(&function.name)
                .into_iter()
                .flat_map(|consumed| consumed.iter().copied())
                .filter_map(|index| function.params.get(index))
                .enumerate()
                .map(|(alloc_index, param)| (param.name.clone(), alloc_index + 1))
                .collect::<BTreeMap<_, _>>()
        };
        let mut state = OwnershipState {
            owner_candidates: function
                .params
                .iter()
                .map(|param| param.name.clone())
                .collect::<BTreeSet<_>>(),
            owners: seeded_owners,
            ..OwnershipState::default()
        };
        let mut next_alloc = state.owners.len() + 1;
        let _ = analyze_ownership_block(
            function,
            &function.body,
            &mut state,
            &mut next_alloc,
            &mut violations,
            &function.name,
            &ownership_summaries,
            struct_defs,
            enum_defs,
            None,
        );
        record_live_owner_leaks(&state, &mut violations, &function.name);
    }
    for (caller, callee) in call_graph {
        let Some(callee_summary) = summaries.get(callee) else {
            continue;
        };
        let Some(caller_summary) = summaries.get(caller) else {
            continue;
        };
        if callee_summary.unsafe_sites > 0
            && callee_summary.unsafe_reasoned_sites == 0
            && !callee_summary.unsafe_call_edge_covered
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` reaches unsafe code without invariant proof/reasoned contract",
            ));
        }
        if callee_summary.alloc_sites
            > callee_summary.free_sites
                + callee_summary.close_sites
                + callee_summary.returned_owned_sites
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` crosses function with potential resource escape (alloc/free+close imbalance)",
            ));
        }
        if caller_summary.is_async && caller_summary.has_await && callee_summary.has_mut_ref_params
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` can hold mutable borrows across await boundary",
            ));
        }
        if caller_summary.is_async
            && caller_summary.has_await
            && callee_summary.has_ref_params
            && callee_summary.returns_ref
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` can propagate borrowed references across async suspension boundary",
            ));
        }
        if (callee_summary.generic_param_count > 0 || callee_summary.trait_bound_count > 0)
            && callee_summary.has_ref_params
            && caller_summary.is_async
            && caller_summary.has_await
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` is generic/trait-heavy with borrowed parameters across await; inter-procedural lifetime summary rejected",
            ));
        }
    }
    violations
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OwnershipState {
    owners: BTreeMap<String, usize>,
    moved: BTreeSet<String>,
    maybe_moved: BTreeSet<String>,
    owner_candidates: BTreeSet<String>,
    deferred: BTreeSet<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LoopExitStates {
    breaks: Vec<OwnershipState>,
    continues: Vec<OwnershipState>,
}

fn record_live_owner_leaks(
    state: &OwnershipState,
    violations: &mut Vec<String>,
    function_name: &str,
) {
    for (name, alloc_id) in &state.owners {
        if state.deferred.contains(alloc_id) {
            continue;
        }
        violations.push(format!(
            "function `{}` leaks allocation id={} owned by `{}`",
            function_name, alloc_id, name
        ));
    }
}

fn build_function_ownership_summaries(
    functions: &[TypedFunction],
) -> BTreeMap<String, BTreeSet<usize>> {
    let mut summaries = functions
        .iter()
        .map(|function| (function.name.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut changed = true;
    while changed {
        changed = false;
        for function in functions {
            let next = infer_consumed_param_indices(function, &summaries);
            let entry = summaries.entry(function.name.clone()).or_default();
            if *entry != next {
                *entry = next;
                changed = true;
            }
        }
    }
    summaries
}

fn infer_consumed_param_indices(
    function: &TypedFunction,
    summaries: &BTreeMap<String, BTreeSet<usize>>,
) -> BTreeSet<usize> {
    let mut consumed = function
        .is_extern
        .then(|| {
            function
                .params
                .iter()
                .enumerate()
                .filter(|(_, param)| function.is_unsafe && param.name.ends_with("_owned"))
                .map(|(index, _)| index)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let param_indexes = function
        .params
        .iter()
        .enumerate()
        .map(|(index, param)| (param.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    collect_consumed_params_from_stmts(&function.body, &param_indexes, summaries, &mut consumed);
    consumed
}

fn collect_consumed_params_from_stmts(
    body: &[Stmt],
    param_indexes: &BTreeMap<&str, usize>,
    summaries: &BTreeMap<String, BTreeSet<usize>>,
    out: &mut BTreeSet<usize>,
) {
    for stmt in body {
        match stmt {
            Stmt::Let { value, .. }
            | Stmt::LetPattern { value, .. }
            | Stmt::Assign { value, .. }
            | Stmt::CompoundAssign { value, .. }
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value)
            | Stmt::Expr(value) => {
                collect_consumed_params_from_expr(value, param_indexes, summaries, out);
            }
            Stmt::Return(Some(expr)) => {
                collect_consumed_params_from_expr(expr, param_indexes, summaries, out);
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(then_body, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(else_body, param_indexes, summaries, out);
            }
            Stmt::While { condition, body } => {
                collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_consumed_params_from_stmts(
                        std::slice::from_ref(init.as_ref()),
                        param_indexes,
                        summaries,
                        out,
                    );
                }
                if let Some(condition) = condition {
                    collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
                }
                if let Some(step) = step {
                    collect_consumed_params_from_stmts(
                        std::slice::from_ref(step.as_ref()),
                        param_indexes,
                        summaries,
                        out,
                    );
                }
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::ForIn { iterable, body, .. } => {
                collect_consumed_params_from_expr(iterable, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::Loop { body } => {
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::Match { scrutinee, arms } => {
                collect_consumed_params_from_expr(scrutinee, param_indexes, summaries, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_consumed_params_from_expr(guard, param_indexes, summaries, out);
                    }
                    collect_consumed_params_from_expr(&arm.value, param_indexes, summaries, out);
                }
            }
            Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => {}
        }
    }
}

fn collect_consumed_params_from_expr(
    expr: &Expr,
    param_indexes: &BTreeMap<&str, usize>,
    summaries: &BTreeMap<String, BTreeSet<usize>>,
    out: &mut BTreeSet<usize>,
) {
    match expr {
        Expr::Call { callee, args } => {
            for name in consumed_arg_identity_names(callee, args, summaries) {
                if let Some(index) = param_indexes.get(name).copied() {
                    out.insert(index);
                }
            }
            for arg in args {
                collect_consumed_params_from_expr(arg, param_indexes, summaries, out);
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
            collect_consumed_params_from_expr(then_expr, param_indexes, summaries, out);
            collect_consumed_params_from_expr(else_expr, param_indexes, summaries, out);
        }
        Expr::Match { scrutinee, arms } => {
            collect_consumed_params_from_expr(scrutinee, param_indexes, summaries, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_consumed_params_from_expr(guard, param_indexes, summaries, out);
                }
                collect_consumed_params_from_expr(&arm.value, param_indexes, summaries, out);
            }
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_consumed_params_from_expr(try_expr, param_indexes, summaries, out);
            collect_consumed_params_from_expr(catch_expr, param_indexes, summaries, out);
        }
        Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Discard(inner)
        | Expr::Unary { expr: inner, .. } => {
            collect_consumed_params_from_expr(inner, param_indexes, summaries, out);
        }
        Expr::Binary { left, right, .. } => {
            collect_consumed_params_from_expr(left, param_indexes, summaries, out);
            collect_consumed_params_from_expr(right, param_indexes, summaries, out);
        }
        Expr::FieldAccess { base, .. } => {
            collect_consumed_params_from_expr(base, param_indexes, summaries, out);
        }
        Expr::Index { base, index } => {
            collect_consumed_params_from_expr(base, param_indexes, summaries, out);
            collect_consumed_params_from_expr(index, param_indexes, summaries, out);
        }
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_consumed_params_from_expr(value, param_indexes, summaries, out);
            }
        }
        Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for item in payload {
                collect_consumed_params_from_expr(item, param_indexes, summaries, out);
            }
            for (_, value) in named_payload {
                collect_consumed_params_from_expr(value, param_indexes, summaries, out);
            }
        }
        Expr::Tuple(items) | Expr::ArrayLiteral(items) => {
            for item in items {
                collect_consumed_params_from_expr(item, param_indexes, summaries, out);
            }
        }
        _ => {}
    }
}

fn expr_identity_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(name) => Some(name.as_str()),
        Expr::Group(inner) => expr_identity_name(inner),
        _ => None,
    }
}

fn expr_consumed_binding_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(name) => Some(name.as_str()),
        Expr::Group(inner)
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Index { base: inner, .. } => expr_consumed_binding_name(inner),
        _ => None,
    }
}

fn runtime_consumed_param_indices(callee: &str) -> &'static [usize] {
    match callee {
        "join"
        | "detach"
        | "cancel_task"
        | "task.group_join"
        | "task.group_join_all"
        | "task.group_cancel" => &[0],
        "proc.spawn_cmd" | "proc.run_cmd" | "proc.spawnl" | "proc.runl" => &[1, 2],
        _ if is_free_callee(callee) || is_close_callee(callee) => &[0],
        _ if callee.ends_with("http.write")
            || callee.ends_with("http.write_json")
            || callee.ends_with("http.write_response")
            || callee.ends_with("route.write_404")
            || callee.ends_with("route.write_405")
            || callee.ends_with("http.stream_close")
            || callee.ends_with("http.websocket_accept") =>
        {
            &[0]
        }
        _ if runtime_handle_contracts()
            .iter()
            .any(|contract| contract.consumer_intrinsics.contains(&callee)) =>
        {
            &[0]
        }
        _ => &[],
    }
}

fn consumed_arg_identity_names<'a>(
    callee: &str,
    args: &'a [Expr],
    summaries: &BTreeMap<String, BTreeSet<usize>>,
) -> Vec<&'a str> {
    let mut names = runtime_consumed_param_indices(callee)
        .iter()
        .filter_map(|index| args.get(*index))
        .filter_map(expr_consumed_binding_name)
        .collect::<Vec<_>>();
    if let Some(consumed_params) = summaries.get(callee) {
        for consumed_index in consumed_params {
            if let Some(name) = args
                .get(*consumed_index)
                .and_then(expr_consumed_binding_name)
            {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReturnProvenanceSummary {
    Param(usize),
    Fresh,
    Unknown,
}

#[derive(Debug, Clone)]
struct CallShape {
    params: Vec<ast::Param>,
    return_type: Type,
    is_extern: bool,
    is_unsafe: bool,
    return_provenance: ReturnProvenanceSummary,
}

fn analyze_unsafe_context_violations(functions: &[TypedFunction]) -> Vec<String> {
    fn analyze_stmt(
        function_name: &str,
        stmt: &Stmt,
        in_unsafe_context: bool,
        unsafe_functions: &BTreeSet<String>,
        violations: &mut Vec<String>,
    ) {
        match stmt {
            Stmt::Let { value, .. }
            | Stmt::LetPattern { value, .. }
            | Stmt::Assign { value, .. }
            | Stmt::CompoundAssign { value, .. }
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value)
            | Stmt::Expr(value) => analyze_expr(
                function_name,
                value,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Stmt::Return(value) => {
                if let Some(value) = value {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for nested in then_body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                for nested in else_body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::While { condition, body } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
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
                if let Some(init) = init {
                    analyze_stmt(
                        function_name,
                        init,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                if let Some(condition) = condition {
                    analyze_expr(
                        function_name,
                        condition,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                if let Some(step) = step {
                    analyze_stmt(
                        function_name,
                        step,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::ForIn { iterable, body, .. } => {
                analyze_expr(
                    function_name,
                    iterable,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::Loop { body } => {
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::Match { scrutinee, arms } => {
                analyze_expr(
                    function_name,
                    scrutinee,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        analyze_expr(
                            function_name,
                            guard,
                            in_unsafe_context,
                            unsafe_functions,
                            violations,
                        );
                    }
                    analyze_expr(
                        function_name,
                        &arm.value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::Break(_) | Stmt::Continue => {}
        }
    }

    fn analyze_expr(
        function_name: &str,
        expr: &Expr,
        in_unsafe_context: bool,
        unsafe_functions: &BTreeSet<String>,
        violations: &mut Vec<String>,
    ) {
        match expr {
            Expr::Call { callee, args } => {
                if !in_unsafe_context {
                    if let Some(unsafe_callee) = resolve_unsafe_callee(unsafe_functions, callee) {
                        violations.push(format!(
                            "function `{}` calls unsafe function `{}` outside `unsafe` context",
                            function_name, unsafe_callee
                        ));
                    }
                }
                for arg in args {
                    analyze_expr(
                        function_name,
                        arg,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::UnsafeBlock { body, .. } => {
                for stmt in body {
                    analyze_stmt(function_name, stmt, true, unsafe_functions, violations);
                }
            }
            Expr::FieldAccess { base, .. } => analyze_expr(
                function_name,
                base,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::EnumInit { payload, .. } => {
                for value in payload {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Tuple(items) => {
                for item in items {
                    analyze_expr(
                        function_name,
                        item,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Closure { body, .. } => analyze_expr(
                function_name,
                body,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Expr::Group(inner)
            | Expr::Await(inner)
            | Expr::Discard(inner)
            | Expr::Unary { expr: inner, .. } => analyze_expr(
                function_name,
                inner,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                analyze_expr(
                    function_name,
                    try_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    catch_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
            }
            Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    then_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    else_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
            }
            Expr::Match { scrutinee, arms } => {
                analyze_expr(
                    function_name,
                    scrutinee,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        analyze_expr(
                            function_name,
                            guard,
                            in_unsafe_context,
                            unsafe_functions,
                            violations,
                        );
                    }
                    analyze_expr(
                        function_name,
                        &arm.value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::While { condition, body } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
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
                if let Some(init) = init {
                    analyze_stmt(
                        function_name,
                        init,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                if let Some(condition) = condition {
                    analyze_expr(
                        function_name,
                        condition,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                if let Some(step) = step {
                    analyze_stmt(
                        function_name,
                        step,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::ForIn { iterable, body, .. } => {
                analyze_expr(
                    function_name,
                    iterable,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Loop { body } => {
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Return(value) | Expr::Break(value) => {
                if let Some(value) = value {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Continue => {}
            Expr::Binary { left, right, .. }
            | Expr::Range {
                start: left,
                end: right,
                ..
            } => {
                analyze_expr(
                    function_name,
                    left,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    right,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
            }
            Expr::ArrayLiteral(items) => {
                for item in items {
                    analyze_expr(
                        function_name,
                        item,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::ObjectLiteral(fields) => {
                for (_, value) in fields {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Index { base, index } => {
                analyze_expr(
                    function_name,
                    base,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    index,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
            }
            Expr::Int(_)
            | Expr::Float { .. }
            | Expr::Char(_)
            | Expr::Bool(_)
            | Expr::Str(_)
            | Expr::Ident(_) => {}
        }
    }

    let unsafe_functions = functions
        .iter()
        .filter(|function| function.is_unsafe)
        .map(|function| function.name.clone())
        .collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for function in functions {
        let context = function.is_unsafe;
        for stmt in &function.body {
            analyze_stmt(
                &function.name,
                stmt,
                context,
                &unsafe_functions,
                &mut violations,
            );
        }
    }
    violations
}

fn resolve_unsafe_callee(unsafe_functions: &BTreeSet<String>, callee: &str) -> Option<String> {
    if unsafe_functions.contains(callee) {
        return Some(callee.to_string());
    }
    let suffix = format!(".{callee}");
    let mut matched: Option<String> = None;
    for candidate in unsafe_functions {
        if candidate.ends_with(&suffix) || candidate == callee {
            if matched.is_some() {
                return None;
            }
            matched = Some(candidate.clone());
        }
    }
    matched
}

fn analyze_ownership_block(
    function: &TypedFunction,
    body: &[Stmt],
    state: &mut OwnershipState,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    mut loop_exits: Option<&mut LoopExitStates>,
) -> bool {
    for stmt in body {
        for name in state.moved.iter() {
            if stmt_uses_ident(stmt, name) {
                violations.push(format!(
                    "function `{}` uses moved value `{}` after move/consume",
                    function_name, name
                ));
            }
        }
        for name in state.maybe_moved.iter() {
            if stmt_uses_ident(stmt, name) {
                violations.push(format!(
                    "function `{}` uses conditionally consumed value `{}` after path-sensitive ownership merge",
                    function_name, name
                ));
            }
        }
        match stmt {
            Stmt::Let {
                name, value, ty, ..
            } => {
                analyze_expr_value_ownership(
                    function,
                    value,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                state.owner_candidates.insert(name.clone());
                if binding_creates_owned_resource(function, name, ty.as_ref(), value) {
                    state.owners.insert(name.clone(), *next_alloc);
                    *next_alloc += 1;
                    state.moved.remove(name);
                    state.maybe_moved.remove(name);
                }
                if let Some(from) = expr_identity_name(value) {
                    if let Some(owner) = state.owners.remove(from) {
                        state.owners.insert(name.clone(), owner);
                        state.moved.insert(from.to_string());
                        state.moved.remove(name);
                        state.maybe_moved.remove(name);
                    }
                }
                if is_partial_move_expr(function, value, &state.owners, struct_defs, enum_defs) {
                    violations.push(format!(
                        "function `{}` performs partial move from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::LetPattern { pattern, value, .. } => {
                analyze_expr_value_ownership(
                    function,
                    value,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                collect_pattern_bindings(pattern, &mut state.owner_candidates);
                if is_partial_move_expr(function, value, &state.owners, struct_defs, enum_defs)
                    || pattern_performs_partial_move(
                        pattern,
                        function,
                        value,
                        struct_defs,
                        enum_defs,
                    )
                {
                    violations.push(format!(
                        "function `{}` performs partial move from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::Assign { target, value } => {
                analyze_expr_value_ownership(
                    function,
                    value,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                state.owner_candidates.insert(target.clone());
                if let Some(from) = expr_identity_name(value) {
                    if let Some(owner) = state.owners.remove(from) {
                        state.owners.insert(target.clone(), owner);
                        state.moved.insert(from.to_string());
                    }
                }
                state.moved.remove(target);
                state.maybe_moved.remove(target);
                if is_partial_move_expr(function, value, &state.owners, struct_defs, enum_defs) {
                    violations.push(format!(
                        "function `{}` performs partial move assignment from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::CompoundAssign { target, value, .. } => {
                analyze_expr_value_ownership(
                    function,
                    value,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                state.owner_candidates.insert(target.clone());
                if let Some(from) = expr_identity_name(value) {
                    if let Some(owner) = state.owners.remove(from) {
                        state.owners.insert(target.clone(), owner);
                        state.moved.insert(from.to_string());
                    }
                }
                state.moved.remove(target);
                state.maybe_moved.remove(target);
            }
            Stmt::Expr(Expr::Call { callee, args }) => {
                if callee == "free"
                    || callee.ends_with(".free")
                    || callee == "close"
                    || callee.ends_with(".close")
                {
                    if let Some(name) = args.first().and_then(expr_consumed_binding_name) {
                        if let Some(owner) = state.owners.remove(name) {
                            if state.deferred.contains(&owner) {
                                violations.push(format!(
                                    "function `{}` consumes value `{}` after scheduling deferred cleanup for the same owner",
                                    function_name, name
                                ));
                            }
                            state.moved.insert(name.to_string());
                            state.maybe_moved.remove(name);
                        } else {
                            violations.push(format!(
                                "function `{}` consumes non-owned or already-consumed value `{}` via `{}`",
                                function_name, name, callee
                            ));
                        }
                    }
                }
                apply_call_consumed_params(callee, args, state, ownership_summaries);
            }
            Stmt::Defer(expr) => {
                register_deferred_cleanup(expr, state, violations, function_name);
            }
            Stmt::Expr(Expr::UnsafeBlock { body, .. }) => {
                if !analyze_ownership_block(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                ) {
                    return false;
                }
            }
            Stmt::Return(Some(expr)) => {
                analyze_terminal_return_expr(
                    function,
                    expr,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                );
                return false;
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                analyze_expr_value_ownership(
                    function,
                    condition,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                let entry_state = state.clone();
                let mut then_state = state.clone();
                let mut else_state = state.clone();
                let then_fallthrough = analyze_ownership_block(
                    function,
                    then_body,
                    &mut then_state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                let else_fallthrough = analyze_ownership_block(
                    function,
                    else_body,
                    &mut else_state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                *state = match (then_fallthrough, else_fallthrough) {
                    (true, true) => merge_ownership_states(
                        function_name,
                        "conditional branches",
                        &entry_state,
                        &[then_state, else_state],
                        violations,
                    ),
                    (true, false) => then_state,
                    (false, true) => else_state,
                    (false, false) => return false,
                };
            }
            Stmt::While { condition, body } => {
                analyze_expr_value_ownership(
                    function,
                    condition,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                if !analyze_loop_ownership(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    !matches!(condition, Expr::Bool(true)),
                ) {
                    return false;
                }
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    let _ = analyze_ownership_block(
                        function,
                        std::slice::from_ref(init.as_ref()),
                        state,
                        next_alloc,
                        violations,
                        function_name,
                        ownership_summaries,
                        struct_defs,
                        enum_defs,
                        None,
                    );
                }
                if let Some(condition) = condition {
                    analyze_expr_value_ownership(
                        function,
                        condition,
                        state,
                        next_alloc,
                        violations,
                        function_name,
                        ownership_summaries,
                        struct_defs,
                        enum_defs,
                        None,
                    );
                }
                let mut loop_body = body.to_vec();
                if let Some(step) = step {
                    loop_body.push((**step).clone());
                }
                if !analyze_loop_ownership(
                    function,
                    &loop_body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    true,
                ) {
                    return false;
                }
            }
            Stmt::ForIn {
                binding,
                iterable,
                body,
            } => {
                analyze_expr_value_ownership(
                    function,
                    iterable,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                state.moved.remove(binding);
                state.maybe_moved.remove(binding);
                state.owner_candidates.insert(binding.clone());
                if !analyze_loop_ownership(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    true,
                ) {
                    return false;
                }
            }
            Stmt::Loop { body } => {
                if !analyze_loop_ownership(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    false,
                ) {
                    return false;
                }
            }
            Stmt::Break(_) => {
                if let Some(loop_exits) = loop_exits.as_deref_mut() {
                    loop_exits.breaks.push(state.clone());
                }
                return false;
            }
            Stmt::Continue => {
                if let Some(loop_exits) = loop_exits.as_deref_mut() {
                    loop_exits.continues.push(state.clone());
                }
                return false;
            }
            Stmt::Match { scrutinee, arms } => {
                analyze_expr_value_ownership(
                    function,
                    scrutinee,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                let entry_state = state.clone();
                let mut arm_states = Vec::new();
                for arm in arms {
                    let mut arm_state = state.clone();
                    if pattern_performs_partial_move(
                        &arm.pattern,
                        function,
                        scrutinee,
                        struct_defs,
                        enum_defs,
                    ) {
                        violations.push(format!(
                            "function `{}` performs partial move from owned aggregate; partial moves are forbidden in v0",
                            function_name
                        ));
                    }
                    if let Some(guard) = &arm.guard {
                        analyze_expr_value_ownership(
                            function,
                            guard,
                            &mut arm_state,
                            next_alloc,
                            violations,
                            function_name,
                            ownership_summaries,
                            struct_defs,
                            enum_defs,
                            None,
                        );
                    }
                    analyze_expr_value_ownership(
                        function,
                        &arm.value,
                        &mut arm_state,
                        next_alloc,
                        violations,
                        function_name,
                        ownership_summaries,
                        struct_defs,
                        enum_defs,
                        None,
                    );
                    arm_states.push(arm_state);
                }
                if !arm_states.is_empty() {
                    *state = merge_ownership_states(
                        function_name,
                        "match arms",
                        &entry_state,
                        &arm_states,
                        violations,
                    );
                }
            }
            Stmt::Expr(expr) => {
                analyze_expr_value_ownership(
                    function,
                    expr,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
            }
            Stmt::Return(None) => {
                record_live_owner_leaks(state, violations, function_name);
                return false;
            }
            Stmt::Requires(_) | Stmt::Ensures(_) => {}
        }
    }
    true
}

fn analyze_expr_value_ownership(
    function: &TypedFunction,
    expr: &Expr,
    state: &mut OwnershipState,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    mut loop_exits: Option<&mut LoopExitStates>,
) {
    match expr {
        Expr::Call { callee, args } if is_free_callee(callee) || is_close_callee(callee) => {
            if let Some(name) = args.first().and_then(expr_consumed_binding_name) {
                if let Some(owner) = state.owners.remove(name) {
                    if state.deferred.contains(&owner) {
                        violations.push(format!(
                            "function `{}` consumes value `{}` after scheduling deferred cleanup for the same owner",
                            function_name, name
                        ));
                    }
                    state.moved.insert(name.to_string());
                    state.maybe_moved.remove(name);
                } else {
                    violations.push(format!(
                        "function `{}` consumes non-owned or already-consumed value `{}` via `{}`",
                        function_name, name, callee
                    ));
                }
            }
        }
        Expr::Call { callee, args } => {
            apply_call_consumed_params(callee, args, state, ownership_summaries);
            for arg in args {
                analyze_expr_value_ownership(
                    function,
                    arg,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            let _ = analyze_ownership_block(
                function,
                body,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
        }
        Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Discard(inner)
        | Expr::Unary { expr: inner, .. } => {
            analyze_expr_value_ownership(
                function,
                inner,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                loop_exits.as_deref_mut(),
            );
        }
        Expr::Binary { left, right, .. } => {
            analyze_expr_value_ownership(
                function,
                left,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            analyze_expr_value_ownership(
                function,
                right,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
        }
        Expr::FieldAccess { base, .. } => {
            analyze_expr_value_ownership(
                function,
                base,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
        }
        Expr::Index { base, index } => {
            analyze_expr_value_ownership(
                function,
                base,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            analyze_expr_value_ownership(
                function,
                index,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let entry_state = state.clone();
            let mut try_state = state.clone();
            let mut catch_state = state.clone();
            analyze_expr_value_ownership(
                function,
                try_expr,
                &mut try_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            consume_value_result_owner(try_expr, &mut try_state);
            analyze_expr_value_ownership(
                function,
                catch_expr,
                &mut catch_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            consume_value_result_owner(catch_expr, &mut catch_state);
            *state = merge_ownership_states(
                function_name,
                "try/catch expressions",
                &entry_state,
                &[try_state, catch_state],
                violations,
            );
        }
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let entry_state = state.clone();
            let mut then_state = state.clone();
            let mut else_state = state.clone();
            analyze_expr_value_ownership(
                function,
                then_expr,
                &mut then_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            consume_value_result_owner(then_expr, &mut then_state);
            analyze_expr_value_ownership(
                function,
                else_expr,
                &mut else_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            consume_value_result_owner(else_expr, &mut else_state);
            *state = merge_ownership_states(
                function_name,
                "conditional expressions",
                &entry_state,
                &[then_state, else_state],
                violations,
            );
        }
        Expr::Match { arms, .. } => {
            let entry_state = state.clone();
            let mut arm_states = Vec::new();
            for arm in arms {
                let mut arm_state = state.clone();
                analyze_expr_value_ownership(
                    function,
                    &arm.value,
                    &mut arm_state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                consume_value_result_owner(&arm.value, &mut arm_state);
                arm_states.push(arm_state);
            }
            if !arm_states.is_empty() {
                *state = merge_ownership_states(
                    function_name,
                    "match expressions",
                    &entry_state,
                    &arm_states,
                    violations,
                );
            }
        }
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                analyze_expr_value_ownership(
                    function,
                    value,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
            }
        }
        Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for item in payload {
                analyze_expr_value_ownership(
                    function,
                    item,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
            }
            for (_, value) in named_payload {
                analyze_expr_value_ownership(
                    function,
                    value,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
            }
        }
        Expr::Tuple(items) | Expr::ArrayLiteral(items) => {
            for item in items {
                analyze_expr_value_ownership(
                    function,
                    item,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
            }
        }
        _ => {}
    }
}

fn analyze_terminal_return_expr(
    function: &TypedFunction,
    expr: &Expr,
    state: &mut OwnershipState,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) {
    match expr {
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            analyze_expr_value_ownership(
                function,
                condition,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            let mut then_state = state.clone();
            analyze_terminal_return_expr(
                function,
                then_expr,
                &mut then_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
            );
            let mut else_state = state.clone();
            analyze_terminal_return_expr(
                function,
                else_expr,
                &mut else_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
            );
        }
        Expr::Match { scrutinee, arms } => {
            analyze_expr_value_ownership(
                function,
                scrutinee,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            for arm in arms {
                let mut arm_state = state.clone();
                if let Some(guard) = &arm.guard {
                    analyze_expr_value_ownership(
                        function,
                        guard,
                        &mut arm_state,
                        next_alloc,
                        violations,
                        function_name,
                        ownership_summaries,
                        struct_defs,
                        enum_defs,
                        None,
                    );
                }
                analyze_terminal_return_expr(
                    function,
                    &arm.value,
                    &mut arm_state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                );
            }
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let mut try_state = state.clone();
            analyze_terminal_return_expr(
                function,
                try_expr,
                &mut try_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
            );
            let mut catch_state = state.clone();
            analyze_terminal_return_expr(
                function,
                catch_expr,
                &mut catch_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
            );
        }
        _ => {
            analyze_expr_value_ownership(
                function,
                expr,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            consume_value_result_owner(expr, state);
            record_live_owner_leaks(state, violations, function_name);
        }
    }
    *state = OwnershipState::default();
}

#[allow(clippy::too_many_arguments)]
fn analyze_loop_ownership(
    function: &TypedFunction,
    body: &[Stmt],
    state: &mut OwnershipState,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    can_skip_loop: bool,
) -> bool {
    let entry_state = state.clone();
    let mut header_state = entry_state.clone();
    let mut break_states = Vec::<OwnershipState>::new();

    for _ in 0..8 {
        let mut iteration_state = header_state.clone();
        let mut exits = LoopExitStates::default();
        let falls_through = analyze_ownership_block(
            function,
            body,
            &mut iteration_state,
            next_alloc,
            violations,
            function_name,
            ownership_summaries,
            struct_defs,
            enum_defs,
            Some(&mut exits),
        );

        let mut backedge_states = vec![entry_state.clone()];
        if falls_through {
            backedge_states.push(iteration_state);
        }
        backedge_states.extend(exits.continues.into_iter());
        let next_header = merge_ownership_states(
            function_name,
            "loop iterations",
            &entry_state,
            &backedge_states,
            violations,
        );
        let next_breaks = exits.breaks;
        if next_header == header_state && next_breaks == break_states {
            break;
        }
        header_state = next_header;
        break_states = next_breaks;
    }

    let mut post_loop_states = Vec::new();
    if can_skip_loop {
        post_loop_states.push(header_state);
    }
    post_loop_states.extend(break_states);
    if post_loop_states.is_empty() {
        return false;
    }
    *state = merge_ownership_states(
        function_name,
        "loop exits",
        &entry_state,
        &post_loop_states,
        violations,
    );
    true
}

fn apply_call_consumed_params(
    callee: &str,
    args: &[Expr],
    state: &mut OwnershipState,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
) {
    for arg_name in consumed_arg_identity_names(callee, args, ownership_summaries) {
        if let Some(owner) = state.owners.remove(arg_name) {
            state.moved.insert(arg_name.to_string());
            state.maybe_moved.remove(arg_name);
            state.deferred.remove(&owner);
        }
    }
}

fn consume_value_result_owner(expr: &Expr, state: &mut OwnershipState) {
    if let Some(name) = expr_identity_name(expr) {
        if let Some(owner) = state.owners.remove(name) {
            state.moved.insert(name.to_string());
            state.maybe_moved.remove(name);
            state.deferred.remove(&owner);
        }
    }
}

fn merge_ownership_states(
    function_name: &str,
    control_kind: &str,
    entry_state: &OwnershipState,
    branches: &[OwnershipState],
    violations: &mut Vec<String>,
) -> OwnershipState {
    let mut merged = OwnershipState::default();
    merged.deferred.extend(entry_state.deferred.iter().copied());
    let mut names = BTreeSet::<String>::new();
    names.extend(entry_state.owners.keys().cloned());
    names.extend(entry_state.owner_candidates.iter().cloned());
    names.extend(entry_state.moved.iter().cloned());
    names.extend(entry_state.maybe_moved.iter().cloned());
    for branch in branches {
        merged.deferred.extend(branch.deferred.iter().copied());
    }
    for name in names {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum MergeClass {
            Owned(usize),
            Moved,
            MaybeMoved,
            Clear,
        }

        let classes = branches
            .iter()
            .map(|branch| {
                if let Some(owner) = branch.owners.get(&name).copied() {
                    MergeClass::Owned(owner)
                } else if branch.moved.contains(&name) {
                    MergeClass::Moved
                } else if branch.maybe_moved.contains(&name) {
                    MergeClass::MaybeMoved
                } else {
                    MergeClass::Clear
                }
            })
            .collect::<Vec<_>>();
        if classes.windows(2).any(|window| window[0] != window[1]) {
            violations.push(format!(
                "function `{}` has divergent ownership state for `{}` across {}; rewrite control flow so ownership is consistent on every path",
                function_name, name, control_kind
            ));
        }
        match classes.first().copied().unwrap_or(MergeClass::Clear) {
            MergeClass::Owned(owner_id)
                if classes
                    .iter()
                    .all(|class| *class == MergeClass::Owned(owner_id)) =>
            {
                merged.owners.insert(name.clone(), owner_id);
            }
            MergeClass::Moved if classes.iter().all(|class| *class == MergeClass::Moved) => {
                merged.moved.insert(name.clone());
            }
            MergeClass::Clear if classes.iter().all(|class| *class == MergeClass::Clear) => {}
            _ => {
                if classes.iter().any(|class| *class != MergeClass::Clear) {
                    merged.maybe_moved.insert(name.clone());
                }
            }
        }
        if entry_state.owner_candidates.contains(&name)
            || branches
                .iter()
                .any(|branch| branch.owner_candidates.contains(&name))
        {
            merged.owner_candidates.insert(name);
        }
    }
    merged
}

fn register_deferred_cleanup(
    expr: &Expr,
    state: &mut OwnershipState,
    violations: &mut Vec<String>,
    function_name: &str,
) {
    let mut resources = BTreeSet::new();
    collect_cleanup_targets(expr, &mut resources);
    for name in resources {
        let Some(owner) = state.owners.get(&name).copied() else {
            violations.push(format!(
                "function `{}` schedules deferred cleanup for non-owned or already-consumed value `{}`",
                function_name, name
            ));
            continue;
        };
        if !state.deferred.insert(owner) {
            violations.push(format!(
                "function `{}` schedules deferred cleanup more than once for `{}`",
                function_name, name
            ));
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FunctionMemorySummary {
    alloc_sites: usize,
    free_sites: usize,
    close_sites: usize,
    returned_owned_sites: usize,
    unsafe_sites: usize,
    unsafe_reasoned_sites: usize,
    unsafe_call_edge_covered: bool,
    has_mut_ref_params: bool,
    has_ref_params: bool,
    returns_ref: bool,
    generic_param_count: usize,
    trait_bound_count: usize,
    has_await: bool,
    is_async: bool,
}

fn unsafe_contract_counts_as_call_edge_covered(site: &UnsafeContractSite) -> bool {
    unsafe_contract_metadata_complete(site) && unsafe_contract_invariant_is_specific(site)
}

fn build_function_memory_summaries(
    functions: &[TypedFunction],
) -> BTreeMap<String, FunctionMemorySummary> {
    let mut out = BTreeMap::new();
    let signatures = build_call_shapes(functions);
    let extern_unsafe_c_imports = functions
        .iter()
        .filter(|function| {
            function.is_extern
                && function.is_unsafe
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        })
        .map(|function| function.name.clone())
        .collect::<BTreeSet<_>>();
    let mut unsafe_reasoned_sites_by_function = BTreeMap::<String, usize>::new();
    for site in collect_unsafe_contract_sites(functions)
        .into_iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .filter(unsafe_contract_counts_as_call_edge_covered)
    {
        *unsafe_reasoned_sites_by_function
            .entry(site.function.clone())
            .or_insert(0) += 1;
    }
    for function in functions {
        let mut alloc_sites = 0usize;
        let mut free_sites = 0usize;
        let mut close_sites = 0usize;
        let returned_owned_sites = count_owned_return_transfers(function, &signatures);
        let mut unsafe_sites = 0usize;
        let mut has_await = false;
        if function.is_unsafe {
            unsafe_sites += 1;
        }
        struct Collector<'a> {
            alloc_sites: &'a mut usize,
            free_sites: &'a mut usize,
            close_sites: &'a mut usize,
            unsafe_sites: &'a mut usize,
            has_await: &'a mut bool,
        }
        impl AstVisitor for Collector<'_> {
            fn visit_expr(&mut self, expr: &Expr) {
                match expr {
                    Expr::Call { callee, args } => {
                        if is_alloc_callee(callee) {
                            *self.alloc_sites += 1;
                        }
                        if is_free_callee(callee) {
                            *self.free_sites += 1;
                        }
                        if is_close_callee(callee) {
                            *self.close_sites += 1;
                        }
                        let _ = args;
                    }
                    Expr::UnsafeBlock { .. } => {
                        *self.unsafe_sites += 1;
                    }
                    Expr::Await(_) => {
                        *self.has_await = true;
                    }
                    _ => {}
                }
                ast::walk_expr(self, expr);
            }
        }
        let mut collector = Collector {
            alloc_sites: &mut alloc_sites,
            free_sites: &mut free_sites,
            close_sites: &mut close_sites,
            unsafe_sites: &mut unsafe_sites,
            has_await: &mut has_await,
        };
        for stmt in &function.body {
            collector.visit_stmt(stmt);
        }
        let has_mut_ref_params = function
            .params
            .iter()
            .any(|param| matches!(param.ty, Type::Ref { mutable: true, .. }));
        let has_ref_params = function
            .params
            .iter()
            .any(|param| matches!(param.ty, Type::Ref { .. }));
        let returns_ref = matches!(function.return_type, Type::Ref { .. });
        let generic_param_count = function.generics.len();
        let trait_bound_count = function
            .generics
            .iter()
            .map(|g| g.bounds.len())
            .sum::<usize>();
        let unsafe_reasoned_sites = unsafe_reasoned_sites_by_function
            .get(&function.name)
            .copied()
            .unwrap_or(0);
        out.insert(
            function.name.clone(),
            FunctionMemorySummary {
                alloc_sites,
                free_sites,
                close_sites,
                returned_owned_sites,
                unsafe_sites,
                unsafe_reasoned_sites,
                unsafe_call_edge_covered: is_zero_arg_extern_unsafe_c_import(function)
                    || is_documented_ffi_import_wrapper(function, &extern_unsafe_c_imports),
                has_mut_ref_params,
                has_ref_params,
                returns_ref,
                generic_param_count,
                trait_bound_count,
                has_await,
                is_async: function.is_async,
            },
        );
    }
    out
}

pub fn count_module_owned_return_transfers(functions: &[TypedFunction]) -> usize {
    let signatures = build_call_shapes(functions);
    functions
        .iter()
        .map(|function| count_owned_return_transfers(function, &signatures))
        .sum()
}

fn count_owned_return_transfers(
    function: &TypedFunction,
    signatures: &BTreeMap<String, CallShape>,
) -> usize {
    fn count_expr(expr: &Expr, signatures: &BTreeMap<String, CallShape>) -> usize {
        match expr {
            Expr::Group(inner) => count_expr(inner, signatures),
            Expr::UnsafeBlock { body, .. } => body
                .iter()
                .map(|stmt| count_stmt(stmt, signatures))
                .sum::<usize>(),
            Expr::If {
                then_expr,
                else_expr,
                ..
            } => count_expr(then_expr, signatures) + count_expr(else_expr, signatures),
            Expr::Match { arms, .. } => arms
                .iter()
                .map(|arm| count_expr(&arm.value, signatures))
                .sum(),
            Expr::Call { callee, .. } => usize::from(
                is_alloc_expr(expr)
                    || signatures
                        .get(callee)
                        .is_some_and(|shape| is_owned_transfer_return_type(&shape.return_type)),
            ),
            _ => usize::from(is_owned_return_transfer_expr(expr)),
        }
    }

    fn count_stmt(stmt: &Stmt, signatures: &BTreeMap<String, CallShape>) -> usize {
        match stmt {
            Stmt::Return(Some(expr)) => count_expr(expr, signatures),
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                then_body
                    .iter()
                    .map(|stmt| count_stmt(stmt, signatures))
                    .sum::<usize>()
                    + else_body
                        .iter()
                        .map(|stmt| count_stmt(stmt, signatures))
                        .sum::<usize>()
            }
            Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::ForIn { body, .. } => {
                body.iter().map(|stmt| count_stmt(stmt, signatures)).sum()
            }
            Stmt::For {
                init, step, body, ..
            } => {
                init.as_deref()
                    .map(|stmt| count_stmt(stmt, signatures))
                    .unwrap_or(0)
                    + step
                        .as_deref()
                        .map(|stmt| count_stmt(stmt, signatures))
                        .unwrap_or(0)
                    + body
                        .iter()
                        .map(|stmt| count_stmt(stmt, signatures))
                        .sum::<usize>()
            }
            Stmt::Match { arms, .. } => arms
                .iter()
                .map(|arm| count_expr(&arm.value, signatures))
                .sum(),
            _ => 0,
        }
    }

    function
        .body
        .iter()
        .map(|stmt| count_stmt(stmt, signatures))
        .sum()
}

fn is_owned_return_transfer_expr(expr: &Expr) -> bool {
    expr_identity_name(expr).is_some() || is_alloc_expr(expr)
}

fn intersect_identity_sets(left: BTreeSet<String>, right: BTreeSet<String>) -> BTreeSet<String> {
    left.intersection(&right).cloned().collect()
}

fn terminal_return_identity_names_on_all_paths(expr: &Expr) -> BTreeSet<String> {
    match expr {
        Expr::Ident(name) => BTreeSet::from([name.clone()]),
        Expr::Group(inner) | Expr::Discard(inner) => {
            terminal_return_identity_names_on_all_paths(inner)
        }
        Expr::UnsafeBlock { body, .. } => body
            .last()
            .map(|stmt| match stmt {
                Stmt::Expr(expr) | Stmt::Return(Some(expr)) => {
                    terminal_return_identity_names_on_all_paths(expr)
                }
                _ => BTreeSet::new(),
            })
            .unwrap_or_default(),
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => intersect_identity_sets(
            terminal_return_identity_names_on_all_paths(then_expr),
            terminal_return_identity_names_on_all_paths(else_expr),
        ),
        Expr::Match { arms, .. } => {
            let mut arm_sets = arms
                .iter()
                .map(|arm| terminal_return_identity_names_on_all_paths(&arm.value));
            let Some(first) = arm_sets.next() else {
                return BTreeSet::new();
            };
            arm_sets.fold(first, intersect_identity_sets)
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => intersect_identity_sets(
            terminal_return_identity_names_on_all_paths(try_expr),
            terminal_return_identity_names_on_all_paths(catch_expr),
        ),
        _ => BTreeSet::new(),
    }
}

fn is_owned_transfer_return_type(ty: &Type) -> bool {
    matches!(ty, Type::Ptr { .. }) || is_linear_type(ty)
}

fn unsafe_contract_counts_as_reasoned(site: &UnsafeContractSite) -> bool {
    unsafe_contract_metadata_complete(site)
        && unsafe_contract_invariant_is_specific(site)
        && unsafe_contract_has_independent_proof(site)
}

fn unsafe_contract_metadata_complete(site: &UnsafeContractSite) -> bool {
    site.reason.as_deref().is_some_and(|v| !v.is_empty())
        && site.invariant.as_deref().is_some_and(|v| !v.is_empty())
        && site.owner.as_deref().is_some_and(|v| !v.is_empty())
        && site.scope.as_deref().is_some_and(|v| !v.is_empty())
        && site.risk_class.as_deref().is_some_and(|v| !v.is_empty())
        && site.proof_ref.as_deref().is_some_and(|v| !v.is_empty())
}

fn unsafe_contract_invariant_is_specific(site: &UnsafeContractSite) -> bool {
    site.owner
        .as_deref()
        .is_some_and(|owner| owner != "scope_root")
}

fn unsafe_contract_has_independent_proof(site: &UnsafeContractSite) -> bool {
    let Some(proof_ref) = site.proof_ref.as_deref() else {
        return false;
    };
    !proof_ref.starts_with("gate://compiler-generated/")
}

fn is_zero_arg_extern_unsafe_c_import(function: &TypedFunction) -> bool {
    function.is_extern
        && function.is_unsafe
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        && function.params.is_empty()
}

fn is_documented_ffi_import_wrapper(
    function: &TypedFunction,
    extern_unsafe_c_imports: &BTreeSet<String>,
) -> bool {
    if function.is_extern {
        return false;
    }

    let mut saw_unsafe_block = false;
    let mut only_import_calls = true;

    struct Visitor<'a> {
        extern_unsafe_c_imports: &'a BTreeSet<String>,
        saw_unsafe_block: &'a mut bool,
        only_import_calls: &'a mut bool,
        in_unsafe_block: bool,
    }

    impl AstVisitor for Visitor<'_> {
        fn visit_expr(&mut self, expr: &Expr) {
            match expr {
                Expr::UnsafeBlock { body, .. } => {
                    *self.saw_unsafe_block = true;
                    let previous = self.in_unsafe_block;
                    self.in_unsafe_block = true;
                    for stmt in body {
                        self.visit_stmt(stmt);
                    }
                    self.in_unsafe_block = previous;
                }
                Expr::Call { callee, args } => {
                    if self.in_unsafe_block && !self.extern_unsafe_c_imports.contains(callee) {
                        *self.only_import_calls = false;
                    }
                    for arg in args {
                        self.visit_expr(arg);
                    }
                }
                _ => ast::walk_expr(self, expr),
            }
        }
    }

    let mut visitor = Visitor {
        extern_unsafe_c_imports,
        saw_unsafe_block: &mut saw_unsafe_block,
        only_import_calls: &mut only_import_calls,
        in_unsafe_block: false,
    };
    for stmt in &function.body {
        visitor.visit_stmt(stmt);
    }

    saw_unsafe_block && only_import_calls
}

fn stmt_uses_ident(stmt: &Stmt, target: &str) -> bool {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_uses_ident(value, target),
        Stmt::Return(None) => false,
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_uses_ident(condition, target)
                || then_body
                    .iter()
                    .any(|nested| stmt_uses_ident(nested, target))
                || else_body
                    .iter()
                    .any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::While { condition, body } => {
            expr_uses_ident(condition, target)
                || body.iter().any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref()
                .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || condition
                    .as_ref()
                    .is_some_and(|expr| expr_uses_ident(expr, target))
                || step
                    .as_deref()
                    .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || body.iter().any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::ForIn { iterable, body, .. } => {
            expr_uses_ident(iterable, target)
                || body.iter().any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::Loop { body } => body.iter().any(|nested| stmt_uses_ident(nested, target)),
        Stmt::Break(_) | Stmt::Continue => false,
        Stmt::Match { scrutinee, arms } => {
            expr_uses_ident(scrutinee, target)
                || arms.iter().any(|arm| {
                    arm.guard
                        .as_ref()
                        .is_some_and(|guard| expr_uses_ident(guard, target))
                        || expr_uses_ident(&arm.value, target)
                })
        }
    }
}

fn expr_uses_ident(expr: &Expr, target: &str) -> bool {
    match expr {
        Expr::Ident(name) => name == target,
        Expr::Call { args, .. } => args.iter().any(|arg| expr_uses_ident(arg, target)),
        Expr::UnsafeBlock { body, meta } => {
            meta.as_ref().is_some_and(|m| m.owner == target)
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::FieldAccess { base, .. } => expr_uses_ident(base, target),
        Expr::StructInit { fields, .. } => fields
            .iter()
            .any(|(_, value)| expr_uses_ident(value, target)),
        Expr::EnumInit { payload, .. } => {
            payload.iter().any(|value| expr_uses_ident(value, target))
        }
        Expr::Tuple(items) => items.iter().any(|value| expr_uses_ident(value, target)),
        Expr::Closure { params, body, .. } => {
            if params.iter().any(|param| param.name == target) {
                false
            } else {
                expr_uses_ident(body, target)
            }
        }
        Expr::Group(inner) | Expr::Await(inner) | Expr::Discard(inner) => {
            expr_uses_ident(inner, target)
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => expr_uses_ident(try_expr, target) || expr_uses_ident(catch_expr, target),
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            expr_uses_ident(condition, target)
                || expr_uses_ident(then_expr, target)
                || expr_uses_ident(else_expr, target)
        }
        Expr::Match { scrutinee, arms } => {
            expr_uses_ident(scrutinee, target)
                || arms.iter().any(|arm| {
                    arm.guard
                        .as_ref()
                        .is_some_and(|guard| expr_uses_ident(guard, target))
                        || expr_uses_ident(&arm.value, target)
                })
        }
        Expr::While { condition, body } => {
            expr_uses_ident(condition, target)
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_ref()
                .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || condition
                    .as_ref()
                    .is_some_and(|expr| expr_uses_ident(expr, target))
                || step
                    .as_ref()
                    .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::ForIn { iterable, body, .. } => {
            expr_uses_ident(iterable, target)
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::Loop { body } => body.iter().any(|stmt| stmt_uses_ident(stmt, target)),
        Expr::Return(value) | Expr::Break(value) => value
            .as_ref()
            .is_some_and(|expr| expr_uses_ident(expr, target)),
        Expr::Continue => false,
        Expr::Binary { left, right, .. } => {
            expr_uses_ident(left, target) || expr_uses_ident(right, target)
        }
        Expr::Range { start, end, .. } => {
            expr_uses_ident(start, target) || expr_uses_ident(end, target)
        }
        Expr::ArrayLiteral(items) => items.iter().any(|item| expr_uses_ident(item, target)),
        Expr::ObjectLiteral(fields) => fields
            .iter()
            .any(|(_, value)| expr_uses_ident(value, target)),
        Expr::Index { base, index } => {
            expr_uses_ident(base, target) || expr_uses_ident(index, target)
        }
        Expr::Unary { expr, .. } => expr_uses_ident(expr, target),
        Expr::Int(_) | Expr::Float { .. } | Expr::Char(_) | Expr::Bool(_) | Expr::Str(_) => false,
    }
}

fn is_partial_move_expr(
    function: &TypedFunction,
    expr: &Expr,
    owners: &BTreeMap<String, usize>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    match expr {
        Expr::Group(inner) => is_partial_move_expr(function, inner, owners, struct_defs, enum_defs),
        Expr::FieldAccess { .. } | Expr::Index { .. } => expr_root_binding_name(expr)
            .and_then(|name| binding_partial_move_root_type(function, name))
            .is_some_and(|ty| {
                !matches!(ty, Type::Ptr { .. } | Type::Ref { .. })
                    && type_contains_linear_members(ty, struct_defs, enum_defs)
            }),
        Expr::Tuple(items) | Expr::ArrayLiteral(items) => items
            .iter()
            .any(|item| is_partial_move_expr(function, item, owners, struct_defs, enum_defs)),
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            fields.iter().any(|(_, value)| {
                is_partial_move_expr(function, value, owners, struct_defs, enum_defs)
            })
        }
        Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            payload
                .iter()
                .any(|item| is_partial_move_expr(function, item, owners, struct_defs, enum_defs))
                || named_payload.iter().any(|(_, value)| {
                    is_partial_move_expr(function, value, owners, struct_defs, enum_defs)
                })
        }
        _ => owners.is_empty() && false,
    }
}

fn expr_root_binding_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(name) => Some(name.as_str()),
        Expr::Group(inner)
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Index { base: inner, .. } => expr_root_binding_name(inner),
        _ => None,
    }
}

fn supports_index_base_type(ty: &Type) -> bool {
    match ty {
        Type::Array { .. } | Type::Slice(_) | Type::Vec(_) | Type::Ptr { .. } => true,
        Type::Named { name, args } => name == "GpuSlice" && args.len() == 1,
        _ => false,
    }
}

fn binding_partial_move_root_type<'a>(function: &'a TypedFunction, name: &str) -> Option<&'a Type> {
    function.local_types.get(name).or_else(|| {
        function
            .params
            .iter()
            .find(|param| param.name == name)
            .map(|param| &param.ty)
    })
}

fn type_contains_linear_members(
    ty: &Type,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    fn walk(
        ty: &Type,
        struct_defs: &HashMap<String, ast::Struct>,
        enum_defs: &HashMap<String, ast::Enum>,
        seen: &mut BTreeSet<String>,
    ) -> bool {
        if is_linear_type(ty) {
            return true;
        }
        match ty {
            Type::Tuple(items) => items
                .iter()
                .any(|item| walk(item, struct_defs, enum_defs, seen)),
            Type::Array { elem, .. }
            | Type::Slice(elem)
            | Type::Option(elem)
            | Type::Vec(elem)
            | Type::Deque(elem)
            | Type::Ring(elem)
            | Type::Set(elem)
            | Type::Future(elem) => walk(elem, struct_defs, enum_defs, seen),
            Type::Result { ok, err } => {
                walk(ok, struct_defs, enum_defs, seen) || walk(err, struct_defs, enum_defs, seen)
            }
            Type::Map { key, value } => {
                walk(key, struct_defs, enum_defs, seen) || walk(value, struct_defs, enum_defs, seen)
            }
            Type::Named { name, .. } => {
                if !seen.insert(name.clone()) {
                    return false;
                }
                let result = struct_defs.get(name).is_some_and(|def| {
                    def.fields
                        .iter()
                        .any(|field| walk(&field.ty, struct_defs, enum_defs, seen))
                }) || enum_defs.get(name).is_some_and(|def| {
                    def.variants.iter().any(|variant| {
                        variant
                            .payload
                            .iter()
                            .any(|payload| walk(payload, struct_defs, enum_defs, seen))
                            || variant
                                .named_payload
                                .iter()
                                .any(|field| walk(&field.ty, struct_defs, enum_defs, seen))
                    })
                });
                seen.remove(name);
                result
            }
            _ => false,
        }
    }

    walk(ty, struct_defs, enum_defs, &mut BTreeSet::new())
}

fn pattern_performs_partial_move(
    pattern: &ast::Pattern,
    function: &TypedFunction,
    value: &Expr,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    let Some(root_name) = expr_root_binding_name(value) else {
        return false;
    };
    let Some(root_ty) = binding_partial_move_root_type(function, root_name) else {
        return false;
    };
    if !type_contains_linear_members(root_ty, struct_defs, enum_defs) {
        return false;
    }
    pattern_is_partial_move(pattern, root_ty, struct_defs, enum_defs)
}

fn pattern_is_partial_move(
    pattern: &ast::Pattern,
    scrutinee_ty: &Type,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    match (pattern, scrutinee_ty) {
        (ast::Pattern::Tuple(items), Type::Tuple(scrutinee_items)) => {
            if items.len() != scrutinee_items.len() {
                return true;
            }
            items.iter().zip(scrutinee_items.iter()).any(|(item, ty)| {
                matches!(item, ast::Pattern::Wildcard)
                    || pattern_is_partial_move(item, ty, struct_defs, enum_defs)
            })
        }
        (ast::Pattern::Struct { name, fields }, Type::Named { name: ty_name, .. })
            if name == ty_name =>
        {
            let Some(def) = struct_defs.get(name) else {
                return false;
            };
            if fields.len() != def.fields.len() {
                return true;
            }
            fields.iter().any(|(_, binding)| binding == "_")
        }
        (
            ast::Pattern::Variant {
                enum_name,
                variant,
                bindings,
                named_bindings,
            },
            Type::Named { name: ty_name, .. },
        ) if enum_name == ty_name => {
            let Some(def) = enum_defs.get(enum_name) else {
                return false;
            };
            let Some(variant_def) = def
                .variants
                .iter()
                .find(|candidate| candidate.name == *variant)
            else {
                return false;
            };
            if !named_bindings.is_empty() {
                return named_bindings.len() != variant_def.named_payload.len()
                    || named_bindings.iter().any(|(_, binding)| binding == "_");
            }
            bindings.len() != variant_def.payload.len()
                || bindings.iter().any(|binding| binding == "_")
        }
        (ast::Pattern::Or(patterns), _) => patterns.iter().any(|candidate| {
            pattern_is_partial_move(candidate, scrutinee_ty, struct_defs, enum_defs)
        }),
        _ => false,
    }
}

fn is_alloc_callee(callee: &str) -> bool {
    callee == "alloc" || callee.ends_with(".alloc") || callee.starts_with("gpu.alloc_")
}

fn is_free_callee(callee: &str) -> bool {
    callee == "free" || callee.ends_with(".free")
}

fn is_close_callee(callee: &str) -> bool {
    callee == "close" || callee.ends_with(".close") || callee.ends_with("_close")
}

fn is_alloc_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { callee, .. } if is_alloc_callee(callee))
}

