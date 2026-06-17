use crate::*;

pub(crate) fn analyze_alias_and_provenance(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    let signatures = build_call_shapes(functions);
    for function in functions {
        let mut next_root = 1usize;
        let mut state = ProvenanceState::default();
        for param in &function.params {
            if param.ty.is_pointer_like() || matches!(param.ty, Type::Ref { .. }) {
                state.roots.insert(param.name.clone(), next_root);
                next_root += 1;
            }
        }
        analyze_provenance_block(
            &function.body,
            &mut state,
            &mut next_root,
            &mut violations,
            &function.name,
            &signatures,
        );
    }
    violations
}

pub(crate) fn build_call_shapes(functions: &[TypedFunction]) -> BTreeMap<String, CallShape> {
    let mut signatures = functions
        .iter()
        .map(|function| {
            (
                function.name.clone(),
                CallShape {
                    params: function.params.clone(),
                    return_type: function.return_type.clone(),
                    is_extern: function.is_extern,
                    is_unsafe: function.is_unsafe,
                    return_provenance: ReturnProvenanceSummary::Unknown,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    populate_return_provenance_summaries(functions, &mut signatures);
    signatures
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ProvenanceState {
    roots: BTreeMap<String, usize>,
    freed_roots: BTreeSet<usize>,
}

pub(crate) fn analyze_provenance_block(
    body: &[Stmt],
    state: &mut ProvenanceState,
    next_root: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    for stmt in body {
        analyze_provenance_stmt(
            stmt,
            state,
            next_root,
            violations,
            function_name,
            signatures,
        );
    }
}

pub(crate) fn analyze_provenance_stmt(
    stmt: &Stmt,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    let used = collect_stmt_idents(stmt);
    for used_name in used {
        let Some(root) = state.roots.get(&used_name).copied() else {
            continue;
        };
        if state.freed_roots.contains(&root) && !stmt_is_direct_free_of(stmt, &used_name) {
            violations.push(format!(
                "function `{}` uses value `{}` after provenance root {} was freed",
                function_name, used_name, root
            ));
        }
    }
    match stmt {
        Stmt::Let { name, value, .. } => {
            assign_provenance_value(name, value, state, next_root, signatures);
        }
        Stmt::LetPattern { pattern, value, .. } => {
            assign_pattern_provenance(pattern, value, state, next_root, signatures);
        }
        Stmt::Assign { target, value } => {
            assign_provenance_value(target, value, state, next_root, signatures);
        }
        Stmt::Expr(Expr::Call { callee, args }) => {
            analyze_provenance_call(callee, args, state, violations, function_name, signatures);
        }
        Stmt::Expr(Expr::UnsafeBlock { body, .. }) => {
            analyze_provenance_block(
                body,
                state,
                next_root,
                violations,
                function_name,
                signatures,
            );
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            let entry_state = state.clone();
            let mut then_state = state.clone();
            let mut else_state = state.clone();
            analyze_provenance_block(
                then_body,
                &mut then_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            analyze_provenance_block(
                else_body,
                &mut else_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
                function_name,
                "conditional branches",
                &entry_state,
                &[then_state, else_state],
                violations,
            );
        }
        Stmt::While { body, .. } | Stmt::Loop { body } => {
            let entry_state = state.clone();
            let mut body_state = state.clone();
            analyze_provenance_block(
                body,
                &mut body_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
                function_name,
                "loop iterations",
                &entry_state,
                &[entry_state.clone(), body_state],
                violations,
            );
        }
        Stmt::For {
            init, step, body, ..
        } => {
            if let Some(init) = init {
                analyze_provenance_stmt(
                    init,
                    state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
            }
            let entry_state = state.clone();
            let mut body_state = state.clone();
            analyze_provenance_block(
                body,
                &mut body_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            if let Some(step) = step {
                analyze_provenance_stmt(
                    step,
                    &mut body_state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
            }
            *state = merge_provenance_states(
                function_name,
                "loop iterations",
                &entry_state,
                &[entry_state.clone(), body_state],
                violations,
            );
        }
        Stmt::ForIn { body, .. } => {
            let entry_state = state.clone();
            let mut body_state = state.clone();
            analyze_provenance_block(
                body,
                &mut body_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
                function_name,
                "loop iterations",
                &entry_state,
                &[entry_state.clone(), body_state],
                violations,
            );
        }
        Stmt::Match { arms, .. } => {
            let entry_state = state.clone();
            let mut arm_states = Vec::new();
            for arm in arms {
                let mut arm_state = state.clone();
                analyze_provenance_expr(
                    &arm.value,
                    &mut arm_state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
                arm_states.push(arm_state);
            }
            if !arm_states.is_empty() {
                *state = merge_provenance_states(
                    function_name,
                    "match arms",
                    &entry_state,
                    &arm_states,
                    violations,
                );
            }
        }
        Stmt::Expr(expr) => {
            analyze_provenance_expr(
                expr,
                state,
                next_root,
                violations,
                function_name,
                signatures,
            );
        }
        Stmt::CompoundAssign { .. }
        | Stmt::Return(_)
        | Stmt::Defer(_)
        | Stmt::Requires(_)
        | Stmt::Ensures(_)
        | Stmt::Break(_)
        | Stmt::Continue => {}
    }
}

pub(crate) fn assign_provenance_value(
    target: &str,
    value: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    signatures: &BTreeMap<String, CallShape>,
) {
    match infer_expr_provenance_source(value, state, signatures) {
        ExprProvenanceSource::Existing(root) => {
            state.roots.insert(target.to_string(), root);
        }
        ExprProvenanceSource::Fresh => {
            state.roots.insert(target.to_string(), *next_root);
            *next_root += 1;
        }
        ExprProvenanceSource::Unknown => {
            state.roots.remove(target);
        }
    }
}

pub(crate) fn assign_pattern_provenance(
    pattern: &ast::Pattern,
    value: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    signatures: &BTreeMap<String, CallShape>,
) {
    match pattern {
        ast::Pattern::Ident(name) => {
            assign_provenance_value(name, value, state, next_root, signatures);
        }
        ast::Pattern::Tuple(items) => {
            if let Expr::Tuple(values) = value {
                if items.len() == values.len() {
                    for (item, value) in items.iter().zip(values.iter()) {
                        assign_pattern_provenance(item, value, state, next_root, signatures);
                    }
                    return;
                }
            }
            let source = infer_expr_provenance_source(value, state, signatures);
            for item in items {
                assign_pattern_binding_from_source(item, source, state, next_root);
            }
        }
        ast::Pattern::Struct { fields, .. } => {
            if let Expr::StructInit {
                fields: value_fields,
                ..
            } = value
            {
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some((_, field_value)) = value_fields
                        .iter()
                        .find(|(candidate, _)| candidate == field_name)
                    {
                        assign_provenance_value(
                            binding_name,
                            field_value,
                            state,
                            next_root,
                            signatures,
                        );
                    } else {
                        state.roots.remove(binding_name);
                    }
                }
                return;
            }
            let source = infer_expr_provenance_source(value, state, signatures);
            for (_, binding_name) in fields {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => {
            if let Expr::EnumInit {
                payload,
                named_payload,
                ..
            } = value
            {
                if bindings.len() == payload.len() {
                    for (binding, value) in bindings.iter().zip(payload.iter()) {
                        assign_name_from_expr(binding, value, state, next_root, signatures);
                    }
                } else {
                    let source = infer_expr_provenance_source(value, state, signatures);
                    for binding in bindings {
                        assign_name_from_source(binding, source, state, next_root);
                    }
                }
                for (field_name, binding_name) in named_bindings {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some((_, field_value)) = named_payload
                        .iter()
                        .find(|(candidate, _)| candidate == field_name)
                    {
                        assign_provenance_value(
                            binding_name,
                            field_value,
                            state,
                            next_root,
                            signatures,
                        );
                    } else {
                        state.roots.remove(binding_name);
                    }
                }
                return;
            }
            let source = infer_expr_provenance_source(value, state, signatures);
            for binding in bindings {
                assign_name_from_source(binding, source, state, next_root);
            }
            for (_, binding_name) in named_bindings {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            for pattern in patterns {
                assign_pattern_provenance(pattern, value, state, next_root, signatures);
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => {}
    }
}

pub(crate) fn assign_pattern_binding_from_source(
    pattern: &ast::Pattern,
    source: ExprProvenanceSource,
    state: &mut ProvenanceState,
    next_root: &mut usize,
) {
    match pattern {
        ast::Pattern::Ident(name) => assign_name_from_source(name, source, state, next_root),
        ast::Pattern::Tuple(items) => {
            for item in items {
                assign_pattern_binding_from_source(item, source, state, next_root);
            }
        }
        ast::Pattern::Struct { fields, .. } => {
            for (_, binding_name) in fields {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => {
            for binding in bindings {
                assign_name_from_source(binding, source, state, next_root);
            }
            for (_, binding_name) in named_bindings {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            for pattern in patterns {
                assign_pattern_binding_from_source(pattern, source, state, next_root);
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => {}
    }
}

pub(crate) fn assign_name_from_expr(
    name: &str,
    value: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    signatures: &BTreeMap<String, CallShape>,
) {
    if name != "_" {
        assign_provenance_value(name, value, state, next_root, signatures);
    }
}

pub(crate) fn assign_name_from_source(
    name: &str,
    source: ExprProvenanceSource,
    state: &mut ProvenanceState,
    next_root: &mut usize,
) {
    if name == "_" {
        return;
    }
    match source {
        ExprProvenanceSource::Existing(root) => {
            state.roots.insert(name.to_string(), root);
        }
        ExprProvenanceSource::Fresh => {
            state.roots.insert(name.to_string(), *next_root);
            *next_root += 1;
        }
        ExprProvenanceSource::Unknown => {
            state.roots.remove(name);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExprProvenanceSource {
    Existing(usize),
    Fresh,
    Unknown,
}

pub(crate) fn infer_expr_provenance_source(
    expr: &Expr,
    state: &ProvenanceState,
    signatures: &BTreeMap<String, CallShape>,
) -> ExprProvenanceSource {
    match expr {
        Expr::Ident(from) => state
            .roots
            .get(from)
            .copied()
            .map(ExprProvenanceSource::Existing)
            .unwrap_or(ExprProvenanceSource::Unknown),
        expr if is_alloc_expr(expr) => ExprProvenanceSource::Fresh,
        Expr::FieldAccess { base, .. } | Expr::Group(base) => {
            infer_expr_provenance_source(base, state, signatures)
        }
        Expr::Call { callee, args } => signatures
            .get(callee)
            .and_then(|shape| {
                if matches!(shape.return_type, Type::Ref { .. } | Type::Ptr { .. }) {
                    Some(match shape.return_provenance {
                        ReturnProvenanceSummary::Param(index) => args
                            .get(index)
                            .map(|arg| infer_expr_provenance_source(arg, state, signatures))
                            .unwrap_or(ExprProvenanceSource::Unknown),
                        ReturnProvenanceSummary::Fresh => ExprProvenanceSource::Fresh,
                        ReturnProvenanceSummary::Unknown => ExprProvenanceSource::Unknown,
                    })
                } else {
                    None
                }
            })
            .unwrap_or(ExprProvenanceSource::Unknown),
        _ => ExprProvenanceSource::Unknown,
    }
}

pub(crate) fn populate_return_provenance_summaries(
    functions: &[TypedFunction],
    signatures: &mut BTreeMap<String, CallShape>,
) {
    for _ in 0..functions.len().max(1) {
        let mut changed = false;
        for function in functions {
            let summary = infer_function_return_provenance(function, signatures);
            if let Some(shape) = signatures.get_mut(&function.name) {
                if shape.return_provenance != summary {
                    shape.return_provenance = summary;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

pub(crate) fn infer_function_return_provenance(
    function: &TypedFunction,
    signatures: &BTreeMap<String, CallShape>,
) -> ReturnProvenanceSummary {
    if !matches!(function.return_type, Type::Ref { .. } | Type::Ptr { .. }) {
        return ReturnProvenanceSummary::Unknown;
    }
    let param_indexes = function
        .params
        .iter()
        .enumerate()
        .map(|(index, param)| (param.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut summaries = Vec::new();
    collect_return_provenance_from_stmts(
        &function.body,
        &param_indexes,
        signatures,
        &mut summaries,
    );
    if summaries.is_empty() {
        ReturnProvenanceSummary::Unknown
    } else if summaries.windows(2).all(|window| window[0] == window[1]) {
        summaries[0]
    } else {
        ReturnProvenanceSummary::Unknown
    }
}

pub(crate) fn collect_return_provenance_from_stmts(
    body: &[Stmt],
    param_indexes: &BTreeMap<&str, usize>,
    signatures: &BTreeMap<String, CallShape>,
    out: &mut Vec<ReturnProvenanceSummary>,
) {
    for stmt in body {
        match stmt {
            Stmt::Return(Some(expr)) => {
                out.push(infer_return_expr_provenance(
                    expr,
                    param_indexes,
                    signatures,
                ));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_return_provenance_from_stmts(then_body, param_indexes, signatures, out);
                collect_return_provenance_from_stmts(else_body, param_indexes, signatures, out);
            }
            Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::ForIn { body, .. } => {
                collect_return_provenance_from_stmts(body, param_indexes, signatures, out);
            }
            Stmt::For {
                init, step, body, ..
            } => {
                if let Some(init) = init {
                    collect_return_provenance_from_stmts(
                        std::slice::from_ref(init.as_ref()),
                        param_indexes,
                        signatures,
                        out,
                    );
                }
                collect_return_provenance_from_stmts(body, param_indexes, signatures, out);
                if let Some(step) = step {
                    collect_return_provenance_from_stmts(
                        std::slice::from_ref(step.as_ref()),
                        param_indexes,
                        signatures,
                        out,
                    );
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    collect_return_provenance_from_expr(&arm.value, param_indexes, signatures, out);
                }
            }
            Stmt::Expr(expr)
            | Stmt::Defer(expr)
            | Stmt::Requires(expr)
            | Stmt::Ensures(expr)
            | Stmt::Let { value: expr, .. }
            | Stmt::LetPattern { value: expr, .. }
            | Stmt::Assign { value: expr, .. }
            | Stmt::CompoundAssign { value: expr, .. } => {
                collect_return_provenance_from_expr(expr, param_indexes, signatures, out);
            }
            Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => {}
        }
    }
}

pub(crate) fn collect_return_provenance_from_expr(
    expr: &Expr,
    param_indexes: &BTreeMap<&str, usize>,
    signatures: &BTreeMap<String, CallShape>,
    out: &mut Vec<ReturnProvenanceSummary>,
) {
    match expr {
        Expr::Return(Some(value)) => {
            out.push(infer_return_expr_provenance(
                value,
                param_indexes,
                signatures,
            ));
        }
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            collect_return_provenance_from_expr(then_expr, param_indexes, signatures, out);
            collect_return_provenance_from_expr(else_expr, param_indexes, signatures, out);
        }
        Expr::Match { arms, .. } => {
            for arm in arms {
                collect_return_provenance_from_expr(&arm.value, param_indexes, signatures, out);
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            collect_return_provenance_from_stmts(body, param_indexes, signatures, out);
        }
        _ => {}
    }
}

pub(crate) fn infer_return_expr_provenance(
    expr: &Expr,
    param_indexes: &BTreeMap<&str, usize>,
    signatures: &BTreeMap<String, CallShape>,
) -> ReturnProvenanceSummary {
    match expr {
        Expr::Ident(name) => param_indexes
            .get(name.as_str())
            .copied()
            .map(ReturnProvenanceSummary::Param)
            .unwrap_or(ReturnProvenanceSummary::Unknown),
        expr if is_alloc_expr(expr) => ReturnProvenanceSummary::Fresh,
        Expr::FieldAccess { base, .. } | Expr::Group(base) => {
            infer_return_expr_provenance(base, param_indexes, signatures)
        }
        Expr::Call { callee, args } => match signatures
            .get(callee)
            .map(|shape| shape.return_provenance)
            .unwrap_or(ReturnProvenanceSummary::Unknown)
        {
            ReturnProvenanceSummary::Param(index) => args
                .get(index)
                .map(|arg| infer_return_expr_provenance(arg, param_indexes, signatures))
                .unwrap_or(ReturnProvenanceSummary::Unknown),
            summary => summary,
        },
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let then_summary = infer_return_expr_provenance(then_expr, param_indexes, signatures);
            let else_summary = infer_return_expr_provenance(else_expr, param_indexes, signatures);
            if then_summary == else_summary {
                then_summary
            } else {
                ReturnProvenanceSummary::Unknown
            }
        }
        Expr::Match { arms, .. } => {
            let summaries = arms
                .iter()
                .map(|arm| infer_return_expr_provenance(&arm.value, param_indexes, signatures))
                .collect::<Vec<_>>();
            if summaries.is_empty() {
                ReturnProvenanceSummary::Unknown
            } else if summaries.windows(2).all(|window| window[0] == window[1]) {
                summaries[0]
            } else {
                ReturnProvenanceSummary::Unknown
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            let mut summaries = Vec::new();
            collect_return_provenance_from_stmts(body, param_indexes, signatures, &mut summaries);
            if summaries.is_empty() {
                ReturnProvenanceSummary::Unknown
            } else if summaries.windows(2).all(|window| window[0] == window[1]) {
                summaries[0]
            } else {
                ReturnProvenanceSummary::Unknown
            }
        }
        _ => ReturnProvenanceSummary::Unknown,
    }
}

pub(crate) fn analyze_provenance_call(
    callee: &str,
    args: &[Expr],
    state: &mut ProvenanceState,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    if is_free_callee(callee) {
        if let Some(arg) = args.first() {
            if let Some(root) = expr_provenance_root(arg, state, signatures) {
                if !state.freed_roots.insert(root) {
                    violations.push(format!(
                        "function `{}` double-frees provenance root {} via `{}`",
                        function_name,
                        root,
                        provenance_expr_label(arg)
                    ));
                }
            }
        }
    }
    if let Some(shape) = signatures.get(callee) {
        let mut mut_ref_aliases = BTreeMap::<String, (String, usize)>::new();
        let mut shared_ref_aliases = BTreeMap::<String, String>::new();
        for (index, param) in shape.params.iter().enumerate() {
            let Some(arg) = args.get(index) else {
                continue;
            };
            let label = provenance_expr_label(arg);
            let key = provenance_expr_alias_key(arg, state, signatures);
            match &param.ty {
                Type::Ref { mutable: true, .. } => {
                    let entry = mut_ref_aliases.entry(key).or_insert((label, 0));
                    entry.1 += 1;
                }
                Type::Ref { mutable: false, .. } => {
                    shared_ref_aliases.entry(key).or_insert(label);
                }
                _ => {}
            }
        }
        for (key, (name, count)) in &mut_ref_aliases {
            if *count > 1 {
                let detail = if let Some(root) = key.strip_prefix("root:") {
                    format!(
                        "function `{}` call `{}` aliases mutable reference parameter `{}` {} times (provenance root {})",
                        function_name, callee, name, count, root
                    )
                } else {
                    format!(
                        "function `{}` call `{}` aliases mutable reference parameter `{}` {} times",
                        function_name, callee, name, count
                    )
                };
                violations.push(detail);
            }
            if shared_ref_aliases.contains_key(key) {
                violations.push(format!(
                    "function `{}` call `{}` aliases mutable and shared borrows for `{}`",
                    function_name, callee, name
                ));
            }
        }
        if shape.is_extern && shape.is_unsafe {
            for (index, param) in shape.params.iter().enumerate() {
                let Some(arg) = args.get(index) else {
                    continue;
                };
                if param.name.ends_with("_owned") {
                    if let Some(root) = expr_provenance_root(arg, state, signatures) {
                        state.freed_roots.insert(root);
                    }
                }
            }
        }
    }
}

pub(crate) fn expr_provenance_root(
    expr: &Expr,
    state: &ProvenanceState,
    signatures: &BTreeMap<String, CallShape>,
) -> Option<usize> {
    match infer_expr_provenance_source(expr, state, signatures) {
        ExprProvenanceSource::Existing(root) => Some(root),
        ExprProvenanceSource::Fresh | ExprProvenanceSource::Unknown => None,
    }
}

pub(crate) fn provenance_expr_alias_key(
    expr: &Expr,
    state: &ProvenanceState,
    signatures: &BTreeMap<String, CallShape>,
) -> String {
    expr_provenance_root(expr, state, signatures)
        .map(|root| format!("root:{root}"))
        .unwrap_or_else(|| format!("label:{}", provenance_expr_label(expr)))
}

pub(crate) fn provenance_expr_label(expr: &Expr) -> String {
    match expr {
        Expr::Ident(name) => name.clone(),
        Expr::Group(inner) => provenance_expr_label(inner),
        Expr::FieldAccess { base, field } => format!("{}.{}", provenance_expr_label(base), field),
        Expr::Index { base, .. } => format!("{}[..]", provenance_expr_label(base)),
        _ => "<expr>".to_string(),
    }
}

pub(crate) fn analyze_provenance_expr(
    expr: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    match expr {
        Expr::UnsafeBlock { body, .. } => {
            analyze_provenance_block(
                body,
                state,
                next_root,
                violations,
                function_name,
                signatures,
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
            analyze_provenance_expr(
                then_expr,
                &mut then_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            analyze_provenance_expr(
                else_expr,
                &mut else_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
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
                analyze_provenance_expr(
                    &arm.value,
                    &mut arm_state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
                arm_states.push(arm_state);
            }
            if !arm_states.is_empty() {
                *state = merge_provenance_states(
                    function_name,
                    "match expressions",
                    &entry_state,
                    &arm_states,
                    violations,
                );
            }
        }
        _ => {}
    }
}

pub(crate) fn merge_provenance_states(
    function_name: &str,
    control_kind: &str,
    entry_state: &ProvenanceState,
    branches: &[ProvenanceState],
    violations: &mut Vec<String>,
) -> ProvenanceState {
    let mut merged = ProvenanceState::default();
    merged
        .freed_roots
        .extend(entry_state.freed_roots.iter().copied());
    let mut names = BTreeSet::<String>::new();
    names.extend(entry_state.roots.keys().cloned());
    for branch in branches {
        merged
            .freed_roots
            .extend(branch.freed_roots.iter().copied());
        names.extend(branch.roots.keys().cloned());
    }
    for name in names {
        let root_views = branches
            .iter()
            .map(|branch| branch.roots.get(&name).copied())
            .collect::<Vec<_>>();
        let root_diverges = root_views.windows(2).any(|window| window[0] != window[1]);
        if root_diverges {
            violations.push(format!(
                "function `{}` has divergent provenance state for `{}` across {}; rewrite control flow so provenance is consistent on every path",
                function_name, name, control_kind
            ));
            continue;
        }
        if let Some(Some(root)) = root_views.first() {
            merged.roots.insert(name, *root);
        }
    }
    merged
}

pub(crate) fn analyze_atomic_ordering_claims(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    struct Collector {
        function: String,
        violations: Vec<String>,
    }
    impl AstVisitor for Collector {
        fn visit_expr(&mut self, expr: &Expr) {
            if let Expr::Call { callee, args } = expr {
                if callee.starts_with("atomic.") {
                    if let Some(message) = validate_atomic_call(callee, args) {
                        self.violations
                            .push(format!("function `{}` {}", self.function, message));
                    }
                }
            }
            ast::walk_expr(self, expr);
        }
    }
    for function in functions {
        let mut collector = Collector {
            function: function.name.clone(),
            violations: Vec::new(),
        };
        for stmt in &function.body {
            collector.visit_stmt(stmt);
        }
        violations.extend(collector.violations);
    }
    violations
}

pub(crate) fn validate_atomic_call(callee: &str, args: &[Expr]) -> Option<String> {
    let ordering = |index: usize| {
        args.get(index).and_then(|arg| match arg {
            Expr::Str(value) | Expr::Ident(value) => Some(value.as_str()),
            _ => None,
        })
    };
    let is_supported = |value: &str| {
        matches!(
            value,
            "Relaxed" | "Acquire" | "Release" | "AcqRel" | "SeqCst"
        )
    };
    let is_release_like = |value: &str| matches!(value, "Release" | "AcqRel" | "SeqCst");
    match callee {
        "atomic.load" => {
            let Some(ord) = ordering(1) else {
                return Some("atomic.load is missing ordering argument".to_string());
            };
            if !is_supported(ord) {
                return Some(format!(
                    "atomic.load uses unsupported ordering `{ord}` (expected Relaxed/Acquire/SeqCst)"
                ));
            }
            if matches!(ord, "Release" | "AcqRel") {
                return Some(format!(
                    "atomic.load ordering `{ord}` is invalid (expected Relaxed/Acquire/SeqCst)"
                ));
            }
        }
        "atomic.store" => {
            let Some(ord) = ordering(2) else {
                return Some("atomic.store is missing ordering argument".to_string());
            };
            if !is_supported(ord) {
                return Some(format!(
                    "atomic.store uses unsupported ordering `{ord}` (expected Relaxed/Release/SeqCst)"
                ));
            }
            if matches!(ord, "Acquire" | "AcqRel") {
                return Some(format!(
                    "atomic.store ordering `{ord}` is invalid (expected Relaxed/Release/SeqCst)"
                ));
            }
        }
        "atomic.compare_exchange" => {
            let Some(success) = ordering(3) else {
                return Some(
                    "atomic.compare_exchange is missing success ordering argument".to_string(),
                );
            };
            let Some(failure) = ordering(4) else {
                return Some(
                    "atomic.compare_exchange is missing failure ordering argument".to_string(),
                );
            };
            if !is_supported(success) || !is_supported(failure) {
                return Some(format!(
                    "atomic.compare_exchange uses unsupported orderings success=`{success}` failure=`{failure}`"
                ));
            }
            if matches!(failure, "Release" | "AcqRel") {
                return Some(format!(
                    "atomic.compare_exchange failure ordering `{failure}` is invalid (failure must not be release-like)"
                ));
            }
            if is_release_like(failure) && !is_release_like(success) {
                return Some(format!(
                    "atomic.compare_exchange failure ordering `{failure}` cannot be stronger than success ordering `{success}`"
                ));
            }
        }
        "atomic.fetch_add" | "atomic.fetch_sub" | "atomic.fetch_and" | "atomic.fetch_or"
        | "atomic.fetch_xor" | "atomic.swap" => {
            let Some(ord) = ordering(2) else {
                return Some(format!("{callee} is missing ordering argument"));
            };
            if !is_supported(ord) {
                return Some(format!("{callee} uses unsupported ordering `{ord}`"));
            }
        }
        "atomic.fence" => {
            let Some(ord) = ordering(0) else {
                return Some("atomic.fence is missing ordering argument".to_string());
            };
            if !is_supported(ord) {
                return Some(format!("atomic.fence uses unsupported ordering `{ord}`"));
            }
            if ord == "Relaxed" {
                return Some(
                    "atomic.fence ordering `Relaxed` is invalid (expected Acquire/Release/AcqRel/SeqCst)"
                        .to_string(),
                );
            }
        }
        _ => {}
    }
    None
}

pub(crate) fn stmt_is_direct_free_of(stmt: &Stmt, name: &str) -> bool {
    matches!(
        stmt,
        Stmt::Expr(Expr::Call { callee, args })
            if is_free_callee(callee)
                && matches!(args.first(), Some(Expr::Ident(arg)) if arg == name)
    )
}

pub(crate) fn collect_stmt_idents(stmt: &Stmt) -> Vec<String> {
    let mut out = Vec::new();
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => collect_expr_idents(value, &mut out),
        Stmt::Return(None) => {}
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_expr_idents(condition, &mut out);
            for nested in then_body {
                out.extend(collect_stmt_idents(nested));
            }
            for nested in else_body {
                out.extend(collect_stmt_idents(nested));
            }
        }
        Stmt::While { condition, body } => {
            collect_expr_idents(condition, &mut out);
            for nested in body {
                out.extend(collect_stmt_idents(nested));
            }
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                out.extend(collect_stmt_idents(init));
            }
            if let Some(condition) = condition {
                collect_expr_idents(condition, &mut out);
            }
            if let Some(step) = step {
                out.extend(collect_stmt_idents(step));
            }
            for nested in body {
                out.extend(collect_stmt_idents(nested));
            }
        }
        Stmt::ForIn { iterable, body, .. } => {
            collect_expr_idents(iterable, &mut out);
            for nested in body {
                out.extend(collect_stmt_idents(nested));
            }
        }
        Stmt::Loop { body } => {
            for nested in body {
                out.extend(collect_stmt_idents(nested));
            }
        }
        Stmt::Break(_) | Stmt::Continue => {}
        Stmt::Match { scrutinee, arms } => {
            collect_expr_idents(scrutinee, &mut out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_expr_idents(guard, &mut out);
                }
                collect_expr_idents(&arm.value, &mut out);
            }
        }
    }
    out
}

pub(crate) fn collect_expr_idents(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Ident(name) => out.push(name.clone()),
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_idents(arg, out);
            }
        }
        Expr::UnsafeBlock { body, meta } => {
            if let Some(meta) = meta {
                out.push(meta.owner.clone());
            }
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::FieldAccess { base, .. } => collect_expr_idents(base, out),
        Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_expr_idents(value, out);
            }
        }
        Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_expr_idents(value, out);
            }
        }
        Expr::Tuple(items) => {
            for item in items {
                collect_expr_idents(item, out);
            }
        }
        Expr::Closure { params, body, .. } => {
            let mut nested = Vec::new();
            collect_expr_idents(body, &mut nested);
            for ident in nested {
                if !params.iter().any(|param| param.name == ident) {
                    out.push(ident);
                }
            }
        }
        Expr::Group(inner) | Expr::Await(inner) | Expr::Discard(inner) => {
            collect_expr_idents(inner, out)
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_expr_idents(try_expr, out);
            collect_expr_idents(catch_expr, out);
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_expr_idents(condition, out);
            collect_expr_idents(then_expr, out);
            collect_expr_idents(else_expr, out);
        }
        Expr::Match { scrutinee, arms } => {
            collect_expr_idents(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_expr_idents(guard, out);
                }
                collect_expr_idents(&arm.value, out);
            }
        }
        Expr::While { condition, body } => {
            collect_expr_idents(condition, out);
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                out.extend(collect_stmt_idents(init));
            }
            if let Some(condition) = condition {
                collect_expr_idents(condition, out);
            }
            if let Some(step) = step {
                out.extend(collect_stmt_idents(step));
            }
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            collect_expr_idents(iterable, out);
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::Loop { body } => {
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::Return(value) | Expr::Break(value) => {
            if let Some(value) = value {
                collect_expr_idents(value, out);
            }
        }
        Expr::Continue => {}
        Expr::Binary { left, right, .. } => {
            collect_expr_idents(left, out);
            collect_expr_idents(right, out);
        }
        Expr::Range { start, end, .. } => {
            collect_expr_idents(start, out);
            collect_expr_idents(end, out);
        }
        Expr::ArrayLiteral(items) => {
            for item in items {
                collect_expr_idents(item, out);
            }
        }
        Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_expr_idents(value, out);
            }
        }
        Expr::Index { base, index } => {
            collect_expr_idents(base, out);
            collect_expr_idents(index, out);
        }
        Expr::Unary { expr, .. } => collect_expr_idents(expr, out),
        Expr::Int(_) | Expr::Float { .. } | Expr::Char(_) | Expr::Bool(_) | Expr::Str(_) => {}
    }
}

pub(crate) fn build_call_graph(module: &Module) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        struct Collector {
            from: String,
            edges: Vec<(String, String)>,
        }
        impl AstVisitor for Collector {
            fn visit_expr(&mut self, expr: &Expr) {
                if let Expr::Call { callee, .. } = expr {
                    let (base, _) = split_generic_callee(callee);
                    self.edges.push((self.from.clone(), base.to_string()));
                }
                ast::walk_expr(self, expr);
            }
        }
        let mut collector = Collector {
            from: function.name.clone(),
            edges: Vec::new(),
        };
        for stmt in &function.body {
            collector.visit_stmt(stmt);
        }
        out.extend(collector.edges);
    }
    out
}

pub(crate) fn infer_capabilities(functions: &[TypedFunction]) -> Vec<String> {
    let mut caps = BTreeSet::new();
    for function in functions {
        if function.is_test {
            continue;
        }
        if function.is_async {
            caps.insert("thread".to_string());
        }
        struct Collector<'a> {
            caps: &'a mut BTreeSet<String>,
        }
        impl AstVisitor for Collector<'_> {
            fn visit_expr(&mut self, expr: &Expr) {
                if let Expr::Call { callee, .. } = expr {
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
        let mut collector = Collector { caps: &mut caps };
        for stmt in &function.body {
            collector.visit_stmt(stmt);
        }
    }
    caps.into_iter().collect()
}

pub(crate) fn is_thread_capability_callee(callee: &str) -> bool {
    matches!(
        callee,
        "spawn"
            | "spawn_ctx"
            | "join"
            | "detach"
            | "cancel_task"
            | "task_result"
            | "yield"
            | "checkpoint"
            | "timeout"
            | "deadline"
            | "cancel"
            | "recv"
            | "pulse"
    ) || callee.starts_with("thread.")
        || callee.starts_with("task.")
}

pub(crate) fn collect_generic_instantiations(module: &Module) -> Vec<String> {
    let mut out = Vec::new();
    for item in &module.items {
        match item {
            ast::Item::Function(function) => {
                collect_type_instantiation(&function.return_type, &mut out);
                for param in &function.params {
                    collect_type_instantiation(&param.ty, &mut out);
                }
                for statement in &function.body {
                    match statement {
                        Stmt::Let { ty: Some(ty), .. } | Stmt::LetPattern { ty: Some(ty), .. } => {
                            collect_type_instantiation(ty, &mut out);
                        }
                        _ => {}
                    }
                }
            }
            ast::Item::Const(item) => {
                collect_type_instantiation(&item.ty, &mut out);
            }
            ast::Item::Static(item) => {
                collect_type_instantiation(&item.ty, &mut out);
            }
            ast::Item::TypeAlias(item) => {
                collect_type_instantiation(&item.ty, &mut out);
            }
            ast::Item::NewType(item) => {
                collect_type_instantiation(&item.inner, &mut out);
            }
            ast::Item::Struct(item) => {
                for field in &item.fields {
                    collect_type_instantiation(&field.ty, &mut out);
                }
            }
            ast::Item::Enum(item) => {
                for variant in &item.variants {
                    for payload in &variant.payload {
                        collect_type_instantiation(payload, &mut out);
                    }
                }
            }
            ast::Item::Test(_) => {}
            ast::Item::Trait(item) => {
                for assoc in &item.associated_consts {
                    collect_type_instantiation(&assoc.ty, &mut out);
                }
                for method in &item.methods {
                    collect_type_instantiation(&method.return_type, &mut out);
                    for param in &method.params {
                        collect_type_instantiation(&param.ty, &mut out);
                    }
                }
            }
            ast::Item::Impl(item) => {
                collect_type_instantiation(&item.for_type, &mut out);
                for (_, ty) in &item.associated_types {
                    collect_type_instantiation(ty, &mut out);
                }
                for assoc in &item.associated_consts {
                    collect_type_instantiation(&assoc.ty, &mut out);
                }
                for method in &item.methods {
                    collect_type_instantiation(&method.return_type, &mut out);
                    for param in &method.params {
                        collect_type_instantiation(&param.ty, &mut out);
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) fn collect_type_instantiation(ty: &Type, out: &mut Vec<String>) {
    match ty {
        Type::Vec(inner) => {
            out.push(format!("Vec<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Option(inner) => {
            out.push(format!("Option<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Result { ok, err } => {
            out.push(format!("Result<{ok}, {err}>"));
            collect_type_instantiation(ok, out);
            collect_type_instantiation(err, out);
        }
        Type::Map { key, value } => {
            out.push(format!("Map<{key}, {value}>"));
            collect_type_instantiation(key, out);
            collect_type_instantiation(value, out);
        }
        Type::Set(inner) => {
            out.push(format!("Set<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Deque(inner) => {
            out.push(format!("Deque<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Ring(inner) => {
            out.push(format!("Ring<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Future(inner) => {
            out.push(format!("Future<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::DynTrait(name) => out.push(format!("dyn {name}")),
        Type::Tuple(items) => {
            out.push(format!(
                "({})",
                items
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            for item in items {
                collect_type_instantiation(item, out);
            }
        }
        Type::Named { name, args } if !args.is_empty() => {
            out.push(format!(
                "{}<{}>",
                name,
                args.iter()
                    .map(|t| t.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            for arg in args {
                collect_type_instantiation(arg, out);
            }
        }
        Type::Ptr { to, .. }
        | Type::Ref { to, .. }
        | Type::Slice(to)
        | Type::Array { elem: to, .. } => collect_type_instantiation(to, out),
        Type::Function { params, ret } => {
            for param in params {
                collect_type_instantiation(param, out);
            }
            collect_type_instantiation(ret, out);
        }
        Type::Never
        | Type::Void
        | Type::Bool
        | Type::ISize
        | Type::USize
        | Type::Int { .. }
        | Type::BigInt
        | Type::BigUint
        | Type::Float { .. }
        | Type::Decimal128
        | Type::Char
        | Type::Str
        | Type::Bytes
        | Type::Uuid
        | Type::Named { .. }
        | Type::TypeVar(_) => {}
        Type::Path
        | Type::PathBuf
        | Type::Url
        | Type::SocketAddr
        | Type::Duration
        | Type::Instant
        | Type::Decimal
        | Type::DateTimeTz
        | Type::ExitStatus
        | Type::SimdVector(_)
        | Type::SimdMask(_) => {}
    }
}

pub(crate) fn collect_semantic_hints(
    functions: &[TypedFunction],
) -> (Vec<String>, Vec<String>, usize, usize, usize) {
    let mut linear_resources = BTreeSet::new();
    let mut deferred_resources = BTreeSet::new();
    let mut matches_without_wildcard = 0usize;
    let mut match_unreachable_arms = 0usize;
    let mut match_duplicate_catchall_arms = 0usize;

    for function in functions {
        struct Collector<'a> {
            function: &'a TypedFunction,
            linear_resources: &'a mut BTreeSet<String>,
            deferred_resources: &'a mut BTreeSet<String>,
            matches_without_wildcard: &'a mut usize,
            match_unreachable_arms: &'a mut usize,
            match_duplicate_catchall_arms: &'a mut usize,
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
                            self.linear_resources.insert(name.clone());
                        }
                    }
                }
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, self.deferred_resources);
                }
                if let Stmt::Match { arms, .. } = stmt {
                    if !arms
                        .iter()
                        .any(|arm| pattern_is_catchall(&arm.pattern) && arm.guard.is_none())
                    {
                        *self.matches_without_wildcard += 1;
                    }
                    let mut seen_catchall = false;
                    for arm in arms {
                        let is_catchall = pattern_is_catchall(&arm.pattern) && arm.guard.is_none();
                        if seen_catchall {
                            *self.match_unreachable_arms += 1;
                            if is_catchall {
                                *self.match_duplicate_catchall_arms += 1;
                            }
                        } else if is_catchall {
                            seen_catchall = true;
                        }
                    }
                }
                ast::walk_stmt(self, stmt);
            }
        }
        let mut collector = Collector {
            function,
            linear_resources: &mut linear_resources,
            deferred_resources: &mut deferred_resources,
            matches_without_wildcard: &mut matches_without_wildcard,
            match_unreachable_arms: &mut match_unreachable_arms,
            match_duplicate_catchall_arms: &mut match_duplicate_catchall_arms,
        };
        for statement in &function.body {
            collector.visit_stmt(statement);
        }
    }

    (
        linear_resources.into_iter().collect(),
        deferred_resources.into_iter().collect(),
        matches_without_wildcard,
        match_unreachable_arms,
        match_duplicate_catchall_arms,
    )
}

pub(crate) fn collect_effect_markers(
    functions: &[TypedFunction],
) -> (usize, usize, usize, usize, usize, usize) {
    let mut host_syscall_sites = 0usize;
    let mut unsafe_sites = 0usize;
    let mut unsafe_reasoned_sites = 0usize;
    let mut reference_sites = 0usize;
    let mut alloc_sites = 0usize;
    let mut free_sites = 0usize;

    for function in functions {
        if function.is_unsafe {
            unsafe_sites += 1;
            unsafe_reasoned_sites += 1;
        }
        for param in &function.params {
            if matches!(param.ty, Type::Ref { .. }) {
                reference_sites += 1;
            }
        }
        struct Counter {
            host_syscall_sites: usize,
            unsafe_sites: usize,
            unsafe_reasoned_sites: usize,
            alloc_sites: usize,
            free_sites: usize,
            reference_sites: usize,
        }
        impl AstVisitor for Counter {
            fn visit_expr(&mut self, expr: &Expr) {
                if let Expr::Call { callee, .. } = expr {
                    if callee.starts_with("syscall.") {
                        self.host_syscall_sites += 1;
                    }
                    if is_alloc_callee(callee) {
                        self.alloc_sites += 1;
                    }
                    if is_free_callee(callee) {
                        self.free_sites += 1;
                    }
                }
                if let Expr::UnsafeBlock { .. } = expr {
                    self.unsafe_sites += 1;
                    self.unsafe_reasoned_sites += 1;
                }
                ast::walk_expr(self, expr);
            }
        }
        let mut counter = Counter {
            host_syscall_sites: 0,
            unsafe_sites: 0,
            unsafe_reasoned_sites: 0,
            alloc_sites: 0,
            free_sites: 0,
            reference_sites: 0,
        };
        for stmt in &function.body {
            counter.visit_stmt(stmt);
        }
        host_syscall_sites += counter.host_syscall_sites;
        unsafe_sites += counter.unsafe_sites;
        unsafe_reasoned_sites += counter.unsafe_reasoned_sites;
        alloc_sites += counter.alloc_sites;
        free_sites += counter.free_sites;
        reference_sites += counter.reference_sites;
    }

    (
        host_syscall_sites,
        unsafe_sites,
        unsafe_reasoned_sites,
        reference_sites,
        alloc_sites,
        free_sites,
    )
}

pub(crate) fn collect_unsafe_contract_sites(
    functions: &[TypedFunction],
) -> Vec<UnsafeContractSite> {
    let unsafe_functions = functions
        .iter()
        .filter(|function| function.is_unsafe)
        .map(|function| function.name.clone())
        .collect::<BTreeSet<_>>();
    let mut out = Vec::<UnsafeContractSite>::new();
    for function in functions {
        let owner = function
            .params
            .first()
            .map(|param| param.name.clone())
            .unwrap_or_else(|| "scope_root".to_string());
        if function.is_unsafe {
            let snippet = format!("unsafe fn {}", function.name);
            out.push(generated_unsafe_contract_site(
                "unsafe_fn",
                &function.name,
                &snippet,
                &owner,
                function.is_async,
                None,
            ));
        }
        if function.is_extern
            && function
                .abi
                .as_deref()
                .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
            && function.is_unsafe
        {
            let snippet = format!("ext unsafe c fn {}", function.name);
            out.push(generated_unsafe_contract_site(
                "unsafe_import",
                &function.name,
                &snippet,
                &owner,
                function.is_async,
                None,
            ));
        }
        for stmt in &function.body {
            collect_unsafe_contract_sites_from_stmt(
                stmt,
                &function.name,
                function.is_unsafe,
                function.is_async,
                &owner,
                &unsafe_functions,
                &mut out,
            );
        }
    }
    out
}

pub(crate) fn collect_unsafe_contract_sites_from_stmt(
    stmt: &Stmt,
    function_name: &str,
    in_unsafe_context: bool,
    in_async_context: bool,
    owner: &str,
    unsafe_functions: &BTreeSet<String>,
    out: &mut Vec<UnsafeContractSite>,
) {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => collect_unsafe_contract_sites_from_expr(
            value,
            function_name,
            in_unsafe_context,
            in_async_context,
            owner,
            unsafe_functions,
            out,
        ),
        Stmt::Return(value) => {
            if let Some(value) = value {
                collect_unsafe_contract_sites_from_expr(
                    value,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_unsafe_contract_sites_from_expr(
                condition,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for nested in then_body {
                collect_unsafe_contract_sites_from_stmt(
                    nested,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
            for nested in else_body {
                collect_unsafe_contract_sites_from_stmt(
                    nested,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Stmt::While { condition, body } => {
            collect_unsafe_contract_sites_from_expr(
                condition,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for nested in body {
                collect_unsafe_contract_sites_from_stmt(
                    nested,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
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
                collect_unsafe_contract_sites_from_stmt(
                    init,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
            if let Some(condition) = condition {
                collect_unsafe_contract_sites_from_expr(
                    condition,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
            if let Some(step) = step {
                collect_unsafe_contract_sites_from_stmt(
                    step,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
            for nested in body {
                collect_unsafe_contract_sites_from_stmt(
                    nested,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Stmt::ForIn { iterable, body, .. } => {
            collect_unsafe_contract_sites_from_expr(
                iterable,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for nested in body {
                collect_unsafe_contract_sites_from_stmt(
                    nested,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Stmt::Loop { body } => {
            for nested in body {
                collect_unsafe_contract_sites_from_stmt(
                    nested,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Stmt::Match { scrutinee, arms } => {
            collect_unsafe_contract_sites_from_expr(
                scrutinee,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unsafe_contract_sites_from_expr(
                        guard,
                        function_name,
                        in_unsafe_context,
                        in_async_context,
                        owner,
                        unsafe_functions,
                        out,
                    );
                }
                collect_unsafe_contract_sites_from_expr(
                    &arm.value,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Stmt::Break(_) | Stmt::Continue => {}
    }
}

pub(crate) fn collect_unsafe_contract_sites_from_expr(
    expr: &Expr,
    function_name: &str,
    in_unsafe_context: bool,
    in_async_context: bool,
    owner: &str,
    unsafe_functions: &BTreeSet<String>,
    out: &mut Vec<UnsafeContractSite>,
) {
    match expr {
        Expr::UnsafeBlock { body, .. } => {
            let snippet = format!("{function_name}: unsafe {{ ... }}");
            out.push(generated_unsafe_contract_site(
                "unsafe_block",
                function_name,
                &snippet,
                owner,
                in_async_context,
                None,
            ));
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    true,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Call { callee, args } => {
            if !in_unsafe_context {
                if let Some(unsafe_callee) = resolve_unsafe_callee(unsafe_functions, callee) {
                    let snippet = format!("{function_name}: call to unsafe `{unsafe_callee}`");
                    out.push(unsafe_violation_site(
                        function_name,
                        &snippet,
                        in_async_context,
                    ));
                }
            }
            for arg in args {
                collect_unsafe_contract_sites_from_expr(
                    arg,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::FieldAccess { base, .. } => collect_unsafe_contract_sites_from_expr(
            base,
            function_name,
            in_unsafe_context,
            in_async_context,
            owner,
            unsafe_functions,
            out,
        ),
        Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_unsafe_contract_sites_from_expr(
                    value,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_unsafe_contract_sites_from_expr(
                    value,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Tuple(items) => {
            for item in items {
                collect_unsafe_contract_sites_from_expr(
                    item,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Closure { body, .. } => collect_unsafe_contract_sites_from_expr(
            body,
            function_name,
            in_unsafe_context,
            in_async_context,
            owner,
            unsafe_functions,
            out,
        ),
        Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Discard(inner)
        | Expr::Unary { expr: inner, .. } => collect_unsafe_contract_sites_from_expr(
            inner,
            function_name,
            in_unsafe_context,
            in_async_context,
            owner,
            unsafe_functions,
            out,
        ),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_unsafe_contract_sites_from_expr(
                try_expr,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            collect_unsafe_contract_sites_from_expr(
                catch_expr,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_unsafe_contract_sites_from_expr(
                condition,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            collect_unsafe_contract_sites_from_expr(
                then_expr,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            collect_unsafe_contract_sites_from_expr(
                else_expr,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
        }
        Expr::Match { scrutinee, arms } => {
            collect_unsafe_contract_sites_from_expr(
                scrutinee,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unsafe_contract_sites_from_expr(
                        guard,
                        function_name,
                        in_unsafe_context,
                        in_async_context,
                        owner,
                        unsafe_functions,
                        out,
                    );
                }
                collect_unsafe_contract_sites_from_expr(
                    &arm.value,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::While { condition, body } => {
            collect_unsafe_contract_sites_from_expr(
                condition,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
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
                collect_unsafe_contract_sites_from_stmt(
                    init,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
            if let Some(condition) = condition {
                collect_unsafe_contract_sites_from_expr(
                    condition,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
            if let Some(step) = step {
                collect_unsafe_contract_sites_from_stmt(
                    step,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            collect_unsafe_contract_sites_from_expr(
                iterable,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Loop { body } => {
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Return(value) | Expr::Break(value) => {
            if let Some(value) = value {
                collect_unsafe_contract_sites_from_expr(
                    value,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Continue => {}
        Expr::Binary { left, right, .. } => {
            collect_unsafe_contract_sites_from_expr(
                left,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            collect_unsafe_contract_sites_from_expr(
                right,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
        }
        Expr::Range { start, end, .. } => {
            collect_unsafe_contract_sites_from_expr(
                start,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            collect_unsafe_contract_sites_from_expr(
                end,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
        }
        Expr::ArrayLiteral(items) => {
            for item in items {
                collect_unsafe_contract_sites_from_expr(
                    item,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_unsafe_contract_sites_from_expr(
                    value,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Index { base, index } => {
            collect_unsafe_contract_sites_from_expr(
                base,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            collect_unsafe_contract_sites_from_expr(
                index,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
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

pub(crate) fn generated_unsafe_contract_site(
    kind: &str,
    function_name: &str,
    snippet: &str,
    owner: &str,
    async_context: bool,
    callee: Option<&str>,
) -> UnsafeContractSite {
    let reason = match kind {
        "unsafe_import" => format!("compiler-generated: unsafe FFI import `{function_name}`"),
        "unsafe_fn" => format!("compiler-generated: unsafe function `{function_name}`"),
        "unsafe_block" => format!("compiler-generated: unsafe island in `{function_name}`"),
        _ => format!("compiler-generated: unsafe site in `{function_name}`"),
    };
    let scope = format!("{function_name}::{kind}");
    let risk_class = if kind == "unsafe_import" || callee.is_some_and(|v| v.contains("c_")) {
        "ffi".to_string()
    } else {
        "memory".to_string()
    };
    let site_id = stable_unsafe_site_id(kind, function_name, snippet);
    let proof_ref = format!("gate://compiler-generated/{function_name}/{site_id}");
    let owner_id = format!("owner::{function_name}::{owner}");
    UnsafeContractSite {
        site_id,
        kind: kind.to_string(),
        function: function_name.to_string(),
        snippet: snippet.to_string(),
        reason: Some(reason),
        invariant: Some(format!("owner_live({owner})")),
        owner: Some(owner.to_string()),
        owner_id: Some(owner_id),
        scope: Some(scope),
        risk_class: Some(risk_class),
        proof_ref: Some(proof_ref),
        async_context,
    }
}

pub(crate) fn unsafe_violation_site(
    function_name: &str,
    snippet: &str,
    async_context: bool,
) -> UnsafeContractSite {
    let site_id = stable_unsafe_site_id("unsafe_violation_callsite", function_name, snippet);
    UnsafeContractSite {
        site_id,
        kind: "unsafe_violation_callsite".to_string(),
        function: function_name.to_string(),
        snippet: snippet.to_string(),
        reason: None,
        invariant: None,
        owner: None,
        owner_id: None,
        scope: None,
        risk_class: None,
        proof_ref: None,
        async_context,
    }
}

pub(crate) fn stable_unsafe_site_id(kind: &str, function_name: &str, snippet: &str) -> String {
    let material = format!("{kind}|{function_name}|{snippet}");
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in material.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("usite_{hash:016x}")
}

pub(crate) fn collect_cleanup_targets(expr: &ast::Expr, out: &mut BTreeSet<String>) {
    match expr {
        ast::Expr::Call { callee, args } if is_free_callee(callee) || is_close_callee(callee) => {
            if let Some(ast::Expr::Ident(name)) = args.first() {
                out.insert(name.clone());
            }
            for arg in args {
                collect_cleanup_targets(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_cleanup_targets(try_expr, out);
            collect_cleanup_targets(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_cleanup_targets(condition, out);
            collect_cleanup_targets(then_expr, out);
            collect_cleanup_targets(else_expr, out);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_cleanup_targets(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_cleanup_targets(guard, out);
                }
                collect_cleanup_targets(&arm.value, out);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_cleanup_targets(condition, out);
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(stmt) = init {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
            if let Some(expr) = condition {
                collect_cleanup_targets(expr, out);
            }
            if let Some(stmt) = step {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_cleanup_targets(iterable, out);
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::Group(inner)
        | ast::Expr::Await(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::Unary { expr: inner, .. }
        | ast::Expr::FieldAccess { base: inner, .. } => collect_cleanup_targets(inner, out),
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_cleanup_targets(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. }
        | ast::Expr::Tuple(payload)
        | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_cleanup_targets(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_cleanup_targets(body, out),
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(expr) = value {
                collect_cleanup_targets(expr, out);
            }
        }
        ast::Expr::Binary { left, right, .. }
        | ast::Expr::Range {
            start: left,
            end: right,
            ..
        } => {
            collect_cleanup_targets(left, out);
            collect_cleanup_targets(right, out);
        }
        ast::Expr::Index { base, index } => {
            collect_cleanup_targets(base, out);
            collect_cleanup_targets(index, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_)
        | ast::Expr::Continue
        | ast::Expr::Call { .. } => {}
    }
}

pub(crate) fn collect_entry_contracts(
    functions: &[TypedFunction],
    fn_sigs: &HashMap<String, (Vec<Type>, Type)>,
) -> (Vec<Option<bool>>, Vec<Option<bool>>) {
    let mut requires = Vec::new();
    let mut ensures = Vec::new();
    for function in functions {
        if function.name != "main" {
            continue;
        }
        let env = BTreeMap::new();
        for statement in &function.body {
            match statement {
                Stmt::Requires(expr) => {
                    requires.push(eval_bool_expr(expr, &env, functions, fn_sigs));
                }
                Stmt::Ensures(expr) => {
                    ensures.push(eval_bool_expr(expr, &env, functions, fn_sigs));
                }
                _ => {}
            }
        }
    }
    (requires, ensures)
}
