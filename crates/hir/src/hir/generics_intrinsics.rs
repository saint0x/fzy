fn collect_and_rewrite_explicit_generic_calls(
    templates: &HashMap<String, TypedFunction>,
    function: &mut TypedFunction,
    depth: usize,
    queue: &mut VecDeque<(String, Vec<Type>, usize)>,
    rewrite: &mut HashMap<String, String>,
) {
    fn rewrite_expr(
        expr: &mut Expr,
        templates: &HashMap<String, TypedFunction>,
        depth: usize,
        queue: &mut VecDeque<(String, Vec<Type>, usize)>,
        rewrite: &mut HashMap<String, String>,
    ) {
        match expr {
            Expr::Call { callee, args } => {
                let current = callee.clone();
                let (base, explicit) = split_generic_callee(&current);
                if let Some(explicit) = explicit {
                    if templates.contains_key(base) {
                        let base_name = base.to_string();
                        let symbol = monomorphized_symbol(base, &explicit);
                        rewrite.insert(current, symbol.clone());
                        *callee = symbol.clone();
                        queue.push_back((base_name, explicit, depth));
                    }
                }
                if let Some(mapped) = rewrite.get(callee).cloned() {
                    *callee = mapped;
                }
                for arg in args {
                    rewrite_expr(arg, templates, depth, queue, rewrite);
                }
            }
            Expr::UnsafeBlock { body, .. } => rewrite_stmts(body, templates, depth, queue, rewrite),
            Expr::FieldAccess { base, .. } => rewrite_expr(base, templates, depth, queue, rewrite),
            Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    rewrite_expr(value, templates, depth, queue, rewrite);
                }
            }
            Expr::EnumInit { payload, .. } | Expr::Tuple(payload) | Expr::ArrayLiteral(payload) => {
                for value in payload {
                    rewrite_expr(value, templates, depth, queue, rewrite);
                }
            }
            Expr::ObjectLiteral(fields) => {
                for (_, value) in fields {
                    rewrite_expr(value, templates, depth, queue, rewrite);
                }
            }
            Expr::Closure { body, .. }
            | Expr::Group(body)
            | Expr::Await(body)
            | Expr::Discard(body) => rewrite_expr(body, templates, depth, queue, rewrite),
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                rewrite_expr(try_expr, templates, depth, queue, rewrite);
                rewrite_expr(catch_expr, templates, depth, queue, rewrite);
            }
            Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                rewrite_expr(condition, templates, depth, queue, rewrite);
                rewrite_expr(then_expr, templates, depth, queue, rewrite);
                rewrite_expr(else_expr, templates, depth, queue, rewrite);
            }
            Expr::Match { scrutinee, arms } => {
                rewrite_expr(scrutinee, templates, depth, queue, rewrite);
                for arm in arms {
                    if let Some(guard) = &mut arm.guard {
                        rewrite_expr(guard, templates, depth, queue, rewrite);
                    }
                    rewrite_expr(&mut arm.value, templates, depth, queue, rewrite);
                }
            }
            Expr::While { condition, body } => {
                rewrite_expr(condition, templates, depth, queue, rewrite);
                rewrite_stmts(body, templates, depth, queue, rewrite);
            }
            Expr::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    rewrite_stmts(
                        std::slice::from_mut(init.as_mut()),
                        templates,
                        depth,
                        queue,
                        rewrite,
                    );
                }
                if let Some(condition) = condition {
                    rewrite_expr(condition, templates, depth, queue, rewrite);
                }
                if let Some(step) = step {
                    rewrite_stmts(
                        std::slice::from_mut(step.as_mut()),
                        templates,
                        depth,
                        queue,
                        rewrite,
                    );
                }
                rewrite_stmts(body, templates, depth, queue, rewrite);
            }
            Expr::ForIn { iterable, body, .. } => {
                rewrite_expr(iterable, templates, depth, queue, rewrite);
                rewrite_stmts(body, templates, depth, queue, rewrite);
            }
            Expr::Loop { body } => rewrite_stmts(body, templates, depth, queue, rewrite),
            Expr::Return(value) | Expr::Break(value) => {
                if let Some(value) = value {
                    rewrite_expr(value, templates, depth, queue, rewrite);
                }
            }
            Expr::Continue => {}
            Expr::Unary { expr, .. } => rewrite_expr(expr, templates, depth, queue, rewrite),
            Expr::Binary { left, right, .. } => {
                rewrite_expr(left, templates, depth, queue, rewrite);
                rewrite_expr(right, templates, depth, queue, rewrite);
            }
            Expr::Range { start, end, .. } => {
                rewrite_expr(start, templates, depth, queue, rewrite);
                rewrite_expr(end, templates, depth, queue, rewrite);
            }
            Expr::Index { base, index } => {
                rewrite_expr(base, templates, depth, queue, rewrite);
                rewrite_expr(index, templates, depth, queue, rewrite);
            }
            Expr::Int(_)
            | Expr::Float { .. }
            | Expr::Char(_)
            | Expr::Bool(_)
            | Expr::Str(_)
            | Expr::Ident(_) => {}
        }
    }

    fn rewrite_stmts(
        stmts: &mut [Stmt],
        templates: &HashMap<String, TypedFunction>,
        depth: usize,
        queue: &mut VecDeque<(String, Vec<Type>, usize)>,
        rewrite: &mut HashMap<String, String>,
    ) {
        for stmt in stmts {
            match stmt {
                Stmt::Let { value, .. }
                | Stmt::LetPattern { value, .. }
                | Stmt::Assign { value, .. }
                | Stmt::CompoundAssign { value, .. }
                | Stmt::Defer(value)
                | Stmt::Requires(value)
                | Stmt::Ensures(value)
                | Stmt::Expr(value) => rewrite_expr(value, templates, depth, queue, rewrite),
                Stmt::Return(value) => {
                    if let Some(value) = value {
                        rewrite_expr(value, templates, depth, queue, rewrite);
                    }
                }
                Stmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    rewrite_expr(condition, templates, depth, queue, rewrite);
                    rewrite_stmts(then_body, templates, depth, queue, rewrite);
                    rewrite_stmts(else_body, templates, depth, queue, rewrite);
                }
                Stmt::While { condition, body } => {
                    rewrite_expr(condition, templates, depth, queue, rewrite);
                    rewrite_stmts(body, templates, depth, queue, rewrite);
                }
                Stmt::For {
                    init,
                    condition,
                    step,
                    body,
                } => {
                    if let Some(init) = init {
                        rewrite_stmts(
                            std::slice::from_mut(init.as_mut()),
                            templates,
                            depth,
                            queue,
                            rewrite,
                        );
                    }
                    if let Some(condition) = condition {
                        rewrite_expr(condition, templates, depth, queue, rewrite);
                    }
                    if let Some(step) = step {
                        rewrite_stmts(
                            std::slice::from_mut(step.as_mut()),
                            templates,
                            depth,
                            queue,
                            rewrite,
                        );
                    }
                    rewrite_stmts(body, templates, depth, queue, rewrite);
                }
                Stmt::ForIn { iterable, body, .. } => {
                    rewrite_expr(iterable, templates, depth, queue, rewrite);
                    rewrite_stmts(body, templates, depth, queue, rewrite);
                }
                Stmt::Loop { body } => rewrite_stmts(body, templates, depth, queue, rewrite),
                Stmt::Match { scrutinee, arms } => {
                    rewrite_expr(scrutinee, templates, depth, queue, rewrite);
                    for arm in arms {
                        if let Some(guard) = &mut arm.guard {
                            rewrite_expr(guard, templates, depth, queue, rewrite);
                        }
                        rewrite_expr(&mut arm.value, templates, depth, queue, rewrite);
                    }
                }
                Stmt::Break(_) | Stmt::Continue => {}
            }
        }
    }

    rewrite_stmts(&mut function.body, templates, depth, queue, rewrite);
}

fn rewrite_generic_calls_in_stmts(stmts: &mut [Stmt], rewrite: &HashMap<String, String>) {
    fn rewrite_expr(expr: &mut Expr, rewrite: &HashMap<String, String>) {
        match expr {
            Expr::Call { callee, args } => {
                if let Some(mapped) = rewrite.get(callee).cloned() {
                    *callee = mapped;
                }
                for arg in args {
                    rewrite_expr(arg, rewrite);
                }
            }
            Expr::UnsafeBlock { body, .. } => rewrite_generic_calls_in_stmts(body, rewrite),
            Expr::FieldAccess { base, .. } => rewrite_expr(base, rewrite),
            Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    rewrite_expr(value, rewrite);
                }
            }
            Expr::EnumInit { payload, .. } | Expr::Tuple(payload) | Expr::ArrayLiteral(payload) => {
                for value in payload {
                    rewrite_expr(value, rewrite);
                }
            }
            Expr::ObjectLiteral(fields) => {
                for (_, value) in fields {
                    rewrite_expr(value, rewrite);
                }
            }
            Expr::Closure { body, .. }
            | Expr::Group(body)
            | Expr::Await(body)
            | Expr::Discard(body) => rewrite_expr(body, rewrite),
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                rewrite_expr(try_expr, rewrite);
                rewrite_expr(catch_expr, rewrite);
            }
            Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                rewrite_expr(condition, rewrite);
                rewrite_expr(then_expr, rewrite);
                rewrite_expr(else_expr, rewrite);
            }
            Expr::Match { scrutinee, arms } => {
                rewrite_expr(scrutinee, rewrite);
                for arm in arms {
                    if let Some(guard) = &mut arm.guard {
                        rewrite_expr(guard, rewrite);
                    }
                    rewrite_expr(&mut arm.value, rewrite);
                }
            }
            Expr::While { condition, body } => {
                rewrite_expr(condition, rewrite);
                rewrite_generic_calls_in_stmts(body, rewrite);
            }
            Expr::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    rewrite_generic_calls_in_stmts(std::slice::from_mut(init.as_mut()), rewrite);
                }
                if let Some(condition) = condition {
                    rewrite_expr(condition, rewrite);
                }
                if let Some(step) = step {
                    rewrite_generic_calls_in_stmts(std::slice::from_mut(step.as_mut()), rewrite);
                }
                rewrite_generic_calls_in_stmts(body, rewrite);
            }
            Expr::ForIn { iterable, body, .. } => {
                rewrite_expr(iterable, rewrite);
                rewrite_generic_calls_in_stmts(body, rewrite);
            }
            Expr::Loop { body } => rewrite_generic_calls_in_stmts(body, rewrite),
            Expr::Return(value) | Expr::Break(value) => {
                if let Some(value) = value {
                    rewrite_expr(value, rewrite);
                }
            }
            Expr::Continue => {}
            Expr::Unary { expr, .. } => rewrite_expr(expr, rewrite),
            Expr::Binary { left, right, .. } => {
                rewrite_expr(left, rewrite);
                rewrite_expr(right, rewrite);
            }
            Expr::Range { start, end, .. } => {
                rewrite_expr(start, rewrite);
                rewrite_expr(end, rewrite);
            }
            Expr::Index { base, index } => {
                rewrite_expr(base, rewrite);
                rewrite_expr(index, rewrite);
            }
            Expr::Int(_)
            | Expr::Float { .. }
            | Expr::Char(_)
            | Expr::Bool(_)
            | Expr::Str(_)
            | Expr::Ident(_) => {}
        }
    }

    for stmt in stmts {
        match stmt {
            Stmt::Let { value, .. }
            | Stmt::LetPattern { value, .. }
            | Stmt::Assign { value, .. }
            | Stmt::CompoundAssign { value, .. }
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value)
            | Stmt::Expr(value) => rewrite_expr(value, rewrite),
            Stmt::Return(value) => {
                if let Some(value) = value {
                    rewrite_expr(value, rewrite);
                }
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                rewrite_expr(condition, rewrite);
                rewrite_generic_calls_in_stmts(then_body, rewrite);
                rewrite_generic_calls_in_stmts(else_body, rewrite);
            }
            Stmt::While { condition, body } => {
                rewrite_expr(condition, rewrite);
                rewrite_generic_calls_in_stmts(body, rewrite);
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    rewrite_generic_calls_in_stmts(std::slice::from_mut(init.as_mut()), rewrite);
                }
                if let Some(condition) = condition {
                    rewrite_expr(condition, rewrite);
                }
                if let Some(step) = step {
                    rewrite_generic_calls_in_stmts(std::slice::from_mut(step.as_mut()), rewrite);
                }
                rewrite_generic_calls_in_stmts(body, rewrite);
            }
            Stmt::ForIn { iterable, body, .. } => {
                rewrite_expr(iterable, rewrite);
                rewrite_generic_calls_in_stmts(body, rewrite);
            }
            Stmt::Loop { body } => rewrite_generic_calls_in_stmts(body, rewrite),
            Stmt::Match { scrutinee, arms } => {
                rewrite_expr(scrutinee, rewrite);
                for arm in arms {
                    if let Some(guard) = &mut arm.guard {
                        rewrite_expr(guard, rewrite);
                    }
                    rewrite_expr(&mut arm.value, rewrite);
                }
            }
            Stmt::Break(_) | Stmt::Continue => {}
        }
    }
}

fn substitute_typevars_in_stmts(stmts: &mut [Stmt], bindings: &BTreeMap<String, Type>) {
    fn substitute_expr(expr: &mut Expr, bindings: &BTreeMap<String, Type>) {
        match expr {
            Expr::Call { callee, args } => {
                let current = callee.clone();
                let (base, explicit) = split_generic_callee(&current);
                if let Some(explicit) = explicit {
                    let rewritten = explicit
                        .iter()
                        .map(|ty| substitute_typevars(ty, bindings))
                        .collect::<Vec<_>>();
                    *callee = monomorphized_symbol(base, &rewritten);
                }
                for arg in args {
                    substitute_expr(arg, bindings);
                }
            }
            Expr::UnsafeBlock { body, .. } => substitute_typevars_in_stmts(body, bindings),
            Expr::FieldAccess { base, .. } => substitute_expr(base, bindings),
            Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    substitute_expr(value, bindings);
                }
            }
            Expr::EnumInit { payload, .. } | Expr::Tuple(payload) | Expr::ArrayLiteral(payload) => {
                for value in payload {
                    substitute_expr(value, bindings);
                }
            }
            Expr::ObjectLiteral(fields) => {
                for (_, value) in fields {
                    substitute_expr(value, bindings);
                }
            }
            Expr::Closure {
                params,
                return_type,
                body,
            } => {
                for param in params {
                    param.ty = substitute_typevars(&param.ty, bindings);
                }
                if let Some(return_type) = return_type {
                    *return_type = substitute_typevars(return_type, bindings);
                }
                substitute_expr(body, bindings);
            }
            Expr::Group(inner) | Expr::Await(inner) | Expr::Discard(inner) => {
                substitute_expr(inner, bindings)
            }
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                substitute_expr(try_expr, bindings);
                substitute_expr(catch_expr, bindings);
            }
            Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                substitute_expr(condition, bindings);
                substitute_expr(then_expr, bindings);
                substitute_expr(else_expr, bindings);
            }
            Expr::Match { scrutinee, arms } => {
                substitute_expr(scrutinee, bindings);
                for arm in arms {
                    if let Some(guard) = &mut arm.guard {
                        substitute_expr(guard, bindings);
                    }
                    substitute_expr(&mut arm.value, bindings);
                }
            }
            Expr::While { condition, body } => {
                substitute_expr(condition, bindings);
                substitute_typevars_in_stmts(body, bindings);
            }
            Expr::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    substitute_typevars_in_stmts(std::slice::from_mut(init.as_mut()), bindings);
                }
                if let Some(condition) = condition {
                    substitute_expr(condition, bindings);
                }
                if let Some(step) = step {
                    substitute_typevars_in_stmts(std::slice::from_mut(step.as_mut()), bindings);
                }
                substitute_typevars_in_stmts(body, bindings);
            }
            Expr::ForIn { iterable, body, .. } => {
                substitute_expr(iterable, bindings);
                substitute_typevars_in_stmts(body, bindings);
            }
            Expr::Loop { body } => substitute_typevars_in_stmts(body, bindings),
            Expr::Return(value) | Expr::Break(value) => {
                if let Some(value) = value {
                    substitute_expr(value, bindings);
                }
            }
            Expr::Continue => {}
            Expr::Unary { expr, .. } => substitute_expr(expr, bindings),
            Expr::Binary { left, right, .. } => {
                substitute_expr(left, bindings);
                substitute_expr(right, bindings);
            }
            Expr::Range { start, end, .. } => {
                substitute_expr(start, bindings);
                substitute_expr(end, bindings);
            }
            Expr::Index { base, index } => {
                substitute_expr(base, bindings);
                substitute_expr(index, bindings);
            }
            Expr::Int(_)
            | Expr::Float { .. }
            | Expr::Char(_)
            | Expr::Bool(_)
            | Expr::Str(_)
            | Expr::Ident(_) => {}
        }
    }

    for stmt in stmts {
        match stmt {
            Stmt::Let { ty, value, .. } | Stmt::LetPattern { ty, value, .. } => {
                if let Some(ty) = ty {
                    *ty = substitute_typevars(ty, bindings);
                }
                substitute_expr(value, bindings);
            }
            Stmt::Assign { value, .. }
            | Stmt::CompoundAssign { value, .. }
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value)
            | Stmt::Expr(value) => substitute_expr(value, bindings),
            Stmt::Return(value) => {
                if let Some(value) = value {
                    substitute_expr(value, bindings);
                }
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                substitute_expr(condition, bindings);
                substitute_typevars_in_stmts(then_body, bindings);
                substitute_typevars_in_stmts(else_body, bindings);
            }
            Stmt::While { condition, body } => {
                substitute_expr(condition, bindings);
                substitute_typevars_in_stmts(body, bindings);
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    substitute_typevars_in_stmts(std::slice::from_mut(init.as_mut()), bindings);
                }
                if let Some(condition) = condition {
                    substitute_expr(condition, bindings);
                }
                if let Some(step) = step {
                    substitute_typevars_in_stmts(std::slice::from_mut(step.as_mut()), bindings);
                }
                substitute_typevars_in_stmts(body, bindings);
            }
            Stmt::ForIn { iterable, body, .. } => {
                substitute_expr(iterable, bindings);
                substitute_typevars_in_stmts(body, bindings);
            }
            Stmt::Loop { body } => substitute_typevars_in_stmts(body, bindings),
            Stmt::Match { scrutinee, arms } => {
                substitute_expr(scrutinee, bindings);
                for arm in arms {
                    if let Some(guard) = &mut arm.guard {
                        substitute_expr(guard, bindings);
                    }
                    substitute_expr(&mut arm.value, bindings);
                }
            }
            Stmt::Break(_) | Stmt::Continue => {}
        }
    }
}

fn resolve_call_signature(
    params: &[Type],
    ret: &Type,
    generics: &[ast::GenericParam],
    arg_types: &[Option<Type>],
    explicit_types: Option<&[Type]>,
) -> Option<CallSignature> {
    let mut bindings = BTreeMap::<String, Type>::new();
    if let Some(explicit_types) = explicit_types {
        if explicit_types.len() != generics.len() {
            return None;
        }
        for (generic, concrete) in generics.iter().zip(explicit_types) {
            bindings.insert(generic.name.clone(), concrete.clone());
        }
    }
    for (param, arg_ty) in params.iter().zip(arg_types.iter()) {
        let Some(arg_ty) = arg_ty else {
            continue;
        };
        if !type_contains_typevars(param) {
            continue;
        }
        if !bind_typevars(param, arg_ty, &mut bindings) {
            return None;
        }
    }
    let resolved_params = params
        .iter()
        .map(|ty| substitute_typevars(ty, &bindings))
        .collect::<Vec<_>>();
    let resolved_ret = substitute_typevars(ret, &bindings);
    Some((
        resolved_params,
        resolved_ret,
        bindings.into_iter().collect::<Vec<_>>(),
    ))
}

fn type_contains_typevars(ty: &Type) -> bool {
    let mut names = BTreeSet::new();
    collect_typevars_from_type(ty, &mut names);
    !names.is_empty()
}

fn collect_typevars_from_type(ty: &Type, out: &mut BTreeSet<String>) {
    match ty {
        Type::TypeVar(name) => {
            out.insert(name.clone());
        }
        Type::Ptr { to, .. } | Type::Ref { to, .. } => collect_typevars_from_type(to, out),
        Type::Slice(inner)
        | Type::Set(inner)
        | Type::Deque(inner)
        | Type::Ring(inner)
        | Type::Option(inner)
        | Type::Vec(inner)
        | Type::Future(inner) => collect_typevars_from_type(inner, out),
        Type::Array { elem, .. } => collect_typevars_from_type(elem, out),
        Type::Result { ok, err } => {
            collect_typevars_from_type(ok, out);
            collect_typevars_from_type(err, out);
        }
        Type::Map { key, value } => {
            collect_typevars_from_type(key, out);
            collect_typevars_from_type(value, out);
        }
        Type::Tuple(items) => {
            for item in items {
                collect_typevars_from_type(item, out);
            }
        }
        Type::Named { args, .. } => {
            for arg in args {
                collect_typevars_from_type(arg, out);
            }
        }
        Type::Function { params, ret } => {
            for param in params {
                collect_typevars_from_type(param, out);
            }
            collect_typevars_from_type(ret, out);
        }
        _ => {}
    }
}

fn runtime_signature_generics(params: &[Type], ret: &Type) -> Vec<ast::GenericParam> {
    let mut names = BTreeSet::new();
    for param in params {
        collect_typevars_from_type(param, &mut names);
    }
    collect_typevars_from_type(ret, &mut names);
    names
        .into_iter()
        .map(|name| ast::GenericParam {
            name,
            bounds: Vec::new(),
        })
        .collect()
}

fn bind_typevars(template: &Type, concrete: &Type, bindings: &mut BTreeMap<String, Type>) -> bool {
    match template {
        Type::TypeVar(name) => {
            if let Some(existing) = bindings.get(name) {
                type_compatible(existing, concrete)
            } else {
                bindings.insert(name.clone(), concrete.clone());
                true
            }
        }
        Type::Named { name, args } => match concrete {
            Type::Named {
                name: other_name,
                args: other_args,
            } if name == other_name && args.len() == other_args.len() => args
                .iter()
                .zip(other_args.iter())
                .all(|(left, right)| bind_typevars(left, right, bindings)),
            _ => false,
        },
        Type::Ptr {
            mutable,
            to: template_to,
        } => {
            matches!(concrete, Type::Ptr { mutable: other_mut, to: other_to } if mutable == other_mut && bind_typevars(template_to, other_to, bindings))
        }
        Type::Ref {
            mutable,
            lifetime,
            to: template_to,
        } => match concrete {
            Type::Ref {
                mutable: other_mut,
                lifetime: other_lifetime,
                to: other_to,
            } => {
                mutable == other_mut
                    && lifetime == other_lifetime
                    && bind_typevars(template_to, other_to, bindings)
            }
            _ => bind_typevars(template_to, concrete, bindings),
        },
        Type::Slice(inner) => {
            matches!(concrete, Type::Slice(other) if bind_typevars(inner, other, bindings))
                || matches!(concrete, Type::Array { elem, .. } if bind_typevars(inner, elem, bindings))
        }
        Type::Array { elem, len } => {
            matches!(concrete, Type::Array { elem: other_elem, len: other_len } if len == other_len && bind_typevars(elem, other_elem, bindings))
        }
        Type::Result { ok, err } => {
            matches!(concrete, Type::Result { ok: other_ok, err: other_err } if bind_typevars(ok, other_ok, bindings) && bind_typevars(err, other_err, bindings))
        }
        Type::Map { key, value } => {
            matches!(concrete, Type::Map { key: other_key, value: other_value }
                if bind_typevars(key, other_key, bindings) && bind_typevars(value, other_value, bindings))
        }
        Type::Set(inner) => {
            matches!(concrete, Type::Set(other) if bind_typevars(inner, other, bindings))
        }
        Type::Deque(inner) => {
            matches!(concrete, Type::Deque(other) if bind_typevars(inner, other, bindings))
        }
        Type::Ring(inner) => {
            matches!(concrete, Type::Ring(other) if bind_typevars(inner, other, bindings))
        }
        Type::Option(inner) => {
            matches!(concrete, Type::Option(other) if bind_typevars(inner, other, bindings))
        }
        Type::Vec(inner) => {
            matches!(concrete, Type::Vec(other) if bind_typevars(inner, other, bindings))
        }
        Type::Future(inner) => {
            matches!(concrete, Type::Future(other) if bind_typevars(inner, other, bindings))
        }
        Type::Tuple(items) => {
            matches!(concrete, Type::Tuple(other_items) if items.len() == other_items.len()
                && items.iter().zip(other_items.iter()).all(|(left, right)| bind_typevars(left, right, bindings)))
        }
        Type::DynTrait(name) => matches!(concrete, Type::DynTrait(other) if name == other),
        _ => type_compatible(template, concrete),
    }
}

fn substitute_typevars(ty: &Type, bindings: &BTreeMap<String, Type>) -> Type {
    match ty {
        Type::TypeVar(name) => bindings
            .get(name)
            .cloned()
            .unwrap_or_else(|| Type::TypeVar(name.clone())),
        Type::Ptr { mutable, to } => Type::Ptr {
            mutable: *mutable,
            to: Box::new(substitute_typevars(to, bindings)),
        },
        Type::Ref {
            mutable,
            lifetime,
            to,
        } => Type::Ref {
            mutable: *mutable,
            lifetime: lifetime.clone(),
            to: Box::new(substitute_typevars(to, bindings)),
        },
        Type::Slice(inner) => Type::Slice(Box::new(substitute_typevars(inner, bindings))),
        Type::Array { elem, len } => Type::Array {
            elem: Box::new(substitute_typevars(elem, bindings)),
            len: *len,
        },
        Type::Result { ok, err } => Type::Result {
            ok: Box::new(substitute_typevars(ok, bindings)),
            err: Box::new(substitute_typevars(err, bindings)),
        },
        Type::Map { key, value } => Type::Map {
            key: Box::new(substitute_typevars(key, bindings)),
            value: Box::new(substitute_typevars(value, bindings)),
        },
        Type::Set(inner) => Type::Set(Box::new(substitute_typevars(inner, bindings))),
        Type::Deque(inner) => Type::Deque(Box::new(substitute_typevars(inner, bindings))),
        Type::Ring(inner) => Type::Ring(Box::new(substitute_typevars(inner, bindings))),
        Type::Option(inner) => Type::Option(Box::new(substitute_typevars(inner, bindings))),
        Type::Vec(inner) => Type::Vec(Box::new(substitute_typevars(inner, bindings))),
        Type::Future(inner) => Type::Future(Box::new(substitute_typevars(inner, bindings))),
        Type::DynTrait(name) => Type::DynTrait(name.clone()),
        Type::Tuple(items) => Type::Tuple(
            items
                .iter()
                .map(|item| substitute_typevars(item, bindings))
                .collect(),
        ),
        Type::Named { name, args } => Type::Named {
            name: name.clone(),
            args: args
                .iter()
                .map(|arg| substitute_typevars(arg, bindings))
                .collect(),
        },
        other => other.clone(),
    }
}

fn trait_impl_match_count(
    ty: &Type,
    trait_name: &str,
    trait_impls: &HashMap<String, Vec<Type>>,
) -> usize {
    if trait_name == "Error" {
        match ty {
            Type::Str
            | Type::Int { .. }
            | Type::ISize
            | Type::USize
            | Type::Path
            | Type::PathBuf
            | Type::Url
            | Type::SocketAddr
            | Type::Decimal
            | Type::DateTimeTz
            | Type::ExitStatus
            | Type::Named { .. } => return 1,
            _ => {}
        }
    }
    trait_impls
        .get(trait_name)
        .map(|impls| {
            impls
                .iter()
                .filter(|candidate| type_compatible(candidate, ty))
                .count()
        })
        .unwrap_or(0)
}

pub fn is_runtime_intrinsic(name: &str) -> bool {
    runtime_intrinsic_names().contains(&name)
}

pub fn runtime_intrinsic_names() -> &'static [&'static str] {
    &[
        "spawn",
        "thread.spawn",
        "spawn_ctx",
        "thread.spawn_ctx",
        "join",
        "detach",
        "cancel_task",
        "task_result",
        "yield",
        "checkpoint",
        "assert.eq_i32",
        "timeout",
        "deadline",
        "cancel",
        "recv",
        "pulse",
        "task.context_id",
        "task.group_begin",
        "task.group_spawn",
        "task.group_spawn_n",
        "task.group_join",
        "task.group_join_all",
        "task.group_cancel",
        "task.parallel_map",
        "gpu.device_count",
        "gpu.default_device",
        "gpu.device_name",
        "gpu.device_memory_bytes",
        "gpu.alloc_f32",
        "gpu.alloc_i32",
        "gpu.alloc_u32",
        "gpu.free",
        "gpu.upload_f32",
        "gpu.upload_i32",
        "gpu.upload_u32",
        "gpu.download_f32",
        "gpu.download_i32",
        "gpu.download_u32",
        "gpu.slice",
        "gpu.slice_len",
        "gpu.load_f32",
        "gpu.load_i32",
        "gpu.load_u32",
        "gpu.store_f32",
        "gpu.store_i32",
        "gpu.store_u32",
        "gpu.launch0",
        "gpu.launch1",
        "gpu.launch2",
        "gpu.launch3",
        "gpu.launch4",
        "gpu.wait",
        "gpu.wait_async",
        "gpu.global_id_x",
        "gpu.global_id_y",
        "gpu.global_id_z",
        "gpu.thread_id_x",
        "gpu.thread_id_y",
        "gpu.thread_id_z",
        "gpu.block_id_x",
        "gpu.block_id_y",
        "gpu.block_id_z",
        "gpu.block_dim_x",
        "gpu.block_dim_y",
        "gpu.block_dim_z",
        "gpu.grid_dim_x",
        "gpu.grid_dim_y",
        "gpu.grid_dim_z",
        "gpu.barrier",
        "alloc",
        "free",
        "mem.freeze",
        "mem.unfreeze",
        "close",
        "http.bind",
        "http.accept",
        "http.connect",
        "http.poll_next",
        "http.listen",
        "http.read",
        "http.read_headers",
        "http.close",
        "http.poll_register",
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
        "http.write",
        "http.write_json",
        "http.write_response",
        "http.websocket_accept",
        "http.websocket_read",
        "http.websocket_kind",
        "http.websocket_close_code",
        "http.websocket_error",
        "http.websocket_write_text",
        "http.websocket_write_binary",
        "http.websocket_ping",
        "http.websocket_pong",
        "http.websocket_close",
        "http.post_json",
        "http.post_json_capture",
        "http.post_json_stream",
        "http.request_stream",
        "http.stream_read",
        "http.stream_read_line",
        "http.stream_eof",
        "http.stream_status",
        "http.stream_error",
        "http.stream_close",
        "http.header_set",
        "http.last_status",
        "http.last_error",
        "crypto.random_hex",
        "crypto.random_base64",
        "crypto.sha256",
        "crypto.hmac_sha256",
        "crypto.constant_time_eq",
        "crypto.base64_encode",
        "crypto.base64_decode",
        "crypto.base64_url_encode",
        "crypto.base64_url_decode",
        "simd.__i32x4",
        "simd.__u32x4",
        "simd.__f32x4",
        "simd.__mask32x4",
        "simd.__i32x4_splat",
        "simd.__i32x4_load",
        "simd.__i32x4_load_aligned_ptr",
        "simd.__i32x4_load_unaligned_ptr",
        "simd.__i32x4_store_aligned_ptr",
        "simd.__i32x4_store_unaligned_ptr",
        "simd.__u32x4_splat",
        "simd.__u32x4_load",
        "simd.__u32x4_load_aligned_ptr",
        "simd.__u32x4_load_unaligned_ptr",
        "simd.__u32x4_store_aligned_ptr",
        "simd.__u32x4_store_unaligned_ptr",
        "simd.__f32x4_splat",
        "simd.__f32x4_load",
        "simd.__f32x4_load_aligned_ptr",
        "simd.__f32x4_load_unaligned_ptr",
        "simd.__f32x4_store_aligned_ptr",
        "simd.__f32x4_store_unaligned_ptr",
        "simd.__mask32x4_splat",
        "simd.__mask32x4_load",
        "simd.__mask32x4_load_aligned_ptr",
        "simd.__mask32x4_load_unaligned_ptr",
        "simd.__mask32x4_store_aligned_ptr",
        "simd.__mask32x4_store_unaligned_ptr",
        "simd.__i32x4_add",
        "simd.__i32x4_sub",
        "simd.__i32x4_mul",
        "simd.__i32x4_saturating_add",
        "simd.__i32x4_saturating_sub",
        "simd.__i32x4_shl",
        "simd.__i32x4_shr",
        "simd.__i32x4_min",
        "simd.__i32x4_max",
        "simd.__u32x4_add",
        "simd.__u32x4_sub",
        "simd.__u32x4_mul",
        "simd.__u32x4_saturating_add",
        "simd.__u32x4_saturating_sub",
        "simd.__u32x4_shl",
        "simd.__u32x4_shr",
        "simd.__u32x4_min",
        "simd.__u32x4_max",
        "simd.__f32x4_add",
        "simd.__f32x4_sub",
        "simd.__f32x4_mul",
        "simd.__f32x4_min",
        "simd.__f32x4_max",
        "simd.__i32x4_and",
        "simd.__i32x4_or",
        "simd.__i32x4_xor",
        "simd.__i32x4_not",
        "simd.__u32x4_and",
        "simd.__u32x4_or",
        "simd.__u32x4_xor",
        "simd.__u32x4_not",
        "simd.__mask32x4_and",
        "simd.__mask32x4_or",
        "simd.__mask32x4_xor",
        "simd.__mask32x4_not",
        "simd.__i32x4_eq",
        "simd.__i32x4_ne",
        "simd.__i32x4_lt",
        "simd.__i32x4_le",
        "simd.__i32x4_gt",
        "simd.__i32x4_ge",
        "simd.__u32x4_eq",
        "simd.__u32x4_ne",
        "simd.__u32x4_lt",
        "simd.__u32x4_le",
        "simd.__u32x4_gt",
        "simd.__u32x4_ge",
        "simd.__f32x4_eq",
        "simd.__f32x4_ne",
        "simd.__f32x4_lt",
        "simd.__f32x4_le",
        "simd.__f32x4_gt",
        "simd.__f32x4_ge",
        "simd.__i32x4_select",
        "simd.__u32x4_select",
        "simd.__f32x4_select",
        "simd.__i32x4_shuffle",
        "simd.__u32x4_shuffle",
        "simd.__f32x4_shuffle",
        "simd.__mask32x4_shuffle",
        "simd.__i32x4_as_u32x4",
        "simd.__u32x4_as_i32x4",
        "simd.__i32x4_bitcast_f32x4",
        "simd.__u32x4_bitcast_f32x4",
        "simd.__f32x4_bitcast_i32x4",
        "simd.__f32x4_bitcast_u32x4",
        "simd.__i32x4_reduce_add",
        "simd.__i32x4_reduce_min",
        "simd.__i32x4_reduce_max",
        "simd.__u32x4_reduce_add",
        "simd.__u32x4_reduce_min",
        "simd.__u32x4_reduce_max",
        "simd.__f32x4_reduce_add",
        "simd.__f32x4_reduce_min",
        "simd.__f32x4_reduce_max",
        "simd.__mask32x4_any",
        "simd.__mask32x4_all",
        "simd.__mask32x4_none",
        "simd.__mask32x4_bitmask",
        "simd.__i32x4_lane0",
        "simd.__i32x4_lane1",
        "simd.__i32x4_lane2",
        "simd.__i32x4_lane3",
        "simd.__u32x4_lane0",
        "simd.__u32x4_lane1",
        "simd.__u32x4_lane2",
        "simd.__u32x4_lane3",
        "simd.__f32x4_lane0",
        "simd.__f32x4_lane1",
        "simd.__f32x4_lane2",
        "simd.__f32x4_lane3",
        "simd.__mask32x4_lane0",
        "simd.__mask32x4_lane1",
        "simd.__mask32x4_lane2",
        "simd.__mask32x4_lane3",
        "env.get",
        "proc.argv_count",
        "proc.argv_get",
        "term.read_line",
        "term.stdin_eof",
        "term.write",
        "term.write_err",
        "term.stdin_is_tty",
        "term.stdout_is_tty",
        "str.concat",
        "str.concat2",
        "str.concat3",
        "str.concat4",
        "str.from_i32",
        "str.from_bool",
        "str.repeat",
        "str.contains",
        "str.starts_with",
        "str.ends_with",
        "str.replace",
        "str.trim",
        "str.split",
        "str.len",
        "str.visible_len_ansi",
        "str.slice",
        "str.upper_ascii",
        "str.lower_ascii",
        "json.escape",
        "json.str",
        "json.raw",
        "json.from_list",
        "json.from_map",
        "json.array",
        "json.object",
        "json.to_list",
        "json.to_map",
        "json.keys",
        "json.parse",
        "json.get",
        "json.get_str",
        "json.has",
        "json.path",
        "time.now",
        "time.monotonic_ms",
        "time.sleep_ms",
        "time.interval",
        "time.tick",
        "time.elapsed_ms",
        "time.deadline_after",
        "fs.open",
        "fs.close",
        "fs.write",
        "fs.flush",
        "fs.atomic_write",
        "fs.fsync",
        "fs.lock",
        "fs.read",
        "fs.read_file",
        "fs.write_file",
        "fs.mkdir",
        "fs.exists",
        "fs.is_file",
        "fs.is_dir",
        "fs.is_symlink",
        "fs.remove_file",
        "fs.remove",
        "fs.stat_size",
        "fs.stat_mtime",
        "fs.listdir",
        "fs.temp_file",
        "fs.copy_file",
        "fs.copy_tree",
        "path.join",
        "path.basename",
        "path.dirname",
        "path.stem",
        "path.extension",
        "path.normalize",
        "route.match",
        "route.write_404",
        "route.write_405",
        "log.info",
        "log.warn",
        "log.error",
        "log.fields",
        "log.set_json",
        "log.set_enabled",
        "log.set_level",
        "log.set_sink",
        "log.correlation_id",
        "error.code",
        "error.class",
        "error.message",
        "error.context",
        "proc.run",
        "proc.spawn",
        "proc.runl",
        "proc.spawnl",
        "proc.argv_new",
        "proc.argv_push",
        "proc.env_new",
        "proc.env_set",
        "proc.close",
        "proc.spawn_cmd",
        "proc.run_cmd",
        "proc.exec_timeout",
        "proc.wait",
        "proc.poll",
        "proc.event",
        "proc.read_stdout",
        "proc.read_stderr",
        "proc.stdout",
        "proc.stderr",
        "proc.exit_code",
        "proc.exit_class",
        "ctx.deadline",
        "ctx.cancel_if_timeout",
        "channel.send",
        "channel.recv",
        "list.new",
        "list.push",
        "list.pop",
        "list.len",
        "list.get",
        "list.set",
        "list.clear",
        "list.join",
        "map.new",
        "map.set",
        "map.get",
        "map.has",
        "map.delete",
        "map.keys",
        "map.len",
        "storage.append",
        "storage.atomic_append",
        "storage.kv_open",
        "storage.kv_close",
        "storage.kv_get",
        "storage.kv_put",
    ]
}

fn nearest_intrinsic_name(name: &str) -> Option<String> {
    runtime_intrinsic_names()
        .iter()
        .map(|candidate| (*candidate, edit_distance(name, candidate)))
        .min_by_key(|(_, distance)| *distance)
        .and_then(|(candidate, distance)| (distance <= 6).then_some(candidate.to_string()))
}

fn builtin_namespace_hint(name: &str) -> Option<String> {
    let namespace = name.split('.').next()?;
    match namespace {
        "env" | "str" | "json" | "list" | "map" | "route" | "gpu" | "mem" => Some(format!(
            "`{namespace}.*` is a builtin namespace; call it directly and do not treat `core.{namespace}` as an ordinary imported module"
        )),
        "process" => Some(
            "`process.*` was removed; use `proc.*` runtime intrinsics or `use core.process;` for the stdlib facade"
                .to_string(),
        ),
        "proc" | "term" => Some(format!(
            "`{namespace}.*` is always available as a runtime intrinsic namespace; `use core.{namespace}` is only needed for the higher-level stdlib facade"
        )),
        _ => None,
    }
}

fn edit_distance(left: &str, right: &str) -> usize {
    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut prev = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut curr = vec![0usize; right_chars.len() + 1];
    for (i, lch) in left_chars.iter().enumerate() {
        curr[0] = i + 1;
        for (j, rch) in right_chars.iter().enumerate() {
            let cost = if lch == rch { 0 } else { 1 };
            curr[j + 1] = (curr[j] + 1).min(prev[j + 1] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[right_chars.len()]
}

fn i32_type() -> Type {
    Type::Int {
        signed: true,
        bits: 32,
    }
}

fn runtime_call_signature(name: &str) -> Option<(Vec<Type>, Type)> {
    let i32 = i32_type();
    let i64 = Type::Int {
        signed: true,
        bits: 64,
    };
    let task_handle = Type::Named {
        name: "TaskHandle".to_string(),
        args: Vec::new(),
    };
    let task_group_handle = Type::Named {
        name: "TaskGroupHandle".to_string(),
        args: Vec::new(),
    };
    let http_handle = Type::Named {
        name: "HttpHandle".to_string(),
        args: Vec::new(),
    };
    let http_stream_handle = Type::Named {
        name: "HttpStreamHandle".to_string(),
        args: Vec::new(),
    };
    let websocket_handle = Type::Named {
        name: "WebSocketHandle".to_string(),
        args: Vec::new(),
    };
    let json_handle = Type::Named {
        name: "JsonHandle".to_string(),
        args: Vec::new(),
    };
    let list_handle = Type::Named {
        name: "ListHandle".to_string(),
        args: Vec::new(),
    };
    let map_handle = Type::Named {
        name: "MapHandle".to_string(),
        args: Vec::new(),
    };
    let proc_handle = Type::Named {
        name: "ProcessHandle".to_string(),
        args: Vec::new(),
    };
    let proc_argv = Type::Named {
        name: "ProcessArgv".to_string(),
        args: Vec::new(),
    };
    let proc_env = Type::Named {
        name: "ProcessEnv".to_string(),
        args: Vec::new(),
    };
    let file_handle = Type::Named {
        name: "FileHandle".to_string(),
        args: Vec::new(),
    };
    let kv_handle = Type::Named {
        name: "KvStoreHandle".to_string(),
        args: Vec::new(),
    };
    let channel_handle = Type::Named {
        name: "ChannelHandle".to_string(),
        args: Vec::new(),
    };
    let gpu_device = Type::Named {
        name: "GpuDevice".to_string(),
        args: Vec::new(),
    };
    let gpu_event = Type::Named {
        name: "GpuEvent".to_string(),
        args: Vec::new(),
    };
    let launch_a = Type::TypeVar("LaunchA".to_string());
    let launch_b = Type::TypeVar("LaunchB".to_string());
    let launch_c = Type::TypeVar("LaunchC".to_string());
    let launch_d = Type::TypeVar("LaunchD".to_string());
    let gpu_type_var = Type::TypeVar("T".to_string());
    let gpu_buffer = Type::Named {
        name: "GpuBuffer".to_string(),
        args: vec![gpu_type_var.clone()],
    };
    let gpu_slice = Type::Named {
        name: "GpuSlice".to_string(),
        args: vec![gpu_type_var.clone()],
    };
    let gpu_buffer_f32 = Type::Named {
        name: "GpuBuffer".to_string(),
        args: vec![Type::Float { bits: 32 }],
    };
    let gpu_buffer_i32 = Type::Named {
        name: "GpuBuffer".to_string(),
        args: vec![i32.clone()],
    };
    let gpu_buffer_u32 = Type::Named {
        name: "GpuBuffer".to_string(),
        args: vec![Type::Int {
            signed: false,
            bits: 32,
        }],
    };
    let gpu_slice_f32 = Type::Named {
        name: "GpuSlice".to_string(),
        args: vec![Type::Float { bits: 32 }],
    };
    let gpu_slice_i32 = Type::Named {
        name: "GpuSlice".to_string(),
        args: vec![i32.clone()],
    };
    let gpu_slice_u32 = Type::Named {
        name: "GpuSlice".to_string(),
        args: vec![Type::Int {
            signed: false,
            bits: 32,
        }],
    };
    let task_fn = Type::Function {
        params: Vec::new(),
        ret: Box::new(i32.clone()),
    };
    let usize_ty = Type::USize;
    let u8_ty = Type::Int {
        signed: false,
        bits: 8,
    };
    let ptr_u8 = Type::Ptr {
        mutable: true,
        to: Box::new(u8_ty),
    };
    let str_ty = Type::Str;
    let i32x4 = Type::SimdVector(ast::SimdVectorType {
        element: ast::SimdElement::I32,
        lanes: 4,
    });
    let u32x4 = Type::SimdVector(ast::SimdVectorType {
        element: ast::SimdElement::U32,
        lanes: 4,
    });
    let f32x4 = Type::SimdVector(ast::SimdVectorType {
        element: ast::SimdElement::F32,
        lanes: 4,
    });
    let mask32x4 = Type::SimdMask(ast::SimdMaskType {
        lane_bits: 32,
        lanes: 4,
    });
    let bool_ty = Type::Bool;
    let u32_ty = Type::Int {
        signed: false,
        bits: 32,
    };
    let f32_ty = Type::Float { bits: 32 };
    Some(match name {
        "spawn" | "thread.spawn" => (vec![task_fn.clone()], task_handle.clone()),
        "spawn_ctx" | "thread.spawn_ctx" => {
            (vec![task_fn.clone(), i32.clone()], task_handle.clone())
        }
        "join" | "task_result" => (vec![task_handle.clone()], i32.clone()),
        "detach" | "cancel_task" => (vec![task_handle.clone()], i32.clone()),
        "yield" | "checkpoint" | "cancel" | "recv" | "pulse" => (vec![], i32.clone()),
        "assert.eq_i32" => (vec![i32.clone(), i32.clone()], i32.clone()),
        "timeout" | "deadline" => (vec![i32.clone()], i32.clone()),
        "task.context_id" => (vec![], i32.clone()),
        "task.group_begin" => (vec![], task_group_handle.clone()),
        "task.group_spawn" => (
            vec![task_group_handle.clone(), task_fn],
            task_handle.clone(),
        ),
        "task.group_spawn_n" => (
            vec![task_group_handle.clone(), task_fn, i32.clone()],
            i32.clone(),
        ),
        "task.group_join" | "task.group_join_all" | "task.group_cancel" => {
            (vec![task_group_handle.clone()], i32.clone())
        }
        "task.parallel_map" => (vec![task_group_handle.clone(), task_fn], i32.clone()),
        "gpu.device_count" => (vec![], i32.clone()),
        "gpu.default_device" => (vec![], gpu_device.clone()),
        "gpu.device_name" => (vec![gpu_device.clone()], str_ty.clone()),
        "gpu.device_memory_bytes" => (vec![gpu_device.clone()], i64.clone()),
        "gpu.alloc_f32" => (
            vec![gpu_device.clone(), i32.clone()],
            gpu_buffer_f32.clone(),
        ),
        "gpu.alloc_i32" => (
            vec![gpu_device.clone(), i32.clone()],
            gpu_buffer_i32.clone(),
        ),
        "gpu.alloc_u32" => (
            vec![gpu_device.clone(), i32.clone()],
            gpu_buffer_u32.clone(),
        ),
        "gpu.free" => (vec![gpu_buffer.clone()], Type::Void),
        "gpu.upload_f32" => (
            vec![gpu_device.clone(), Type::Slice(Box::new(f32_ty.clone()))],
            gpu_buffer_f32.clone(),
        ),
        "gpu.upload_i32" => (
            vec![gpu_device.clone(), Type::Slice(Box::new(i32.clone()))],
            gpu_buffer_i32.clone(),
        ),
        "gpu.upload_u32" => (
            vec![gpu_device.clone(), Type::Slice(Box::new(u32_ty.clone()))],
            gpu_buffer_u32.clone(),
        ),
        "gpu.download_f32" => (
            vec![gpu_buffer_f32.clone()],
            Type::Vec(Box::new(f32_ty.clone())),
        ),
        "gpu.download_i32" => (
            vec![gpu_buffer_i32.clone()],
            Type::Vec(Box::new(i32.clone())),
        ),
        "gpu.download_u32" => (
            vec![gpu_buffer_u32.clone()],
            Type::Vec(Box::new(u32_ty.clone())),
        ),
        "gpu.slice" => (
            vec![gpu_buffer.clone(), i32.clone(), i32.clone()],
            gpu_slice.clone(),
        ),
        "gpu.slice_len" => (vec![gpu_slice.clone()], i32.clone()),
        "gpu.load_f32" => (vec![gpu_slice_f32.clone(), i32.clone()], f32_ty.clone()),
        "gpu.load_i32" => (vec![gpu_slice_i32.clone(), i32.clone()], i32.clone()),
        "gpu.load_u32" => (vec![gpu_slice_u32.clone(), i32.clone()], u32_ty.clone()),
        "gpu.store_f32" => (
            vec![gpu_slice_f32.clone(), i32.clone(), f32_ty.clone()],
            Type::Void,
        ),
        "gpu.store_i32" => (
            vec![gpu_slice_i32.clone(), i32.clone(), i32.clone()],
            Type::Void,
        ),
        "gpu.store_u32" => (
            vec![gpu_slice_u32.clone(), i32.clone(), u32_ty.clone()],
            Type::Void,
        ),
        "gpu.launch0" => (
            vec![
                Type::Function {
                    params: Vec::new(),
                    ret: Box::new(Type::Void),
                },
                i32.clone(),
                i32.clone(),
            ],
            gpu_event.clone(),
        ),
        "gpu.launch1" => (
            vec![
                Type::Function {
                    params: vec![launch_a.clone()],
                    ret: Box::new(Type::Void),
                },
                i32.clone(),
                i32.clone(),
                launch_a.clone(),
            ],
            gpu_event.clone(),
        ),
        "gpu.launch2" => (
            vec![
                Type::Function {
                    params: vec![launch_a.clone(), launch_b.clone()],
                    ret: Box::new(Type::Void),
                },
                i32.clone(),
                i32.clone(),
                launch_a.clone(),
                launch_b.clone(),
            ],
            gpu_event.clone(),
        ),
        "gpu.launch3" => (
            vec![
                Type::Function {
                    params: vec![launch_a.clone(), launch_b.clone(), launch_c.clone()],
                    ret: Box::new(Type::Void),
                },
                i32.clone(),
                i32.clone(),
                launch_a.clone(),
                launch_b.clone(),
                launch_c.clone(),
            ],
            gpu_event.clone(),
        ),
        "gpu.launch4" => (
            vec![
                Type::Function {
                    params: vec![
                        launch_a.clone(),
                        launch_b.clone(),
                        launch_c.clone(),
                        launch_d.clone(),
                    ],
                    ret: Box::new(Type::Void),
                },
                i32.clone(),
                i32.clone(),
                launch_a.clone(),
                launch_b.clone(),
                launch_c.clone(),
                launch_d.clone(),
            ],
            gpu_event.clone(),
        ),
        "gpu.wait" => (vec![gpu_event.clone()], i32.clone()),
        "gpu.wait_async" => (vec![gpu_event.clone()], Type::Future(Box::new(i32.clone()))),
        "gpu.global_id_x" | "gpu.global_id_y" | "gpu.global_id_z" => (vec![], i32.clone()),
        "gpu.thread_id_x" | "gpu.thread_id_y" | "gpu.thread_id_z" => (vec![], i32.clone()),
        "gpu.block_id_x" | "gpu.block_id_y" | "gpu.block_id_z" => (vec![], i32.clone()),
        "gpu.block_dim_x" | "gpu.block_dim_y" | "gpu.block_dim_z" => (vec![], i32.clone()),
        "gpu.grid_dim_x" | "gpu.grid_dim_y" | "gpu.grid_dim_z" => (vec![], i32.clone()),
        "gpu.barrier" => (vec![], Type::Void),
        "alloc" => (vec![usize_ty], ptr_u8.clone()),
        "free" => (vec![ptr_u8], Type::Void),
        "mem.freeze" | "mem.unfreeze" => (vec![], Type::Void),
        "close" => (vec![http_handle.clone()], Type::Void),
        "http.bind" | "http.accept" | "http.connect" | "http.poll_next" => {
            (vec![], http_handle.clone())
        }
        "http.listen" | "http.read" | "http.read_headers" | "http.close" | "http.poll_register" => {
            (vec![http_handle.clone()], i32.clone())
        }
        "http.method" | "http.path" | "http.body" => (vec![http_handle.clone()], str_ty.clone()),
        "http.body_read" => (vec![http_handle.clone(), i32.clone()], str_ty.clone()),
        "http.body_eof" | "http.body_discard" => (vec![http_handle.clone()], i32.clone()),
        "http.body_json" => (vec![http_handle.clone()], json_handle.clone()),
        "http.body_bind" => (vec![http_handle.clone()], json_handle.clone()),
        "http.header" | "http.query" | "http.param" => {
            (vec![http_handle.clone(), str_ty.clone()], str_ty.clone())
        }
        "http.headers" => (vec![http_handle.clone()], map_handle.clone()),
        "http.request_id" | "http.remote_addr" => (vec![http_handle.clone()], str_ty.clone()),
        "http.response_header_set" | "http.response_header_add" => (
            vec![http_handle.clone(), str_ty.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "http.response_header_clear" => (vec![http_handle.clone()], i32.clone()),
        "http.header_set" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "http.websocket_accept" => (vec![http_handle.clone()], websocket_handle.clone()),
        "http.websocket_read" => (vec![websocket_handle.clone(), i32.clone()], str_ty.clone()),
        "http.websocket_kind" | "http.websocket_error" => {
            (vec![websocket_handle.clone()], str_ty.clone())
        }
        "http.websocket_close_code" => (vec![websocket_handle.clone()], i32.clone()),
        "http.websocket_write_text"
        | "http.websocket_write_binary"
        | "http.websocket_ping"
        | "http.websocket_pong" => (vec![websocket_handle.clone(), str_ty.clone()], i32.clone()),
        "http.websocket_close" => (
            vec![websocket_handle.clone(), i32.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "http.request_stream" => (
            vec![str_ty.clone(), str_ty.clone(), str_ty.clone()],
            http_stream_handle.clone(),
        ),
        "http.stream_read" => (
            vec![http_stream_handle.clone(), i32.clone()],
            str_ty.clone(),
        ),
        "http.stream_read_line" => (vec![http_stream_handle.clone()], str_ty.clone()),
        "http.stream_eof" => (vec![http_stream_handle.clone()], i32.clone()),
        "http.stream_status" => (vec![http_stream_handle.clone()], i32.clone()),
        "http.stream_error" => (vec![http_stream_handle.clone()], str_ty.clone()),
        "http.stream_close" => (vec![http_stream_handle.clone()], i32.clone()),
        "http.write" | "http.write_json" => (
            vec![http_handle.clone(), i32.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "http.write_response" => (
            vec![
                http_handle.clone(),
                i32.clone(),
                str_ty.clone(),
                str_ty.clone(),
                i32.clone(),
            ],
            i32.clone(),
        ),
        "crypto.random_hex" | "crypto.random_base64" => (vec![i32.clone()], str_ty.clone()),
        "crypto.sha256"
        | "crypto.base64_encode"
        | "crypto.base64_decode"
        | "crypto.base64_url_encode"
        | "crypto.base64_url_decode" => (vec![str_ty.clone()], str_ty.clone()),
        "crypto.hmac_sha256" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "crypto.constant_time_eq" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "simd.__i32x4" => (
            vec![i32.clone(), i32.clone(), i32.clone(), i32.clone()],
            i32x4.clone(),
        ),
        "simd.__u32x4" => (
            vec![i32.clone(), i32.clone(), i32.clone(), i32.clone()],
            u32x4.clone(),
        ),
        "simd.__f32x4" => (
            vec![
                Type::Float { bits: 64 },
                Type::Float { bits: 64 },
                Type::Float { bits: 64 },
                Type::Float { bits: 64 },
            ],
            f32x4.clone(),
        ),
        "simd.__mask32x4" => (
            vec![i32.clone(), i32.clone(), i32.clone(), i32.clone()],
            mask32x4.clone(),
        ),
        "simd.__i32x4_splat" => (vec![i32.clone()], i32x4.clone()),
        "simd.__i32x4_load" => (
            vec![Type::Array {
                elem: Box::new(i32.clone()),
                len: 4,
            }],
            i32x4.clone(),
        ),
        "simd.__i32x4_load_aligned_ptr" | "simd.__i32x4_load_unaligned_ptr" => {
            (vec![ptr_u8.clone()], i32x4.clone())
        }
        "simd.__i32x4_store_aligned_ptr" | "simd.__i32x4_store_unaligned_ptr" => {
            (vec![ptr_u8.clone(), i32x4.clone()], Type::Void)
        }
        "simd.__u32x4_splat" => (vec![i32.clone()], u32x4.clone()),
        "simd.__u32x4_load" => (
            vec![Type::Array {
                elem: Box::new(u32_ty.clone()),
                len: 4,
            }],
            u32x4.clone(),
        ),
        "simd.__u32x4_load_aligned_ptr" | "simd.__u32x4_load_unaligned_ptr" => {
            (vec![ptr_u8.clone()], u32x4.clone())
        }
        "simd.__u32x4_store_aligned_ptr" | "simd.__u32x4_store_unaligned_ptr" => {
            (vec![ptr_u8.clone(), u32x4.clone()], Type::Void)
        }
        "simd.__f32x4_splat" => (vec![f32_ty.clone()], f32x4.clone()),
        "simd.__f32x4_load" => (
            vec![Type::Array {
                elem: Box::new(f32_ty.clone()),
                len: 4,
            }],
            f32x4.clone(),
        ),
        "simd.__f32x4_load_aligned_ptr" | "simd.__f32x4_load_unaligned_ptr" => {
            (vec![ptr_u8.clone()], f32x4.clone())
        }
        "simd.__f32x4_store_aligned_ptr" | "simd.__f32x4_store_unaligned_ptr" => {
            (vec![ptr_u8.clone(), f32x4.clone()], Type::Void)
        }
        "simd.__mask32x4_splat" => (vec![i32.clone()], mask32x4.clone()),
        "simd.__mask32x4_load" => (
            vec![Type::Array {
                elem: Box::new(bool_ty.clone()),
                len: 4,
            }],
            mask32x4.clone(),
        ),
        "simd.__mask32x4_load_aligned_ptr" | "simd.__mask32x4_load_unaligned_ptr" => {
            (vec![ptr_u8.clone()], mask32x4.clone())
        }
        "simd.__mask32x4_store_aligned_ptr" | "simd.__mask32x4_store_unaligned_ptr" => {
            (vec![ptr_u8.clone(), mask32x4.clone()], Type::Void)
        }
        "simd.__i32x4_add"
        | "simd.__i32x4_sub"
        | "simd.__i32x4_mul"
        | "simd.__i32x4_saturating_add"
        | "simd.__i32x4_saturating_sub"
        | "simd.__i32x4_and"
        | "simd.__i32x4_or"
        | "simd.__i32x4_xor" => (vec![i32x4.clone(), i32x4.clone()], i32x4.clone()),
        "simd.__i32x4_shl" | "simd.__i32x4_shr" => {
            (vec![i32x4.clone(), i32.clone()], i32x4.clone())
        }
        "simd.__i32x4_min" | "simd.__i32x4_max" => {
            (vec![i32x4.clone(), i32x4.clone()], i32x4.clone())
        }
        "simd.__u32x4_add"
        | "simd.__u32x4_sub"
        | "simd.__u32x4_mul"
        | "simd.__u32x4_saturating_add"
        | "simd.__u32x4_saturating_sub"
        | "simd.__u32x4_and"
        | "simd.__u32x4_or"
        | "simd.__u32x4_xor" => (vec![u32x4.clone(), u32x4.clone()], u32x4.clone()),
        "simd.__u32x4_shl" | "simd.__u32x4_shr" => {
            (vec![u32x4.clone(), i32.clone()], u32x4.clone())
        }
        "simd.__u32x4_min" | "simd.__u32x4_max" => {
            (vec![u32x4.clone(), u32x4.clone()], u32x4.clone())
        }
        "simd.__f32x4_add" | "simd.__f32x4_sub" | "simd.__f32x4_mul" => {
            (vec![f32x4.clone(), f32x4.clone()], f32x4.clone())
        }
        "simd.__f32x4_min" | "simd.__f32x4_max" => {
            (vec![f32x4.clone(), f32x4.clone()], f32x4.clone())
        }
        "simd.__mask32x4_and" | "simd.__mask32x4_or" | "simd.__mask32x4_xor" => {
            (vec![mask32x4.clone(), mask32x4.clone()], mask32x4.clone())
        }
        "simd.__i32x4_not" => (vec![i32x4.clone()], i32x4.clone()),
        "simd.__u32x4_not" => (vec![u32x4.clone()], u32x4.clone()),
        "simd.__mask32x4_not" => (vec![mask32x4.clone()], mask32x4.clone()),
        "simd.__i32x4_eq" | "simd.__i32x4_ne" | "simd.__i32x4_lt" | "simd.__i32x4_le"
        | "simd.__i32x4_gt" | "simd.__i32x4_ge" => {
            (vec![i32x4.clone(), i32x4.clone()], mask32x4.clone())
        }
        "simd.__u32x4_eq" | "simd.__u32x4_ne" | "simd.__u32x4_lt" | "simd.__u32x4_le"
        | "simd.__u32x4_gt" | "simd.__u32x4_ge" => {
            (vec![u32x4.clone(), u32x4.clone()], mask32x4.clone())
        }
        "simd.__f32x4_eq" | "simd.__f32x4_ne" | "simd.__f32x4_lt" | "simd.__f32x4_le"
        | "simd.__f32x4_gt" | "simd.__f32x4_ge" => {
            (vec![f32x4.clone(), f32x4.clone()], mask32x4.clone())
        }
        "simd.__i32x4_select" => (
            vec![mask32x4.clone(), i32x4.clone(), i32x4.clone()],
            i32x4.clone(),
        ),
        "simd.__u32x4_select" => (
            vec![mask32x4.clone(), u32x4.clone(), u32x4.clone()],
            u32x4.clone(),
        ),
        "simd.__f32x4_select" => (
            vec![mask32x4.clone(), f32x4.clone(), f32x4.clone()],
            f32x4.clone(),
        ),
        "simd.__i32x4_shuffle" => (
            vec![
                i32x4.clone(),
                i32x4.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
            ],
            i32x4.clone(),
        ),
        "simd.__u32x4_shuffle" => (
            vec![
                u32x4.clone(),
                u32x4.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
            ],
            u32x4.clone(),
        ),
        "simd.__f32x4_shuffle" => (
            vec![
                f32x4.clone(),
                f32x4.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
            ],
            f32x4.clone(),
        ),
        "simd.__mask32x4_shuffle" => (
            vec![
                mask32x4.clone(),
                mask32x4.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
                i32.clone(),
            ],
            mask32x4.clone(),
        ),
        "simd.__i32x4_as_u32x4" => (vec![i32x4.clone()], u32x4.clone()),
        "simd.__u32x4_as_i32x4" => (vec![u32x4.clone()], i32x4.clone()),
        "simd.__i32x4_bitcast_f32x4" => (vec![i32x4.clone()], f32x4.clone()),
        "simd.__u32x4_bitcast_f32x4" => (vec![u32x4.clone()], f32x4.clone()),
        "simd.__f32x4_bitcast_i32x4" => (vec![f32x4.clone()], i32x4.clone()),
        "simd.__f32x4_bitcast_u32x4" => (vec![f32x4.clone()], u32x4.clone()),
        "simd.__i32x4_reduce_add" => (vec![i32x4.clone()], i32.clone()),
        "simd.__i32x4_reduce_min" => (vec![i32x4.clone()], i32.clone()),
        "simd.__i32x4_reduce_max" => (vec![i32x4.clone()], i32.clone()),
        "simd.__u32x4_reduce_add" => (vec![u32x4.clone()], u32_ty.clone()),
        "simd.__u32x4_reduce_min" => (vec![u32x4.clone()], u32_ty.clone()),
        "simd.__u32x4_reduce_max" => (vec![u32x4.clone()], u32_ty.clone()),
        "simd.__f32x4_reduce_add" => (vec![f32x4.clone()], f32_ty.clone()),
        "simd.__f32x4_reduce_min" => (vec![f32x4.clone()], f32_ty.clone()),
        "simd.__f32x4_reduce_max" => (vec![f32x4.clone()], f32_ty.clone()),
        "simd.__mask32x4_any" | "simd.__mask32x4_all" | "simd.__mask32x4_none" => {
            (vec![mask32x4.clone()], bool_ty.clone())
        }
        "simd.__mask32x4_bitmask" => (vec![mask32x4.clone()], i32.clone()),
        "simd.__i32x4_lane0" | "simd.__i32x4_lane1" | "simd.__i32x4_lane2"
        | "simd.__i32x4_lane3" => (vec![i32x4.clone()], i32.clone()),
        "simd.__u32x4_lane0" | "simd.__u32x4_lane1" | "simd.__u32x4_lane2"
        | "simd.__u32x4_lane3" => (vec![u32x4.clone()], u32_ty.clone()),
        "simd.__f32x4_lane0" | "simd.__f32x4_lane1" | "simd.__f32x4_lane2"
        | "simd.__f32x4_lane3" => (vec![f32x4.clone()], f32_ty.clone()),
        "simd.__mask32x4_lane0"
        | "simd.__mask32x4_lane1"
        | "simd.__mask32x4_lane2"
        | "simd.__mask32x4_lane3" => (vec![mask32x4.clone()], bool_ty.clone()),
        "env.get" => (vec![str_ty.clone()], str_ty.clone()),
        "proc.argv_count" => (vec![], i32.clone()),
        "proc.argv_get" => (vec![i32.clone()], str_ty.clone()),
        "term.read_line" => (vec![], str_ty.clone()),
        "term.stdin_eof" => (vec![], i32.clone()),
        "term.write" | "term.write_err" => (vec![str_ty.clone()], i32.clone()),
        "term.stdin_is_tty" | "term.stdout_is_tty" => (vec![], i32.clone()),
        "str.concat" | "str.concat2" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "str.concat3" => (
            vec![str_ty.clone(), str_ty.clone(), str_ty.clone()],
            str_ty.clone(),
        ),
        "str.concat4" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "str.from_i32" => (vec![i32.clone()], str_ty.clone()),
        "str.from_bool" => (vec![Type::Bool], str_ty.clone()),
        "str.repeat" => (vec![str_ty.clone(), i32.clone()], str_ty.clone()),
        "str.contains" | "str.starts_with" | "str.ends_with" => {
            (vec![str_ty.clone(), str_ty.clone()], i32.clone())
        }
        "str.replace" => (
            vec![str_ty.clone(), str_ty.clone(), str_ty.clone()],
            str_ty.clone(),
        ),
        "str.trim" => (vec![str_ty.clone()], str_ty.clone()),
        "str.split" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "str.len" => (vec![str_ty.clone()], i32.clone()),
        "str.visible_len_ansi" => (vec![str_ty.clone()], i32.clone()),
        "str.slice" => (
            vec![str_ty.clone(), i32.clone(), i32.clone()],
            str_ty.clone(),
        ),
        "str.upper_ascii" | "str.lower_ascii" => (vec![str_ty.clone()], str_ty.clone()),
        "http.post_json" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "http.post_json_capture" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "http.post_json_stream" => (
            vec![str_ty.clone(), str_ty.clone()],
            http_stream_handle.clone(),
        ),
        "http.last_status" => (vec![], i32.clone()),
        "http.last_error" => (vec![], str_ty.clone()),
        "json.escape" => (vec![str_ty.clone()], str_ty.clone()),
        "json.str" => (vec![str_ty.clone()], str_ty.clone()),
        "json.raw" => (vec![str_ty.clone()], str_ty.clone()),
        "json.from_list" => (vec![list_handle.clone()], str_ty.clone()),
        "json.from_map" => (vec![map_handle.clone()], str_ty.clone()),
        "json.array" => (vec![list_handle.clone()], str_ty.clone()),
        "json.object" => (vec![map_handle.clone()], str_ty.clone()),
        "json.to_list" => (vec![json_handle.clone()], list_handle.clone()),
        "json.to_map" => (vec![json_handle.clone()], map_handle.clone()),
        "json.keys" => (vec![json_handle.clone()], list_handle.clone()),
        "json.parse" => (vec![str_ty.clone()], json_handle.clone()),
        "json.get" => (
            vec![json_handle.clone(), str_ty.clone()],
            json_handle.clone(),
        ),
        "json.get_str" => (vec![json_handle.clone(), str_ty.clone()], str_ty.clone()),
        "json.has" => (vec![json_handle.clone(), str_ty.clone()], i32.clone()),
        "json.path" => (
            vec![json_handle.clone(), str_ty.clone()],
            json_handle.clone(),
        ),
        "time.now" | "time.monotonic_ms" => (vec![], i32.clone()),
        "time.sleep_ms" => (vec![i32.clone()], i32.clone()),
        "time.interval" | "time.tick" => (vec![i32.clone()], i32.clone()),
        "time.elapsed_ms" | "time.deadline_after" => (vec![i32.clone()], i32.clone()),
        "fs.open" => (vec![str_ty.clone()], file_handle.clone()),
        "fs.close" | "fs.flush" | "fs.fsync" | "fs.lock" => {
            (vec![file_handle.clone()], i32.clone())
        }
        "fs.write" => (vec![file_handle.clone(), str_ty.clone()], i32.clone()),
        "fs.read" => (vec![file_handle.clone(), i32.clone()], str_ty.clone()),
        "fs.atomic_write" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "fs.read_file" => (vec![str_ty.clone()], str_ty.clone()),
        "fs.write_file" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "fs.mkdir" | "fs.exists" | "fs.is_file" | "fs.is_dir" | "fs.is_symlink"
        | "fs.remove_file" | "fs.remove" => (vec![str_ty.clone()], i32.clone()),
        "fs.stat_size" => (vec![str_ty.clone()], i32.clone()),
        "fs.stat_mtime" => (vec![str_ty.clone()], i32.clone()),
        "fs.listdir" => (vec![str_ty.clone()], list_handle.clone()),
        "fs.temp_file" => (vec![str_ty.clone()], str_ty.clone()),
        "fs.copy_file" | "fs.copy_tree" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "path.join" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "path.basename" | "path.dirname" | "path.stem" | "path.extension" | "path.normalize" => {
            (vec![str_ty.clone()], str_ty.clone())
        }
        "route.match" => (
            vec![http_handle.clone(), str_ty.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "route.write_404" | "route.write_405" => (vec![http_handle.clone()], i32.clone()),
        "log.info" | "log.warn" | "log.error" => {
            (vec![str_ty.clone(), str_ty.clone()], i32.clone())
        }
        "log.fields" => (vec![map_handle.clone()], str_ty.clone()),
        "log.set_json" | "log.set_enabled" => (vec![i32.clone()], i32.clone()),
        "log.set_level" | "log.set_sink" => (vec![str_ty.clone()], i32.clone()),
        "log.correlation_id" => (vec![map_handle.clone()], str_ty.clone()),
        "error.code" | "error.class" => (vec![], i32.clone()),
        "error.message" => (vec![], str_ty.clone()),
        "error.context" => (vec![str_ty.clone()], i32.clone()),
        "proc.run" => (vec![str_ty.clone()], i32.clone()),
        "proc.spawn" => (vec![str_ty.clone()], proc_handle.clone()),
        "proc.runl" | "proc.spawnl" => (
            vec![
                str_ty.clone(),
                proc_argv.clone(),
                proc_env.clone(),
                str_ty.clone(),
            ],
            proc_handle.clone(),
        ),
        "proc.argv_new" => (vec![], proc_argv.clone()),
        "proc.env_new" => (vec![], proc_env.clone()),
        "proc.argv_push" => (vec![proc_argv.clone(), str_ty.clone()], i32.clone()),
        "proc.env_set" => (
            vec![proc_env.clone(), str_ty.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "proc.spawn_cmd" | "proc.run_cmd" => (
            vec![
                str_ty.clone(),
                proc_argv.clone(),
                proc_env.clone(),
                str_ty.clone(),
            ],
            proc_handle.clone(),
        ),
        "proc.exec_timeout" => (vec![proc_handle.clone()], i32.clone()),
        "proc.close" => (vec![proc_handle.clone()], i32.clone()),
        "proc.wait" => (vec![proc_handle.clone(), i32.clone()], i32.clone()),
        "proc.poll" | "proc.event" => (vec![proc_handle.clone()], i32.clone()),
        "proc.read_stdout" | "proc.read_stderr" => {
            (vec![proc_handle.clone(), i32.clone()], str_ty.clone())
        }
        "proc.stdout" | "proc.stderr" => (vec![proc_handle.clone()], str_ty.clone()),
        "proc.exit_code" => (vec![proc_handle.clone()], i32.clone()),
        "proc.exit_class" => (vec![], i32.clone()),
        "ctx.deadline" => (vec![task_handle.clone()], i32.clone()),
        "ctx.cancel_if_timeout" => (vec![], i32.clone()),
        "channel.send" => (vec![channel_handle.clone(), str_ty.clone()], i32.clone()),
        "channel.recv" => (vec![channel_handle.clone()], str_ty.clone()),
        "list.new" => (vec![], list_handle.clone()),
        "map.new" => (vec![], map_handle.clone()),
        "list.push" => (vec![list_handle.clone(), str_ty.clone()], i32.clone()),
        "list.pop" => (vec![list_handle.clone()], str_ty.clone()),
        "list.len" => (vec![list_handle.clone()], i32.clone()),
        "list.get" => (vec![list_handle.clone(), i32.clone()], str_ty.clone()),
        "list.set" => (
            vec![list_handle.clone(), i32.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "list.clear" => (vec![list_handle.clone()], i32.clone()),
        "list.join" => (vec![list_handle.clone(), str_ty.clone()], str_ty.clone()),
        "map.set" => (
            vec![map_handle.clone(), str_ty.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "map.get" => (vec![map_handle.clone(), str_ty.clone()], str_ty.clone()),
        "map.has" => (vec![map_handle.clone(), str_ty.clone()], i32.clone()),
        "map.delete" => (vec![map_handle.clone(), str_ty.clone()], i32.clone()),
        "map.keys" => (vec![map_handle.clone()], list_handle.clone()),
        "map.len" => (vec![map_handle.clone()], i32.clone()),
        "storage.append" | "storage.atomic_append" => {
            (vec![str_ty.clone(), str_ty.clone()], i32.clone())
        }
        "storage.kv_open" => (vec![str_ty.clone()], kv_handle.clone()),
        "storage.kv_close" => (vec![kv_handle.clone()], i32.clone()),
        "storage.kv_get" => (vec![kv_handle.clone(), str_ty.clone()], str_ty.clone()),
        "storage.kv_put" => (
            vec![kv_handle.clone(), str_ty.clone(), str_ty.clone()],
            i32.clone(),
        ),
        _ => return None,
    })
}

fn runtime_default_value(ty: &Type) -> Option<Value> {
    fn is_runtime_handle(name: &str) -> bool {
        runtime_handle_contract(name).is_some()
    }
    match ty {
        Type::Bool => Some(Value::Bool(false)),
        Type::ISize | Type::USize | Type::Int { .. } => Some(Value::I32(0)),
        Type::BigInt | Type::BigUint | Type::Decimal128 => Some(Value::I32(0)),
        Type::Float { .. } => Some(Value::F64(0.0)),
        Type::Char => Some(Value::Char('\0')),
        Type::Str => Some(Value::Str(String::new())),
        Type::Bytes => Some(Value::List(Vec::new())),
        Type::Uuid => Some(Value::Str(String::new())),
        Type::Map { .. } => Some(Value::I32(0)),
        Type::Set(_) | Type::Deque(_) | Type::Ring(_) => Some(Value::I32(0)),
        Type::Path | Type::PathBuf | Type::Url | Type::SocketAddr => {
            Some(Value::Str(String::new()))
        }
        Type::Duration | Type::Instant | Type::Decimal | Type::DateTimeTz | Type::ExitStatus => {
            Some(Value::I32(0))
        }
        Type::Tuple(items) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                values.push(runtime_default_value(item)?);
            }
            Some(Value::Tuple(values))
        }
        Type::Named { name, .. } if is_runtime_handle(name) => Some(Value::I32(0)),
        Type::Future(inner) => runtime_default_value(inner),
        Type::DynTrait(_) => Some(Value::I32(0)),
        Type::Void => Some(Value::I32(0)),
        _ => None,
    }
}

fn check_pattern_compatibility(
    pattern: &ast::Pattern,
    scrutinee_ty: Option<&Type>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    errors: &mut usize,
    type_error_details: &mut Vec<String>,
) {
    match (pattern, scrutinee_ty) {
        (ast::Pattern::Int(_), Some(ty)) if is_integer_type(ty) => {}
        (ast::Pattern::Bool(_), Some(Type::Bool)) => {}
        (ast::Pattern::Wildcard, _) | (ast::Pattern::Ident(_), _) => {}
        (ast::Pattern::Tuple(items), Some(Type::Tuple(scrutinee_items))) => {
            if items.len() != scrutinee_items.len() {
                record_type_error(
                    errors,
                    type_error_details,
                    format!(
                        "tuple pattern arity mismatch: expected {}, got {}",
                        scrutinee_items.len(),
                        items.len()
                    ),
                );
                return;
            }
            for (pattern_item, ty_item) in items.iter().zip(scrutinee_items.iter()) {
                check_pattern_compatibility(
                    pattern_item,
                    Some(ty_item),
                    struct_defs,
                    enum_defs,
                    errors,
                    type_error_details,
                );
            }
        }
        (
            ast::Pattern::Struct { name, fields },
            Some(Type::Named {
                name: scrutinee_name,
                ..
            }),
        ) => {
            if scrutinee_name != name {
                record_type_error(
                    errors,
                    type_error_details,
                    format!(
                        "pattern `{name} {{ ... }}` does not match scrutinee type `{scrutinee_name}`"
                    ),
                );
                return;
            }
            let Some(struct_def) = struct_defs.get(name) else {
                record_type_error(
                    errors,
                    type_error_details,
                    format!("match pattern references unknown struct `{name}`"),
                );
                return;
            };
            for (field, _) in fields {
                if !struct_def
                    .fields
                    .iter()
                    .any(|candidate| candidate.name == *field)
                {
                    record_type_error(
                        errors,
                        type_error_details,
                        format!("struct `{name}` has no field `{field}`"),
                    );
                }
            }
        }
        (
            ast::Pattern::Variant {
                enum_name,
                variant,
                bindings,
                named_bindings,
            },
            Some(Type::Named { name, .. }),
        ) => {
            if name != enum_name {
                record_type_error(
                    errors,
                    type_error_details,
                    format!(
                        "pattern `{enum_name}::{variant}` does not match scrutinee enum `{name}`"
                    ),
                );
                return;
            }
            let Some(enum_def) = enum_defs.get(enum_name) else {
                record_type_error(
                    errors,
                    type_error_details,
                    format!("match pattern references unknown enum `{enum_name}`"),
                );
                return;
            };
            let Some(found_variant) = enum_def
                .variants
                .iter()
                .find(|candidate| candidate.name == *variant)
            else {
                record_type_error(
                    errors,
                    type_error_details,
                    format!("enum `{enum_name}` has no variant `{variant}`"),
                );
                return;
            };
            if found_variant.named_payload.is_empty() {
                if found_variant.payload.len() != bindings.len() || !named_bindings.is_empty() {
                    record_type_error(
                        errors,
                        type_error_details,
                        format!(
                            "pattern `{enum_name}::{variant}` binding arity mismatch: expected {} positional binding(s), got {}",
                            found_variant.payload.len(),
                            bindings.len()
                        ),
                    );
                }
            } else if !bindings.is_empty()
                || found_variant.named_payload.len() != named_bindings.len()
            {
                record_type_error(
                    errors,
                    type_error_details,
                    format!(
                        "pattern `{enum_name}::{variant}` named binding arity mismatch: expected {}, got {}",
                        found_variant.named_payload.len(),
                        named_bindings.len()
                    ),
                );
            }
        }
        (
            ast::Pattern::Variant {
                enum_name, variant, ..
            },
            Some(actual),
        ) => record_type_error(
            errors,
            type_error_details,
            format!("pattern `{enum_name}::{variant}` expects enum scrutinee, got `{actual}`"),
        ),
        (
            ast::Pattern::Variant {
                enum_name, variant, ..
            },
            None,
        ) => record_type_error(
            errors,
            type_error_details,
            format!(
                "pattern `{enum_name}::{variant}` could not be validated because scrutinee type is unknown"
            ),
        ),
        (ast::Pattern::Struct { name, .. }, Some(actual)) => record_type_error(
            errors,
            type_error_details,
            format!("pattern `{name} {{ ... }}` expects struct scrutinee, got `{actual}`"),
        ),
        (ast::Pattern::Struct { name, .. }, None) => record_type_error(
            errors,
            type_error_details,
            format!(
                "pattern `{name} {{ ... }}` could not be validated because scrutinee type is unknown"
            ),
        ),
        (ast::Pattern::Tuple(_), Some(actual)) => record_type_error(
            errors,
            type_error_details,
            format!("tuple pattern expects tuple scrutinee, got `{actual}`"),
        ),
        (ast::Pattern::Tuple(_), None) => record_type_error(
            errors,
            type_error_details,
            "tuple pattern could not be validated because scrutinee type is unknown".to_string(),
        ),
        (ast::Pattern::Or(patterns), ty) => {
            for pattern in patterns {
                check_pattern_compatibility(
                    pattern,
                    ty,
                    struct_defs,
                    enum_defs,
                    errors,
                    type_error_details,
                );
            }
        }
        (ast::Pattern::Int(_), Some(actual)) => record_type_error(
            errors,
            type_error_details,
            format!("match pattern expects integer scrutinee, got `{actual}`"),
        ),
        (ast::Pattern::Bool(_), Some(actual)) => record_type_error(
            errors,
            type_error_details,
            format!("match pattern expects bool scrutinee, got `{actual}`"),
        ),
        (ast::Pattern::Int(_) | ast::Pattern::Bool(_), None) => record_type_error(
            errors,
            type_error_details,
            "match pattern could not be validated because scrutinee type is unknown".to_string(),
        ),
    }
}

fn bind_pattern_types(
    pattern: &ast::Pattern,
    scrutinee_ty: &Type,
    mutable: bool,
    scopes: &mut SymbolScopes,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    errors: &mut usize,
    type_error_details: &mut Vec<String>,
) {
    match pattern {
        ast::Pattern::Ident(name) => {
            scopes.insert(name.clone(), scrutinee_ty.clone(), mutable);
        }
        ast::Pattern::Tuple(items) => {
            let Type::Tuple(scrutinee_items) = scrutinee_ty else {
                return;
            };
            if items.len() != scrutinee_items.len() {
                record_type_error(
                    errors,
                    type_error_details,
                    format!(
                        "tuple pattern arity mismatch: expected {}, got {}",
                        scrutinee_items.len(),
                        items.len()
                    ),
                );
                return;
            }
            for (pattern_item, ty_item) in items.iter().zip(scrutinee_items.iter()) {
                bind_pattern_types(
                    pattern_item,
                    ty_item,
                    mutable,
                    scopes,
                    struct_defs,
                    enum_defs,
                    errors,
                    type_error_details,
                );
            }
        }
        ast::Pattern::Struct { name, fields } => {
            let Type::Named {
                name: scrutinee,
                args: scrutinee_args,
            } = scrutinee_ty
            else {
                return;
            };
            if name != scrutinee {
                return;
            }
            let Some(struct_def) = struct_defs.get(name) else {
                return;
            };
            let generic_bindings = struct_def
                .generics
                .iter()
                .zip(scrutinee_args.iter())
                .map(|(param, arg)| (param.name.clone(), arg.clone()))
                .collect::<BTreeMap<_, _>>();
            for (field_name, binding_name) in fields {
                let Some(field) = struct_def
                    .fields
                    .iter()
                    .find(|candidate| candidate.name == *field_name)
                else {
                    record_type_error(
                        errors,
                        type_error_details,
                        format!("struct `{name}` has no field `{field_name}`"),
                    );
                    continue;
                };
                if binding_name != "_" {
                    scopes.insert(
                        binding_name.clone(),
                        substitute_typevars(&field.ty, &generic_bindings),
                        mutable,
                    );
                }
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } => {
            let Type::Named {
                name,
                args: scrutinee_args,
            } = scrutinee_ty
            else {
                return;
            };
            if name != enum_name {
                return;
            }
            let Some(enum_def) = enum_defs.get(enum_name) else {
                return;
            };
            let generic_bindings = enum_def
                .generics
                .iter()
                .zip(scrutinee_args.iter())
                .map(|(param, arg)| (param.name.clone(), arg.clone()))
                .collect::<BTreeMap<_, _>>();
            let Some(found_variant) = enum_def
                .variants
                .iter()
                .find(|candidate| candidate.name == *variant)
            else {
                return;
            };
            if found_variant.named_payload.is_empty() {
                if found_variant.payload.len() != bindings.len() || !named_bindings.is_empty() {
                    record_type_error(
                        errors,
                        type_error_details,
                        format!(
                            "pattern `{enum_name}::{variant}` binding arity mismatch: expected {} positional binding(s), got {}",
                            found_variant.payload.len(),
                            bindings.len()
                        ),
                    );
                    return;
                }
                for (name, ty) in bindings.iter().zip(found_variant.payload.iter()) {
                    scopes.insert(
                        name.clone(),
                        substitute_typevars(ty, &generic_bindings),
                        mutable,
                    );
                }
            } else {
                if !bindings.is_empty() || found_variant.named_payload.len() != named_bindings.len()
                {
                    record_type_error(
                        errors,
                        type_error_details,
                        format!(
                            "pattern `{enum_name}::{variant}` named binding arity mismatch: expected {}, got {}",
                            found_variant.named_payload.len(),
                            named_bindings.len()
                        ),
                    );
                    return;
                }
                for (field_name, binding_name) in named_bindings {
                    let Some(field) = found_variant
                        .named_payload
                        .iter()
                        .find(|candidate| candidate.name == *field_name)
                    else {
                        record_type_error(
                            errors,
                            type_error_details,
                            format!(
                                "enum struct-variant `{enum_name}::{variant}` has no field `{field_name}`"
                            ),
                        );
                        continue;
                    };
                    if binding_name != "_" {
                        scopes.insert(
                            binding_name.clone(),
                            substitute_typevars(&field.ty, &generic_bindings),
                            mutable,
                        );
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            let mut canonical: Option<BTreeMap<String, Type>> = None;
            for candidate in patterns {
                let binding_map =
                    pattern_binding_type_map(candidate, scrutinee_ty, struct_defs, enum_defs);
                if let Some(expected) = &canonical {
                    if expected != &binding_map {
                        record_type_error(
                            errors,
                            type_error_details,
                            "or-pattern alternatives must bind identical names and types"
                                .to_string(),
                        );
                        return;
                    }
                } else {
                    canonical = Some(binding_map);
                }
            }
            if let Some(bindings) = canonical {
                for (name, ty) in bindings {
                    scopes.insert(name, ty, mutable);
                }
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => {}
    }
}

fn pattern_binding_type_map(
    pattern: &ast::Pattern,
    scrutinee_ty: &Type,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> BTreeMap<String, Type> {
    match pattern {
        ast::Pattern::Ident(name) => {
            let mut map = BTreeMap::new();
            map.insert(name.clone(), scrutinee_ty.clone());
            map
        }
        ast::Pattern::Tuple(items) => {
            let Type::Tuple(scrutinee_items) = scrutinee_ty else {
                return BTreeMap::new();
            };
            if items.len() != scrutinee_items.len() {
                return BTreeMap::new();
            }
            let mut map = BTreeMap::new();
            for (pattern_item, ty_item) in items.iter().zip(scrutinee_items.iter()) {
                map.extend(pattern_binding_type_map(
                    pattern_item,
                    ty_item,
                    struct_defs,
                    enum_defs,
                ));
            }
            map
        }
        ast::Pattern::Struct { name, fields } => {
            let Type::Named {
                name: scrutinee, ..
            } = scrutinee_ty
            else {
                return BTreeMap::new();
            };
            if name != scrutinee {
                return BTreeMap::new();
            }
            let Some(struct_def) = struct_defs.get(name) else {
                return BTreeMap::new();
            };
            let Type::Named {
                args: scrutinee_args,
                ..
            } = scrutinee_ty
            else {
                return BTreeMap::new();
            };
            let generic_bindings = struct_def
                .generics
                .iter()
                .zip(scrutinee_args.iter())
                .map(|(param, arg)| (param.name.clone(), arg.clone()))
                .collect::<BTreeMap<_, _>>();
            let mut map = BTreeMap::new();
            for (field_name, binding_name) in fields {
                if binding_name == "_" {
                    continue;
                }
                if let Some(field) = struct_def.fields.iter().find(|f| f.name == *field_name) {
                    map.insert(
                        binding_name.clone(),
                        substitute_typevars(&field.ty, &generic_bindings),
                    );
                }
            }
            map
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } => {
            let Type::Named {
                name: scrutinee,
                args: scrutinee_args,
            } = scrutinee_ty
            else {
                return BTreeMap::new();
            };
            if scrutinee != enum_name {
                return BTreeMap::new();
            }
            let Some(enum_def) = enum_defs.get(enum_name) else {
                return BTreeMap::new();
            };
            let generic_bindings = enum_def
                .generics
                .iter()
                .zip(scrutinee_args.iter())
                .map(|(param, arg)| (param.name.clone(), arg.clone()))
                .collect::<BTreeMap<_, _>>();
            let Some(found_variant) = enum_def
                .variants
                .iter()
                .find(|candidate| candidate.name == *variant)
            else {
                return BTreeMap::new();
            };
            let mut map = BTreeMap::new();
            if found_variant.named_payload.is_empty() {
                if found_variant.payload.len() != bindings.len() || !named_bindings.is_empty() {
                    return BTreeMap::new();
                }
                for (name, ty) in bindings.iter().zip(found_variant.payload.iter()) {
                    map.insert(name.clone(), substitute_typevars(ty, &generic_bindings));
                }
            } else {
                if !bindings.is_empty() || found_variant.named_payload.len() != named_bindings.len()
                {
                    return BTreeMap::new();
                }
                for (field_name, binding_name) in named_bindings {
                    if binding_name == "_" {
                        continue;
                    }
                    let Some(field) = found_variant
                        .named_payload
                        .iter()
                        .find(|candidate| candidate.name == *field_name)
                    else {
                        continue;
                    };
                    map.insert(
                        binding_name.clone(),
                        substitute_typevars(&field.ty, &generic_bindings),
                    );
                }
            }
            map
        }
        ast::Pattern::Or(patterns) => {
            if let Some(first) = patterns.first() {
                pattern_binding_type_map(first, scrutinee_ty, struct_defs, enum_defs)
            } else {
                BTreeMap::new()
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => BTreeMap::new(),
    }
}

fn type_compatible(expected: &Type, actual: &Type) -> bool {
    match (expected, actual) {
        (Type::Never, _) | (_, Type::Never) => true,
        (Type::TypeVar(_), _) | (_, Type::TypeVar(_)) => true,
        (
            Type::Function {
                params: lhs_params,
                ret: lhs_ret,
            },
            Type::Function {
                params: rhs_params,
                ret: rhs_ret,
            },
        ) => {
            lhs_params.len() == rhs_params.len()
                && lhs_params
                    .iter()
                    .zip(rhs_params.iter())
                    .all(|(lhs, rhs)| type_compatible(lhs, rhs))
                && type_compatible(lhs_ret, rhs_ret)
        }
        _ => expected == actual,
    }
}

fn coercible_integer_literal_value(expr: &Expr) -> Option<i128> {
    match expr {
        Expr::Int(v) => Some(*v as i128),
        Expr::Group(inner) | Expr::Discard(inner) => coercible_integer_literal_value(inner),
        Expr::Unary { op, expr } => {
            let value = coercible_integer_literal_value(expr)?;
            match op {
                ast::UnaryOp::Plus => Some(value),
                ast::UnaryOp::Neg => Some(-value),
                _ => None,
            }
        }
        _ => None,
    }
}

fn coercible_float_literal_value(expr: &Expr) -> Option<f64> {
    match expr {
        Expr::Float { value, .. } => Some(*value),
        Expr::Group(inner) | Expr::Discard(inner) => coercible_float_literal_value(inner),
        Expr::Unary { op, expr } => {
            let value = coercible_float_literal_value(expr)?;
            match op {
                ast::UnaryOp::Plus => Some(value),
                ast::UnaryOp::Neg => Some(-value),
                _ => None,
            }
        }
        _ => None,
    }
}

fn expr_type_compatible(expected: &Type, actual: &Type, expr: &Expr) -> bool {
    if type_compatible(expected, actual) {
        return true;
    }
    if let (Type::Slice(expected_inner), Type::Array { elem, .. }) = (expected, actual) {
        if type_compatible(expected_inner, elem) {
            return true;
        }
    }
    if let (Type::Ptr { to, .. }, Type::Array { elem, .. }) = (expected, actual) {
        if expr_supports_implicit_borrow(expr) && type_compatible(to, elem) {
            return true;
        }
    }
    if let Type::Ref { to, .. } = expected {
        if expr_supports_implicit_borrow(expr) && type_compatible(to, actual) {
            return true;
        }
    }
    if let (
        Type::Float {
            bits: expected_bits,
        },
        Type::Float { bits: actual_bits },
    ) = (expected, actual)
    {
        if expected_bits == actual_bits {
            return true;
        }
        let Some(value) = coercible_float_literal_value(expr) else {
            return false;
        };
        return match expected_bits {
            32 => value.is_finite() && (value as f32).is_finite(),
            64 => true,
            _ => false,
        };
    }
    if is_integer_type(expected) && is_integer_type(actual) {
        match (expected, actual) {
            (
                Type::Int {
                    bits: expected_bits,
                    ..
                },
                Type::Int {
                    bits: actual_bits, ..
                },
            ) if expected_bits == actual_bits => return true,
            (Type::USize, Type::ISize) | (Type::ISize, Type::USize) => return true,
            _ => {}
        }
    }
    if !is_integer_type(expected) || !is_integer_type(actual) {
        return false;
    }
    let Some(value) = coercible_integer_literal_value(expr) else {
        return false;
    };
    match expected {
        Type::USize => value >= 0,
        Type::ISize => true,
        Type::Int { signed, bits } => {
            if *signed {
                let width = (*bits).clamp(1, 127) as u32;
                let min = -(1i128 << (width - 1));
                let max = (1i128 << (width - 1)) - 1;
                value >= min && value <= max
            } else if value < 0 {
                false
            } else {
                let width = (*bits).clamp(1, 127) as u32;
                value <= ((1i128 << width) - 1)
            }
        }
        _ => false,
    }
}

fn expr_supports_implicit_borrow(expr: &Expr) -> bool {
    match expr {
        Expr::Ident(_) => true,
        Expr::Group(inner)
        | Expr::Discard(inner)
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Index { base: inner, .. } => expr_supports_implicit_borrow(inner),
        _ => false,
    }
}

fn is_integer_type(ty: &Type) -> bool {
    matches!(ty, Type::ISize | Type::USize | Type::Int { .. })
}

fn is_float_type(ty: &Type) -> bool {
    matches!(ty, Type::Float { .. })
}

fn is_bool_or_integer(ty: Option<&Type>) -> bool {
    matches!(ty, Some(Type::Bool | Type::Never)) || ty.is_some_and(is_integer_type)
}
