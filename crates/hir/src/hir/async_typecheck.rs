use crate::*;

pub(crate) fn validate_async_semantics(
    functions: &[TypedFunction],
    fn_async: &HashMap<String, bool>,
    errors: &mut usize,
    type_error_details: &mut Vec<String>,
) {
    for function in functions {
        struct AsyncVisitor<'a> {
            function_name: &'a str,
            function_is_async: bool,
            fn_async: &'a HashMap<String, bool>,
            errors: &'a mut usize,
            type_error_details: &'a mut Vec<String>,
        }
        impl AstVisitor for AsyncVisitor<'_> {
            fn visit_expr(&mut self, expr: &Expr) {
                if let Expr::Await(inner) = expr {
                    if !self.function_is_async {
                        record_type_error(
                            self.errors,
                            self.type_error_details,
                            format!(
                                "function `{}` uses `await` but is not declared async",
                                self.function_name
                            ),
                        );
                    }
                    match inner.as_ref() {
                        Expr::Call { callee, .. } => {
                            let (base_callee, _) = split_generic_callee(callee);
                            if self
                                .fn_async
                                .get(base_callee)
                                .is_some_and(|is_async| !*is_async)
                            {
                                record_type_error(
                                    self.errors,
                                    self.type_error_details,
                                    format!(
                                        "function `{}` awaits non-async call `{}`",
                                        self.function_name, base_callee
                                    ),
                                );
                            }
                        }
                        _ => {
                            record_type_error(
                                self.errors,
                                self.type_error_details,
                                format!(
                                    "function `{}` can only await call expressions",
                                    self.function_name
                                ),
                            );
                        }
                    }
                }
                ast::walk_expr(self, expr);
            }
        }

        let mut visitor = AsyncVisitor {
            function_name: &function.name,
            function_is_async: function.is_async,
            fn_async,
            errors,
            type_error_details,
        };
        for stmt in &function.body {
            visitor.visit_stmt(stmt);
        }
    }
}

pub(crate) struct TypeCheckEnv<'a> {
    pub(crate) current_namespace: &'a str,
    pub(crate) fn_sigs: &'a HashMap<String, (Vec<Type>, Type)>,
    pub(crate) fn_async: &'a HashMap<String, bool>,
    pub(crate) fn_generics: &'a HashMap<String, Vec<ast::GenericParam>>,
    pub(crate) fn_param_names: &'a HashMap<String, Vec<String>>,
    pub(crate) fn_is_extern_unsafe_c: &'a BTreeSet<String>,
    pub(crate) struct_defs: &'a HashMap<String, ast::Struct>,
    pub(crate) enum_defs: &'a HashMap<String, ast::Enum>,
    pub(crate) trait_impls: &'a HashMap<String, Vec<Type>>,
    pub(crate) global_types: &'a HashMap<String, Type>,
    pub(crate) global_mutability: &'a HashMap<String, bool>,
}

pub(crate) struct TypeCheckState<'a> {
    pub(crate) errors: &'a mut usize,
    pub(crate) type_error_details: &'a mut Vec<String>,
    pub(crate) generic_specializations: &'a mut BTreeSet<String>,
    pub(crate) trait_violations: &'a mut Vec<String>,
}

pub(crate) fn type_check_stmt(
    stmt: &Stmt,
    scopes: &mut SymbolScopes,
    local_types: &mut BTreeMap<String, Type>,
    env: &TypeCheckEnv<'_>,
    loop_depth: usize,
    expected_return: &Type,
    state: &mut TypeCheckState<'_>,
) {
    let enum_defs = env.enum_defs;
    let struct_defs = env.struct_defs;
    match stmt {
        Stmt::Let {
            name,
            mutable,
            ty,
            value,
        } => {
            let inferred = infer_expr_type(value, scopes, env, state);
            let final_ty = match (ty, inferred) {
                (Some(explicit), Some(actual)) => {
                    if !expr_type_compatible(explicit, &actual, value) {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "let binding `{}` type mismatch: expected `{}`, got `{}`",
                                name, explicit, actual
                            ),
                        );
                    }
                    explicit.clone()
                }
                (Some(explicit), None) => explicit.clone(),
                (None, Some(actual)) => actual,
                (None, None) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "cannot infer type for let binding `{}`; add an explicit type annotation",
                            name
                        ),
                    );
                    Type::Void
                }
            };
            scopes.insert(name.clone(), final_ty, *mutable);
            local_types.insert(name.clone(), scopes.get(name).unwrap_or(Type::Void));
        }
        Stmt::LetPattern {
            pattern,
            mutable,
            ty,
            value,
        } => {
            let inferred = infer_expr_type(value, scopes, env, state);
            let final_ty = match (ty, inferred.clone()) {
                (Some(explicit), Some(actual)) => {
                    if !expr_type_compatible(explicit, &actual, value) {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "let pattern type mismatch: expected `{}`, got `{}`",
                                explicit, actual
                            ),
                        );
                    }
                    explicit.clone()
                }
                (Some(explicit), None) => explicit.clone(),
                (None, Some(actual)) => actual,
                (None, None) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        "cannot infer type for let pattern; add an explicit type annotation"
                            .to_string(),
                    );
                    Type::Void
                }
            };
            check_pattern_compatibility(
                pattern,
                Some(&final_ty),
                struct_defs,
                enum_defs,
                state.errors,
                state.type_error_details,
            );
            bind_pattern_types(
                pattern,
                &final_ty,
                *mutable,
                scopes,
                struct_defs,
                enum_defs,
                state.errors,
                state.type_error_details,
            );
            for (name, bound_ty) in
                pattern_binding_type_map(pattern, &final_ty, struct_defs, enum_defs)
            {
                local_types.insert(name, bound_ty);
            }
        }
        Stmt::Assign { target, value } => {
            let target_mutable = scopes.is_mutable(target)
                || env.global_mutability.get(target).copied().unwrap_or(false);
            if !target_mutable {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("assignment to immutable binding `{target}`; declare with `let mut`"),
                );
            }
            let target_ty = scopes
                .get(target)
                .or_else(|| env.global_types.get(target).cloned());
            let value_ty = infer_expr_type(value, scopes, env, state);
            if let (Some(target_ty), Some(value_ty)) = (target_ty, value_ty) {
                if !type_compatible(&target_ty, &value_ty) {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "assignment type mismatch for `{}`: expected `{}`, got `{}`",
                            target, target_ty, value_ty
                        ),
                    );
                }
            }
        }
        Stmt::CompoundAssign { target, value, .. } => {
            let target_mutable = scopes.is_mutable(target)
                || env.global_mutability.get(target).copied().unwrap_or(false);
            if !target_mutable {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!(
                        "compound assignment to immutable binding `{target}`; declare with `let mut`"
                    ),
                );
            }
            let target_ty = scopes
                .get(target)
                .or_else(|| env.global_types.get(target).cloned());
            let value_ty = infer_expr_type(value, scopes, env, state);
            if let (Some(target_ty), Some(value_ty)) = (target_ty, value_ty) {
                if !type_compatible(&target_ty, &value_ty) {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "compound assignment type mismatch for `{}`: expected `{}`, got `{}`",
                            target, target_ty, value_ty
                        ),
                    );
                }
            }
        }
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            let cond_ty = infer_expr_type(condition, scopes, env, state);
            if !is_bool_or_integer(cond_ty.as_ref()) {
                let found = cond_ty
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string());
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("if-condition must be bool/integer-compatible, got `{found}`"),
                );
            }
            scopes.push();
            for stmt in then_body {
                type_check_stmt(
                    stmt,
                    scopes,
                    local_types,
                    env,
                    loop_depth,
                    expected_return,
                    state,
                );
            }
            scopes.pop();
            scopes.push();
            for stmt in else_body {
                type_check_stmt(
                    stmt,
                    scopes,
                    local_types,
                    env,
                    loop_depth,
                    expected_return,
                    state,
                );
            }
            scopes.pop();
        }
        Stmt::While { condition, body } => {
            let cond_ty = infer_expr_type(condition, scopes, env, state);
            if !is_bool_or_integer(cond_ty.as_ref()) {
                let found = cond_ty
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string());
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("while-condition must be bool/integer-compatible, got `{found}`"),
                );
            }
            scopes.push();
            for stmt in body {
                type_check_stmt(
                    stmt,
                    scopes,
                    local_types,
                    env,
                    loop_depth + 1,
                    expected_return,
                    state,
                );
            }
            scopes.pop();
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            scopes.push();
            if let Some(init) = init {
                type_check_stmt(
                    init,
                    scopes,
                    local_types,
                    env,
                    loop_depth + 1,
                    expected_return,
                    state,
                );
            }
            if let Some(condition) = condition {
                let cond_ty = infer_expr_type(condition, scopes, env, state);
                if !is_bool_or_integer(cond_ty.as_ref()) {
                    let found = cond_ty
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "unknown".to_string());
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!("for-condition must be bool/integer-compatible, got `{found}`"),
                    );
                }
            }
            for stmt in body {
                type_check_stmt(
                    stmt,
                    scopes,
                    local_types,
                    env,
                    loop_depth + 1,
                    expected_return,
                    state,
                );
            }
            if let Some(step) = step {
                type_check_stmt(
                    step,
                    scopes,
                    local_types,
                    env,
                    loop_depth + 1,
                    expected_return,
                    state,
                );
            }
            scopes.pop();
        }
        Stmt::ForIn {
            binding,
            iterable,
            body,
        } => {
            let iterable_ty = infer_expr_type(iterable, scopes, env, state);
            let binding_ty = match iterable_ty {
                Some(Type::Named { name, args }) if name == "Range" && args.len() == 1 => {
                    args[0].clone()
                }
                Some(other) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "for-in iterable must be a range expression, got `{}`",
                            other
                        ),
                    );
                    Type::Int {
                        signed: true,
                        bits: 32,
                    }
                }
                None => Type::Int {
                    signed: true,
                    bits: 32,
                },
            };
            scopes.push();
            scopes.insert(binding.clone(), binding_ty, false);
            local_types.insert(binding.clone(), scopes.get(binding).unwrap_or(Type::Void));
            for stmt in body {
                type_check_stmt(
                    stmt,
                    scopes,
                    local_types,
                    env,
                    loop_depth + 1,
                    expected_return,
                    state,
                );
            }
            scopes.pop();
        }
        Stmt::Loop { body } => {
            scopes.push();
            for stmt in body {
                type_check_stmt(
                    stmt,
                    scopes,
                    local_types,
                    env,
                    loop_depth + 1,
                    expected_return,
                    state,
                );
            }
            scopes.pop();
        }
        Stmt::Break(value) => {
            if loop_depth == 0 {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    "`break` is only valid inside loop bodies".to_string(),
                );
            }
            if let Some(value) = value {
                let _ = infer_expr_type(value, scopes, env, state);
            }
        }
        Stmt::Continue => {
            if loop_depth == 0 {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    "`continue` is only valid inside loop bodies".to_string(),
                );
            }
        }
        Stmt::Return(Some(expr)) => {
            if let Some(actual) = infer_expr_type(expr, scopes, env, state) {
                if !expr_type_compatible(expected_return, &actual, expr) {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "return type mismatch: expected `{}`, got `{}`",
                            expected_return, actual
                        ),
                    );
                }
            }
        }
        Stmt::Return(None) => {
            if !matches!(expected_return, Type::Void) {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!(
                        "return type mismatch: expected `{}`, got `void`",
                        expected_return
                    ),
                );
            }
        }
        Stmt::Match { scrutinee, arms } => {
            let scrutinee_ty = infer_expr_type(scrutinee, scopes, env, state);
            check_match_exhaustiveness(
                scrutinee_ty.as_ref(),
                arms,
                enum_defs,
                state.errors,
                state.type_error_details,
            );
            for arm in arms {
                scopes.push();
                check_pattern_compatibility(
                    &arm.pattern,
                    scrutinee_ty.as_ref(),
                    struct_defs,
                    enum_defs,
                    state.errors,
                    state.type_error_details,
                );
                if let Some(scrutinee_ty) = scrutinee_ty.as_ref() {
                    bind_pattern_types(
                        &arm.pattern,
                        scrutinee_ty,
                        false,
                        scopes,
                        struct_defs,
                        enum_defs,
                        state.errors,
                        state.type_error_details,
                    );
                }
                if let Some(guard) = &arm.guard {
                    let guard_ty = infer_expr_type(guard, scopes, env, state);
                    if !is_bool_or_integer(guard_ty.as_ref()) {
                        let found = guard_ty
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".to_string());
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!("match guard must be bool/integer-compatible, got `{found}`"),
                        );
                    }
                }
                let value_ty = infer_expr_type(&arm.value, scopes, env, state);
                if arm.returns {
                    if let Some(actual) = value_ty.as_ref() {
                        if !type_compatible(expected_return, actual) {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "return type mismatch: expected `{}`, got `{}`",
                                    expected_return, actual
                                ),
                            );
                        }
                    }
                }
                let _ = value_ty;
                scopes.pop();
            }
        }
        Stmt::Expr(Expr::Call { callee, args }) if callee == "__index_assign" => {
            if args.len() != 3 {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    "indexed assignment expects exactly 3 arguments".to_string(),
                );
                return;
            }
            let mut base_ty = infer_expr_type(&args[0], scopes, env, state);
            if !base_ty.as_ref().is_some_and(supports_index_base_type) {
                if let Some(root_name) = expr_root_binding_name(&args[0]) {
                    if let Some(found) = scopes.get(root_name) {
                        base_ty = Some(found.clone());
                    } else if let Some(found) = env.global_types.get(root_name) {
                        base_ty = Some(found.clone());
                    }
                }
            }
            let index_ty = infer_expr_type(&args[1], scopes, env, state);
            let value_ty = infer_expr_type(&args[2], scopes, env, state);
            if !index_ty.as_ref().is_some_and(is_integer_type) {
                let found = index_ty
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string());
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("index expression must be integer, got `{found}`"),
                );
            }
            match base_ty {
                Some(Type::Array { elem, .. })
                | Some(Type::Slice(elem))
                | Some(Type::Vec(elem))
                | Some(Type::Ptr { to: elem, .. }) => {
                    if let Some(actual) = value_ty.as_ref() {
                        if !expr_type_compatible(&elem, actual, &args[2]) {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "indexed assignment type mismatch: expected `{}`, got `{}`",
                                    elem, actual
                                ),
                            );
                        }
                    }
                }
                Some(Type::Named {
                    name,
                    args: named_args,
                }) if name == "GpuSlice" && named_args.len() == 1 => {
                    if let Some(actual) = value_ty.as_ref() {
                        if !expr_type_compatible(&named_args[0], actual, &args[2]) {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "indexed assignment type mismatch: expected `{}`, got `{}`",
                                    named_args[0], actual
                                ),
                            );
                        }
                    }
                }
                Some(Type::Str) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        "indexed assignment is not supported for type `str`".to_string(),
                    );
                }
                Some(other) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!("indexed assignment is not supported for type `{other}`"),
                    );
                }
                None => {}
            }
        }
        Stmt::Defer(expr) | Stmt::Requires(expr) | Stmt::Ensures(expr) | Stmt::Expr(expr) => {
            let _ = infer_expr_type(expr, scopes, env, state);
        }
    }
}

pub(crate) fn pattern_covers_variant(
    pattern: &ast::Pattern,
    enum_name: &str,
    covered: &mut BTreeSet<String>,
) -> bool {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => true,
        ast::Pattern::Variant {
            enum_name: arm_enum,
            variant,
            ..
        } => {
            if arm_enum == enum_name {
                covered.insert(variant.clone());
            }
            false
        }
        ast::Pattern::Or(patterns) => patterns
            .iter()
            .any(|pattern| pattern_covers_variant(pattern, enum_name, covered)),
        ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Struct { .. } => false,
    }
}

pub(crate) fn check_match_exhaustiveness(
    scrutinee_ty: Option<&Type>,
    arms: &[ast::MatchArm],
    enum_defs: &HashMap<String, ast::Enum>,
    errors: &mut usize,
    type_error_details: &mut Vec<String>,
) {
    let Some(Type::Named { name, .. }) = scrutinee_ty else {
        return;
    };
    let Some(enum_def) = enum_defs.get(name) else {
        return;
    };
    let mut covered = BTreeSet::new();
    for arm in arms {
        if arm.guard.is_none() && pattern_covers_variant(&arm.pattern, name, &mut covered) {
            return;
        }
    }
    let missing = enum_def
        .variants
        .iter()
        .map(|variant| variant.name.clone())
        .filter(|variant| !covered.contains(variant))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        record_type_error(
            errors,
            type_error_details,
            format!(
                "non-exhaustive match for enum `{name}`: missing variant(s): {}",
                missing.join(", ")
            ),
        );
    }
}

pub(crate) fn infer_unsafe_block_type(
    body: &[Stmt],
    scopes: &SymbolScopes,
    env: &TypeCheckEnv<'_>,
    state: &mut TypeCheckState<'_>,
) -> Option<Type> {
    let mut block_scopes = scopes.clone();
    block_scopes.push();
    let mut local_types = BTreeMap::new();
    let mut tail_ty = Some(Type::Void);
    for stmt in body {
        match stmt {
            Stmt::Expr(expr) => {
                tail_ty = infer_expr_type(expr, &block_scopes, env, state);
            }
            Stmt::Return(Some(expr)) => {
                let _ = infer_expr_type(expr, &block_scopes, env, state);
                tail_ty = Some(Type::Never);
            }
            Stmt::Return(None) => {
                tail_ty = Some(Type::Never);
            }
            Stmt::Break(value) => {
                if let Some(value) = value {
                    let _ = infer_expr_type(value, &block_scopes, env, state);
                }
                tail_ty = Some(Type::Never);
            }
            Stmt::Continue => {
                tail_ty = Some(Type::Never);
            }
            _ => {
                type_check_stmt(
                    stmt,
                    &mut block_scopes,
                    &mut local_types,
                    env,
                    0,
                    &Type::Void,
                    state,
                );
                tail_ty = Some(Type::Void);
            }
        }
    }
    block_scopes.pop();
    tail_ty
}

pub(crate) fn ffi_borrowed_str_arg_compatible(
    env: &TypeCheckEnv<'_>,
    callee: &str,
    index: usize,
    expected: &Type,
    actual: &Type,
    arg: &Expr,
) -> bool {
    let resolved_callee = if env.fn_is_extern_unsafe_c.contains(callee) {
        callee.to_string()
    } else if !env.current_namespace.is_empty() {
        let qualified = format!("{}.{}", env.current_namespace, callee);
        if env.fn_is_extern_unsafe_c.contains(&qualified) {
            qualified
        } else {
            return false;
        }
    } else {
        return false;
    };
    let Some(name) = env
        .fn_param_names
        .get(&resolved_callee)
        .and_then(|params| params.get(index))
    else {
        return false;
    };
    match expected {
        Type::Ptr { to, .. }
            if name.contains("_borrowed")
                && matches!(actual, Type::Str)
                && matches!(
                    to.as_ref(),
                    Type::Int {
                        signed: false,
                        bits: 8
                    }
                ) =>
        {
            true
        }
        Type::USize
            if name.ends_with("len")
                && matches!(
                    actual,
                    Type::Int {
                        signed: true,
                        bits: 32
                    }
                )
                && matches!(arg, Expr::Call { callee, .. } if callee == "str.len") =>
        {
            true
        }
        _ => false,
    }
}

pub(crate) fn sibling_len_binding_name(name: &str) -> Option<String> {
    for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
        if let Some(stem) = name.strip_suffix(suffix) {
            return Some(format!("{stem}_len"));
        }
    }
    if let Some(stem) = name.strip_suffix("_ptr") {
        return Some(format!("{stem}_len"));
    }
    Some(format!("{name}_len"))
}

pub(crate) fn gpu_upload_ptr_arg_compatible(
    scopes: &SymbolScopes,
    callee: &str,
    index: usize,
    expected: &Type,
    actual: &Type,
    arg: &Expr,
) -> bool {
    let is_upload = callee.ends_with("gpu.upload_f32")
        || callee.ends_with("gpu.upload_i32")
        || callee.ends_with("gpu.upload_u32")
        || matches!(
            callee,
            "gpu.upload_f32" | "gpu.upload_i32" | "gpu.upload_u32"
        );
    if !is_upload || index != 1 {
        return false;
    }
    let (Type::Slice(expected_inner), Type::Ptr { to, .. }) = (expected, actual) else {
        return false;
    };
    if !type_compatible(expected_inner, to) {
        return false;
    }
    let Expr::Ident(name) = arg else {
        return false;
    };
    let Some(len_name) = sibling_len_binding_name(name) else {
        return false;
    };
    scopes.get(&len_name).is_some_and(|ty| is_integer_type(&ty))
}

pub(crate) fn coerce_gpu_upload_arg_types(
    scopes: &SymbolScopes,
    callee: &str,
    params: &[Type],
    args: &[Expr],
    arg_types: &[Option<Type>],
) -> Vec<Option<Type>> {
    arg_types
        .iter()
        .enumerate()
        .map(|(index, actual)| {
            let Some(actual) = actual else {
                return None;
            };
            let Some(expected) = params.get(index) else {
                return Some(actual.clone());
            };
            let Some(arg) = args.get(index) else {
                return Some(actual.clone());
            };
            if gpu_upload_ptr_arg_compatible(scopes, callee, index, expected, actual, arg) {
                Some(expected.clone())
            } else {
                Some(actual.clone())
            }
        })
        .collect()
}

pub(crate) fn coerce_ffi_borrowed_str_arg_types(
    env: &TypeCheckEnv<'_>,
    callee: &str,
    params: &[Type],
    args: &[Expr],
    arg_types: &[Option<Type>],
) -> Vec<Option<Type>> {
    let resolved_callee = if env.fn_is_extern_unsafe_c.contains(callee) {
        callee.to_string()
    } else if !env.current_namespace.is_empty() {
        let qualified = format!("{}.{}", env.current_namespace, callee);
        if env.fn_is_extern_unsafe_c.contains(&qualified) {
            qualified
        } else {
            return arg_types.to_vec();
        }
    } else {
        return arg_types.to_vec();
    };
    let Some(param_names) = env.fn_param_names.get(&resolved_callee) else {
        return arg_types.to_vec();
    };
    arg_types
        .iter()
        .enumerate()
        .map(|(index, actual)| {
            let Some(actual) = actual else {
                return None;
            };
            let Some(expected) = params.get(index) else {
                return Some(actual.clone());
            };
            let Some(arg) = args.get(index) else {
                return Some(actual.clone());
            };
            let Some(name) = param_names.get(index) else {
                return Some(actual.clone());
            };
            match expected {
                Type::Ptr { to, .. }
                    if name.contains("_borrowed")
                        && matches!(actual, Type::Str)
                        && matches!(
                            to.as_ref(),
                            Type::Int {
                                signed: false,
                                bits: 8
                            }
                        ) =>
                {
                    Some(expected.clone())
                }
                Type::USize
                    if name.ends_with("len")
                        && matches!(
                            actual,
                            Type::Int {
                                signed: true,
                                bits: 32
                            }
                        )
                        && matches!(arg, Expr::Call { callee, .. } if callee == "str.len") =>
                {
                    Some(Type::USize)
                }
                _ => Some(actual.clone()),
            }
        })
        .collect()
}

pub(crate) fn infer_expr_type(
    expr: &Expr,
    scopes: &SymbolScopes,
    env: &TypeCheckEnv<'_>,
    state: &mut TypeCheckState<'_>,
) -> Option<Type> {
    let fn_sigs = env.fn_sigs;
    let fn_async = env.fn_async;
    let fn_generics = env.fn_generics;
    let struct_defs = env.struct_defs;
    let enum_defs = env.enum_defs;
    let trait_impls = env.trait_impls;
    let global_types = env.global_types;
    fn resolve_function_ref_name(
        fn_sigs: &HashMap<String, (Vec<Type>, Type)>,
        candidate: &str,
    ) -> Option<String> {
        if fn_sigs.contains_key(candidate) {
            return Some(candidate.to_string());
        }
        let suffix = format!(".{candidate}");
        let mut matched: Option<String> = None;
        for name in fn_sigs.keys() {
            if name.ends_with(&suffix) {
                if matched.is_some() {
                    return None;
                }
                matched = Some(name.clone());
            }
        }
        matched
    }

    fn function_ref_type(
        fn_sigs: &HashMap<String, (Vec<Type>, Type)>,
        candidate: &str,
    ) -> Option<Type> {
        let resolved = resolve_function_ref_name(fn_sigs, candidate)?;
        let (params, ret) = fn_sigs.get(&resolved)?;
        Some(Type::Function {
            params: params.clone(),
            ret: Box::new(ret.clone()),
        })
    }

    fn resolve_method_call_target(
        fn_sigs: &HashMap<String, (Vec<Type>, Type)>,
        scopes: &SymbolScopes,
        global_types: &HashMap<String, Type>,
        candidate: &str,
    ) -> Option<String> {
        if fn_sigs.contains_key(candidate) {
            return Some(candidate.to_string());
        }
        let (receiver_name, method_name) = candidate.rsplit_once('.')?;
        let receiver_ty = scopes
            .get(receiver_name)
            .or_else(|| global_types.get(receiver_name).cloned())?;
        let target = format!("{receiver_ty}.{method_name}");
        fn_sigs.contains_key(&target).then_some(target)
    }

    fn expr_function_ref_name(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Ident(name) => Some(name.clone()),
            Expr::Group(inner) => expr_function_ref_name(inner),
            Expr::FieldAccess { base, field } => {
                let mut base_name = expr_function_ref_name(base)?;
                base_name.push('.');
                base_name.push_str(field);
                Some(base_name)
            }
            _ => None,
        }
    }

    match expr {
        Expr::Int(v) => {
            let bits = if i32::try_from(*v).is_ok() {
                32
            } else if i64::try_from(*v).is_ok() {
                64
            } else {
                128
            };
            Some(Type::Int { signed: true, bits })
        }
        Expr::Float { bits, .. } => Some(Type::Float {
            bits: bits.unwrap_or(64),
        }),
        Expr::Char(_) => Some(Type::Char),
        Expr::Bool(_) => Some(Type::Bool),
        Expr::Str(_) => Some(Type::Str),
        Expr::Ident(name) => {
            if let Some(found) = scopes.get(name) {
                return Some(found);
            }
            if let Some(found) = global_types.get(name) {
                return Some(found.clone());
            }
            if !env.current_namespace.is_empty() {
                let qualified_name = format!("{}.{}", env.current_namespace, name);
                if let Some(found) = global_types.get(&qualified_name) {
                    return Some(found.clone());
                }
            }
            if let Some(fn_ty) = function_ref_type(fn_sigs, name) {
                return Some(fn_ty);
            }
            let mut detail = format!("unresolved identifier `{name}`");
            if let Some(hint) = builtin_namespace_hint(name) {
                detail.push_str(&format!("; {hint}"));
            }
            record_type_error(state.errors, state.type_error_details, detail);
            None
        }
        Expr::UnsafeBlock { body, .. } => infer_unsafe_block_type(body, scopes, env, state),
        Expr::Closure {
            params,
            return_type,
            body,
        } => {
            let mut closure_scopes = scopes.clone();
            closure_scopes.push();
            for param in params {
                closure_scopes.insert(param.name.clone(), param.ty.clone(), false);
            }
            let inferred_body = infer_expr_type(body, &closure_scopes, env, state);
            let resolved_ret = match (return_type, inferred_body) {
                (Some(expected), Some(actual)) => {
                    if !type_compatible(expected, &actual) {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "closure return type mismatch: expected `{}`, got `{}`",
                                expected, actual
                            ),
                        );
                    }
                    expected.clone()
                }
                (Some(expected), None) => expected.clone(),
                (None, Some(actual)) => actual,
                (None, None) => Type::Void,
            };
            Some(Type::Function {
                params: params.iter().map(|param| param.ty.clone()).collect(),
                ret: Box::new(resolved_ret),
            })
        }
        Expr::Group(inner) => infer_expr_type(inner, scopes, env, state),
        Expr::Tuple(items) => Some(Type::Tuple(
            items
                .iter()
                .map(|item| infer_expr_type(item, scopes, env, state).unwrap_or(Type::Never))
                .collect(),
        )),
        Expr::Await(inner) => match infer_expr_type(inner, scopes, env, state) {
            Some(Type::Future(value)) => Some(*value),
            Some(other) => {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("await expects `Future<T>`, got `{other}`"),
                );
                None
            }
            None => None,
        },
        Expr::Discard(inner) => {
            let _ = infer_expr_type(inner, scopes, env, state);
            Some(Type::Void)
        }
        Expr::Return(value) => {
            if let Some(value) = value {
                let _ = infer_expr_type(value, scopes, env, state);
            }
            Some(Type::Never)
        }
        Expr::Break(value) => {
            if let Some(value) = value {
                let _ = infer_expr_type(value, scopes, env, state);
            }
            Some(Type::Never)
        }
        Expr::Continue => Some(Type::Never),
        Expr::Call { callee, args } => {
            let has_specialization_syntax = callee.contains('<') || callee.contains('>');
            let (raw_callee, explicit_types) = split_generic_callee(callee);
            if has_specialization_syntax && explicit_types.is_none() {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!(
                        "invalid generic specialization syntax for call `{}`; expected `name<Type, ...>(...)` with balanced type arguments",
                        callee
                    ),
                );
                return None;
            }
            let resolved_callee =
                resolve_method_call_target(fn_sigs, scopes, global_types, raw_callee)
                    .unwrap_or_else(|| raw_callee.to_string());
            let base_callee = resolved_callee.as_str();
            if base_callee == "__index_assign" {
                if args.len() != 3 {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        "indexed assignment expects exactly 3 arguments".to_string(),
                    );
                    return Some(Type::Void);
                }
                let mut base_ty = infer_expr_type(&args[0], scopes, env, state);
                if !base_ty.as_ref().is_some_and(supports_index_base_type) {
                    if let Some(root_name) = expr_root_binding_name(&args[0]) {
                        if let Some(found) = scopes.get(root_name) {
                            base_ty = Some(found.clone());
                        } else if let Some(found) = global_types.get(root_name) {
                            base_ty = Some(found.clone());
                        }
                    }
                }
                let index_ty = infer_expr_type(&args[1], scopes, env, state);
                let value_ty = infer_expr_type(&args[2], scopes, env, state);
                if !index_ty.as_ref().is_some_and(is_integer_type) {
                    let found = index_ty
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "unknown".to_string());
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!("index expression must be integer, got `{found}`"),
                    );
                }
                match base_ty {
                    Some(Type::Array { elem, .. })
                    | Some(Type::Slice(elem))
                    | Some(Type::Vec(elem))
                    | Some(Type::Ptr { to: elem, .. }) => {
                        if let Some(actual) = value_ty.as_ref() {
                            if !expr_type_compatible(&elem, actual, &args[2]) {
                                record_type_error(
                                    state.errors,
                                    state.type_error_details,
                                    format!(
                                        "indexed assignment type mismatch: expected `{}`, got `{}`",
                                        elem, actual
                                    ),
                                );
                            }
                        }
                    }
                    Some(Type::Named {
                        name,
                        args: named_args,
                    }) if name == "GpuSlice" && named_args.len() == 1 => {
                        if let Some(actual) = value_ty.as_ref() {
                            if !expr_type_compatible(&named_args[0], actual, &args[2]) {
                                record_type_error(
                                    state.errors,
                                    state.type_error_details,
                                    format!(
                                        "indexed assignment type mismatch: expected `{}`, got `{}`",
                                        named_args[0], actual
                                    ),
                                );
                            }
                        }
                    }
                    Some(Type::Str) => {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            "indexed assignment is not supported for type `str`".to_string(),
                        );
                    }
                    Some(other) => {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!("indexed assignment is not supported for type `{other}`"),
                        );
                    }
                    None => {}
                }
                return Some(Type::Void);
            }
            if let Some(Type::Function { params, ret }) = scopes.get(base_callee) {
                if explicit_types.is_some() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "generic specialization is not valid on function values: `{}`",
                            base_callee
                        ),
                    );
                }
                let mut arg_types = Vec::with_capacity(args.len());
                for arg in args {
                    arg_types.push(infer_expr_type(arg, scopes, env, state));
                }
                if params.len() != arg_types.len() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "call `{}` expects {} args but got {}",
                            base_callee,
                            params.len(),
                            arg_types.len()
                        ),
                    );
                }
                for (index, expected) in params.iter().enumerate() {
                    if let Some(Some(actual)) = arg_types.get(index) {
                        if !expr_type_compatible(expected, actual, &args[index])
                            && !ffi_borrowed_str_arg_compatible(
                                env,
                                base_callee,
                                index,
                                expected,
                                actual,
                                &args[index],
                            )
                            && !gpu_upload_ptr_arg_compatible(
                                scopes,
                                base_callee,
                                index,
                                expected,
                                actual,
                                &args[index],
                            )
                        {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "call `{}` argument {} type mismatch: expected `{}`, got `{}`",
                                    base_callee, index, expected, actual
                                ),
                            );
                        }
                    }
                }
                return Some(*ret);
            }
            if let Some(found) = scopes.get(base_callee) {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!(
                        "call target `{}` is not callable (found `{}`)",
                        base_callee, found
                    ),
                );
                return None;
            }
            if base_callee == "str.concat" {
                if args.len() < 2 {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        "runtime call `str.concat` expects at least 2 string args; use `str.concat(a, b, ...)`".to_string(),
                    );
                    return None;
                }
                for arg in args {
                    let actual = infer_expr_type(arg, scopes, env, state);
                    if let Some(actual) = actual.as_ref() {
                        if !type_compatible(&Type::Str, actual) {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "runtime call `str.concat` argument type mismatch: expected `str`, got `{}`",
                                    actual
                                ),
                            );
                        }
                    }
                }
                return Some(Type::Str);
            }
            let runtime_sig = runtime_call_signature(base_callee);
            let mut is_function_async = false;
            let (params, ret) = if let Some((params, ret)) = fn_sigs.get(base_callee) {
                is_function_async = fn_async.get(base_callee).copied().unwrap_or(false);
                let ret = if is_function_async && !matches!(ret, Type::Future(_)) {
                    Type::Future(Box::new(ret.clone()))
                } else {
                    ret.clone()
                };
                (params.clone(), ret)
            } else if let Some((params, ret)) = runtime_sig {
                (params, ret)
            } else {
                let mut detail = format!("unresolved call target `{}`", base_callee);
                if let Some(stripped) = base_callee.strip_prefix("process.") {
                    let migrated = format!("proc.{stripped}");
                    if runtime_call_signature(&migrated).is_some() {
                        detail.push_str(&format!(
                            "; `process.*` was removed, migrate to `{}`",
                            migrated
                        ));
                    }
                } else if let Some(arity_suffix) = base_callee.strip_prefix("json.object") {
                    if !arity_suffix.is_empty()
                        && arity_suffix.chars().all(|ch| ch.is_ascii_digit())
                    {
                        detail.push_str(
                            "; autofix: replace with `json.object(#{\"k\": json.str(\"v\")})` and expand fields as needed",
                        );
                    }
                } else if let Some(arity_suffix) = base_callee.strip_prefix("json.array") {
                    if !arity_suffix.is_empty()
                        && arity_suffix.chars().all(|ch| ch.is_ascii_digit())
                    {
                        detail.push_str(
                            "; autofix: replace with `json.array([item1, item2])` or build via `list.new/push`",
                        );
                    }
                } else if let Some(arity_suffix) = base_callee.strip_prefix("log.fields") {
                    if !arity_suffix.is_empty()
                        && arity_suffix.chars().all(|ch| ch.is_ascii_digit())
                    {
                        detail.push_str(
                            "; autofix: replace with `log.fields(#{\"k\": json.str(\"v\")})`",
                        );
                    }
                } else if let Some(hint) = builtin_namespace_hint(base_callee) {
                    detail.push_str(&format!("; {hint}"));
                } else if let Some(nearest) = nearest_intrinsic_name(base_callee) {
                    detail.push_str(&format!("; did you mean `{}`?", nearest));
                }
                record_type_error(state.errors, state.type_error_details, detail);
                return None;
            };
            let generics = if fn_sigs.contains_key(base_callee) {
                fn_generics.get(base_callee).cloned().unwrap_or_default()
            } else {
                runtime_signature_generics(&params, &ret)
            };
            if fn_sigs.contains_key(base_callee) && !generics.is_empty() && explicit_types.is_none()
            {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!(
                        "generic call `{}` requires explicit specialization in production mode (for example: `{}<...>(...)`)",
                        base_callee, base_callee
                    ),
                );
                return None;
            }
            let mut arg_types = Vec::with_capacity(args.len());
            for arg in args {
                arg_types.push(infer_expr_type(arg, scopes, env, state));
            }
            let signature_arg_types = coerce_gpu_upload_arg_types(
                scopes,
                base_callee,
                &params,
                args,
                &coerce_ffi_borrowed_str_arg_types(env, base_callee, &params, args, &arg_types),
            );
            let (
                resolved_params,
                resolved_ret,
                bindings,
                skip_post_call_validation,
                post_check_arg_types,
            ) = if fn_sigs.contains_key(base_callee) {
                let Some((resolved_params, resolved_ret, bindings)) = resolve_call_signature(
                    &params,
                    &ret,
                    &generics,
                    &signature_arg_types,
                    explicit_types.as_deref(),
                ) else {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "call signature mismatch for `{}`: expected ({}) -> {}",
                            base_callee,
                            params
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                            ret
                        ),
                    );
                    return None;
                };
                let resolved_ret = if is_function_async && !matches!(resolved_ret, Type::Future(_))
                {
                    Type::Future(Box::new(resolved_ret))
                } else {
                    resolved_ret
                };
                (
                    resolved_params,
                    resolved_ret,
                    bindings,
                    false,
                    signature_arg_types,
                )
            } else {
                let Some((resolved_params, resolved_ret, bindings)) = resolve_call_signature(
                    &params,
                    &ret,
                    &generics,
                    &signature_arg_types,
                    explicit_types.as_deref(),
                ) else {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "runtime call signature mismatch for `{}`: expected ({}) -> {}",
                            base_callee,
                            params
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                            ret
                        ),
                    );
                    return None;
                };
                if params.len() != args.len() {
                    let detail = if matches!(base_callee, "http.write" | "http.write_json")
                        && args.len() == 1
                    {
                        format!(
                            "runtime call `{}` migrated to `(conn, status, body)`; update call sites like `{}(conn, 200, \"ok\")`",
                            base_callee, base_callee
                        )
                    } else if matches!(base_callee, "str.concat2" | "str.concat3" | "str.concat4") {
                        format!(
                            "runtime call `{}` expects {} args but got {}; use `str.concat(...)` for the general string-assembly path or match the fixed helper arity exactly",
                            base_callee,
                            params.len(),
                            args.len()
                        )
                    } else {
                        format!(
                            "runtime call `{}` expects {} args but got {}",
                            base_callee,
                            params.len(),
                            args.len()
                        )
                    };
                    record_type_error(state.errors, state.type_error_details, detail);
                    return None;
                }
                for (index, (expected, actual)) in resolved_params
                    .iter()
                    .zip(signature_arg_types.iter())
                    .enumerate()
                {
                    let Some(actual) = actual else {
                        continue;
                    };
                    if !expr_type_compatible(expected, actual, &args[index])
                        && !ffi_borrowed_str_arg_compatible(
                            env,
                            base_callee,
                            index,
                            expected,
                            actual,
                            &args[index],
                        )
                        && !gpu_upload_ptr_arg_compatible(
                            scopes,
                            base_callee,
                            index,
                            expected,
                            actual,
                            &args[index],
                        )
                    {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "runtime call `{}` argument type mismatch: expected `{}`, got `{}`",
                                base_callee, expected, actual
                            ),
                        );
                    }
                }
                (
                    resolved_params,
                    resolved_ret,
                    bindings,
                    false,
                    signature_arg_types,
                )
            };
            if !bindings.is_empty() {
                let rendered = bindings
                    .iter()
                    .map(|(name, ty)| format!("{name}={ty}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                state
                    .generic_specializations
                    .insert(format!("{base_callee}<{rendered}>"));
                for generic in &generics {
                    if let Some((_, concrete)) =
                        bindings.iter().find(|(name, _)| *name == generic.name)
                    {
                        for bound in &generic.bounds {
                            let match_count = trait_impl_match_count(concrete, bound, trait_impls);
                            if match_count == 0 {
                                let detail = format!(
                                    "generic specialization `{}` violates bound `{}` on `{}`",
                                    base_callee, bound, generic.name
                                );
                                state.trait_violations.push(detail.clone());
                                record_type_error(state.errors, state.type_error_details, detail);
                            } else if match_count > 1 {
                                let detail = format!(
                                    "generic specialization `{}` has ambiguous bound `{}` on `{}`: {} matching impls",
                                    base_callee, bound, generic.name, match_count
                                );
                                state.trait_violations.push(detail.clone());
                                record_type_error(state.errors, state.type_error_details, detail);
                            }
                        }
                    }
                }
            }
            if !skip_post_call_validation {
                if resolved_params.len() != args.len() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "call `{}` parameter count mismatch after resolution: expected {}, got {}",
                            base_callee,
                            resolved_params.len(),
                            args.len()
                        ),
                    );
                }
                for (index, arg_ty) in post_check_arg_types.into_iter().enumerate() {
                    if let (Some(expected), Some(actual)) = (resolved_params.get(index), arg_ty) {
                        if !expr_type_compatible(expected, &actual, &args[index])
                            && !ffi_borrowed_str_arg_compatible(
                                env,
                                base_callee,
                                index,
                                expected,
                                &actual,
                                &args[index],
                            )
                            && !gpu_upload_ptr_arg_compatible(
                                scopes,
                                base_callee,
                                index,
                                expected,
                                &actual,
                                &args[index],
                            )
                        {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "call `{}` argument {} type mismatch: expected `{}`, got `{}`",
                                    base_callee, index, expected, actual
                                ),
                            );
                        }
                    }
                }
            }
            Some(resolved_ret)
        }
        Expr::FieldAccess { base, field } => {
            if let Some(function_ref) = expr_function_ref_name(expr) {
                if let Some(found) = scopes.get(&function_ref) {
                    return Some(found);
                }
                if let Some(found) = global_types.get(&function_ref) {
                    return Some(found.clone());
                }
                if let Some(resolved_method_ref) =
                    resolve_method_call_target(fn_sigs, scopes, global_types, &function_ref)
                {
                    if let Some(fn_ty) = function_ref_type(fn_sigs, &resolved_method_ref) {
                        return Some(fn_ty);
                    }
                }
                if let Some(fn_ty) = function_ref_type(fn_sigs, &function_ref) {
                    return Some(fn_ty);
                }
            }
            let base_ty = infer_expr_type(base, scopes, env, state)?;
            let Type::Named { name, .. } = base_ty else {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!(
                        "field access requires struct-like receiver; expression resolved to `{}`",
                        base_ty
                    ),
                );
                return None;
            };
            let Some(struct_def) = struct_defs.get(&name) else {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("field access targets unknown struct `{name}`"),
                );
                return None;
            };
            let Some(found) = struct_def
                .fields
                .iter()
                .find(|candidate| candidate.name == *field)
            else {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("struct `{name}` has no field `{field}`"),
                );
                return None;
            };
            Some(found.ty.clone())
        }
        Expr::StructInit { name, fields } => {
            let Some(struct_def) = struct_defs.get(name) else {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("unknown struct `{name}` in initializer"),
                );
                return None;
            };
            let mut generic_bindings = struct_def
                .generics
                .iter()
                .map(|param| (param.name.clone(), Type::TypeVar(param.name.clone())))
                .collect::<BTreeMap<_, _>>();
            for (field_name, value) in fields {
                let Some(found) = struct_def
                    .fields
                    .iter()
                    .find(|candidate| candidate.name == *field_name)
                else {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!("struct `{name}` has no field `{field_name}`"),
                    );
                    continue;
                };
                let value_ty = infer_expr_type(value, scopes, env, state);
                if let Some(value_ty) = value_ty {
                    if !bind_typevars(&found.ty, &value_ty, &mut generic_bindings)
                        && !type_compatible(&found.ty, &value_ty)
                    {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "struct field `{name}.{field_name}` type mismatch: expected `{}`, got `{}`",
                                found.ty, value_ty
                            ),
                        );
                    }
                }
            }
            let resolved_args = struct_def
                .generics
                .iter()
                .map(|param| {
                    generic_bindings
                        .get(&param.name)
                        .cloned()
                        .unwrap_or_else(|| Type::TypeVar(param.name.clone()))
                })
                .collect::<Vec<_>>();
            Some(Type::Named {
                name: name.clone(),
                args: resolved_args,
            })
        }
        Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => {
            let Some(enum_def) = enum_defs.get(enum_name) else {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("unknown enum `{enum_name}` in initializer"),
                );
                return None;
            };
            let Some(found_variant) = enum_def
                .variants
                .iter()
                .find(|candidate| candidate.name == *variant)
            else {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("enum `{enum_name}` has no variant `{variant}`"),
                );
                return None;
            };
            let mut generic_bindings = enum_def
                .generics
                .iter()
                .map(|param| (param.name.clone(), Type::TypeVar(param.name.clone())))
                .collect::<BTreeMap<_, _>>();
            if !found_variant.named_payload.is_empty() {
                if !payload.is_empty() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "enum struct-variant `{enum_name}.{variant}` requires named payload fields"
                        ),
                    );
                }
                if found_variant.named_payload.len() != named_payload.len() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "enum struct-variant `{enum_name}.{variant}` field arity mismatch: expected {}, got {}",
                            found_variant.named_payload.len(),
                            named_payload.len()
                        ),
                    );
                }
                for (field_name, value) in named_payload {
                    let expected = found_variant
                        .named_payload
                        .iter()
                        .find(|field| field.name == *field_name);
                    let Some(expected) = expected else {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "enum struct-variant `{enum_name}.{variant}` has no field `{field_name}`"
                            ),
                        );
                        let _ = infer_expr_type(value, scopes, env, state);
                        continue;
                    };
                    if let Some(actual) = infer_expr_type(value, scopes, env, state) {
                        if !bind_typevars(&expected.ty, &actual, &mut generic_bindings)
                            && !type_compatible(&expected.ty, &actual)
                        {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "enum struct-variant `{enum_name}.{variant}.{field_name}` type mismatch: expected `{}`, got `{}`",
                                    expected.ty, actual
                                ),
                            );
                        }
                    }
                }
            } else {
                if !named_payload.is_empty() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "enum tuple/unit variant `{enum_name}.{variant}` does not accept named payload fields"
                        ),
                    );
                }
                if found_variant.payload.len() != payload.len() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "enum variant `{enum_name}.{variant}` payload arity mismatch: expected {}, got {}",
                            found_variant.payload.len(),
                            payload.len()
                        ),
                    );
                }
                for (index, value) in payload.iter().enumerate() {
                    let value_ty = infer_expr_type(value, scopes, env, state);
                    if let (Some(expected), Some(actual)) =
                        (found_variant.payload.get(index), value_ty)
                    {
                        if !bind_typevars(expected, &actual, &mut generic_bindings)
                            && !type_compatible(expected, &actual)
                        {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "enum variant `{enum_name}.{variant}` payload {index} type mismatch: expected `{expected}`, got `{actual}`"
                                ),
                            );
                        }
                    }
                }
            }
            let resolved_args = enum_def
                .generics
                .iter()
                .map(|param| {
                    generic_bindings
                        .get(&param.name)
                        .cloned()
                        .unwrap_or_else(|| Type::TypeVar(param.name.clone()))
                })
                .collect::<Vec<_>>();
            Some(Type::Named {
                name: enum_name.clone(),
                args: resolved_args,
            })
        }
        Expr::Unary { op, expr } => {
            let inner = infer_expr_type(expr, scopes, env, state);
            match (op, inner) {
                (ast::UnaryOp::Not, Some(ty)) => {
                    if is_bool_or_integer(Some(&ty)) {
                        Some(Type::Bool)
                    } else {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "logical not expects bool/integer-compatible operand, got `{ty}`"
                            ),
                        );
                        None
                    }
                }
                (ast::UnaryOp::BitNot, Some(ty))
                | (ast::UnaryOp::Plus, Some(ty))
                | (ast::UnaryOp::Neg, Some(ty)) => {
                    if is_integer_type(&ty) {
                        Some(ty)
                    } else if !matches!(op, ast::UnaryOp::BitNot) && is_float_type(&ty) {
                        Some(ty)
                    } else {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!("unary operator expects numeric operand, got `{ty}`"),
                        );
                        None
                    }
                }
                (_, None) => None,
            }
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let cond_ty = infer_expr_type(condition, scopes, env, state);
            if !is_bool_or_integer(cond_ty.as_ref()) {
                let found = cond_ty
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string());
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("if condition must be bool/integer-compatible, got `{found}`"),
                );
            }
            let then_ty = infer_expr_type(then_expr, scopes, env, state);
            let else_ty = infer_expr_type(else_expr, scopes, env, state);
            match (then_ty, else_ty) {
                (Some(left), Some(right)) if type_compatible(&left, &right) => Some(left),
                (Some(left), Some(right)) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "if-expression branches must resolve to compatible types, got `{left}` and `{right}`"
                        ),
                    );
                    None
                }
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (None, None) => None,
            }
        }
        Expr::Match { scrutinee, arms } => {
            let scrutinee_ty = infer_expr_type(scrutinee, scopes, env, state);
            check_match_exhaustiveness(
                scrutinee_ty.as_ref(),
                arms,
                enum_defs,
                state.errors,
                state.type_error_details,
            );
            let mut arm_ty: Option<Type> = None;
            for arm in arms {
                let mut arm_scopes = scopes.clone();
                arm_scopes.push();
                check_pattern_compatibility(
                    &arm.pattern,
                    scrutinee_ty.as_ref(),
                    struct_defs,
                    enum_defs,
                    state.errors,
                    state.type_error_details,
                );
                if let Some(scrutinee_ty) = scrutinee_ty.as_ref() {
                    bind_pattern_types(
                        &arm.pattern,
                        scrutinee_ty,
                        false,
                        &mut arm_scopes,
                        struct_defs,
                        enum_defs,
                        state.errors,
                        state.type_error_details,
                    );
                }
                if let Some(guard) = &arm.guard {
                    let guard_ty = infer_expr_type(guard, &arm_scopes, env, state);
                    if !is_bool_or_integer(guard_ty.as_ref()) {
                        let found = guard_ty
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".to_string());
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!("match guard must be bool/integer-compatible, got `{found}`"),
                        );
                    }
                }
                let value_ty = if arm.returns {
                    let _ = infer_expr_type(&arm.value, &arm_scopes, env, state);
                    Some(Type::Never)
                } else {
                    infer_expr_type(&arm.value, &arm_scopes, env, state)
                };
                if let Some(value_ty) = value_ty {
                    if let Some(existing) = &arm_ty {
                        if !type_compatible(existing, &value_ty) {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "match expression arms must resolve to compatible types, got `{existing}` and `{value_ty}`"
                                ),
                            );
                        }
                    } else {
                        arm_ty = Some(value_ty);
                    }
                }
            }
            arm_ty
        }
        Expr::While { condition, body } => {
            let cond_ty = infer_expr_type(condition, scopes, env, state);
            if !is_bool_or_integer(cond_ty.as_ref()) {
                let found = cond_ty
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string());
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("while-condition must be bool/integer-compatible, got `{found}`"),
                );
            }
            let mut loop_scopes = scopes.clone();
            loop_scopes.push();
            let mut loop_local_types = BTreeMap::new();
            for stmt in body {
                type_check_stmt(
                    stmt,
                    &mut loop_scopes,
                    &mut loop_local_types,
                    env,
                    1,
                    &Type::Void,
                    state,
                );
            }
            Some(Type::Void)
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            let mut loop_scopes = scopes.clone();
            loop_scopes.push();
            let mut loop_local_types = BTreeMap::new();
            if let Some(init) = init {
                type_check_stmt(
                    init,
                    &mut loop_scopes,
                    &mut loop_local_types,
                    env,
                    1,
                    &Type::Void,
                    state,
                );
            }
            if let Some(condition) = condition {
                let cond_ty = infer_expr_type(condition, &loop_scopes, env, state);
                if !is_bool_or_integer(cond_ty.as_ref()) {
                    let found = cond_ty
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "unknown".to_string());
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!("for-condition must be bool/integer-compatible, got `{found}`"),
                    );
                }
            }
            for stmt in body {
                type_check_stmt(
                    stmt,
                    &mut loop_scopes,
                    &mut loop_local_types,
                    env,
                    1,
                    &Type::Void,
                    state,
                );
            }
            if let Some(step) = step {
                type_check_stmt(
                    step,
                    &mut loop_scopes,
                    &mut loop_local_types,
                    env,
                    1,
                    &Type::Void,
                    state,
                );
            }
            Some(Type::Void)
        }
        Expr::ForIn {
            binding,
            iterable,
            body,
        } => {
            let iterable_ty = infer_expr_type(iterable, scopes, env, state);
            let binding_ty = match iterable_ty {
                Some(Type::Named { name, args }) if name == "Range" && args.len() == 1 => {
                    args[0].clone()
                }
                Some(other) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!("for-in iterable must be a range expression, got `{other}`"),
                    );
                    Type::Int {
                        signed: true,
                        bits: 32,
                    }
                }
                None => Type::Int {
                    signed: true,
                    bits: 32,
                },
            };
            let mut loop_scopes = scopes.clone();
            loop_scopes.push();
            loop_scopes.insert(binding.clone(), binding_ty, false);
            let mut loop_local_types = BTreeMap::new();
            for stmt in body {
                type_check_stmt(
                    stmt,
                    &mut loop_scopes,
                    &mut loop_local_types,
                    env,
                    1,
                    &Type::Void,
                    state,
                );
            }
            Some(Type::Void)
        }
        Expr::Loop { body } => {
            let mut loop_scopes = scopes.clone();
            loop_scopes.push();
            let mut loop_local_types = BTreeMap::new();
            for stmt in body {
                type_check_stmt(
                    stmt,
                    &mut loop_scopes,
                    &mut loop_local_types,
                    env,
                    1,
                    &Type::Void,
                    state,
                );
            }
            Some(Type::Void)
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let left = infer_expr_type(try_expr, scopes, env, state);
            let right = infer_expr_type(catch_expr, scopes, env, state);
            match (left, right) {
                (Some(l), Some(r)) if type_compatible(&l, &r) => Some(l),
                (Some(_), Some(_)) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        "try/catch branches must resolve to compatible types".to_string(),
                    );
                    None
                }
                (Some(l), None) => Some(l),
                (None, Some(r)) => Some(r),
                (None, None) => None,
            }
        }
        Expr::Range {
            start,
            end,
            inclusive: _,
        } => {
            let left_ty = infer_expr_type(start, scopes, env, state);
            let right_ty = infer_expr_type(end, scopes, env, state);
            match (left_ty, right_ty) {
                (Some(left), Some(right))
                    if is_integer_type(&left)
                        && is_integer_type(&right)
                        && type_compatible(&left, &right) =>
                {
                    Some(Type::Named {
                        name: "Range".to_string(),
                        args: vec![left],
                    })
                }
                (Some(left), Some(right)) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!(
                            "range bounds must be compatible integers, got `{}` and `{}`",
                            left, right
                        ),
                    );
                    None
                }
                _ => None,
            }
        }
        Expr::ArrayLiteral(items) => {
            if items.is_empty() {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    "cannot infer type of empty array literal".to_string(),
                );
                return Some(Type::Array {
                    elem: Box::new(i32_type()),
                    len: 0,
                });
            }
            let mut elem_ty: Option<Type> = None;
            for item in items {
                let ty = infer_expr_type(item, scopes, env, state);
                if let Some(ty) = ty {
                    if let Some(existing) = &elem_ty {
                        if !type_compatible(existing, &ty) {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "array literal element type mismatch: expected `{}`, got `{}`",
                                    existing, ty
                                ),
                            );
                        }
                    } else {
                        elem_ty = Some(ty);
                    }
                }
            }
            Some(Type::Array {
                elem: Box::new(elem_ty.unwrap_or_else(i32_type)),
                len: items.len(),
            })
        }
        Expr::ObjectLiteral(fields) => {
            let map_handle = Type::Named {
                name: "MapHandle".to_string(),
                args: Vec::new(),
            };
            let mut has_error = false;
            for (key, value) in fields {
                if key.trim().is_empty() {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        "object literal key must not be empty".to_string(),
                    );
                    has_error = true;
                }
                let value_ty = infer_expr_type(value, scopes, env, state);
                if let Some(actual) = value_ty {
                    if !type_compatible(&Type::Str, &actual) {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "object literal value for key `{key}` must be `str`-compatible JSON fragment, got `{actual}`"
                            ),
                        );
                        has_error = true;
                    }
                }
            }
            if has_error {
                None
            } else {
                // Object literals lower to canonical runtime map handles and interoperate
                // directly with `log.fields(map)` and `json.object(map)`.
                Some(map_handle)
            }
        }
        Expr::Index { base, index } => {
            let mut base_ty = infer_expr_type(base, scopes, env, state);
            if !base_ty.as_ref().is_some_and(supports_index_base_type) {
                if let Some(root_name) = expr_root_binding_name(base) {
                    if let Some(found) = scopes.get(root_name) {
                        base_ty = Some(found.clone());
                    } else if let Some(found) = global_types.get(root_name) {
                        base_ty = Some(found.clone());
                    }
                }
            }
            let index_ty = infer_expr_type(index, scopes, env, state);
            if !index_ty.as_ref().is_some_and(is_integer_type) {
                let found = index_ty
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string());
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("index expression must be integer, got `{found}`"),
                );
            }
            match base_ty {
                Some(Type::Array { elem, .. }) => Some(*elem),
                Some(Type::Slice(elem)) => Some(*elem),
                Some(Type::Vec(elem)) => Some(*elem),
                Some(Type::Ptr { to, .. }) => Some(*to),
                Some(Type::Named { name, args }) if name == "GpuSlice" && args.len() == 1 => {
                    Some(args[0].clone())
                }
                Some(Type::Str) => Some(Type::Char),
                Some(other) => {
                    record_type_error(
                        state.errors,
                        state.type_error_details,
                        format!("indexing is not supported for type `{other}`"),
                    );
                    None
                }
                None => None,
            }
        }
        Expr::Binary { op, left, right } => {
            let left_ty = infer_expr_type(left, scopes, env, state);
            let right_ty = infer_expr_type(right, scopes, env, state);
            match op {
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div => {
                    if left_ty.as_ref().is_some_and(is_integer_type)
                        && right_ty.as_ref().is_some_and(is_integer_type)
                    {
                        left_ty
                    } else if matches!(op, BinaryOp::Add | BinaryOp::Sub)
                        && left_ty
                            .as_ref()
                            .is_some_and(|ty| matches!(ty, Type::Ptr { .. }))
                        && right_ty.as_ref().is_some_and(is_integer_type)
                    {
                        left_ty
                    } else if *op == BinaryOp::Add
                        && left_ty.as_ref().is_some_and(is_integer_type)
                        && right_ty
                            .as_ref()
                            .is_some_and(|ty| matches!(ty, Type::Ptr { .. }))
                    {
                        right_ty
                    } else if left_ty.as_ref().is_some_and(is_float_type)
                        && right_ty.as_ref().is_some_and(is_float_type)
                    {
                        left_ty
                    } else if left_ty.as_ref().is_some_and(is_float_type)
                        && right_ty.as_ref().is_some_and(is_integer_type)
                    {
                        left_ty
                    } else if left_ty.as_ref().is_some_and(is_integer_type)
                        && right_ty.as_ref().is_some_and(is_float_type)
                    {
                        right_ty
                    } else {
                        let left = left_ty
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".to_string());
                        let right = right_ty
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".to_string());
                        let detail = if *op == BinaryOp::Add
                            && left_ty.as_ref().is_some_and(|ty| matches!(ty, Type::Str))
                            && right_ty.as_ref().is_some_and(|ty| matches!(ty, Type::Str))
                        {
                            "string addition is unsupported; use `str.concat(left, right)`"
                                .to_string()
                        } else if *op == BinaryOp::Add
                            && (left_ty.as_ref().is_some_and(|ty| matches!(ty, Type::Str))
                                || right_ty.as_ref().is_some_and(|ty| matches!(ty, Type::Str)))
                        {
                            format!(
                                "string addition is unsupported; use `str.concat(...)` with string arguments instead of `+` (got left=`{left}` right=`{right}`)"
                            )
                        } else {
                            format!(
                                "arithmetic operands must be numeric-compatible, got left=`{left}` right=`{right}`"
                            )
                        };
                        record_type_error(state.errors, state.type_error_details, detail);
                        None
                    }
                }
                BinaryOp::Mod => {
                    if left_ty.as_ref().is_some_and(is_integer_type)
                        && right_ty.as_ref().is_some_and(is_integer_type)
                    {
                        left_ty
                    } else {
                        let left = left_ty
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".to_string());
                        let right = right_ty
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown".to_string());
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            format!(
                                "arithmetic operands must be integers, got left=`{left}` right=`{right}`"
                            ),
                        );
                        None
                    }
                }
                BinaryOp::BitAnd
                | BinaryOp::BitOr
                | BinaryOp::BitXor
                | BinaryOp::Shl
                | BinaryOp::Shr => {
                    if left_ty.as_ref().is_some_and(is_integer_type)
                        && right_ty.as_ref().is_some_and(is_integer_type)
                    {
                        left_ty
                    } else {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            "bitwise operands must be integers".to_string(),
                        );
                        None
                    }
                }
                BinaryOp::And | BinaryOp::Or => {
                    if is_bool_or_integer(left_ty.as_ref()) && is_bool_or_integer(right_ty.as_ref())
                    {
                        Some(Type::Bool)
                    } else {
                        record_type_error(
                            state.errors,
                            state.type_error_details,
                            "logical operands must be bool/integer-compatible".to_string(),
                        );
                        None
                    }
                }
                BinaryOp::Eq
                | BinaryOp::Neq
                | BinaryOp::Lt
                | BinaryOp::Lte
                | BinaryOp::Gt
                | BinaryOp::Gte => {
                    if let (Some(l), Some(r)) = (&left_ty, &right_ty) {
                        let numeric_compatible = (is_integer_type(l) && is_integer_type(r))
                            || (is_float_type(l) && is_float_type(r))
                            || (is_float_type(l) && is_integer_type(r))
                            || (is_integer_type(l) && is_float_type(r));
                        if !numeric_compatible && !type_compatible(l, r) {
                            record_type_error(
                                state.errors,
                                state.type_error_details,
                                format!(
                                    "comparison operands must have compatible types, got `{}` and `{}`",
                                    l, r
                                ),
                            );
                        }
                    }
                    Some(Type::Bool)
                }
            }
        }
    }
}

pub(crate) fn split_generic_callee(callee: &str) -> (&str, Option<Vec<Type>>) {
    let Some(start) = callee.find('<') else {
        return (callee, None);
    };
    let mut depth = 0usize;
    let mut end = None;
    for (idx, ch) in callee.char_indices().skip(start) {
        match ch {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    return (&callee[..start], None);
                }
                depth -= 1;
                if depth == 0 {
                    end = Some(idx);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(end) = end else {
        return (&callee[..start], None);
    };
    if !callee[end + 1..].trim().is_empty() {
        return (&callee[..start], None);
    }
    let base = &callee[..start];
    let inside = &callee[start + 1..end];
    let Some(parts) = split_top_level_type_args(inside) else {
        return (base, None);
    };
    let parsed = parts
        .into_iter()
        .map(parse_simple_type)
        .collect::<Option<Vec<_>>>();
    (base, parsed)
}

pub(crate) fn split_top_level_type_args(input: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut depth_angle = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_paren = 0usize;
    let mut start = 0usize;
    for (idx, ch) in input.char_indices() {
        match ch {
            '<' => depth_angle += 1,
            '>' => {
                if depth_angle == 0 {
                    return None;
                }
                depth_angle -= 1;
            }
            '[' => depth_bracket += 1,
            ']' => {
                if depth_bracket == 0 {
                    return None;
                }
                depth_bracket -= 1;
            }
            '(' => depth_paren += 1,
            ')' => {
                if depth_paren == 0 {
                    return None;
                }
                depth_paren -= 1;
            }
            ',' if depth_angle == 0 && depth_bracket == 0 && depth_paren == 0 => {
                out.push(input[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    if depth_angle != 0 || depth_bracket != 0 || depth_paren != 0 {
        return None;
    }
    let tail = input[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    Some(out)
}

pub(crate) fn parse_simple_type(token: &str) -> Option<Type> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if let Some(simd_ty) = Type::parse_builtin_simd_alias(token) {
        return Some(simd_ty);
    }
    Some(match token {
        "never" => Type::Never,
        "bool" => Type::Bool,
        "str" => Type::Str,
        "bytes" => Type::Bytes,
        "void" => Type::Void,
        "Path" | "path" => Type::Path,
        "PathBuf" | "pathbuf" => Type::PathBuf,
        "Url" | "url" => Type::Url,
        "SocketAddr" | "socket_addr" => Type::SocketAddr,
        "Duration" | "duration" => Type::Duration,
        "Instant" | "instant" => Type::Instant,
        "Decimal" | "decimal" => Type::Decimal,
        "DateTimeTz" | "datetime_tz" => Type::DateTimeTz,
        "ExitStatus" | "exit_status" => Type::ExitStatus,
        "isize" => Type::ISize,
        "usize" => Type::USize,
        "BigInt" | "bigint" => Type::BigInt,
        "BigUint" | "biguint" => Type::BigUint,
        "i8" => Type::Int {
            signed: true,
            bits: 8,
        },
        "i16" => Type::Int {
            signed: true,
            bits: 16,
        },
        "i32" => Type::Int {
            signed: true,
            bits: 32,
        },
        "i64" => Type::Int {
            signed: true,
            bits: 64,
        },
        "i128" => Type::Int {
            signed: true,
            bits: 128,
        },
        "u8" => Type::Int {
            signed: false,
            bits: 8,
        },
        "u16" => Type::Int {
            signed: false,
            bits: 16,
        },
        "u32" => Type::Int {
            signed: false,
            bits: 32,
        },
        "u64" => Type::Int {
            signed: false,
            bits: 64,
        },
        "u128" => Type::Int {
            signed: false,
            bits: 128,
        },
        "f32" => Type::Float { bits: 32 },
        "f64" => Type::Float { bits: 64 },
        "Decimal128" | "decimal128" => Type::Decimal128,
        "Uuid" | "uuid" => Type::Uuid,
        other if other.starts_with("dyn ") => {
            Type::DynTrait(other.trim_start_matches("dyn ").trim().to_string())
        }
        other if other.starts_with("fn(") => return None,
        other if other.starts_with('(') && other.ends_with(')') => {
            let inside = &other[1..other.len() - 1];
            let parts = split_top_level_type_args(inside)?;
            let items = parts
                .into_iter()
                .map(parse_simple_type)
                .collect::<Option<Vec<_>>>()?;
            Type::Tuple(items)
        }
        other if other.starts_with("*mut ") => Type::Ptr {
            mutable: true,
            to: Box::new(parse_simple_type(other.trim_start_matches("*mut "))?),
        },
        other if other.starts_with('*') => Type::Ptr {
            mutable: false,
            to: Box::new(parse_simple_type(other.trim_start_matches('*'))?),
        },
        other if other.starts_with("&mut ") => Type::Ref {
            mutable: true,
            lifetime: None,
            to: Box::new(parse_simple_type(other.trim_start_matches("&mut "))?),
        },
        other if other.starts_with('&') => Type::Ref {
            mutable: false,
            lifetime: None,
            to: Box::new(parse_simple_type(other.trim_start_matches('&'))?),
        },
        other if other.starts_with("[]") => {
            Type::Slice(Box::new(parse_simple_type(other.trim_start_matches("[]"))?))
        }
        other if other.starts_with('[') && other.ends_with(']') && other.contains(';') => {
            let inside = &other[1..other.len() - 1];
            let (elem, len) = inside.split_once(';')?;
            let len = len.trim().parse::<usize>().ok()?;
            Type::Array {
                elem: Box::new(parse_simple_type(elem)?),
                len,
            }
        }
        other if other.ends_with('>') && other.contains('<') => {
            let start = other.find('<')?;
            let name = other[..start].trim();
            if name.is_empty() {
                return None;
            }
            let mut depth = 0usize;
            let mut end = None;
            for (idx, ch) in other.char_indices().skip(start) {
                match ch {
                    '<' => depth += 1,
                    '>' => {
                        if depth == 0 {
                            return None;
                        }
                        depth -= 1;
                        if depth == 0 {
                            end = Some(idx);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end?;
            if !other[end + 1..].trim().is_empty() {
                return None;
            }
            let inside = &other[start + 1..end];
            let args = split_top_level_type_args(inside)?
                .into_iter()
                .map(parse_simple_type)
                .collect::<Option<Vec<_>>>()?;
            match (name, args.as_slice()) {
                ("Map", [key, value]) => Type::Map {
                    key: Box::new(key.clone()),
                    value: Box::new(value.clone()),
                },
                ("Set", [inner]) => Type::Set(Box::new(inner.clone())),
                ("Deque", [inner]) => Type::Deque(Box::new(inner.clone())),
                ("Ring", [inner]) => Type::Ring(Box::new(inner.clone())),
                ("Vec", [inner]) => Type::Vec(Box::new(inner.clone())),
                ("Option", [inner]) => Type::Option(Box::new(inner.clone())),
                ("Future", [inner]) => Type::Future(Box::new(inner.clone())),
                ("Result", [ok, err]) => Type::Result {
                    ok: Box::new(ok.clone()),
                    err: Box::new(err.clone()),
                },
                _ => Type::Named {
                    name: name.to_string(),
                    args,
                },
            }
        }
        other if other.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_') => {
            Type::TypeVar(other.to_string())
        }
        other if !other.is_empty() => Type::Named {
            name: other.to_string(),
            args: Vec::new(),
        },
        _ => return None,
    })
}

pub(crate) type CallSignature = (Vec<Type>, Type, Vec<(String, Type)>);
const MAX_MONOMORPHIZATION_DEPTH: usize = 32;
const MAX_MONOMORPHIZED_SPECIALIZATIONS: usize = 2048;

pub(crate) fn monomorphized_symbol(base: &str, args: &[Type]) -> String {
    let rendered = args
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{base}<{rendered}>")
}

pub(crate) fn monomorphize_typed_functions(
    typed_functions: &mut Vec<TypedFunction>,
    generic_specializations: &mut BTreeSet<String>,
    type_errors: &mut usize,
    type_error_details: &mut Vec<String>,
) {
    let templates = typed_functions
        .iter()
        .filter(|function| !function.generics.is_empty())
        .map(|function| (function.name.clone(), function.clone()))
        .collect::<HashMap<_, _>>();
    if templates.is_empty() {
        return;
    }

    let mut rewrite = HashMap::<String, String>::new();
    let mut queue = VecDeque::<(String, Vec<Type>, usize)>::new();
    for function in typed_functions.iter_mut() {
        collect_and_rewrite_explicit_generic_calls(
            &templates,
            function,
            1,
            &mut queue,
            &mut rewrite,
        );
    }

    let mut generated = Vec::<TypedFunction>::new();
    let mut seen = BTreeSet::<String>::new();
    while let Some((base, args, depth)) = queue.pop_front() {
        if depth > MAX_MONOMORPHIZATION_DEPTH {
            record_type_error(
                type_errors,
                type_error_details,
                format!(
                    "monomorphization depth limit exceeded for `{}` at depth {} (max {})",
                    base, depth, MAX_MONOMORPHIZATION_DEPTH
                ),
            );
            continue;
        }
        let symbol = monomorphized_symbol(&base, &args);
        if !seen.insert(symbol.clone()) {
            continue;
        }
        if seen.len() > MAX_MONOMORPHIZED_SPECIALIZATIONS {
            record_type_error(
                type_errors,
                type_error_details,
                format!(
                    "monomorphization specialization limit exceeded (max {} symbols)",
                    MAX_MONOMORPHIZED_SPECIALIZATIONS
                ),
            );
            break;
        }
        let Some(template) = templates.get(&base) else {
            record_type_error(
                type_errors,
                type_error_details,
                format!("generic specialization references unknown function `{base}`"),
            );
            continue;
        };
        if template.generics.len() != args.len() {
            record_type_error(
                type_errors,
                type_error_details,
                format!(
                    "generic specialization arity mismatch for `{}`: expected {}, got {}",
                    base,
                    template.generics.len(),
                    args.len()
                ),
            );
            continue;
        }
        let bindings = template
            .generics
            .iter()
            .zip(args.iter())
            .map(|(generic, ty)| (generic.name.clone(), ty.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut specialized = template.clone();
        specialized.name = symbol.clone();
        specialized.generics.clear();
        for param in &mut specialized.params {
            param.ty = substitute_typevars(&param.ty, &bindings);
        }
        specialized.return_type = substitute_typevars(&specialized.return_type, &bindings);
        substitute_typevars_in_stmts(&mut specialized.body, &bindings);
        collect_and_rewrite_explicit_generic_calls(
            &templates,
            &mut specialized,
            depth.saturating_add(1),
            &mut queue,
            &mut rewrite,
        );
        rewrite.insert(symbol.clone(), symbol.clone());
        generated.push(specialized);
    }

    for function in typed_functions.iter_mut() {
        rewrite_generic_calls_in_stmts(&mut function.body, &rewrite);
    }
    typed_functions.retain(|function| function.generics.is_empty());
    typed_functions.extend(generated);
    generic_specializations.clear();
    generic_specializations.extend(seen);
}
