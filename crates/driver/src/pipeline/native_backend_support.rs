use super::*;

pub(super) fn native_lowerability_diagnostics(
    module: &ast::Module,
) -> Vec<diagnostics::Diagnostic> {
    let mut diagnostics = Vec::new();
    let passthrough_functions = collect_passthrough_function_map_from_module(module);
    let mut variant_keys = BTreeSet::<String>::new();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        for stmt in &function.body {
            collect_variant_keys_from_stmt(stmt, &mut variant_keys);
        }
    }
    let variant_tags = variant_keys
        .into_iter()
        .enumerate()
        .map(|(idx, key)| (key, idx as i32 + 1))
        .collect::<HashMap<_, _>>();
    diagnostics.extend(native_runtime_import_contract_errors().into_iter().map(|message| {
        diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            message,
            Some(
                "runtime shim imports are reserved for capability/host-effect boundaries; local data-plane paths must lower directly"
                    .to_string(),
            ),
        )
    }));
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        for param in &function.params {
            if !native_backend_supports_signature_type(&param.ty) {
                diagnostics.push(diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    format!(
                        "native backend does not support parameter type `{}` in function `{}`",
                        param.ty, function.name
                    ),
                    Some(
                        "native backend signatures support scalar widths, pointer-sized integers, floats, and pointer-like/aggregate handles"
                            .to_string(),
                    ),
                ));
            }
        }
        if !native_backend_supports_signature_type(&function.return_type) {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "native backend does not support return type `{}` in function `{}`",
                    function.return_type, function.name
                ),
                Some(
                    "native backend signatures support scalar widths, pointer-sized integers, floats, and pointer-like/aggregate handles"
                        .to_string(),
                ),
            ));
        }
        if let Err(error) =
            build_control_flow_cfg(&function.body, &variant_tags, &passthrough_functions)
        {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "native backend cannot lower pattern/control-flow semantics in function `{}`: {}",
                    function.name, error
                ),
                Some(
                    "rewrite unsupported pattern guard shapes or non-lowerable control-flow forms to explicit statements"
                        .to_string(),
                ),
            ));
        }
    }

    let defined_functions = collect_defined_function_names(module);
    let mut unresolved = HashSet::<String>::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            let mut local_callables = HashSet::<String>::new();
            collect_local_callable_bindings(&function.body, &mut local_callables);
            for stmt in &function.body {
                collect_unresolved_calls_from_stmt(
                    stmt,
                    &defined_functions,
                    &local_callables,
                    &mut unresolved,
                );
            }
        }
    }
    let mut unresolved = unresolved.into_iter().collect::<Vec<_>>();
    unresolved.sort();
    diagnostics.extend(unresolved.into_iter().map(|callee| {
        let nearest = hir::runtime_intrinsic_names()
            .iter()
            .map(|candidate| {
                (
                    *candidate,
                    candidate
                        .chars()
                        .zip(callee.chars())
                        .filter(|(left, right)| left != right)
                        .count()
                        + candidate.len().abs_diff(callee.len()),
                )
            })
            .min_by_key(|(_, distance)| *distance)
            .and_then(|(candidate, distance)| (distance <= 6).then_some(candidate));
        let mut help =
            "run via Fozzy scenario/host backends or provide a real native implementation for this symbol"
                .to_string();
        if let Some(suggested) = nearest {
            help.push_str(&format!("; did you mean `{suggested}`?"));
        }
        diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            format!("native backend cannot execute unresolved call `{callee}`"),
            Some(help),
        )
    }));

    diagnostics::assign_stable_codes(
        &mut diagnostics,
        diagnostics::DiagnosticDomain::NativeLowering,
    );
    diagnostics
}

pub(super) fn experimental_feature_diagnostics(
    _module: &ast::Module,
    manifest: Option<&manifest::Manifest>,
) -> Vec<diagnostics::Diagnostic> {
    let tier = manifest
        .map(|value| value.language.tier.as_str())
        .unwrap_or("core_v1");
    let allow_experimental = manifest
        .map(|value| value.language.allow_experimental)
        .unwrap_or(false);
    if tier == "experimental" && allow_experimental {
        return Vec::new();
    }

    let mut diagnostics = Vec::new();
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Verifier);
    diagnostics
}

pub(super) fn backend_capability_diagnostics(
    module: &ast::Module,
    backend: &str,
    for_library: bool,
) -> Vec<diagnostics::Diagnostic> {
    let mut diagnostics = Vec::new();
    let backend = backend.trim().to_ascii_lowercase();
    if backend == "cranelift" {
        for item in &module.items {
            let ast::Item::Function(function) = item else {
                continue;
            };
            if !for_library
                && function.is_pubext
                && function.is_async
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
            {
                diagnostics.push(
                    diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        format!(
                            "backend `cranelift` does not support async C export `{}`",
                            function.name
                        ),
                        Some(
                            "compile with `--backend llvm` or remove async C export surface"
                                .to_string(),
                        ),
                    )
                    .with_fix("switch backend: `fz build <path> --backend llvm`"),
                );
            }
            if function.is_async && function.is_unsafe {
                diagnostics.push(
                    diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        format!(
                            "backend `cranelift` rejects async+unsafe function `{}`",
                            function.name
                        ),
                        Some(
                            "use backend llvm for this code shape or refactor unsafe code outside async path"
                                .to_string(),
                        ),
                    )
                    .with_fix("switch backend: `fz build <path> --backend llvm`"),
                );
            }
        }
    }
    diagnostics
}

pub(super) fn native_backend_supports_signature_type(ty: &ast::Type) -> bool {
    ast_signature_type_to_clif_type(ty).is_some()
        || matches!(ty, ast::Type::Void | ast::Type::Never)
}

pub(super) fn collect_unresolved_calls_from_stmt(
    stmt: &ast::Stmt,
    defined_functions: &HashSet<String>,
    local_callables: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_unresolved_calls_from_expr(
            value,
            defined_functions,
            local_callables,
            unresolved,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in then_body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            for nested in else_body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
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
                collect_unresolved_calls_from_stmt(
                    init,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            if let Some(condition) = condition {
                collect_unresolved_calls_from_expr(
                    condition,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            if let Some(step) = step {
                collect_unresolved_calls_from_stmt(
                    step,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_unresolved_calls_from_expr(
                iterable,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_unresolved_calls_from_expr(
                scrutinee,
                defined_functions,
                local_callables,
                unresolved,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unresolved_calls_from_expr(
                        guard,
                        defined_functions,
                        local_callables,
                        unresolved,
                    );
                }
                collect_unresolved_calls_from_expr(
                    &arm.value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
    }
}

fn collect_unresolved_calls_from_expr(
    expr: &ast::Expr,
    defined_functions: &HashSet<String>,
    local_callables: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let (base_callee, _) = split_generic_suffix(callee);
            if !defined_functions.contains(callee)
                && !defined_functions.contains(base_callee)
                && !local_callables.contains(callee)
                && !local_callables.contains(base_callee)
                && !native_backend_supports_call(callee)
                && !native_backend_supports_call(base_callee)
            {
                unresolved.insert(callee.clone());
            }
            for arg in args {
                collect_unresolved_calls_from_expr(
                    arg,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_unresolved_calls_from_stmt(
                    stmt,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_unresolved_calls_from_expr(base, defined_functions, local_callables, unresolved);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_unresolved_calls_from_expr(body, defined_functions, local_callables, unresolved);
        }
        ast::Expr::Group(inner) => {
            collect_unresolved_calls_from_expr(inner, defined_functions, local_callables, unresolved);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_unresolved_calls_from_expr(inner, defined_functions, local_callables, unresolved);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_unresolved_calls_from_expr(expr, defined_functions, local_callables, unresolved);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_unresolved_calls_from_expr(
                try_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                catch_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                then_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                else_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_unresolved_calls_from_expr(
                left,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                right,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Range { start, end, .. } => {
            collect_unresolved_calls_from_expr(
                start,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(end, defined_functions, local_callables, unresolved);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_unresolved_calls_from_expr(
                    item,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            collect_unresolved_calls_from_expr(
                base,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                index,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

pub(super) fn collect_local_callable_bindings(body: &[ast::Stmt], out: &mut HashSet<String>) {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                if matches!(value, ast::Expr::Closure { .. }) {
                    out.insert(name.clone());
                }
                collect_local_callable_bindings_from_expr(value, out);
            }
            ast::Stmt::Assign { target, value } => {
                if matches!(value, ast::Expr::Closure { .. }) {
                    out.insert(target.clone());
                }
                collect_local_callable_bindings_from_expr(value, out);
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => collect_local_callable_bindings_from_expr(value, out),
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    collect_local_callable_bindings_from_expr(value, out);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_local_callable_bindings_from_expr(condition, out);
                collect_local_callable_bindings(then_body, out);
                collect_local_callable_bindings(else_body, out);
            }
            ast::Stmt::While { condition, body } => {
                collect_local_callable_bindings_from_expr(condition, out);
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_local_callable_bindings(std::slice::from_ref(init.as_ref()), out);
                }
                if let Some(condition) = condition {
                    collect_local_callable_bindings_from_expr(condition, out);
                }
                if let Some(step) = step {
                    collect_local_callable_bindings(std::slice::from_ref(step.as_ref()), out);
                }
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                collect_local_callable_bindings_from_expr(iterable, out);
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::Loop { body } => collect_local_callable_bindings(body, out),
            ast::Stmt::Match { scrutinee, arms } => {
                collect_local_callable_bindings_from_expr(scrutinee, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_local_callable_bindings_from_expr(guard, out);
                    }
                    collect_local_callable_bindings_from_expr(&arm.value, out);
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }
}

fn collect_local_callable_bindings_from_expr(expr: &ast::Expr, out: &mut HashSet<String>) {
    match expr {
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_local_callable_bindings_from_expr(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            collect_local_callable_bindings(body, out);
        }
        ast::Expr::FieldAccess { base, .. } => collect_local_callable_bindings_from_expr(base, out),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_local_callable_bindings_from_expr(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_local_callable_bindings_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_local_callable_bindings_from_expr(body, out),
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_local_callable_bindings_from_expr(inner, out)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_local_callable_bindings_from_expr(try_expr, out);
            collect_local_callable_bindings_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_local_callable_bindings_from_expr(condition, out);
            collect_local_callable_bindings_from_expr(then_expr, out);
            collect_local_callable_bindings_from_expr(else_expr, out);
        }
        ast::Expr::Unary { expr, .. } => collect_local_callable_bindings_from_expr(expr, out),
        ast::Expr::Binary { left, right, .. } => {
            collect_local_callable_bindings_from_expr(left, out);
            collect_local_callable_bindings_from_expr(right, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_local_callable_bindings_from_expr(start, out);
            collect_local_callable_bindings_from_expr(end, out);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_local_callable_bindings_from_expr(item, out);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_local_callable_bindings_from_expr(base, out);
            collect_local_callable_bindings_from_expr(index, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

pub(super) fn native_backend_supports_call(callee: &str) -> bool {
    native_runtime_import_for_callee(callee).is_some()
        || native_data_plane_import_for_callee(callee).is_some()
}

pub(super) fn declare_native_runtime_imports(
    module: &mut ObjectModule,
    function_ids: &mut HashMap<String, cranelift_module::FuncId>,
    function_signatures: &mut HashMap<String, ClifFunctionSignature>,
) -> Result<()> {
    for import in NATIVE_RUNTIME_IMPORTS {
        if function_ids.contains_key(import.callee) {
            continue;
        }
        let mut sig = module.make_signature();
        for _ in 0..import.arity {
            sig.params.push(AbiParam::new(types::I32));
        }
        sig.returns.push(AbiParam::new(types::I32));
        let id = module
            .declare_function(import.symbol, Linkage::Import, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring native runtime import `{}` for `{}`: {error}",
                    import.symbol,
                    import.callee
                )
            })?;
        function_ids.insert(import.callee.to_string(), id);
        function_signatures.insert(
            import.callee.to_string(),
            ClifFunctionSignature {
                params: (0..import.arity).map(|_| types::I32).collect(),
                ret: Some(types::I32),
            },
        );
    }
    Ok(())
}

pub(super) fn declare_native_data_plane_imports(
    module: &mut ObjectModule,
    function_ids: &mut HashMap<String, cranelift_module::FuncId>,
    function_signatures: &mut HashMap<String, ClifFunctionSignature>,
) -> Result<()> {
    for import in NATIVE_DATA_PLANE_IMPORTS {
        if function_ids.contains_key(import.callee) {
            continue;
        }
        let mut sig = module.make_signature();
        for _ in 0..import.arity {
            sig.params.push(AbiParam::new(types::I32));
        }
        sig.returns.push(AbiParam::new(types::I32));
        let id = module
            .declare_function(import.symbol, Linkage::Import, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring native data-plane import `{}` for `{}`: {error}",
                    import.symbol,
                    import.callee
                )
            })?;
        function_ids.insert(import.callee.to_string(), id);
        function_signatures.insert(
            import.callee.to_string(),
            ClifFunctionSignature {
                params: (0..import.arity).map(|_| types::I32).collect(),
                ret: Some(types::I32),
            },
        );
    }
    Ok(())
}
