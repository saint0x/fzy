fn analyze_live_borrow_consumption(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    let signatures = functions
        .iter()
        .map(|function| (function.name.as_str(), function))
        .collect::<FunctionSignatures<'_>>();
    let ownership_summaries = build_function_ownership_summaries(functions);
    for function in functions {
        let mut bindings = CowBindings::<BorrowBinding>::default();
        analyze_live_borrow_block(
            function,
            &function.body,
            &[],
            &mut bindings,
            &signatures,
            &ownership_summaries,
            &mut violations,
        );
    }
    violations
}

fn analyze_gpu_kernel_contracts(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    let signatures = functions
        .iter()
        .map(|function| (function.name.clone(), function.clone()))
        .collect::<BTreeMap<_, _>>();
    let slice_access = build_gpu_slice_access_summaries(functions, &signatures);
    let barrier_summary = build_gpu_barrier_summary(functions);
    violations.extend(validate_gpu_kernel_launch_abi(functions));
    for function in functions {
        let mut bindings = BTreeMap::<String, BorrowBinding>::new();
        for param in &function.params {
            if matches!(&param.ty, Type::Named { name, args } if name == "GpuSlice" && args.len() == 1)
            {
                bindings.insert(
                    param.name.clone(),
                    BorrowBinding {
                        owner: param.name.clone(),
                        mutable: true,
                    },
                );
            }
        }
        analyze_gpu_kernel_contract_block(
            function,
            &function.body,
            &mut bindings,
            &signatures,
            &slice_access,
            &barrier_summary,
            0,
            &mut violations,
        );
    }
    violations
}

fn analyze_gpu_kernel_contract_block(
    function: &TypedFunction,
    body: &[Stmt],
    bindings: &mut BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
    slice_access: &BTreeMap<String, BTreeMap<String, GpuSliceAccessMode>>,
    barrier_summary: &BTreeMap<String, bool>,
    divergent_depth: usize,
    violations: &mut Vec<String>,
) {
    for stmt in body {
        match stmt {
            Stmt::Let {
                name, value, ty, ..
            } => {
                analyze_gpu_kernel_contract_expr(
                    function,
                    value,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
                let explicit_ty = ty
                    .as_ref()
                    .or_else(|| function.local_types.get(name))
                    .or_else(|| {
                        function
                            .params
                            .iter()
                            .find(|param| param.name == *name)
                            .map(|param| &param.ty)
                    });
                if let Some(binding) =
                    infer_borrow_binding_from_expr_owned(value, explicit_ty, bindings, signatures)
                {
                    bindings.insert(name.clone(), binding);
                } else {
                    bindings.remove(name);
                }
            }
            Stmt::Assign { target, value } => {
                analyze_gpu_kernel_contract_expr(
                    function,
                    value,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
                let explicit_ty = function.local_types.get(target).or_else(|| {
                    function
                        .params
                        .iter()
                        .find(|param| param.name == *target)
                        .map(|param| &param.ty)
                });
                if let Some(binding) =
                    infer_borrow_binding_from_expr_owned(value, explicit_ty, bindings, signatures)
                {
                    bindings.insert(target.clone(), binding);
                } else {
                    bindings.remove(target);
                }
            }
            Stmt::CompoundAssign { value, .. }
            | Stmt::Return(Some(value))
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value)
            | Stmt::Expr(value) => {
                analyze_gpu_kernel_contract_expr(
                    function,
                    value,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                analyze_gpu_kernel_contract_expr(
                    function,
                    condition,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
                let mut then_bindings = bindings.clone();
                analyze_gpu_kernel_contract_block(
                    function,
                    then_body,
                    &mut then_bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
                let mut else_bindings = bindings.clone();
                analyze_gpu_kernel_contract_block(
                    function,
                    else_body,
                    &mut else_bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
            }
            Stmt::While { condition, body } => {
                analyze_gpu_kernel_contract_expr(
                    function,
                    condition,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
                let mut loop_bindings = bindings.clone();
                analyze_gpu_kernel_contract_block(
                    function,
                    body,
                    &mut loop_bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
            }
            Stmt::Loop { body } => {
                let mut loop_bindings = bindings.clone();
                analyze_gpu_kernel_contract_block(
                    function,
                    body,
                    &mut loop_bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
            }
            Stmt::ForIn { iterable, body, .. } => {
                analyze_gpu_kernel_contract_expr(
                    function,
                    iterable,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
                let mut loop_bindings = bindings.clone();
                analyze_gpu_kernel_contract_block(
                    function,
                    body,
                    &mut loop_bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    analyze_gpu_kernel_contract_block(
                        function,
                        std::slice::from_ref(init.as_ref()),
                        bindings,
                        signatures,
                        slice_access,
                        barrier_summary,
                        divergent_depth,
                        violations,
                    );
                }
                if let Some(condition) = condition {
                    analyze_gpu_kernel_contract_expr(
                        function,
                        condition,
                        bindings,
                        signatures,
                        slice_access,
                        barrier_summary,
                        divergent_depth,
                        violations,
                    );
                }
                let mut loop_bindings = bindings.clone();
                analyze_gpu_kernel_contract_block(
                    function,
                    body,
                    &mut loop_bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
                if let Some(step) = step {
                    analyze_gpu_kernel_contract_block(
                        function,
                        std::slice::from_ref(step.as_ref()),
                        bindings,
                        signatures,
                        slice_access,
                        barrier_summary,
                        divergent_depth + 1,
                        violations,
                    );
                }
            }
            Stmt::Match { scrutinee, arms } => {
                analyze_gpu_kernel_contract_expr(
                    function,
                    scrutinee,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
                for arm in arms {
                    let mut arm_bindings = bindings.clone();
                    if let Some(guard) = &arm.guard {
                        analyze_gpu_kernel_contract_expr(
                            function,
                            guard,
                            &mut arm_bindings,
                            signatures,
                            slice_access,
                            barrier_summary,
                            divergent_depth + 1,
                            violations,
                        );
                    }
                    analyze_gpu_kernel_contract_expr(
                        function,
                        &arm.value,
                        &mut arm_bindings,
                        signatures,
                        slice_access,
                        barrier_summary,
                        divergent_depth + 1,
                        violations,
                    );
                }
            }
            Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue | Stmt::LetPattern { .. } => {}
        }
    }
}

fn validate_gpu_kernel_launch_abi(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        if function.execution_space != ast::ExecutionSpace::Kernel {
            continue;
        }
        for param in &function.params {
            if !is_supported_gpu_launch_abi_type(&param.ty) {
                violations.push(format!(
                    "kernel function `{}` parameter `{}` uses type `{}` that is not yet supported by the stable GPU launch ABI",
                    function.name, param.name, param.ty
                ));
            }
        }
    }
    violations
}

fn is_supported_gpu_launch_abi_type(ty: &Type) -> bool {
    match ty {
        Type::Int {
            signed: true,
            bits: 32,
        }
        | Type::Int {
            signed: false,
            bits: 32,
        }
        | Type::Float { bits: 32 } => true,
        Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => matches!(
            &args[0],
            Type::Float { bits: 32 }
                | Type::Int {
                    signed: true,
                    bits: 32
                }
                | Type::Int {
                    signed: false,
                    bits: 32
                }
        ),
        _ => false,
    }
}

fn analyze_gpu_kernel_contract_expr(
    function: &TypedFunction,
    expr: &Expr,
    bindings: &mut BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
    slice_access: &BTreeMap<String, BTreeMap<String, GpuSliceAccessMode>>,
    barrier_summary: &BTreeMap<String, bool>,
    divergent_depth: usize,
    violations: &mut Vec<String>,
) {
    match expr {
        Expr::Call { callee, args } => {
            if divergent_depth > 0
                && matches!(
                    function.execution_space,
                    ast::ExecutionSpace::Device | ast::ExecutionSpace::Kernel
                )
            {
                if callee == "gpu.barrier" {
                    violations.push(format!(
                        "{} function `{}` cannot use `gpu.barrier` inside divergent control flow",
                        execution_space_label(function.execution_space),
                        function.name
                    ));
                } else if barrier_summary.get(callee).copied().unwrap_or(false) {
                    violations.push(format!(
                        "{} function `{}` cannot call barrier-carrying function `{}` inside divergent control flow",
                        execution_space_label(function.execution_space),
                        function.name,
                        callee
                    ));
                }
            }
            if is_gpu_launch_callee(callee) {
                analyze_gpu_launch_aliases(
                    function,
                    callee,
                    args,
                    bindings,
                    signatures,
                    slice_access,
                    violations,
                );
            }
            for arg in args {
                analyze_gpu_kernel_contract_expr(
                    function,
                    arg,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
            }
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            analyze_gpu_kernel_contract_expr(
                function,
                condition,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            analyze_gpu_kernel_contract_expr(
                function,
                then_expr,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth + 1,
                violations,
            );
            analyze_gpu_kernel_contract_expr(
                function,
                else_expr,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth + 1,
                violations,
            );
        }
        Expr::Discard(inner) => analyze_gpu_kernel_contract_expr(
            function,
            inner,
            bindings,
            signatures,
            slice_access,
            barrier_summary,
            divergent_depth,
            violations,
        ),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            analyze_gpu_kernel_contract_expr(
                function,
                try_expr,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            analyze_gpu_kernel_contract_expr(
                function,
                catch_expr,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth + 1,
                violations,
            );
        }
        Expr::Match { scrutinee, arms } => {
            analyze_gpu_kernel_contract_expr(
                function,
                scrutinee,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    analyze_gpu_kernel_contract_expr(
                        function,
                        guard,
                        bindings,
                        signatures,
                        slice_access,
                        barrier_summary,
                        divergent_depth + 1,
                        violations,
                    );
                }
                analyze_gpu_kernel_contract_expr(
                    function,
                    &arm.value,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            analyze_gpu_kernel_contract_block(
                function,
                body,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
        }
        Expr::While { condition, body } => {
            analyze_gpu_kernel_contract_expr(
                function,
                condition,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            let mut loop_bindings = bindings.clone();
            analyze_gpu_kernel_contract_block(
                function,
                body,
                &mut loop_bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth + 1,
                violations,
            );
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                analyze_gpu_kernel_contract_block(
                    function,
                    std::slice::from_ref(init.as_ref()),
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
            }
            if let Some(condition) = condition {
                analyze_gpu_kernel_contract_expr(
                    function,
                    condition,
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth,
                    violations,
                );
            }
            let mut loop_bindings = bindings.clone();
            analyze_gpu_kernel_contract_block(
                function,
                body,
                &mut loop_bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth + 1,
                violations,
            );
            if let Some(step) = step {
                analyze_gpu_kernel_contract_block(
                    function,
                    std::slice::from_ref(step.as_ref()),
                    bindings,
                    signatures,
                    slice_access,
                    barrier_summary,
                    divergent_depth + 1,
                    violations,
                );
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            analyze_gpu_kernel_contract_expr(
                function,
                iterable,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            let mut loop_bindings = bindings.clone();
            analyze_gpu_kernel_contract_block(
                function,
                body,
                &mut loop_bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth + 1,
                violations,
            );
        }
        Expr::Loop { body } => {
            let mut loop_bindings = bindings.clone();
            analyze_gpu_kernel_contract_block(
                function,
                body,
                &mut loop_bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth + 1,
                violations,
            );
        }
        Expr::FieldAccess { base, .. } | Expr::Group(base) => analyze_gpu_kernel_contract_expr(
            function,
            base,
            bindings,
            signatures,
            slice_access,
            barrier_summary,
            divergent_depth,
            violations,
        ),
        Expr::Index { base, index } => {
            analyze_gpu_kernel_contract_expr(
                function,
                base,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            analyze_gpu_kernel_contract_expr(
                function,
                index,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
        }
        Expr::Unary { expr, .. } => analyze_gpu_kernel_contract_expr(
            function,
            expr,
            bindings,
            signatures,
            slice_access,
            barrier_summary,
            divergent_depth,
            violations,
        ),
        Expr::Binary { left, right, .. } => {
            analyze_gpu_kernel_contract_expr(
                function,
                left,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            analyze_gpu_kernel_contract_expr(
                function,
                right,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
        }
        Expr::Await(inner) | Expr::Return(Some(inner)) => analyze_gpu_kernel_contract_expr(
            function,
            inner,
            bindings,
            signatures,
            slice_access,
            barrier_summary,
            divergent_depth,
            violations,
        ),
        Expr::Range { start, end, .. } => {
            analyze_gpu_kernel_contract_expr(
                function,
                start,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
            analyze_gpu_kernel_contract_expr(
                function,
                end,
                bindings,
                signatures,
                slice_access,
                barrier_summary,
                divergent_depth,
                violations,
            );
        }
        Expr::Return(None)
        | Expr::Ident(_)
        | Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Char(_)
        | Expr::Break(_)
        | Expr::Continue
        | Expr::Closure { .. }
        | Expr::ArrayLiteral(_)
        | Expr::Tuple(_)
        | Expr::StructInit { .. }
        | Expr::EnumInit { .. }
        | Expr::ObjectLiteral(_) => {}
    }
}

fn is_gpu_launch_callee(callee: &str) -> bool {
    matches!(
        callee,
        "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4"
    )
}

fn gpu_base_callee(callee: &str) -> &str {
    callee.split('<').next().unwrap_or(callee)
}

fn analyze_gpu_launch_aliases(
    function: &TypedFunction,
    callee: &str,
    args: &[Expr],
    bindings: &BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
    slice_access: &BTreeMap<String, BTreeMap<String, GpuSliceAccessMode>>,
    violations: &mut Vec<String>,
) {
    let Some(Expr::Ident(kernel_name)) = args.first() else {
        return;
    };
    let Some(kernel) = signatures.get(kernel_name) else {
        return;
    };
    if kernel.execution_space != ast::ExecutionSpace::Kernel {
        return;
    }
    let mut seen = BTreeMap::<String, String>::new();
    let access_summary = slice_access.get(&kernel.name);
    for (index, param) in kernel.params.iter().enumerate() {
        let Some(arg) = args.get(index + 3) else {
            continue;
        };
        let Type::Named {
            name,
            args: named_args,
        } = &param.ty
        else {
            continue;
        };
        if name != "GpuSlice" || named_args.len() != 1 {
            continue;
        }
        let Some(owner) = infer_gpu_slice_owner_name(arg, bindings, signatures) else {
            continue;
        };
        if let Some(previous_param) = seen.insert(owner.clone(), param.name.clone()) {
            let current_mode = access_summary
                .and_then(|summary| summary.get(&param.name))
                .copied()
                .unwrap_or(GpuSliceAccessMode::ReadWrite);
            let previous_mode = access_summary
                .and_then(|summary| summary.get(&previous_param))
                .copied()
                .unwrap_or(GpuSliceAccessMode::ReadWrite);
            if current_mode.is_read_only_like() && previous_mode.is_read_only_like() {
                continue;
            }
            violations.push(format!(
                "host function `{}` launch `{}` via `{}` aliases GpuSlice parameters `{}` and `{}` through owner `{}`",
                function.name,
                kernel.name,
                callee,
                previous_param,
                param.name,
                owner
            ));
        }
    }
}

fn build_gpu_slice_access_summaries(
    functions: &[TypedFunction],
    signatures: &BTreeMap<String, TypedFunction>,
) -> BTreeMap<String, BTreeMap<String, GpuSliceAccessMode>> {
    let mut summaries = functions
        .iter()
        .map(|function| {
            (
                function.name.clone(),
                function
                    .params
                    .iter()
                    .filter(|param| matches!(&param.ty, Type::Named { name, args } if name == "GpuSlice" && args.len() == 1))
                    .map(|param| (param.name.clone(), GpuSliceAccessMode::Observe))
                    .collect::<BTreeMap<_, _>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    loop {
        let snapshot = summaries.clone();
        let mut changed = false;
        for function in functions {
            let mut bindings = function
                .params
                .iter()
                .filter(|param| matches!(&param.ty, Type::Named { name, args } if name == "GpuSlice" && args.len() == 1))
                .map(|param| {
                    (
                        param.name.clone(),
                        BorrowBinding {
                            owner: param.name.clone(),
                            mutable: true,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut updates = BTreeMap::<String, GpuSliceAccessMode>::new();
            collect_gpu_stmt_slice_access(
                function,
                &function.body,
                &mut bindings,
                signatures,
                &snapshot,
                &mut updates,
            );
            let summary = summaries.entry(function.name.clone()).or_default();
            for (param, mode) in updates {
                let entry = summary.entry(param).or_insert(GpuSliceAccessMode::Observe);
                if *entry != mode {
                    *entry = mode;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    summaries
}

fn collect_gpu_stmt_slice_access(
    function: &TypedFunction,
    body: &[Stmt],
    bindings: &mut BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
    summaries: &BTreeMap<String, BTreeMap<String, GpuSliceAccessMode>>,
    out: &mut BTreeMap<String, GpuSliceAccessMode>,
) {
    for stmt in body {
        match stmt {
            Stmt::Let {
                name, value, ty, ..
            } => {
                collect_gpu_expr_slice_access(
                    function, value, bindings, signatures, summaries, out,
                );
                let explicit_ty = ty
                    .as_ref()
                    .or_else(|| function.local_types.get(name))
                    .or_else(|| {
                        function
                            .params
                            .iter()
                            .find(|param| param.name == *name)
                            .map(|param| &param.ty)
                    });
                if let Some(binding) =
                    infer_borrow_binding_from_expr_owned(value, explicit_ty, bindings, signatures)
                {
                    bindings.insert(name.clone(), binding);
                } else {
                    bindings.remove(name);
                }
            }
            Stmt::Assign { target, value } => {
                collect_gpu_expr_slice_access(
                    function, value, bindings, signatures, summaries, out,
                );
                let explicit_ty = function.local_types.get(target).or_else(|| {
                    function
                        .params
                        .iter()
                        .find(|param| param.name == *target)
                        .map(|param| &param.ty)
                });
                if let Some(binding) =
                    infer_borrow_binding_from_expr_owned(value, explicit_ty, bindings, signatures)
                {
                    bindings.insert(target.clone(), binding);
                } else {
                    bindings.remove(target);
                }
            }
            Stmt::CompoundAssign { value, .. }
            | Stmt::Expr(value)
            | Stmt::Return(Some(value))
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value) => {
                collect_gpu_expr_slice_access(
                    function, value, bindings, signatures, summaries, out,
                );
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_gpu_expr_slice_access(
                    function, condition, bindings, signatures, summaries, out,
                );
                collect_gpu_stmt_slice_access(
                    function,
                    then_body,
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
                collect_gpu_stmt_slice_access(
                    function,
                    else_body,
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
            }
            Stmt::While { condition, body } => {
                collect_gpu_expr_slice_access(
                    function, condition, bindings, signatures, summaries, out,
                );
                collect_gpu_stmt_slice_access(
                    function,
                    body,
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
            }
            Stmt::Loop { body } => {
                collect_gpu_stmt_slice_access(
                    function,
                    body,
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_gpu_stmt_slice_access(
                        function,
                        std::slice::from_ref(init.as_ref()),
                        bindings,
                        signatures,
                        summaries,
                        out,
                    );
                }
                if let Some(condition) = condition {
                    collect_gpu_expr_slice_access(
                        function, condition, bindings, signatures, summaries, out,
                    );
                }
                collect_gpu_stmt_slice_access(
                    function,
                    body,
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
                if let Some(step) = step {
                    collect_gpu_stmt_slice_access(
                        function,
                        std::slice::from_ref(step.as_ref()),
                        bindings,
                        signatures,
                        summaries,
                        out,
                    );
                }
            }
            Stmt::ForIn { iterable, body, .. } => {
                collect_gpu_expr_slice_access(
                    function, iterable, bindings, signatures, summaries, out,
                );
                collect_gpu_stmt_slice_access(
                    function,
                    body,
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
            }
            Stmt::Match { scrutinee, arms } => {
                collect_gpu_expr_slice_access(
                    function, scrutinee, bindings, signatures, summaries, out,
                );
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_gpu_expr_slice_access(
                            function, guard, bindings, signatures, summaries, out,
                        );
                    }
                    collect_gpu_expr_slice_access(
                        function, &arm.value, bindings, signatures, summaries, out,
                    );
                }
            }
            Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue | Stmt::LetPattern { .. } => {}
        }
    }
}

fn collect_gpu_expr_slice_access(
    function: &TypedFunction,
    expr: &Expr,
    bindings: &BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
    summaries: &BTreeMap<String, BTreeMap<String, GpuSliceAccessMode>>,
    out: &mut BTreeMap<String, GpuSliceAccessMode>,
) {
    match expr {
        Expr::Index { base, index } => {
            mark_gpu_slice_read(base, bindings, signatures, out);
            collect_gpu_expr_slice_access(function, index, bindings, signatures, summaries, out);
        }
        Expr::Call { callee, args } if gpu_base_callee(callee) == "__index_assign" => {
            if let Some(base) = args.first() {
                mark_gpu_slice_write(base, bindings, signatures, out);
            }
            for arg in args.iter().skip(1) {
                collect_gpu_expr_slice_access(function, arg, bindings, signatures, summaries, out);
            }
        }
        Expr::Call { callee, args } => {
            let callee = gpu_base_callee(callee);
            match callee {
                "gpu.load_f32" | "gpu.load_i32" | "gpu.load_u32" => {
                    if let Some(base) = args.first() {
                        mark_gpu_slice_read(base, bindings, signatures, out);
                    }
                }
                "gpu.store_f32" | "gpu.store_i32" | "gpu.store_u32" => {
                    if let Some(base) = args.first() {
                        mark_gpu_slice_write(base, bindings, signatures, out);
                    }
                }
                _ => {}
            }
            if let (Some(callee_fn), Some(summary)) =
                (signatures.get(callee), summaries.get(callee))
            {
                for (index, arg) in args.iter().enumerate() {
                    if let Some(param) = callee_fn.params.get(index) {
                        if let Some(mode) = summary.get(&param.name).copied() {
                            match mode {
                                GpuSliceAccessMode::Observe => {}
                                GpuSliceAccessMode::ReadOnly => {
                                    mark_gpu_slice_read(arg, bindings, signatures, out)
                                }
                                GpuSliceAccessMode::WriteOnly => {
                                    mark_gpu_slice_write(arg, bindings, signatures, out)
                                }
                                GpuSliceAccessMode::ReadWrite => {
                                    mark_gpu_slice_read(arg, bindings, signatures, out);
                                    mark_gpu_slice_write(arg, bindings, signatures, out);
                                }
                            }
                        }
                    }
                    collect_gpu_expr_slice_access(
                        function, arg, bindings, signatures, summaries, out,
                    );
                }
            } else {
                for arg in args {
                    collect_gpu_expr_slice_access(
                        function, arg, bindings, signatures, summaries, out,
                    );
                }
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            collect_gpu_stmt_slice_access(
                function,
                body,
                &mut bindings.clone(),
                signatures,
                summaries,
                out,
            );
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_gpu_expr_slice_access(
                function, condition, bindings, signatures, summaries, out,
            );
            collect_gpu_expr_slice_access(
                function, then_expr, bindings, signatures, summaries, out,
            );
            collect_gpu_expr_slice_access(
                function, else_expr, bindings, signatures, summaries, out,
            );
        }
        Expr::Match { scrutinee, arms } => {
            collect_gpu_expr_slice_access(
                function, scrutinee, bindings, signatures, summaries, out,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_gpu_expr_slice_access(
                        function, guard, bindings, signatures, summaries, out,
                    );
                }
                collect_gpu_expr_slice_access(
                    function, &arm.value, bindings, signatures, summaries, out,
                );
            }
        }
        Expr::While { condition, body } => {
            collect_gpu_expr_slice_access(
                function, condition, bindings, signatures, summaries, out,
            );
            collect_gpu_stmt_slice_access(
                function,
                body,
                &mut bindings.clone(),
                signatures,
                summaries,
                out,
            );
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_gpu_stmt_slice_access(
                    function,
                    std::slice::from_ref(init.as_ref()),
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
            }
            if let Some(condition) = condition {
                collect_gpu_expr_slice_access(
                    function, condition, bindings, signatures, summaries, out,
                );
            }
            collect_gpu_stmt_slice_access(
                function,
                body,
                &mut bindings.clone(),
                signatures,
                summaries,
                out,
            );
            if let Some(step) = step {
                collect_gpu_stmt_slice_access(
                    function,
                    std::slice::from_ref(step.as_ref()),
                    &mut bindings.clone(),
                    signatures,
                    summaries,
                    out,
                );
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            collect_gpu_expr_slice_access(function, iterable, bindings, signatures, summaries, out);
            collect_gpu_stmt_slice_access(
                function,
                body,
                &mut bindings.clone(),
                signatures,
                summaries,
                out,
            );
        }
        Expr::Loop { body } => {
            collect_gpu_stmt_slice_access(
                function,
                body,
                &mut bindings.clone(),
                signatures,
                summaries,
                out,
            );
        }
        Expr::Group(inner)
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Unary { expr: inner, .. }
        | Expr::Await(inner)
        | Expr::Discard(inner)
        | Expr::Return(Some(inner)) => {
            collect_gpu_expr_slice_access(function, inner, bindings, signatures, summaries, out)
        }
        Expr::Binary { left, right, .. } => {
            collect_gpu_expr_slice_access(function, left, bindings, signatures, summaries, out);
            collect_gpu_expr_slice_access(function, right, bindings, signatures, summaries, out);
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_gpu_expr_slice_access(function, try_expr, bindings, signatures, summaries, out);
            collect_gpu_expr_slice_access(
                function, catch_expr, bindings, signatures, summaries, out,
            );
        }
        Expr::Range { start, end, .. } => {
            collect_gpu_expr_slice_access(function, start, bindings, signatures, summaries, out);
            collect_gpu_expr_slice_access(function, end, bindings, signatures, summaries, out);
        }
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_gpu_expr_slice_access(
                    function, value, bindings, signatures, summaries, out,
                );
            }
        }
        Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_gpu_expr_slice_access(
                    function, value, bindings, signatures, summaries, out,
                );
            }
            for (_, value) in named_payload {
                collect_gpu_expr_slice_access(
                    function, value, bindings, signatures, summaries, out,
                );
            }
        }
        Expr::ArrayLiteral(values) | Expr::Tuple(values) => {
            for value in values {
                collect_gpu_expr_slice_access(
                    function, value, bindings, signatures, summaries, out,
                );
            }
        }
        Expr::Closure { .. }
        | Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Bool(_)
        | Expr::Char(_)
        | Expr::Str(_)
        | Expr::Ident(_)
        | Expr::Break(_)
        | Expr::Continue
        | Expr::Return(None) => {}
    }
}

fn mark_gpu_slice_read(
    expr: &Expr,
    bindings: &BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
    out: &mut BTreeMap<String, GpuSliceAccessMode>,
) {
    if let Some(owner) = infer_gpu_slice_owner_name(expr, bindings, signatures) {
        let entry = out.entry(owner).or_insert(GpuSliceAccessMode::Observe);
        *entry = entry.with_read();
    }
}

fn mark_gpu_slice_write(
    expr: &Expr,
    bindings: &BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
    out: &mut BTreeMap<String, GpuSliceAccessMode>,
) {
    if let Some(owner) = infer_gpu_slice_owner_name(expr, bindings, signatures) {
        let entry = out.entry(owner).or_insert(GpuSliceAccessMode::Observe);
        *entry = entry.with_write();
    }
}

fn build_gpu_barrier_summary(functions: &[TypedFunction]) -> BTreeMap<String, bool> {
    let function_map = functions
        .iter()
        .map(|function| (function.name.clone(), function))
        .collect::<BTreeMap<_, _>>();
    let mut cache = BTreeMap::new();
    for function in functions {
        let mut visiting = BTreeSet::new();
        let contains =
            function_contains_gpu_barrier(function, &function_map, &mut cache, &mut visiting);
        cache.insert(function.name.clone(), contains);
    }
    cache
}

fn function_contains_gpu_barrier(
    function: &TypedFunction,
    functions: &BTreeMap<String, &TypedFunction>,
    cache: &mut BTreeMap<String, bool>,
    visiting: &mut BTreeSet<String>,
) -> bool {
    if let Some(cached) = cache.get(&function.name) {
        return *cached;
    }
    if !visiting.insert(function.name.clone()) {
        return false;
    }
    let contains = block_contains_gpu_barrier(&function.body, functions, cache, visiting);
    visiting.remove(&function.name);
    cache.insert(function.name.clone(), contains);
    contains
}

fn block_contains_gpu_barrier(
    body: &[Stmt],
    functions: &BTreeMap<String, &TypedFunction>,
    cache: &mut BTreeMap<String, bool>,
    visiting: &mut BTreeSet<String>,
) -> bool {
    body.iter()
        .any(|stmt| stmt_contains_gpu_barrier(stmt, functions, cache, visiting))
}

fn stmt_contains_gpu_barrier(
    stmt: &Stmt,
    functions: &BTreeMap<String, &TypedFunction>,
    cache: &mut BTreeMap<String, bool>,
    visiting: &mut BTreeSet<String>,
) -> bool {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Expr(value)
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Return(Some(value)) => expr_contains_gpu_barrier(value, functions, cache, visiting),
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_contains_gpu_barrier(condition, functions, cache, visiting)
                || block_contains_gpu_barrier(then_body, functions, cache, visiting)
                || block_contains_gpu_barrier(else_body, functions, cache, visiting)
        }
        Stmt::While { condition, body } => {
            expr_contains_gpu_barrier(condition, functions, cache, visiting)
                || block_contains_gpu_barrier(body, functions, cache, visiting)
        }
        Stmt::Loop { body } => block_contains_gpu_barrier(body, functions, cache, visiting),
        Stmt::ForIn { iterable, body, .. } => {
            expr_contains_gpu_barrier(iterable, functions, cache, visiting)
                || block_contains_gpu_barrier(body, functions, cache, visiting)
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref()
                .is_some_and(|stmt| stmt_contains_gpu_barrier(stmt, functions, cache, visiting))
                || condition
                    .as_ref()
                    .is_some_and(|expr| expr_contains_gpu_barrier(expr, functions, cache, visiting))
                || step
                    .as_deref()
                    .is_some_and(|stmt| stmt_contains_gpu_barrier(stmt, functions, cache, visiting))
                || block_contains_gpu_barrier(body, functions, cache, visiting)
        }
        Stmt::Match { scrutinee, arms } => {
            expr_contains_gpu_barrier(scrutinee, functions, cache, visiting)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(|guard| {
                        expr_contains_gpu_barrier(guard, functions, cache, visiting)
                    }) || expr_contains_gpu_barrier(&arm.value, functions, cache, visiting)
                })
        }
        Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => false,
    }
}

fn expr_contains_gpu_barrier(
    expr: &Expr,
    functions: &BTreeMap<String, &TypedFunction>,
    cache: &mut BTreeMap<String, bool>,
    visiting: &mut BTreeSet<String>,
) -> bool {
    match expr {
        Expr::Call { callee, args } => {
            callee == "gpu.barrier"
                || functions.get(callee).is_some_and(|function| {
                    function_contains_gpu_barrier(function, functions, cache, visiting)
                })
                || args
                    .iter()
                    .any(|arg| expr_contains_gpu_barrier(arg, functions, cache, visiting))
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            expr_contains_gpu_barrier(condition, functions, cache, visiting)
                || expr_contains_gpu_barrier(then_expr, functions, cache, visiting)
                || expr_contains_gpu_barrier(else_expr, functions, cache, visiting)
        }
        Expr::Discard(inner) => expr_contains_gpu_barrier(inner, functions, cache, visiting),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            expr_contains_gpu_barrier(try_expr, functions, cache, visiting)
                || expr_contains_gpu_barrier(catch_expr, functions, cache, visiting)
        }
        Expr::Match { scrutinee, arms } => {
            expr_contains_gpu_barrier(scrutinee, functions, cache, visiting)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(|guard| {
                        expr_contains_gpu_barrier(guard, functions, cache, visiting)
                    }) || expr_contains_gpu_barrier(&arm.value, functions, cache, visiting)
                })
        }
        Expr::UnsafeBlock { body, .. } => {
            block_contains_gpu_barrier(body, functions, cache, visiting)
        }
        Expr::While { condition, body } => {
            expr_contains_gpu_barrier(condition, functions, cache, visiting)
                || block_contains_gpu_barrier(body, functions, cache, visiting)
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref()
                .is_some_and(|stmt| stmt_contains_gpu_barrier(stmt, functions, cache, visiting))
                || condition
                    .as_ref()
                    .is_some_and(|expr| expr_contains_gpu_barrier(expr, functions, cache, visiting))
                || step
                    .as_deref()
                    .is_some_and(|stmt| stmt_contains_gpu_barrier(stmt, functions, cache, visiting))
                || block_contains_gpu_barrier(body, functions, cache, visiting)
        }
        Expr::ForIn { iterable, body, .. } => {
            expr_contains_gpu_barrier(iterable, functions, cache, visiting)
                || block_contains_gpu_barrier(body, functions, cache, visiting)
        }
        Expr::Loop { body } => block_contains_gpu_barrier(body, functions, cache, visiting),
        Expr::FieldAccess { base, .. } | Expr::Group(base) | Expr::Await(base) => {
            expr_contains_gpu_barrier(base, functions, cache, visiting)
        }
        Expr::Index { base, index } => {
            expr_contains_gpu_barrier(base, functions, cache, visiting)
                || expr_contains_gpu_barrier(index, functions, cache, visiting)
        }
        Expr::Unary { expr, .. } | Expr::Return(Some(expr)) => {
            expr_contains_gpu_barrier(expr, functions, cache, visiting)
        }
        Expr::Range { start, end, .. } => {
            expr_contains_gpu_barrier(start, functions, cache, visiting)
                || expr_contains_gpu_barrier(end, functions, cache, visiting)
        }
        Expr::Binary { left, right, .. } => {
            expr_contains_gpu_barrier(left, functions, cache, visiting)
                || expr_contains_gpu_barrier(right, functions, cache, visiting)
        }
        Expr::Return(None)
        | Expr::Ident(_)
        | Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Char(_)
        | Expr::Break(_)
        | Expr::Continue
        | Expr::Closure { .. }
        | Expr::ArrayLiteral(_)
        | Expr::Tuple(_)
        | Expr::StructInit { .. }
        | Expr::EnumInit { .. }
        | Expr::ObjectLiteral(_) => false,
    }
}

fn analyze_live_borrow_block(
    function: &TypedFunction,
    body: &[Stmt],
    suffix_after_block: &[Stmt],
    bindings: &mut CowBindings<BorrowBinding>,
    signatures: &FunctionSignatures<'_>,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    violations: &mut Vec<String>,
) {
    for (index, stmt) in body.iter().enumerate() {
        let remaining = &body[index + 1..];
        let future_uses_alias = |alias: &str| {
            remaining
                .iter()
                .any(|candidate| stmt_uses_ident(candidate, alias))
                || suffix_after_block
                    .iter()
                    .any(|candidate| stmt_uses_ident(candidate, alias))
        };
        for creation in stmt_borrow_creations(function, stmt, bindings, signatures) {
            for (alias, binding) in bindings.iter() {
                if creation.alias.as_deref() == Some(alias.as_str()) {
                    continue;
                }
                if binding.owner != creation.owner
                    || !future_uses_alias(alias)
                    || !(binding.mutable || creation.mutable)
                {
                    continue;
                }
                let new_kind = if creation.mutable {
                    "mutable"
                } else {
                    "shared"
                };
                let existing_kind = if binding.mutable { "mutable" } else { "shared" };
                let detail = if let Some(new_alias) = creation.alias.as_deref() {
                    format!(
                        "function `{}` creates {} borrow `{}` from owner `{}` while {} borrowed reference `{}` is still live",
                        function.name,
                        new_kind,
                        new_alias,
                        creation.owner,
                        existing_kind,
                        alias
                    )
                } else {
                    format!(
                        "function `{}` creates {} borrow of owner `{}` via `{}` while {} borrowed reference `{}` is still live",
                        function.name,
                        new_kind,
                        creation.owner,
                        creation.via,
                        existing_kind,
                        alias
                    )
                };
                violations.push(detail);
            }
        }
        for (alias, binding) in bindings.iter() {
            if !binding.mutable || !future_uses_alias(alias) {
                continue;
            }
            if let Some(access) = stmt_direct_owner_access_label(
                function,
                stmt,
                &binding.owner,
                bindings,
                signatures,
                ownership_summaries,
            ) {
                violations.push(format!(
                    "function `{}` accesses owner `{}` via `{}` while mutable borrowed reference `{}` is still live",
                    function.name, binding.owner, access, alias
                ));
            }
        }
        for consume in stmt_borrow_consumptions(stmt, ownership_summaries) {
            for (alias, binding) in bindings.iter() {
                if binding.owner == consume.owner && future_uses_alias(alias) {
                    violations.push(format!(
                        "function `{}` consumes owner `{}` via `{}` while borrowed reference `{}` is still live",
                        function.name, consume.owner, consume.via, alias
                    ));
                }
            }
        }
        match stmt {
            Stmt::Let {
                name, value, ty, ..
            } => {
                let explicit_ty = ty
                    .as_ref()
                    .or_else(|| function.local_types.get(name))
                    .or_else(|| {
                        function
                            .params
                            .iter()
                            .find(|param| param.name == *name)
                            .map(|param| &param.ty)
                    });
                if let Some(binding) =
                    infer_borrow_binding_from_expr(value, explicit_ty, bindings, signatures)
                {
                    bindings.insert(name.clone(), binding);
                } else {
                    bindings.remove(name);
                }
            }
            Stmt::Assign { target, value } => {
                let explicit_ty = function.local_types.get(target).or_else(|| {
                    function
                        .params
                        .iter()
                        .find(|param| param.name == *target)
                        .map(|param| &param.ty)
                });
                if let Some(binding) =
                    infer_borrow_binding_from_expr(value, explicit_ty, bindings, signatures)
                {
                    bindings.insert(target.clone(), binding);
                } else {
                    bindings.remove(target);
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let mut stitched_suffix = remaining.to_vec();
                stitched_suffix.extend_from_slice(suffix_after_block);
                let mut then_bindings = bindings.clone();
                analyze_live_borrow_block(
                    function,
                    then_body,
                    &stitched_suffix,
                    &mut then_bindings,
                    signatures,
                    ownership_summaries,
                    violations,
                );
                let mut else_bindings = bindings.clone();
                analyze_live_borrow_block(
                    function,
                    else_body,
                    &stitched_suffix,
                    &mut else_bindings,
                    signatures,
                    ownership_summaries,
                    violations,
                );
            }
            Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::ForIn { body, .. } => {
                let mut stitched_suffix = remaining.to_vec();
                stitched_suffix.extend_from_slice(suffix_after_block);
                let mut loop_bindings = bindings.clone();
                analyze_live_borrow_block(
                    function,
                    body,
                    &stitched_suffix,
                    &mut loop_bindings,
                    signatures,
                    ownership_summaries,
                    violations,
                );
            }
            Stmt::For {
                init, step, body, ..
            } => {
                let mut stitched_suffix = remaining.to_vec();
                stitched_suffix.extend_from_slice(suffix_after_block);
                if let Some(init) = init {
                    analyze_live_borrow_block(
                        function,
                        std::slice::from_ref(init.as_ref()),
                        &stitched_suffix,
                        bindings,
                        signatures,
                        ownership_summaries,
                        violations,
                    );
                }
                let mut loop_bindings = bindings.clone();
                analyze_live_borrow_block(
                    function,
                    body,
                    &stitched_suffix,
                    &mut loop_bindings,
                    signatures,
                    ownership_summaries,
                    violations,
                );
                if let Some(step) = step {
                    analyze_live_borrow_block(
                        function,
                        std::slice::from_ref(step.as_ref()),
                        &stitched_suffix,
                        bindings,
                        signatures,
                        ownership_summaries,
                        violations,
                    );
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BorrowConsume {
    owner: String,
    via: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BorrowCreation {
    owner: String,
    via: String,
    mutable: bool,
    alias: Option<String>,
}

fn stmt_borrow_consumptions(
    stmt: &Stmt,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
) -> Vec<BorrowConsume> {
    let mut out = Vec::new();
    match stmt {
        Stmt::Let {
            name, value, ty, ..
        } => {
            if !matches!(ty.as_ref(), Some(Type::Ref { .. })) {
                if let Expr::Ident(from) = value {
                    out.push(BorrowConsume {
                        owner: from.clone(),
                        via: format!("let {name} = {from}"),
                    });
                }
            }
        }
        Stmt::Assign { target, value } | Stmt::CompoundAssign { target, value, .. } => {
            if let Expr::Ident(from) = value {
                out.push(BorrowConsume {
                    owner: from.clone(),
                    via: format!("{target} = {from}"),
                });
            }
        }
        Stmt::Expr(Expr::Call { callee, args }) => {
            for index in runtime_consumed_param_indices(callee) {
                if let Some(owner) = args.get(*index).and_then(expr_consumed_binding_name) {
                    out.push(BorrowConsume {
                        owner: owner.to_string(),
                        via: format!("{callee}({owner})"),
                    });
                }
            }
            if let Some(consumed) = ownership_summaries.get(callee) {
                for index in consumed {
                    if let Some(owner) = args.get(*index).and_then(expr_consumed_binding_name) {
                        if !out.iter().any(|existing| existing.owner == owner) {
                            out.push(BorrowConsume {
                                owner: owner.to_string(),
                                via: format!("{callee}({owner})"),
                            });
                        }
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn stmt_borrow_creations(
    function: &TypedFunction,
    stmt: &Stmt,
    bindings: &CowBindings<BorrowBinding>,
    signatures: &FunctionSignatures<'_>,
) -> Vec<BorrowCreation> {
    let mut out = Vec::new();
    match stmt {
        Stmt::Let {
            name, value, ty, ..
        } => {
            let explicit_ty = ty
                .as_ref()
                .or_else(|| function.local_types.get(name))
                .or_else(|| {
                    function
                        .params
                        .iter()
                        .find(|param| param.name == *name)
                        .map(|param| &param.ty)
                });
            if let Some(binding) =
                infer_borrow_binding_from_expr(value, explicit_ty, bindings, signatures)
            {
                out.push(BorrowCreation {
                    owner: binding.owner,
                    via: format!("let {name} = {}", borrow_creation_expr_label(value)),
                    mutable: binding.mutable,
                    alias: Some(name.clone()),
                });
            }
        }
        Stmt::Assign { target, value } => {
            let explicit_ty = function.local_types.get(target).or_else(|| {
                function
                    .params
                    .iter()
                    .find(|param| param.name == *target)
                    .map(|param| &param.ty)
            });
            if let Some(binding) =
                infer_borrow_binding_from_expr(value, explicit_ty, bindings, signatures)
            {
                out.push(BorrowCreation {
                    owner: binding.owner,
                    via: format!("{target} = {}", borrow_creation_expr_label(value)),
                    mutable: binding.mutable,
                    alias: Some(target.clone()),
                });
            }
        }
        Stmt::Expr(Expr::Call { callee, args }) => {
            let params = signatures
                .get(callee.as_str())
                .map(|function| {
                    function
                        .params
                        .iter()
                        .map(|param| param.ty.clone())
                        .collect::<Vec<_>>()
                })
                .or_else(|| runtime_call_signature(callee).map(|(params, _)| params));
            let Some(params) = params else {
                return out;
            };
            for (index, param_ty) in params.iter().enumerate() {
                let Type::Ref { mutable, .. } = param_ty else {
                    continue;
                };
                let Some(arg) = args.get(index) else {
                    continue;
                };
                let Some(owner) = infer_borrow_owner_name(arg, bindings, signatures) else {
                    continue;
                };
                out.push(BorrowCreation {
                    via: format!("{callee}({owner})"),
                    owner,
                    mutable: *mutable,
                    alias: None,
                });
            }
        }
        _ => {}
    }
    out
}

fn stmt_direct_owner_access_label(
    function: &TypedFunction,
    stmt: &Stmt,
    owner: &str,
    bindings: &CowBindings<BorrowBinding>,
    signatures: &FunctionSignatures<'_>,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
) -> Option<String> {
    if !stmt_uses_ident(stmt, owner) {
        return None;
    }
    if stmt_borrow_consumptions(stmt, ownership_summaries)
        .iter()
        .any(|consume| consume.owner == owner)
    {
        return None;
    }
    if stmt_borrow_creations(function, stmt, bindings, signatures)
        .iter()
        .any(|creation| creation.owner == owner)
    {
        return None;
    }
    match stmt {
        Stmt::Expr(expr) => expr_direct_owner_access_label(expr, owner),
        Stmt::Return(Some(expr)) => {
            expr_direct_owner_access_label(expr, owner).map(|label| format!("return {label}"))
        }
        Stmt::Let { name, value, .. } if expr_uses_ident(value, owner) => Some(format!(
            "let {name} = {}",
            borrow_creation_expr_label(value)
        )),
        Stmt::Assign { target, value } if expr_uses_ident(value, owner) => {
            Some(format!("{target} = {}", borrow_creation_expr_label(value)))
        }
        _ => Some(owner.to_string()),
    }
}

fn expr_direct_owner_access_label(expr: &Expr, owner: &str) -> Option<String> {
    match expr {
        Expr::Ident(name) if name == owner => Some(name.clone()),
        Expr::Call { callee, args } if args.iter().any(|arg| expr_uses_ident(arg, owner)) => {
            Some(format!("{callee}({owner})"))
        }
        Expr::Discard(inner) => {
            expr_direct_owner_access_label(inner, owner).map(|label| format!("discard {label}"))
        }
        Expr::Group(inner) => expr_direct_owner_access_label(inner, owner),
        _ if expr_uses_ident(expr, owner) => Some(owner.to_string()),
        _ => None,
    }
}

fn borrow_creation_expr_label(expr: &Expr) -> String {
    match expr {
        Expr::Ident(name) => name.clone(),
        Expr::Group(inner) => borrow_creation_expr_label(inner),
        Expr::Call { callee, args } => {
            let rendered = args
                .iter()
                .filter_map(expr_consumed_binding_name)
                .collect::<Vec<_>>();
            if rendered.is_empty() {
                format!("{callee}(...)")
            } else {
                format!("{callee}({})", rendered.join(", "))
            }
        }
        _ => "<expr>".to_string(),
    }
}

fn infer_borrow_binding_from_expr(
    value: &Expr,
    explicit_ty: Option<&Type>,
    bindings: &CowBindings<BorrowBinding>,
    signatures: &FunctionSignatures<'_>,
) -> Option<BorrowBinding> {
    match explicit_ty? {
        Type::Ref { mutable, .. } => {
            infer_borrow_owner_name(value, bindings, signatures).map(|owner| BorrowBinding {
                owner,
                mutable: *mutable,
            })
        }
        Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
            infer_gpu_slice_owner_name_borrowed(value, bindings, signatures).map(|owner| {
                BorrowBinding {
                    owner,
                    // Until readonly/writeonly qualifiers land, treat live GPU slices as mutable views.
                    mutable: true,
                }
            })
        }
        _ => None,
    }
}

fn infer_borrow_binding_from_expr_owned(
    value: &Expr,
    explicit_ty: Option<&Type>,
    bindings: &BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
) -> Option<BorrowBinding> {
    match explicit_ty? {
        Type::Ref { mutable, .. } => infer_borrow_owner_name_owned(value, bindings, signatures)
            .map(|owner| BorrowBinding {
                owner,
                mutable: *mutable,
            }),
        Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
            infer_gpu_slice_owner_name(value, bindings, signatures).map(|owner| BorrowBinding {
                owner,
                mutable: true,
            })
        }
        _ => None,
    }
}

fn infer_borrow_owner_name(
    expr: &Expr,
    bindings: &CowBindings<BorrowBinding>,
    signatures: &FunctionSignatures<'_>,
) -> Option<String> {
    match expr {
        Expr::Ident(name) => Some(
            bindings
                .get(name)
                .map(|binding| binding.owner.clone())
                .unwrap_or_else(|| name.clone()),
        ),
        Expr::Group(inner) | Expr::FieldAccess { base: inner, .. } => {
            infer_borrow_owner_name(inner, bindings, signatures)
        }
        Expr::Call { callee, args } => signatures.get(callee.as_str()).and_then(|function| {
            let Type::Ref {
                lifetime: Some(return_lifetime),
                ..
            } = &function.return_type
            else {
                return None;
            };
            let matching = function
                .params
                .iter()
                .enumerate()
                .filter_map(|(index, param)| match &param.ty {
                    Type::Ref {
                        lifetime: Some(param_lifetime),
                        ..
                    } if param_lifetime == return_lifetime => args.get(index),
                    _ => None,
                })
                .filter_map(|arg| infer_borrow_owner_name(arg, bindings, signatures))
                .collect::<Vec<_>>();
            if matching.is_empty() {
                None
            } else if matching.windows(2).all(|window| window[0] == window[1]) {
                matching.first().cloned()
            } else {
                None
            }
        }),
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let then_owner = infer_borrow_owner_name(then_expr, bindings, signatures);
            let else_owner = infer_borrow_owner_name(else_expr, bindings, signatures);
            if then_owner == else_owner {
                then_owner
            } else {
                None
            }
        }
        Expr::Match { arms, .. } => {
            let owners = arms
                .iter()
                .filter_map(|arm| infer_borrow_owner_name(&arm.value, bindings, signatures))
                .collect::<Vec<_>>();
            if owners.is_empty() {
                None
            } else if owners.windows(2).all(|window| window[0] == window[1]) {
                owners.first().cloned()
            } else {
                None
            }
        }
        _ => None,
    }
}

fn infer_borrow_owner_name_owned(
    expr: &Expr,
    bindings: &BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
) -> Option<String> {
    match expr {
        Expr::Ident(name) => Some(
            bindings
                .get(name)
                .map(|binding| binding.owner.clone())
                .unwrap_or_else(|| name.clone()),
        ),
        Expr::Group(inner) | Expr::FieldAccess { base: inner, .. } => {
            infer_borrow_owner_name_owned(inner, bindings, signatures)
        }
        Expr::Call { callee, args } => signatures.get(callee).and_then(|function| {
            let Type::Ref {
                lifetime: Some(return_lifetime),
                ..
            } = &function.return_type
            else {
                return None;
            };
            let matching = function
                .params
                .iter()
                .enumerate()
                .filter_map(|(index, param)| match &param.ty {
                    Type::Ref {
                        lifetime: Some(param_lifetime),
                        ..
                    } if param_lifetime == return_lifetime => args.get(index),
                    _ => None,
                })
                .filter_map(|arg| infer_borrow_owner_name_owned(arg, bindings, signatures))
                .collect::<Vec<_>>();
            if matching.is_empty() {
                None
            } else if matching.windows(2).all(|window| window[0] == window[1]) {
                matching.first().cloned()
            } else {
                None
            }
        }),
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let then_owner = infer_borrow_owner_name_owned(then_expr, bindings, signatures);
            let else_owner = infer_borrow_owner_name_owned(else_expr, bindings, signatures);
            if then_owner == else_owner {
                then_owner
            } else {
                None
            }
        }
        Expr::Match { arms, .. } => {
            let owners = arms
                .iter()
                .filter_map(|arm| infer_borrow_owner_name_owned(&arm.value, bindings, signatures))
                .collect::<Vec<_>>();
            if owners.is_empty() {
                None
            } else if owners.windows(2).all(|window| window[0] == window[1]) {
                owners.first().cloned()
            } else {
                None
            }
        }
        _ => None,
    }
}

fn infer_gpu_slice_owner_name_borrowed(
    expr: &Expr,
    bindings: &CowBindings<BorrowBinding>,
    signatures: &FunctionSignatures<'_>,
) -> Option<String> {
    match expr {
        Expr::Ident(name) => Some(
            bindings
                .get(name)
                .map(|binding| binding.owner.clone())
                .unwrap_or_else(|| name.clone()),
        ),
        Expr::Group(inner) | Expr::FieldAccess { base: inner, .. } => {
            infer_gpu_slice_owner_name_borrowed(inner, bindings, signatures)
        }
        Expr::Call { callee, args } if callee == "gpu.slice" => args
            .first()
            .and_then(|arg| infer_gpu_slice_owner_name_borrowed(arg, bindings, signatures)),
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let then_owner = infer_gpu_slice_owner_name_borrowed(then_expr, bindings, signatures);
            let else_owner = infer_gpu_slice_owner_name_borrowed(else_expr, bindings, signatures);
            if then_owner == else_owner {
                then_owner
            } else {
                None
            }
        }
        Expr::Match { arms, .. } => {
            let owners = arms
                .iter()
                .filter_map(|arm| {
                    infer_gpu_slice_owner_name_borrowed(&arm.value, bindings, signatures)
                })
                .collect::<Vec<_>>();
            if owners.is_empty() {
                None
            } else if owners.windows(2).all(|window| window[0] == window[1]) {
                owners.first().cloned()
            } else {
                None
            }
        }
        Expr::Call { callee, args } => signatures.get(callee.as_str()).and_then(|function| {
            let Type::Named { name, args: ret_args } = &function.return_type else {
                return None;
            };
            if name != "GpuSlice" || ret_args.len() != 1 {
                return None;
            }
            function
                .params
                .iter()
                .enumerate()
                .find(|(_, param)| {
                    matches!(&param.ty, Type::Named { name, args } if name == "GpuSlice" && args.len() == 1)
                })
                .and_then(|(index, _)| args.get(index))
                .and_then(|arg| infer_gpu_slice_owner_name_borrowed(arg, bindings, signatures))
        }),
        _ => None,
    }
}

fn infer_gpu_slice_owner_name(
    expr: &Expr,
    bindings: &BTreeMap<String, BorrowBinding>,
    signatures: &BTreeMap<String, TypedFunction>,
) -> Option<String> {
    match expr {
        Expr::Ident(name) => Some(
            bindings
                .get(name)
                .map(|binding| binding.owner.clone())
                .unwrap_or_else(|| name.clone()),
        ),
        Expr::Group(inner) | Expr::FieldAccess { base: inner, .. } => {
            infer_gpu_slice_owner_name(inner, bindings, signatures)
        }
        Expr::Call { callee, args } if callee == "gpu.slice" => args
            .first()
            .and_then(|arg| infer_gpu_slice_owner_name(arg, bindings, signatures)),
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let then_owner = infer_gpu_slice_owner_name(then_expr, bindings, signatures);
            let else_owner = infer_gpu_slice_owner_name(else_expr, bindings, signatures);
            if then_owner == else_owner {
                then_owner
            } else {
                None
            }
        }
        Expr::Match { arms, .. } => {
            let owners = arms
                .iter()
                .filter_map(|arm| infer_gpu_slice_owner_name(&arm.value, bindings, signatures))
                .collect::<Vec<_>>();
            if owners.is_empty() {
                None
            } else if owners.windows(2).all(|window| window[0] == window[1]) {
                owners.first().cloned()
            } else {
                None
            }
        }
        Expr::Call { callee, args } => signatures.get(callee).and_then(|function| match &function
            .return_type
        {
            Type::Named {
                name,
                args: named_args,
            } if name == "GpuSlice" && named_args.len() == 1 => args
                .iter()
                .filter_map(|arg| infer_gpu_slice_owner_name(arg, bindings, signatures))
                .collect::<Vec<_>>()
                .first()
                .cloned(),
            _ => None,
        }),
        _ => None,
    }
}

fn execution_space_label(execution: ast::ExecutionSpace) -> &'static str {
    match execution {
        ast::ExecutionSpace::Host => "host",
        ast::ExecutionSpace::Pure => "pure",
        ast::ExecutionSpace::Device => "device",
        ast::ExecutionSpace::Kernel => "kernel",
    }
}

fn validate_reference_returns(
    body: &[Stmt],
    function: &TypedFunction,
    ref_bindings: &mut CowBindings<(Option<String>, bool)>,
    signatures: &FunctionSignatures<'_>,
    return_lifetime: &Option<String>,
    violations: &mut Vec<String>,
) -> bool {
    for stmt in body {
        match stmt {
            Stmt::Return(Some(expr)) => {
                let inferred = infer_reference_lifetime(expr, ref_bindings, signatures);
                if inferred.is_none() {
                    violations.push(format!(
                        "function `{}` returns reference expression without a statically traced lifetime source",
                        function.name
                    ));
                    continue;
                }
                if inferred != Some(return_lifetime.clone()) {
                    violations.push(format!(
                        "function `{}` returns reference expression with mismatched lifetime (expected {:?}, got {:?})",
                        function.name, return_lifetime, inferred
                    ));
                }
                return false;
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let entry_bindings = ref_bindings.clone();
                let mut then_bindings = ref_bindings.clone();
                let mut else_bindings = ref_bindings.clone();
                let then_fallthrough = validate_reference_returns(
                    then_body,
                    function,
                    &mut then_bindings,
                    signatures,
                    return_lifetime,
                    violations,
                );
                let else_fallthrough = validate_reference_returns(
                    else_body,
                    function,
                    &mut else_bindings,
                    signatures,
                    return_lifetime,
                    violations,
                );
                *ref_bindings = match (then_fallthrough, else_fallthrough) {
                    (true, true) => {
                        merge_reference_bindings(&entry_bindings, &[then_bindings, else_bindings])
                    }
                    (true, false) => then_bindings,
                    (false, true) => else_bindings,
                    (false, false) => return false,
                };
            }
            Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::ForIn { body, .. } => {
                let mut nested = ref_bindings.clone();
                let _ = validate_reference_returns(
                    body,
                    function,
                    &mut nested,
                    signatures,
                    return_lifetime,
                    violations,
                );
                *ref_bindings = merge_reference_bindings(ref_bindings, &[nested]);
            }
            Stmt::For {
                init, step, body, ..
            } => {
                if let Some(init) = init {
                    let _ = validate_reference_returns(
                        std::slice::from_ref(init.as_ref()),
                        function,
                        ref_bindings,
                        signatures,
                        return_lifetime,
                        violations,
                    );
                }
                let mut body_bindings = ref_bindings.clone();
                let _ = validate_reference_returns(
                    body,
                    function,
                    &mut body_bindings,
                    signatures,
                    return_lifetime,
                    violations,
                );
                *ref_bindings = merge_reference_bindings(ref_bindings, &[body_bindings]);
                if let Some(step) = step {
                    let _ = validate_reference_returns(
                        std::slice::from_ref(step.as_ref()),
                        function,
                        ref_bindings,
                        signatures,
                        return_lifetime,
                        violations,
                    );
                }
            }
            Stmt::Match { arms, .. } => {
                let entry_bindings = ref_bindings.clone();
                let mut arm_bindings = Vec::new();
                let mut any_fallthrough = false;
                for arm in arms {
                    let mut branch_bindings = ref_bindings.clone();
                    let fallthrough = validate_reference_return_expr(
                        &arm.value,
                        function,
                        &mut branch_bindings,
                        signatures,
                        return_lifetime,
                        violations,
                    );
                    if fallthrough {
                        any_fallthrough = true;
                        arm_bindings.push(branch_bindings);
                    }
                }
                if any_fallthrough {
                    *ref_bindings = merge_reference_bindings(&entry_bindings, &arm_bindings);
                } else {
                    return false;
                }
            }
            Stmt::Let { name, value, .. }
            | Stmt::Assign {
                target: name,
                value,
            } => {
                update_reference_binding(name, value, ref_bindings, signatures);
            }
            Stmt::LetPattern { .. }
            | Stmt::CompoundAssign { .. }
            | Stmt::Expr(_)
            | Stmt::Defer(_)
            | Stmt::Requires(_)
            | Stmt::Ensures(_)
            | Stmt::Break(_)
            | Stmt::Continue => {}
            Stmt::Return(None) => return false,
        }
    }
    true
}

fn validate_reference_return_expr(
    expr: &Expr,
    function: &TypedFunction,
    ref_bindings: &mut CowBindings<(Option<String>, bool)>,
    signatures: &FunctionSignatures<'_>,
    return_lifetime: &Option<String>,
    violations: &mut Vec<String>,
) -> bool {
    match expr {
        Expr::Return(Some(value)) => {
            let inferred = infer_reference_lifetime(value, ref_bindings, signatures);
            if inferred.is_none() {
                violations.push(format!(
                    "function `{}` returns reference expression without a statically traced lifetime source",
                    function.name
                ));
            } else if inferred != Some(return_lifetime.clone()) {
                violations.push(format!(
                    "function `{}` returns reference expression with mismatched lifetime (expected {:?}, got {:?})",
                    function.name, return_lifetime, inferred
                ));
            }
            false
        }
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let entry_bindings = ref_bindings.clone();
            let mut then_bindings = ref_bindings.clone();
            let mut else_bindings = ref_bindings.clone();
            let then_fallthrough = validate_reference_return_expr(
                then_expr,
                function,
                &mut then_bindings,
                signatures,
                return_lifetime,
                violations,
            );
            let else_fallthrough = validate_reference_return_expr(
                else_expr,
                function,
                &mut else_bindings,
                signatures,
                return_lifetime,
                violations,
            );
            *ref_bindings = match (then_fallthrough, else_fallthrough) {
                (true, true) => {
                    merge_reference_bindings(&entry_bindings, &[then_bindings, else_bindings])
                }
                (true, false) => then_bindings,
                (false, true) => else_bindings,
                (false, false) => return false,
            };
            true
        }
        Expr::Match { arms, .. } => {
            let entry_bindings = ref_bindings.clone();
            let mut branches = Vec::new();
            for arm in arms {
                let mut branch_bindings = ref_bindings.clone();
                if validate_reference_return_expr(
                    &arm.value,
                    function,
                    &mut branch_bindings,
                    signatures,
                    return_lifetime,
                    violations,
                ) {
                    branches.push(branch_bindings);
                }
            }
            if branches.is_empty() {
                false
            } else {
                *ref_bindings = merge_reference_bindings(&entry_bindings, &branches);
                true
            }
        }
        Expr::UnsafeBlock { body, .. } => validate_reference_returns(
            body,
            function,
            ref_bindings,
            signatures,
            return_lifetime,
            violations,
        ),
        _ => true,
    }
}

fn merge_reference_bindings(
    entry: &CowBindings<(Option<String>, bool)>,
    branches: &[CowBindings<(Option<String>, bool)>],
) -> CowBindings<(Option<String>, bool)> {
    let mut merged = entry.clone();
    for name in entry.keys() {
        let mut current = branches
            .first()
            .and_then(|branch| branch.get(name))
            .cloned();
        for branch in branches.iter().skip(1) {
            if branch.get(name).cloned() != current {
                current = current.map(|(_, mutable)| (None, mutable));
                break;
            }
        }
        if let Some(value) = current {
            merged.insert(name.clone(), value);
        }
    }
    merged
}

fn update_reference_binding(
    name: &str,
    value: &Expr,
    ref_bindings: &mut CowBindings<(Option<String>, bool)>,
    signatures: &FunctionSignatures<'_>,
) {
    let Some((_, mutable)) = ref_bindings.get(name).cloned() else {
        return;
    };
    let next_lifetime = infer_reference_lifetime(value, ref_bindings, signatures).flatten();
    ref_bindings.insert(name.to_string(), (next_lifetime, mutable));
}

fn infer_reference_lifetime(
    expr: &Expr,
    ref_bindings: &CowBindings<(Option<String>, bool)>,
    signatures: &FunctionSignatures<'_>,
) -> Option<Option<String>> {
    match expr {
        Expr::Ident(name) => ref_bindings.get(name).map(|(lifetime, _)| lifetime.clone()),
        Expr::Group(inner) | Expr::FieldAccess { base: inner, .. } => {
            infer_reference_lifetime(inner, ref_bindings, signatures)
        }
        Expr::Await(inner) | Expr::Discard(inner) | Expr::Unary { expr: inner, .. } => {
            infer_reference_lifetime(inner, ref_bindings, signatures)
        }
        Expr::Call { callee, args } => signatures.get(callee.as_str()).and_then(|function| {
            let Type::Ref {
                lifetime: Some(return_lifetime),
                ..
            } = &function.return_type
            else {
                return None;
            };
            let matching = function
                .params
                .iter()
                .enumerate()
                .filter_map(|(index, param)| match &param.ty {
                    Type::Ref {
                        lifetime: Some(param_lifetime),
                        ..
                    } if param_lifetime == return_lifetime => args.get(index),
                    _ => None,
                })
                .map(|arg| infer_reference_lifetime(arg, ref_bindings, signatures))
                .collect::<Vec<_>>();
            if matching.len() == 1 {
                matching[0].clone()
            } else if matching.windows(2).all(|window| window[0] == window[1]) {
                matching.first().cloned().flatten()
            } else {
                None
            }
        }),
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let then_lifetime = infer_reference_lifetime(then_expr, ref_bindings, signatures);
            let else_lifetime = infer_reference_lifetime(else_expr, ref_bindings, signatures);
            if then_lifetime == else_lifetime {
                then_lifetime
            } else {
                None
            }
        }
        Expr::Match { arms, .. } => {
            let lifetimes = arms
                .iter()
                .map(|arm| infer_reference_lifetime(&arm.value, ref_bindings, signatures))
                .collect::<Vec<_>>();
            if lifetimes.windows(2).all(|window| window[0] == window[1]) {
                lifetimes.first().cloned().flatten()
            } else {
                None
            }
        }
        Expr::UnsafeBlock { .. } => None,
        _ => None,
    }
}

fn ref_used_after_await(body: &[Stmt], name: &str, _mutable: bool) -> bool {
    let mut seen_await = false;
    body_uses_ident_after_await(body, name, &mut seen_await)
}

fn body_uses_ident_after_await(body: &[Stmt], name: &str, seen_await: &mut bool) -> bool {
    for stmt in body {
        if *seen_await && stmt_uses_ident(stmt, name) {
            return true;
        }
        if stmt_uses_ident_after_await(stmt, name, seen_await) {
            return true;
        }
    }
    false
}

fn stmt_uses_ident_after_await(stmt: &Stmt, name: &str, seen_await: &mut bool) -> bool {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_uses_ident_after_await(value, name, seen_await),
        Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => false,
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            if expr_uses_ident_after_await(condition, name, seen_await) {
                return true;
            }
            let branch_entry = *seen_await;
            let mut then_seen = branch_entry;
            if body_uses_ident_after_await(then_body, name, &mut then_seen) {
                return true;
            }
            let mut else_seen = branch_entry;
            if body_uses_ident_after_await(else_body, name, &mut else_seen) {
                return true;
            }
            *seen_await = then_seen || else_seen;
            false
        }
        Stmt::While { condition, body } => {
            if expr_uses_ident_after_await(condition, name, seen_await) {
                return true;
            }
            let mut body_seen = *seen_await;
            if body_uses_ident_after_await(body, name, &mut body_seen) {
                return true;
            }
            *seen_await = body_seen;
            false
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if init
                .as_deref()
                .is_some_and(|stmt| stmt_uses_ident_after_await(stmt, name, seen_await))
            {
                return true;
            }
            if condition
                .as_ref()
                .is_some_and(|expr| expr_uses_ident_after_await(expr, name, seen_await))
            {
                return true;
            }
            let mut body_seen = *seen_await;
            if body_uses_ident_after_await(body, name, &mut body_seen) {
                return true;
            }
            if step
                .as_deref()
                .is_some_and(|stmt| stmt_uses_ident_after_await(stmt, name, &mut body_seen))
            {
                return true;
            }
            *seen_await = body_seen;
            false
        }
        Stmt::ForIn { iterable, body, .. } => {
            if expr_uses_ident_after_await(iterable, name, seen_await) {
                return true;
            }
            let mut body_seen = *seen_await;
            if body_uses_ident_after_await(body, name, &mut body_seen) {
                return true;
            }
            *seen_await = body_seen;
            false
        }
        Stmt::Loop { body } => {
            let mut body_seen = *seen_await;
            if body_uses_ident_after_await(body, name, &mut body_seen) {
                return true;
            }
            *seen_await = body_seen;
            false
        }
        Stmt::Match { scrutinee, arms } => {
            if expr_uses_ident_after_await(scrutinee, name, seen_await) {
                return true;
            }
            let branch_entry = *seen_await;
            let mut any_seen = branch_entry;
            for arm in arms {
                let mut arm_seen = branch_entry;
                if arm
                    .guard
                    .as_ref()
                    .is_some_and(|guard| expr_uses_ident_after_await(guard, name, &mut arm_seen))
                {
                    return true;
                }
                if expr_uses_ident_after_await(&arm.value, name, &mut arm_seen) {
                    return true;
                }
                any_seen |= arm_seen;
            }
            *seen_await = any_seen;
            false
        }
    }
}

fn expr_uses_ident_after_await(expr: &Expr, name: &str, seen_await: &mut bool) -> bool {
    match expr {
        Expr::Ident(ident) => *seen_await && ident == name,
        Expr::Await(inner) => {
            if expr_uses_ident_after_await(inner, name, seen_await) {
                return true;
            }
            *seen_await = true;
            false
        }
        Expr::Discard(inner)
        | Expr::Group(inner)
        | Expr::Unary { expr: inner, .. }
        | Expr::FieldAccess { base: inner, .. } => {
            expr_uses_ident_after_await(inner, name, seen_await)
        }
        Expr::Call { args, .. } => args
            .iter()
            .any(|arg| expr_uses_ident_after_await(arg, name, seen_await)),
        Expr::UnsafeBlock { body, .. } => body_uses_ident_after_await(body, name, seen_await),
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => fields
            .iter()
            .any(|(_, value)| expr_uses_ident_after_await(value, name, seen_await)),
        Expr::EnumInit { payload, .. } | Expr::Tuple(payload) | Expr::ArrayLiteral(payload) => {
            payload
                .iter()
                .any(|value| expr_uses_ident_after_await(value, name, seen_await))
        }
        Expr::Closure { params, body, .. } => {
            if params.iter().any(|param| param.name == name) {
                false
            } else {
                let mut closure_seen = *seen_await;
                let uses = expr_uses_ident_after_await(body, name, &mut closure_seen);
                *seen_await |= closure_seen;
                uses
            }
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let entry_seen = *seen_await;
            let mut try_seen = entry_seen;
            if expr_uses_ident_after_await(try_expr, name, &mut try_seen) {
                return true;
            }
            let mut catch_seen = entry_seen;
            if expr_uses_ident_after_await(catch_expr, name, &mut catch_seen) {
                return true;
            }
            *seen_await = try_seen || catch_seen;
            false
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            if expr_uses_ident_after_await(condition, name, seen_await) {
                return true;
            }
            let branch_entry = *seen_await;
            let mut then_seen = branch_entry;
            if expr_uses_ident_after_await(then_expr, name, &mut then_seen) {
                return true;
            }
            let mut else_seen = branch_entry;
            if expr_uses_ident_after_await(else_expr, name, &mut else_seen) {
                return true;
            }
            *seen_await = then_seen || else_seen;
            false
        }
        Expr::Match { scrutinee, arms } => {
            if expr_uses_ident_after_await(scrutinee, name, seen_await) {
                return true;
            }
            let branch_entry = *seen_await;
            let mut any_seen = branch_entry;
            for arm in arms {
                let mut arm_seen = branch_entry;
                if arm
                    .guard
                    .as_ref()
                    .is_some_and(|guard| expr_uses_ident_after_await(guard, name, &mut arm_seen))
                {
                    return true;
                }
                if expr_uses_ident_after_await(&arm.value, name, &mut arm_seen) {
                    return true;
                }
                any_seen |= arm_seen;
            }
            *seen_await = any_seen;
            false
        }
        Expr::While { condition, body } => {
            if expr_uses_ident_after_await(condition, name, seen_await) {
                return true;
            }
            body_uses_ident_after_await(body, name, seen_await)
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if init
                .as_deref()
                .is_some_and(|stmt| stmt_uses_ident_after_await(stmt, name, seen_await))
            {
                return true;
            }
            if condition
                .as_ref()
                .is_some_and(|expr| expr_uses_ident_after_await(expr, name, seen_await))
            {
                return true;
            }
            if body_uses_ident_after_await(body, name, seen_await) {
                return true;
            }
            step.as_deref()
                .is_some_and(|stmt| stmt_uses_ident_after_await(stmt, name, seen_await))
        }
        Expr::ForIn { iterable, body, .. } => {
            if expr_uses_ident_after_await(iterable, name, seen_await) {
                return true;
            }
            body_uses_ident_after_await(body, name, seen_await)
        }
        Expr::Loop { body } => body_uses_ident_after_await(body, name, seen_await),
        Expr::Return(value) | Expr::Break(value) => value
            .as_ref()
            .is_some_and(|expr| expr_uses_ident_after_await(expr, name, seen_await)),
        Expr::Continue => false,
        Expr::Binary { left, right, .. }
        | Expr::Range {
            start: left,
            end: right,
            ..
        } => {
            expr_uses_ident_after_await(left, name, seen_await)
                || expr_uses_ident_after_await(right, name, seen_await)
        }
        Expr::Index { base, index } => {
            expr_uses_ident_after_await(base, name, seen_await)
                || expr_uses_ident_after_await(index, name, seen_await)
        }
        Expr::Int(_) | Expr::Float { .. } | Expr::Char(_) | Expr::Bool(_) | Expr::Str(_) => false,
    }
}

