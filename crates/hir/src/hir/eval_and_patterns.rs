fn record_type_error(errors: &mut usize, type_error_details: &mut Vec<String>, detail: String) {
    *errors += 1;
    type_error_details.push(detail);
}

fn eval_const_i32(expr: &Expr, known: &HashMap<String, i32>) -> Option<i32> {
    match expr {
        Expr::Int(v) => i32::try_from(*v).ok(),
        Expr::Bool(v) => Some(if *v { 1 } else { 0 }),
        Expr::Char(v) => Some(*v as i32),
        Expr::Ident(name) => known.get(name).copied(),
        Expr::Group(inner) => eval_const_i32(inner, known),
        Expr::Discard(inner) => eval_const_i32(inner, known),
        Expr::Unary { op, expr } => {
            let value = eval_const_i32(expr, known)?;
            Some(match op {
                ast::UnaryOp::Plus => value,
                ast::UnaryOp::Neg => -value,
                ast::UnaryOp::BitNot => !value,
                ast::UnaryOp::Not => {
                    if value == 0 {
                        1
                    } else {
                        0
                    }
                }
            })
        }
        Expr::Binary { op, left, right } => {
            let lhs = eval_const_i32(left, known)?;
            let rhs = eval_const_i32(right, known)?;
            Some(match op {
                ast::BinaryOp::Add => lhs.wrapping_add(rhs),
                ast::BinaryOp::Sub => lhs.wrapping_sub(rhs),
                ast::BinaryOp::Mul => lhs.wrapping_mul(rhs),
                ast::BinaryOp::Div => {
                    if rhs == 0 {
                        return None;
                    }
                    lhs.wrapping_div(rhs)
                }
                ast::BinaryOp::Mod => {
                    if rhs == 0 {
                        return None;
                    }
                    lhs.wrapping_rem(rhs)
                }
                ast::BinaryOp::BitAnd => lhs & rhs,
                ast::BinaryOp::BitOr => lhs | rhs,
                ast::BinaryOp::BitXor => lhs ^ rhs,
                ast::BinaryOp::Shl => lhs.wrapping_shl(rhs as u32),
                ast::BinaryOp::Shr => lhs.wrapping_shr(rhs as u32),
                ast::BinaryOp::And => {
                    if lhs != 0 && rhs != 0 {
                        1
                    } else {
                        0
                    }
                }
                ast::BinaryOp::Or => {
                    if lhs != 0 || rhs != 0 {
                        1
                    } else {
                        0
                    }
                }
                ast::BinaryOp::Lt => (lhs < rhs) as i32,
                ast::BinaryOp::Lte => (lhs <= rhs) as i32,
                ast::BinaryOp::Gt => (lhs > rhs) as i32,
                ast::BinaryOp::Gte => (lhs >= rhs) as i32,
                ast::BinaryOp::Eq => (lhs == rhs) as i32,
                ast::BinaryOp::Neq => (lhs != rhs) as i32,
            })
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let cond = eval_const_i32(condition, known)?;
            if cond != 0 {
                eval_const_i32(then_expr, known)
            } else {
                eval_const_i32(else_expr, known)
            }
        }
        _ => None,
    }
}

fn interpret_entry_i32(functions: &[TypedFunction]) -> Option<i32> {
    let map = functions
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect::<HashMap<_, _>>();
    let main = map.get("main")?;
    let mut env = BTreeMap::new();
    CONST_EVAL_BUDGET.with(|budget| budget.set(CONST_EVAL_STEP_LIMIT));
    let result = eval_block(&main.body, &mut env, &map).and_then(|value| match value {
        Value::I32(v) => Some(v),
        Value::F64(v) => Some(v as i32),
        Value::Bool(v) => Some(v as i32),
        Value::Char(v) => Some(v as i32),
        Value::Str(_) => None,
        Value::FnRef(_)
        | Value::Closure(_)
        | Value::Tuple(_)
        | Value::List(_)
        | Value::Struct { .. }
        | Value::Enum { .. } => None,
    });
    CONST_EVAL_BUDGET.with(|budget| budget.set(0));
    result
}

fn function_has_explicit_return(body: &[Stmt]) -> bool {
    body.iter().any(stmt_has_explicit_return)
}

fn stmt_has_explicit_return(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return(_) => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(stmt_has_explicit_return)
                || else_body.iter().any(stmt_has_explicit_return)
        }
        Stmt::While { body, .. } => body.iter().any(stmt_has_explicit_return),
        Stmt::For {
            init,
            condition: _,
            step,
            body,
        } => {
            init.as_deref().is_some_and(stmt_has_explicit_return)
                || step.as_deref().is_some_and(stmt_has_explicit_return)
                || body.iter().any(stmt_has_explicit_return)
        }
        Stmt::ForIn { body, .. } | Stmt::Loop { body } => body.iter().any(stmt_has_explicit_return),
        Stmt::Break(_) | Stmt::Continue => false,
        Stmt::Match { arms, .. } => arms
            .iter()
            .any(|arm| arm.returns || expr_has_nested_return(&arm.value)),
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Expr(value)
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value) => expr_has_nested_return(value),
    }
}

fn expr_has_nested_return(_expr: &Expr) -> bool {
    false
}

enum EvalOutcome {
    Continue,
    Break,
    ContinueLoop,
    Return(Value),
}

thread_local! {
    static CONST_EVAL_BUDGET: Cell<usize> = const { Cell::new(0) };
}

const CONST_EVAL_STEP_LIMIT: usize = 20_000;

fn const_eval_allow_step() -> bool {
    CONST_EVAL_BUDGET.with(|budget| {
        let remaining = budget.get();
        if remaining == 0 {
            false
        } else {
            budget.set(remaining - 1);
            true
        }
    })
}

fn eval_block<'a>(
    body: &[Stmt],
    env: &mut BTreeMap<String, Value>,
    functions: &HashMap<&'a str, &'a TypedFunction>,
) -> Option<Value> {
    match eval_block_control(body, env, functions) {
        EvalOutcome::Return(value) => Some(value),
        EvalOutcome::Continue | EvalOutcome::Break | EvalOutcome::ContinueLoop => None,
    }
}

fn eval_block_control<'a>(
    body: &[Stmt],
    env: &mut BTreeMap<String, Value>,
    functions: &HashMap<&'a str, &'a TypedFunction>,
) -> EvalOutcome {
    let mut deferred = Vec::<Expr>::new();
    for stmt in body {
        if !const_eval_allow_step() {
            for expr in deferred.iter().rev() {
                let _ = eval_expr(expr, env, functions);
            }
            return EvalOutcome::Continue;
        }
        match stmt {
            Stmt::Let { name, value, .. } => {
                let Some(val) = eval_expr(value, env, functions) else {
                    return EvalOutcome::Continue;
                };
                env.insert(name.clone(), val);
            }
            Stmt::LetPattern { pattern, value, .. } => {
                let Some(val) = eval_expr(value, env, functions) else {
                    return EvalOutcome::Continue;
                };
                let mut bindings = BTreeMap::new();
                if bind_pattern_values(pattern, &val, &mut bindings) {
                    for (name, value) in bindings {
                        env.insert(name, value);
                    }
                }
            }
            Stmt::Assign { target, value } => {
                let Some(val) = eval_expr(value, env, functions) else {
                    return EvalOutcome::Continue;
                };
                env.insert(target.clone(), val);
            }
            Stmt::CompoundAssign { target, op, value } => {
                let Some(lhs) = env.get(target).cloned() else {
                    return EvalOutcome::Continue;
                };
                let Some(rhs) = eval_expr(value, env, functions) else {
                    return EvalOutcome::Continue;
                };
                let Some(next) = eval_binary(*op, lhs, rhs) else {
                    return EvalOutcome::Continue;
                };
                env.insert(target.clone(), next);
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let Some(cond) = eval_expr(condition, env, functions) else {
                    return EvalOutcome::Continue;
                };
                let branch = if truthy(&cond) { then_body } else { else_body };
                match eval_block_control(branch, env, functions) {
                    EvalOutcome::Return(v) => {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::Return(v);
                    }
                    EvalOutcome::Break => {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::Break;
                    }
                    EvalOutcome::ContinueLoop => {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::ContinueLoop;
                    }
                    EvalOutcome::Continue => {}
                }
            }
            Stmt::While { condition, body } => {
                let mut guard = 0usize;
                while truthy(&match eval_expr(condition, env, functions) {
                    Some(value) => value,
                    None => {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::Continue;
                    }
                }) {
                    match eval_block_control(body, env, functions) {
                        EvalOutcome::Return(v) => {
                            for expr in deferred.iter().rev() {
                                let _ = eval_expr(expr, env, functions);
                            }
                            return EvalOutcome::Return(v);
                        }
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    guard += 1;
                    if guard > 1_000_000 {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::Continue;
                    }
                }
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    match eval_block_control(std::slice::from_ref(init.as_ref()), env, functions) {
                        EvalOutcome::Return(v) => {
                            for expr in deferred.iter().rev() {
                                let _ = eval_expr(expr, env, functions);
                            }
                            return EvalOutcome::Return(v);
                        }
                        EvalOutcome::Break | EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                }
                let mut guard = 0usize;
                loop {
                    if let Some(condition) = condition {
                        let Some(value) = eval_expr(condition, env, functions) else {
                            for expr in deferred.iter().rev() {
                                let _ = eval_expr(expr, env, functions);
                            }
                            return EvalOutcome::Continue;
                        };
                        if !truthy(&value) {
                            break;
                        }
                    }
                    match eval_block_control(body, env, functions) {
                        EvalOutcome::Return(v) => {
                            for expr in deferred.iter().rev() {
                                let _ = eval_expr(expr, env, functions);
                            }
                            return EvalOutcome::Return(v);
                        }
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    if let Some(step) = step {
                        match eval_block_control(
                            std::slice::from_ref(step.as_ref()),
                            env,
                            functions,
                        ) {
                            EvalOutcome::Return(v) => {
                                for expr in deferred.iter().rev() {
                                    let _ = eval_expr(expr, env, functions);
                                }
                                return EvalOutcome::Return(v);
                            }
                            EvalOutcome::Break
                            | EvalOutcome::ContinueLoop
                            | EvalOutcome::Continue => {}
                        }
                    }
                    guard += 1;
                    if guard > 1_000_000 {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::Continue;
                    }
                }
            }
            Stmt::ForIn {
                binding,
                iterable,
                body,
            } => {
                let Some(range) = eval_expr(iterable, env, functions) else {
                    for expr in deferred.iter().rev() {
                        let _ = eval_expr(expr, env, functions);
                    }
                    return EvalOutcome::Continue;
                };
                let Value::Struct { fields, .. } = range else {
                    continue;
                };
                let Some(Value::I32(mut current)) = fields.get("start").cloned() else {
                    continue;
                };
                let Some(Value::I32(end)) = fields.get("end").cloned() else {
                    continue;
                };
                let inclusive = matches!(fields.get("inclusive"), Some(Value::Bool(true)));
                let mut guard = 0usize;
                while if inclusive {
                    current <= end
                } else {
                    current < end
                } {
                    env.insert(binding.clone(), Value::I32(current));
                    match eval_block_control(body, env, functions) {
                        EvalOutcome::Return(v) => {
                            for expr in deferred.iter().rev() {
                                let _ = eval_expr(expr, env, functions);
                            }
                            return EvalOutcome::Return(v);
                        }
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    current += 1;
                    guard += 1;
                    if guard > 1_000_000 {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::Continue;
                    }
                }
            }
            Stmt::Loop { body } => {
                let mut guard = 0usize;
                loop {
                    match eval_block_control(body, env, functions) {
                        EvalOutcome::Return(v) => {
                            for expr in deferred.iter().rev() {
                                let _ = eval_expr(expr, env, functions);
                            }
                            return EvalOutcome::Return(v);
                        }
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    guard += 1;
                    if guard > 1_000_000 {
                        for expr in deferred.iter().rev() {
                            let _ = eval_expr(expr, env, functions);
                        }
                        return EvalOutcome::Continue;
                    }
                }
            }
            Stmt::Defer(expr) => {
                deferred.push(expr.clone());
            }
            Stmt::Break(value) => {
                if let Some(value) = value {
                    let _ = eval_expr(value, env, functions);
                }
                for expr in deferred.iter().rev() {
                    let _ = eval_expr(expr, env, functions);
                }
                return EvalOutcome::Break;
            }
            Stmt::Continue => {
                for expr in deferred.iter().rev() {
                    let _ = eval_expr(expr, env, functions);
                }
                return EvalOutcome::ContinueLoop;
            }
            Stmt::Return(Some(expr)) => {
                let Some(val) = eval_expr(expr, env, functions) else {
                    for expr in deferred.iter().rev() {
                        let _ = eval_expr(expr, env, functions);
                    }
                    return EvalOutcome::Continue;
                };
                for expr in deferred.iter().rev() {
                    let _ = eval_expr(expr, env, functions);
                }
                return EvalOutcome::Return(val);
            }
            Stmt::Return(None) => {
                for expr in deferred.iter().rev() {
                    let _ = eval_expr(expr, env, functions);
                }
                return EvalOutcome::Return(Value::I32(0));
            }
            Stmt::Match { scrutinee, arms } => {
                let Some(value) = eval_expr(scrutinee, env, functions) else {
                    for expr in deferred.iter().rev() {
                        let _ = eval_expr(expr, env, functions);
                    }
                    return EvalOutcome::Continue;
                };
                for arm in arms {
                    let mut arm_env = env.clone();
                    let mut bindings = BTreeMap::new();
                    if !bind_pattern_values(&arm.pattern, &value, &mut bindings) {
                        continue;
                    }
                    for (name, value) in bindings {
                        arm_env.insert(name, value);
                    }
                    let guard_ok = match &arm.guard {
                        Some(guard) => {
                            let Some(guard_val) = eval_expr(guard, &arm_env, functions) else {
                                for expr in deferred.iter().rev() {
                                    let _ = eval_expr(expr, env, functions);
                                }
                                return EvalOutcome::Continue;
                            };
                            truthy(&guard_val)
                        }
                        None => true,
                    };
                    if guard_ok {
                        if arm.returns {
                            let Some(out) = eval_expr(&arm.value, &arm_env, functions) else {
                                for expr in deferred.iter().rev() {
                                    let _ = eval_expr(expr, env, functions);
                                }
                                return EvalOutcome::Continue;
                            };
                            for expr in deferred.iter().rev() {
                                let _ = eval_expr(expr, env, functions);
                            }
                            return EvalOutcome::Return(out);
                        }
                        let _ = eval_expr(&arm.value, &arm_env, functions);
                        break;
                    }
                }
            }
            Stmt::Requires(_) | Stmt::Ensures(_) | Stmt::Expr(_) => {}
        }
    }
    for expr in deferred.iter().rev() {
        let _ = eval_expr(expr, env, functions);
    }
    EvalOutcome::Continue
}

fn eval_expr<'a>(
    expr: &Expr,
    env: &BTreeMap<String, Value>,
    functions: &HashMap<&'a str, &'a TypedFunction>,
) -> Option<Value> {
    if !const_eval_allow_step() {
        return None;
    }
    fn has_function_ref(functions: &HashMap<&str, &TypedFunction>, candidate: &str) -> bool {
        if functions.contains_key(candidate) {
            return true;
        }
        let suffix = format!(".{candidate}");
        let mut found = false;
        for name in functions.keys() {
            if name.ends_with(&suffix) {
                if found {
                    return false;
                }
                found = true;
            }
        }
        found
    }

    fn resolve_function_ref_name(
        functions: &HashMap<&str, &TypedFunction>,
        candidate: &str,
    ) -> Option<String> {
        if functions.contains_key(candidate) {
            return Some(candidate.to_string());
        }
        let suffix = format!(".{candidate}");
        let mut matched: Option<String> = None;
        for name in functions.keys() {
            if name.ends_with(&suffix) {
                if matched.is_some() {
                    return None;
                }
                matched = Some((*name).to_string());
            }
        }
        matched
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
        Expr::Int(v) => i32::try_from(*v).ok().map(Value::I32),
        Expr::Float { value, .. } => Some(Value::F64(*value)),
        Expr::Char(v) => Some(Value::Char(*v)),
        Expr::Bool(v) => Some(Value::Bool(*v)),
        Expr::Str(v) => Some(Value::Str(v.clone())),
        Expr::Ident(name) => env.get(name).cloned().or_else(|| {
            if has_function_ref(functions, name.as_str()) {
                resolve_function_ref_name(functions, name).map(Value::FnRef)
            } else {
                None
            }
        }),
        Expr::UnsafeBlock { body, .. } => {
            let mut local = env.clone();
            let _ = eval_block(body, &mut local, functions);
            Some(Value::I32(0))
        }
        Expr::Closure {
            params,
            return_type,
            body,
        } => Some(Value::Closure(RuntimeClosure {
            params: params.clone(),
            return_type: return_type.clone(),
            body: body.as_ref().clone(),
            captures: env.clone(),
        })),
        Expr::Group(inner) => eval_expr(inner, env, functions),
        Expr::Tuple(items) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                values.push(eval_expr(item, env, functions)?);
            }
            Some(Value::Tuple(values))
        }
        Expr::Await(inner) => eval_expr(inner, env, functions),
        Expr::Discard(inner) => {
            let _ = eval_expr(inner, env, functions)?;
            Some(Value::I32(0))
        }
        Expr::Return(value) => {
            if let Some(value) = value {
                let _ = eval_expr(value, env, functions)?;
            }
            None
        }
        Expr::Break(value) => {
            if let Some(value) = value {
                let _ = eval_expr(value, env, functions)?;
            }
            None
        }
        Expr::Continue => None,
        Expr::Call { callee, args } => {
            let (callee_name, _) = split_generic_callee(callee);
            let resolved_name = match functions.get(callee_name) {
                Some(_) => Some(callee_name.to_string()),
                None => match env.get(callee_name) {
                    Some(Value::FnRef(function)) => Some(function.clone()),
                    _ => None,
                },
            };
            if let Some(Value::Closure(closure)) = env.get(callee_name) {
                if closure.params.len() != args.len() {
                    return None;
                }
                let mut local = closure.captures.clone();
                for (arg, param) in args.iter().zip(&closure.params) {
                    local.insert(param.name.clone(), eval_expr(arg, env, functions)?);
                }
                let value = eval_expr(&closure.body, &local, functions);
                if value.is_none() {
                    return runtime_default_value(
                        closure.return_type.as_ref().unwrap_or(&Type::Void),
                    );
                }
                return value;
            }
            let Some(resolved_name) = resolved_name else {
                if let Some((_, ret_ty)) = runtime_call_signature(callee_name) {
                    for arg in args {
                        let _ = eval_expr(arg, env, functions)?;
                    }
                    return runtime_default_value(&ret_ty);
                }
                return None;
            };
            let function = functions.get(resolved_name.as_str())?;
            if function.params.len() != args.len() {
                return None;
            }
            let mut local = BTreeMap::new();
            for (arg, param) in args.iter().zip(&function.params) {
                local.insert(param.name.clone(), eval_expr(arg, env, functions)?);
            }
            eval_block(&function.body, &mut local, functions)
        }
        Expr::FieldAccess { base, field } => {
            if let Some(function_ref) = expr_function_ref_name(expr) {
                if has_function_ref(functions, function_ref.as_str()) {
                    return resolve_function_ref_name(functions, function_ref.as_str())
                        .map(Value::FnRef);
                }
            }
            let base = eval_expr(base, env, functions)?;
            match base {
                Value::Struct { fields, .. } => fields.get(field).cloned(),
                _ => None,
            }
        }
        Expr::Unary { op, expr } => {
            let value = eval_expr(expr, env, functions)?;
            match (op, value) {
                (ast::UnaryOp::Not, Value::Bool(v)) => Some(Value::Bool(!v)),
                (ast::UnaryOp::Not, Value::I32(v)) => Some(Value::Bool(v == 0)),
                (ast::UnaryOp::BitNot, Value::I32(v)) => Some(Value::I32(!v)),
                (ast::UnaryOp::Plus, Value::I32(v)) => Some(Value::I32(v)),
                (ast::UnaryOp::Plus, Value::F64(v)) => Some(Value::F64(v)),
                (ast::UnaryOp::Neg, Value::I32(v)) => Some(Value::I32(-v)),
                (ast::UnaryOp::Neg, Value::F64(v)) => Some(Value::F64(-v)),
                _ => None,
            }
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let cond = eval_expr(condition, env, functions)?;
            if truthy(&cond) {
                eval_expr(then_expr, env, functions)
            } else {
                eval_expr(else_expr, env, functions)
            }
        }
        Expr::Match { scrutinee, arms } => {
            let value = eval_expr(scrutinee, env, functions)?;
            for arm in arms {
                let mut arm_env = env.clone();
                let mut bindings = BTreeMap::new();
                if !bind_pattern_values(&arm.pattern, &value, &mut bindings) {
                    continue;
                }
                for (name, value) in bindings {
                    arm_env.insert(name, value);
                }
                let guard_ok = match &arm.guard {
                    Some(guard) => {
                        let guard_val = eval_expr(guard, &arm_env, functions)?;
                        truthy(&guard_val)
                    }
                    None => true,
                };
                if guard_ok {
                    if arm.returns {
                        let _ = eval_expr(&arm.value, &arm_env, functions)?;
                        return None;
                    }
                    return eval_expr(&arm.value, &arm_env, functions);
                }
            }
            Some(Value::I32(0))
        }
        Expr::While { condition, body } => {
            let mut local = env.clone();
            let mut guard = 0usize;
            while truthy(&eval_expr(condition, &local, functions)?) {
                match eval_block_control(body, &mut local, functions) {
                    EvalOutcome::Continue | EvalOutcome::ContinueLoop => {}
                    EvalOutcome::Break => break,
                    EvalOutcome::Return(_) => return None,
                }
                guard += 1;
                if guard > 1_000_000 {
                    return None;
                }
            }
            Some(Value::I32(0))
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            let mut local = env.clone();
            if let Some(init) = init {
                let _ =
                    eval_block_control(std::slice::from_ref(init.as_ref()), &mut local, functions);
            }
            let mut guard = 0usize;
            loop {
                if let Some(condition) = condition {
                    if !truthy(&eval_expr(condition, &local, functions)?) {
                        break;
                    }
                }
                match eval_block_control(body, &mut local, functions) {
                    EvalOutcome::Continue | EvalOutcome::ContinueLoop => {}
                    EvalOutcome::Break => break,
                    EvalOutcome::Return(_) => return None,
                }
                if let Some(step) = step {
                    let _ = eval_block_control(
                        std::slice::from_ref(step.as_ref()),
                        &mut local,
                        functions,
                    );
                }
                guard += 1;
                if guard > 1_000_000 {
                    return None;
                }
            }
            Some(Value::I32(0))
        }
        Expr::ForIn {
            binding,
            iterable,
            body,
        } => {
            let mut local = env.clone();
            let range = eval_expr(iterable, &local, functions)?;
            let Value::Struct { fields, .. } = range else {
                return None;
            };
            let Some(Value::I32(mut current)) = fields.get("start").cloned() else {
                return None;
            };
            let Some(Value::I32(end)) = fields.get("end").cloned() else {
                return None;
            };
            let inclusive = matches!(fields.get("inclusive"), Some(Value::Bool(true)));
            let mut guard = 0usize;
            while if inclusive {
                current <= end
            } else {
                current < end
            } {
                local.insert(binding.clone(), Value::I32(current));
                match eval_block_control(body, &mut local, functions) {
                    EvalOutcome::Continue | EvalOutcome::ContinueLoop => {}
                    EvalOutcome::Break => break,
                    EvalOutcome::Return(_) => return None,
                }
                current += 1;
                guard += 1;
                if guard > 1_000_000 {
                    return None;
                }
            }
            Some(Value::I32(0))
        }
        Expr::Loop { body } => {
            let mut local = env.clone();
            let mut guard = 0usize;
            loop {
                match eval_block_control(body, &mut local, functions) {
                    EvalOutcome::Continue | EvalOutcome::ContinueLoop => {}
                    EvalOutcome::Break => break,
                    EvalOutcome::Return(_) => return None,
                }
                guard += 1;
                if guard > 1_000_000 {
                    return None;
                }
            }
            Some(Value::I32(0))
        }
        Expr::StructInit { name, fields } => {
            let mut map = BTreeMap::new();
            for (field, value) in fields {
                map.insert(field.clone(), eval_expr(value, env, functions)?);
            }
            Some(Value::Struct {
                _name: name.clone(),
                fields: map,
            })
        }
        Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => {
            let mut values =
                Vec::with_capacity(payload.len() + usize::from(!named_payload.is_empty()));
            for value in payload {
                values.push(eval_expr(value, env, functions)?);
            }
            if !named_payload.is_empty() {
                let mut fields = BTreeMap::new();
                for (field, value) in named_payload {
                    fields.insert(field.clone(), eval_expr(value, env, functions)?);
                }
                values.push(Value::Struct {
                    _name: format!("{enum_name}::{variant}"),
                    fields,
                });
            }
            Some(Value::Enum {
                enum_name: enum_name.clone(),
                variant: variant.clone(),
                payload: values,
            })
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => eval_expr(try_expr, env, functions).or_else(|| eval_expr(catch_expr, env, functions)),
        Expr::Range {
            start,
            end,
            inclusive,
        } => {
            let start = eval_expr(start, env, functions)?;
            let end = eval_expr(end, env, functions)?;
            let (Value::I32(start), Value::I32(end)) = (start, end) else {
                return None;
            };
            let mut fields = BTreeMap::new();
            fields.insert("start".to_string(), Value::I32(start));
            fields.insert("end".to_string(), Value::I32(end));
            fields.insert("inclusive".to_string(), Value::Bool(*inclusive));
            Some(Value::Struct {
                _name: "Range".to_string(),
                fields,
            })
        }
        Expr::ArrayLiteral(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(eval_expr(item, env, functions)?);
            }
            Some(Value::List(out))
        }
        Expr::ObjectLiteral(fields) => {
            let mut out = BTreeMap::new();
            for (key, value) in fields {
                out.insert(key.clone(), eval_expr(value, env, functions)?);
            }
            Some(Value::Struct {
                _name: "ObjectLiteral".to_string(),
                fields: out,
            })
        }
        Expr::Index { base, index } => {
            let base = eval_expr(base, env, functions)?;
            let index = eval_expr(index, env, functions)?;
            let Value::I32(index) = index else {
                return None;
            };
            let Ok(index) = usize::try_from(index) else {
                return None;
            };
            match base {
                Value::List(items) => items.get(index).cloned(),
                Value::Str(text) => text.chars().nth(index).map(Value::Char),
                _ => None,
            }
        }
        Expr::Binary { op, left, right } => match op {
            BinaryOp::And => {
                let left = eval_expr(left, env, functions)?;
                if !truthy(&left) {
                    Some(Value::Bool(false))
                } else {
                    let right = eval_expr(right, env, functions)?;
                    Some(Value::Bool(truthy(&right)))
                }
            }
            BinaryOp::Or => {
                let left = eval_expr(left, env, functions)?;
                if truthy(&left) {
                    Some(Value::Bool(true))
                } else {
                    let right = eval_expr(right, env, functions)?;
                    Some(Value::Bool(truthy(&right)))
                }
            }
            _ => {
                let left = eval_expr(left, env, functions)?;
                let right = eval_expr(right, env, functions)?;
                eval_binary(*op, left, right)
            }
        },
    }
}

fn eval_binary(op: BinaryOp, left: Value, right: Value) -> Option<Value> {
    match (op, left, right) {
        (BinaryOp::Add, Value::I32(a), Value::I32(b)) => Some(Value::I32(a + b)),
        (BinaryOp::Add, Value::F64(a), Value::F64(b)) => Some(Value::F64(a + b)),
        (BinaryOp::Sub, Value::I32(a), Value::I32(b)) => Some(Value::I32(a - b)),
        (BinaryOp::Sub, Value::F64(a), Value::F64(b)) => Some(Value::F64(a - b)),
        (BinaryOp::Mul, Value::I32(a), Value::I32(b)) => Some(Value::I32(a * b)),
        (BinaryOp::Mul, Value::F64(a), Value::F64(b)) => Some(Value::F64(a * b)),
        (BinaryOp::Div, Value::I32(a), Value::I32(b)) => Some(Value::I32(a / b)),
        (BinaryOp::Div, Value::F64(a), Value::F64(b)) => Some(Value::F64(a / b)),
        (BinaryOp::Mod, Value::I32(a), Value::I32(b)) => Some(Value::I32(a % b)),
        (BinaryOp::BitAnd, Value::I32(a), Value::I32(b)) => Some(Value::I32(a & b)),
        (BinaryOp::BitOr, Value::I32(a), Value::I32(b)) => Some(Value::I32(a | b)),
        (BinaryOp::BitXor, Value::I32(a), Value::I32(b)) => Some(Value::I32(a ^ b)),
        (BinaryOp::Shl, Value::I32(a), Value::I32(b)) => Some(Value::I32(a << b)),
        (BinaryOp::Shr, Value::I32(a), Value::I32(b)) => Some(Value::I32(a >> b)),
        (BinaryOp::And, Value::Bool(a), Value::Bool(b)) => Some(Value::Bool(a && b)),
        (BinaryOp::Or, Value::Bool(a), Value::Bool(b)) => Some(Value::Bool(a || b)),
        (BinaryOp::Eq, Value::I32(a), Value::I32(b)) => Some(Value::Bool(a == b)),
        (BinaryOp::Neq, Value::I32(a), Value::I32(b)) => Some(Value::Bool(a != b)),
        (BinaryOp::Lt, Value::I32(a), Value::I32(b)) => Some(Value::Bool(a < b)),
        (BinaryOp::Lte, Value::I32(a), Value::I32(b)) => Some(Value::Bool(a <= b)),
        (BinaryOp::Gt, Value::I32(a), Value::I32(b)) => Some(Value::Bool(a > b)),
        (BinaryOp::Gte, Value::I32(a), Value::I32(b)) => Some(Value::Bool(a >= b)),
        (BinaryOp::Eq, Value::Bool(a), Value::Bool(b)) => Some(Value::Bool(a == b)),
        (BinaryOp::Neq, Value::Bool(a), Value::Bool(b)) => Some(Value::Bool(a != b)),
        (BinaryOp::Eq, Value::Str(a), Value::Str(b)) => Some(Value::Bool(a == b)),
        (BinaryOp::Neq, Value::Str(a), Value::Str(b)) => Some(Value::Bool(a != b)),
        (BinaryOp::Eq, Value::F64(a), Value::F64(b)) => Some(Value::Bool(a == b)),
        (BinaryOp::Neq, Value::F64(a), Value::F64(b)) => Some(Value::Bool(a != b)),
        (BinaryOp::Lt, Value::F64(a), Value::F64(b)) => Some(Value::Bool(a < b)),
        (BinaryOp::Lte, Value::F64(a), Value::F64(b)) => Some(Value::Bool(a <= b)),
        (BinaryOp::Gt, Value::F64(a), Value::F64(b)) => Some(Value::Bool(a > b)),
        (BinaryOp::Gte, Value::F64(a), Value::F64(b)) => Some(Value::Bool(a >= b)),
        (BinaryOp::Eq, Value::Char(a), Value::Char(b)) => Some(Value::Bool(a == b)),
        (BinaryOp::Neq, Value::Char(a), Value::Char(b)) => Some(Value::Bool(a != b)),
        _ => None,
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(v) => *v,
        Value::I32(v) => *v != 0,
        Value::F64(v) => *v != 0.0,
        Value::Char(v) => *v != '\0',
        Value::Str(v) => !v.is_empty(),
        Value::Tuple(v) => !v.is_empty(),
        Value::List(v) => !v.is_empty(),
        Value::FnRef(_) | Value::Closure(_) | Value::Struct { .. } | Value::Enum { .. } => true,
    }
}

fn bind_pattern_values(
    pattern: &ast::Pattern,
    value: &Value,
    bindings: &mut BTreeMap<String, Value>,
) -> bool {
    match (pattern, value) {
        (ast::Pattern::Wildcard, _) => true,
        (ast::Pattern::Int(a), Value::I32(b)) => i128::from(*b) == *a,
        (ast::Pattern::Bool(a), Value::Bool(b)) => a == b,
        (ast::Pattern::Ident(name), value) => {
            bindings.insert(name.clone(), value.clone());
            true
        }
        (ast::Pattern::Tuple(pattern_items), Value::Tuple(value_items)) => {
            if pattern_items.len() != value_items.len() {
                return false;
            }
            for (pattern_item, value_item) in pattern_items.iter().zip(value_items.iter()) {
                if !bind_pattern_values(pattern_item, value_item, bindings) {
                    return false;
                }
            }
            true
        }
        (
            ast::Pattern::Struct {
                name,
                fields: pattern_fields,
            },
            Value::Struct {
                _name: value_name,
                fields,
            },
        ) => {
            if name != value_name {
                return false;
            }
            for (field_name, binding_name) in pattern_fields {
                let Some(field_value) = fields.get(field_name) else {
                    return false;
                };
                if binding_name != "_" {
                    bindings.insert(binding_name.clone(), field_value.clone());
                }
            }
            true
        }
        (
            ast::Pattern::Variant {
                enum_name,
                variant,
                bindings: pattern_bindings,
                named_bindings: pattern_named_bindings,
            },
            Value::Enum {
                enum_name: value_enum_name,
                variant: value_variant,
                payload,
            },
        ) => {
            if enum_name != value_enum_name || variant != value_variant {
                return false;
            }
            if pattern_named_bindings.is_empty() {
                if pattern_bindings.len() != payload.len() {
                    return false;
                }
                for (name, value) in pattern_bindings.iter().zip(payload.iter()) {
                    bindings.insert(name.clone(), value.clone());
                }
                return true;
            }
            if !pattern_bindings.is_empty() || payload.len() != 1 {
                return false;
            }
            let Value::Struct { fields, .. } = &payload[0] else {
                return false;
            };
            for (field_name, binding_name) in pattern_named_bindings {
                let Some(field_value) = fields.get(field_name) else {
                    return false;
                };
                if binding_name != "_" {
                    bindings.insert(binding_name.clone(), field_value.clone());
                }
            }
            true
        }
        (ast::Pattern::Variant { .. }, _) => false,
        (ast::Pattern::Struct { .. }, _) => false,
        (ast::Pattern::Tuple(_), _) => false,
        (ast::Pattern::Or(patterns), value) => {
            for candidate in patterns {
                let mut local = bindings.clone();
                if bind_pattern_values(candidate, value, &mut local) {
                    *bindings = local;
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn pattern_is_catchall(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => true,
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_is_catchall),
        ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Struct { .. }
        | ast::Pattern::Variant { .. } => false,
    }
}

fn collect_pattern_bindings(pattern: &ast::Pattern, out: &mut BTreeSet<String>) {
    match pattern {
        ast::Pattern::Ident(name) => {
            out.insert(name.clone());
        }
        ast::Pattern::Tuple(items) => {
            for item in items {
                collect_pattern_bindings(item, out);
            }
        }
        ast::Pattern::Struct { fields, .. } => {
            for (_, binding) in fields {
                out.insert(binding.clone());
            }
        }
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => {
            for binding in bindings {
                out.insert(binding.clone());
            }
            for (_, binding) in named_bindings {
                if binding != "_" {
                    out.insert(binding.clone());
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            for candidate in patterns {
                collect_pattern_bindings(candidate, out);
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => {}
    }
}

fn eval_bool_expr(
    expr: &Expr,
    env: &BTreeMap<String, Value>,
    functions: &[TypedFunction],
    fn_sigs: &HashMap<String, (Vec<Type>, Type)>,
) -> Option<bool> {
    let map = functions
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect::<HashMap<_, _>>();
    let _ = fn_sigs;
    match eval_expr(expr, env, &map)? {
        Value::Bool(v) => Some(v),
        Value::I32(v) => Some(v != 0),
        Value::F64(v) => Some(v != 0.0),
        Value::Char(v) => Some(v != '\0'),
        Value::Str(v) => Some(!v.is_empty()),
        Value::Tuple(v) => Some(!v.is_empty()),
        Value::List(v) => Some(!v.is_empty()),
        Value::FnRef(_) | Value::Closure(_) | Value::Struct { .. } | Value::Enum { .. } => {
            Some(true)
        }
    }
}

