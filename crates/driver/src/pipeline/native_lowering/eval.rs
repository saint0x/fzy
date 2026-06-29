use super::super::llvm::{
    llvm_emit_array_literal_value, llvm_emit_binary_expr, llvm_emit_complex_expr,
    llvm_emit_simple_expr, llvm_float_literal, LlvmFuncCtx, LlvmValue,
};
use super::*;

pub(crate) fn llvm_emit_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    if let Some(result) = llvm_emit_complex_expr(expr, ctx, string_literal_ids, task_ref_ids) {
        return result;
    }
    if let Some(result) = llvm_emit_simple_expr(expr, ctx, string_literal_ids, task_ref_ids) {
        return result;
    }
    Ok(match expr {
        ast::Expr::Int(v) => {
            let ty = if i32::try_from(*v).is_ok() {
                "i32"
            } else {
                "i64"
            };
            LlvmValue {
                value: v.to_string(),
                ty: ty.to_string(),
            }
        }
        ast::Expr::Float { value, bits } => LlvmValue {
            value: llvm_float_literal(*value),
            ty: if bits.unwrap_or(64) == 32 {
                "float".to_string()
            } else {
                "double".to_string()
            },
        },
        ast::Expr::Char(value) => LlvmValue {
            value: (*value as i32).to_string(),
            ty: "i32".to_string(),
        },
        ast::Expr::Bool(v) => LlvmValue {
            value: if *v { "1".to_string() } else { "0".to_string() },
            ty: "i8".to_string(),
        },
        ast::Expr::Str(value) => LlvmValue {
            value: string_literal_ids
                .get(value)
                .copied()
                .unwrap_or(0)
                .to_string(),
            ty: "i32".to_string(),
        },
        ast::Expr::Ident(_) => unreachable!("simple expressions are handled above"),
        ast::Expr::Group(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?,
        ast::Expr::Await(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?,
        ast::Expr::Discard(_) => unreachable!("simple expressions are handled above"),
        ast::Expr::Closure { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::Unary { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::FieldAccess { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::StructInit { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::EnumInit { .. } => unreachable!("simple expressions are handled above"),
        ast::Expr::TryCatch { try_expr, .. } => {
            llvm_emit_expr(try_expr, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::If { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Range { start, .. } => {
            llvm_emit_expr(start, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::ArrayLiteral(items) => {
            llvm_emit_array_literal_value(items, ctx, string_literal_ids, task_ref_ids)?
        }
        ast::Expr::ObjectLiteral(_) => unreachable!("complex expressions are handled above"),
        ast::Expr::Index { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Call { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::UnsafeBlock { .. } => unreachable!("complex expressions are handled above"),
        ast::Expr::Binary { op, left, right } => {
            llvm_emit_binary_expr(*op, left, right, ctx, string_literal_ids, task_ref_ids)?
        }
        _ => LlvmValue {
            value: "0".to_string(),
            ty: "i32".to_string(),
        },
    })
}

pub(crate) fn expr_task_ref_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::FieldAccess { base, field } => {
            let mut name = expr_task_ref_name(base)?;
            name.push('.');
            name.push_str(field);
            Some(name)
        }
        ast::Expr::Group(inner) => expr_task_ref_name(inner),
        ast::Expr::Unary { expr, .. } => expr_task_ref_name(expr),
        _ => None,
    }
}

pub(crate) fn eval_const_string_expr(
    expr: &ast::Expr,
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        ast::Expr::Str(value) => Some(value.clone()),
        ast::Expr::Ident(name) => const_strings.get(name).cloned(),
        ast::Expr::Group(inner) => eval_const_string_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_string_call(callee, args, const_strings),
        _ => None,
    }
}

pub(crate) fn eval_const_string_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match callee {
        "str.concat2" if args.len() == 2 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            Some(format!("{a}{b}"))
        }
        "str.concat3" if args.len() == 3 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            Some(format!("{a}{b}{c}"))
        }
        "str.concat4" if args.len() == 4 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            let d = eval_const_string_expr(&args[3], const_strings)?;
            Some(format!("{a}{b}{c}{d}"))
        }
        "str.concat" if !args.is_empty() => {
            let mut out = String::new();
            for arg in args {
                out.push_str(&eval_const_string_expr(arg, const_strings)?);
            }
            Some(out)
        }
        "str.trim" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.trim().to_string())
        }
        "str.replace" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let from = eval_const_string_expr(&args[1], const_strings)?;
            let to = eval_const_string_expr(&args[2], const_strings)?;
            Some(value.replace(&from, &to))
        }
        "str.slice" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let start = eval_const_i32_expr(&args[1], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let end = eval_const_i32_expr(&args[2], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let len = value.len();
            let s = start.min(len);
            let e = end.min(len);
            if value.is_char_boundary(s) && value.is_char_boundary(e) {
                if e >= s {
                    Some(value[s..e].to_string())
                } else {
                    Some(String::new())
                }
            } else {
                None
            }
        }
        "str.upper_ascii" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.to_ascii_uppercase())
        }
        "str.lower_ascii" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.to_ascii_lowercase())
        }
        _ => None,
    }
}

pub(crate) fn eval_const_i32_expr(
    expr: &ast::Expr,
    const_strings: &HashMap<String, String>,
) -> Option<i32> {
    match expr {
        ast::Expr::Int(value) => i32::try_from(*value).ok(),
        ast::Expr::Bool(value) => Some(if *value { 1 } else { 0 }),
        ast::Expr::Group(inner) => eval_const_i32_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_i32_call(callee, args, const_strings),
        _ => None,
    }
}

pub(crate) fn eval_const_i32_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<i32> {
    match callee {
        "str.contains" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let needle = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.contains(&needle) { 1 } else { 0 })
        }
        "str.starts_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let prefix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.starts_with(&prefix) { 1 } else { 0 })
        }
        "str.ends_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let suffix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.ends_with(&suffix) { 1 } else { 0 })
        }
        "str.len" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            i32::try_from(value.len()).ok()
        }
        _ => None,
    }
}

pub(crate) fn is_native_data_plane_string_call(callee: &str) -> bool {
    matches!(callee, "str.concat")
        || native_data_plane_import_for_callee(callee)
            .is_some_and(|import| import.callee.starts_with("str."))
}

pub(crate) fn canonicalize_array_index_window(expr: &ast::Expr) -> Option<(String, i32)> {
    match expr {
        ast::Expr::Ident(name) => Some((name.clone(), 0)),
        ast::Expr::Group(inner) => canonicalize_array_index_window(inner),
        ast::Expr::Binary { op, left, right } => match op {
            ast::BinaryOp::Add => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                (ast::Expr::Int(offset), ast::Expr::Ident(name)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                _ => None,
            },
            ast::BinaryOp::Sub => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => i32::try_from(*offset)
                    .ok()
                    .and_then(|off| off.checked_neg())
                    .map(|off| (name.clone(), off)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn collect_used_runtime_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_runtime_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_runtime_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_runtime_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_runtime_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_runtime_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_runtime_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_runtime_imports_from_expr(guard, seen, used);
                }
                collect_used_runtime_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

pub(crate) fn collect_used_runtime_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let empty_const_strings = HashMap::<String, String>::new();
            let folded_const = eval_const_string_call(callee, args, &empty_const_strings).is_some()
                || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
            if !folded_const {
                if let Some(import) = native_runtime_import_for_callee(callee) {
                    if seen.insert(import.symbol) {
                        used.push(import);
                    }
                }
            }
            for arg in args {
                collect_used_runtime_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_used_runtime_imports_from_stmt(stmt, seen, used);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            if let Some(import) = native_runtime_import_for_callee("map.new") {
                if seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            if let Some(import) = native_runtime_import_for_callee("map.set") {
                if seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for (_, value) in fields {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_runtime_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_runtime_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_runtime_imports_from_expr(try_expr, seen, used);
            collect_used_runtime_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            collect_used_runtime_imports_from_expr(then_expr, seen, used);
            collect_used_runtime_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_runtime_imports_from_expr(left, seen, used);
            collect_used_runtime_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_runtime_imports_from_expr(start, seen, used);
            collect_used_runtime_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_runtime_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
            collect_used_runtime_imports_from_expr(index, seen, used);
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

pub(crate) fn collect_used_data_plane_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_data_plane_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_data_plane_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_data_plane_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_data_plane_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_data_plane_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_data_plane_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_data_plane_imports_from_expr(guard, seen, used);
                }
                collect_used_data_plane_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

pub(crate) fn collect_used_data_plane_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(import) = native_data_plane_import_for_callee(callee) {
                let empty_const_strings = HashMap::<String, String>::new();
                let folded_const = eval_const_string_call(callee, args, &empty_const_strings)
                    .is_some()
                    || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
                let can_skip = folded_const && callee.starts_with("str.");
                if !can_skip && seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for arg in args {
                collect_used_data_plane_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_used_data_plane_imports_from_stmt(stmt, seen, used);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_data_plane_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_data_plane_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_data_plane_imports_from_expr(try_expr, seen, used);
            collect_used_data_plane_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            collect_used_data_plane_imports_from_expr(then_expr, seen, used);
            collect_used_data_plane_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_data_plane_imports_from_expr(left, seen, used);
            collect_used_data_plane_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_data_plane_imports_from_expr(start, seen, used);
            collect_used_data_plane_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_data_plane_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
            collect_used_data_plane_imports_from_expr(index, seen, used);
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
