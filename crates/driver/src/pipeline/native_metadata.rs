use std::collections::{BTreeSet, HashMap, HashSet};

use super::{eval_const_string_expr, native_mangle_symbol};

pub(super) fn collect_string_literals(fir: &fir::FirModule) -> Vec<String> {
    let mut literals = HashSet::<String>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_string_literals_from_stmt(stmt, &mut literals);
        }
    }
    let mut literals = literals.into_iter().collect::<Vec<_>>();
    literals.sort();
    literals
}

pub(super) fn collect_folded_temp_string_literals(fir: &fir::FirModule) -> Vec<String> {
    fn collect_from_body(
        body: &[ast::Stmt],
        const_strings: &mut HashMap<String, String>,
        out: &mut HashSet<String>,
    ) {
        for stmt in body {
            collect_from_stmt(stmt, const_strings, out);
        }
    }

    fn collect_from_stmt(
        stmt: &ast::Stmt,
        const_strings: &mut HashMap<String, String>,
        out: &mut HashSet<String>,
    ) {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                collect_from_expr(value, const_strings, out);
                if let Some(value) = eval_const_string_expr(value, const_strings) {
                    const_strings.insert(name.clone(), value);
                } else {
                    const_strings.remove(name);
                }
            }
            ast::Stmt::Assign { target, value } => {
                collect_from_expr(value, const_strings, out);
                if let Some(value) = eval_const_string_expr(value, const_strings) {
                    const_strings.insert(target.clone(), value);
                } else {
                    const_strings.remove(target);
                }
            }
            ast::Stmt::CompoundAssign { target, value, .. } => {
                collect_from_expr(value, const_strings, out);
                const_strings.remove(target);
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => collect_from_expr(value, const_strings, out),
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    collect_from_expr(value, const_strings, out);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_from_expr(condition, const_strings, out);
                collect_from_body(then_body, &mut const_strings.clone(), out);
                collect_from_body(else_body, &mut const_strings.clone(), out);
            }
            ast::Stmt::While { condition, body } => {
                collect_from_expr(condition, const_strings, out);
                collect_from_body(body, &mut const_strings.clone(), out);
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_from_stmt(init, &mut const_strings.clone(), out);
                }
                if let Some(condition) = condition {
                    collect_from_expr(condition, const_strings, out);
                }
                if let Some(step) = step {
                    collect_from_stmt(step, &mut const_strings.clone(), out);
                }
                collect_from_body(body, &mut const_strings.clone(), out);
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                collect_from_expr(iterable, const_strings, out);
                collect_from_body(body, &mut const_strings.clone(), out);
            }
            ast::Stmt::Loop { body } => collect_from_body(body, &mut const_strings.clone(), out),
            ast::Stmt::Match { scrutinee, arms } => {
                collect_from_expr(scrutinee, const_strings, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_from_expr(guard, const_strings, out);
                    }
                    collect_from_expr(&arm.value, const_strings, out);
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }

    fn collect_from_expr(
        expr: &ast::Expr,
        const_strings: &HashMap<String, String>,
        out: &mut HashSet<String>,
    ) {
        if let Some(value) = eval_const_string_expr(expr, const_strings) {
            out.insert(value);
        }
        match expr {
            ast::Expr::Call { args, .. } => {
                for arg in args {
                    collect_from_expr(arg, const_strings, out);
                }
            }
            ast::Expr::UnsafeBlock { .. } => {}
            ast::Expr::FieldAccess { base, .. } => collect_from_expr(base, const_strings, out),
            ast::Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    collect_from_expr(value, const_strings, out);
                }
            }
            ast::Expr::EnumInit { payload, .. } | ast::Expr::ArrayLiteral(payload) => {
                for value in payload {
                    collect_from_expr(value, const_strings, out);
                }
            }
            ast::Expr::ObjectLiteral(fields) => {
                for (key, value) in fields {
                    out.insert(key.clone());
                    collect_from_expr(value, const_strings, out);
                }
            }
            ast::Expr::Closure { body, .. }
            | ast::Expr::Group(body)
            | ast::Expr::Await(body)
            | ast::Expr::Discard(body) => collect_from_expr(body, const_strings, out),
            ast::Expr::Unary { expr, .. } => collect_from_expr(expr, const_strings, out),
            ast::Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                collect_from_expr(try_expr, const_strings, out);
                collect_from_expr(catch_expr, const_strings, out);
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                collect_from_expr(condition, const_strings, out);
                collect_from_expr(then_expr, const_strings, out);
                collect_from_expr(else_expr, const_strings, out);
            }
            ast::Expr::Binary { left, right, .. } => {
                collect_from_expr(left, const_strings, out);
                collect_from_expr(right, const_strings, out);
            }
            ast::Expr::Range { start, end, .. } => {
                collect_from_expr(start, const_strings, out);
                collect_from_expr(end, const_strings, out);
            }
            ast::Expr::Index { base, index } => {
                collect_from_expr(base, const_strings, out);
                collect_from_expr(index, const_strings, out);
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

    let mut out = HashSet::<String>::new();
    for function in &fir.typed_functions {
        collect_from_body(&function.body, &mut HashMap::new(), &mut out);
    }
    let mut out = out.into_iter().collect::<Vec<_>>();
    out.sort();
    out
}

pub(super) fn collect_native_string_literals(fir: &fir::FirModule) -> Vec<String> {
    let mut merged = collect_string_literals(fir).into_iter().collect::<HashSet<_>>();
    for folded in collect_folded_temp_string_literals(fir) {
        merged.insert(folded);
    }
    let mut merged = merged.into_iter().collect::<Vec<_>>();
    merged.sort();
    merged
}

fn collect_string_literals_from_stmt(stmt: &ast::Stmt, literals: &mut HashSet<String>) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_string_literals_from_expr(value, literals),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_string_literals_from_expr(condition, literals);
            for nested in then_body {
                collect_string_literals_from_stmt(nested, literals);
            }
            for nested in else_body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_string_literals_from_expr(condition, literals);
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_string_literals_from_stmt(init, literals);
            }
            if let Some(condition) = condition {
                collect_string_literals_from_expr(condition, literals);
            }
            if let Some(step) = step {
                collect_string_literals_from_stmt(step, literals);
            }
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_string_literals_from_expr(iterable, literals);
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_string_literals_from_expr(scrutinee, literals);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_string_literals_from_expr(guard, literals);
                }
                collect_string_literals_from_expr(&arm.value, literals);
            }
        }
    }
}

fn collect_string_literals_from_expr(expr: &ast::Expr, literals: &mut HashSet<String>) {
    match expr {
        ast::Expr::Str(value) => {
            literals.insert(value.clone());
        }
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_string_literals_from_expr(arg, literals);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => collect_string_literals_from_expr(base, literals),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            for (key, value) in fields {
                literals.insert(key.clone());
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_string_literals_from_expr(body, literals);
        }
        ast::Expr::Group(inner) => collect_string_literals_from_expr(inner, literals),
        ast::Expr::Await(inner) => collect_string_literals_from_expr(inner, literals),
        ast::Expr::Discard(inner) => collect_string_literals_from_expr(inner, literals),
        ast::Expr::Unary { expr, .. } => collect_string_literals_from_expr(expr, literals),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_string_literals_from_expr(try_expr, literals);
            collect_string_literals_from_expr(catch_expr, literals);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_string_literals_from_expr(condition, literals);
            collect_string_literals_from_expr(then_expr, literals);
            collect_string_literals_from_expr(else_expr, literals);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_string_literals_from_expr(left, literals);
            collect_string_literals_from_expr(right, literals);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_string_literals_from_expr(start, literals);
            collect_string_literals_from_expr(end, literals);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_string_literals_from_expr(item, literals);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_string_literals_from_expr(base, literals);
            collect_string_literals_from_expr(index, literals);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

pub(super) fn build_string_literal_ids(literals: &[String]) -> HashMap<String, i32> {
    literals
        .iter()
        .enumerate()
        .map(|(index, value)| (value.clone(), index as i32 + 1))
        .collect()
}

pub(super) fn build_global_const_i32_map(fir: &fir::FirModule) -> HashMap<String, i32> {
    fir.typed_globals
        .iter()
        .filter_map(|item| {
            if item.is_static && item.mutable {
                None
            } else {
                item.const_i32.map(|value| (item.name.clone(), value))
            }
        })
        .collect()
}

pub(super) fn build_mutable_static_i32_map(fir: &fir::FirModule) -> HashMap<String, i32> {
    fir.typed_globals
        .iter()
        .filter_map(|item| {
            if item.is_static && item.mutable {
                item.const_i32.map(|value| (item.name.clone(), value))
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn llvm_static_symbol_name(name: &str) -> String {
    format!("fz_static_{}", native_mangle_symbol(name))
}

pub(super) fn collect_spawn_task_symbols(fir: &fir::FirModule) -> Vec<String> {
    fir.typed_functions
        .iter()
        .filter(|function| function.params.is_empty())
        .map(|function| function.name.clone())
        .collect()
}

pub(super) fn build_variant_tag_map(fir: &fir::FirModule) -> HashMap<String, i32> {
    let mut keys = BTreeSet::<String>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_variant_keys_from_stmt(stmt, &mut keys);
        }
    }
    keys.into_iter()
        .enumerate()
        .map(|(idx, key)| (key, idx as i32 + 1))
        .collect()
}

pub(super) fn collect_passthrough_function_map_from_typed(
    functions: &[hir::TypedFunction],
) -> HashMap<String, usize> {
    let mut passthrough = HashMap::<String, usize>::new();
    for function in functions {
        if function.params.is_empty() || function.body.len() != 1 {
            continue;
        }
        let ast::Stmt::Return(Some(ast::Expr::Ident(name))) = &function.body[0] else {
            continue;
        };
        if let Some((index, _)) = function
            .params
            .iter()
            .enumerate()
            .find(|(_, param)| &param.name == name)
        {
            passthrough.insert(function.name.clone(), index);
        }
    }
    passthrough
}

pub(super) fn collect_passthrough_function_map_from_module(
    module: &ast::Module,
) -> HashMap<String, usize> {
    let mut passthrough = HashMap::<String, usize>::new();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        if function.params.is_empty() || function.body.len() != 1 {
            continue;
        }
        let ast::Stmt::Return(Some(ast::Expr::Ident(name))) = &function.body[0] else {
            continue;
        };
        if let Some((index, _)) = function
            .params
            .iter()
            .enumerate()
            .find(|(_, param)| &param.name == name)
        {
            passthrough.insert(function.name.clone(), index);
        }
    }
    passthrough
}

pub(super) fn collect_variant_keys_from_stmt(stmt: &ast::Stmt, out: &mut BTreeSet<String>) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_variant_keys_from_expr(value, out),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_variant_keys_from_expr(value, out);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_variant_keys_from_expr(condition, out);
            for nested in then_body {
                collect_variant_keys_from_stmt(nested, out);
            }
            for nested in else_body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_variant_keys_from_expr(condition, out);
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_variant_keys_from_stmt(init, out);
            }
            if let Some(condition) = condition {
                collect_variant_keys_from_expr(condition, out);
            }
            if let Some(step) = step {
                collect_variant_keys_from_stmt(step, out);
            }
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_variant_keys_from_expr(iterable, out);
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_variant_keys_from_expr(scrutinee, out);
            for arm in arms {
                collect_variant_keys_from_pattern(&arm.pattern, out);
                if let Some(guard) = &arm.guard {
                    collect_variant_keys_from_expr(guard, out);
                }
                collect_variant_keys_from_expr(&arm.value, out);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_variant_keys_from_expr(expr: &ast::Expr, out: &mut BTreeSet<String>) {
    match expr {
        ast::Expr::EnumInit {
            enum_name, variant, ..
        } => {
            out.insert(format!("{enum_name}::{variant}"));
        }
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_variant_keys_from_expr(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => collect_variant_keys_from_expr(base, out),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_variant_keys_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_variant_keys_from_expr(body, out),
        ast::Expr::Group(inner) => collect_variant_keys_from_expr(inner, out),
        ast::Expr::Await(inner) => collect_variant_keys_from_expr(inner, out),
        ast::Expr::Discard(inner) => collect_variant_keys_from_expr(inner, out),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_variant_keys_from_expr(try_expr, out);
            collect_variant_keys_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_variant_keys_from_expr(condition, out);
            collect_variant_keys_from_expr(then_expr, out);
            collect_variant_keys_from_expr(else_expr, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_variant_keys_from_expr(start, out);
            collect_variant_keys_from_expr(end, out);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_variant_keys_from_expr(item, out);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_variant_keys_from_expr(base, out);
            collect_variant_keys_from_expr(index, out);
        }
        ast::Expr::Unary { expr, .. } => collect_variant_keys_from_expr(expr, out),
        ast::Expr::Binary { left, right, .. } => {
            collect_variant_keys_from_expr(left, out);
            collect_variant_keys_from_expr(right, out);
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

fn collect_variant_keys_from_pattern(pattern: &ast::Pattern, out: &mut BTreeSet<String>) {
    match pattern {
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            out.insert(format!("{enum_name}::{variant}"));
        }
        ast::Pattern::Or(patterns) => {
            for nested in patterns {
                collect_variant_keys_from_pattern(nested, out);
            }
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_)
        | ast::Pattern::Struct { .. } => {}
    }
}
