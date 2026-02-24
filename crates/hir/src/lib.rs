use std::collections::BTreeMap;

use ast::Module;

#[derive(Debug, Clone)]
pub struct TypedModule {
    pub name: String,
    pub symbol_count: usize,
    pub capabilities: Vec<String>,
    pub inferred_capabilities: Vec<String>,
    pub entry_return_type: Option<String>,
    pub entry_return_const_i32: Option<i32>,
    pub linear_resources: Vec<String>,
    pub deferred_resources: Vec<String>,
    pub matches_without_wildcard: usize,
    pub entry_requires: Vec<Option<bool>>,
    pub entry_ensures: Vec<Option<bool>>,
    pub host_syscall_sites: usize,
    pub unsafe_sites: usize,
    pub unsafe_reasoned_sites: usize,
    pub reference_sites: usize,
    pub alloc_sites: usize,
    pub free_sites: usize,
    pub extern_c_abi_functions: usize,
    pub repr_c_layout_items: usize,
    pub generic_instantiations: Vec<String>,
}

pub fn lower(module: &Module) -> TypedModule {
    let entry_return_type = module.items.iter().find_map(|item| match item {
        ast::Item::Function(function) if function.name == "main" => {
            Some(function.return_type.clone())
        }
        _ => None,
    });
    let entry_return_const_i32 = module.items.iter().find_map(|item| match item {
        ast::Item::Function(function) if function.name == "main" => {
            evaluate_const_return(&function.body)
        }
        _ => None,
    });
    let (linear_resources, deferred_resources, matches_without_wildcard) =
        collect_semantic_hints(module);
    let (entry_requires, entry_ensures) = collect_entry_contracts(module);
    let extern_c_abi_functions = module
        .items
        .iter()
        .filter(|item| {
            matches!(
                item,
                ast::Item::Function(function)
                    if function.is_extern
                        && function
                            .abi
                            .as_deref()
                            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
            )
        })
        .count();
    let repr_c_layout_items = module
        .items
        .iter()
        .filter(|item| {
            matches!(
                item,
                ast::Item::Struct(ast::Struct { repr: Some(repr), .. })
                    | ast::Item::Enum(ast::Enum { repr: Some(repr), .. })
                    if repr.to_ascii_lowercase().contains('c')
            )
        })
        .count();
    let generic_instantiations = collect_generic_instantiations(module);

    TypedModule {
        name: module.name.clone(),
        symbol_count: module.items.len(),
        capabilities: module.capabilities.clone(),
        inferred_capabilities: module.inferred_capabilities.clone(),
        entry_return_type,
        entry_return_const_i32,
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
        entry_requires,
        entry_ensures,
        host_syscall_sites: module.host_syscall_sites,
        unsafe_sites: module.unsafe_sites,
        unsafe_reasoned_sites: module.unsafe_reasoned_sites,
        reference_sites: module.reference_sites,
        alloc_sites: module.alloc_sites,
        free_sites: module.free_sites,
        extern_c_abi_functions,
        repr_c_layout_items,
        generic_instantiations,
    }
}

fn collect_generic_instantiations(module: &Module) -> Vec<String> {
    let mut out = Vec::new();
    for item in &module.items {
        match item {
            ast::Item::Function(function) => {
                collect_type_instantiation(&function.return_type, &mut out);
                for param in &function.params {
                    collect_type_instantiation(&param.ty, &mut out);
                }
                for statement in &function.body {
                    if let ast::Stmt::Let { ty: Some(ty), .. } = statement {
                        collect_type_instantiation(ty, &mut out);
                    }
                }
            }
            ast::Item::Struct(_) | ast::Item::Enum(_) | ast::Item::Test(_) => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

fn collect_type_instantiation(ty: &str, out: &mut Vec<String>) {
    let trimmed = ty.trim();
    if let Some(open) = trimmed.find('<') {
        if trimmed.ends_with('>') && open > 0 {
            out.push(trimmed.to_string());
            let inner = &trimmed[(open + 1)..(trimmed.len() - 1)];
            for part in split_top_level_types(inner) {
                collect_type_instantiation(part, out);
            }
        }
    }
}

fn split_top_level_types(input: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (index, ch) in input.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(input[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < input.len() {
        out.push(input[start..].trim());
    }
    out.into_iter().filter(|part| !part.is_empty()).collect()
}

fn collect_semantic_hints(module: &Module) -> (Vec<String>, Vec<String>, usize) {
    let mut linear_resources = Vec::new();
    let mut deferred_resources = Vec::new();
    let mut matches_without_wildcard = 0usize;

    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        for statement in &function.body {
            match statement {
                ast::Stmt::Let { name, ty, .. } => {
                    let looks_linear = name.ends_with("_res")
                        || name.ends_with("_handle")
                        || ty.as_ref().is_some_and(|ty| ty.starts_with('*'));
                    if looks_linear {
                        linear_resources.push(name.clone());
                    }
                }
                ast::Stmt::Defer(expr) => {
                    if let Some(resource) = deferred_resource(expr) {
                        deferred_resources.push(resource);
                    }
                }
                ast::Stmt::Match { arms, .. } => {
                    if !arms
                        .iter()
                        .any(|arm| matches!(arm.pattern, ast::Pattern::Wildcard))
                    {
                        matches_without_wildcard += 1;
                    }
                }
                ast::Stmt::Return(_)
                | ast::Stmt::Expr(_)
                | ast::Stmt::Requires(_)
                | ast::Stmt::Ensures(_) => {}
            }
        }
    }

    (
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
    )
}

fn deferred_resource(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::Call { args, .. } => args.first().and_then(|arg| match arg {
            ast::Expr::Ident(name) => Some(name.clone()),
            _ => None,
        }),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => deferred_resource(try_expr).or_else(|| deferred_resource(catch_expr)),
        ast::Expr::Int(_) | ast::Expr::Bool(_) | ast::Expr::Binary { .. } => None,
    }
}

fn evaluate_const_return(body: &[ast::Stmt]) -> Option<i32> {
    let mut scope = BTreeMap::<String, i32>::new();
    for statement in body {
        match statement {
            ast::Stmt::Let { name, value, .. } => {
                if let Some(constant) = eval_expr(value, &scope) {
                    scope.insert(name.clone(), constant);
                }
            }
            ast::Stmt::Return(expr) => return eval_expr(expr, &scope),
            ast::Stmt::Match { .. }
            | ast::Stmt::Defer(_)
            | ast::Stmt::Expr(_)
            | ast::Stmt::Requires(_)
            | ast::Stmt::Ensures(_) => {}
        }
    }
    None
}

fn collect_entry_contracts(module: &Module) -> (Vec<Option<bool>>, Vec<Option<bool>>) {
    let mut requires = Vec::new();
    let mut ensures = Vec::new();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        if function.name != "main" {
            continue;
        }
        for statement in &function.body {
            match statement {
                ast::Stmt::Requires(expr) => requires.push(eval_bool_expr(expr)),
                ast::Stmt::Ensures(expr) => ensures.push(eval_bool_expr(expr)),
                ast::Stmt::Let { .. }
                | ast::Stmt::Return(_)
                | ast::Stmt::Defer(_)
                | ast::Stmt::Match { .. }
                | ast::Stmt::Expr(_) => {}
            }
        }
    }
    (requires, ensures)
}

fn eval_bool_expr(expr: &ast::Expr) -> Option<bool> {
    match expr {
        ast::Expr::Bool(value) => Some(*value),
        ast::Expr::Int(value) => Some(*value != 0),
        ast::Expr::Binary { op, left, right } => {
            let left = eval_bool_expr(left)
                .or_else(|| eval_expr(left, &BTreeMap::new()).map(|v| v != 0))?;
            let right = eval_bool_expr(right)
                .or_else(|| eval_expr(right, &BTreeMap::new()).map(|v| v != 0))?;
            match op {
                ast::BinaryOp::Eq => Some(left == right),
                ast::BinaryOp::Neq => Some(left != right),
                ast::BinaryOp::Add | ast::BinaryOp::Sub => None,
            }
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => eval_bool_expr(try_expr).or_else(|| eval_bool_expr(catch_expr)),
        ast::Expr::Ident(_) | ast::Expr::Call { .. } => None,
    }
}

fn eval_expr(expr: &ast::Expr, scope: &BTreeMap<String, i32>) -> Option<i32> {
    match expr {
        ast::Expr::Int(value) => Some(*value),
        ast::Expr::Ident(name) => scope.get(name).copied(),
        ast::Expr::Binary { op, left, right } => {
            let left = eval_expr(left, scope)?;
            let right = eval_expr(right, scope)?;
            match op {
                ast::BinaryOp::Add => Some(left + right),
                ast::BinaryOp::Sub => Some(left - right),
                ast::BinaryOp::Eq => Some((left == right) as i32),
                ast::BinaryOp::Neq => Some((left != right) as i32),
            }
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => eval_expr(try_expr, scope).or_else(|| eval_expr(catch_expr, scope)),
        ast::Expr::Bool(_) | ast::Expr::Call { .. } => None,
    }
}
