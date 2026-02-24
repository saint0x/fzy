use std::collections::{BTreeMap, BTreeSet, HashMap};

use ast::{AstVisitor, BinaryOp, Expr, Module, Stmt, Type};

#[derive(Debug, Clone)]
pub struct TypedFunction {
    pub name: String,
    pub params: Vec<ast::Param>,
    pub return_type: Type,
    pub body: Vec<Stmt>,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TypedModule {
    pub name: String,
    pub symbol_count: usize,
    pub capabilities: Vec<String>,
    pub inferred_capabilities: Vec<String>,
    pub entry_return_type: Option<Type>,
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
    pub call_graph: Vec<(String, String)>,
    pub typed_functions: Vec<TypedFunction>,
    pub type_errors: usize,
    pub function_capability_requirements: Vec<FunctionCapabilityRequirement>,
    pub ownership_violations: Vec<String>,
    pub capability_token_violations: Vec<String>,
    pub reference_lifetime_violations: Vec<String>,
    pub linear_type_violations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionCapabilityRequirement {
    pub function: String,
    pub required: Vec<String>,
}

#[derive(Debug, Clone)]
enum Value {
    I32(i32),
    Bool(bool),
    Str(String),
}

#[derive(Default)]
struct SymbolScopes {
    stack: Vec<HashMap<String, Type>>,
}

impl SymbolScopes {
    fn new() -> Self {
        Self {
            stack: vec![HashMap::new()],
        }
    }

    fn push(&mut self) {
        self.stack.push(HashMap::new());
    }

    fn pop(&mut self) {
        let _ = self.stack.pop();
    }

    fn insert(&mut self, name: String, ty: Type) {
        if let Some(scope) = self.stack.last_mut() {
            scope.insert(name, ty);
        }
    }

    fn get(&self, name: &str) -> Option<Type> {
        self.stack
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
    }
}

pub fn lower(module: &Module) -> TypedModule {
    let mut fn_sigs = HashMap::<String, (Vec<Type>, Type)>::new();
    let mut typed_functions = Vec::new();
    let mut type_errors = 0usize;

    for item in &module.items {
        if let ast::Item::Function(function) = item {
            fn_sigs.insert(
                function.name.clone(),
                (
                    function.params.iter().map(|p| p.ty.clone()).collect(),
                    function.return_type.clone(),
                ),
            );
            typed_functions.push(TypedFunction {
                name: function.name.clone(),
                params: function.params.clone(),
                return_type: function.return_type.clone(),
                body: function.body.clone(),
                required_capabilities: Vec::new(),
            });
        }
    }

    let function_capability_requirements = compute_function_capabilities(&typed_functions);
    for function in &mut typed_functions {
        if let Some(entry) = function_capability_requirements
            .iter()
            .find(|entry| entry.function == function.name)
        {
            function.required_capabilities = entry.required.clone();
        }
    }

    for function in &typed_functions {
        if function.body.is_empty() {
            continue;
        }
        let mut scopes = SymbolScopes::new();
        for param in &function.params {
            scopes.insert(param.name.clone(), param.ty.clone());
        }
        for stmt in &function.body {
            type_check_stmt(stmt, &mut scopes, &fn_sigs, &function.return_type, &mut type_errors);
        }
    }

    let entry_return_type = typed_functions
        .iter()
        .find(|f| f.name == "main")
        .map(|f| f.return_type.clone());
    let entry_return_const_i32 = interpret_entry_i32(&typed_functions);

    let (linear_resources, deferred_resources, matches_without_wildcard) =
        collect_semantic_hints(&typed_functions);
    let (entry_requires, entry_ensures) = collect_entry_contracts(&typed_functions, &fn_sigs);
    let (host_syscall_sites, unsafe_sites, unsafe_reasoned_sites, reference_sites, alloc_sites, free_sites) =
        collect_effect_markers(&typed_functions);
    let inferred_capabilities = infer_capabilities(&typed_functions);
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
    let call_graph = build_call_graph(module);
    let ownership_violations = analyze_ownership(&typed_functions);
    let capability_token_violations = if capability_token_mode_enabled(&typed_functions) {
        analyze_capability_token_contracts(&typed_functions, &function_capability_requirements)
    } else {
        Vec::new()
    };
    let reference_lifetime_violations = analyze_reference_lifetimes(&typed_functions);
    let linear_type_violations = analyze_linear_types(&typed_functions);

    TypedModule {
        name: module.name.clone(),
        symbol_count: module.items.len(),
        capabilities: module.capabilities.clone(),
        inferred_capabilities,
        entry_return_type,
        entry_return_const_i32,
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
        entry_requires,
        entry_ensures,
        host_syscall_sites,
        unsafe_sites,
        unsafe_reasoned_sites,
        reference_sites,
        alloc_sites,
        free_sites,
        extern_c_abi_functions,
        repr_c_layout_items,
        generic_instantiations,
        call_graph,
        typed_functions,
        type_errors,
        function_capability_requirements,
        ownership_violations,
        capability_token_violations,
        reference_lifetime_violations,
        linear_type_violations,
    }
}

fn analyze_capability_token_contracts(
    functions: &[TypedFunction],
    requirements: &[FunctionCapabilityRequirement],
) -> Vec<String> {
    let mut violations = Vec::new();
    let requirement_map = requirements
        .iter()
        .map(|entry| (entry.function.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    for function in functions {
        let required = requirement_map
            .get(function.name.as_str())
            .map(|entry| entry.required.clone())
            .unwrap_or_default();
        if required.is_empty() {
            continue;
        }

        let mut available = BTreeSet::<String>::new();
        for param in &function.params {
            if let Some(caps) = capability_set_from_type(&param.ty) {
                available.extend(caps);
            }
        }
        for cap in &required {
            if !available.contains(cap) {
                violations.push(format!(
                    "function `{}` requires capability `{}` but has no capability token parameter proving it",
                    function.name, cap
                ));
            }
        }

        let local_types = function
            .params
            .iter()
            .map(|p| (p.name.clone(), p.ty.clone()))
            .collect::<BTreeMap<_, _>>();
        analyze_call_token_propagation(
            &function.name,
            &function.body,
            &local_types,
            &requirement_map,
            &mut violations,
        );
    }

    violations
}

fn capability_token_mode_enabled(functions: &[TypedFunction]) -> bool {
    for function in functions {
        for param in &function.params {
            if capability_set_from_type(&param.ty).is_some() {
                return true;
            }
        }
        for stmt in &function.body {
            if statement_uses_cap_token_intrinsic(stmt) {
                return true;
            }
        }
    }
    false
}

fn statement_uses_cap_token_intrinsic(stmt: &Stmt) -> bool {
    fn expr_has_cap_intrinsic(expr: &Expr) -> bool {
        match expr {
            Expr::Call { callee, args } => {
                if callee == "revoke_cap"
                    || callee == "delegate_cap"
                    || callee == "compose_cap"
                    || callee == "intersect_cap"
                    || callee == "negate_cap"
                {
                    return true;
                }
                args.iter().any(expr_has_cap_intrinsic)
            }
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => expr_has_cap_intrinsic(try_expr) || expr_has_cap_intrinsic(catch_expr),
            Expr::Binary { left, right, .. } => {
                expr_has_cap_intrinsic(left) || expr_has_cap_intrinsic(right)
            }
            Expr::Group(inner) => expr_has_cap_intrinsic(inner),
            Expr::Int(_) | Expr::Bool(_) | Expr::Str(_) | Expr::Ident(_) => false,
        }
    }

    match stmt {
        Stmt::Let { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::Return(value)
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_has_cap_intrinsic(value),
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_has_cap_intrinsic(condition)
                || then_body.iter().any(statement_uses_cap_token_intrinsic)
                || else_body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::While { condition, body } => {
            expr_has_cap_intrinsic(condition) || body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::Match { scrutinee, arms } => {
            expr_has_cap_intrinsic(scrutinee)
                || arms.iter().any(|arm| {
                    arm.guard
                        .as_ref()
                        .is_some_and(expr_has_cap_intrinsic)
                        || expr_has_cap_intrinsic(&arm.value)
                })
        }
    }
}

fn analyze_call_token_propagation(
    function_name: &str,
    body: &[Stmt],
    local_types: &BTreeMap<String, Type>,
    requirement_map: &BTreeMap<&str, &FunctionCapabilityRequirement>,
    violations: &mut Vec<String>,
) {
    for stmt in body {
        match stmt {
            Stmt::Let { .. }
            | Stmt::Assign { .. }
            | Stmt::Return(_)
            | Stmt::Defer(_)
            | Stmt::Requires(_)
            | Stmt::Ensures(_)
            | Stmt::Expr(_) => {
                analyze_expr_call_tokens(function_name, stmt_expr(stmt), local_types, requirement_map, violations);
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(condition),
                    local_types,
                    requirement_map,
                    violations,
                );
                analyze_call_token_propagation(
                    function_name,
                    then_body,
                    local_types,
                    requirement_map,
                    violations,
                );
                analyze_call_token_propagation(
                    function_name,
                    else_body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::While { condition, body } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(condition),
                    local_types,
                    requirement_map,
                    violations,
                );
                analyze_call_token_propagation(
                    function_name,
                    body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::Match { scrutinee, arms } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(scrutinee),
                    local_types,
                    requirement_map,
                    violations,
                );
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        analyze_expr_call_tokens(
                            function_name,
                            Some(guard),
                            local_types,
                            requirement_map,
                            violations,
                        );
                    }
                    analyze_expr_call_tokens(
                        function_name,
                        Some(&arm.value),
                        local_types,
                        requirement_map,
                        violations,
                    );
                }
            }
        }
    }
}

fn stmt_expr(stmt: &Stmt) -> Option<&Expr> {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::Return(value)
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value)
        | Stmt::Assign { value, .. } => Some(value),
        Stmt::If { .. } | Stmt::While { .. } | Stmt::Match { .. } => None,
    }
}

fn analyze_expr_call_tokens(
    function_name: &str,
    expr: Option<&Expr>,
    local_types: &BTreeMap<String, Type>,
    requirement_map: &BTreeMap<&str, &FunctionCapabilityRequirement>,
    violations: &mut Vec<String>,
) {
    let Some(expr) = expr else {
        return;
    };
    match expr {
        Expr::Call { callee, args } => {
            if let Some(requirement) = requirement_map.get(callee.as_str()) {
                let mut provided = BTreeSet::<String>::new();
                for arg in args {
                    if let Expr::Ident(name) = arg {
                        if let Some(ty) = local_types.get(name) {
                            if let Some(caps) = capability_set_from_type(ty) {
                                provided.extend(caps);
                            }
                        }
                    }
                }
                for cap in &requirement.required {
                    if !provided.contains(cap) {
                        violations.push(format!(
                            "function `{}` calls `{}` without passing capability token for `{}`",
                            function_name, callee, cap
                        ));
                    }
                }
            }

            if callee == "revoke_cap" || callee == "delegate_cap" {
                if args.is_empty() {
                    violations.push(format!(
                        "function `{}` uses `{}` without token argument",
                        function_name, callee
                    ));
                }
            }

            for arg in args {
                analyze_expr_call_tokens(
                    function_name,
                    Some(arg),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            analyze_expr_call_tokens(
                function_name,
                Some(try_expr),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(catch_expr),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::Binary { left, right, .. } => {
            analyze_expr_call_tokens(
                function_name,
                Some(left),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(right),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::Group(inner) => analyze_expr_call_tokens(
            function_name,
            Some(inner),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Int(_) | Expr::Bool(_) | Expr::Str(_) | Expr::Ident(_) => {}
    }
}

fn capability_set_from_type(ty: &Type) -> Option<BTreeSet<String>> {
    match ty {
        Type::Named { name, args } if name == "Cap" && args.len() == 1 => {
            let mut set = BTreeSet::new();
            if let Some(cap_name) = capability_name_from_type(&args[0]) {
                set.insert(cap_name);
                return Some(set);
            }
            None
        }
        Type::Named { name, args } if name == "CapSet" => {
            let mut set = BTreeSet::new();
            for arg in args {
                if let Some(cap_name) = capability_name_from_type(arg) {
                    set.insert(cap_name);
                }
            }
            if set.is_empty() { None } else { Some(set) }
        }
        _ => None,
    }
}

fn capability_name_from_type(ty: &Type) -> Option<String> {
    match ty {
        Type::Named { name, args } if args.is_empty() => {
            capabilities::Capability::parse(name).map(|cap| cap.as_str().to_string())
        }
        Type::TypeVar(name) => capabilities::Capability::parse(name).map(|cap| cap.as_str().to_string()),
        _ => None,
    }
}

fn analyze_reference_lifetimes(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        let param_refs = function
            .params
            .iter()
            .filter_map(|param| matches!(param.ty, Type::Ref { .. }).then_some(param.name.clone()))
            .collect::<BTreeSet<_>>();
        let mut local_refs = BTreeSet::<String>::new();
        for stmt in &function.body {
            if let Stmt::Let {
                name,
                ty: Some(Type::Ref { .. }),
                ..
            } = stmt
            {
                local_refs.insert(name.clone());
            }
            if let Stmt::Return(Expr::Ident(name)) = stmt {
                if local_refs.contains(name) && !param_refs.contains(name) {
                    violations.push(format!(
                        "function `{}` returns local reference `{}` without valid lifetime region",
                        function.name, name
                    ));
                }
            }
        }
    }
    violations
}

fn analyze_linear_types(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        let mut linear_owned = BTreeSet::<String>::new();
        let mut linear_freed = BTreeSet::<String>::new();
        for stmt in &function.body {
            match stmt {
                Stmt::Let {
                    name,
                    ty: Some(ty),
                    ..
                } if is_linear_type(ty) => {
                    linear_owned.insert(name.clone());
                }
                Stmt::Expr(Expr::Call { callee, args }) if callee == "free" || callee.ends_with(".free") => {
                    if let Some(Expr::Ident(name)) = args.first() {
                        if !linear_owned.contains(name) {
                            violations.push(format!(
                                "function `{}` frees non-linear value `{}` as linear resource",
                                function.name, name
                            ));
                        }
                        linear_freed.insert(name.clone());
                    }
                }
                _ => {}
            }
        }
        for name in linear_owned {
            if !linear_freed.contains(&name) {
                violations.push(format!(
                    "function `{}` linear value `{}` was not consumed/freed",
                    function.name, name
                ));
            }
        }
    }
    violations
}

fn is_linear_type(ty: &Type) -> bool {
    match ty {
        Type::Ptr { .. } => true,
        Type::Named { name, .. } if name == "Linear" || name == "Resource" || name.ends_with("Handle") => {
            true
        }
        _ => false,
    }
}

fn compute_function_capabilities(
    functions: &[TypedFunction],
) -> Vec<FunctionCapabilityRequirement> {
    let mut local = BTreeMap::<String, BTreeSet<String>>::new();
    let mut calls = BTreeMap::<String, BTreeSet<String>>::new();

    for function in functions {
        let mut local_caps = BTreeSet::<String>::new();
        let mut local_calls = BTreeSet::<String>::new();
        collect_function_caps_and_calls(function, &mut local_caps, &mut local_calls);
        local.insert(function.name.clone(), local_caps);
        calls.insert(function.name.clone(), local_calls);
    }

    let known = functions
        .iter()
        .map(|f| f.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut changed = true;
    while changed {
        changed = false;
        for function in functions {
            let mut next = local.get(&function.name).cloned().unwrap_or_default();
            for callee in calls
                .get(&function.name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
            {
                if !known.contains(callee.as_str()) {
                    continue;
                }
                if let Some(callee_caps) = local.get(&callee) {
                    let before = next.len();
                    next.extend(callee_caps.iter().cloned());
                    if next.len() != before {
                        changed = true;
                    }
                }
            }
            local.insert(function.name.clone(), next);
        }
    }

    functions
        .iter()
        .map(|function| FunctionCapabilityRequirement {
            function: function.name.clone(),
            required: local
                .get(&function.name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect(),
        })
        .collect()
}

fn collect_function_caps_and_calls(
    function: &TypedFunction,
    caps: &mut BTreeSet<String>,
    calls: &mut BTreeSet<String>,
) {
    struct Collector<'a> {
        caps: &'a mut BTreeSet<String>,
        calls: &'a mut BTreeSet<String>,
    }
    impl AstVisitor for Collector<'_> {
        fn visit_expr(&mut self, expr: &Expr) {
            if let Expr::Call { callee, .. } = expr {
                self.calls.insert(callee.clone());
                if let Some((prefix, _)) = callee.split_once('.') {
                    match prefix {
                        "time" | "std.time" => {
                            self.caps.insert("time".to_string());
                        }
                        "rng" | "random" | "std.rand" => {
                            self.caps.insert("rng".to_string());
                        }
                        "fs" | "file" | "std.io" => {
                            self.caps.insert("fs".to_string());
                        }
                        "net" | "socket" | "std.net" => {
                            self.caps.insert("net".to_string());
                        }
                        "proc" | "process" | "syscall" | "std.proc" => {
                            self.caps.insert("proc".to_string());
                        }
                        "alloc" | "std.alloc" => {
                            self.caps.insert("mem".to_string());
                        }
                        "thread" | "std.thread" => {
                            self.caps.insert("thread".to_string());
                        }
                        _ => {}
                    }
                }
                if callee == "spawn" || callee.contains("await") {
                    self.caps.insert("thread".to_string());
                }
                if callee.contains("timeout") || callee.contains("deadline") || callee.contains("cancel")
                {
                    self.caps.insert("net".to_string());
                }
            }
            ast::walk_expr(self, expr);
        }
    }

    let mut collector = Collector { caps, calls };
    for stmt in &function.body {
        collector.visit_stmt(stmt);
    }
}

fn analyze_ownership(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        let mut owners = BTreeMap::<String, usize>::new();
        let mut next_alloc = 1usize;
        analyze_ownership_block(
            &function.body,
            &mut owners,
            &mut next_alloc,
            &mut violations,
            &function.name,
        );
        for (name, alloc_id) in owners {
            violations.push(format!(
                "function `{}` leaks allocation id={} owned by `{}`",
                function.name, alloc_id, name
            ));
        }
    }
    violations
}

fn analyze_ownership_block(
    body: &[Stmt],
    owners: &mut BTreeMap<String, usize>,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
) {
    for stmt in body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                if is_alloc_expr(value) {
                    owners.insert(name.clone(), *next_alloc);
                    *next_alloc += 1;
                }
                if let Expr::Ident(from) = value {
                    if let Some(owner) = owners.remove(from) {
                        owners.insert(name.clone(), owner);
                    }
                }
            }
            Stmt::Assign { target, value } => {
                if let Expr::Ident(from) = value {
                    if let Some(owner) = owners.remove(from) {
                        owners.insert(target.clone(), owner);
                    }
                }
            }
            Stmt::Expr(Expr::Call { callee, args }) => {
                if callee == "free" || callee.ends_with(".free") {
                    if let Some(Expr::Ident(name)) = args.first() {
                        if owners.remove(name).is_none() {
                            violations.push(format!(
                                "function `{}` frees non-owned or already-freed value `{}`",
                                function_name, name
                            ));
                        }
                    }
                }
            }
            Stmt::Return(Expr::Ident(name)) => {
                owners.remove(name);
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let mut then_owners = owners.clone();
                let mut else_owners = owners.clone();
                analyze_ownership_block(
                    then_body,
                    &mut then_owners,
                    next_alloc,
                    violations,
                    function_name,
                );
                analyze_ownership_block(
                    else_body,
                    &mut else_owners,
                    next_alloc,
                    violations,
                    function_name,
                );
                *owners = then_owners
                    .into_iter()
                    .filter(|(name, id)| else_owners.get(name).is_some_and(|other| other == id))
                    .collect();
            }
            Stmt::While { body, .. } => {
                analyze_ownership_block(body, owners, next_alloc, violations, function_name);
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        let _ = guard;
                    }
                }
            }
            Stmt::Defer(_)
            | Stmt::Requires(_)
            | Stmt::Ensures(_)
            | Stmt::Expr(_)
            | Stmt::Return(_) => {}
        }
    }
}

fn is_alloc_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { callee, .. } if callee == "alloc" || callee.ends_with(".alloc"))
}

fn build_call_graph(module: &Module) -> Vec<(String, String)> {
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
                    self.edges.push((self.from.clone(), callee.clone()));
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

fn infer_capabilities(functions: &[TypedFunction]) -> Vec<String> {
    let mut caps = BTreeSet::new();
    for function in functions {
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
                            "rng" | "random" | "std.rand" => {
                                self.caps.insert("rng".to_string());
                            }
                            "fs" | "file" | "std.io" => {
                                self.caps.insert("fs".to_string());
                            }
                            "net" | "socket" | "std.net" => {
                                self.caps.insert("net".to_string());
                            }
                            "proc" | "process" | "syscall" | "std.proc" => {
                                self.caps.insert("proc".to_string());
                            }
                            "alloc" | "std.alloc" => {
                                self.caps.insert("mem".to_string());
                            }
                            "thread" | "std.thread" => {
                                self.caps.insert("thread".to_string());
                            }
                            _ => {}
                        }
                    }
                    if callee == "spawn" || callee.contains("await") {
                        self.caps.insert("thread".to_string());
                    }
                    if callee.contains("timeout") || callee.contains("deadline") || callee.contains("cancel") {
                        self.caps.insert("net".to_string());
                    }
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
                    if let Stmt::Let { ty: Some(ty), .. } = statement {
                        collect_type_instantiation(ty, &mut out);
                    }
                }
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
        }
    }
    out.sort();
    out.dedup();
    out
}

fn collect_type_instantiation(ty: &Type, out: &mut Vec<String>) {
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
        Type::Void
        | Type::Bool
        | Type::Int { .. }
        | Type::Float { .. }
        | Type::Char
        | Type::Str
        | Type::Named { .. }
        | Type::TypeVar(_) => {}
    }
}

fn collect_semantic_hints(functions: &[TypedFunction]) -> (Vec<String>, Vec<String>, usize) {
    let mut linear_resources = Vec::new();
    let mut deferred_resources = Vec::new();
    let mut matches_without_wildcard = 0usize;

    for function in functions {
        for statement in &function.body {
            match statement {
                Stmt::Let {
                    name,
                    ty: Some(ty),
                    ..
                } if ty.is_pointer_like() => {
                    linear_resources.push(name.clone());
                }
                Stmt::Defer(expr) => {
                    if let Some(resource) = deferred_resource(expr) {
                        deferred_resources.push(resource);
                    }
                }
                Stmt::Match { arms, .. } => {
                    if !arms
                        .iter()
                        .any(|arm| pattern_has_wildcard(&arm.pattern))
                    {
                        matches_without_wildcard += 1;
                    }
                }
                _ => {}
            }
        }
    }

    (
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
    )
}

fn collect_effect_markers(functions: &[TypedFunction]) -> (usize, usize, usize, usize, usize, usize) {
    let mut host_syscall_sites = 0usize;
    let mut unsafe_sites = 0usize;
    let mut unsafe_reasoned_sites = 0usize;
    let mut reference_sites = 0usize;
    let mut alloc_sites = 0usize;
    let mut free_sites = 0usize;

    for function in functions {
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
                    if callee == "unsafe" {
                        self.unsafe_sites += 1;
                        self.unsafe_reasoned_sites += 1;
                    }
                    if callee.starts_with("alloc") {
                        self.alloc_sites += 1;
                    }
                    if callee.starts_with("free") {
                        self.free_sites += 1;
                    }
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
        ast::Expr::Int(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Binary { .. }
        | ast::Expr::Group(_) => None,
    }
}

fn collect_entry_contracts(
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

fn type_check_stmt(
    stmt: &Stmt,
    scopes: &mut SymbolScopes,
    fn_sigs: &HashMap<String, (Vec<Type>, Type)>,
    expected_return: &Type,
    errors: &mut usize,
) {
    match stmt {
        Stmt::Let { name, ty, value } => {
            let inferred = infer_expr_type(value, scopes, fn_sigs, errors);
            let final_ty = match (ty, inferred) {
                (Some(explicit), Some(actual)) => {
                    if !type_compatible(explicit, &actual) {
                        *errors += 1;
                    }
                    explicit.clone()
                }
                (Some(explicit), None) => explicit.clone(),
                (None, Some(actual)) => actual,
                (None, None) => {
                    *errors += 1;
                    Type::Void
                }
            };
            scopes.insert(name.clone(), final_ty);
        }
        Stmt::Assign { target, value } => {
            let target_ty = scopes.get(target);
            let value_ty = infer_expr_type(value, scopes, fn_sigs, errors);
            if let (Some(target_ty), Some(value_ty)) = (target_ty, value_ty) {
                if !type_compatible(&target_ty, &value_ty) {
                    *errors += 1;
                }
            }
        }
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            let cond_ty = infer_expr_type(condition, scopes, fn_sigs, errors);
            if !matches!(cond_ty, Some(Type::Bool) | Some(Type::Int { .. })) {
                *errors += 1;
            }
            scopes.push();
            for stmt in then_body {
                type_check_stmt(stmt, scopes, fn_sigs, expected_return, errors);
            }
            scopes.pop();
            scopes.push();
            for stmt in else_body {
                type_check_stmt(stmt, scopes, fn_sigs, expected_return, errors);
            }
            scopes.pop();
        }
        Stmt::While { condition, body } => {
            let cond_ty = infer_expr_type(condition, scopes, fn_sigs, errors);
            if !matches!(cond_ty, Some(Type::Bool) | Some(Type::Int { .. })) {
                *errors += 1;
            }
            scopes.push();
            for stmt in body {
                type_check_stmt(stmt, scopes, fn_sigs, expected_return, errors);
            }
            scopes.pop();
        }
        Stmt::Return(expr) => {
            if let Some(actual) = infer_expr_type(expr, scopes, fn_sigs, errors) {
                if !type_compatible(expected_return, &actual) {
                    *errors += 1;
                }
            }
        }
        Stmt::Match { scrutinee, arms } => {
            let scrutinee_ty = infer_expr_type(scrutinee, scopes, fn_sigs, errors);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    let guard_ty = infer_expr_type(guard, scopes, fn_sigs, errors);
                    if !matches!(guard_ty, Some(Type::Bool) | Some(Type::Int { .. })) {
                        *errors += 1;
                    }
                }
                let value_ty = infer_expr_type(&arm.value, scopes, fn_sigs, errors);
                check_pattern_compatibility(&arm.pattern, scrutinee_ty.as_ref(), errors);
                let _ = value_ty;
            }
        }
        Stmt::Defer(expr) | Stmt::Requires(expr) | Stmt::Ensures(expr) | Stmt::Expr(expr) => {
            let _ = infer_expr_type(expr, scopes, fn_sigs, errors);
        }
    }
}

fn infer_expr_type(
    expr: &Expr,
    scopes: &SymbolScopes,
    fn_sigs: &HashMap<String, (Vec<Type>, Type)>,
    errors: &mut usize,
) -> Option<Type> {
    match expr {
        Expr::Int(_) => Some(Type::Int {
            signed: true,
            bits: 32,
        }),
        Expr::Bool(_) => Some(Type::Bool),
        Expr::Str(_) => Some(Type::Str),
        Expr::Ident(name) => scopes.get(name),
        Expr::Group(inner) => infer_expr_type(inner, scopes, fn_sigs, errors),
        Expr::Call { callee, args } => {
            let Some((params, ret)) = fn_sigs.get(callee) else {
                if callee.contains('.') || is_runtime_intrinsic(callee) {
                    for arg in args {
                        let _ = infer_expr_type(arg, scopes, fn_sigs, errors);
                    }
                    return Some(Type::Int {
                        signed: true,
                        bits: 32,
                    });
                }
                *errors += 1;
                return None;
            };
            if params.len() != args.len() {
                *errors += 1;
            }
            for (index, arg) in args.iter().enumerate() {
                let arg_ty = infer_expr_type(arg, scopes, fn_sigs, errors);
                if let (Some(expected), Some(actual)) = (params.get(index), arg_ty) {
                    if !type_compatible(expected, &actual) {
                        *errors += 1;
                    }
                }
            }
            Some(ret.clone())
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let left = infer_expr_type(try_expr, scopes, fn_sigs, errors);
            let right = infer_expr_type(catch_expr, scopes, fn_sigs, errors);
            match (left, right) {
                (Some(l), Some(r)) if type_compatible(&l, &r) => Some(l),
                (Some(_), Some(_)) => {
                    *errors += 1;
                    None
                }
                (Some(l), None) => Some(l),
                (None, Some(r)) => Some(r),
                (None, None) => None,
            }
        }
        Expr::Binary { op, left, right } => {
            let left_ty = infer_expr_type(left, scopes, fn_sigs, errors);
            let right_ty = infer_expr_type(right, scopes, fn_sigs, errors);
            match op {
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div => {
                    if matches!(left_ty, Some(Type::Int { .. }))
                        && matches!(right_ty, Some(Type::Int { .. }))
                    {
                        left_ty
                    } else {
                        *errors += 1;
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
                        if !type_compatible(l, r) {
                            *errors += 1;
                        }
                    }
                    Some(Type::Bool)
                }
            }
        }
    }
}

fn is_runtime_intrinsic(name: &str) -> bool {
    matches!(
        name,
        "spawn"
            | "yield"
            | "checkpoint"
            | "timeout"
            | "deadline"
            | "cancel"
            | "recv"
            | "pulse"
    )
}

fn check_pattern_compatibility(pattern: &ast::Pattern, scrutinee_ty: Option<&Type>, errors: &mut usize) {
    match (pattern, scrutinee_ty) {
        (ast::Pattern::Int(_), Some(Type::Int { .. })) => {}
        (ast::Pattern::Bool(_), Some(Type::Bool)) => {}
        (ast::Pattern::Wildcard, _)
        | (ast::Pattern::Ident(_), _)
        | (ast::Pattern::Variant { .. }, _) => {}
        (ast::Pattern::Or(patterns), ty) => {
            for pattern in patterns {
                check_pattern_compatibility(pattern, ty, errors);
            }
        }
        (ast::Pattern::Int(_), Some(_)) | (ast::Pattern::Bool(_), Some(_)) => *errors += 1,
        (ast::Pattern::Int(_) | ast::Pattern::Bool(_), None) => *errors += 1,
    }
}

fn type_compatible(expected: &Type, actual: &Type) -> bool {
    expected == actual
}

fn interpret_entry_i32(functions: &[TypedFunction]) -> Option<i32> {
    let map = functions
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect::<HashMap<_, _>>();
    let main = map.get("main")?;
    let mut env = BTreeMap::new();
    eval_block(&main.body, &mut env, &map).and_then(|value| match value {
        Value::I32(v) => Some(v),
        Value::Bool(v) => Some(v as i32),
        Value::Str(_) => None,
    })
}

fn eval_block<'a>(
    body: &[Stmt],
    env: &mut BTreeMap<String, Value>,
    functions: &HashMap<&'a str, &'a TypedFunction>,
) -> Option<Value> {
    for stmt in body {
        match stmt {
            Stmt::Let { name, value, .. } => {
                let val = eval_expr(value, env, functions)?;
                env.insert(name.clone(), val);
            }
            Stmt::Assign { target, value } => {
                let val = eval_expr(value, env, functions)?;
                env.insert(target.clone(), val);
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let cond = eval_expr(condition, env, functions)?;
                let branch = if truthy(&cond) { then_body } else { else_body };
                if let Some(v) = eval_block(branch, env, functions) {
                    return Some(v);
                }
            }
            Stmt::While { condition, body } => {
                let mut guard = 0usize;
                while truthy(&eval_expr(condition, env, functions)?) {
                    if let Some(v) = eval_block(body, env, functions) {
                        return Some(v);
                    }
                    guard += 1;
                    if guard > 1_000_000 {
                        return None;
                    }
                }
            }
            Stmt::Return(expr) => {
                let val = eval_expr(expr, env, functions)?;
                return Some(val);
            }
            Stmt::Match { scrutinee, arms } => {
                let value = eval_expr(scrutinee, env, functions)?;
                for arm in arms {
                    let guard_ok = match &arm.guard {
                        Some(guard) => truthy(&eval_expr(guard, env, functions)?),
                        None => true,
                    };
                    if guard_ok && pattern_matches(&arm.pattern, &value) {
                        let out = eval_expr(&arm.value, env, functions)?;
                        return Some(out);
                    }
                }
            }
            Stmt::Defer(_) | Stmt::Requires(_) | Stmt::Ensures(_) | Stmt::Expr(_) => {}
        }
    }
    None
}

fn eval_expr<'a>(
    expr: &Expr,
    env: &BTreeMap<String, Value>,
    functions: &HashMap<&'a str, &'a TypedFunction>,
) -> Option<Value> {
    match expr {
        Expr::Int(v) => Some(Value::I32(*v)),
        Expr::Bool(v) => Some(Value::Bool(*v)),
        Expr::Str(v) => Some(Value::Str(v.clone())),
        Expr::Ident(name) => env.get(name).cloned(),
        Expr::Group(inner) => eval_expr(inner, env, functions),
        Expr::Call { callee, args } => {
            let Some(function) = functions.get(callee.as_str()) else {
                if callee.contains('.') || is_runtime_intrinsic(callee) {
                    for arg in args {
                        let _ = eval_expr(arg, env, functions)?;
                    }
                    return Some(Value::I32(0));
                }
                return None;
            };
            if function.params.len() != args.len() {
                return None;
            }
            let mut local = BTreeMap::new();
            for (arg, param) in args.iter().zip(&function.params) {
                local.insert(param.name.clone(), eval_expr(arg, env, functions)?);
            }
            eval_block(&function.body, &mut local, functions)
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => eval_expr(try_expr, env, functions).or_else(|| eval_expr(catch_expr, env, functions)),
        Expr::Binary { op, left, right } => {
            let left = eval_expr(left, env, functions)?;
            let right = eval_expr(right, env, functions)?;
            eval_binary(*op, left, right)
        }
    }
}

fn eval_binary(op: BinaryOp, left: Value, right: Value) -> Option<Value> {
    match (op, left, right) {
        (BinaryOp::Add, Value::I32(a), Value::I32(b)) => Some(Value::I32(a + b)),
        (BinaryOp::Sub, Value::I32(a), Value::I32(b)) => Some(Value::I32(a - b)),
        (BinaryOp::Mul, Value::I32(a), Value::I32(b)) => Some(Value::I32(a * b)),
        (BinaryOp::Div, Value::I32(a), Value::I32(b)) => Some(Value::I32(a / b)),
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
        _ => None,
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(v) => *v,
        Value::I32(v) => *v != 0,
        Value::Str(v) => !v.is_empty(),
    }
}

fn pattern_matches(pattern: &ast::Pattern, value: &Value) -> bool {
    match (pattern, value) {
        (ast::Pattern::Wildcard, _) => true,
        (ast::Pattern::Int(a), Value::I32(b)) => a == b,
        (ast::Pattern::Bool(a), Value::Bool(b)) => a == b,
        (ast::Pattern::Ident(_), _) => true,
        (ast::Pattern::Variant { .. }, _) => true,
        (ast::Pattern::Or(patterns), value) => patterns.iter().any(|p| pattern_matches(p, value)),
        _ => false,
    }
}

fn pattern_has_wildcard(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Wildcard => true,
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_wildcard),
        ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_)
        | ast::Pattern::Variant { .. } => false,
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
        Value::Str(v) => Some(!v.is_empty()),
    }
}
