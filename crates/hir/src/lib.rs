use std::collections::{BTreeMap, BTreeSet, HashMap};

use ast::{AstVisitor, BinaryOp, Expr, Module, Stmt, Type};

#[derive(Debug, Clone)]
pub struct TypedFunction {
    pub name: String,
    pub generics: Vec<ast::GenericParam>,
    pub params: Vec<ast::Param>,
    pub return_type: Type,
    pub body: Vec<Stmt>,
    pub is_unsafe: bool,
    pub is_async: bool,
    pub is_extern: bool,
    pub abi: Option<String>,
    pub ffi_panic: Option<String>,
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
    pub entry_has_return_expr: bool,
    pub linear_resources: Vec<String>,
    pub deferred_resources: Vec<String>,
    pub matches_without_wildcard: usize,
    pub match_unreachable_arms: usize,
    pub match_duplicate_catchall_arms: usize,
    pub entry_requires: Vec<Option<bool>>,
    pub entry_ensures: Vec<Option<bool>>,
    pub host_syscall_sites: usize,
    pub unsafe_sites: usize,
    pub unsafe_reasoned_sites: usize,
    pub unsafe_contract_sites: Vec<UnsafeContractSite>,
    pub reference_sites: usize,
    pub alloc_sites: usize,
    pub free_sites: usize,
    pub extern_c_abi_functions: usize,
    pub repr_c_layout_items: usize,
    pub generic_instantiations: Vec<String>,
    pub generic_specializations: Vec<String>,
    pub call_graph: Vec<(String, String)>,
    pub typed_functions: Vec<TypedFunction>,
    pub typed_globals: Vec<TypedGlobal>,
    pub type_errors: usize,
    pub type_error_details: Vec<String>,
    pub function_capability_requirements: Vec<FunctionCapabilityRequirement>,
    pub ownership_violations: Vec<String>,
    pub unsafe_context_violations: Vec<String>,
    pub capability_token_violations: Vec<String>,
    pub trait_violations: Vec<String>,
    pub reference_lifetime_violations: Vec<String>,
    pub linear_type_violations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct UnsafeContractSite {
    pub site_id: String,
    pub kind: String,
    pub function: String,
    pub snippet: String,
    pub reason: Option<String>,
    pub invariant: Option<String>,
    pub owner: Option<String>,
    pub owner_id: Option<String>,
    pub scope: Option<String>,
    pub risk_class: Option<String>,
    pub proof_ref: Option<String>,
    pub async_context: bool,
}

#[derive(Debug, Clone)]
pub struct TypedGlobal {
    pub name: String,
    pub ty: Type,
    pub is_static: bool,
    pub mutable: bool,
    pub is_pub: bool,
    pub const_i32: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct FunctionCapabilityRequirement {
    pub function: String,
    pub required: Vec<String>,
}

#[derive(Debug, Clone)]
enum Value {
    I32(i32),
    F64(f64),
    Bool(bool),
    Char(char),
    Str(String),
    List(Vec<Value>),
    Struct {
        _name: String,
        fields: BTreeMap<String, Value>,
    },
    Enum {
        enum_name: String,
        variant: String,
        payload: Vec<Value>,
    },
    FnRef(String),
    Closure(RuntimeClosure),
}

#[derive(Debug, Clone)]
struct RuntimeClosure {
    params: Vec<ast::Param>,
    return_type: Option<Type>,
    body: Expr,
    captures: BTreeMap<String, Value>,
}

#[derive(Default, Clone)]
struct SymbolScopes {
    stack: Vec<HashMap<String, SymbolBinding>>,
}

#[derive(Debug, Clone)]
struct SymbolBinding {
    ty: Type,
    mutable: bool,
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

    fn insert(&mut self, name: String, ty: Type, mutable: bool) {
        if let Some(scope) = self.stack.last_mut() {
            scope.insert(name, SymbolBinding { ty, mutable });
        }
    }

    fn get(&self, name: &str) -> Option<Type> {
        self.stack
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).map(|binding| binding.ty.clone()))
    }

    fn is_mutable(&self, name: &str) -> bool {
        self.stack
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).map(|binding| binding.mutable))
            .unwrap_or(false)
    }
}

pub fn lower(module: &Module) -> TypedModule {
    let mut fn_sigs = HashMap::<String, (Vec<Type>, Type)>::new();
    let mut fn_async = HashMap::<String, bool>::new();
    let mut fn_generics = HashMap::<String, Vec<ast::GenericParam>>::new();
    let mut typed_functions = Vec::new();
    let mut type_errors = 0usize;
    let mut type_error_details = Vec::new();
    let mut typed_globals = Vec::new();
    let mut global_scope = SymbolScopes::new();
    let mut global_const_values = HashMap::<String, i32>::new();
    let struct_defs = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Struct(item) => Some((item.name.clone(), item.clone())),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let enum_defs = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Enum(item) => Some((item.name.clone(), item.clone())),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let trait_defs = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Trait(item) => Some((item.name.clone(), item.clone())),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let trait_impls = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Impl(item) => item
                .trait_name
                .clone()
                .map(|trait_name| (trait_name, item.for_type.clone())),
            _ => None,
        })
        .fold(
            HashMap::<String, Vec<Type>>::new(),
            |mut acc, (trait_name, ty)| {
                acc.entry(trait_name).or_default().push(ty);
                acc
            },
        );
    let mut generic_specializations = BTreeSet::new();
    let mut trait_violations = validate_trait_impls(module, &trait_defs);

    for item in &module.items {
        match item {
            ast::Item::Const(item) => {
                let inferred = infer_expr_type(
                    &item.value,
                    &global_scope,
                    &TypeCheckEnv {
                        fn_sigs: &fn_sigs,
                        fn_generics: &fn_generics,
                        struct_defs: &struct_defs,
                        enum_defs: &enum_defs,
                        trait_impls: &trait_impls,
                        global_types: &HashMap::new(),
                        global_mutability: &HashMap::new(),
                    },
                    &mut TypeCheckState {
                        errors: &mut type_errors,
                        type_error_details: &mut type_error_details,
                        generic_specializations: &mut generic_specializations,
                        trait_violations: &mut trait_violations,
                    },
                );
                if let Some(actual) = inferred {
                    if !type_compatible(&item.ty, &actual) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!(
                                "const `{}` type mismatch: expected `{}`, got `{}`",
                                item.name, item.ty, actual
                            ),
                        );
                    }
                }
                let const_i32 = eval_const_i32(&item.value, &global_const_values);
                if const_i32.is_none() {
                    record_type_error(
                        &mut type_errors,
                        &mut type_error_details,
                        format!(
                            "const `{}` must be initialized with an integer/char/bool compile-time expression",
                            item.name
                        ),
                    );
                }
                if let Some(value) = const_i32 {
                    global_const_values.insert(item.name.clone(), value);
                }
                global_scope.insert(item.name.clone(), item.ty.clone(), false);
                typed_globals.push(TypedGlobal {
                    name: item.name.clone(),
                    ty: item.ty.clone(),
                    is_static: false,
                    mutable: false,
                    is_pub: item.is_pub,
                    const_i32,
                });
            }
            ast::Item::Static(item) => {
                let inferred = infer_expr_type(
                    &item.value,
                    &global_scope,
                    &TypeCheckEnv {
                        fn_sigs: &fn_sigs,
                        fn_generics: &fn_generics,
                        struct_defs: &struct_defs,
                        enum_defs: &enum_defs,
                        trait_impls: &trait_impls,
                        global_types: &HashMap::new(),
                        global_mutability: &HashMap::new(),
                    },
                    &mut TypeCheckState {
                        errors: &mut type_errors,
                        type_error_details: &mut type_error_details,
                        generic_specializations: &mut generic_specializations,
                        trait_violations: &mut trait_violations,
                    },
                );
                if let Some(actual) = inferred {
                    if !type_compatible(&item.ty, &actual) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!(
                                "static `{}` type mismatch: expected `{}`, got `{}`",
                                item.name, item.ty, actual
                            ),
                        );
                    }
                }
                let const_i32 = eval_const_i32(&item.value, &global_const_values);
                if const_i32.is_none() {
                    record_type_error(
                        &mut type_errors,
                        &mut type_error_details,
                        format!(
                            "static `{}` must be initialized with an integer/char/bool compile-time expression",
                            item.name
                        ),
                    );
                }
                if let Some(value) = const_i32 {
                    global_const_values.insert(item.name.clone(), value);
                }
                global_scope.insert(item.name.clone(), item.ty.clone(), item.mutable);
                typed_globals.push(TypedGlobal {
                    name: item.name.clone(),
                    ty: item.ty.clone(),
                    is_static: true,
                    mutable: item.mutable,
                    is_pub: item.is_pub,
                    const_i32,
                });
            }
            ast::Item::Function(function) => {
                fn_sigs.insert(
                    function.name.clone(),
                    (
                        function.params.iter().map(|p| p.ty.clone()).collect(),
                        function.return_type.clone(),
                    ),
                );
                fn_async.insert(function.name.clone(), function.is_async);
                fn_generics.insert(function.name.clone(), function.generics.clone());
                typed_functions.push(TypedFunction {
                    name: function.name.clone(),
                    generics: function.generics.clone(),
                    params: function.params.clone(),
                    return_type: function.return_type.clone(),
                    body: function.body.clone(),
                    is_unsafe: function.is_unsafe,
                    is_async: function.is_async,
                    is_extern: function.is_extern,
                    abi: function.abi.clone(),
                    ffi_panic: function.ffi_panic.clone(),
                    required_capabilities: Vec::new(),
                });
            }
            ast::Item::Test(test) => {
                let name = format!("test::{}", sanitize_test_name(&test.name));
                fn_sigs.insert(name.clone(), (Vec::new(), Type::Void));
                fn_async.insert(name.clone(), false);
                fn_generics.insert(name.clone(), Vec::new());
                typed_functions.push(TypedFunction {
                    name,
                    generics: Vec::new(),
                    params: Vec::new(),
                    return_type: Type::Void,
                    body: test.body.clone(),
                    is_unsafe: false,
                    is_async: false,
                    is_extern: false,
                    abi: None,
                    ffi_panic: None,
                    required_capabilities: Vec::new(),
                });
            }
            _ => {}
        }
    }
    let global_types = typed_globals
        .iter()
        .map(|item| (item.name.clone(), item.ty.clone()))
        .collect::<HashMap<_, _>>();
    let global_mutability = typed_globals
        .iter()
        .map(|item| (item.name.clone(), item.mutable))
        .collect::<HashMap<_, _>>();

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
        let env = TypeCheckEnv {
            fn_sigs: &fn_sigs,
            fn_generics: &fn_generics,
            struct_defs: &struct_defs,
            enum_defs: &enum_defs,
            trait_impls: &trait_impls,
            global_types: &global_types,
            global_mutability: &global_mutability,
        };
        let mut state = TypeCheckState {
            errors: &mut type_errors,
            type_error_details: &mut type_error_details,
            generic_specializations: &mut generic_specializations,
            trait_violations: &mut trait_violations,
        };
        for param in &function.params {
            scopes.insert(param.name.clone(), param.ty.clone(), false);
        }
        for stmt in &function.body {
            type_check_stmt(
                stmt,
                &mut scopes,
                &env,
                0,
                &function.return_type,
                &mut state,
            );
        }
    }
    validate_async_semantics(
        &typed_functions,
        &fn_async,
        &mut type_errors,
        &mut type_error_details,
    );

    let entry_return_type = typed_functions
        .iter()
        .find(|f| f.name == "main")
        .map(|f| f.return_type.clone());
    let entry_return_const_i32 = interpret_entry_i32(&typed_functions);
    let entry_has_return_expr = typed_functions
        .iter()
        .find(|f| f.name == "main")
        .is_some_and(|f| function_has_explicit_return(&f.body));

    let (
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
        match_unreachable_arms,
        match_duplicate_catchall_arms,
    ) = collect_semantic_hints(&typed_functions);
    let (entry_requires, entry_ensures) = collect_entry_contracts(&typed_functions, &fn_sigs);
    let (
        host_syscall_sites,
        _unsafe_sites_markers,
        _unsafe_reasoned_sites_markers,
        reference_sites,
        alloc_sites,
        free_sites,
    ) = collect_effect_markers(&typed_functions);
    let unsafe_contract_sites = collect_unsafe_contract_sites(&typed_functions);
    let unsafe_sites = unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .count();
    let unsafe_reasoned_sites = unsafe_contract_sites
        .iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .filter(|site| {
            site.reason.as_deref().is_some_and(|v| !v.is_empty())
                && site.invariant.as_deref().is_some_and(|v| !v.is_empty())
                && site.owner.as_deref().is_some_and(|v| !v.is_empty())
                && site.scope.as_deref().is_some_and(|v| !v.is_empty())
                && site.risk_class.as_deref().is_some_and(|v| !v.is_empty())
                && site.proof_ref.as_deref().is_some_and(|v| !v.is_empty())
        })
        .count();
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
    let ownership_violations = analyze_ownership(&typed_functions, &call_graph);
    let unsafe_context_violations = analyze_unsafe_context_violations(&typed_functions);
    let mut capability_token_violations = if capability_token_mode_enabled(&typed_functions) {
        analyze_capability_token_contracts(&typed_functions, &function_capability_requirements)
    } else {
        Vec::new()
    };
    capability_token_violations.extend(analyze_send_sync_contracts(&typed_functions));
    let reference_lifetime_violations = analyze_reference_lifetimes(&typed_functions);
    let linear_type_violations = analyze_linear_types(&typed_functions);

    TypedModule {
        name: module.name.clone(),
        symbol_count: module.items.len(),
        capabilities: module.capabilities.clone(),
        inferred_capabilities,
        entry_return_type,
        entry_return_const_i32,
        entry_has_return_expr,
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
        match_unreachable_arms,
        match_duplicate_catchall_arms,
        entry_requires,
        entry_ensures,
        host_syscall_sites,
        unsafe_sites,
        unsafe_reasoned_sites,
        unsafe_contract_sites,
        reference_sites,
        alloc_sites,
        free_sites,
        extern_c_abi_functions,
        repr_c_layout_items,
        generic_instantiations,
        generic_specializations: generic_specializations.into_iter().collect(),
        call_graph,
        typed_functions,
        typed_globals,
        type_errors,
        type_error_details,
        function_capability_requirements,
        ownership_violations,
        unsafe_context_violations,
        capability_token_violations,
        trait_violations,
        reference_lifetime_violations,
        linear_type_violations,
    }
}

fn sanitize_test_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unnamed".to_string()
    } else {
        out
    }
}

fn validate_trait_impls(module: &Module, trait_defs: &HashMap<String, ast::Trait>) -> Vec<String> {
    let mut violations = Vec::new();
    for item in &module.items {
        let ast::Item::Impl(item) = item else {
            continue;
        };
        let Some(trait_name) = &item.trait_name else {
            continue;
        };
        let Some(trait_def) = trait_defs.get(trait_name) else {
            violations.push(format!("impl references unknown trait `{trait_name}`"));
            continue;
        };
        for method in &trait_def.methods {
            let Some(found) = item
                .methods
                .iter()
                .find(|candidate| candidate.name == method.name)
            else {
                violations.push(format!(
                    "impl for `{}` missing method `{}` required by trait `{}`",
                    item.for_type, method.name, trait_name
                ));
                continue;
            };
            if found.params.len() != method.params.len() {
                violations.push(format!(
                    "impl method `{}` parameter count mismatch for trait `{}`",
                    method.name, trait_name
                ));
            }
            if !type_compatible(&found.return_type, &method.return_type) {
                violations.push(format!(
                    "impl method `{}` return type mismatch for trait `{}`",
                    method.name, trait_name
                ));
            }
        }
    }
    violations
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
            Expr::UnsafeBlock { .. } => false,
            Expr::FieldAccess { base, .. } => expr_has_cap_intrinsic(base),
            Expr::StructInit { fields, .. } => fields
                .iter()
                .any(|(_, value)| expr_has_cap_intrinsic(value)),
            Expr::EnumInit { payload, .. } => payload.iter().any(expr_has_cap_intrinsic),
            Expr::Closure { body, .. } => expr_has_cap_intrinsic(body),
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => expr_has_cap_intrinsic(try_expr) || expr_has_cap_intrinsic(catch_expr),
            Expr::Binary { left, right, .. } => {
                expr_has_cap_intrinsic(left) || expr_has_cap_intrinsic(right)
            }
            Expr::Range { start, end, .. } => {
                expr_has_cap_intrinsic(start) || expr_has_cap_intrinsic(end)
            }
            Expr::ArrayLiteral(items) => items.iter().any(expr_has_cap_intrinsic),
            Expr::Index { base, index } => {
                expr_has_cap_intrinsic(base) || expr_has_cap_intrinsic(index)
            }
            Expr::Group(inner) => expr_has_cap_intrinsic(inner),
            Expr::Await(inner) => expr_has_cap_intrinsic(inner),
            Expr::Unary { expr, .. } => expr_has_cap_intrinsic(expr),
            Expr::Int(_)
            | Expr::Float { .. }
            | Expr::Char(_)
            | Expr::Bool(_)
            | Expr::Str(_)
            | Expr::Ident(_) => false,
        }
    }

    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_has_cap_intrinsic(value),
        Stmt::Return(None) => false,
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
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref()
                .is_some_and(statement_uses_cap_token_intrinsic)
                || condition.as_ref().is_some_and(expr_has_cap_intrinsic)
                || step
                    .as_deref()
                    .is_some_and(statement_uses_cap_token_intrinsic)
                || body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::ForIn { iterable, body, .. } => {
            expr_has_cap_intrinsic(iterable) || body.iter().any(statement_uses_cap_token_intrinsic)
        }
        Stmt::Loop { body } => body.iter().any(statement_uses_cap_token_intrinsic),
        Stmt::Break | Stmt::Continue => false,
        Stmt::Match { scrutinee, arms } => {
            expr_has_cap_intrinsic(scrutinee)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(expr_has_cap_intrinsic)
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
            | Stmt::LetPattern { .. }
            | Stmt::Assign { .. }
            | Stmt::CompoundAssign { .. }
            | Stmt::Return(_)
            | Stmt::Defer(_)
            | Stmt::Requires(_)
            | Stmt::Ensures(_)
            | Stmt::Expr(_) => {
                analyze_expr_call_tokens(
                    function_name,
                    stmt_expr(stmt),
                    local_types,
                    requirement_map,
                    violations,
                );
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
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    analyze_call_token_propagation(
                        function_name,
                        std::slice::from_ref(init.as_ref()),
                        local_types,
                        requirement_map,
                        violations,
                    );
                }
                analyze_expr_call_tokens(
                    function_name,
                    condition.as_ref(),
                    local_types,
                    requirement_map,
                    violations,
                );
                if let Some(step) = step {
                    analyze_call_token_propagation(
                        function_name,
                        std::slice::from_ref(step.as_ref()),
                        local_types,
                        requirement_map,
                        violations,
                    );
                }
                analyze_call_token_propagation(
                    function_name,
                    body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::ForIn { iterable, body, .. } => {
                analyze_expr_call_tokens(
                    function_name,
                    Some(iterable),
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
            Stmt::Loop { body } => {
                analyze_call_token_propagation(
                    function_name,
                    body,
                    local_types,
                    requirement_map,
                    violations,
                );
            }
            Stmt::Break | Stmt::Continue => {}
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
        | Stmt::LetPattern { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value)
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. } => Some(value),
        Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::For { .. }
        | Stmt::ForIn { .. }
        | Stmt::Loop { .. }
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Match { .. }
        | Stmt::Return(None) => None,
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

            if (callee == "revoke_cap" || callee == "delegate_cap") && args.is_empty() {
                violations.push(format!(
                    "function `{}` uses `{}` without token argument",
                    function_name, callee
                ));
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
        Expr::UnsafeBlock { body, .. } => {
            analyze_call_token_propagation(
                function_name,
                body,
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::FieldAccess { base, .. } => analyze_expr_call_tokens(
            function_name,
            Some(base),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                analyze_expr_call_tokens(
                    function_name,
                    Some(value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::EnumInit { payload, .. } => {
            for value in payload {
                analyze_expr_call_tokens(
                    function_name,
                    Some(value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::Closure { body, .. } => analyze_expr_call_tokens(
            function_name,
            Some(body),
            local_types,
            requirement_map,
            violations,
        ),
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
        Expr::Range { start, end, .. } => {
            analyze_expr_call_tokens(
                function_name,
                Some(start),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(end),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::ArrayLiteral(items) => {
            for item in items {
                analyze_expr_call_tokens(
                    function_name,
                    Some(item),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::Index { base, index } => {
            analyze_expr_call_tokens(
                function_name,
                Some(base),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(index),
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
        Expr::Await(inner) => analyze_expr_call_tokens(
            function_name,
            Some(inner),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Unary { expr, .. } => analyze_expr_call_tokens(
            function_name,
            Some(expr),
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Ident(_) => {}
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
            if set.is_empty() {
                None
            } else {
                Some(set)
            }
        }
        _ => None,
    }
}

fn capability_name_from_type(ty: &Type) -> Option<String> {
    match ty {
        Type::Named { name, args } if args.is_empty() => {
            core::Capability::parse(name).map(|cap| cap.as_str().to_string())
        }
        Type::TypeVar(name) => core::Capability::parse(name).map(|cap| cap.as_str().to_string()),
        _ => None,
    }
}

fn analyze_reference_lifetimes(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        let has_await = function_body_has_await(&function.body);
        let mut ref_bindings = BTreeMap::<String, (Option<String>, bool)>::new();
        for param in &function.params {
            if let Type::Ref {
                lifetime, mutable, ..
            } = &param.ty
            {
                if lifetime.is_none() {
                    violations.push(format!(
                        "function `{}` parameter `{}` is a reference missing explicit lifetime annotation",
                        function.name, param.name
                    ));
                }
                ref_bindings.insert(param.name.clone(), (lifetime.clone(), *mutable));
                if function.is_async
                    && has_await
                    && ref_used_after_await(&function.body, &param.name, *mutable)
                {
                    violations.push(format!(
                        "function `{}` cannot use {} reference `{}` across await suspension points",
                        function.name,
                        if *mutable { "mutable" } else { "borrowed" },
                        param.name
                    ));
                }
            }
        }
        let return_lifetime = match &function.return_type {
            Type::Ref { lifetime, .. } => {
                if lifetime.is_none() {
                    violations.push(format!(
                        "function `{}` return reference is missing explicit lifetime annotation",
                        function.name
                    ));
                }
                lifetime.clone()
            }
            _ => None,
        };
        for stmt in &function.body {
            if let Stmt::Let {
                name,
                ty: Some(Type::Ref {
                    lifetime, mutable, ..
                }),
                ..
            } = stmt
            {
                if lifetime.is_none() {
                    violations.push(format!(
                        "function `{}` local reference `{}` is missing explicit lifetime annotation",
                        function.name, name
                    ));
                }
                ref_bindings.insert(name.clone(), (lifetime.clone(), *mutable));
                if function.is_async
                    && has_await
                    && ref_used_after_await(&function.body, name, *mutable)
                {
                    violations.push(format!(
                        "function `{}` cannot use {} local reference `{}` across await suspension points",
                        function.name,
                        if *mutable { "mutable" } else { "borrowed" },
                        name
                    ));
                }
            }
            if let Stmt::Return(Some(Expr::Ident(name))) = stmt {
                if let Some((bound_lifetime, _)) = ref_bindings.get(name) {
                    if return_lifetime.is_some() && return_lifetime != *bound_lifetime {
                        violations.push(format!(
                            "function `{}` returns reference `{}` with mismatched lifetime (expected {:?}, got {:?})",
                            function.name, name, return_lifetime, bound_lifetime
                        ));
                    }
                } else if return_lifetime.is_some() {
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

fn ref_used_after_await(body: &[Stmt], name: &str, mutable: bool) -> bool {
    let mut seen_await = false;
    for stmt in body {
        if seen_await && stmt_uses_ident(stmt, name) {
            return true;
        }
        if stmt_has_await(stmt) {
            if mutable && stmt_uses_ident(stmt, name) {
                return true;
            }
            seen_await = true;
        }
    }
    false
}

fn analyze_send_sync_contracts(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        let requires_thread = function.is_async
            || function
                .required_capabilities
                .iter()
                .any(|cap| cap == "thread");
        if !requires_thread {
            continue;
        }
        for param in &function.params {
            if matches!(
                param.ty,
                Type::Ptr { mutable: true, .. } | Type::Ref { mutable: true, .. }
            ) {
                violations.push(format!(
                    "function `{}` parameter `{}` requires Send/Sync-safe wrapper before thread crossing",
                    function.name, param.name
                ));
            }
        }
        if matches!(function.return_type, Type::Ref { .. }) {
            violations.push(format!(
                "function `{}` returns borrowed reference across thread-capable boundary; return owned/Send-safe handle instead",
                function.name
            ));
        }
    }
    violations
}

fn function_body_has_await(body: &[Stmt]) -> bool {
    body.iter().any(stmt_has_await)
}

fn stmt_has_await(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_has_await(value),
        Stmt::Return(None) => false,
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_has_await(condition)
                || then_body.iter().any(stmt_has_await)
                || else_body.iter().any(stmt_has_await)
        }
        Stmt::While { condition, body } => {
            expr_has_await(condition) || body.iter().any(stmt_has_await)
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref().is_some_and(stmt_has_await)
                || condition.as_ref().is_some_and(expr_has_await)
                || step.as_deref().is_some_and(stmt_has_await)
                || body.iter().any(stmt_has_await)
        }
        Stmt::ForIn { iterable, body, .. } => {
            expr_has_await(iterable) || body.iter().any(stmt_has_await)
        }
        Stmt::Loop { body } => body.iter().any(stmt_has_await),
        Stmt::Break | Stmt::Continue => false,
        Stmt::Match { scrutinee, arms } => {
            expr_has_await(scrutinee)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(expr_has_await) || expr_has_await(&arm.value)
                })
        }
    }
}

fn expr_has_await(expr: &Expr) -> bool {
    match expr {
        Expr::Await(_) => true,
        Expr::Call { args, .. } => args.iter().any(expr_has_await),
        Expr::UnsafeBlock { body, .. } => body.iter().any(stmt_has_await),
        Expr::FieldAccess { base, .. } => expr_has_await(base),
        Expr::StructInit { fields, .. } => fields.iter().any(|(_, value)| expr_has_await(value)),
        Expr::EnumInit { payload, .. } => payload.iter().any(expr_has_await),
        Expr::Closure { body, .. } => expr_has_await(body),
        Expr::Group(inner) => expr_has_await(inner),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => expr_has_await(try_expr) || expr_has_await(catch_expr),
        Expr::Binary { left, right, .. } => expr_has_await(left) || expr_has_await(right),
        Expr::Range { start, end, .. } => expr_has_await(start) || expr_has_await(end),
        Expr::ArrayLiteral(items) => items.iter().any(expr_has_await),
        Expr::Index { base, index } => expr_has_await(base) || expr_has_await(index),
        Expr::Unary { expr, .. } => expr_has_await(expr),
        Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Ident(_) => false,
    }
}

fn analyze_linear_types(functions: &[TypedFunction]) -> Vec<String> {
    let mut violations = Vec::new();
    for function in functions {
        let mut linear_owned = BTreeSet::<String>::new();
        let mut linear_freed = BTreeSet::<String>::new();
        for stmt in &function.body {
            match stmt {
                Stmt::Let {
                    name, ty: Some(ty), ..
                } if is_linear_type(ty) => {
                    linear_owned.insert(name.clone());
                }
                Stmt::LetPattern { .. } => {}
                Stmt::Expr(Expr::Call { callee, args })
                    if callee == "free" || callee.ends_with(".free") =>
                {
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
        Type::Named { name, .. }
            if name == "Linear" || name == "Resource" || name.ends_with("Handle") =>
        {
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
    if function.is_async {
        caps.insert("thread".to_string());
    }
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
                        "http" | "socket" | "std.http" => {
                            self.caps.insert("http".to_string());
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
                if callee == "spawn" {
                    self.caps.insert("thread".to_string());
                }
                if matches!(callee.as_str(), "timeout" | "deadline" | "cancel") {
                    self.caps.insert("thread".to_string());
                }
            } else if matches!(expr, Expr::Await(_)) {
                self.caps.insert("thread".to_string());
            }
            ast::walk_expr(self, expr);
        }
    }

    let mut collector = Collector { caps, calls };
    for stmt in &function.body {
        collector.visit_stmt(stmt);
    }
}

fn analyze_ownership(functions: &[TypedFunction], call_graph: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let summaries = build_function_memory_summaries(functions);
    violations.extend(analyze_alias_and_provenance(functions));
    violations.extend(analyze_atomic_ordering_claims(functions));
    for function in functions {
        let mut owners = BTreeMap::<String, usize>::new();
        let mut moved = BTreeSet::<String>::new();
        let mut owner_candidates = function
            .params
            .iter()
            .map(|param| param.name.clone())
            .collect::<BTreeSet<_>>();
        let mut next_alloc = 1usize;
        analyze_ownership_block(
            &function.body,
            &mut owners,
            &mut moved,
            &mut owner_candidates,
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
    for (caller, callee) in call_graph {
        let Some(callee_summary) = summaries.get(callee) else {
            continue;
        };
        let Some(caller_summary) = summaries.get(caller) else {
            continue;
        };
        if callee_summary.unsafe_sites > 0 && callee_summary.unsafe_reasoned_sites == 0 {
            violations.push(format!(
                "call edge `{caller} -> {callee}` reaches unsafe code without invariant proof/reasoned contract",
            ));
        }
        if callee_summary.alloc_sites > callee_summary.free_sites + callee_summary.close_sites {
            violations.push(format!(
                "call edge `{caller} -> {callee}` crosses function with potential resource escape (alloc/free+close imbalance)",
            ));
        }
        if caller_summary.is_async && caller_summary.has_await && callee_summary.has_mut_ref_params
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` can hold mutable borrows across await boundary",
            ));
        }
        if caller_summary.is_async
            && caller_summary.has_await
            && callee_summary.has_ref_params
            && callee_summary.returns_ref
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` can propagate borrowed references across async suspension boundary",
            ));
        }
        if (callee_summary.generic_param_count > 0 || callee_summary.trait_bound_count > 0)
            && callee_summary.has_ref_params
            && caller_summary.is_async
            && caller_summary.has_await
        {
            violations.push(format!(
                "call edge `{caller} -> {callee}` is generic/trait-heavy with borrowed parameters across await; inter-procedural lifetime summary rejected",
            ));
        }
    }
    violations
}

fn analyze_unsafe_context_violations(functions: &[TypedFunction]) -> Vec<String> {
    fn analyze_stmt(
        function_name: &str,
        stmt: &Stmt,
        in_unsafe_context: bool,
        unsafe_functions: &BTreeSet<String>,
        violations: &mut Vec<String>,
    ) {
        match stmt {
            Stmt::Let { value, .. }
            | Stmt::LetPattern { value, .. }
            | Stmt::Assign { value, .. }
            | Stmt::CompoundAssign { value, .. }
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value)
            | Stmt::Expr(value) => analyze_expr(
                function_name,
                value,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Stmt::Return(value) => {
                if let Some(value) = value {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for nested in then_body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                for nested in else_body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::While { condition, body } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
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
                    analyze_stmt(
                        function_name,
                        init,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                if let Some(condition) = condition {
                    analyze_expr(
                        function_name,
                        condition,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                if let Some(step) = step {
                    analyze_stmt(
                        function_name,
                        step,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::ForIn { iterable, body, .. } => {
                analyze_expr(
                    function_name,
                    iterable,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::Loop { body } => {
                for nested in body {
                    analyze_stmt(
                        function_name,
                        nested,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::Match { scrutinee, arms } => {
                analyze_expr(
                    function_name,
                    scrutinee,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        analyze_expr(
                            function_name,
                            guard,
                            in_unsafe_context,
                            unsafe_functions,
                            violations,
                        );
                    }
                    analyze_expr(
                        function_name,
                        &arm.value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Stmt::Break | Stmt::Continue => {}
        }
    }

    fn analyze_expr(
        function_name: &str,
        expr: &Expr,
        in_unsafe_context: bool,
        unsafe_functions: &BTreeSet<String>,
        violations: &mut Vec<String>,
    ) {
        match expr {
            Expr::Call { callee, args } => {
                if !in_unsafe_context {
                    if let Some(unsafe_callee) = resolve_unsafe_callee(unsafe_functions, callee) {
                        violations.push(format!(
                            "function `{}` calls unsafe function `{}` outside `unsafe` context",
                            function_name, unsafe_callee
                        ));
                    }
                }
                for arg in args {
                    analyze_expr(
                        function_name,
                        arg,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::UnsafeBlock { body, .. } => {
                for stmt in body {
                    analyze_stmt(function_name, stmt, true, unsafe_functions, violations);
                }
            }
            Expr::FieldAccess { base, .. } => analyze_expr(
                function_name,
                base,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::EnumInit { payload, .. } => {
                for value in payload {
                    analyze_expr(
                        function_name,
                        value,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Closure { body, .. } => analyze_expr(
                function_name,
                body,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Expr::Group(inner) | Expr::Await(inner) | Expr::Unary { expr: inner, .. } => {
                analyze_expr(
                    function_name,
                    inner,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                )
            }
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                analyze_expr(
                    function_name,
                    try_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    catch_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
            }
            Expr::Binary { left, right, .. }
            | Expr::Range {
                start: left,
                end: right,
                ..
            } => {
                analyze_expr(
                    function_name,
                    left,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    right,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
            }
            Expr::ArrayLiteral(items) => {
                for item in items {
                    analyze_expr(
                        function_name,
                        item,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Index { base, index } => {
                analyze_expr(
                    function_name,
                    base,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    index,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
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

    let unsafe_functions = functions
        .iter()
        .filter(|function| function.is_unsafe)
        .map(|function| function.name.clone())
        .collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for function in functions {
        let context = function.is_unsafe;
        for stmt in &function.body {
            analyze_stmt(
                &function.name,
                stmt,
                context,
                &unsafe_functions,
                &mut violations,
            );
        }
    }
    violations
}

fn resolve_unsafe_callee(unsafe_functions: &BTreeSet<String>, callee: &str) -> Option<String> {
    if unsafe_functions.contains(callee) {
        return Some(callee.to_string());
    }
    let suffix = format!(".{callee}");
    let mut matched: Option<String> = None;
    for candidate in unsafe_functions {
        if candidate.ends_with(&suffix) || candidate == callee {
            if matched.is_some() {
                return None;
            }
            matched = Some(candidate.clone());
        }
    }
    matched
}

fn analyze_ownership_block(
    body: &[Stmt],
    owners: &mut BTreeMap<String, usize>,
    moved: &mut BTreeSet<String>,
    owner_candidates: &mut BTreeSet<String>,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
) {
    for stmt in body {
        for name in moved.iter() {
            if stmt_uses_ident(stmt, name) {
                violations.push(format!(
                    "function `{}` uses moved value `{}` after move/consume",
                    function_name, name
                ));
            }
        }
        match stmt {
            Stmt::Let { name, value, .. } => {
                owner_candidates.insert(name.clone());
                if is_alloc_expr(value) {
                    owners.insert(name.clone(), *next_alloc);
                    *next_alloc += 1;
                    moved.remove(name);
                }
                if let Expr::Ident(from) = value {
                    if let Some(owner) = owners.remove(from) {
                        owners.insert(name.clone(), owner);
                        moved.insert(from.clone());
                        moved.remove(name);
                    }
                }
                if is_partial_move_expr(value, owners) {
                    violations.push(format!(
                        "function `{}` performs partial move from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::LetPattern { pattern, value, .. } => {
                collect_pattern_bindings(pattern, owner_candidates);
                if is_partial_move_expr(value, owners) {
                    violations.push(format!(
                        "function `{}` performs partial move from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::Assign { target, value } => {
                owner_candidates.insert(target.clone());
                if let Expr::Ident(from) = value {
                    if let Some(owner) = owners.remove(from) {
                        owners.insert(target.clone(), owner);
                        moved.insert(from.clone());
                    }
                }
                moved.remove(target);
                if is_partial_move_expr(value, owners) {
                    violations.push(format!(
                        "function `{}` performs partial move assignment from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::CompoundAssign { target, value, .. } => {
                owner_candidates.insert(target.clone());
                if let Expr::Ident(from) = value {
                    if let Some(owner) = owners.remove(from) {
                        owners.insert(target.clone(), owner);
                        moved.insert(from.clone());
                    }
                }
                moved.remove(target);
            }
            Stmt::Expr(Expr::Call { callee, args }) => {
                if callee == "free"
                    || callee.ends_with(".free")
                    || callee == "close"
                    || callee.ends_with(".close")
                {
                    if let Some(Expr::Ident(name)) = args.first() {
                        if owners.remove(name).is_none() {
                            violations.push(format!(
                                "function `{}` consumes non-owned or already-consumed value `{}` via `{}`",
                                function_name, name, callee
                            ));
                        } else {
                            moved.insert(name.clone());
                        }
                    }
                }
            }
            Stmt::Expr(Expr::UnsafeBlock { body, .. }) => {
                analyze_ownership_block(
                    body,
                    owners,
                    moved,
                    owner_candidates,
                    next_alloc,
                    violations,
                    function_name,
                );
            }
            Stmt::Return(Some(Expr::Ident(name))) => {
                owners.remove(name);
                moved.insert(name.clone());
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let mut then_owners = owners.clone();
                let mut else_owners = owners.clone();
                let mut then_moved = moved.clone();
                let mut else_moved = moved.clone();
                let mut then_owner_candidates = owner_candidates.clone();
                let mut else_owner_candidates = owner_candidates.clone();
                analyze_ownership_block(
                    then_body,
                    &mut then_owners,
                    &mut then_moved,
                    &mut then_owner_candidates,
                    next_alloc,
                    violations,
                    function_name,
                );
                analyze_ownership_block(
                    else_body,
                    &mut else_owners,
                    &mut else_moved,
                    &mut else_owner_candidates,
                    next_alloc,
                    violations,
                    function_name,
                );
                *owners = then_owners
                    .into_iter()
                    .filter(|(name, id)| else_owners.get(name).is_some_and(|other| other == id))
                    .collect();
                *moved = then_moved
                    .intersection(&else_moved)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                *owner_candidates = then_owner_candidates
                    .intersection(&else_owner_candidates)
                    .cloned()
                    .collect::<BTreeSet<_>>();
            }
            Stmt::While { body, .. } => {
                analyze_ownership_block(
                    body,
                    owners,
                    moved,
                    owner_candidates,
                    next_alloc,
                    violations,
                    function_name,
                );
            }
            Stmt::For {
                init,
                condition: _,
                step,
                body,
            } => {
                if let Some(init) = init {
                    analyze_ownership_block(
                        std::slice::from_ref(init.as_ref()),
                        owners,
                        moved,
                        owner_candidates,
                        next_alloc,
                        violations,
                        function_name,
                    );
                }
                analyze_ownership_block(
                    body,
                    owners,
                    moved,
                    owner_candidates,
                    next_alloc,
                    violations,
                    function_name,
                );
                if let Some(step) = step {
                    analyze_ownership_block(
                        std::slice::from_ref(step.as_ref()),
                        owners,
                        moved,
                        owner_candidates,
                        next_alloc,
                        violations,
                        function_name,
                    );
                }
            }
            Stmt::ForIn { binding, body, .. } => {
                moved.remove(binding);
                owner_candidates.insert(binding.clone());
                analyze_ownership_block(
                    body,
                    owners,
                    moved,
                    owner_candidates,
                    next_alloc,
                    violations,
                    function_name,
                );
            }
            Stmt::Loop { body } => {
                analyze_ownership_block(
                    body,
                    owners,
                    moved,
                    owner_candidates,
                    next_alloc,
                    violations,
                    function_name,
                );
            }
            Stmt::Break | Stmt::Continue => {}
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

#[derive(Debug, Clone, Copy)]
struct FunctionMemorySummary {
    alloc_sites: usize,
    free_sites: usize,
    close_sites: usize,
    unsafe_sites: usize,
    unsafe_reasoned_sites: usize,
    has_mut_ref_params: bool,
    has_ref_params: bool,
    returns_ref: bool,
    generic_param_count: usize,
    trait_bound_count: usize,
    has_await: bool,
    is_async: bool,
}

fn build_function_memory_summaries(
    functions: &[TypedFunction],
) -> BTreeMap<String, FunctionMemorySummary> {
    let mut out = BTreeMap::new();
    for function in functions {
        let mut alloc_sites = 0usize;
        let mut free_sites = 0usize;
        let mut close_sites = 0usize;
        let mut unsafe_sites = 0usize;
        let mut unsafe_reasoned_sites = 0usize;
        let mut has_await = false;
        if function.is_unsafe {
            unsafe_sites += 1;
            unsafe_reasoned_sites += 1;
        }
        struct Collector<'a> {
            alloc_sites: &'a mut usize,
            free_sites: &'a mut usize,
            close_sites: &'a mut usize,
            unsafe_sites: &'a mut usize,
            unsafe_reasoned_sites: &'a mut usize,
            has_await: &'a mut bool,
        }
        impl AstVisitor for Collector<'_> {
            fn visit_expr(&mut self, expr: &Expr) {
                match expr {
                    Expr::Call { callee, args } => {
                        if is_alloc_callee(callee) {
                            *self.alloc_sites += 1;
                        }
                        if is_free_callee(callee) {
                            *self.free_sites += 1;
                        }
                        if is_close_callee(callee) {
                            *self.close_sites += 1;
                        }
                        let _ = args;
                    }
                    Expr::UnsafeBlock { .. } => {
                        *self.unsafe_sites += 1;
                        *self.unsafe_reasoned_sites += 1;
                    }
                    Expr::Await(_) => {
                        *self.has_await = true;
                    }
                    _ => {}
                }
                ast::walk_expr(self, expr);
            }
        }
        let mut collector = Collector {
            alloc_sites: &mut alloc_sites,
            free_sites: &mut free_sites,
            close_sites: &mut close_sites,
            unsafe_sites: &mut unsafe_sites,
            unsafe_reasoned_sites: &mut unsafe_reasoned_sites,
            has_await: &mut has_await,
        };
        for stmt in &function.body {
            collector.visit_stmt(stmt);
        }
        let has_mut_ref_params = function
            .params
            .iter()
            .any(|param| matches!(param.ty, Type::Ref { mutable: true, .. }));
        let has_ref_params = function
            .params
            .iter()
            .any(|param| matches!(param.ty, Type::Ref { .. }));
        let returns_ref = matches!(function.return_type, Type::Ref { .. });
        let generic_param_count = function.generics.len();
        let trait_bound_count = function
            .generics
            .iter()
            .map(|g| g.bounds.len())
            .sum::<usize>();
        out.insert(
            function.name.clone(),
            FunctionMemorySummary {
                alloc_sites,
                free_sites,
                close_sites,
                unsafe_sites,
                unsafe_reasoned_sites,
                has_mut_ref_params,
                has_ref_params,
                returns_ref,
                generic_param_count,
                trait_bound_count,
                has_await,
                is_async: function.is_async,
            },
        );
    }
    out
}

fn stmt_uses_ident(stmt: &Stmt, target: &str) -> bool {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Assign { value, .. }
        | Stmt::CompoundAssign { value, .. }
        | Stmt::Return(Some(value))
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => expr_uses_ident(value, target),
        Stmt::Return(None) => false,
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            expr_uses_ident(condition, target)
                || then_body
                    .iter()
                    .any(|nested| stmt_uses_ident(nested, target))
                || else_body
                    .iter()
                    .any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::While { condition, body } => {
            expr_uses_ident(condition, target)
                || body.iter().any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_deref()
                .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || condition
                    .as_ref()
                    .is_some_and(|expr| expr_uses_ident(expr, target))
                || step
                    .as_deref()
                    .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || body.iter().any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::ForIn { iterable, body, .. } => {
            expr_uses_ident(iterable, target)
                || body.iter().any(|nested| stmt_uses_ident(nested, target))
        }
        Stmt::Loop { body } => body.iter().any(|nested| stmt_uses_ident(nested, target)),
        Stmt::Break | Stmt::Continue => false,
        Stmt::Match { scrutinee, arms } => {
            expr_uses_ident(scrutinee, target)
                || arms.iter().any(|arm| {
                    arm.guard
                        .as_ref()
                        .is_some_and(|guard| expr_uses_ident(guard, target))
                        || expr_uses_ident(&arm.value, target)
                })
        }
    }
}

fn expr_uses_ident(expr: &Expr, target: &str) -> bool {
    match expr {
        Expr::Ident(name) => name == target,
        Expr::Call { args, .. } => args.iter().any(|arg| expr_uses_ident(arg, target)),
        Expr::UnsafeBlock { body, meta } => {
            meta.as_ref().is_some_and(|m| m.owner == target)
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::FieldAccess { base, .. } => expr_uses_ident(base, target),
        Expr::StructInit { fields, .. } => fields
            .iter()
            .any(|(_, value)| expr_uses_ident(value, target)),
        Expr::EnumInit { payload, .. } => {
            payload.iter().any(|value| expr_uses_ident(value, target))
        }
        Expr::Closure { params, body, .. } => {
            if params.iter().any(|param| param.name == target) {
                false
            } else {
                expr_uses_ident(body, target)
            }
        }
        Expr::Group(inner) | Expr::Await(inner) => expr_uses_ident(inner, target),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => expr_uses_ident(try_expr, target) || expr_uses_ident(catch_expr, target),
        Expr::Binary { left, right, .. } => {
            expr_uses_ident(left, target) || expr_uses_ident(right, target)
        }
        Expr::Range { start, end, .. } => {
            expr_uses_ident(start, target) || expr_uses_ident(end, target)
        }
        Expr::ArrayLiteral(items) => items.iter().any(|item| expr_uses_ident(item, target)),
        Expr::Index { base, index } => {
            expr_uses_ident(base, target) || expr_uses_ident(index, target)
        }
        Expr::Unary { expr, .. } => expr_uses_ident(expr, target),
        Expr::Int(_) | Expr::Float { .. } | Expr::Char(_) | Expr::Bool(_) | Expr::Str(_) => false,
    }
}

fn is_partial_move_expr(expr: &Expr, owners: &BTreeMap<String, usize>) -> bool {
    matches!(
        expr,
        Expr::FieldAccess {
            base,
            ..
        } if matches!(base.as_ref(), Expr::Ident(name) if owners.contains_key(name))
    )
}

fn is_alloc_callee(callee: &str) -> bool {
    callee == "alloc" || callee.ends_with(".alloc")
}

fn is_free_callee(callee: &str) -> bool {
    callee == "free" || callee.ends_with(".free")
}

fn is_close_callee(callee: &str) -> bool {
    callee == "close" || callee.ends_with(".close")
}

fn is_alloc_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { callee, .. } if callee == "alloc" || callee.ends_with(".alloc"))
}

fn analyze_alias_and_provenance(functions: &[TypedFunction]) -> Vec<String> {
    #[derive(Debug, Clone)]
    struct CallShape {
        params: Vec<ast::Param>,
        return_type: Type,
        is_extern: bool,
        is_unsafe: bool,
    }
    let mut violations = Vec::new();
    let signatures = functions
        .iter()
        .map(|function| {
            (
                function.name.clone(),
                CallShape {
                    params: function.params.clone(),
                    return_type: function.return_type.clone(),
                    is_extern: function.is_extern,
                    is_unsafe: function.is_unsafe,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for function in functions {
        let mut next_root = 1usize;
        let mut roots = BTreeMap::<String, usize>::new();
        let mut freed_roots = BTreeSet::<usize>::new();
        for param in &function.params {
            if param.ty.is_pointer_like() || matches!(param.ty, Type::Ref { .. }) {
                roots.insert(param.name.clone(), next_root);
                next_root += 1;
            }
        }
        for stmt in &function.body {
            let used = collect_stmt_idents(stmt);
            for used_name in used {
                let Some(root) = roots.get(&used_name).copied() else {
                    continue;
                };
                if freed_roots.contains(&root) && !stmt_is_direct_free_of(stmt, &used_name) {
                    violations.push(format!(
                        "function `{}` uses value `{}` after provenance root {} was freed",
                        function.name, used_name, root
                    ));
                }
            }
            match stmt {
                Stmt::Let { name, value, .. } => {
                    if is_alloc_expr(value) {
                        roots.insert(name.clone(), next_root);
                        next_root += 1;
                    } else if let Expr::Ident(from) = value {
                        if let Some(root) = roots.get(from).copied() {
                            roots.insert(name.clone(), root);
                        }
                    } else if let Expr::FieldAccess { base, .. } = value {
                        if let Expr::Ident(from) = base.as_ref() {
                            if let Some(root) = roots.get(from).copied() {
                                roots.insert(name.clone(), root);
                            }
                        }
                    } else if let Expr::Call { callee, args } = value {
                        if let Some(shape) = signatures.get(callee) {
                            if matches!(shape.return_type, Type::Ref { .. } | Type::Ptr { .. }) {
                                let maybe_root = args.iter().find_map(|arg| match arg {
                                    Expr::Ident(arg_name) => roots.get(arg_name).copied(),
                                    _ => None,
                                });
                                if let Some(root) = maybe_root {
                                    roots.insert(name.clone(), root);
                                }
                            }
                        }
                    }
                }
                Stmt::LetPattern { .. } => {}
                Stmt::Assign {
                    target,
                    value: Expr::Ident(from),
                } => {
                    if let Some(root) = roots.get(from).copied() {
                        roots.insert(target.clone(), root);
                    }
                }
                Stmt::Assign {
                    target,
                    value: Expr::Call { callee, args },
                } => {
                    if let Some(shape) = signatures.get(callee) {
                        if matches!(shape.return_type, Type::Ref { .. } | Type::Ptr { .. }) {
                            let maybe_root = args.iter().find_map(|arg| match arg {
                                Expr::Ident(arg_name) => roots.get(arg_name).copied(),
                                _ => None,
                            });
                            if let Some(root) = maybe_root {
                                roots.insert(target.clone(), root);
                            }
                        }
                    }
                }
                Stmt::Assign { .. } => {}
                Stmt::Expr(Expr::Call { callee, args }) => {
                    if is_free_callee(callee) {
                        if let Some(Expr::Ident(name)) = args.first() {
                            if let Some(root) = roots.get(name).copied() {
                                if !freed_roots.insert(root) {
                                    violations.push(format!(
                                        "function `{}` double-frees provenance root {} via `{}`",
                                        function.name, root, name
                                    ));
                                }
                            }
                        }
                    }
                    if let Some(shape) = signatures.get(callee) {
                        let mut mut_ref_aliases = BTreeMap::<String, usize>::new();
                        let mut shared_ref_aliases = BTreeMap::<String, usize>::new();
                        for (index, param) in shape.params.iter().enumerate() {
                            let Some(Expr::Ident(arg_name)) = args.get(index) else {
                                continue;
                            };
                            match &param.ty {
                                Type::Ref { mutable: true, .. } => {
                                    *mut_ref_aliases.entry(arg_name.clone()).or_default() += 1;
                                }
                                Type::Ref { mutable: false, .. } => {
                                    *shared_ref_aliases.entry(arg_name.clone()).or_default() += 1;
                                }
                                _ => {}
                            }
                        }
                        for (name, count) in &mut_ref_aliases {
                            if *count > 1 {
                                violations.push(format!(
                                    "function `{}` call `{}` aliases mutable reference parameter `{}` {} times",
                                    function.name, callee, name, count
                                ));
                            }
                            if shared_ref_aliases.contains_key(name) {
                                violations.push(format!(
                                    "function `{}` call `{}` aliases mutable and shared borrows for `{}`",
                                    function.name, callee, name
                                ));
                            }
                        }
                        if shape.is_extern && shape.is_unsafe {
                            for (index, param) in shape.params.iter().enumerate() {
                                let Some(Expr::Ident(arg_name)) = args.get(index) else {
                                    continue;
                                };
                                if param.name.ends_with("_owned") {
                                    if let Some(root) = roots.remove(arg_name) {
                                        freed_roots.insert(root);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    violations
}

fn analyze_atomic_ordering_claims(functions: &[TypedFunction]) -> Vec<String> {
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

fn validate_atomic_call(callee: &str, args: &[Expr]) -> Option<String> {
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

fn stmt_is_direct_free_of(stmt: &Stmt, name: &str) -> bool {
    matches!(
        stmt,
        Stmt::Expr(Expr::Call { callee, args })
            if is_free_callee(callee)
                && matches!(args.first(), Some(Expr::Ident(arg)) if arg == name)
    )
}

fn collect_stmt_idents(stmt: &Stmt) -> Vec<String> {
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
        Stmt::Break | Stmt::Continue => {}
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

fn collect_expr_idents(expr: &Expr, out: &mut Vec<String>) {
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
        Expr::Closure { params, body, .. } => {
            let mut nested = Vec::new();
            collect_expr_idents(body, &mut nested);
            for ident in nested {
                if !params.iter().any(|param| param.name == ident) {
                    out.push(ident);
                }
            }
        }
        Expr::Group(inner) | Expr::Await(inner) => collect_expr_idents(inner, out),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_expr_idents(try_expr, out);
            collect_expr_idents(catch_expr, out);
        }
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
        Expr::Index { base, index } => {
            collect_expr_idents(base, out);
            collect_expr_idents(index, out);
        }
        Expr::Unary { expr, .. } => collect_expr_idents(expr, out),
        Expr::Int(_) | Expr::Float { .. } | Expr::Char(_) | Expr::Bool(_) | Expr::Str(_) => {}
    }
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

fn infer_capabilities(functions: &[TypedFunction]) -> Vec<String> {
    let mut caps = BTreeSet::new();
    for function in functions {
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
                            "rng" | "random" | "std.rand" => {
                                self.caps.insert("rng".to_string());
                            }
                            "fs" | "file" | "std.io" => {
                                self.caps.insert("fs".to_string());
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
                            "thread" | "std.thread" => {
                                self.caps.insert("thread".to_string());
                            }
                            _ => {}
                        }
                    }
                    if callee == "spawn" {
                        self.caps.insert("thread".to_string());
                    }
                    if matches!(callee.as_str(), "timeout" | "deadline" | "cancel") {
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
                for method in &item.methods {
                    collect_type_instantiation(&method.return_type, &mut out);
                    for param in &method.params {
                        collect_type_instantiation(&param.ty, &mut out);
                    }
                }
            }
            ast::Item::Impl(item) => {
                collect_type_instantiation(&item.for_type, &mut out);
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
        Type::Function { params, ret } => {
            for param in params {
                collect_type_instantiation(param, out);
            }
            collect_type_instantiation(ret, out);
        }
        Type::Void
        | Type::Bool
        | Type::ISize
        | Type::USize
        | Type::Int { .. }
        | Type::Float { .. }
        | Type::Char
        | Type::Str
        | Type::Named { .. }
        | Type::TypeVar(_) => {}
    }
}

fn collect_semantic_hints(
    functions: &[TypedFunction],
) -> (Vec<String>, Vec<String>, usize, usize, usize) {
    let mut linear_resources = Vec::new();
    let mut deferred_resources = Vec::new();
    let mut matches_without_wildcard = 0usize;
    let mut match_unreachable_arms = 0usize;
    let mut match_duplicate_catchall_arms = 0usize;

    for function in functions {
        for statement in &function.body {
            collect_semantic_hints_from_stmt(
                statement,
                &mut linear_resources,
                &mut deferred_resources,
                &mut matches_without_wildcard,
                &mut match_unreachable_arms,
                &mut match_duplicate_catchall_arms,
            );
        }
    }

    (
        linear_resources,
        deferred_resources,
        matches_without_wildcard,
        match_unreachable_arms,
        match_duplicate_catchall_arms,
    )
}

fn collect_semantic_hints_from_stmt(
    statement: &Stmt,
    linear_resources: &mut Vec<String>,
    deferred_resources: &mut Vec<String>,
    matches_without_wildcard: &mut usize,
    match_unreachable_arms: &mut usize,
    match_duplicate_catchall_arms: &mut usize,
) {
    match statement {
        Stmt::Let {
            name, ty: Some(ty), ..
        } if ty.is_pointer_like() => {
            linear_resources.push(name.clone());
        }
        Stmt::LetPattern { .. } => {}
        Stmt::Defer(expr) => {
            if let Some(resource) = deferred_resource(expr) {
                deferred_resources.push(resource);
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            for nested in then_body {
                collect_semantic_hints_from_stmt(
                    nested,
                    linear_resources,
                    deferred_resources,
                    matches_without_wildcard,
                    match_unreachable_arms,
                    match_duplicate_catchall_arms,
                );
            }
            for nested in else_body {
                collect_semantic_hints_from_stmt(
                    nested,
                    linear_resources,
                    deferred_resources,
                    matches_without_wildcard,
                    match_unreachable_arms,
                    match_duplicate_catchall_arms,
                );
            }
        }
        Stmt::While { body, .. } => {
            for nested in body {
                collect_semantic_hints_from_stmt(
                    nested,
                    linear_resources,
                    deferred_resources,
                    matches_without_wildcard,
                    match_unreachable_arms,
                    match_duplicate_catchall_arms,
                );
            }
        }
        Stmt::Match { arms, .. } => {
            if !arms
                .iter()
                .any(|arm| pattern_is_catchall(&arm.pattern) && arm.guard.is_none())
            {
                *matches_without_wildcard += 1;
            }
            let mut seen_catchall = false;
            for arm in arms {
                let is_catchall = pattern_is_catchall(&arm.pattern) && arm.guard.is_none();
                if seen_catchall {
                    *match_unreachable_arms += 1;
                    if is_catchall {
                        *match_duplicate_catchall_arms += 1;
                    }
                } else if is_catchall {
                    seen_catchall = true;
                }
            }
        }
        _ => {}
    }
}

fn collect_effect_markers(
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

fn collect_unsafe_contract_sites(functions: &[TypedFunction]) -> Vec<UnsafeContractSite> {
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

fn collect_unsafe_contract_sites_from_stmt(
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
        Stmt::Break | Stmt::Continue => {}
    }
}

fn collect_unsafe_contract_sites_from_expr(
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
        Expr::Closure { body, .. } => collect_unsafe_contract_sites_from_expr(
            body,
            function_name,
            in_unsafe_context,
            in_async_context,
            owner,
            unsafe_functions,
            out,
        ),
        Expr::Group(inner) | Expr::Await(inner) | Expr::Unary { expr: inner, .. } => {
            collect_unsafe_contract_sites_from_expr(
                inner,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            )
        }
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

fn generated_unsafe_contract_site(
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

fn unsafe_violation_site(
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

fn stable_unsafe_site_id(kind: &str, function_name: &str, snippet: &str) -> String {
    let material = format!("{kind}|{function_name}|{snippet}");
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in material.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("usite_{hash:016x}")
}

fn deferred_resource(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::Call { args, .. } => args.first().and_then(|arg| match arg {
            ast::Expr::Ident(name) => Some(name.clone()),
            _ => None,
        }),
        ast::Expr::UnsafeBlock { meta, .. } => meta.as_ref().map(|m| m.owner.clone()),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => deferred_resource(try_expr).or_else(|| deferred_resource(catch_expr)),
        ast::Expr::FieldAccess { base, .. } => deferred_resource(base),
        ast::Expr::StructInit { fields, .. } => fields
            .iter()
            .find_map(|(_, value)| deferred_resource(value)),
        ast::Expr::EnumInit { payload, .. } => payload.iter().find_map(deferred_resource),
        ast::Expr::Closure { body, .. } => deferred_resource(body),
        ast::Expr::Await(inner) => deferred_resource(inner),
        ast::Expr::ArrayLiteral(items) => items.iter().find_map(deferred_resource),
        ast::Expr::Index { base, index } => {
            deferred_resource(base).or_else(|| deferred_resource(index))
        }
        ast::Expr::Unary { expr, .. } => deferred_resource(expr),
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Range { .. }
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

fn validate_async_semantics(
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

struct TypeCheckEnv<'a> {
    fn_sigs: &'a HashMap<String, (Vec<Type>, Type)>,
    fn_generics: &'a HashMap<String, Vec<ast::GenericParam>>,
    struct_defs: &'a HashMap<String, ast::Struct>,
    enum_defs: &'a HashMap<String, ast::Enum>,
    trait_impls: &'a HashMap<String, Vec<Type>>,
    global_types: &'a HashMap<String, Type>,
    global_mutability: &'a HashMap<String, bool>,
}

struct TypeCheckState<'a> {
    errors: &'a mut usize,
    type_error_details: &'a mut Vec<String>,
    generic_specializations: &'a mut BTreeSet<String>,
    trait_violations: &'a mut Vec<String>,
}

fn type_check_stmt(
    stmt: &Stmt,
    scopes: &mut SymbolScopes,
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
                    if !type_compatible(explicit, &actual) {
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
                    if !type_compatible(explicit, &actual) {
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
                type_check_stmt(stmt, scopes, env, loop_depth, expected_return, state);
            }
            scopes.pop();
            scopes.push();
            for stmt in else_body {
                type_check_stmt(stmt, scopes, env, loop_depth, expected_return, state);
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
                type_check_stmt(stmt, scopes, env, loop_depth + 1, expected_return, state);
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
                type_check_stmt(init, scopes, env, loop_depth + 1, expected_return, state);
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
                type_check_stmt(stmt, scopes, env, loop_depth + 1, expected_return, state);
            }
            if let Some(step) = step {
                type_check_stmt(step, scopes, env, loop_depth + 1, expected_return, state);
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
            for stmt in body {
                type_check_stmt(stmt, scopes, env, loop_depth + 1, expected_return, state);
            }
            scopes.pop();
        }
        Stmt::Loop { body } => {
            scopes.push();
            for stmt in body {
                type_check_stmt(stmt, scopes, env, loop_depth + 1, expected_return, state);
            }
            scopes.pop();
        }
        Stmt::Break => {
            if loop_depth == 0 {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    "`break` is only valid inside loop bodies".to_string(),
                );
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
                if !type_compatible(expected_return, &actual) {
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
            for arm in arms {
                scopes.push();
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
        Stmt::Defer(expr) | Stmt::Requires(expr) | Stmt::Ensures(expr) | Stmt::Expr(expr) => {
            let _ = infer_expr_type(expr, scopes, env, state);
        }
    }
}

fn infer_expr_type(
    expr: &Expr,
    scopes: &SymbolScopes,
    env: &TypeCheckEnv<'_>,
    state: &mut TypeCheckState<'_>,
) -> Option<Type> {
    let fn_sigs = env.fn_sigs;
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
            if let Some(fn_ty) = function_ref_type(fn_sigs, name) {
                return Some(fn_ty);
            }
            record_type_error(
                state.errors,
                state.type_error_details,
                format!("unresolved identifier `{name}`"),
            );
            None
        }
        Expr::UnsafeBlock { .. } => Some(Type::Void),
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
        Expr::Await(inner) => infer_expr_type(inner, scopes, env, state),
        Expr::Call { callee, args } => {
            let (base_callee, explicit_types) = split_generic_callee(callee);
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
                        if !type_compatible(expected, actual) {
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
            let runtime_sig = runtime_call_signature(base_callee);
            let (params, ret) = if let Some((params, ret)) = fn_sigs.get(base_callee) {
                (params.clone(), ret.clone())
            } else if let Some((params, ret)) = runtime_sig {
                (params, ret)
            } else {
                record_type_error(
                    state.errors,
                    state.type_error_details,
                    format!("unresolved call target `{}`", base_callee),
                );
                return None;
            };
            let generics = fn_generics.get(base_callee).cloned().unwrap_or_default();
            let mut arg_types = Vec::with_capacity(args.len());
            for arg in args {
                arg_types.push(infer_expr_type(arg, scopes, env, state));
            }
            let (resolved_params, resolved_ret, bindings, skip_post_call_validation) = if fn_sigs
                .contains_key(base_callee)
            {
                let Some((resolved_params, resolved_ret, bindings)) = resolve_call_signature(
                    &params,
                    &ret,
                    &generics,
                    &arg_types,
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
                (resolved_params, resolved_ret, bindings, false)
            } else {
                if params.len() != args.len() {
                    let detail = if matches!(base_callee, "http.write" | "http.write_json")
                        && args.len() == 1
                    {
                        format!(
                            "runtime call `{}` migrated to `(conn, status, body)`; update call sites like `{}(conn, 200, \"ok\")`",
                            base_callee, base_callee
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
                for (expected, actual) in params.iter().zip(arg_types.iter()) {
                    let Some(actual) = actual else {
                        continue;
                    };
                    if !type_compatible(expected, actual) {
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
                (params.clone(), ret.clone(), Vec::new(), true)
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
                            if !type_satisfies_trait(concrete, bound, trait_impls) {
                                let detail = format!(
                                    "generic specialization `{}` violates bound `{}` on `{}`",
                                    base_callee, bound, generic.name
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
                for (index, arg_ty) in arg_types.into_iter().enumerate() {
                    if let (Some(expected), Some(actual)) = (resolved_params.get(index), arg_ty) {
                        if !type_compatible(expected, &actual) {
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
                    if !type_compatible(&found.ty, &value_ty) {
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
            Some(Type::Named {
                name: name.clone(),
                args: Vec::new(),
            })
        }
        Expr::EnumInit {
            enum_name,
            variant,
            payload,
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
                if let (Some(expected), Some(actual)) = (found_variant.payload.get(index), value_ty)
                {
                    if !type_compatible(expected, &actual) {
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
            Some(Type::Named {
                name: enum_name.clone(),
                args: Vec::new(),
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
        Expr::Index { base, index } => {
            let base_ty = infer_expr_type(base, scopes, env, state);
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
                    } else if left_ty.as_ref().is_some_and(is_float_type)
                        && right_ty.as_ref().is_some_and(is_float_type)
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
                                "arithmetic operands must be numeric-compatible, got left=`{left}` right=`{right}`"
                            ),
                        );
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
                        if !type_compatible(l, r) {
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

fn split_generic_callee(callee: &str) -> (&str, Option<Vec<Type>>) {
    let Some(start) = callee.find('<') else {
        return (callee, None);
    };
    let Some(end) = callee.rfind('>') else {
        return (&callee[..start], None);
    };
    let base = &callee[..start];
    let inside = &callee[start + 1..end];
    let parsed = inside
        .split(',')
        .map(|token| parse_simple_type(token.trim()))
        .collect::<Option<Vec<_>>>();
    (base, parsed)
}

fn parse_simple_type(token: &str) -> Option<Type> {
    Some(match token {
        "bool" => Type::Bool,
        "str" => Type::Str,
        "void" => Type::Void,
        "isize" => Type::ISize,
        "usize" => Type::USize,
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
        other if other.starts_with("fn(") => return None,
        other if !other.is_empty() => Type::Named {
            name: other.to_string(),
            args: Vec::new(),
        },
        _ => return None,
    })
}

type CallSignature = (Vec<Type>, Type, Vec<(String, Type)>);

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
        } => {
            matches!(concrete, Type::Ref { mutable: other_mut, lifetime: other_lifetime, to: other_to } if mutable == other_mut && lifetime == other_lifetime && bind_typevars(template_to, other_to, bindings))
        }
        Type::Slice(inner) => {
            matches!(concrete, Type::Slice(other) if bind_typevars(inner, other, bindings))
        }
        Type::Array { elem, len } => {
            matches!(concrete, Type::Array { elem: other_elem, len: other_len } if len == other_len && bind_typevars(elem, other_elem, bindings))
        }
        Type::Result { ok, err } => {
            matches!(concrete, Type::Result { ok: other_ok, err: other_err } if bind_typevars(ok, other_ok, bindings) && bind_typevars(err, other_err, bindings))
        }
        Type::Option(inner) => {
            matches!(concrete, Type::Option(other) if bind_typevars(inner, other, bindings))
        }
        Type::Vec(inner) => {
            matches!(concrete, Type::Vec(other) if bind_typevars(inner, other, bindings))
        }
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
        Type::Option(inner) => Type::Option(Box::new(substitute_typevars(inner, bindings))),
        Type::Vec(inner) => Type::Vec(Box::new(substitute_typevars(inner, bindings))),
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

fn type_satisfies_trait(
    ty: &Type,
    trait_name: &str,
    trait_impls: &HashMap<String, Vec<Type>>,
) -> bool {
    trait_impls
        .get(trait_name)
        .is_some_and(|impls| impls.iter().any(|candidate| type_compatible(candidate, ty)))
}

pub fn is_runtime_intrinsic(name: &str) -> bool {
    matches!(
        name,
        "spawn"
            | "thread.spawn"
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
            | "task.context"
            | "task.group_begin"
            | "task.group_spawn"
            | "task.group_join"
            | "task.group_cancel"
            | "alloc"
            | "free"
            | "close"
    )
}

fn i32_type() -> Type {
    Type::Int {
        signed: true,
        bits: 32,
    }
}

fn runtime_call_signature(name: &str) -> Option<(Vec<Type>, Type)> {
    let i32 = i32_type();
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
    Some(match name {
        "spawn" | "thread.spawn" => (vec![task_fn.clone()], i32.clone()),
        "spawn_ctx" => (vec![task_fn.clone(), i32.clone()], i32.clone()),
        "join" | "detach" | "cancel_task" | "task_result" => (vec![i32.clone()], i32.clone()),
        "yield" | "checkpoint" | "cancel" | "recv" | "pulse" => (vec![], i32.clone()),
        "timeout" | "deadline" => (vec![i32.clone()], i32.clone()),
        "task.context" | "task.group_begin" => (vec![], i32.clone()),
        "task.group_spawn" => (vec![i32.clone(), task_fn], i32.clone()),
        "task.group_join" | "task.group_cancel" => (vec![i32.clone()], i32.clone()),
        "alloc" => (vec![usize_ty], ptr_u8.clone()),
        "free" => (vec![ptr_u8], Type::Void),
        "close" => (vec![i32.clone()], Type::Void),
        "http.bind" | "http.accept" | "http.connect" | "http.poll_next" => (vec![], i32.clone()),
        "http.listen" | "http.read" | "http.close" | "http.poll_register" => {
            (vec![i32.clone()], i32.clone())
        }
        "http.method" | "http.path" | "http.body" => (vec![i32.clone()], str_ty.clone()),
        "http.body_json" => (vec![i32.clone()], i32.clone()),
        "http.body_bind" => (vec![i32.clone()], i32.clone()),
        "http.header" | "http.query" | "http.param" => {
            (vec![i32.clone(), str_ty.clone()], str_ty.clone())
        }
        "http.headers" => (vec![i32.clone()], i32.clone()),
        "http.request_id" | "http.remote_addr" => (vec![i32.clone()], str_ty.clone()),
        "http.write" | "http.write_json" => {
            (vec![i32.clone(), i32.clone(), str_ty.clone()], i32.clone())
        }
        "http.write_response" => (
            vec![
                i32.clone(),
                i32.clone(),
                str_ty.clone(),
                str_ty.clone(),
                i32.clone(),
            ],
            i32.clone(),
        ),
        "env.get" => (vec![str_ty.clone()], str_ty.clone()),
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
        "str.slice" => (
            vec![str_ty.clone(), i32.clone(), i32.clone()],
            str_ty.clone(),
        ),
        "http.post_json" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "http.post_json_capture" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "http.last_status" => (vec![], i32.clone()),
        "http.last_error" => (vec![], str_ty.clone()),
        "json.escape" => (vec![str_ty.clone()], str_ty.clone()),
        "json.str" => (vec![str_ty.clone()], str_ty.clone()),
        "json.raw" => (vec![str_ty.clone()], str_ty.clone()),
        "json.array1" => (vec![str_ty.clone()], str_ty.clone()),
        "json.array2" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "json.array3" => (
            vec![str_ty.clone(), str_ty.clone(), str_ty.clone()],
            str_ty.clone(),
        ),
        "json.array4" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "json.from_list" => (vec![i32.clone()], str_ty.clone()),
        "json.from_map" => (vec![i32.clone()], str_ty.clone()),
        "json.to_list" => (vec![str_ty.clone()], i32.clone()),
        "json.to_map" => (vec![str_ty.clone()], i32.clone()),
        "json.parse" => (vec![str_ty.clone()], i32.clone()),
        "json.get" => (vec![i32.clone(), str_ty.clone()], i32.clone()),
        "json.get_str" => (vec![i32.clone(), str_ty.clone()], str_ty.clone()),
        "json.has" => (vec![i32.clone(), str_ty.clone()], i32.clone()),
        "json.path" => (vec![i32.clone(), str_ty.clone()], i32.clone()),
        "json.object1" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "json.object2" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "json.object3" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "json.object4" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "time.now" | "time.monotonic_ms" => (vec![], i32.clone()),
        "time.sleep_ms" => (vec![i32.clone()], i32.clone()),
        "time.interval" | "time.tick" => (vec![i32.clone()], i32.clone()),
        "time.elapsed_ms" | "time.deadline_after" => (vec![i32.clone()], i32.clone()),
        "fs.open" | "fs.write" | "fs.flush" | "fs.atomic_write" | "fs.rename_atomic"
        | "fs.fsync" | "fs.lock" | "fs.read" => (vec![], i32.clone()),
        "fs.read_file" => (vec![str_ty.clone()], str_ty.clone()),
        "fs.write_file" => (vec![str_ty.clone(), str_ty.clone()], i32.clone()),
        "fs.mkdir" | "fs.exists" | "fs.remove_file" => (vec![str_ty.clone()], i32.clone()),
        "fs.stat_size" => (vec![str_ty.clone()], i32.clone()),
        "fs.listdir" => (vec![str_ty.clone()], i32.clone()),
        "fs.temp_file" => (vec![str_ty.clone()], str_ty.clone()),
        "path.join" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "path.normalize" => (vec![str_ty.clone()], str_ty.clone()),
        "list.new" => (vec![], i32.clone()),
        "list.push" => (vec![i32.clone(), str_ty.clone()], i32.clone()),
        "list.pop" => (vec![i32.clone()], str_ty.clone()),
        "list.len" => (vec![i32.clone()], i32.clone()),
        "list.get" => (vec![i32.clone(), i32.clone()], str_ty.clone()),
        "list.set" => (vec![i32.clone(), i32.clone(), str_ty.clone()], i32.clone()),
        "list.clear" => (vec![i32.clone()], i32.clone()),
        "list.join" => (vec![i32.clone(), str_ty.clone()], str_ty.clone()),
        "map.new" => (vec![], i32.clone()),
        "map.set" => (
            vec![i32.clone(), str_ty.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "map.get" => (vec![i32.clone(), str_ty.clone()], str_ty.clone()),
        "map.has" | "map.delete" => (vec![i32.clone(), str_ty.clone()], i32.clone()),
        "map.keys" => (vec![i32.clone()], i32.clone()),
        "map.len" => (vec![i32.clone()], i32.clone()),
        "route.match" => (
            vec![i32.clone(), str_ty.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "route.write_404" | "route.write_405" => (vec![i32.clone()], i32.clone()),
        "log.info" | "log.warn" | "log.error" => {
            (vec![str_ty.clone(), str_ty.clone()], i32.clone())
        }
        "log.fields1" => (vec![str_ty.clone(), str_ty.clone()], str_ty.clone()),
        "log.fields2" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "log.fields3" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "log.fields4" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            str_ty.clone(),
        ),
        "log.set_json" => (vec![i32.clone()], i32.clone()),
        "log.correlation_id" => (vec![i32.clone()], str_ty.clone()),
        "error.code" | "error.class" => (vec![], i32.clone()),
        "error.message" => (vec![], str_ty.clone()),
        "error.context" => (vec![str_ty.clone()], i32.clone()),
        "process.run" | "proc.run" | "process.spawn" | "proc.spawn" => {
            (vec![str_ty.clone()], i32.clone())
        }
        "process.runv" | "proc.runv" | "process.spawnv" | "proc.spawnv" => (
            vec![
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
                str_ty.clone(),
            ],
            i32.clone(),
        ),
        "process.runl" | "proc.runl" | "process.spawnl" | "proc.spawnl" => (
            vec![str_ty.clone(), i32.clone(), i32.clone(), str_ty.clone()],
            i32.clone(),
        ),
        "process.exec_timeout" | "proc.exec_timeout" => (vec![i32.clone()], i32.clone()),
        "process.wait" | "proc.wait" => (vec![i32.clone(), i32.clone()], i32.clone()),
        "process.poll" | "proc.poll" | "process.event" | "proc.event" => {
            (vec![i32.clone()], i32.clone())
        }
        "process.read_stdout" | "proc.read_stdout" | "process.read_stderr" | "proc.read_stderr" => {
            (vec![i32.clone(), i32.clone()], str_ty.clone())
        }
        "process.stdout" | "proc.stdout" | "process.stderr" | "proc.stderr" => {
            (vec![i32.clone()], str_ty.clone())
        }
        "process.exit_code" | "proc.exit_code" => (vec![i32.clone()], i32.clone()),
        "process.exit_class" | "proc.exit_class" => (vec![], i32.clone()),
        "ctx.deadline" => (vec![i32.clone()], i32.clone()),
        "ctx.cancel_if_timeout" | "channel.send" | "channel.recv" => (vec![], i32.clone()),
        _ => return None,
    })
}

fn runtime_default_value(ty: &Type) -> Option<Value> {
    match ty {
        Type::Bool => Some(Value::Bool(false)),
        Type::ISize | Type::USize | Type::Int { .. } => Some(Value::I32(0)),
        Type::Float { .. } => Some(Value::F64(0.0)),
        Type::Char => Some(Value::Char('\0')),
        Type::Str => Some(Value::Str(String::new())),
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
                if !struct_def.fields.iter().any(|candidate| candidate.name == *field) {
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
            if found_variant.payload.len() != bindings.len() {
                record_type_error(
                    errors,
                    type_error_details,
                    format!(
                        "pattern `{enum_name}::{variant}` binding arity mismatch: expected {}, got {}",
                        found_variant.payload.len(),
                        bindings.len()
                    ),
                );
            }
        }
        (ast::Pattern::Variant { enum_name, variant, .. }, Some(actual)) => {
            record_type_error(
                errors,
                type_error_details,
                format!("pattern `{enum_name}::{variant}` expects enum scrutinee, got `{actual}`"),
            )
        }
        (ast::Pattern::Variant { enum_name, variant, .. }, None) => record_type_error(
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
        ast::Pattern::Struct { name, fields } => {
            let Type::Named {
                name: scrutinee, ..
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
                    scopes.insert(binding_name.clone(), field.ty.clone(), mutable);
                }
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
        } => {
            let Type::Named { name, .. } = scrutinee_ty else {
                return;
            };
            if name != enum_name {
                return;
            }
            let Some(enum_def) = enum_defs.get(enum_name) else {
                return;
            };
            let Some(found_variant) = enum_def
                .variants
                .iter()
                .find(|candidate| candidate.name == *variant)
            else {
                return;
            };
            if found_variant.payload.len() != bindings.len() {
                record_type_error(
                    errors,
                    type_error_details,
                    format!(
                        "pattern `{enum_name}::{variant}` binding arity mismatch: expected {}, got {}",
                        found_variant.payload.len(),
                        bindings.len()
                    ),
                );
                return;
            }
            for (name, ty) in bindings.iter().zip(found_variant.payload.iter()) {
                scopes.insert(name.clone(), ty.clone(), mutable);
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(first) = patterns.first() {
                bind_pattern_types(
                    first,
                    scrutinee_ty,
                    mutable,
                    scopes,
                    struct_defs,
                    enum_defs,
                    errors,
                    type_error_details,
                );
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => {}
    }
}

fn type_compatible(expected: &Type, actual: &Type) -> bool {
    match (expected, actual) {
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

fn is_integer_type(ty: &Type) -> bool {
    matches!(ty, Type::ISize | Type::USize | Type::Int { .. })
}

fn is_float_type(ty: &Type) -> bool {
    matches!(ty, Type::Float { .. })
}

fn is_bool_or_integer(ty: Option<&Type>) -> bool {
    matches!(ty, Some(Type::Bool)) || ty.is_some_and(is_integer_type)
}

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
    eval_block(&main.body, &mut env, &map).and_then(|value| match value {
        Value::I32(v) => Some(v),
        Value::F64(v) => Some(v as i32),
        Value::Bool(v) => Some(v as i32),
        Value::Char(v) => Some(v as i32),
        Value::Str(_) => None,
        Value::FnRef(_)
        | Value::Closure(_)
        | Value::List(_)
        | Value::Struct { .. }
        | Value::Enum { .. } => None,
    })
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
        Stmt::Break | Stmt::Continue => false,
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
    for stmt in body {
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
                    EvalOutcome::Return(v) => return EvalOutcome::Return(v),
                    EvalOutcome::Break => return EvalOutcome::Break,
                    EvalOutcome::ContinueLoop => return EvalOutcome::ContinueLoop,
                    EvalOutcome::Continue => {}
                }
            }
            Stmt::While { condition, body } => {
                let mut guard = 0usize;
                while truthy(&match eval_expr(condition, env, functions) {
                    Some(value) => value,
                    None => return EvalOutcome::Continue,
                }) {
                    match eval_block_control(body, env, functions) {
                        EvalOutcome::Return(v) => return EvalOutcome::Return(v),
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    guard += 1;
                    if guard > 1_000_000 {
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
                        EvalOutcome::Return(v) => return EvalOutcome::Return(v),
                        EvalOutcome::Break | EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                }
                let mut guard = 0usize;
                loop {
                    if let Some(condition) = condition {
                        let Some(value) = eval_expr(condition, env, functions) else {
                            return EvalOutcome::Continue;
                        };
                        if !truthy(&value) {
                            break;
                        }
                    }
                    match eval_block_control(body, env, functions) {
                        EvalOutcome::Return(v) => return EvalOutcome::Return(v),
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    if let Some(step) = step {
                        match eval_block_control(
                            std::slice::from_ref(step.as_ref()),
                            env,
                            functions,
                        ) {
                            EvalOutcome::Return(v) => return EvalOutcome::Return(v),
                            EvalOutcome::Break
                            | EvalOutcome::ContinueLoop
                            | EvalOutcome::Continue => {}
                        }
                    }
                    guard += 1;
                    if guard > 1_000_000 {
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
                        EvalOutcome::Return(v) => return EvalOutcome::Return(v),
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    current += 1;
                    guard += 1;
                    if guard > 1_000_000 {
                        return EvalOutcome::Continue;
                    }
                }
            }
            Stmt::Loop { body } => {
                let mut guard = 0usize;
                loop {
                    match eval_block_control(body, env, functions) {
                        EvalOutcome::Return(v) => return EvalOutcome::Return(v),
                        EvalOutcome::Break => break,
                        EvalOutcome::ContinueLoop | EvalOutcome::Continue => {}
                    }
                    guard += 1;
                    if guard > 1_000_000 {
                        return EvalOutcome::Continue;
                    }
                }
            }
            Stmt::Break => return EvalOutcome::Break,
            Stmt::Continue => return EvalOutcome::ContinueLoop,
            Stmt::Return(Some(expr)) => {
                let Some(val) = eval_expr(expr, env, functions) else {
                    return EvalOutcome::Continue;
                };
                return EvalOutcome::Return(val);
            }
            Stmt::Return(None) => return EvalOutcome::Return(Value::I32(0)),
            Stmt::Match { scrutinee, arms } => {
                let Some(value) = eval_expr(scrutinee, env, functions) else {
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
                                return EvalOutcome::Continue;
                            };
                            truthy(&guard_val)
                        }
                        None => true,
                    };
                    if guard_ok {
                        if arm.returns {
                            let Some(out) = eval_expr(&arm.value, &arm_env, functions) else {
                                return EvalOutcome::Continue;
                            };
                            return EvalOutcome::Return(out);
                        }
                        let _ = eval_expr(&arm.value, &arm_env, functions);
                        break;
                    }
                }
            }
            Stmt::Defer(_) | Stmt::Requires(_) | Stmt::Ensures(_) | Stmt::Expr(_) => {}
        }
    }
    EvalOutcome::Continue
}

fn eval_expr<'a>(
    expr: &Expr,
    env: &BTreeMap<String, Value>,
    functions: &HashMap<&'a str, &'a TypedFunction>,
) -> Option<Value> {
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
        Expr::Await(inner) => eval_expr(inner, env, functions),
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
        } => {
            let mut values = Vec::with_capacity(payload.len());
            for value in payload {
                values.push(eval_expr(value, env, functions)?);
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
            },
            Value::Enum {
                enum_name: value_enum_name,
                variant: value_variant,
                payload,
            },
        ) => {
            if enum_name != value_enum_name
                || variant != value_variant
                || pattern_bindings.len() != payload.len()
            {
                return false;
            }
            for (name, value) in pattern_bindings.iter().zip(payload.iter()) {
                bindings.insert(name.clone(), value.clone());
            }
            true
        }
        (ast::Pattern::Variant { .. }, _) => false,
        (ast::Pattern::Struct { .. }, _) => false,
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
        | ast::Pattern::Struct { .. }
        | ast::Pattern::Variant { .. } => false,
    }
}

fn collect_pattern_bindings(pattern: &ast::Pattern, out: &mut BTreeSet<String>) {
    match pattern {
        ast::Pattern::Ident(name) => {
            out.insert(name.clone());
        }
        ast::Pattern::Struct { fields, .. } => {
            for (_, binding) in fields {
                out.insert(binding.clone());
            }
        }
        ast::Pattern::Variant { bindings, .. } => {
            for binding in bindings {
                out.insert(binding.clone());
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
        Value::List(v) => Some(!v.is_empty()),
        Value::FnRef(_) | Value::Closure(_) | Value::Struct { .. } | Value::Enum { .. } => {
            Some(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::lower;

    #[test]
    fn lowers_trait_bounds_and_generic_specializations() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            struct Boxed { value: i32 }
            impl Show for Boxed { fn show(v: i32) -> i32 { return v; } }
            fn id<T: Show>(v: T) -> T { return v; }
            fn main() -> i32 {
                let b = Boxed { value: 9 };
                let b2 = id<Boxed>(b);
                return b2.value;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.trait_violations.is_empty());
        assert!(typed
            .generic_specializations
            .iter()
            .any(|entry| entry.starts_with("id<")));
    }

    #[test]
    fn flags_missing_trait_impl_for_specialization() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            fn id<T: Show>(v: T) -> T { return v; }
            fn main() -> i32 {
                let v: i32 = 4;
                discard id<i32>(v);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(!typed.trait_violations.is_empty());
    }

    #[test]
    fn flags_reference_without_lifetime_annotation() {
        let source = r#"
            fn borrow(v: &str) -> &str {
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.reference_lifetime_violations.is_empty());
    }

    #[test]
    fn net_path_routing_typechecks_and_keeps_entry_i32() {
        let source = r#"
            use core.http;
            fn main() -> i32 {
                let l = http.bind();
                http.listen(l);
                let c = http.accept();
                http.read(c);
                let p = http.path(c);
                if p == "/a" {
                    http.write(c, 200, "path-a");
                } else {
                    http.write(c, 200, "path-other");
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(0));
    }

    #[test]
    fn unknown_dotted_call_is_a_type_error() {
        let source = r#"
            fn main() -> i32 {
                fake.module.call();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
    }

    #[test]
    fn process_spawn_string_command_typechecks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                process.spawn("echo hi");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn process_spawn_non_string_reports_detail() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                process.spawn(1);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("process.spawn") && detail.contains("expected `str`")));
    }

    #[test]
    fn process_spawnv_with_json_args_typechecks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                process.spawnv("echo", "[\"hi\"]", "{\"K\":\"V\"}", "stdin");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn process_spawnl_with_typed_args_typechecks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let args = list.new();
                list.push(args, "hi");
                let env = map.new();
                map.set(env, "K", "V");
                process.spawnl("echo", args, env, "stdin");
                process.runl("echo", args, env, "");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn http_capture_and_json_builders_typecheck() {
        let source = r#"
            use core.http;
            fn main() -> i32 {
                let user = json.str("hello");
                let msg = json.object2("role", json.str("user"), "content", user);
                let messages = json.array1(msg);
                let payload = json.object2("model", json.str("claude"), "messages", messages);
                discard http.post_json_capture("https://example.com", payload);
                discard http.last_status();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn extended_runtime_primitives_typecheck() {
        let source = r#"
            use core.http;
            use core.proc;
            fn main() -> i32 {
                let l = list.new();
                list.push(l, "a");
                let m = map.new();
                map.set(m, "k", "v");
                discard str.contains("abc", "a");
                discard fs.exists("/tmp");
                discard time.monotonic_ms();
                discard process.poll(process.spawn("echo hi"));
                let c = http.accept();
                discard http.header(c, "content-type");
                discard route.match(c, "GET", "/sessions/:id/messages");
                let fields = log.fields2("component", "test", "phase", "boot");
                discard log.info("x", fields);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn json_parse_and_body_json_primitives_typecheck() {
        let source = r#"
            use core.http;
            fn main() -> i32 {
                let c = http.accept();
                let body = http.body_json(c);
                let bound = http.body_bind(c);
                discard map.get(bound, "message");
                discard json.has(body, "message");
                let msg = json.get_str(body, "message");
                let nested = json.path(body, "meta.user.id");
                discard json.get(nested, "raw");
                discard json.parse("{\"ok\":true}");
                if str.len(msg) > 0 {
                    http.write(c, 200, msg);
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn match_semantic_hints_track_unreachable_and_duplicate_catchalls() {
        let source = r#"
            fn main() -> i32 {
                let v: i32 = 1;
                match v {
                    _ => 1,
                    2 => 2,
                    x => x,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.match_unreachable_arms, 2);
        assert_eq!(typed.match_duplicate_catchall_arms, 1);
    }

    #[test]
    fn qualified_variant_patterns_typecheck_against_scrutinee_enum() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let m = Maybe::Some(7);
                match m {
                    Maybe::Some(v) => return v,
                    Maybe::None => 0,
                    _ => 0,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn let_pattern_variant_binding_is_available_after_destructure() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let Maybe::Some(v) = Maybe::Some(9);
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(9));
    }

    #[test]
    fn struct_patterns_bind_fields_in_let_and_match() {
        let source = r#"
            struct Pair { left: i32, right: i32 }
            fn main() -> i32 {
                let Pair { left, right: r } = Pair { left: 4, right: 9 };
                match Pair { left: left, right: r } {
                    Pair { left: a, right: b } => return a + b,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(13));
    }

    #[test]
    fn qualified_variant_pattern_rejects_wrong_enum_name() {
        let source = r#"
            enum Left { A(i32) }
            enum Right { A(i32) }
            fn main() -> i32 {
                let v = Left::A(1);
                match v {
                    Right::A(x) => x,
                    _ => 0,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("does not match scrutinee enum")));
    }

    #[test]
    fn match_arm_return_typechecks_and_counts_as_explicit_return() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    1 => return 7,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn match_arm_return_type_mismatch_reports_error() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    1 => return true,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("return type mismatch")));
    }

    #[test]
    fn async_await_typechecks_in_async_function() {
        let source = r#"
            async fn worker() -> i32 { return 1; }
            async fn main() -> i32 {
                let v: i32 = await worker();
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn await_in_non_async_function_reports_semantic_error() {
        let source = r#"
            async fn worker() -> i32 { return 1; }
            fn main() -> i32 {
                let v: i32 = await worker();
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("uses `await` but is not declared async")));
    }

    #[test]
    fn timeout_requires_millis_argument() {
        let source = r#"
            fn main() -> i32 {
                timeout();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
    }

    #[test]
    fn timeout_with_millis_argument_typechecks() {
        let source = r#"
            fn main() -> i32 {
                timeout(25);
                discard deadline(100);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn assignment_to_immutable_binding_reports_error() {
        let source = r#"
            fn main() -> i32 {
                let v: i32 = 0;
                v = 1;
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("assignment to immutable binding")));
    }

    #[test]
    fn assignment_to_mutable_binding_typechecks() {
        let source = r#"
            fn main() -> i32 {
                let mut v: i32 = 0;
                v = 1;
                v += 2;
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn const_and_static_are_resolved_in_function_scope() {
        let source = r#"
            const MAGIC: i32 = 7;
            static LIMIT: i32 = MAGIC + 3;
            fn main() -> i32 {
                let x: i32 = MAGIC;
                let y: i32 = LIMIT;
                return x + y;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.typed_globals.iter().any(|item| item.name == "MAGIC"));
        assert!(typed.typed_globals.iter().any(|item| item.name == "LIMIT"));
    }

    #[test]
    fn const_initializer_requires_compile_time_integer_expression() {
        let source = r#"
            fn runtime() -> i32 { return 1; }
            const BAD: i32 = runtime();
            fn main() -> i32 { return BAD; }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed.type_error_details.iter().any(|detail| detail
            .contains("must be initialized with an integer/char/bool compile-time expression")));
    }

    #[test]
    fn detects_use_after_free_via_alias_provenance() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                let q = p;
                free(p);
                close(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `q` after provenance root")));
    }

    #[test]
    fn detects_mutable_aliasing_across_ref_params() {
        let source = r#"
            fn touch(a: &'a mut i32, b: &'a mut i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                touch(x, x);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("aliases mutable reference parameter `x`")));
    }

    #[test]
    fn detects_invalid_atomic_ordering_claims() {
        let source = r#"
            fn main() -> i32 {
                let v = atomic.load(1, "Release");
                discard v;
                atomic.fence("Relaxed");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("atomic.load ordering `Release` is invalid")));
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("atomic.fence ordering `Relaxed` is invalid")));
    }

    #[test]
    fn detects_generic_borrow_across_await_call_edge() {
        let source = r#"
            fn project<T: Show>(value: &'a T) -> &'a T {
                return value;
            }
            async fn worker(v: &'a i32) -> i32 {
                await recv();
                discard project<i32>(v);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("generic/trait-heavy with borrowed parameters across await")
        }));
    }

    #[test]
    fn break_continue_outside_loop_reports_type_error() {
        let source = r#"
            fn main() -> i32 {
                break;
                continue;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("`break` is only valid inside loop bodies")));
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("`continue` is only valid inside loop bodies")));
    }

    #[test]
    fn for_in_range_typechecks() {
        let source = r#"
            fn main() -> i32 {
                let sum: i32 = 0;
                for i in 0..5 {
                    discard i;
                }
                return sum;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn logical_short_circuit_skips_rhs_side_effects() {
        let source = r#"
            fn main() -> i32 {
                if false && (1 / 0 == 1) {
                    return 1;
                }
                if true || (1 / 0 == 1) {
                    return 0;
                }
                return 2;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(0));
    }

    #[test]
    fn unit_return_allowed_for_void_functions() {
        let source = r#"
            fn main() -> void {
                return;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn function_type_values_support_higher_order_calls() {
        let source = r#"
            fn id(v: i32) -> i32 {
                return v;
            }
            fn apply(f: fn(i32) -> i32, value: i32) -> i32 {
                return f(value);
            }
            fn main() -> i32 {
                return apply(id, 7);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn closure_values_capture_outer_bindings_and_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let base: i32 = 5;
                let add = |x: i32| x + base;
                return add(2);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn closure_explicit_return_type_mismatch_is_reported() {
        let source = r#"
            fn main() -> i32 {
                let f = |x: i32| -> bool x + 1;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("closure return type mismatch")));
    }

    #[test]
    fn non_callable_values_fail_callability_checks() {
        let source = r#"
            fn main() -> i32 {
                let value: i32 = 1;
                return value(2);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("is not callable")));
    }

    #[test]
    fn primitive_parity_fixture_typechecks_and_interprets() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/primitive_parity/main.fzy"),
        )
        .expect("primitive parity fixture should be readable");
        let module = parser::parse(&source, "primitive_parity").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(27));
    }

    #[test]
    fn detects_unsafe_call_outside_unsafe_context() {
        let source = r#"
            unsafe fn danger(v: i32) -> i32 {
                return v + 1;
            }
            fn main() -> i32 {
                return danger(1);
            }
        "#;
        let module = parser::parse(source, "unsafe_ctx").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .unsafe_context_violations
            .iter()
            .any(|detail| detail.contains("outside `unsafe` context")));
    }
}
