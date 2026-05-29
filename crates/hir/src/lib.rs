use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use ast::{AstVisitor, BinaryOp, Expr, Module, Stmt, Type};

#[derive(Debug, Clone)]
pub struct TypedFunction {
    pub name: String,
    pub link_name: Option<String>,
    pub generics: Vec<ast::GenericParam>,
    pub params: Vec<ast::Param>,
    pub local_types: BTreeMap<String, Type>,
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
    pub struct_defs: HashMap<String, ast::Struct>,
    pub enum_defs: HashMap<String, ast::Enum>,
    pub type_errors: usize,
    pub type_error_details: Vec<String>,
    pub function_capability_requirements: Vec<FunctionCapabilityRequirement>,
    pub ownership_violations: Vec<String>,
    pub unsafe_context_violations: Vec<String>,
    pub capability_token_violations: Vec<String>,
    pub thread_boundary_violations: Vec<String>,
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
    Tuple(Vec<Value>),
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

fn resolve_alias_type(ty: &Type, aliases: &HashMap<String, Type>, depth: usize) -> Type {
    if depth > 32 {
        return ty.clone();
    }
    match ty {
        Type::Named { name, args } if args.is_empty() => {
            if let Some(target) = aliases.get(name) {
                return resolve_alias_type(target, aliases, depth + 1);
            }
            ty.clone()
        }
        Type::Ptr { mutable, to } => Type::Ptr {
            mutable: *mutable,
            to: Box::new(resolve_alias_type(to, aliases, depth)),
        },
        Type::Ref {
            mutable,
            lifetime,
            to,
        } => Type::Ref {
            mutable: *mutable,
            lifetime: lifetime.clone(),
            to: Box::new(resolve_alias_type(to, aliases, depth)),
        },
        Type::Slice(inner) => Type::Slice(Box::new(resolve_alias_type(inner, aliases, depth))),
        Type::Array { elem, len } => Type::Array {
            elem: Box::new(resolve_alias_type(elem, aliases, depth)),
            len: *len,
        },
        Type::Result { ok, err } => Type::Result {
            ok: Box::new(resolve_alias_type(ok, aliases, depth)),
            err: Box::new(resolve_alias_type(err, aliases, depth)),
        },
        Type::Map { key, value } => Type::Map {
            key: Box::new(resolve_alias_type(key, aliases, depth)),
            value: Box::new(resolve_alias_type(value, aliases, depth)),
        },
        Type::Set(inner) => Type::Set(Box::new(resolve_alias_type(inner, aliases, depth))),
        Type::Deque(inner) => Type::Deque(Box::new(resolve_alias_type(inner, aliases, depth))),
        Type::Ring(inner) => Type::Ring(Box::new(resolve_alias_type(inner, aliases, depth))),
        Type::Option(inner) => Type::Option(Box::new(resolve_alias_type(inner, aliases, depth))),
        Type::Vec(inner) => Type::Vec(Box::new(resolve_alias_type(inner, aliases, depth))),
        Type::Future(inner) => Type::Future(Box::new(resolve_alias_type(inner, aliases, depth))),
        Type::Function { params, ret } => Type::Function {
            params: params
                .iter()
                .map(|param| resolve_alias_type(param, aliases, depth))
                .collect(),
            ret: Box::new(resolve_alias_type(ret, aliases, depth)),
        },
        Type::Tuple(items) => Type::Tuple(
            items
                .iter()
                .map(|item| resolve_alias_type(item, aliases, depth))
                .collect(),
        ),
        _ => ty.clone(),
    }
}

fn resolve_impl_context_type(
    ty: &Type,
    self_type: &Type,
    associated_types: &HashMap<String, Type>,
) -> Type {
    match ty {
        Type::Named { name, .. } if name == "Self" => self_type.clone(),
        Type::Named { name, args: _ } if name.starts_with("Self::") => associated_types
            .get(name.trim_start_matches("Self::"))
            .cloned()
            .unwrap_or_else(|| ty.clone()),
        Type::Named { name, args } => Type::Named {
            name: name.clone(),
            args: args
                .iter()
                .map(|arg| resolve_impl_context_type(arg, self_type, associated_types))
                .collect(),
        },
        Type::Ptr { mutable, to } => Type::Ptr {
            mutable: *mutable,
            to: Box::new(resolve_impl_context_type(to, self_type, associated_types)),
        },
        Type::Ref {
            mutable,
            lifetime,
            to,
        } => Type::Ref {
            mutable: *mutable,
            lifetime: lifetime.clone(),
            to: Box::new(resolve_impl_context_type(to, self_type, associated_types)),
        },
        Type::Slice(inner) => Type::Slice(Box::new(resolve_impl_context_type(
            inner,
            self_type,
            associated_types,
        ))),
        Type::Array { elem, len } => Type::Array {
            elem: Box::new(resolve_impl_context_type(elem, self_type, associated_types)),
            len: *len,
        },
        Type::Result { ok, err } => Type::Result {
            ok: Box::new(resolve_impl_context_type(ok, self_type, associated_types)),
            err: Box::new(resolve_impl_context_type(err, self_type, associated_types)),
        },
        Type::Map { key, value } => Type::Map {
            key: Box::new(resolve_impl_context_type(key, self_type, associated_types)),
            value: Box::new(resolve_impl_context_type(
                value,
                self_type,
                associated_types,
            )),
        },
        Type::Set(inner) => Type::Set(Box::new(resolve_impl_context_type(
            inner,
            self_type,
            associated_types,
        ))),
        Type::Deque(inner) => Type::Deque(Box::new(resolve_impl_context_type(
            inner,
            self_type,
            associated_types,
        ))),
        Type::Ring(inner) => Type::Ring(Box::new(resolve_impl_context_type(
            inner,
            self_type,
            associated_types,
        ))),
        Type::Option(inner) => Type::Option(Box::new(resolve_impl_context_type(
            inner,
            self_type,
            associated_types,
        ))),
        Type::Vec(inner) => Type::Vec(Box::new(resolve_impl_context_type(
            inner,
            self_type,
            associated_types,
        ))),
        Type::Future(inner) => Type::Future(Box::new(resolve_impl_context_type(
            inner,
            self_type,
            associated_types,
        ))),
        Type::Function { params, ret } => Type::Function {
            params: params
                .iter()
                .map(|param| resolve_impl_context_type(param, self_type, associated_types))
                .collect(),
            ret: Box::new(resolve_impl_context_type(ret, self_type, associated_types)),
        },
        Type::Tuple(items) => Type::Tuple(
            items
                .iter()
                .map(|item| resolve_impl_context_type(item, self_type, associated_types))
                .collect(),
        ),
        other => other.clone(),
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
    let mut trait_defs = trait_defs;
    trait_defs
        .entry("Error".to_string())
        .or_insert_with(|| ast::Trait {
            name: "Error".to_string(),
            generics: Vec::new(),
            associated_types: Vec::new(),
            associated_consts: Vec::new(),
            methods: vec![ast::TraitMethod {
                name: "message".to_string(),
                params: vec![ast::Param {
                    name: "self".to_string(),
                    ty: Type::TypeVar("Self".to_string()),
                }],
                return_type: Type::Str,
            }],
            is_pub: true,
        });
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
    let type_aliases = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::TypeAlias(item) => Some((item.name.clone(), item.ty.clone())),
            ast::Item::NewType(item) => Some((item.name.clone(), item.inner.clone())),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let mut generic_specializations = BTreeSet::new();
    let mut trait_violations = validate_trait_impls(module, &trait_defs);

    for item in &module.items {
        match item {
            ast::Item::Const(item) => {
                let declared_ty = resolve_alias_type(&item.ty, &type_aliases, 0);
                let inferred = infer_expr_type(
                    &item.value,
                    &global_scope,
                    &TypeCheckEnv {
                        current_namespace: "",
                        fn_sigs: &fn_sigs,
                        fn_async: &fn_async,
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
                    if !type_compatible(&declared_ty, &actual) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!(
                                "const `{}` type mismatch: expected `{}`, got `{}`",
                                item.name, declared_ty, actual
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
                global_scope.insert(item.name.clone(), declared_ty.clone(), false);
                typed_globals.push(TypedGlobal {
                    name: item.name.clone(),
                    ty: declared_ty,
                    is_static: false,
                    mutable: false,
                    is_pub: item.is_pub,
                    const_i32,
                });
            }
            ast::Item::Static(item) => {
                let declared_ty = resolve_alias_type(&item.ty, &type_aliases, 0);
                let inferred = infer_expr_type(
                    &item.value,
                    &global_scope,
                    &TypeCheckEnv {
                        current_namespace: "",
                        fn_sigs: &fn_sigs,
                        fn_async: &fn_async,
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
                    if !type_compatible(&declared_ty, &actual) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!(
                                "static `{}` type mismatch: expected `{}`, got `{}`",
                                item.name, declared_ty, actual
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
                global_scope.insert(item.name.clone(), declared_ty.clone(), item.mutable);
                typed_globals.push(TypedGlobal {
                    name: item.name.clone(),
                    ty: declared_ty,
                    is_static: true,
                    mutable: item.mutable,
                    is_pub: item.is_pub,
                    const_i32,
                });
            }
            ast::Item::Function(function) => {
                let params = function
                    .params
                    .iter()
                    .map(|param| ast::Param {
                        name: param.name.clone(),
                        ty: resolve_alias_type(&param.ty, &type_aliases, 0),
                    })
                    .collect::<Vec<_>>();
                let return_type = resolve_alias_type(&function.return_type, &type_aliases, 0);
                for detail in
                    validate_generic_bounds_exist(&function.name, &function.generics, &trait_defs)
                {
                    record_type_error(&mut type_errors, &mut type_error_details, detail.clone());
                    trait_violations.push(detail);
                }
                fn_sigs.insert(
                    function.name.clone(),
                    (
                        params.iter().map(|p| p.ty.clone()).collect(),
                        return_type.clone(),
                    ),
                );
                fn_async.insert(function.name.clone(), function.is_async);
                fn_generics.insert(function.name.clone(), function.generics.clone());
                typed_functions.push(TypedFunction {
                    name: function.name.clone(),
                    link_name: function.link_name.clone(),
                    generics: function.generics.clone(),
                    params,
                    local_types: BTreeMap::new(),
                    return_type,
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
                    link_name: None,
                    generics: Vec::new(),
                    params: Vec::new(),
                    local_types: BTreeMap::new(),
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
            ast::Item::Impl(item) => {
                let for_type = resolve_alias_type(&item.for_type, &type_aliases, 0);
                let receiver = for_type.to_string();
                let impl_associated_types = item
                    .associated_types
                    .iter()
                    .map(|(name, ty)| {
                        let resolved = resolve_alias_type(ty, &type_aliases, 0);
                        let contextual =
                            resolve_impl_context_type(&resolved, &for_type, &HashMap::new());
                        (name.clone(), contextual)
                    })
                    .collect::<HashMap<_, _>>();
                for method in &item.methods {
                    let params = method
                        .params
                        .iter()
                        .map(|param| ast::Param {
                            name: param.name.clone(),
                            ty: resolve_impl_context_type(
                                &resolve_alias_type(&param.ty, &type_aliases, 0),
                                &for_type,
                                &impl_associated_types,
                            ),
                        })
                        .collect::<Vec<_>>();
                    let return_type = resolve_impl_context_type(
                        &resolve_alias_type(&method.return_type, &type_aliases, 0),
                        &for_type,
                        &impl_associated_types,
                    );
                    let method_symbol = format!("{receiver}.{}", method.name);
                    for detail in
                        validate_generic_bounds_exist(&method_symbol, &method.generics, &trait_defs)
                    {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            detail.clone(),
                        );
                        trait_violations.push(detail);
                    }
                    if fn_sigs.contains_key(&method_symbol) {
                        record_type_error(
                            &mut type_errors,
                            &mut type_error_details,
                            format!("duplicate impl method symbol `{method_symbol}`"),
                        );
                        continue;
                    }
                    fn_sigs.insert(
                        method_symbol.clone(),
                        (
                            params.iter().map(|p| p.ty.clone()).collect(),
                            return_type.clone(),
                        ),
                    );
                    fn_async.insert(method_symbol.clone(), method.is_async);
                    fn_generics.insert(method_symbol.clone(), method.generics.clone());
                    typed_functions.push(TypedFunction {
                        name: method_symbol,
                        link_name: method.link_name.clone(),
                        generics: method.generics.clone(),
                        params,
                        local_types: BTreeMap::new(),
                        return_type,
                        body: method.body.clone(),
                        is_unsafe: method.is_unsafe,
                        is_async: method.is_async,
                        is_extern: method.is_extern,
                        abi: method.abi.clone(),
                        ffi_panic: method.ffi_panic.clone(),
                        required_capabilities: Vec::new(),
                    });
                }
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

    for function in &mut typed_functions {
        if function.body.is_empty() {
            continue;
        }
        let mut scopes = SymbolScopes::new();
        let mut local_types = BTreeMap::new();
        let current_namespace = function
            .name
            .rsplit_once('.')
            .map(|(prefix, _)| prefix)
            .unwrap_or("");
        let env = TypeCheckEnv {
            current_namespace,
            fn_sigs: &fn_sigs,
            fn_async: &fn_async,
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
            local_types.insert(param.name.clone(), param.ty.clone());
        }
        for stmt in &function.body {
            type_check_stmt(
                stmt,
                &mut scopes,
                &mut local_types,
                &env,
                0,
                &function.return_type,
                &mut state,
            );
        }
        function.local_types = local_types;
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
        .filter(|site| unsafe_contract_counts_as_reasoned(site))
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
    let ownership_violations =
        analyze_ownership(&typed_functions, &call_graph, &struct_defs, &enum_defs);
    let unsafe_context_violations = analyze_unsafe_context_violations(&typed_functions);
    let capability_token_violations = if capability_token_mode_enabled(&typed_functions) {
        analyze_capability_token_contracts(&typed_functions, &function_capability_requirements)
    } else {
        Vec::new()
    };
    let thread_boundary_violations = analyze_send_sync_contracts(&typed_functions);
    let reference_lifetime_violations = analyze_reference_lifetimes(&typed_functions);
    let linear_type_violations = analyze_linear_types(&typed_functions);
    monomorphize_typed_functions(
        &mut typed_functions,
        &mut generic_specializations,
        &mut type_errors,
        &mut type_error_details,
    );

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
        struct_defs,
        enum_defs,
        type_errors,
        type_error_details,
        function_capability_requirements,
        ownership_violations,
        unsafe_context_violations,
        capability_token_violations,
        thread_boundary_violations,
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
    let mut trait_impl_targets = HashMap::<String, Vec<Type>>::new();
    for item in &module.items {
        let ast::Item::Impl(item) = item else {
            continue;
        };
        let Some(trait_name) = &item.trait_name else {
            continue;
        };
        let recorded = trait_impl_targets.entry(trait_name.clone()).or_default();
        for existing in recorded.iter() {
            if type_compatible(existing, &item.for_type)
                || type_compatible(&item.for_type, existing)
            {
                violations.push(format!(
                    "overlapping impls for trait `{}`: `{}` conflicts with `{}`",
                    trait_name, item.for_type, existing
                ));
            }
        }
        recorded.push(item.for_type.clone());
        let Some(trait_def) = trait_defs.get(trait_name) else {
            violations.push(format!("impl references unknown trait `{trait_name}`"));
            continue;
        };
        let self_type = &item.for_type;
        let impl_associated_types = item
            .associated_types
            .iter()
            .map(|(name, ty)| (name.clone(), ty.clone()))
            .collect::<HashMap<_, _>>();
        for (name, _) in &item.associated_types {
            if !trait_def
                .associated_types
                .iter()
                .any(|candidate| candidate == name)
            {
                violations.push(format!(
                    "impl for `{}` defines extra associated type `{}` not declared by trait `{}`",
                    item.for_type, name, trait_name
                ));
            }
        }
        for item_const in &item.associated_consts {
            if trait_def
                .associated_consts
                .iter()
                .all(|candidate| candidate.name != item_const.name)
            {
                violations.push(format!(
                    "impl for `{}` defines extra associated const `{}` not declared by trait `{}`",
                    item.for_type, item_const.name, trait_name
                ));
            }
        }
        for assoc_type in &trait_def.associated_types {
            if item
                .associated_types
                .iter()
                .all(|(name, _)| name != assoc_type)
            {
                violations.push(format!(
                    "impl for `{}` missing associated type `{}` required by trait `{}`",
                    item.for_type, assoc_type, trait_name
                ));
            }
        }
        for assoc_const in &trait_def.associated_consts {
            let Some(found) = item
                .associated_consts
                .iter()
                .find(|candidate| candidate.name == assoc_const.name)
            else {
                violations.push(format!(
                    "impl for `{}` missing associated const `{}` required by trait `{}`",
                    item.for_type, assoc_const.name, trait_name
                ));
                continue;
            };
            let expected_ty =
                resolve_impl_context_type(&assoc_const.ty, self_type, &impl_associated_types);
            let actual_ty = resolve_impl_context_type(&found.ty, self_type, &impl_associated_types);
            if !type_compatible(&actual_ty, &expected_ty) {
                violations.push(format!(
                    "impl associated const `{}` type mismatch for trait `{}`: expected `{}`, got `{}`",
                    assoc_const.name, trait_name, expected_ty, actual_ty
                ));
            }
        }
        for impl_method in &item.methods {
            if trait_def
                .methods
                .iter()
                .all(|candidate| candidate.name != impl_method.name)
            {
                violations.push(format!(
                    "impl for `{}` defines extra method `{}` not declared by trait `{}`",
                    item.for_type, impl_method.name, trait_name
                ));
            }
        }
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
            for (index, (found_param, trait_param)) in
                found.params.iter().zip(method.params.iter()).enumerate()
            {
                let expected_ty =
                    resolve_impl_context_type(&trait_param.ty, self_type, &impl_associated_types);
                let actual_ty =
                    resolve_impl_context_type(&found_param.ty, self_type, &impl_associated_types);
                if !type_compatible(&actual_ty, &expected_ty) {
                    violations.push(format!(
                        "impl method `{}` parameter {} type mismatch for trait `{}`: expected `{}`, got `{}`",
                        method.name, index, trait_name, expected_ty, actual_ty
                    ));
                }
            }
            let expected_return =
                resolve_impl_context_type(&method.return_type, self_type, &impl_associated_types);
            let actual_return =
                resolve_impl_context_type(&found.return_type, self_type, &impl_associated_types);
            if !type_compatible(&actual_return, &expected_return) {
                violations.push(format!(
                    "impl method `{}` return type mismatch for trait `{}`: expected `{}`, got `{}`",
                    method.name, trait_name, expected_return, actual_return
                ));
            }
            if !found.generics.is_empty() {
                violations.push(format!(
                    "impl method `{}` in trait `{}` must not declare generic parameters in v1",
                    method.name, trait_name
                ));
            }
            if found.is_async {
                violations.push(format!(
                    "impl method `{}` in trait `{}` must not be async in v1",
                    method.name, trait_name
                ));
            }
            if found.is_unsafe {
                violations.push(format!(
                    "impl method `{}` in trait `{}` must not be unsafe in v1",
                    method.name, trait_name
                ));
            }
        }
    }
    violations
}

fn validate_generic_bounds_exist(
    owner: &str,
    generics: &[ast::GenericParam],
    trait_defs: &HashMap<String, ast::Trait>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for generic in generics {
        for bound in &generic.bounds {
            if !trait_defs.contains_key(bound) {
                violations.push(format!(
                    "{owner} declares generic bound `{}` on `{}` but trait `{}` is not defined",
                    bound, generic.name, bound
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
            Expr::Tuple(items) => items.iter().any(expr_has_cap_intrinsic),
            Expr::Closure { body, .. } => expr_has_cap_intrinsic(body),
            Expr::TryCatch {
                try_expr,
                catch_expr,
            } => expr_has_cap_intrinsic(try_expr) || expr_has_cap_intrinsic(catch_expr),
            Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                expr_has_cap_intrinsic(condition)
                    || expr_has_cap_intrinsic(then_expr)
                    || expr_has_cap_intrinsic(else_expr)
            }
            Expr::Match { scrutinee, arms } => {
                expr_has_cap_intrinsic(scrutinee)
                    || arms.iter().any(|arm| {
                        arm.guard.as_ref().is_some_and(expr_has_cap_intrinsic)
                            || expr_has_cap_intrinsic(&arm.value)
                    })
            }
            Expr::While { condition, body } => {
                expr_has_cap_intrinsic(condition)
                    || body.iter().any(statement_uses_cap_token_intrinsic)
            }
            Expr::For {
                init,
                condition,
                step,
                body,
            } => {
                init.as_ref()
                    .is_some_and(|stmt| statement_uses_cap_token_intrinsic(stmt))
                    || condition
                        .as_ref()
                        .is_some_and(|expr| expr_has_cap_intrinsic(expr))
                    || step
                        .as_ref()
                        .is_some_and(|stmt| statement_uses_cap_token_intrinsic(stmt))
                    || body.iter().any(statement_uses_cap_token_intrinsic)
            }
            Expr::ForIn { iterable, body, .. } => {
                expr_has_cap_intrinsic(iterable)
                    || body.iter().any(statement_uses_cap_token_intrinsic)
            }
            Expr::Loop { body } => body.iter().any(statement_uses_cap_token_intrinsic),
            Expr::Return(value) | Expr::Break(value) => value
                .as_ref()
                .is_some_and(|expr| expr_has_cap_intrinsic(expr)),
            Expr::Continue => false,
            Expr::Binary { left, right, .. } => {
                expr_has_cap_intrinsic(left) || expr_has_cap_intrinsic(right)
            }
            Expr::Range { start, end, .. } => {
                expr_has_cap_intrinsic(start) || expr_has_cap_intrinsic(end)
            }
            Expr::ArrayLiteral(items) => items.iter().any(expr_has_cap_intrinsic),
            Expr::ObjectLiteral(fields) => fields
                .iter()
                .any(|(_, value)| expr_has_cap_intrinsic(value)),
            Expr::Index { base, index } => {
                expr_has_cap_intrinsic(base) || expr_has_cap_intrinsic(index)
            }
            Expr::Group(inner) => expr_has_cap_intrinsic(inner),
            Expr::Await(inner) => expr_has_cap_intrinsic(inner),
            Expr::Discard(inner) => expr_has_cap_intrinsic(inner),
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
        Stmt::Break(_) | Stmt::Continue => false,
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
            Stmt::Break(_) | Stmt::Continue => {}
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
        | Stmt::Break(_)
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
        Expr::Tuple(items) => {
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
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            analyze_expr_call_tokens(
                function_name,
                Some(condition),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(then_expr),
                local_types,
                requirement_map,
                violations,
            );
            analyze_expr_call_tokens(
                function_name,
                Some(else_expr),
                local_types,
                requirement_map,
                violations,
            );
        }
        Expr::Match { scrutinee, arms } => {
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
        Expr::While { condition, body } => {
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
        Expr::For {
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
            if let Some(condition) = condition {
                analyze_expr_call_tokens(
                    function_name,
                    Some(condition),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
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
        Expr::ForIn { iterable, body, .. } => {
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
        Expr::Loop { body } => analyze_call_token_propagation(
            function_name,
            body,
            local_types,
            requirement_map,
            violations,
        ),
        Expr::Return(value) | Expr::Break(value) => {
            if let Some(value) = value {
                analyze_expr_call_tokens(
                    function_name,
                    Some(value),
                    local_types,
                    requirement_map,
                    violations,
                );
            }
        }
        Expr::Continue => {}
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
        Expr::ObjectLiteral(fields) => {
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
        Expr::Discard(inner) => analyze_expr_call_tokens(
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
            if set.is_empty() { None } else { Some(set) }
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
    let signatures = functions
        .iter()
        .map(|function| (function.name.clone(), function.clone()))
        .collect::<BTreeMap<_, _>>();
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
        for (name, ty) in &function.local_types {
            if let Type::Ref {
                lifetime, mutable, ..
            } = ty
            {
                ref_bindings.insert(name.clone(), (lifetime.clone(), *mutable));
                if lifetime.is_none() {
                    violations.push(format!(
                        "function `{}` local reference `{}` is missing explicit lifetime annotation",
                        function.name, name
                    ));
                }
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
        if return_lifetime.is_some() {
            let mut current_bindings = ref_bindings.clone();
            validate_reference_returns(
                &function.body,
                function,
                &mut current_bindings,
                &signatures,
                &return_lifetime,
                &mut violations,
            );
        }
    }
    violations
}

fn validate_reference_returns(
    body: &[Stmt],
    function: &TypedFunction,
    ref_bindings: &mut BTreeMap<String, (Option<String>, bool)>,
    signatures: &BTreeMap<String, TypedFunction>,
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
    ref_bindings: &mut BTreeMap<String, (Option<String>, bool)>,
    signatures: &BTreeMap<String, TypedFunction>,
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
    entry: &BTreeMap<String, (Option<String>, bool)>,
    branches: &[BTreeMap<String, (Option<String>, bool)>],
) -> BTreeMap<String, (Option<String>, bool)> {
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
    ref_bindings: &mut BTreeMap<String, (Option<String>, bool)>,
    signatures: &BTreeMap<String, TypedFunction>,
) {
    let Some((_, mutable)) = ref_bindings.get(name).cloned() else {
        return;
    };
    let next_lifetime = infer_reference_lifetime(value, ref_bindings, signatures).flatten();
    ref_bindings.insert(name.to_string(), (next_lifetime, mutable));
}

fn infer_reference_lifetime(
    expr: &Expr,
    ref_bindings: &BTreeMap<String, (Option<String>, bool)>,
    signatures: &BTreeMap<String, TypedFunction>,
) -> Option<Option<String>> {
    match expr {
        Expr::Ident(name) => ref_bindings.get(name).map(|(lifetime, _)| lifetime.clone()),
        Expr::Group(inner) | Expr::FieldAccess { base: inner, .. } => {
            infer_reference_lifetime(inner, ref_bindings, signatures)
        }
        Expr::Await(inner) | Expr::Discard(inner) | Expr::Unary { expr: inner, .. } => {
            infer_reference_lifetime(inner, ref_bindings, signatures)
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
        Stmt::Break(_) | Stmt::Continue => false,
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
        Expr::Discard(inner) => expr_has_await(inner),
        Expr::Call { args, .. } => args.iter().any(expr_has_await),
        Expr::UnsafeBlock { body, .. } => body.iter().any(stmt_has_await),
        Expr::FieldAccess { base, .. } => expr_has_await(base),
        Expr::StructInit { fields, .. } => fields.iter().any(|(_, value)| expr_has_await(value)),
        Expr::EnumInit { payload, .. } => payload.iter().any(expr_has_await),
        Expr::Tuple(items) => items.iter().any(expr_has_await),
        Expr::Closure { body, .. } => expr_has_await(body),
        Expr::Group(inner) => expr_has_await(inner),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => expr_has_await(try_expr) || expr_has_await(catch_expr),
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => expr_has_await(condition) || expr_has_await(then_expr) || expr_has_await(else_expr),
        Expr::Match { scrutinee, arms } => {
            expr_has_await(scrutinee)
                || arms.iter().any(|arm| {
                    arm.guard.as_ref().is_some_and(expr_has_await) || expr_has_await(&arm.value)
                })
        }
        Expr::While { condition, body } => {
            expr_has_await(condition) || body.iter().any(stmt_has_await)
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_ref().is_some_and(|stmt| stmt_has_await(stmt))
                || condition.as_ref().is_some_and(|expr| expr_has_await(expr))
                || step.as_ref().is_some_and(|stmt| stmt_has_await(stmt))
                || body.iter().any(stmt_has_await)
        }
        Expr::ForIn { iterable, body, .. } => {
            expr_has_await(iterable) || body.iter().any(stmt_has_await)
        }
        Expr::Loop { body } => body.iter().any(stmt_has_await),
        Expr::Return(value) | Expr::Break(value) => {
            value.as_ref().is_some_and(|expr| expr_has_await(expr))
        }
        Expr::Continue => false,
        Expr::Binary { left, right, .. } => expr_has_await(left) || expr_has_await(right),
        Expr::Range { start, end, .. } => expr_has_await(start) || expr_has_await(end),
        Expr::ArrayLiteral(items) => items.iter().any(expr_has_await),
        Expr::ObjectLiteral(fields) => fields.iter().any(|(_, value)| expr_has_await(value)),
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
    let ownership_summaries = build_function_ownership_summaries(functions);
    let mut violations = Vec::new();
    for function in functions {
        let mut linear_owned = ownership_summaries
            .get(&function.name)
            .into_iter()
            .flat_map(|consumed| consumed.iter().copied())
            .filter_map(|index| function.params.get(index))
            .filter(|param| is_linear_type(&param.ty))
            .map(|param| param.name.clone())
            .collect::<BTreeSet<_>>();
        let mut linear_freed = BTreeSet::<String>::new();
        struct Collector<'a> {
            function: &'a TypedFunction,
            linear_owned: &'a mut BTreeSet<String>,
            linear_freed: &'a mut BTreeSet<String>,
            violations: &'a mut Vec<String>,
            ownership_summaries: &'a BTreeMap<String, BTreeSet<usize>>,
        }
        impl AstVisitor for Collector<'_> {
            fn visit_stmt(&mut self, stmt: &Stmt) {
                if let Stmt::Let {
                    name, ty, value, ..
                } = stmt
                {
                    if let Some(resource_ty) =
                        binding_resource_type(self.function, name, ty.as_ref(), value)
                    {
                        if is_linear_type(resource_ty) {
                            self.linear_owned.insert(name.clone());
                        }
                    }
                }
                ast::walk_stmt(self, stmt);
            }

            fn visit_expr(&mut self, expr: &Expr) {
                if let Expr::Call { callee, args } = expr {
                    for name in consumed_arg_identity_names(callee, args, self.ownership_summaries)
                    {
                        if !self.linear_owned.contains(name) {
                            self.violations.push(format!(
                                "function `{}` frees non-linear value `{}` as linear resource",
                                self.function.name, name
                            ));
                        }
                        self.linear_freed.insert(name.to_string());
                    }
                }
                ast::walk_expr(self, expr);
            }
        }
        let mut collector = Collector {
            function,
            linear_owned: &mut linear_owned,
            linear_freed: &mut linear_freed,
            violations: &mut violations,
            ownership_summaries: &ownership_summaries,
        };
        for stmt in &function.body {
            collector.visit_stmt(stmt);
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
        Type::Named { name, .. } if is_linear_runtime_handle(name) => true,
        _ => false,
    }
}

fn is_linear_runtime_handle(name: &str) -> bool {
    matches!(
        name,
        "Linear" | "Resource" | "HttpHandle" | "HttpStreamHandle" | "ProcessHandle"
    )
}

fn binding_resource_type<'a>(
    function: &'a TypedFunction,
    name: &str,
    explicit_ty: Option<&'a Type>,
    value: &'a Expr,
) -> Option<&'a Type> {
    explicit_ty
        .or_else(|| function.local_types.get(name))
        .or_else(|| {
            is_alloc_expr(value)
                .then(|| function.local_types.get(name))
                .flatten()
        })
}

fn binding_creates_owned_resource(
    function: &TypedFunction,
    name: &str,
    ty: Option<&Type>,
    value: &Expr,
) -> bool {
    binding_resource_type(function, name, ty, value).is_some_and(is_linear_type)
        || is_alloc_expr(value)
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
                        "rng" | "random" | "std.rand" | "crypto" => {
                            self.caps.insert("rng".to_string());
                        }
                        "fs" | "file" | "std.io" => {
                            self.caps.insert("fs".to_string());
                        }
                        "storage" => {
                            self.caps.insert("storage".to_string());
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
                        "log" | "logger" | "std.log" => {
                            self.caps.insert("log".to_string());
                        }
                        "error" | "err" | "std.error" => {
                            self.caps.insert("error".to_string());
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

fn analyze_ownership(
    functions: &[TypedFunction],
    call_graph: &[(String, String)],
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let summaries = build_function_memory_summaries(functions);
    let ownership_summaries = build_function_ownership_summaries(functions);
    violations.extend(analyze_alias_and_provenance(functions));
    violations.extend(analyze_atomic_ordering_claims(functions));
    for function in functions {
        let seeded_owners = if function.is_extern {
            BTreeMap::new()
        } else {
            ownership_summaries
                .get(&function.name)
                .into_iter()
                .flat_map(|consumed| consumed.iter().copied())
                .filter_map(|index| function.params.get(index))
                .enumerate()
                .map(|(alloc_index, param)| (param.name.clone(), alloc_index + 1))
                .collect::<BTreeMap<_, _>>()
        };
        let mut state = OwnershipState {
            owner_candidates: function
                .params
                .iter()
                .map(|param| param.name.clone())
                .collect::<BTreeSet<_>>(),
            owners: seeded_owners,
            ..OwnershipState::default()
        };
        let mut next_alloc = state.owners.len() + 1;
        let _ = analyze_ownership_block(
            function,
            &function.body,
            &mut state,
            &mut next_alloc,
            &mut violations,
            &function.name,
            &ownership_summaries,
            struct_defs,
            enum_defs,
            None,
        );
        for (name, alloc_id) in state.owners {
            if state.deferred.contains(&alloc_id) {
                continue;
            }
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OwnershipState {
    owners: BTreeMap<String, usize>,
    moved: BTreeSet<String>,
    maybe_moved: BTreeSet<String>,
    owner_candidates: BTreeSet<String>,
    deferred: BTreeSet<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LoopExitStates {
    breaks: Vec<OwnershipState>,
    continues: Vec<OwnershipState>,
}

fn build_function_ownership_summaries(
    functions: &[TypedFunction],
) -> BTreeMap<String, BTreeSet<usize>> {
    let mut summaries = functions
        .iter()
        .map(|function| (function.name.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut changed = true;
    while changed {
        changed = false;
        for function in functions {
            let next = infer_consumed_param_indices(function, &summaries);
            let entry = summaries.entry(function.name.clone()).or_default();
            if *entry != next {
                *entry = next;
                changed = true;
            }
        }
    }
    summaries
}

fn infer_consumed_param_indices(
    function: &TypedFunction,
    summaries: &BTreeMap<String, BTreeSet<usize>>,
) -> BTreeSet<usize> {
    let mut consumed = function
        .is_extern
        .then(|| {
            function
                .params
                .iter()
                .enumerate()
                .filter(|(_, param)| function.is_unsafe && param.name.ends_with("_owned"))
                .map(|(index, _)| index)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let param_indexes = function
        .params
        .iter()
        .enumerate()
        .map(|(index, param)| (param.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    collect_consumed_params_from_stmts(&function.body, &param_indexes, summaries, &mut consumed);
    consumed
}

fn collect_consumed_params_from_stmts(
    body: &[Stmt],
    param_indexes: &BTreeMap<&str, usize>,
    summaries: &BTreeMap<String, BTreeSet<usize>>,
    out: &mut BTreeSet<usize>,
) {
    for stmt in body {
        match stmt {
            Stmt::Let { value, .. }
            | Stmt::LetPattern { value, .. }
            | Stmt::Assign { value, .. }
            | Stmt::CompoundAssign { value, .. }
            | Stmt::Defer(value)
            | Stmt::Requires(value)
            | Stmt::Ensures(value)
            | Stmt::Expr(value) => {
                collect_consumed_params_from_expr(value, param_indexes, summaries, out);
            }
            Stmt::Return(Some(expr)) => {
                collect_consumed_params_from_expr(expr, param_indexes, summaries, out);
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(then_body, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(else_body, param_indexes, summaries, out);
            }
            Stmt::While { condition, body } => {
                collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_consumed_params_from_stmts(
                        std::slice::from_ref(init.as_ref()),
                        param_indexes,
                        summaries,
                        out,
                    );
                }
                if let Some(condition) = condition {
                    collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
                }
                if let Some(step) = step {
                    collect_consumed_params_from_stmts(
                        std::slice::from_ref(step.as_ref()),
                        param_indexes,
                        summaries,
                        out,
                    );
                }
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::ForIn { iterable, body, .. } => {
                collect_consumed_params_from_expr(iterable, param_indexes, summaries, out);
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::Loop { body } => {
                collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
            }
            Stmt::Match { scrutinee, arms } => {
                collect_consumed_params_from_expr(scrutinee, param_indexes, summaries, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_consumed_params_from_expr(guard, param_indexes, summaries, out);
                    }
                    collect_consumed_params_from_expr(&arm.value, param_indexes, summaries, out);
                }
            }
            Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => {}
        }
    }
}

fn collect_consumed_params_from_expr(
    expr: &Expr,
    param_indexes: &BTreeMap<&str, usize>,
    summaries: &BTreeMap<String, BTreeSet<usize>>,
    out: &mut BTreeSet<usize>,
) {
    match expr {
        Expr::Call { callee, args } => {
            for name in consumed_arg_identity_names(callee, args, summaries) {
                if let Some(index) = param_indexes.get(name).copied() {
                    out.insert(index);
                }
            }
            for arg in args {
                collect_consumed_params_from_expr(arg, param_indexes, summaries, out);
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            collect_consumed_params_from_stmts(body, param_indexes, summaries, out);
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_consumed_params_from_expr(condition, param_indexes, summaries, out);
            collect_consumed_params_from_expr(then_expr, param_indexes, summaries, out);
            collect_consumed_params_from_expr(else_expr, param_indexes, summaries, out);
        }
        Expr::Match { scrutinee, arms } => {
            collect_consumed_params_from_expr(scrutinee, param_indexes, summaries, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_consumed_params_from_expr(guard, param_indexes, summaries, out);
                }
                collect_consumed_params_from_expr(&arm.value, param_indexes, summaries, out);
            }
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_consumed_params_from_expr(try_expr, param_indexes, summaries, out);
            collect_consumed_params_from_expr(catch_expr, param_indexes, summaries, out);
        }
        Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Discard(inner)
        | Expr::Unary { expr: inner, .. } => {
            collect_consumed_params_from_expr(inner, param_indexes, summaries, out);
        }
        Expr::Binary { left, right, .. } => {
            collect_consumed_params_from_expr(left, param_indexes, summaries, out);
            collect_consumed_params_from_expr(right, param_indexes, summaries, out);
        }
        Expr::FieldAccess { base, .. } => {
            collect_consumed_params_from_expr(base, param_indexes, summaries, out);
        }
        Expr::Index { base, index } => {
            collect_consumed_params_from_expr(base, param_indexes, summaries, out);
            collect_consumed_params_from_expr(index, param_indexes, summaries, out);
        }
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_consumed_params_from_expr(value, param_indexes, summaries, out);
            }
        }
        Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for item in payload {
                collect_consumed_params_from_expr(item, param_indexes, summaries, out);
            }
            for (_, value) in named_payload {
                collect_consumed_params_from_expr(value, param_indexes, summaries, out);
            }
        }
        Expr::Tuple(items) | Expr::ArrayLiteral(items) => {
            for item in items {
                collect_consumed_params_from_expr(item, param_indexes, summaries, out);
            }
        }
        _ => {}
    }
}

fn expr_identity_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(name) => Some(name.as_str()),
        Expr::Group(inner) => expr_identity_name(inner),
        _ => None,
    }
}

fn expr_consumed_binding_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(name) => Some(name.as_str()),
        Expr::Group(inner)
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Index { base: inner, .. } => expr_consumed_binding_name(inner),
        _ => None,
    }
}

fn runtime_consumed_param_indices(callee: &str) -> &'static [usize] {
    match callee {
        "http.write"
        | "http.write_json"
        | "http.write_response"
        | "route.write_404"
        | "route.write_405"
        | "http.stream_close" => &[0],
        _ if is_free_callee(callee) || is_close_callee(callee) => &[0],
        _ => &[],
    }
}

fn consumed_arg_identity_names<'a>(
    callee: &str,
    args: &'a [Expr],
    summaries: &BTreeMap<String, BTreeSet<usize>>,
) -> Vec<&'a str> {
    let mut names = runtime_consumed_param_indices(callee)
        .iter()
        .filter_map(|index| args.get(*index))
        .filter_map(expr_consumed_binding_name)
        .collect::<Vec<_>>();
    if let Some(consumed_params) = summaries.get(callee) {
        for consumed_index in consumed_params {
            if let Some(name) = args
                .get(*consumed_index)
                .and_then(expr_consumed_binding_name)
            {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReturnProvenanceSummary {
    Param(usize),
    Fresh,
    Unknown,
}

#[derive(Debug, Clone)]
struct CallShape {
    params: Vec<ast::Param>,
    return_type: Type,
    is_extern: bool,
    is_unsafe: bool,
    return_provenance: ReturnProvenanceSummary,
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
            Stmt::Break(_) | Stmt::Continue => {}
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
            Expr::Tuple(items) => {
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
            Expr::Closure { body, .. } => analyze_expr(
                function_name,
                body,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
            Expr::Group(inner)
            | Expr::Await(inner)
            | Expr::Discard(inner)
            | Expr::Unary { expr: inner, .. } => analyze_expr(
                function_name,
                inner,
                in_unsafe_context,
                unsafe_functions,
                violations,
            ),
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
            Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    then_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                analyze_expr(
                    function_name,
                    else_expr,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
            }
            Expr::Match { scrutinee, arms } => {
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
            Expr::While { condition, body } => {
                analyze_expr(
                    function_name,
                    condition,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::For {
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
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::ForIn { iterable, body, .. } => {
                analyze_expr(
                    function_name,
                    iterable,
                    in_unsafe_context,
                    unsafe_functions,
                    violations,
                );
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Loop { body } => {
                for stmt in body {
                    analyze_stmt(
                        function_name,
                        stmt,
                        in_unsafe_context,
                        unsafe_functions,
                        violations,
                    );
                }
            }
            Expr::Return(value) | Expr::Break(value) => {
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
            Expr::Continue => {}
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
            Expr::ObjectLiteral(fields) => {
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
    function: &TypedFunction,
    body: &[Stmt],
    state: &mut OwnershipState,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    mut loop_exits: Option<&mut LoopExitStates>,
) -> bool {
    for stmt in body {
        for name in state.moved.iter() {
            if stmt_uses_ident(stmt, name) {
                violations.push(format!(
                    "function `{}` uses moved value `{}` after move/consume",
                    function_name, name
                ));
            }
        }
        for name in state.maybe_moved.iter() {
            if stmt_uses_ident(stmt, name) {
                violations.push(format!(
                    "function `{}` uses conditionally consumed value `{}` after path-sensitive ownership merge",
                    function_name, name
                ));
            }
        }
        match stmt {
            Stmt::Let {
                name, value, ty, ..
            } => {
                state.owner_candidates.insert(name.clone());
                if binding_creates_owned_resource(function, name, ty.as_ref(), value) {
                    state.owners.insert(name.clone(), *next_alloc);
                    *next_alloc += 1;
                    state.moved.remove(name);
                    state.maybe_moved.remove(name);
                }
                if let Expr::Ident(from) = value {
                    if let Some(owner) = state.owners.remove(from) {
                        state.owners.insert(name.clone(), owner);
                        state.moved.insert(from.clone());
                        state.moved.remove(name);
                        state.maybe_moved.remove(name);
                    }
                }
                if is_partial_move_expr(function, value, &state.owners, struct_defs, enum_defs) {
                    violations.push(format!(
                        "function `{}` performs partial move from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::LetPattern { pattern, value, .. } => {
                collect_pattern_bindings(pattern, &mut state.owner_candidates);
                if is_partial_move_expr(function, value, &state.owners, struct_defs, enum_defs)
                    || pattern_performs_partial_move(
                        pattern,
                        function,
                        value,
                        struct_defs,
                        enum_defs,
                    )
                {
                    violations.push(format!(
                        "function `{}` performs partial move from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::Assign { target, value } => {
                state.owner_candidates.insert(target.clone());
                if let Expr::Ident(from) = value {
                    if let Some(owner) = state.owners.remove(from) {
                        state.owners.insert(target.clone(), owner);
                        state.moved.insert(from.clone());
                    }
                }
                state.moved.remove(target);
                state.maybe_moved.remove(target);
                if is_partial_move_expr(function, value, &state.owners, struct_defs, enum_defs) {
                    violations.push(format!(
                        "function `{}` performs partial move assignment from owned aggregate; partial moves are forbidden in v0",
                        function_name
                    ));
                }
            }
            Stmt::CompoundAssign { target, value, .. } => {
                state.owner_candidates.insert(target.clone());
                if let Expr::Ident(from) = value {
                    if let Some(owner) = state.owners.remove(from) {
                        state.owners.insert(target.clone(), owner);
                        state.moved.insert(from.clone());
                    }
                }
                state.moved.remove(target);
                state.maybe_moved.remove(target);
            }
            Stmt::Expr(Expr::Call { callee, args }) => {
                if callee == "free"
                    || callee.ends_with(".free")
                    || callee == "close"
                    || callee.ends_with(".close")
                {
                    if let Some(name) = args.first().and_then(expr_consumed_binding_name) {
                        if let Some(owner) = state.owners.remove(name) {
                            if state.deferred.contains(&owner) {
                                violations.push(format!(
                                    "function `{}` consumes value `{}` after scheduling deferred cleanup for the same owner",
                                    function_name, name
                                ));
                            }
                            state.moved.insert(name.to_string());
                            state.maybe_moved.remove(name);
                        } else {
                            violations.push(format!(
                                "function `{}` consumes non-owned or already-consumed value `{}` via `{}`",
                                function_name, name, callee
                            ));
                        }
                    }
                }
                apply_call_consumed_params(callee, args, state, ownership_summaries);
            }
            Stmt::Defer(expr) => {
                register_deferred_cleanup(expr, state, violations, function_name);
            }
            Stmt::Expr(Expr::UnsafeBlock { body, .. }) => {
                if !analyze_ownership_block(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                ) {
                    return false;
                }
            }
            Stmt::Return(Some(expr)) => {
                if let Some(name) = expr_identity_name(expr) {
                    if state.owners.remove(name).is_some() {
                        state.moved.insert(name.to_string());
                    }
                } else {
                    analyze_expr_value_ownership(
                        function,
                        expr,
                        state,
                        next_alloc,
                        violations,
                        function_name,
                        ownership_summaries,
                        struct_defs,
                        enum_defs,
                        None,
                    );
                }
                return false;
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let entry_state = state.clone();
                let mut then_state = state.clone();
                let mut else_state = state.clone();
                let then_fallthrough = analyze_ownership_block(
                    function,
                    then_body,
                    &mut then_state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                let else_fallthrough = analyze_ownership_block(
                    function,
                    else_body,
                    &mut else_state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                *state = match (then_fallthrough, else_fallthrough) {
                    (true, true) => merge_ownership_states(
                        function_name,
                        "conditional branches",
                        &entry_state,
                        &[then_state, else_state],
                        violations,
                    ),
                    (true, false) => then_state,
                    (false, true) => else_state,
                    (false, false) => return false,
                };
            }
            Stmt::While { condition, body } => {
                if !analyze_loop_ownership(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    !matches!(condition, Expr::Bool(true)),
                ) {
                    return false;
                }
            }
            Stmt::For {
                init,
                condition: _,
                step,
                body,
            } => {
                if let Some(init) = init {
                    let _ = analyze_ownership_block(
                        function,
                        std::slice::from_ref(init.as_ref()),
                        state,
                        next_alloc,
                        violations,
                        function_name,
                        ownership_summaries,
                        struct_defs,
                        enum_defs,
                        None,
                    );
                }
                let mut loop_body = body.to_vec();
                if let Some(step) = step {
                    loop_body.push((**step).clone());
                }
                if !analyze_loop_ownership(
                    function,
                    &loop_body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    true,
                ) {
                    return false;
                }
            }
            Stmt::ForIn { binding, body, .. } => {
                state.moved.remove(binding);
                state.maybe_moved.remove(binding);
                state.owner_candidates.insert(binding.clone());
                if !analyze_loop_ownership(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    true,
                ) {
                    return false;
                }
            }
            Stmt::Loop { body } => {
                if !analyze_loop_ownership(
                    function,
                    body,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    false,
                ) {
                    return false;
                }
            }
            Stmt::Break(_) => {
                if let Some(loop_exits) = loop_exits.as_deref_mut() {
                    loop_exits.breaks.push(state.clone());
                }
                return false;
            }
            Stmt::Continue => {
                if let Some(loop_exits) = loop_exits.as_deref_mut() {
                    loop_exits.continues.push(state.clone());
                }
                return false;
            }
            Stmt::Match { arms, .. } => {
                let entry_state = state.clone();
                let mut arm_states = Vec::new();
                for arm in arms {
                    let mut arm_state = state.clone();
                    if let Some(guard) = &arm.guard {
                        let _ = guard;
                    }
                    analyze_expr_value_ownership(
                        function,
                        &arm.value,
                        &mut arm_state,
                        next_alloc,
                        violations,
                        function_name,
                        ownership_summaries,
                        struct_defs,
                        enum_defs,
                        None,
                    );
                    arm_states.push(arm_state);
                }
                if !arm_states.is_empty() {
                    *state = merge_ownership_states(
                        function_name,
                        "match arms",
                        &entry_state,
                        &arm_states,
                        violations,
                    );
                }
            }
            Stmt::Expr(expr) => {
                analyze_expr_value_ownership(
                    function,
                    expr,
                    state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
            }
            Stmt::Return(None) => return false,
            Stmt::Requires(_) | Stmt::Ensures(_) => {}
        }
    }
    true
}

fn analyze_expr_value_ownership(
    function: &TypedFunction,
    expr: &Expr,
    state: &mut OwnershipState,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    mut loop_exits: Option<&mut LoopExitStates>,
) {
    match expr {
        Expr::Call { callee, args } if is_free_callee(callee) || is_close_callee(callee) => {
            if let Some(name) = args.first().and_then(expr_consumed_binding_name) {
                if let Some(owner) = state.owners.remove(name) {
                    if state.deferred.contains(&owner) {
                        violations.push(format!(
                            "function `{}` consumes value `{}` after scheduling deferred cleanup for the same owner",
                            function_name, name
                        ));
                    }
                    state.moved.insert(name.to_string());
                    state.maybe_moved.remove(name);
                } else {
                    violations.push(format!(
                        "function `{}` consumes non-owned or already-consumed value `{}` via `{}`",
                        function_name, name, callee
                    ));
                }
            }
        }
        Expr::Call { callee, args } => {
            apply_call_consumed_params(callee, args, state, ownership_summaries);
        }
        Expr::UnsafeBlock { body, .. } => {
            let _ = analyze_ownership_block(
                function,
                body,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
        }
        Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Discard(inner)
        | Expr::Unary { expr: inner, .. } => {
            analyze_expr_value_ownership(
                function,
                inner,
                state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                loop_exits.as_deref_mut(),
            );
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            let entry_state = state.clone();
            let mut try_state = state.clone();
            let mut catch_state = state.clone();
            analyze_expr_value_ownership(
                function,
                try_expr,
                &mut try_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            analyze_expr_value_ownership(
                function,
                catch_expr,
                &mut catch_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            *state = merge_ownership_states(
                function_name,
                "try/catch expressions",
                &entry_state,
                &[try_state, catch_state],
                violations,
            );
        }
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let entry_state = state.clone();
            let mut then_state = state.clone();
            let mut else_state = state.clone();
            analyze_expr_value_ownership(
                function,
                then_expr,
                &mut then_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            analyze_expr_value_ownership(
                function,
                else_expr,
                &mut else_state,
                next_alloc,
                violations,
                function_name,
                ownership_summaries,
                struct_defs,
                enum_defs,
                None,
            );
            *state = merge_ownership_states(
                function_name,
                "conditional expressions",
                &entry_state,
                &[then_state, else_state],
                violations,
            );
        }
        Expr::Match { arms, .. } => {
            let entry_state = state.clone();
            let mut arm_states = Vec::new();
            for arm in arms {
                let mut arm_state = state.clone();
                analyze_expr_value_ownership(
                    function,
                    &arm.value,
                    &mut arm_state,
                    next_alloc,
                    violations,
                    function_name,
                    ownership_summaries,
                    struct_defs,
                    enum_defs,
                    None,
                );
                arm_states.push(arm_state);
            }
            if !arm_states.is_empty() {
                *state = merge_ownership_states(
                    function_name,
                    "match expressions",
                    &entry_state,
                    &arm_states,
                    violations,
                );
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_loop_ownership(
    function: &TypedFunction,
    body: &[Stmt],
    state: &mut OwnershipState,
    next_alloc: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    can_skip_loop: bool,
) -> bool {
    let entry_state = state.clone();
    let mut header_state = entry_state.clone();
    let mut break_states = Vec::<OwnershipState>::new();

    for _ in 0..8 {
        let mut iteration_state = header_state.clone();
        let mut exits = LoopExitStates::default();
        let falls_through = analyze_ownership_block(
            function,
            body,
            &mut iteration_state,
            next_alloc,
            violations,
            function_name,
            ownership_summaries,
            struct_defs,
            enum_defs,
            Some(&mut exits),
        );

        let mut backedge_states = vec![entry_state.clone()];
        if falls_through {
            backedge_states.push(iteration_state);
        }
        backedge_states.extend(exits.continues.into_iter());
        let next_header = merge_ownership_states(
            function_name,
            "loop iterations",
            &entry_state,
            &backedge_states,
            violations,
        );
        let next_breaks = exits.breaks;
        if next_header == header_state && next_breaks == break_states {
            break;
        }
        header_state = next_header;
        break_states = next_breaks;
    }

    let mut post_loop_states = Vec::new();
    if can_skip_loop {
        post_loop_states.push(header_state);
    }
    post_loop_states.extend(break_states);
    if post_loop_states.is_empty() {
        return false;
    }
    *state = merge_ownership_states(
        function_name,
        "loop exits",
        &entry_state,
        &post_loop_states,
        violations,
    );
    true
}

fn apply_call_consumed_params(
    callee: &str,
    args: &[Expr],
    state: &mut OwnershipState,
    ownership_summaries: &BTreeMap<String, BTreeSet<usize>>,
) {
    for arg_name in consumed_arg_identity_names(callee, args, ownership_summaries) {
        if let Some(owner) = state.owners.remove(arg_name) {
            state.moved.insert(arg_name.to_string());
            state.maybe_moved.remove(arg_name);
            state.deferred.remove(&owner);
        }
    }
}

fn merge_ownership_states(
    function_name: &str,
    control_kind: &str,
    entry_state: &OwnershipState,
    branches: &[OwnershipState],
    violations: &mut Vec<String>,
) -> OwnershipState {
    let mut merged = OwnershipState::default();
    merged.deferred.extend(entry_state.deferred.iter().copied());
    let mut names = BTreeSet::<String>::new();
    names.extend(entry_state.owners.keys().cloned());
    names.extend(entry_state.owner_candidates.iter().cloned());
    names.extend(entry_state.moved.iter().cloned());
    names.extend(entry_state.maybe_moved.iter().cloned());
    for branch in branches {
        merged.deferred.extend(branch.deferred.iter().copied());
    }
    for name in names {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum MergeClass {
            Owned(usize),
            Moved,
            MaybeMoved,
            Clear,
        }

        let classes = branches
            .iter()
            .map(|branch| {
                if let Some(owner) = branch.owners.get(&name).copied() {
                    MergeClass::Owned(owner)
                } else if branch.moved.contains(&name) {
                    MergeClass::Moved
                } else if branch.maybe_moved.contains(&name) {
                    MergeClass::MaybeMoved
                } else {
                    MergeClass::Clear
                }
            })
            .collect::<Vec<_>>();
        if classes.windows(2).any(|window| window[0] != window[1]) {
            violations.push(format!(
                "function `{}` has divergent ownership state for `{}` across {}; rewrite control flow so ownership is consistent on every path",
                function_name, name, control_kind
            ));
        }
        match classes.first().copied().unwrap_or(MergeClass::Clear) {
            MergeClass::Owned(owner_id)
                if classes
                    .iter()
                    .all(|class| *class == MergeClass::Owned(owner_id)) =>
            {
                merged.owners.insert(name.clone(), owner_id);
            }
            MergeClass::Moved if classes.iter().all(|class| *class == MergeClass::Moved) => {
                merged.moved.insert(name.clone());
            }
            MergeClass::Clear if classes.iter().all(|class| *class == MergeClass::Clear) => {}
            _ => {
                if classes.iter().any(|class| *class != MergeClass::Clear) {
                    merged.maybe_moved.insert(name.clone());
                }
            }
        }
        if entry_state.owner_candidates.contains(&name)
            || branches
                .iter()
                .any(|branch| branch.owner_candidates.contains(&name))
        {
            merged.owner_candidates.insert(name);
        }
    }
    merged
}

fn register_deferred_cleanup(
    expr: &Expr,
    state: &mut OwnershipState,
    violations: &mut Vec<String>,
    function_name: &str,
) {
    let mut resources = BTreeSet::new();
    collect_cleanup_targets(expr, &mut resources);
    for name in resources {
        let Some(owner) = state.owners.get(&name).copied() else {
            violations.push(format!(
                "function `{}` schedules deferred cleanup for non-owned or already-consumed value `{}`",
                function_name, name
            ));
            continue;
        };
        if !state.deferred.insert(owner) {
            violations.push(format!(
                "function `{}` schedules deferred cleanup more than once for `{}`",
                function_name, name
            ));
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

fn unsafe_contract_counts_as_call_edge_covered(site: &UnsafeContractSite) -> bool {
    unsafe_contract_metadata_complete(site) && unsafe_contract_invariant_is_specific(site)
}

fn build_function_memory_summaries(
    functions: &[TypedFunction],
) -> BTreeMap<String, FunctionMemorySummary> {
    let mut out = BTreeMap::new();
    let mut unsafe_reasoned_sites_by_function = BTreeMap::<String, usize>::new();
    for site in collect_unsafe_contract_sites(functions)
        .into_iter()
        .filter(|site| site.kind != "unsafe_violation_callsite")
        .filter(unsafe_contract_counts_as_call_edge_covered)
    {
        *unsafe_reasoned_sites_by_function
            .entry(site.function.clone())
            .or_insert(0) += 1;
    }
    for function in functions {
        let mut alloc_sites = 0usize;
        let mut free_sites = 0usize;
        let mut close_sites = 0usize;
        let mut unsafe_sites = 0usize;
        let mut has_await = false;
        if function.is_unsafe {
            unsafe_sites += 1;
        }
        struct Collector<'a> {
            alloc_sites: &'a mut usize,
            free_sites: &'a mut usize,
            close_sites: &'a mut usize,
            unsafe_sites: &'a mut usize,
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
                unsafe_reasoned_sites: unsafe_reasoned_sites_by_function
                    .get(&function.name)
                    .copied()
                    .unwrap_or(0),
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

fn unsafe_contract_counts_as_reasoned(site: &UnsafeContractSite) -> bool {
    unsafe_contract_metadata_complete(site)
        && unsafe_contract_invariant_is_specific(site)
        && unsafe_contract_has_independent_proof(site)
}

fn unsafe_contract_metadata_complete(site: &UnsafeContractSite) -> bool {
    site.reason.as_deref().is_some_and(|v| !v.is_empty())
        && site.invariant.as_deref().is_some_and(|v| !v.is_empty())
        && site.owner.as_deref().is_some_and(|v| !v.is_empty())
        && site.scope.as_deref().is_some_and(|v| !v.is_empty())
        && site.risk_class.as_deref().is_some_and(|v| !v.is_empty())
        && site.proof_ref.as_deref().is_some_and(|v| !v.is_empty())
}

fn unsafe_contract_invariant_is_specific(site: &UnsafeContractSite) -> bool {
    site.owner
        .as_deref()
        .is_some_and(|owner| owner != "scope_root")
}

fn unsafe_contract_has_independent_proof(site: &UnsafeContractSite) -> bool {
    let Some(proof_ref) = site.proof_ref.as_deref() else {
        return false;
    };
    !proof_ref.starts_with("gate://compiler-generated/")
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
        Stmt::Break(_) | Stmt::Continue => false,
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
        Expr::Tuple(items) => items.iter().any(|value| expr_uses_ident(value, target)),
        Expr::Closure { params, body, .. } => {
            if params.iter().any(|param| param.name == target) {
                false
            } else {
                expr_uses_ident(body, target)
            }
        }
        Expr::Group(inner) | Expr::Await(inner) | Expr::Discard(inner) => {
            expr_uses_ident(inner, target)
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => expr_uses_ident(try_expr, target) || expr_uses_ident(catch_expr, target),
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            expr_uses_ident(condition, target)
                || expr_uses_ident(then_expr, target)
                || expr_uses_ident(else_expr, target)
        }
        Expr::Match { scrutinee, arms } => {
            expr_uses_ident(scrutinee, target)
                || arms.iter().any(|arm| {
                    arm.guard
                        .as_ref()
                        .is_some_and(|guard| expr_uses_ident(guard, target))
                        || expr_uses_ident(&arm.value, target)
                })
        }
        Expr::While { condition, body } => {
            expr_uses_ident(condition, target)
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            init.as_ref()
                .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || condition
                    .as_ref()
                    .is_some_and(|expr| expr_uses_ident(expr, target))
                || step
                    .as_ref()
                    .is_some_and(|stmt| stmt_uses_ident(stmt, target))
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::ForIn { iterable, body, .. } => {
            expr_uses_ident(iterable, target)
                || body.iter().any(|stmt| stmt_uses_ident(stmt, target))
        }
        Expr::Loop { body } => body.iter().any(|stmt| stmt_uses_ident(stmt, target)),
        Expr::Return(value) | Expr::Break(value) => value
            .as_ref()
            .is_some_and(|expr| expr_uses_ident(expr, target)),
        Expr::Continue => false,
        Expr::Binary { left, right, .. } => {
            expr_uses_ident(left, target) || expr_uses_ident(right, target)
        }
        Expr::Range { start, end, .. } => {
            expr_uses_ident(start, target) || expr_uses_ident(end, target)
        }
        Expr::ArrayLiteral(items) => items.iter().any(|item| expr_uses_ident(item, target)),
        Expr::ObjectLiteral(fields) => fields
            .iter()
            .any(|(_, value)| expr_uses_ident(value, target)),
        Expr::Index { base, index } => {
            expr_uses_ident(base, target) || expr_uses_ident(index, target)
        }
        Expr::Unary { expr, .. } => expr_uses_ident(expr, target),
        Expr::Int(_) | Expr::Float { .. } | Expr::Char(_) | Expr::Bool(_) | Expr::Str(_) => false,
    }
}

fn is_partial_move_expr(
    function: &TypedFunction,
    expr: &Expr,
    owners: &BTreeMap<String, usize>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    match expr {
        Expr::Group(inner) => is_partial_move_expr(function, inner, owners, struct_defs, enum_defs),
        Expr::FieldAccess { .. } | Expr::Index { .. } => expr_root_binding_name(expr)
            .and_then(|name| binding_partial_move_root_type(function, name))
            .is_some_and(|ty| type_contains_linear_members(ty, struct_defs, enum_defs)),
        Expr::Tuple(items) | Expr::ArrayLiteral(items) => items
            .iter()
            .any(|item| is_partial_move_expr(function, item, owners, struct_defs, enum_defs)),
        Expr::StructInit { fields, .. } | Expr::ObjectLiteral(fields) => {
            fields.iter().any(|(_, value)| {
                is_partial_move_expr(function, value, owners, struct_defs, enum_defs)
            })
        }
        Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            payload
                .iter()
                .any(|item| is_partial_move_expr(function, item, owners, struct_defs, enum_defs))
                || named_payload.iter().any(|(_, value)| {
                    is_partial_move_expr(function, value, owners, struct_defs, enum_defs)
                })
        }
        _ => owners.is_empty() && false,
    }
}

fn expr_root_binding_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(name) => Some(name.as_str()),
        Expr::Group(inner)
        | Expr::FieldAccess { base: inner, .. }
        | Expr::Index { base: inner, .. } => expr_root_binding_name(inner),
        _ => None,
    }
}

fn binding_partial_move_root_type<'a>(function: &'a TypedFunction, name: &str) -> Option<&'a Type> {
    function.local_types.get(name).or_else(|| {
        function
            .params
            .iter()
            .find(|param| param.name == name)
            .map(|param| &param.ty)
    })
}

fn type_contains_linear_members(
    ty: &Type,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    fn walk(
        ty: &Type,
        struct_defs: &HashMap<String, ast::Struct>,
        enum_defs: &HashMap<String, ast::Enum>,
        seen: &mut BTreeSet<String>,
    ) -> bool {
        if is_linear_type(ty) {
            return true;
        }
        match ty {
            Type::Tuple(items) => items
                .iter()
                .any(|item| walk(item, struct_defs, enum_defs, seen)),
            Type::Array { elem, .. }
            | Type::Slice(elem)
            | Type::Option(elem)
            | Type::Vec(elem)
            | Type::Deque(elem)
            | Type::Ring(elem)
            | Type::Set(elem)
            | Type::Future(elem) => walk(elem, struct_defs, enum_defs, seen),
            Type::Result { ok, err } => {
                walk(ok, struct_defs, enum_defs, seen) || walk(err, struct_defs, enum_defs, seen)
            }
            Type::Map { key, value } => {
                walk(key, struct_defs, enum_defs, seen) || walk(value, struct_defs, enum_defs, seen)
            }
            Type::Named { name, .. } => {
                if !seen.insert(name.clone()) {
                    return false;
                }
                let result = struct_defs.get(name).is_some_and(|def| {
                    def.fields
                        .iter()
                        .any(|field| walk(&field.ty, struct_defs, enum_defs, seen))
                }) || enum_defs.get(name).is_some_and(|def| {
                    def.variants.iter().any(|variant| {
                        variant
                            .payload
                            .iter()
                            .any(|payload| walk(payload, struct_defs, enum_defs, seen))
                            || variant
                                .named_payload
                                .iter()
                                .any(|field| walk(&field.ty, struct_defs, enum_defs, seen))
                    })
                });
                seen.remove(name);
                result
            }
            _ => false,
        }
    }

    walk(ty, struct_defs, enum_defs, &mut BTreeSet::new())
}

fn pattern_performs_partial_move(
    pattern: &ast::Pattern,
    function: &TypedFunction,
    value: &Expr,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    let Some(root_name) = expr_root_binding_name(value) else {
        return false;
    };
    let Some(root_ty) = binding_partial_move_root_type(function, root_name) else {
        return false;
    };
    if !type_contains_linear_members(root_ty, struct_defs, enum_defs) {
        return false;
    }
    pattern_is_partial_move(pattern, root_ty, struct_defs, enum_defs)
}

fn pattern_is_partial_move(
    pattern: &ast::Pattern,
    scrutinee_ty: &Type,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
) -> bool {
    match (pattern, scrutinee_ty) {
        (ast::Pattern::Tuple(items), Type::Tuple(scrutinee_items)) => {
            if items.len() != scrutinee_items.len() {
                return true;
            }
            items.iter().zip(scrutinee_items.iter()).any(|(item, ty)| {
                matches!(item, ast::Pattern::Wildcard)
                    || pattern_is_partial_move(item, ty, struct_defs, enum_defs)
            })
        }
        (ast::Pattern::Struct { name, fields }, Type::Named { name: ty_name, .. })
            if name == ty_name =>
        {
            let Some(def) = struct_defs.get(name) else {
                return false;
            };
            if fields.len() != def.fields.len() {
                return true;
            }
            fields.iter().any(|(_, binding)| binding == "_")
        }
        (
            ast::Pattern::Variant {
                enum_name,
                variant,
                bindings,
                named_bindings,
            },
            Type::Named { name: ty_name, .. },
        ) if enum_name == ty_name => {
            let Some(def) = enum_defs.get(enum_name) else {
                return false;
            };
            let Some(variant_def) = def
                .variants
                .iter()
                .find(|candidate| candidate.name == *variant)
            else {
                return false;
            };
            if !named_bindings.is_empty() {
                return named_bindings.len() != variant_def.named_payload.len()
                    || named_bindings.iter().any(|(_, binding)| binding == "_");
            }
            bindings.len() != variant_def.payload.len()
                || bindings.iter().any(|binding| binding == "_")
        }
        (ast::Pattern::Or(patterns), _) => patterns.iter().any(|candidate| {
            pattern_is_partial_move(candidate, scrutinee_ty, struct_defs, enum_defs)
        }),
        _ => false,
    }
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
    let mut violations = Vec::new();
    let mut signatures = functions
        .iter()
        .map(|function| {
            (
                function.name.clone(),
                CallShape {
                    params: function.params.clone(),
                    return_type: function.return_type.clone(),
                    is_extern: function.is_extern,
                    is_unsafe: function.is_unsafe,
                    return_provenance: ReturnProvenanceSummary::Unknown,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    populate_return_provenance_summaries(functions, &mut signatures);
    for function in functions {
        let mut next_root = 1usize;
        let mut state = ProvenanceState::default();
        for param in &function.params {
            if param.ty.is_pointer_like() || matches!(param.ty, Type::Ref { .. }) {
                state.roots.insert(param.name.clone(), next_root);
                next_root += 1;
            }
        }
        analyze_provenance_block(
            &function.body,
            &mut state,
            &mut next_root,
            &mut violations,
            &function.name,
            &signatures,
        );
    }
    violations
}

#[derive(Debug, Clone, Default)]
struct ProvenanceState {
    roots: BTreeMap<String, usize>,
    freed_roots: BTreeSet<usize>,
}

fn analyze_provenance_block(
    body: &[Stmt],
    state: &mut ProvenanceState,
    next_root: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    for stmt in body {
        analyze_provenance_stmt(
            stmt,
            state,
            next_root,
            violations,
            function_name,
            signatures,
        );
    }
}

fn analyze_provenance_stmt(
    stmt: &Stmt,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    let used = collect_stmt_idents(stmt);
    for used_name in used {
        let Some(root) = state.roots.get(&used_name).copied() else {
            continue;
        };
        if state.freed_roots.contains(&root) && !stmt_is_direct_free_of(stmt, &used_name) {
            violations.push(format!(
                "function `{}` uses value `{}` after provenance root {} was freed",
                function_name, used_name, root
            ));
        }
    }
    match stmt {
        Stmt::Let { name, value, .. } => {
            assign_provenance_value(name, value, state, next_root, signatures);
        }
        Stmt::LetPattern { pattern, value, .. } => {
            assign_pattern_provenance(pattern, value, state, next_root, signatures);
        }
        Stmt::Assign { target, value } => {
            assign_provenance_value(target, value, state, next_root, signatures);
        }
        Stmt::Expr(Expr::Call { callee, args }) => {
            analyze_provenance_call(callee, args, state, violations, function_name, signatures);
        }
        Stmt::Expr(Expr::UnsafeBlock { body, .. }) => {
            analyze_provenance_block(
                body,
                state,
                next_root,
                violations,
                function_name,
                signatures,
            );
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            let entry_state = state.clone();
            let mut then_state = state.clone();
            let mut else_state = state.clone();
            analyze_provenance_block(
                then_body,
                &mut then_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            analyze_provenance_block(
                else_body,
                &mut else_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
                function_name,
                "conditional branches",
                &entry_state,
                &[then_state, else_state],
                violations,
            );
        }
        Stmt::While { body, .. } | Stmt::Loop { body } => {
            let entry_state = state.clone();
            let mut body_state = state.clone();
            analyze_provenance_block(
                body,
                &mut body_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
                function_name,
                "loop iterations",
                &entry_state,
                &[entry_state.clone(), body_state],
                violations,
            );
        }
        Stmt::For {
            init, step, body, ..
        } => {
            if let Some(init) = init {
                analyze_provenance_stmt(
                    init,
                    state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
            }
            let entry_state = state.clone();
            let mut body_state = state.clone();
            analyze_provenance_block(
                body,
                &mut body_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            if let Some(step) = step {
                analyze_provenance_stmt(
                    step,
                    &mut body_state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
            }
            *state = merge_provenance_states(
                function_name,
                "loop iterations",
                &entry_state,
                &[entry_state.clone(), body_state],
                violations,
            );
        }
        Stmt::ForIn { body, .. } => {
            let entry_state = state.clone();
            let mut body_state = state.clone();
            analyze_provenance_block(
                body,
                &mut body_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
                function_name,
                "loop iterations",
                &entry_state,
                &[entry_state.clone(), body_state],
                violations,
            );
        }
        Stmt::Match { arms, .. } => {
            let entry_state = state.clone();
            let mut arm_states = Vec::new();
            for arm in arms {
                let mut arm_state = state.clone();
                analyze_provenance_expr(
                    &arm.value,
                    &mut arm_state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
                arm_states.push(arm_state);
            }
            if !arm_states.is_empty() {
                *state = merge_provenance_states(
                    function_name,
                    "match arms",
                    &entry_state,
                    &arm_states,
                    violations,
                );
            }
        }
        Stmt::Expr(expr) => {
            analyze_provenance_expr(
                expr,
                state,
                next_root,
                violations,
                function_name,
                signatures,
            );
        }
        Stmt::CompoundAssign { .. }
        | Stmt::Return(_)
        | Stmt::Defer(_)
        | Stmt::Requires(_)
        | Stmt::Ensures(_)
        | Stmt::Break(_)
        | Stmt::Continue => {}
    }
}

fn assign_provenance_value(
    target: &str,
    value: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    signatures: &BTreeMap<String, CallShape>,
) {
    match infer_expr_provenance_source(value, state, signatures) {
        ExprProvenanceSource::Existing(root) => {
            state.roots.insert(target.to_string(), root);
        }
        ExprProvenanceSource::Fresh => {
            state.roots.insert(target.to_string(), *next_root);
            *next_root += 1;
        }
        ExprProvenanceSource::Unknown => {
            state.roots.remove(target);
        }
    }
}

fn assign_pattern_provenance(
    pattern: &ast::Pattern,
    value: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    signatures: &BTreeMap<String, CallShape>,
) {
    match pattern {
        ast::Pattern::Ident(name) => {
            assign_provenance_value(name, value, state, next_root, signatures);
        }
        ast::Pattern::Tuple(items) => {
            if let Expr::Tuple(values) = value {
                if items.len() == values.len() {
                    for (item, value) in items.iter().zip(values.iter()) {
                        assign_pattern_provenance(item, value, state, next_root, signatures);
                    }
                    return;
                }
            }
            let source = infer_expr_provenance_source(value, state, signatures);
            for item in items {
                assign_pattern_binding_from_source(item, source, state, next_root);
            }
        }
        ast::Pattern::Struct { fields, .. } => {
            if let Expr::StructInit {
                fields: value_fields,
                ..
            } = value
            {
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some((_, field_value)) = value_fields
                        .iter()
                        .find(|(candidate, _)| candidate == field_name)
                    {
                        assign_provenance_value(
                            binding_name,
                            field_value,
                            state,
                            next_root,
                            signatures,
                        );
                    } else {
                        state.roots.remove(binding_name);
                    }
                }
                return;
            }
            let source = infer_expr_provenance_source(value, state, signatures);
            for (_, binding_name) in fields {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => {
            if let Expr::EnumInit {
                payload,
                named_payload,
                ..
            } = value
            {
                if bindings.len() == payload.len() {
                    for (binding, value) in bindings.iter().zip(payload.iter()) {
                        assign_name_from_expr(binding, value, state, next_root, signatures);
                    }
                } else {
                    let source = infer_expr_provenance_source(value, state, signatures);
                    for binding in bindings {
                        assign_name_from_source(binding, source, state, next_root);
                    }
                }
                for (field_name, binding_name) in named_bindings {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some((_, field_value)) = named_payload
                        .iter()
                        .find(|(candidate, _)| candidate == field_name)
                    {
                        assign_provenance_value(
                            binding_name,
                            field_value,
                            state,
                            next_root,
                            signatures,
                        );
                    } else {
                        state.roots.remove(binding_name);
                    }
                }
                return;
            }
            let source = infer_expr_provenance_source(value, state, signatures);
            for binding in bindings {
                assign_name_from_source(binding, source, state, next_root);
            }
            for (_, binding_name) in named_bindings {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            for pattern in patterns {
                assign_pattern_provenance(pattern, value, state, next_root, signatures);
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => {}
    }
}

fn assign_pattern_binding_from_source(
    pattern: &ast::Pattern,
    source: ExprProvenanceSource,
    state: &mut ProvenanceState,
    next_root: &mut usize,
) {
    match pattern {
        ast::Pattern::Ident(name) => assign_name_from_source(name, source, state, next_root),
        ast::Pattern::Tuple(items) => {
            for item in items {
                assign_pattern_binding_from_source(item, source, state, next_root);
            }
        }
        ast::Pattern::Struct { fields, .. } => {
            for (_, binding_name) in fields {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => {
            for binding in bindings {
                assign_name_from_source(binding, source, state, next_root);
            }
            for (_, binding_name) in named_bindings {
                if binding_name != "_" {
                    assign_name_from_source(binding_name, source, state, next_root);
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            for pattern in patterns {
                assign_pattern_binding_from_source(pattern, source, state, next_root);
            }
        }
        ast::Pattern::Wildcard | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => {}
    }
}

fn assign_name_from_expr(
    name: &str,
    value: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    signatures: &BTreeMap<String, CallShape>,
) {
    if name != "_" {
        assign_provenance_value(name, value, state, next_root, signatures);
    }
}

fn assign_name_from_source(
    name: &str,
    source: ExprProvenanceSource,
    state: &mut ProvenanceState,
    next_root: &mut usize,
) {
    if name == "_" {
        return;
    }
    match source {
        ExprProvenanceSource::Existing(root) => {
            state.roots.insert(name.to_string(), root);
        }
        ExprProvenanceSource::Fresh => {
            state.roots.insert(name.to_string(), *next_root);
            *next_root += 1;
        }
        ExprProvenanceSource::Unknown => {
            state.roots.remove(name);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExprProvenanceSource {
    Existing(usize),
    Fresh,
    Unknown,
}

fn infer_expr_provenance_source(
    expr: &Expr,
    state: &ProvenanceState,
    signatures: &BTreeMap<String, CallShape>,
) -> ExprProvenanceSource {
    match expr {
        Expr::Ident(from) => state
            .roots
            .get(from)
            .copied()
            .map(ExprProvenanceSource::Existing)
            .unwrap_or(ExprProvenanceSource::Unknown),
        expr if is_alloc_expr(expr) => ExprProvenanceSource::Fresh,
        Expr::FieldAccess { base, .. } | Expr::Group(base) => {
            infer_expr_provenance_source(base, state, signatures)
        }
        Expr::Call { callee, args } => signatures
            .get(callee)
            .and_then(|shape| {
                if matches!(shape.return_type, Type::Ref { .. } | Type::Ptr { .. }) {
                    Some(match shape.return_provenance {
                        ReturnProvenanceSummary::Param(index) => args
                            .get(index)
                            .map(|arg| infer_expr_provenance_source(arg, state, signatures))
                            .unwrap_or(ExprProvenanceSource::Unknown),
                        ReturnProvenanceSummary::Fresh => ExprProvenanceSource::Fresh,
                        ReturnProvenanceSummary::Unknown => ExprProvenanceSource::Unknown,
                    })
                } else {
                    None
                }
            })
            .unwrap_or(ExprProvenanceSource::Unknown),
        _ => ExprProvenanceSource::Unknown,
    }
}

fn populate_return_provenance_summaries(
    functions: &[TypedFunction],
    signatures: &mut BTreeMap<String, CallShape>,
) {
    for _ in 0..functions.len().max(1) {
        let mut changed = false;
        for function in functions {
            let summary = infer_function_return_provenance(function, signatures);
            if let Some(shape) = signatures.get_mut(&function.name) {
                if shape.return_provenance != summary {
                    shape.return_provenance = summary;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn infer_function_return_provenance(
    function: &TypedFunction,
    signatures: &BTreeMap<String, CallShape>,
) -> ReturnProvenanceSummary {
    if !matches!(function.return_type, Type::Ref { .. } | Type::Ptr { .. }) {
        return ReturnProvenanceSummary::Unknown;
    }
    let param_indexes = function
        .params
        .iter()
        .enumerate()
        .map(|(index, param)| (param.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let mut summaries = Vec::new();
    collect_return_provenance_from_stmts(
        &function.body,
        &param_indexes,
        signatures,
        &mut summaries,
    );
    if summaries.is_empty() {
        ReturnProvenanceSummary::Unknown
    } else if summaries.windows(2).all(|window| window[0] == window[1]) {
        summaries[0]
    } else {
        ReturnProvenanceSummary::Unknown
    }
}

fn collect_return_provenance_from_stmts(
    body: &[Stmt],
    param_indexes: &BTreeMap<&str, usize>,
    signatures: &BTreeMap<String, CallShape>,
    out: &mut Vec<ReturnProvenanceSummary>,
) {
    for stmt in body {
        match stmt {
            Stmt::Return(Some(expr)) => {
                out.push(infer_return_expr_provenance(
                    expr,
                    param_indexes,
                    signatures,
                ));
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_return_provenance_from_stmts(then_body, param_indexes, signatures, out);
                collect_return_provenance_from_stmts(else_body, param_indexes, signatures, out);
            }
            Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::ForIn { body, .. } => {
                collect_return_provenance_from_stmts(body, param_indexes, signatures, out);
            }
            Stmt::For {
                init, step, body, ..
            } => {
                if let Some(init) = init {
                    collect_return_provenance_from_stmts(
                        std::slice::from_ref(init.as_ref()),
                        param_indexes,
                        signatures,
                        out,
                    );
                }
                collect_return_provenance_from_stmts(body, param_indexes, signatures, out);
                if let Some(step) = step {
                    collect_return_provenance_from_stmts(
                        std::slice::from_ref(step.as_ref()),
                        param_indexes,
                        signatures,
                        out,
                    );
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    collect_return_provenance_from_expr(&arm.value, param_indexes, signatures, out);
                }
            }
            Stmt::Expr(expr)
            | Stmt::Defer(expr)
            | Stmt::Requires(expr)
            | Stmt::Ensures(expr)
            | Stmt::Let { value: expr, .. }
            | Stmt::LetPattern { value: expr, .. }
            | Stmt::Assign { value: expr, .. }
            | Stmt::CompoundAssign { value: expr, .. } => {
                collect_return_provenance_from_expr(expr, param_indexes, signatures, out);
            }
            Stmt::Return(None) | Stmt::Break(_) | Stmt::Continue => {}
        }
    }
}

fn collect_return_provenance_from_expr(
    expr: &Expr,
    param_indexes: &BTreeMap<&str, usize>,
    signatures: &BTreeMap<String, CallShape>,
    out: &mut Vec<ReturnProvenanceSummary>,
) {
    match expr {
        Expr::Return(Some(value)) => {
            out.push(infer_return_expr_provenance(
                value,
                param_indexes,
                signatures,
            ));
        }
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            collect_return_provenance_from_expr(then_expr, param_indexes, signatures, out);
            collect_return_provenance_from_expr(else_expr, param_indexes, signatures, out);
        }
        Expr::Match { arms, .. } => {
            for arm in arms {
                collect_return_provenance_from_expr(&arm.value, param_indexes, signatures, out);
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            collect_return_provenance_from_stmts(body, param_indexes, signatures, out);
        }
        _ => {}
    }
}

fn infer_return_expr_provenance(
    expr: &Expr,
    param_indexes: &BTreeMap<&str, usize>,
    signatures: &BTreeMap<String, CallShape>,
) -> ReturnProvenanceSummary {
    match expr {
        Expr::Ident(name) => param_indexes
            .get(name.as_str())
            .copied()
            .map(ReturnProvenanceSummary::Param)
            .unwrap_or(ReturnProvenanceSummary::Unknown),
        expr if is_alloc_expr(expr) => ReturnProvenanceSummary::Fresh,
        Expr::FieldAccess { base, .. } | Expr::Group(base) => {
            infer_return_expr_provenance(base, param_indexes, signatures)
        }
        Expr::Call { callee, args } => match signatures
            .get(callee)
            .map(|shape| shape.return_provenance)
            .unwrap_or(ReturnProvenanceSummary::Unknown)
        {
            ReturnProvenanceSummary::Param(index) => args
                .get(index)
                .map(|arg| infer_return_expr_provenance(arg, param_indexes, signatures))
                .unwrap_or(ReturnProvenanceSummary::Unknown),
            summary => summary,
        },
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let then_summary = infer_return_expr_provenance(then_expr, param_indexes, signatures);
            let else_summary = infer_return_expr_provenance(else_expr, param_indexes, signatures);
            if then_summary == else_summary {
                then_summary
            } else {
                ReturnProvenanceSummary::Unknown
            }
        }
        Expr::Match { arms, .. } => {
            let summaries = arms
                .iter()
                .map(|arm| infer_return_expr_provenance(&arm.value, param_indexes, signatures))
                .collect::<Vec<_>>();
            if summaries.is_empty() {
                ReturnProvenanceSummary::Unknown
            } else if summaries.windows(2).all(|window| window[0] == window[1]) {
                summaries[0]
            } else {
                ReturnProvenanceSummary::Unknown
            }
        }
        Expr::UnsafeBlock { body, .. } => {
            let mut summaries = Vec::new();
            collect_return_provenance_from_stmts(body, param_indexes, signatures, &mut summaries);
            if summaries.is_empty() {
                ReturnProvenanceSummary::Unknown
            } else if summaries.windows(2).all(|window| window[0] == window[1]) {
                summaries[0]
            } else {
                ReturnProvenanceSummary::Unknown
            }
        }
        _ => ReturnProvenanceSummary::Unknown,
    }
}

fn analyze_provenance_call(
    callee: &str,
    args: &[Expr],
    state: &mut ProvenanceState,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    if is_free_callee(callee) {
        if let Some(arg) = args.first() {
            if let Some(root) = expr_provenance_root(arg, state, signatures) {
                if !state.freed_roots.insert(root) {
                    violations.push(format!(
                        "function `{}` double-frees provenance root {} via `{}`",
                        function_name,
                        root,
                        provenance_expr_label(arg)
                    ));
                }
            }
        }
    }
    if let Some(shape) = signatures.get(callee) {
        let mut mut_ref_aliases = BTreeMap::<String, (String, usize)>::new();
        let mut shared_ref_aliases = BTreeMap::<String, String>::new();
        for (index, param) in shape.params.iter().enumerate() {
            let Some(arg) = args.get(index) else {
                continue;
            };
            let label = provenance_expr_label(arg);
            let key = provenance_expr_alias_key(arg, state, signatures);
            match &param.ty {
                Type::Ref { mutable: true, .. } => {
                    let entry = mut_ref_aliases.entry(key).or_insert((label, 0));
                    entry.1 += 1;
                }
                Type::Ref { mutable: false, .. } => {
                    shared_ref_aliases.entry(key).or_insert(label);
                }
                _ => {}
            }
        }
        for (key, (name, count)) in &mut_ref_aliases {
            if *count > 1 {
                let detail = if let Some(root) = key.strip_prefix("root:") {
                    format!(
                        "function `{}` call `{}` aliases mutable reference parameter `{}` {} times (provenance root {})",
                        function_name, callee, name, count, root
                    )
                } else {
                    format!(
                        "function `{}` call `{}` aliases mutable reference parameter `{}` {} times",
                        function_name, callee, name, count
                    )
                };
                violations.push(detail);
            }
            if shared_ref_aliases.contains_key(key) {
                violations.push(format!(
                    "function `{}` call `{}` aliases mutable and shared borrows for `{}`",
                    function_name, callee, name
                ));
            }
        }
        if shape.is_extern && shape.is_unsafe {
            for (index, param) in shape.params.iter().enumerate() {
                let Some(arg) = args.get(index) else {
                    continue;
                };
                if param.name.ends_with("_owned") {
                    if let Some(root) = expr_provenance_root(arg, state, signatures) {
                        state.freed_roots.insert(root);
                    }
                }
            }
        }
    }
}

fn expr_provenance_root(
    expr: &Expr,
    state: &ProvenanceState,
    signatures: &BTreeMap<String, CallShape>,
) -> Option<usize> {
    match infer_expr_provenance_source(expr, state, signatures) {
        ExprProvenanceSource::Existing(root) => Some(root),
        ExprProvenanceSource::Fresh | ExprProvenanceSource::Unknown => None,
    }
}

fn provenance_expr_alias_key(
    expr: &Expr,
    state: &ProvenanceState,
    signatures: &BTreeMap<String, CallShape>,
) -> String {
    expr_provenance_root(expr, state, signatures)
        .map(|root| format!("root:{root}"))
        .unwrap_or_else(|| format!("label:{}", provenance_expr_label(expr)))
}

fn provenance_expr_label(expr: &Expr) -> String {
    match expr {
        Expr::Ident(name) => name.clone(),
        Expr::Group(inner) => provenance_expr_label(inner),
        Expr::FieldAccess { base, field } => format!("{}.{}", provenance_expr_label(base), field),
        Expr::Index { base, .. } => format!("{}[..]", provenance_expr_label(base)),
        _ => "<expr>".to_string(),
    }
}

fn analyze_provenance_expr(
    expr: &Expr,
    state: &mut ProvenanceState,
    next_root: &mut usize,
    violations: &mut Vec<String>,
    function_name: &str,
    signatures: &BTreeMap<String, CallShape>,
) {
    match expr {
        Expr::UnsafeBlock { body, .. } => {
            analyze_provenance_block(
                body,
                state,
                next_root,
                violations,
                function_name,
                signatures,
            );
        }
        Expr::If {
            then_expr,
            else_expr,
            ..
        } => {
            let entry_state = state.clone();
            let mut then_state = state.clone();
            let mut else_state = state.clone();
            analyze_provenance_expr(
                then_expr,
                &mut then_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            analyze_provenance_expr(
                else_expr,
                &mut else_state,
                next_root,
                violations,
                function_name,
                signatures,
            );
            *state = merge_provenance_states(
                function_name,
                "conditional expressions",
                &entry_state,
                &[then_state, else_state],
                violations,
            );
        }
        Expr::Match { arms, .. } => {
            let entry_state = state.clone();
            let mut arm_states = Vec::new();
            for arm in arms {
                let mut arm_state = state.clone();
                analyze_provenance_expr(
                    &arm.value,
                    &mut arm_state,
                    next_root,
                    violations,
                    function_name,
                    signatures,
                );
                arm_states.push(arm_state);
            }
            if !arm_states.is_empty() {
                *state = merge_provenance_states(
                    function_name,
                    "match expressions",
                    &entry_state,
                    &arm_states,
                    violations,
                );
            }
        }
        _ => {}
    }
}

fn merge_provenance_states(
    function_name: &str,
    control_kind: &str,
    entry_state: &ProvenanceState,
    branches: &[ProvenanceState],
    violations: &mut Vec<String>,
) -> ProvenanceState {
    let mut merged = ProvenanceState::default();
    merged
        .freed_roots
        .extend(entry_state.freed_roots.iter().copied());
    let mut names = BTreeSet::<String>::new();
    names.extend(entry_state.roots.keys().cloned());
    for branch in branches {
        merged
            .freed_roots
            .extend(branch.freed_roots.iter().copied());
        names.extend(branch.roots.keys().cloned());
    }
    for name in names {
        let root_views = branches
            .iter()
            .map(|branch| branch.roots.get(&name).copied())
            .collect::<Vec<_>>();
        let root_diverges = root_views.windows(2).any(|window| window[0] != window[1]);
        if root_diverges {
            violations.push(format!(
                "function `{}` has divergent provenance state for `{}` across {}; rewrite control flow so provenance is consistent on every path",
                function_name, name, control_kind
            ));
            continue;
        }
        if let Some(Some(root)) = root_views.first() {
            merged.roots.insert(name, *root);
        }
    }
    merged
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
        Stmt::Break(_) | Stmt::Continue => {}
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
        Expr::Tuple(items) => {
            for item in items {
                collect_expr_idents(item, out);
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
        Expr::Group(inner) | Expr::Await(inner) | Expr::Discard(inner) => {
            collect_expr_idents(inner, out)
        }
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_expr_idents(try_expr, out);
            collect_expr_idents(catch_expr, out);
        }
        Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_expr_idents(condition, out);
            collect_expr_idents(then_expr, out);
            collect_expr_idents(else_expr, out);
        }
        Expr::Match { scrutinee, arms } => {
            collect_expr_idents(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_expr_idents(guard, out);
                }
                collect_expr_idents(&arm.value, out);
            }
        }
        Expr::While { condition, body } => {
            collect_expr_idents(condition, out);
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                out.extend(collect_stmt_idents(init));
            }
            if let Some(condition) = condition {
                collect_expr_idents(condition, out);
            }
            if let Some(step) = step {
                out.extend(collect_stmt_idents(step));
            }
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            collect_expr_idents(iterable, out);
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::Loop { body } => {
            for stmt in body {
                out.extend(collect_stmt_idents(stmt));
            }
        }
        Expr::Return(value) | Expr::Break(value) => {
            if let Some(value) = value {
                collect_expr_idents(value, out);
            }
        }
        Expr::Continue => {}
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
        Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_expr_idents(value, out);
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
                            "rng" | "random" | "std.rand" | "crypto" => {
                                self.caps.insert("rng".to_string());
                            }
                            "fs" | "file" | "std.io" => {
                                self.caps.insert("fs".to_string());
                            }
                            "storage" => {
                                self.caps.insert("storage".to_string());
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
                            "log" | "logger" | "std.log" => {
                                self.caps.insert("log".to_string());
                            }
                            "error" | "err" | "std.error" => {
                                self.caps.insert("error".to_string());
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
            ast::Item::TypeAlias(item) => {
                collect_type_instantiation(&item.ty, &mut out);
            }
            ast::Item::NewType(item) => {
                collect_type_instantiation(&item.inner, &mut out);
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
                for assoc in &item.associated_consts {
                    collect_type_instantiation(&assoc.ty, &mut out);
                }
                for method in &item.methods {
                    collect_type_instantiation(&method.return_type, &mut out);
                    for param in &method.params {
                        collect_type_instantiation(&param.ty, &mut out);
                    }
                }
            }
            ast::Item::Impl(item) => {
                collect_type_instantiation(&item.for_type, &mut out);
                for (_, ty) in &item.associated_types {
                    collect_type_instantiation(ty, &mut out);
                }
                for assoc in &item.associated_consts {
                    collect_type_instantiation(&assoc.ty, &mut out);
                }
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
        Type::Map { key, value } => {
            out.push(format!("Map<{key}, {value}>"));
            collect_type_instantiation(key, out);
            collect_type_instantiation(value, out);
        }
        Type::Set(inner) => {
            out.push(format!("Set<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Deque(inner) => {
            out.push(format!("Deque<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Ring(inner) => {
            out.push(format!("Ring<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::Future(inner) => {
            out.push(format!("Future<{inner}>"));
            collect_type_instantiation(inner, out);
        }
        Type::DynTrait(name) => out.push(format!("dyn {name}")),
        Type::Tuple(items) => {
            out.push(format!(
                "({})",
                items
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            for item in items {
                collect_type_instantiation(item, out);
            }
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
        Type::Never
        | Type::Void
        | Type::Bool
        | Type::ISize
        | Type::USize
        | Type::Int { .. }
        | Type::BigInt
        | Type::BigUint
        | Type::Float { .. }
        | Type::Decimal128
        | Type::Char
        | Type::Str
        | Type::Bytes
        | Type::Uuid
        | Type::Named { .. }
        | Type::TypeVar(_) => {}
        Type::Path
        | Type::PathBuf
        | Type::Url
        | Type::SocketAddr
        | Type::Duration
        | Type::Instant
        | Type::Decimal
        | Type::DateTimeTz
        | Type::ExitStatus
        | Type::SimdVector(_)
        | Type::SimdMask(_) => {}
    }
}

fn collect_semantic_hints(
    functions: &[TypedFunction],
) -> (Vec<String>, Vec<String>, usize, usize, usize) {
    let mut linear_resources = BTreeSet::new();
    let mut deferred_resources = BTreeSet::new();
    let mut matches_without_wildcard = 0usize;
    let mut match_unreachable_arms = 0usize;
    let mut match_duplicate_catchall_arms = 0usize;

    for function in functions {
        struct Collector<'a> {
            function: &'a TypedFunction,
            linear_resources: &'a mut BTreeSet<String>,
            deferred_resources: &'a mut BTreeSet<String>,
            matches_without_wildcard: &'a mut usize,
            match_unreachable_arms: &'a mut usize,
            match_duplicate_catchall_arms: &'a mut usize,
        }
        impl AstVisitor for Collector<'_> {
            fn visit_stmt(&mut self, stmt: &Stmt) {
                if let Stmt::Let {
                    name, ty, value, ..
                } = stmt
                {
                    if let Some(resource_ty) =
                        binding_resource_type(self.function, name, ty.as_ref(), value)
                    {
                        if is_linear_type(resource_ty) {
                            self.linear_resources.insert(name.clone());
                        }
                    }
                }
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, self.deferred_resources);
                }
                if let Stmt::Match { arms, .. } = stmt {
                    if !arms
                        .iter()
                        .any(|arm| pattern_is_catchall(&arm.pattern) && arm.guard.is_none())
                    {
                        *self.matches_without_wildcard += 1;
                    }
                    let mut seen_catchall = false;
                    for arm in arms {
                        let is_catchall = pattern_is_catchall(&arm.pattern) && arm.guard.is_none();
                        if seen_catchall {
                            *self.match_unreachable_arms += 1;
                            if is_catchall {
                                *self.match_duplicate_catchall_arms += 1;
                            }
                        } else if is_catchall {
                            seen_catchall = true;
                        }
                    }
                }
                ast::walk_stmt(self, stmt);
            }
        }
        let mut collector = Collector {
            function,
            linear_resources: &mut linear_resources,
            deferred_resources: &mut deferred_resources,
            matches_without_wildcard: &mut matches_without_wildcard,
            match_unreachable_arms: &mut match_unreachable_arms,
            match_duplicate_catchall_arms: &mut match_duplicate_catchall_arms,
        };
        for statement in &function.body {
            collector.visit_stmt(statement);
        }
    }

    (
        linear_resources.into_iter().collect(),
        deferred_resources.into_iter().collect(),
        matches_without_wildcard,
        match_unreachable_arms,
        match_duplicate_catchall_arms,
    )
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
        Stmt::Break(_) | Stmt::Continue => {}
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
        Expr::Tuple(items) => {
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
        Expr::Closure { body, .. } => collect_unsafe_contract_sites_from_expr(
            body,
            function_name,
            in_unsafe_context,
            in_async_context,
            owner,
            unsafe_functions,
            out,
        ),
        Expr::Group(inner)
        | Expr::Await(inner)
        | Expr::Discard(inner)
        | Expr::Unary { expr: inner, .. } => collect_unsafe_contract_sites_from_expr(
            inner,
            function_name,
            in_unsafe_context,
            in_async_context,
            owner,
            unsafe_functions,
            out,
        ),
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
        Expr::If {
            condition,
            then_expr,
            else_expr,
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
            collect_unsafe_contract_sites_from_expr(
                then_expr,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            collect_unsafe_contract_sites_from_expr(
                else_expr,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
        }
        Expr::Match { scrutinee, arms } => {
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
        Expr::While { condition, body } => {
            collect_unsafe_contract_sites_from_expr(
                condition,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::For {
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
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::ForIn { iterable, body, .. } => {
            collect_unsafe_contract_sites_from_expr(
                iterable,
                function_name,
                in_unsafe_context,
                in_async_context,
                owner,
                unsafe_functions,
                out,
            );
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Loop { body } => {
            for stmt in body {
                collect_unsafe_contract_sites_from_stmt(
                    stmt,
                    function_name,
                    in_unsafe_context,
                    in_async_context,
                    owner,
                    unsafe_functions,
                    out,
                );
            }
        }
        Expr::Return(value) | Expr::Break(value) => {
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
        Expr::Continue => {}
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
        Expr::ObjectLiteral(fields) => {
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

fn collect_cleanup_targets(expr: &ast::Expr, out: &mut BTreeSet<String>) {
    match expr {
        ast::Expr::Call { callee, args } if is_free_callee(callee) || is_close_callee(callee) => {
            if let Some(ast::Expr::Ident(name)) = args.first() {
                out.insert(name.clone());
            }
            for arg in args {
                collect_cleanup_targets(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_cleanup_targets(try_expr, out);
            collect_cleanup_targets(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_cleanup_targets(condition, out);
            collect_cleanup_targets(then_expr, out);
            collect_cleanup_targets(else_expr, out);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_cleanup_targets(scrutinee, out);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_cleanup_targets(guard, out);
                }
                collect_cleanup_targets(&arm.value, out);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_cleanup_targets(condition, out);
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(stmt) = init {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
            if let Some(expr) = condition {
                collect_cleanup_targets(expr, out);
            }
            if let Some(stmt) = step {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_cleanup_targets(iterable, out);
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                if let Some(expr) = stmt_expr(stmt) {
                    collect_cleanup_targets(expr, out);
                }
            }
        }
        ast::Expr::Group(inner)
        | ast::Expr::Await(inner)
        | ast::Expr::Discard(inner)
        | ast::Expr::Unary { expr: inner, .. }
        | ast::Expr::FieldAccess { base: inner, .. } => collect_cleanup_targets(inner, out),
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_cleanup_targets(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. }
        | ast::Expr::Tuple(payload)
        | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_cleanup_targets(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_cleanup_targets(body, out),
        ast::Expr::Return(value) | ast::Expr::Break(value) => {
            if let Some(expr) = value {
                collect_cleanup_targets(expr, out);
            }
        }
        ast::Expr::Binary { left, right, .. }
        | ast::Expr::Range {
            start: left,
            end: right,
            ..
        } => {
            collect_cleanup_targets(left, out);
            collect_cleanup_targets(right, out);
        }
        ast::Expr::Index { base, index } => {
            collect_cleanup_targets(base, out);
            collect_cleanup_targets(index, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_)
        | ast::Expr::Continue
        | ast::Expr::Call { .. } => {}
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
    current_namespace: &'a str,
    fn_sigs: &'a HashMap<String, (Vec<Type>, Type)>,
    fn_async: &'a HashMap<String, bool>,
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
        Stmt::Defer(expr) | Stmt::Requires(expr) | Stmt::Ensures(expr) | Stmt::Expr(expr) => {
            let _ = infer_expr_type(expr, scopes, env, state);
        }
    }
}

fn pattern_covers_variant(
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

fn check_match_exhaustiveness(
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

fn infer_expr_type(
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
            let generics = fn_generics.get(base_callee).cloned().unwrap_or_default();
            if !generics.is_empty() && explicit_types.is_none() {
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
                let resolved_ret = if is_function_async && !matches!(resolved_ret, Type::Future(_))
                {
                    Type::Future(Box::new(resolved_ret))
                } else {
                    resolved_ret
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

fn split_top_level_type_args(input: &str) -> Option<Vec<&str>> {
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

fn parse_simple_type(token: &str) -> Option<Type> {
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

type CallSignature = (Vec<Type>, Type, Vec<(String, Type)>);
const MAX_MONOMORPHIZATION_DEPTH: usize = 32;
const MAX_MONOMORPHIZED_SPECIALIZATIONS: usize = 2048;

fn monomorphized_symbol(base: &str, args: &[Type]) -> String {
    let rendered = args
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{base}<{rendered}>")
}

fn monomorphize_typed_functions(
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
        "alloc",
        "free",
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
        "simd.__i32x4",
        "simd.__u32x4",
        "simd.__f32x4",
        "simd.__mask32x4",
        "simd.__i32x4_splat",
        "simd.__i32x4_load",
        "simd.__u32x4_splat",
        "simd.__u32x4_load",
        "simd.__f32x4_splat",
        "simd.__f32x4_load",
        "simd.__mask32x4_splat",
        "simd.__mask32x4_load",
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
        "fs.write",
        "fs.flush",
        "fs.atomic_write",
        "fs.rename_atomic",
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
        "env" | "str" | "json" | "list" | "map" | "route" => Some(format!(
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
    let kv_handle = Type::Named {
        name: "KvStoreHandle".to_string(),
        args: Vec::new(),
    };
    let channel_handle = Type::Named {
        name: "ChannelHandle".to_string(),
        args: Vec::new(),
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
        "spawn_ctx" => (vec![task_fn.clone(), i32.clone()], task_handle.clone()),
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
        "alloc" => (vec![usize_ty], ptr_u8.clone()),
        "free" => (vec![ptr_u8], Type::Void),
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
        "crypto.sha256" | "crypto.base64_encode" | "crypto.base64_decode" => {
            (vec![str_ty.clone()], str_ty.clone())
        }
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
        "simd.__u32x4_splat" => (vec![i32.clone()], u32x4.clone()),
        "simd.__u32x4_load" => (
            vec![Type::Array {
                elem: Box::new(u32_ty.clone()),
                len: 4,
            }],
            u32x4.clone(),
        ),
        "simd.__f32x4_splat" => (vec![Type::Float { bits: 64 }], f32x4.clone()),
        "simd.__f32x4_load" => (
            vec![Type::Array {
                elem: Box::new(f32_ty.clone()),
                len: 4,
            }],
            f32x4.clone(),
        ),
        "simd.__mask32x4_splat" => (vec![i32.clone()], mask32x4.clone()),
        "simd.__mask32x4_load" => (
            vec![Type::Array {
                elem: Box::new(bool_ty.clone()),
                len: 4,
            }],
            mask32x4.clone(),
        ),
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
        "fs.open" | "fs.write" | "fs.flush" | "fs.atomic_write" | "fs.rename_atomic"
        | "fs.fsync" | "fs.lock" | "fs.read" => (vec![], i32.clone()),
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
        matches!(
            name,
            "TaskHandle"
                | "TaskGroupHandle"
                | "HttpHandle"
                | "HttpStreamHandle"
                | "WebSocketHandle"
                | "JsonHandle"
                | "ListHandle"
                | "MapHandle"
                | "ProcessHandle"
                | "ProcessArgv"
                | "ProcessEnv"
                | "KvStoreHandle"
                | "ChannelHandle"
        )
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
        Type::Named { name, args } if args.is_empty() && is_runtime_handle(name) => {
            Some(Value::I32(0))
        }
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

fn is_integer_type(ty: &Type) -> bool {
    matches!(ty, Type::ISize | Type::USize | Type::Int { .. })
}

fn is_float_type(ty: &Type) -> bool {
    matches!(ty, Type::Float { .. })
}

fn is_bool_or_integer(ty: Option<&Type>) -> bool {
    matches!(ty, Some(Type::Bool | Type::Never)) || ty.is_some_and(is_integer_type)
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{lower, split_generic_callee};

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
        let module = parser::parse(&source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.trait_violations.is_empty());
        assert!(
            typed
                .generic_specializations
                .iter()
                .any(|entry| entry.starts_with("id<"))
        );
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
        let module = parser::parse(&source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(!typed.trait_violations.is_empty());
    }

    #[test]
    fn parses_nested_generic_specializations() {
        let (base, explicit) = split_generic_callee("id<Option<Result<i32, i32>>>");
        assert_eq!(base, "id");
        let explicit = explicit.expect("explicit generic args");
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit[0].to_string(), "Option<Result<i32, i32>>");
    }

    #[test]
    fn lowers_impl_methods_as_callable_symbols() {
        let source = r#"
            trait Render { fn render(v: i32) -> i32; }
            struct Point { x: i32 }
            impl Render for Point {
                fn render(v: i32) -> i32 { return v + 1; }
            }
            fn main() -> i32 {
                return Point.render(4);
            }
        "#;
        let module = parser::parse(&source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(
            typed
                .typed_functions
                .iter()
                .any(|function| function.name == "Point.render")
        );
    }

    #[test]
    fn flags_trait_impl_parameter_type_mismatch() {
        let source = r#"
            trait Render { fn render(v: i32) -> i32; }
            struct Point { x: i32 }
            impl Render for Point {
                fn render(v: i64) -> i32 { return 1; }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .trait_violations
                .iter()
                .any(|detail| detail.contains("parameter 0 type mismatch"))
        );
    }

    #[test]
    fn validates_trait_associated_items_in_impls() {
        let source = r#"
            trait Cache {
                type Key;
                const VERSION: i32;
                fn get(k: i32) -> i32;
            }
            struct Store {}
            impl Cache for Store {
                type Key = i32;
                const VERSION: i32 = 1;
                fn get(k: i32) -> i32 { return k; }
            }
            impl Cache for i32 {
                fn get(k: i32) -> i32 { return k; }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .trait_violations
                .iter()
                .any(|detail| detail.contains("missing associated type `Key`"))
        );
        assert!(
            typed
                .trait_violations
                .iter()
                .any(|detail| detail.contains("missing associated const `VERSION`"))
        );
    }

    #[test]
    fn resolves_self_and_associated_types_inside_trait_impl_methods() {
        let source = r#"
            trait Cache {
                type Key;
                fn get(self: Self, key: Self::Key) -> i32;
            }
            struct Store { value: i32 }
            impl Cache for Store {
                type Key = i32;
                fn get(self: Self, key: i32) -> i32 {
                    return self.value + key;
                }
            }
            fn main() -> i32 {
                let store = Store { value: 3 };
                return Store.get(store, 4);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.trait_violations.is_empty());
    }

    #[test]
    fn allows_generic_trait_impl_targets() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            impl Show for T {
                fn show(v: i32) -> i32 { return v; }
            }
            fn id<U: Show>(v: U) -> U { return v; }
            fn main() -> i32 {
                discard id<i32>(1);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.trait_violations.is_empty());
    }

    #[test]
    fn flags_overlapping_trait_impls_as_ambiguous() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            struct Point { x: i32 }
            impl Show for Point { fn show(v: i32) -> i32 { return v; } }
            impl Show for Point { fn show(v: i32) -> i32 { return v + 1; } }
            fn id<T: Show>(v: T) -> T { return v; }
            fn main() -> i32 {
                let p = Point { x: 1 };
                discard id<Point>(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .trait_violations
                .iter()
                .any(|detail| detail.contains("overlapping impls for trait `Show`"))
        );
        assert!(
            typed
                .trait_violations
                .iter()
                .any(|detail| detail.contains("ambiguous bound `Show`"))
        );
    }

    #[test]
    fn flags_unknown_trait_bound_at_declaration_time() {
        let source = r#"
            fn id<T: Missing>(v: T) -> T { return v; }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .trait_violations
                .iter()
                .any(|detail| detail.contains("trait `Missing` is not defined"))
        );
    }

    #[test]
    fn builtin_error_trait_bound_is_available() {
        let source = r#"
            fn wrap<T: Error>(value: T) -> Result<i32, T> {
                discard value;
                return 0;
            }
        "#;
        let module = parser::parse(source, "error_trait").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .trait_violations
                .iter()
                .any(|detail| detail.contains("trait `Error` is not defined"))
        );
    }

    #[test]
    fn flags_invalid_specialization_shape() {
        let source = r#"
            fn id<T>(v: T) -> T { return v; }
            fn main() -> i32 {
                let v: i32 = 1;
                discard id<fn(i32) -> i32>(v);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_error_details.iter().any(|detail| {
            detail.contains("invalid generic specialization syntax for call `id<fn(i32) -> i32>`")
        }));
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
                proc.spawn("echo hi");
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
                proc.spawn(1);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("proc.spawn") && detail.contains("expected `str`"))
        );
    }

    #[test]
    fn process_spawn_cmd_with_typed_builders_typechecks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argv = proc.argv_new();
                proc.argv_push(argv, "hi");
                let env = proc.env_new();
                proc.env_set(env, "K", "V");
                proc.spawn_cmd("echo", argv, env, "stdin");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn process_close_typechecks_after_wait_and_observation() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                let handle = proc.spawn_cmd("echo", argv, env, "");
                discard proc.wait(handle, 1000);
                discard proc.stdout(handle);
                discard proc.stderr(handle);
                discard proc.exit_code(handle);
                discard proc.close(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn process_close_wrapper_can_consume_linear_param() {
        let source = r#"
            use core.proc;
            fn close_wrapper(handle: ProcessHandle) -> i32 {
                return proc.close(handle);
            }
            fn main() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                let handle = proc.spawn_cmd("echo", argv, env, "");
                discard close_wrapper(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn current_process_cli_intrinsics_typecheck() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argc = proc.argv_count();
                let arg0 = proc.argv_get(0);
                let line = term.read_line();
                discard term.write(arg0);
                discard term.write_err(line);
                discard term.stdin_is_tty();
                discard term.stdout_is_tty();
                return argc + term.stdin_eof();
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
                let argv = proc.argv_new();
                let env = proc.env_new();
                proc.spawnl("echo", argv, env, "stdin");
                proc.runl("echo", argv, env, "");
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
                let msg_obj = map.new();
                map.set(msg_obj, "role", json.str("user"));
                map.set(msg_obj, "content", user);
                let msg = json.object(msg_obj);
                let messages_list = list.new();
                list.push(messages_list, msg);
                let messages = json.array(messages_list);
                let payload_obj = map.new();
                map.set(payload_obj, "model", json.str("claude"));
                map.set(payload_obj, "messages", messages);
                let payload = json.object(payload_obj);
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
    fn http_streaming_and_sse_helpers_typecheck() {
        let source = r#"
            fn main() -> i32 {
                discard http.header_set("accept", "text/event-stream");
                let stream = http.request_stream("POST", "https://example.com", "{\"stream\":true}");
                let line = http.stream_read_line(stream);
                let chunk = http.stream_read(stream, 128);
                discard http.stream_status(stream);
                discard http.stream_error(stream);
                discard http.stream_close(stream);
                if str.len(line) >= 0 && str.len(chunk) >= 0 {
                    return 0;
                }
                return 1;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn extended_runtime_primitives_typecheck() {
        let source = r#"
            use core.http;
            use core.proc;
            fn main() -> i32 {
                discard str.contains("abc", "a");
                discard fs.exists("/tmp");
                discard time.monotonic_ms();
                discard proc.poll(proc.spawn("echo hi"));
                let c = http.accept();
                discard http.header(c, "content-type");
                discard route.match(c, "GET", "/sessions/:id/messages");
                let fields_map = map.new();
                map.set(fields_map, "component", "test");
                map.set(fields_map, "phase", "boot");
                let fields = log.fields(fields_map);
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
                discard bound;
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
    fn json_keys_and_bridges_accept_json_handles() {
        let source = r#"
            fn main() -> i32 {
                let parsed = json.parse("{\"message\":\"hi\",\"count\":\"2\"}")
                let keys = json.keys(parsed)
                let as_map = json.to_map(parsed)
                discard map.keys(as_map)
                return list.len(keys)
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn variadic_str_concat_typechecks() {
        let source = r#"
            fn main() -> i32 {
                let path = str.concat("svc/", "tenant/", "sessions/", "abc", "/latest")
                if str.len(path) > 0 {
                    return 0;
                }
                return 1;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn string_conversion_and_path_helpers_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let rendered = str.concat("port=", str.from_i32(8080), ", enabled=", str.from_bool(true))
                let joined = path.join("/srv/app", "config/runtime.json")
                let base = path.basename(joined)
                let dir = path.dirname(joined)
                let stem = path.stem(joined)
                let extension = path.extension(joined)
                discard rendered
                discard base
                discard dir
                discard stem
                discard extension
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn string_slice_and_ascii_case_helpers_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let first = str.slice("name", 0, 1)
                let middle = str.slice("name", 1, 3)
                let upper = str.upper_ascii("tool_arg_name")
                let lower = str.lower_ascii("TOOL_ARG_NAME")
                discard first
                discard middle
                discard upper
                discard lower
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn fs_listdir_returns_list_handle_for_list_ops() {
        let source = r#"
            use core.fs;
            fn main() -> i32 {
                let entries = fs.listdir("/tmp")
                return list.len(entries)
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn fs_metadata_and_copy_tree_intrinsics_typecheck() {
        let source = r#"
            use core.fs;
            fn main() -> i32 {
                let path = "/tmp/demo"
                let mut score = fs.exists(path)
                score += fs.is_file(path)
                score += fs.is_dir(path)
                score += fs.is_symlink(path)
                score += fs.stat_size(path)
                score += fs.stat_mtime(path)
                score += fs.copy_file("/tmp/a", "/tmp/b")
                score += fs.copy_tree("/tmp/src", "/tmp/out")
                score += fs.remove(path)
                return score % 251
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn string_addition_reports_actionable_concat_guidance() {
        let source = r#"
            fn main() -> i32 {
                let path = "svc/" + "tenant"
                if str.len(path) > 0 {
                    return 0;
                }
                return 1;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("string addition is unsupported")
                    && detail.contains("str.concat")),
            "expected string-addition guidance, got {:?}",
            typed.type_error_details
        );
    }

    #[test]
    fn fixed_arity_concat_reports_variadic_guidance() {
        let source = r#"
            fn main() -> i32 {
                let value = str.concat3("worker=", "7")
                discard value
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("str.concat(...)")),
            "expected variadic concat guidance, got {:?}",
            typed.type_error_details
        );
    }

    #[test]
    fn object_literal_json_and_log_paths_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let fields = map.new();
                map.set(fields, "component", json.str("test"));
                map.set(fields, "phase", json.str("boot"));
                discard log.info("boot", log.fields(fields));
                discard http.post_json_capture("https://example.com", json.object(fields));
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn object_literal_can_flow_directly_into_json_object_and_log_fields() {
        let source = r#"
            fn main() -> i32 {
                let payload = json.object(#{"ok": json.raw("true"), "msg": json.str("hi")});
                discard log.fields(#{"component": json.str("boot"), "phase": json.str("init")});
                if payload == "" {
                    return 1;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn removed_json_object_arity_reports_autofix_hint() {
        let source = r#"
            fn main() -> i32 {
                let payload = json.object3("a", json.str("1"), "b", json.str("2"), "c", json.str("3"));
                discard payload;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("autofix"))
        );
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
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("does not match scrutinee enum"))
        );
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
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("return type mismatch"))
        );
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
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("uses `await` but is not declared async"))
        );
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
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("assignment to immutable binding"))
        );
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
        assert!(typed.type_error_details.iter().any(|detail| {
            detail.contains("must be initialized with an integer/char/bool compile-time expression")
        }));
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
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `q` after provenance root"))
        );
    }

    #[test]
    fn distinguishes_helper_returned_pointer_provenance_by_parameter_index() {
        let source = r#"
            fn first(a: *mut u8, b: *mut u8) -> *mut u8 {
                return a;
            }
            fn second(a: *mut u8, b: *mut u8) -> *mut u8 {
                return b;
            }
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let from_first = first(a, b);
                let from_second = second(a, b);
                free(a);
                close(from_first);
                close(from_second);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `from_first` after provenance root"))
        );
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `from_second` after provenance root"))
        );
    }

    #[test]
    fn tuple_pattern_bindings_preserve_element_provenance() {
        let source = r#"
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let (left, right) = (a, b);
                free(a);
                close(left);
                close(right);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `left` after provenance root"))
        );
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `right` after provenance root"))
        );
    }

    #[test]
    fn struct_pattern_bindings_preserve_field_provenance() {
        let source = r#"
            struct Pair { left: *mut u8, right: *mut u8 }
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let Pair { left, right } = Pair { left: a, right: b };
                free(a);
                close(left);
                close(right);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `left` after provenance root"))
        );
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `right` after provenance root"))
        );
    }

    #[test]
    fn reassignment_clears_stale_provenance_root() {
        let source = r#"
            ext unsafe c fn acquire_owned() -> *u8;
            unsafe fn main() -> i32 {
                let p = alloc(32);
                let q = p;
                q = acquire_owned();
                free(p);
                close(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `q` after provenance root"))
        );
    }

    #[test]
    fn returning_second_pointer_arg_is_not_collapsed_to_first_argument_root() {
        let source = r#"
            fn passthrough(a: *mut u8, b: *mut u8) -> *mut u8 {
                return b;
            }
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let ret = passthrough(a, b);
                free(a);
                close(ret);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `ret` after provenance root"))
        );
    }

    #[test]
    fn detects_nested_use_after_free_via_control_flow() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                let q = p;
                if true {
                    free(p);
                } else {
                    return 0;
                }
                close(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("uses value `q` after provenance root"))
        );
    }

    #[test]
    fn detects_divergent_ownership_across_branches() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                if true {
                    free(p);
                } else {
                }
                close(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `p`")
                || detail.contains("uses moved value `p` after move/consume")
        }));
    }

    #[test]
    fn detects_conditional_move_before_reuse() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                if true {
                    let q = p;
                    discard q;
                }
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("conditionally consumed value `p`")
                || detail.contains("divergent ownership state for `p`")
                || detail.contains("uses moved value `p` after move/consume")
        }));
    }

    #[test]
    fn borrowed_references_are_not_collected_as_linear_resources() {
        let source = r#"
            fn borrow(v: &'a i32) -> &'a i32 {
                return v;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let r = borrow(x);
                discard r;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_resources.iter().any(|name| name == "r"));
    }

    #[test]
    fn inferred_alloc_local_is_treated_as_linear_resource() {
        let source = r#"
            fn main() -> i32 {
                let n: usize = 32;
                let p = alloc(n);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .linear_type_violations
                .iter()
                .any(|detail| detail.contains("frees non-linear value `p`"))
        );
    }

    #[test]
    fn deferred_cleanup_counts_as_real_release() {
        let source = r#"
            fn main() -> i32 {
                let n: usize = 32;
                let p = alloc(n);
                defer free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.deferred_resources.iter().any(|name| name == "p"));
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("leaks allocation") && detail.contains("`p`"))
        );
        assert!(
            !typed
                .linear_type_violations
                .iter()
                .any(|detail| detail.contains("linear value `p` was not consumed/freed"))
        );
    }

    #[test]
    fn inferred_pointer_return_without_cleanup_is_tracked() {
        let source = r#"
            ext unsafe c fn acquire_owned() -> *u8;
            unsafe fn main() -> i32 {
                let p = acquire_owned();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("leaks allocation") && detail.contains("`p`"))
        );
    }

    #[test]
    fn inferred_handle_local_without_cleanup_matches_typed_handle_failure() {
        let inferred = r#"
            fn main() -> i32 {
                let listener = http.accept();
                return 0;
            }
        "#;
        let typed_src = r#"
            fn main() -> i32 {
                let listener: HttpHandle = http.accept();
                return 0;
            }
        "#;
        let inferred_typed = lower(&parser::parse(inferred, "main").expect("parse"));
        let explicit_typed = lower(&parser::parse(typed_src, "main").expect("parse"));
        assert!(
            inferred_typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("leaks allocation") && detail.contains("`listener`"))
        );
        assert!(
            explicit_typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("leaks allocation") && detail.contains("`listener`"))
        );
        assert!(
            inferred_typed
                .linear_type_violations
                .iter()
                .any(|detail| detail.contains("linear value `listener` was not consumed/freed"))
        );
        assert!(
            explicit_typed
                .linear_type_violations
                .iter()
                .any(|detail| detail.contains("linear value `listener` was not consumed/freed"))
        );
    }

    #[test]
    fn match_arm_cleanup_updates_ownership_state() {
        let source = r#"
            fn main() -> i32 {
                let n: usize = 32;
                let p = alloc(n);
                match true {
                    true => free(p),
                    _ => 0,
                }
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `p`")
                || detail.contains("uses moved value `p` after move/consume")
                || detail.contains("consumes non-owned or already-consumed value `p`")
        }));
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
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("aliases mutable reference parameter `x`"))
        );
    }

    #[test]
    fn detects_mutable_aliasing_through_grouped_ref_argument() {
        let source = r#"
            fn touch(a: &'a mut i32, b: &'a mut i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                touch((x), x);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("aliases mutable reference parameter `x`"))
        );
    }

    #[test]
    fn grouped_owned_ffi_argument_marks_root_consumed() {
        let source = r#"
            ext unsafe c fn take_owned(p_owned: *u8) -> i32;
            unsafe fn main() -> i32 {
                let p = alloc(32);
                take_owned((p));
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("double-frees provenance root"))
        );
    }

    #[test]
    fn projected_owned_ffi_argument_marks_root_consumed() {
        let source = r#"
            struct Holder { ptr: *mut u8 }
            ext unsafe c fn take_owned(p_owned: *u8) -> i32;
            unsafe fn main() -> i32 {
                let holder: Holder = Holder { ptr: alloc(32) };
                take_owned(holder.ptr);
                free(holder.ptr);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("consumes non-owned or already-consumed value `holder`")
                || detail.contains("divergent ownership state for `holder`")
                || detail.contains("double-frees provenance root")
        }));
    }

    #[test]
    fn helper_freeing_owned_param_transfers_ownership_from_caller() {
        let source = r#"
            fn consume(p: *mut u8) -> i32 {
                free(p);
                return 0;
            }
            fn main() -> i32 {
                let p = alloc(32);
                consume(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("consumes non-owned or already-consumed value `p`")
                || detail.contains("function `main` leaks allocation")
        }));
    }

    #[test]
    fn unsafe_extern_owned_param_transfers_ownership_from_caller() {
        let source = r#"
            ext unsafe c fn take_owned(p_owned: *u8) -> i32;
            unsafe fn main() -> i32 {
                let p = alloc(32);
                take_owned(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("function `main` leaks allocation"))
        );
    }

    #[test]
    fn grouped_return_transfers_ownership_without_local_defer() {
        let source = r#"
            fn produce() -> *mut u8 {
                let p = alloc(32);
                return (p);
            }
            fn main() -> i32 {
                let p = produce();
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("function `produce` leaks allocation"))
        );
    }

    #[test]
    fn return_of_consuming_helper_call_does_not_require_local_defer() {
        let source = r#"
            fn consume(p: *mut u8) -> i32 {
                free(p);
                return 0;
            }
            fn main() -> i32 {
                let p = alloc(32);
                return consume(p);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `main` leaks allocation")
                || detail.contains("consumes non-owned or already-consumed value `p`")
        }));
    }

    #[test]
    fn tuple_pattern_partial_move_is_rejected() {
        let source = r#"
            fn main() -> i32 {
                let pair: (*mut u8, *mut u8) = (alloc(32), alloc(32));
                let (left, _) = pair;
                close(left);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| { detail.contains("performs partial move from owned aggregate") })
        );
    }

    #[test]
    fn nested_struct_field_partial_move_is_rejected() {
        let source = r#"
            struct Inner { ptr: *mut u8 }
            struct Outer { inner: Inner, tag: i32 }
            fn main() -> i32 {
                let outer: Outer = Outer { inner: Inner { ptr: alloc(32) }, tag: 7 };
                let ptr = outer.inner.ptr;
                close(ptr);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| { detail.contains("performs partial move from owned aggregate") })
        );
    }

    #[test]
    fn struct_pattern_partial_move_is_rejected() {
        let source = r#"
            struct Pair { left: *mut u8, right: *mut u8 }
            fn main() -> i32 {
                let pair: Pair = Pair { left: alloc(32), right: alloc(32) };
                let Pair { left, right: _ } = pair;
                close(left);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| { detail.contains("performs partial move from owned aggregate") })
        );
    }

    #[test]
    fn compiler_generated_unsafe_sites_are_not_counted_as_reasoned() {
        let source = r#"
            unsafe fn main() -> i32 {
                unsafe {
                    return 0;
                }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.unsafe_sites > 0);
        assert_eq!(typed.unsafe_reasoned_sites, 0);
        assert!(
            typed
                .unsafe_contract_sites
                .iter()
                .any(|site| site.owner.as_deref() == Some("scope_root"))
        );
    }

    #[test]
    fn documented_ffi_wrapper_call_edges_do_not_require_independent_proof() {
        let source = r#"
            ext unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;

            fn abi_touch(s: str) -> i32 {
                unsafe {
                    return host_touch(s, str.len(s));
                }
            }

            fn safe_touch(s: str) -> i32 {
                return abi_touch(s);
            }

            fn main() -> i32 {
                return safe_touch("ok");
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.unsafe_sites > 0);
        assert_eq!(typed.unsafe_reasoned_sites, 0);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("call edge `abi_touch -> host_touch` reaches unsafe code")
                || detail.contains("call edge `safe_touch -> abi_touch` reaches unsafe code")
        }));
    }

    #[test]
    fn non_consuming_helper_preserves_caller_ownership() {
        let source = r#"
            fn inspect(p: *mut u8) -> i32 {
                discard p;
                return 0;
            }
            fn main() -> i32 {
                let p = alloc(32);
                inspect(p);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("function `main` leaks allocation"))
        );
        assert!(
            !typed.ownership_violations.iter().any(|detail| {
                detail.contains("consumes non-owned or already-consumed value `p`")
            })
        );
    }

    #[test]
    fn non_consuming_linear_param_is_not_treated_as_locally_owned() {
        let source = r#"
            fn inspect(stream: HttpStreamHandle) -> i32 {
                if http.stream_eof(stream) == 1 {
                    return 1;
                }
                discard http.stream_status(stream);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `inspect` linear value `stream` was not consumed/freed")
        }));
    }

    #[test]
    fn http_write_json_marks_connection_param_consumed() {
        let source = r#"
            fn respond(conn: HttpHandle) -> i32 {
                return http.write_json(conn, 200, "{\"ok\":true}");
            }
            fn main() -> i32 {
                let conn = http.accept();
                discard respond(conn);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `respond` linear value `conn` was not consumed/freed")
        }));
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("function `main` leaks allocation")
                    && detail.contains("`conn`"))
        );
    }

    #[test]
    fn loop_local_consumed_resource_does_not_escape_iteration_merge() {
        let source = r#"
            fn main() -> i32 {
                let mut served = 0;
                while served < 2 {
                    let conn = http.accept();
                    discard http.write_json(conn, 200, "{\"ok\":true}");
                    served = served + 1;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `conn`")
                || detail.contains("uses moved value `conn` after move/consume")
        }));
    }

    #[test]
    fn continue_after_free_marks_later_iteration_reuse_invalid() {
        let source = r#"
            fn main() -> i32 {
                let i: i32 = 0;
                let p = alloc(32);
                while i < 2 {
                    if i == 0 {
                        free(p);
                        i = i + 1;
                        continue;
                    }
                    close(p);
                    i = i + 1;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("conditionally consumed value `p`")
                || detail.contains("uses moved value `p` after move/consume")
                || detail.contains("consumes non-owned or already-consumed value `p`")
        }));
    }

    #[test]
    fn break_after_free_does_not_restore_pre_loop_ownership() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                while true {
                    free(p);
                    break;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("leaks allocation") && detail.contains("`p`"))
        );
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `p`")
                || detail.contains("conditionally consumed value `p`")
        }));
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
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("atomic.load ordering `Release` is invalid"))
        );
        assert!(
            typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("atomic.fence ordering `Relaxed` is invalid"))
        );
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
    fn detects_inferred_local_reference_used_across_await() {
        let source = r#"
            fn borrow(v: &'a i32) -> &'a i32 {
                return v;
            }
            async fn worker(v: &'a i32) -> i32 {
                let alias = borrow(v);
                await recv();
                discard alias;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains(
                "cannot use borrowed local reference `alias` across await suspension points",
            )
        }));
    }

    #[test]
    fn detects_shared_reference_used_after_await_in_same_if_body() {
        let source = r#"
            async fn worker(v: &'a i32) -> i32 {
                if true {
                    await recv();
                    discard v;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("cannot use borrowed reference `v` across await suspension points")
        }));
    }

    #[test]
    fn detects_shared_reference_used_after_await_in_same_match_arm() {
        let source = r#"
            async fn worker(v: &'a i32) -> i32 {
                match await recv() {
                    0 => v,
                    _ => 0,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("cannot use borrowed reference `v` across await suspension points")
        }));
    }

    #[test]
    fn detects_shared_reference_used_after_await_in_loop_body() {
        let source = r#"
            async fn worker(v: &'a i32) -> i32 {
                while false {
                    await recv();
                    discard v;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("cannot use borrowed reference `v` across await suspension points")
        }));
    }

    #[test]
    fn routes_borrowed_return_thread_boundary_failures_out_of_capability_bucket() {
        let source = r#"
            async fn worker(v: &'a i32) -> &'a i32 {
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "returns borrowed reference across thread-capable boundary; return owned/Send-safe handle instead",
            )
        }));
        assert!(typed.capability_token_violations.is_empty());
    }

    #[test]
    fn routes_mutable_reference_thread_boundary_failures_out_of_capability_bucket() {
        let source = r#"
            async fn worker(v: &'a mut i32) -> i32 {
                discard v;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains("parameter `v` requires Send/Sync-safe wrapper before thread crossing")
        }));
        assert!(typed.capability_token_violations.is_empty());
    }

    #[test]
    fn detects_mismatched_reference_lifetime_through_returned_call() {
        let source = r#"
            fn borrow(v: &'b i32) -> &'b i32 {
                return v;
            }
            fn relay(a: &'a i32, b: &'b i32) -> &'a i32 {
                return borrow(b);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("returns reference expression with mismatched lifetime")
        }));
    }

    #[test]
    fn assignment_shaped_reference_flow_still_validates_return_lifetimes() {
        let source = r#"
            fn borrow_a(v: &'a i32) -> &'a i32 {
                return v;
            }
            fn borrow_b(v: &'b i32) -> &'b i32 {
                return v;
            }
            fn relay(a: &'a i32, b: &'b i32) -> &'a i32 {
                let out = borrow_a(a);
                if true {
                    out = borrow_b(b);
                }
                return out;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("returns reference expression with mismatched lifetime")
                || detail.contains(
                    "returns reference expression without a statically traced lifetime source",
                )
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
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("`break` is only valid inside loop bodies"))
        );
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("`continue` is only valid inside loop bodies"))
        );
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
    fn match_guard_can_reference_variant_payload_binding() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let source = Maybe::Some(9);
                match source {
                    Maybe::Some(v) if v > 4 => return v,
                    _ => return 0,
                }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn match_or_pattern_requires_identical_binding_shapes() {
        let source = r#"
            enum Maybe { Some(i32), Also(i32), None }
            fn main() -> i32 {
                let source = Maybe::Some(9);
                match source {
                    Maybe::Some(v) | Maybe::Also(w) => return 1,
                    _ => return 0,
                }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed.type_error_details.iter().any(|detail| {
            detail.contains("or-pattern alternatives must bind identical names and types")
        }));
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
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("closure return type mismatch"))
        );
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
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("is not callable"))
        );
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
        assert!(
            typed
                .unsafe_context_violations
                .iter()
                .any(|detail| detail.contains("outside `unsafe` context"))
        );
    }

    #[test]
    fn flags_non_exhaustive_enum_match_without_catchall() {
        let source = r#"
            enum State { Init, Ready, Done }
            fn main() -> i32 {
                let s = State::Init;
                match s {
                    State::Init => return 1,
                    State::Ready => return 2,
                }
            }
        "#;
        let module = parser::parse(source, "exhaustive").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("non-exhaustive match for enum `State`"))
        );
    }

    #[test]
    fn generic_struct_initialization_inferrs_type_arguments() {
        let source = r#"
            struct Box<T> { value: T }
            fn main() -> i32 {
                let b = Box { value: 7 };
                return b.value;
            }
        "#;
        let module = parser::parse(source, "generic_struct").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn await_requires_future_type_surface() {
        let source = r#"
            fn consume(x: Future<i32>) -> i32 {
                return await x;
            }
            fn bad(x: i32) -> i32 {
                return await x;
            }
        "#;
        let module = parser::parse(source, "await_future").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("await expects `Future<T>`"))
        );
    }

    #[test]
    fn map_set_deque_ring_and_domain_types_typecheck() {
        let source = r#"
            fn main(
                bi: BigInt,
                bu: BigUint,
                id: Uuid,
                d128: Decimal128,
                m: Map<str, i32>,
                s: Set<str>,
                d: Deque<i32>,
                r: Ring<i32>,
                obj: dyn Error,
                p: Path,
                pb: PathBuf,
                u: Url,
                sa: SocketAddr,
                dur: Duration,
                inst: Instant,
                dec: Decimal,
                dt: DateTimeTz,
                es: ExitStatus
            ) -> i32 {
                discard bi; discard bu; discard id; discard d128;
                discard m; discard s; discard d; discard r; discard obj;
                discard p; discard pb; discard u; discard sa; discard dur;
                discard inst; discard dec; discard dt; discard es;
                return 0;
            }
        "#;
        let module = parser::parse(source, "domain_types").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn type_alias_and_newtype_resolve_in_function_signatures() {
        let source = r#"
            type UserId = i32;
            newtype SessionId(UserId);
            fn echo(v: UserId) -> UserId {
                return v;
            }
            fn main(v: SessionId) -> i32 {
                discard v;
                discard echo(7);
                return 0;
            }
        "#;
        let module = parser::parse(source, "aliases").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn enum_struct_variant_payload_typechecks_and_binds() {
        let source = r#"
            enum Message {
                Data { id: i32, body: str },
                Empty,
            }
            fn main() -> i32 {
                let msg = Message::Data { id: 41, body: "ok" };
                match msg {
                    Message::Data { id, body } => return id + str.len(body),
                    Message::Empty => return 0,
                }
            }
        "#;
        let module = parser::parse(source, "enum_struct_variant").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }
}
