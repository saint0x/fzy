use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

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
    pub execution_space: ast::ExecutionSpace,
    pub abi: Option<String>,
    pub ffi_panic: Option<String>,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
struct PendingTypedFunction {
    name: String,
    link_name: Option<String>,
    generics: Vec<ast::GenericParam>,
    params: Vec<ast::Param>,
    return_type: Type,
    body: Vec<Stmt>,
    is_unsafe: bool,
    is_async: bool,
    is_extern: bool,
    execution_space: ast::ExecutionSpace,
    abi: Option<String>,
    ffi_panic: Option<String>,
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

#[derive(Default)]
struct ModuleDeclIndex {
    struct_defs: HashMap<String, ast::Struct>,
    enum_defs: HashMap<String, ast::Enum>,
    trait_defs: HashMap<String, ast::Trait>,
    trait_impls: HashMap<String, Vec<Type>>,
    type_aliases: HashMap<String, Type>,
}

#[derive(Debug, Clone)]
struct CowBindings<V: Clone>(Arc<BTreeMap<String, V>>);

impl<V: Clone> Default for CowBindings<V> {
    fn default() -> Self {
        Self(Arc::new(BTreeMap::new()))
    }
}

impl<V: Clone> Deref for CowBindings<V> {
    type Target = BTreeMap<String, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V: Clone> DerefMut for CowBindings<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

fn index_module_declarations(module: &Module) -> ModuleDeclIndex {
    let mut index = ModuleDeclIndex::default();
    for item in &module.items {
        match item {
            ast::Item::Struct(item) => {
                index.struct_defs.insert(item.name.clone(), item.clone());
            }
            ast::Item::Enum(item) => {
                index.enum_defs.insert(item.name.clone(), item.clone());
            }
            ast::Item::Trait(item) => {
                index.trait_defs.insert(item.name.clone(), item.clone());
            }
            ast::Item::Impl(item) => {
                if let Some(trait_name) = item.trait_name.clone() {
                    index
                        .trait_impls
                        .entry(trait_name)
                        .or_default()
                        .push(item.for_type.clone());
                }
            }
            ast::Item::TypeAlias(item) => {
                index
                    .type_aliases
                    .insert(item.name.clone(), item.ty.clone());
            }
            ast::Item::NewType(item) => {
                index
                    .type_aliases
                    .insert(item.name.clone(), item.inner.clone());
            }
            _ => {}
        }
    }
    index
        .trait_defs
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
    index
}

