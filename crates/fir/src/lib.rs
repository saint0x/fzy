use std::collections::HashMap;

use ast::Type;
use core::CapabilitySet;
pub use hir::count_module_owned_return_transfers;
pub use hir::TypedFunction;
pub use hir::UnsafeContractSite;
use hir::{FunctionCapabilityRequirement, TypedModule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueType {
    Int { signed: bool, bits: u16 },
    Float { bits: u16 },
    Bool,
    Ptr,
    Ref,
    Slice,
    Array,
    Str,
    Aggregate,
    Void,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum Instruction {
    Let {
        name: String,
        ty: ValueType,
    },
    Assign {
        name: String,
    },
    Expr,
    Defer,
    Return,
    Branch {
        then_block: usize,
        else_block: usize,
    },
    Jump {
        target: usize,
    },
    Match {
        arm_count: usize,
    },
    Break,
    Continue,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct FunctionIr {
    pub name: String,
    pub return_type: ValueType,
    pub blocks: Vec<BasicBlock>,
    pub def_use: Vec<DefUseBlock>,
    pub liveness: Vec<LivenessBlock>,
}

#[derive(Debug, Clone)]
pub struct DefUseBlock {
    pub block: usize,
    pub defs: Vec<String>,
    pub uses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LivenessBlock {
    pub block: usize,
    pub live_in: Vec<String>,
    pub live_out: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FirModule {
    pub name: String,
    pub effects: CapabilitySet,
    pub required_effects: CapabilitySet,
    pub unknown_effects: Vec<String>,
    pub nodes: usize,
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
    pub unsafe_contract_sites: Vec<hir::UnsafeContractSite>,
    pub reference_sites: usize,
    pub alloc_sites: usize,
    pub free_sites: usize,
    pub extern_c_abi_functions: usize,
    pub repr_c_layout_items: usize,
    pub generic_instantiations: Vec<String>,
    pub generic_specializations: Vec<String>,
    pub call_graph: Vec<(String, String)>,
    pub functions: Vec<FunctionIr>,
    pub typed_functions: Vec<TypedFunction>,
    pub typed_globals: Vec<hir::TypedGlobal>,
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

#[derive(Debug, Clone, Copy)]
pub struct VerifierFunction<'a> {
    pub name: &'a str,
    pub params: &'a [ast::Param],
    pub return_type: &'a ast::Type,
    pub is_async: bool,
    pub is_unsafe: bool,
    pub is_extern: bool,
    pub abi: &'a Option<String>,
    pub has_body: bool,
}

impl FirModule {
    pub fn verifier_functions(&self) -> impl Iterator<Item = VerifierFunction<'_>> {
        self.typed_functions
            .iter()
            .map(|function| VerifierFunction {
                name: function.name.as_str(),
                params: function.params.as_slice(),
                return_type: &function.return_type,
                is_async: function.is_async,
                is_unsafe: function.is_unsafe,
                is_extern: function.is_extern,
                abi: &function.abi,
                has_body: !function.body.is_empty(),
            })
    }

    pub fn returned_owned_sites(&self) -> usize {
        count_module_owned_return_transfers(&self.typed_functions)
    }
}

pub fn build(typed: TypedModule) -> FirModule {
    build_owned(typed)
}

pub fn build_owned(typed: TypedModule) -> FirModule {
    let TypedModule {
        name,
        symbol_count,
        capabilities,
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
        generic_specializations,
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
    } = typed;

    let mut effects = CapabilitySet::default();
    let mut required_effects = CapabilitySet::default();
    let mut unknown_effects = Vec::new();
    for capability in capabilities {
        if let Some(parsed) = core::Capability::parse(&capability) {
            effects.insert(parsed);
        } else {
            unknown_effects.push(capability);
        }
    }
    for capability in inferred_capabilities {
        if let Some(parsed) = core::Capability::parse(&capability) {
            required_effects.insert(parsed);
        } else {
            unknown_effects.push(capability);
        }
    }

    let functions = typed_functions
        .iter()
        .map(lower_function)
        .collect::<Vec<_>>();

    FirModule {
        name,
        effects,
        required_effects,
        unknown_effects,
        nodes: symbol_count,
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
        generic_specializations,
        call_graph,
        functions,
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

fn lower_function(function: &TypedFunction) -> FunctionIr {
    let mut blocks = Vec::new();
    let mut entry = BasicBlock {
        id: 0,
        instructions: Vec::new(),
        successors: Vec::new(),
    };
    lower_stmts_into_block(&function.body, &mut entry, &mut blocks);
    blocks.insert(0, entry);
    let def_use = compute_def_use(&blocks);

    FunctionIr {
        name: function.name.clone(),
        return_type: to_value_type(&function.return_type),
        def_use: def_use.clone(),
        liveness: compute_liveness(&blocks, &def_use),
        blocks,
    }
}

fn lower_stmts_into_block(
    stmts: &[ast::Stmt],
    current: &mut BasicBlock,
    blocks: &mut Vec<BasicBlock>,
) {
    for stmt in stmts {
        match stmt {
            ast::Stmt::Let { name, ty, .. } => {
                current.instructions.push(Instruction::Let {
                    name: name.clone(),
                    ty: ty.as_ref().map(to_value_type).unwrap_or(ValueType::Unknown),
                });
            }
            ast::Stmt::LetPattern { pattern, ty, .. } => {
                let mut names = Vec::new();
                pattern.bound_names(&mut names);
                for name in names {
                    current.instructions.push(Instruction::Let {
                        name,
                        ty: ty.as_ref().map(to_value_type).unwrap_or(ValueType::Unknown),
                    });
                }
            }
            ast::Stmt::Assign { target, .. } => {
                current.instructions.push(Instruction::Assign {
                    name: target.clone(),
                });
            }
            ast::Stmt::CompoundAssign { target, .. } => {
                current.instructions.push(Instruction::Assign {
                    name: target.clone(),
                });
            }
            ast::Stmt::Expr(_) | ast::Stmt::Requires(_) | ast::Stmt::Ensures(_) => {
                current.instructions.push(Instruction::Expr)
            }
            ast::Stmt::Defer(_) => current.instructions.push(Instruction::Defer),
            ast::Stmt::Return(_) => current.instructions.push(Instruction::Return),
            ast::Stmt::Match { arms, .. } => {
                current.instructions.push(Instruction::Match {
                    arm_count: arms.len(),
                });
            }
            ast::Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                let then_id = blocks.len() + 1;
                let else_id = blocks.len() + 2;
                current.instructions.push(Instruction::Branch {
                    then_block: then_id,
                    else_block: else_id,
                });
                current.successors.push(then_id);
                current.successors.push(else_id);

                let mut then_block = BasicBlock {
                    id: then_id,
                    instructions: Vec::new(),
                    successors: Vec::new(),
                };
                lower_stmts_into_block(then_body, &mut then_block, blocks);
                blocks.push(then_block);

                let mut else_block = BasicBlock {
                    id: else_id,
                    instructions: Vec::new(),
                    successors: Vec::new(),
                };
                lower_stmts_into_block(else_body, &mut else_block, blocks);
                blocks.push(else_block);
            }
            ast::Stmt::While { body, .. } => {
                let loop_id = blocks.len() + 1;
                current
                    .instructions
                    .push(Instruction::Jump { target: loop_id });
                current.successors.push(loop_id);
                let mut loop_block = BasicBlock {
                    id: loop_id,
                    instructions: Vec::new(),
                    successors: vec![loop_id],
                };
                lower_stmts_into_block(body, &mut loop_block, blocks);
                blocks.push(loop_block);
            }
            ast::Stmt::For {
                init, step, body, ..
            } => {
                if let Some(init) = init {
                    lower_stmts_into_block(std::slice::from_ref(init.as_ref()), current, blocks);
                }
                let loop_id = blocks.len() + 1;
                current
                    .instructions
                    .push(Instruction::Jump { target: loop_id });
                current.successors.push(loop_id);
                let mut loop_block = BasicBlock {
                    id: loop_id,
                    instructions: Vec::new(),
                    successors: vec![loop_id],
                };
                lower_stmts_into_block(body, &mut loop_block, blocks);
                if let Some(step) = step {
                    lower_stmts_into_block(
                        std::slice::from_ref(step.as_ref()),
                        &mut loop_block,
                        blocks,
                    );
                }
                blocks.push(loop_block);
            }
            ast::Stmt::ForIn { body, .. } | ast::Stmt::Loop { body } => {
                let loop_id = blocks.len() + 1;
                current
                    .instructions
                    .push(Instruction::Jump { target: loop_id });
                current.successors.push(loop_id);
                let mut loop_block = BasicBlock {
                    id: loop_id,
                    instructions: Vec::new(),
                    successors: vec![loop_id],
                };
                lower_stmts_into_block(body, &mut loop_block, blocks);
                blocks.push(loop_block);
            }
            ast::Stmt::Break(_) => current.instructions.push(Instruction::Break),
            ast::Stmt::Continue => current.instructions.push(Instruction::Continue),
        }
    }
}

fn to_value_type(ty: &Type) -> ValueType {
    match ty {
        Type::Bool => ValueType::Bool,
        Type::ISize => ValueType::Int {
            signed: true,
            bits: usize::BITS as u16,
        },
        Type::USize => ValueType::Int {
            signed: false,
            bits: usize::BITS as u16,
        },
        Type::Int { signed, bits } => ValueType::Int {
            signed: *signed,
            bits: *bits,
        },
        Type::BigInt | Type::BigUint | Type::Decimal128 => ValueType::Aggregate,
        Type::Float { bits } => ValueType::Float { bits: *bits },
        Type::Ptr { .. } => ValueType::Ptr,
        Type::Ref { .. } => ValueType::Ref,
        Type::Slice(_) => ValueType::Slice,
        Type::Array { .. } => ValueType::Array,
        Type::Str => ValueType::Str,
        Type::Bytes => ValueType::Array,
        Type::Named { .. }
        | Type::Uuid
        | Type::DynTrait(_)
        | Type::Map { .. }
        | Type::Set(_)
        | Type::Deque(_)
        | Type::Ring(_)
        | Type::Option(_)
        | Type::Result { .. }
        | Type::Vec(_)
        | Type::Future(_)
        | Type::Path
        | Type::PathBuf
        | Type::Url
        | Type::SocketAddr
        | Type::Duration
        | Type::Instant
        | Type::Decimal
        | Type::DateTimeTz
        | Type::ExitStatus
        | Type::SimdVector(_)
        | Type::SimdMask(_)
        | Type::Tuple(_)
        | Type::Function { .. }
        | Type::Char
        | Type::TypeVar(_) => ValueType::Aggregate,
        Type::Void | Type::Never => ValueType::Void,
    }
}

fn compute_def_use(blocks: &[BasicBlock]) -> Vec<DefUseBlock> {
    let mut out = Vec::new();
    for block in blocks {
        let mut defs = Vec::new();
        let mut uses = Vec::new();
        for inst in &block.instructions {
            match inst {
                Instruction::Let { name, .. } => defs.push(name.clone()),
                Instruction::Assign { name } => {
                    uses.push(name.clone());
                    defs.push(name.clone());
                }
                Instruction::Expr
                | Instruction::Defer
                | Instruction::Return
                | Instruction::Branch { .. }
                | Instruction::Jump { .. }
                | Instruction::Match { .. }
                | Instruction::Break
                | Instruction::Continue => {}
            }
        }
        out.push(DefUseBlock {
            block: block.id,
            defs,
            uses,
        });
    }
    out
}

fn compute_liveness(blocks: &[BasicBlock], def_use: &[DefUseBlock]) -> Vec<LivenessBlock> {
    let block_len = blocks.len();
    let mut symbol_index = std::collections::BTreeMap::<String, usize>::new();
    let mut symbols = Vec::<String>::new();
    let mut indexed_defs = Vec::with_capacity(def_use.len());
    let mut indexed_uses = Vec::with_capacity(def_use.len());
    for du in def_use {
        let defs = du
            .defs
            .iter()
            .map(|name| intern_liveness_symbol(name, &mut symbol_index, &mut symbols))
            .collect::<Vec<_>>();
        let uses = du
            .uses
            .iter()
            .map(|name| intern_liveness_symbol(name, &mut symbol_index, &mut symbols))
            .collect::<Vec<_>>();
        indexed_defs.push(defs);
        indexed_uses.push(uses);
    }
    let symbol_len = symbols.len();
    let mut live_in = vec![vec![false; symbol_len]; block_len];
    let mut live_out = vec![vec![false; symbol_len]; block_len];
    let block_index = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (block.id, idx))
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut changed = true;
    while changed {
        changed = false;
        for (idx, block) in blocks.iter().enumerate().rev() {
            let mut out_set = vec![false; symbol_len];
            for succ in &block.successors {
                if let Some(succ_idx) = block_index.get(succ) {
                    for (symbol_idx, is_live) in live_in[*succ_idx].iter().enumerate() {
                        out_set[symbol_idx] |= *is_live;
                    }
                }
            }

            let mut in_set = out_set.clone();
            for def in &indexed_defs[idx] {
                in_set[*def] = false;
            }
            for used in &indexed_uses[idx] {
                in_set[*used] = true;
            }

            if out_set != live_out[idx] || in_set != live_in[idx] {
                live_out[idx] = out_set;
                live_in[idx] = in_set;
                changed = true;
            }
        }
    }

    blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| LivenessBlock {
            block: block.id,
            live_in: collect_live_symbols(&live_in[idx], &symbols),
            live_out: collect_live_symbols(&live_out[idx], &symbols),
        })
        .collect()
}

fn intern_liveness_symbol(
    name: &str,
    symbol_index: &mut std::collections::BTreeMap<String, usize>,
    symbols: &mut Vec<String>,
) -> usize {
    if let Some(existing) = symbol_index.get(name) {
        return *existing;
    }
    let idx = symbols.len();
    let owned = name.to_string();
    symbols.push(owned.clone());
    symbol_index.insert(owned, idx);
    idx
}

fn collect_live_symbols(bits: &[bool], symbols: &[String]) -> Vec<String> {
    bits.iter()
        .enumerate()
        .filter_map(|(idx, is_live)| is_live.then(|| symbols[idx].clone()))
        .collect()
}
