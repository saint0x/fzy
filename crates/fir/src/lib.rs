use ast::Type;
use capabilities::CapabilitySet;
use hir::{FunctionCapabilityRequirement, TypedFunction, TypedModule};

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
    pub type_errors: usize,
    pub type_error_details: Vec<String>,
    pub function_capability_requirements: Vec<FunctionCapabilityRequirement>,
    pub ownership_violations: Vec<String>,
    pub capability_token_violations: Vec<String>,
    pub trait_violations: Vec<String>,
    pub reference_lifetime_violations: Vec<String>,
    pub linear_type_violations: Vec<String>,
}

pub fn build(typed: &TypedModule) -> FirModule {
    build_owned(typed.clone())
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
        reference_sites,
        alloc_sites,
        free_sites,
        extern_c_abi_functions,
        repr_c_layout_items,
        generic_instantiations,
        generic_specializations,
        call_graph,
        typed_functions,
        type_errors,
        type_error_details,
        function_capability_requirements,
        ownership_violations,
        capability_token_violations,
        trait_violations,
        reference_lifetime_violations,
        linear_type_violations,
    } = typed;

    let mut effects = CapabilitySet::default();
    let mut required_effects = CapabilitySet::default();
    let mut unknown_effects = Vec::new();
    for capability in capabilities {
        if let Some(parsed) = capabilities::Capability::parse(&capability) {
            effects.insert(parsed);
        } else {
            unknown_effects.push(capability);
        }
    }
    for capability in inferred_capabilities {
        if let Some(parsed) = capabilities::Capability::parse(&capability) {
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
        type_errors,
        type_error_details,
        function_capability_requirements,
        ownership_violations,
        capability_token_violations,
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

    FunctionIr {
        name: function.name.clone(),
        return_type: to_value_type(&function.return_type),
        def_use: compute_def_use(&blocks),
        liveness: compute_liveness(&blocks),
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
            ast::Stmt::Assign { target, .. } => {
                current.instructions.push(Instruction::Assign {
                    name: target.clone(),
                });
            }
            ast::Stmt::Expr(_)
            | ast::Stmt::Requires(_)
            | ast::Stmt::Ensures(_)
            | ast::Stmt::Defer(_) => current.instructions.push(Instruction::Expr),
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
        }
    }
}

fn to_value_type(ty: &Type) -> ValueType {
    match ty {
        Type::Bool => ValueType::Bool,
        Type::Int { signed, bits } => ValueType::Int {
            signed: *signed,
            bits: *bits,
        },
        Type::Float { bits } => ValueType::Float { bits: *bits },
        Type::Ptr { .. } => ValueType::Ptr,
        Type::Ref { .. } => ValueType::Ref,
        Type::Slice(_) => ValueType::Slice,
        Type::Array { .. } => ValueType::Array,
        Type::Str => ValueType::Str,
        Type::Named { .. }
        | Type::Option(_)
        | Type::Result { .. }
        | Type::Vec(_)
        | Type::Char
        | Type::TypeVar(_) => ValueType::Aggregate,
        Type::Void => ValueType::Void,
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
                | Instruction::Return
                | Instruction::Branch { .. }
                | Instruction::Jump { .. }
                | Instruction::Match { .. } => {}
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

fn compute_liveness(blocks: &[BasicBlock]) -> Vec<LivenessBlock> {
    let def_use = compute_def_use(blocks);
    let mut live_in = vec![std::collections::BTreeSet::<String>::new(); blocks.len()];
    let mut live_out = vec![std::collections::BTreeSet::<String>::new(); blocks.len()];
    let block_index = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (block.id, idx))
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut changed = true;
    while changed {
        changed = false;
        for (idx, block) in blocks.iter().enumerate().rev() {
            let mut out_set = std::collections::BTreeSet::<String>::new();
            for succ in &block.successors {
                if let Some(succ_idx) = block_index.get(succ) {
                    out_set.extend(live_in[*succ_idx].iter().cloned());
                }
            }

            let mut in_set = out_set.clone();
            let du = &def_use[idx];
            for def in &du.defs {
                in_set.remove(def);
            }
            for used in &du.uses {
                in_set.insert(used.clone());
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
            live_in: live_in[idx].iter().cloned().collect(),
            live_out: live_out[idx].iter().cloned().collect(),
        })
        .collect()
}
