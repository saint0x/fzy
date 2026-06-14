use super::gpu_kernel_metal::MetalKernelLaunchDescriptor;
use super::*;
use anyhow::{anyhow, bail, Result};
use std::collections::{BTreeMap, HashMap};

use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::{types, InstBuilder, TrapCode, Type as ClifType};
use cranelift_frontend::FunctionBuilder;

use super::ClifValue;

fn variant_tag(variant: &str) -> i32 {
    (variant.bytes().fold(0u32, |acc, byte| {
        acc.wrapping_mul(33).wrapping_add(byte as u32)
    }) & 0x7fff_ffff) as i32
}

pub(super) fn variant_tag_for_key(key: &str, variant_tags: &HashMap<String, i32>) -> i32 {
    variant_tags
        .get(key)
        .copied()
        .unwrap_or_else(|| variant_tag(key))
}

pub(super) struct ClifLoweringCtx<'a> {
    pub(super) module: &'a mut ObjectModule,
    pub(super) function_ids: &'a HashMap<String, cranelift_module::FuncId>,
    pub(super) function_signatures: &'a HashMap<String, ClifFunctionSignature>,
    pub(super) string_literal_ids: &'a HashMap<String, i32>,
    pub(super) task_ref_ids: &'a HashMap<String, i32>,
    pub(super) globals: &'a HashMap<String, i32>,
    pub(super) variant_tags: &'a HashMap<String, i32>,
    pub(super) local_types: &'a BTreeMap<String, ast::Type>,
    pub(super) derived_local_types: BTreeMap<String, ast::Type>,
    pub(super) struct_defs: &'a HashMap<String, ast::Struct>,
    pub(super) enum_defs: &'a HashMap<String, ast::Enum>,
    pub(super) mutable_globals: &'a HashMap<String, cranelift_module::DataId>,
    pub(super) gpu_kernel_launch_descriptors: &'a HashMap<String, MetalKernelLaunchDescriptor>,
    pub(super) current_return_ty: Option<ClifType>,
    pub(super) current_return_array: Option<ClifArrayAbi>,
    pub(super) current_return_ptr: Option<LocalBinding>,
    pub(super) closures: HashMap<String, ClifClosureBinding>,
    pub(super) array_bindings: HashMap<String, ClifArrayBinding>,
    pub(super) aggregate_bindings: HashMap<String, ClifAggregateBinding>,
    pub(super) const_strings: HashMap<String, String>,
    pub(super) current_namespace: &'a str,
}

#[derive(Clone)]
pub(super) struct ClifAggregateItemBinding {
    pub(super) index: usize,
    pub(super) ty: ClifType,
}

#[derive(Clone, Default)]
pub(super) struct ClifAggregateBinding {
    pub(super) items: HashMap<String, ClifAggregateItemBinding>,
}

pub(super) fn lower_cranelift_ir(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
) -> Result<String> {
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);
    let mut out = String::new();
    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        if let Some(data_ops) = plan.data_ops_by_function.get(&function.name) {
            for op in data_ops {
                let _ = writeln!(&mut out, "; canonical.dataop {}", render_native_data_op(op));
            }
        }
        let _ = writeln!(
            &mut out,
            "function %{}() -> i32 {{",
            native_mangle_symbol(&function.name)
        );
        match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => {
                for (block_id, block) in cfg.blocks.iter().enumerate() {
                    let _ = writeln!(&mut out, "block{block_id}:");
                    for stmt in &block.stmts {
                        let _ = writeln!(&mut out, "  ; {:?}", stmt);
                    }
                    match &block.terminator {
                        ControlFlowTerminator::Return(Some(expr)) => {
                            let _ = writeln!(&mut out, "  return {:?}", expr);
                        }
                        ControlFlowTerminator::Return(None) => {
                            if function.name == "main" {
                                let fallback = plan
                                    .forced_main_return
                                    .or(fir.entry_return_const_i32)
                                    .unwrap_or(0);
                                let _ = writeln!(&mut out, "  return {}", fallback);
                            } else {
                                let _ = writeln!(&mut out, "  return 0");
                            }
                        }
                        ControlFlowTerminator::Jump { target, edge } => {
                            let _ = writeln!(&mut out, "  jump block{} ; {:?}", target, edge);
                        }
                        ControlFlowTerminator::Branch {
                            condition,
                            then_target,
                            else_target,
                        } => {
                            let _ = writeln!(
                                &mut out,
                                "  br {:?}, block{}, block{}",
                                condition, then_target, else_target
                            );
                        }
                        ControlFlowTerminator::Switch {
                            scrutinee,
                            cases,
                            default_target,
                        } => {
                            let rendered_cases = cases
                                .iter()
                                .map(|(value, target)| format!("{value}->block{target}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            let _ = writeln!(
                                &mut out,
                                "  switch {:?}, [{}], default=block{}",
                                scrutinee, rendered_cases, default_target
                            );
                        }
                        ControlFlowTerminator::Unreachable => {
                            let _ = writeln!(&mut out, "  trap");
                        }
                    }
                }
            }
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        }
        out.push_str("}\n\n");
    }
    if out.is_empty() {
        let fallback = plan
            .forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return Ok(format!(
            "function %main() -> i32 {{\nblock0:\n  return {fallback}\n}}\n"
        ));
    }
    Ok(out)
}

pub(super) fn clif_emit_function_cfg(
    builder: &mut FunctionBuilder,
    module: &mut ObjectModule,
    function_ids: &HashMap<String, cranelift_module::FuncId>,
    function_signatures: &HashMap<String, ClifFunctionSignature>,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    globals: &HashMap<String, i32>,
    variant_tags: &HashMap<String, i32>,
    mutable_globals: &HashMap<String, cranelift_module::DataId>,
    local_types: &BTreeMap<String, ast::Type>,
    gpu_kernel_launch_descriptors: &HashMap<String, MetalKernelLaunchDescriptor>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    current_return_ty: Option<ClifType>,
    current_return_array: Option<ClifArrayAbi>,
    current_return_ptr: Option<LocalBinding>,
    current_function_name: &str,
    cfg: &ControlFlowCfg,
    entry_block: cranelift_codegen::ir::Block,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
    forced_return_i32: Option<i32>,
) -> Result<()> {
    let mut ctx = ClifLoweringCtx {
        module,
        function_ids,
        function_signatures,
        string_literal_ids,
        task_ref_ids,
        globals,
        variant_tags,
        local_types,
        derived_local_types: BTreeMap::new(),
        struct_defs,
        enum_defs,
        mutable_globals,
        gpu_kernel_launch_descriptors,
        current_return_ty,
        current_return_array,
        current_return_ptr,
        closures: HashMap::new(),
        array_bindings: HashMap::new(),
        aggregate_bindings: HashMap::new(),
        const_strings: HashMap::new(),
        current_namespace: native_current_namespace(current_function_name),
    };
    clif_emit_cfg(
        builder,
        &mut ctx,
        cfg,
        entry_block,
        locals,
        current_return_ty,
        next_var,
        forced_return_i32,
    )
}

fn clif_local_type<'a>(ctx: &'a ClifLoweringCtx<'_>, name: &str) -> Option<&'a ast::Type> {
    ctx.derived_local_types
        .get(name)
        .or_else(|| ctx.local_types.get(name))
}

fn clif_ptr_element_type(expr: &ast::Expr, ctx: &ClifLoweringCtx<'_>) -> Option<ClifType> {
    match expr {
        ast::Expr::Ident(name) => match clif_local_type(ctx, name) {
            Some(ast::Type::Ptr { to, .. }) => ast_signature_type_to_clif_type(to),
            _ => None,
        },
        ast::Expr::Group(inner) | ast::Expr::Discard(inner) => clif_ptr_element_type(inner, ctx),
        _ => None,
    }
}

fn clif_emit_cfg(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    cfg: &ControlFlowCfg,
    entry_block: cranelift_codegen::ir::Block,
    locals: &mut HashMap<String, LocalBinding>,
    return_ty: Option<ClifType>,
    next_var: &mut usize,
    forced_return_i32: Option<i32>,
) -> Result<()> {
    let mut clif_blocks = Vec::with_capacity(cfg.blocks.len());
    for block_id in 0..cfg.blocks.len() {
        if block_id == cfg.entry {
            clif_blocks.push(entry_block);
        } else {
            clif_blocks.push(builder.create_block());
        }
    }

    let mut predecessor_count = vec![0usize; cfg.blocks.len()];
    for block in &cfg.blocks {
        match &block.terminator {
            ControlFlowTerminator::Return(_) | ControlFlowTerminator::Unreachable => {}
            ControlFlowTerminator::Jump { target, .. } => {
                predecessor_count[*target] += 1;
            }
            ControlFlowTerminator::Branch {
                then_target,
                else_target,
                ..
            } => {
                predecessor_count[*then_target] += 1;
                predecessor_count[*else_target] += 1;
            }
            ControlFlowTerminator::Switch {
                cases,
                default_target,
                ..
            } => {
                predecessor_count[*default_target] += 1;
                for (_, target) in cases {
                    predecessor_count[*target] += 1;
                }
            }
        }
    }

    let mut observed_predecessors = vec![0usize; cfg.blocks.len()];
    let mut sealed = vec![false; cfg.blocks.len()];
    if predecessor_count[cfg.entry] == 0 {
        builder.seal_block(clif_blocks[cfg.entry]);
        sealed[cfg.entry] = true;
    }

    let mut emitted = vec![false; cfg.blocks.len()];
    let mut queue = vec![cfg.entry];
    while let Some(block_id) = queue.pop() {
        if emitted[block_id] {
            continue;
        }
        emitted[block_id] = true;
        builder.switch_to_block(clif_blocks[block_id]);
        let linear_terminated =
            clif_emit_linear_stmts(builder, ctx, &cfg.blocks[block_id].stmts, locals, next_var)?;
        if linear_terminated {
            emitted[block_id] = true;
            continue;
        }
        match &cfg.blocks[block_id].terminator {
            ControlFlowTerminator::Return(Some(expr)) => {
                if let (Some(return_array), Some(return_ptr)) =
                    (ctx.current_return_array, ctx.current_return_ptr)
                {
                    let dest_ptr = builder.use_var(return_ptr.var);
                    clif_emit_array_expr_to_ptr(
                        builder,
                        ctx,
                        expr,
                        dest_ptr,
                        return_array,
                        locals,
                        next_var,
                    )?;
                    builder.ins().return_(&[]);
                } else if let Some(return_ty) = return_ty {
                    let value = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                    let value = cast_clif_value(builder, value, return_ty)?;
                    builder.ins().return_(&[value.value]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
            ControlFlowTerminator::Return(None) => {
                if let (Some(return_array), Some(return_ptr)) =
                    (ctx.current_return_array, ctx.current_return_ptr)
                {
                    let dest_ptr = builder.use_var(return_ptr.var);
                    clif_zero_fill_array_memory(builder, dest_ptr, return_array);
                    builder.ins().return_(&[]);
                } else if let Some(return_ty) = return_ty {
                    let ret = if return_ty == types::I32 {
                        builder
                            .ins()
                            .iconst(types::I32, forced_return_i32.unwrap_or(0) as i64)
                    } else {
                        zero_for_type(builder, return_ty)
                    };
                    builder.ins().return_(&[ret]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
            ControlFlowTerminator::Jump { target, .. } => {
                builder.ins().jump(clif_blocks[*target], &[]);
                observed_predecessors[*target] += 1;
                if !sealed[*target] && observed_predecessors[*target] >= predecessor_count[*target]
                {
                    builder.seal_block(clif_blocks[*target]);
                    sealed[*target] = true;
                }
                queue.push(*target);
            }
            ControlFlowTerminator::Branch {
                condition,
                then_target,
                else_target,
            } => {
                let cond_val = clif_emit_expr(builder, ctx, condition, locals, next_var)?;
                let cond = clif_truthy_pred(builder, cond_val);
                builder.ins().brif(
                    cond,
                    clif_blocks[*then_target],
                    &[],
                    clif_blocks[*else_target],
                    &[],
                );
                observed_predecessors[*then_target] += 1;
                observed_predecessors[*else_target] += 1;
                if !sealed[*then_target]
                    && observed_predecessors[*then_target] >= predecessor_count[*then_target]
                {
                    builder.seal_block(clif_blocks[*then_target]);
                    sealed[*then_target] = true;
                }
                if !sealed[*else_target]
                    && observed_predecessors[*else_target] >= predecessor_count[*else_target]
                {
                    builder.seal_block(clif_blocks[*else_target]);
                    sealed[*else_target] = true;
                }
                queue.push(*else_target);
                queue.push(*then_target);
            }
            ControlFlowTerminator::Switch {
                scrutinee,
                cases,
                default_target,
            } => {
                let mut cond_val = clif_emit_expr(builder, ctx, scrutinee, locals, next_var)?;
                let aggregate_switch = match scrutinee {
                    ast::Expr::Ident(name) => {
                        ctx.aggregate_bindings.contains_key(name)
                            || clif_local_is_aggregate(name, ctx)
                    }
                    ast::Expr::EnumInit { .. }
                    | ast::Expr::StructInit { .. }
                    | ast::Expr::Tuple(_) => true,
                    _ => false,
                };
                if aggregate_switch && cond_val.ty == types::I64 {
                    let agg_tag_id =
                        ctx.function_ids
                            .get(NATIVE_AGG_TAG)
                            .copied()
                            .ok_or_else(|| {
                                anyhow!("missing runtime import lowering for `{NATIVE_AGG_TAG}`")
                            })?;
                    let agg_tag_ref = ctx.module.declare_func_in_func(agg_tag_id, builder.func);
                    let tag_call = builder.ins().call(agg_tag_ref, &[cond_val.value]);
                    cond_val = ClifValue {
                        value: builder.inst_results(tag_call)[0],
                        ty: types::I32,
                    };
                }
                let cond_val = cast_clif_value(builder, cond_val, default_int_clif_type())?;
                let mut switch = Switch::new();
                for (value, target) in cases {
                    switch.set_entry(*value as u128, clif_blocks[*target]);
                }
                switch.emit(builder, cond_val.value, clif_blocks[*default_target]);
                for (_, target) in cases {
                    observed_predecessors[*target] += 1;
                    if !sealed[*target]
                        && observed_predecessors[*target] >= predecessor_count[*target]
                    {
                        builder.seal_block(clif_blocks[*target]);
                        sealed[*target] = true;
                    }
                    queue.push(*target);
                }
                observed_predecessors[*default_target] += 1;
                if !sealed[*default_target]
                    && observed_predecessors[*default_target] >= predecessor_count[*default_target]
                {
                    builder.seal_block(clif_blocks[*default_target]);
                    sealed[*default_target] = true;
                }
                queue.push(*default_target);
            }
            ControlFlowTerminator::Unreachable => {
                if let Some(return_ty) = return_ty {
                    let ret = zero_for_type(builder, return_ty);
                    builder.ins().return_(&[ret]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
        }
    }

    if emitted.iter().any(|done| !*done) {
        bail!("cranelift cfg emission left one or more reachable blocks un-emitted");
    }
    for (index, block) in clif_blocks.iter().enumerate() {
        if !sealed[index] {
            builder.seal_block(*block);
        }
    }
    Ok(())
}

pub(super) fn clif_snapshot_closure_captures(
    builder: &mut FunctionBuilder,
    locals: &HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> HashMap<String, LocalBinding> {
    let mut captures = HashMap::new();
    for (name, binding) in locals {
        let captured_var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(captured_var, binding.ty);
        let current = builder.use_var(binding.var);
        builder.def_var(captured_var, current);
        captures.insert(
            name.clone(),
            LocalBinding {
                var: captured_var,
                ty: binding.ty,
            },
        );
    }
    captures
}

fn clif_restore_shadowed_locals(
    locals: &mut HashMap<String, LocalBinding>,
    saved: HashMap<String, Option<LocalBinding>>,
    inserted: HashSet<String>,
) {
    for (name, prior) in saved {
        if let Some(binding) = prior {
            locals.insert(name, binding);
        } else if inserted.contains(&name) {
            locals.remove(&name);
        }
    }
}

fn clif_bind_local(
    builder: &mut FunctionBuilder,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
    name: &str,
    ty: ClifType,
    value: cranelift_codegen::ir::Value,
) {
    let binding = if let Some(existing) = locals.get(name).copied() {
        existing
    } else {
        let var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(var, ty);
        let binding = LocalBinding { var, ty };
        locals.insert(name.to_string(), binding);
        binding
    };
    builder.def_var(binding.var, value);
}

fn clif_cast_scalar_to_i64(builder: &mut FunctionBuilder, value: ClifValue) -> Result<ClifValue> {
    cast_clif_value(builder, value, types::I64)
}

fn clif_cast_i64_to_ty(
    builder: &mut FunctionBuilder,
    raw_value: cranelift_codegen::ir::Value,
    target_ty: ClifType,
) -> Result<ClifValue> {
    cast_clif_value(
        builder,
        ClifValue {
            value: raw_value,
            ty: types::I64,
        },
        target_ty,
    )
}

fn clif_expr_is_fzy_str(expr: &ast::Expr, ctx: &ClifLoweringCtx<'_>) -> bool {
    match expr {
        ast::Expr::Str(_) => true,
        ast::Expr::Ident(name) => matches!(clif_local_type(ctx, name), Some(ast::Type::Str)),
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            clif_expr_is_fzy_str(inner, ctx)
        }
        _ => false,
    }
}

fn clif_is_extern_c_borrowed_ptr_param(sig: &ClifFunctionSignature, index: usize) -> bool {
    sig.is_extern_c_import
        && sig
            .param_names
            .get(index)
            .is_some_and(|name| name.contains("_borrowed"))
        && sig
            .params
            .get(index)
            .is_some_and(|ty| *ty == pointer_sized_clif_type())
}

fn clif_emit_borrowed_str_ptr_arg(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    arg: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
    let string_id = cast_clif_value(builder, lowered, types::I32)?;
    let function_id = ctx
        .function_ids
        .get(NATIVE_STR_PTR)
        .copied()
        .ok_or_else(|| {
            anyhow!("missing native helper signature metadata for `{NATIVE_STR_PTR}`")
        })?;
    let signature = ctx.function_signatures.get(NATIVE_STR_PTR).ok_or_else(|| {
        anyhow!("missing native helper signature metadata for `{NATIVE_STR_PTR}`")
    })?;
    let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
    let call = builder.ins().call(func_ref, &[string_id.value]);
    let value = builder.inst_results(call)[0];
    Ok(ClifValue {
        value,
        ty: signature.ret.unwrap_or(pointer_sized_clif_type()),
    })
}

#[path = "clif/simd.rs"]
mod simd;
#[path = "clif/array.rs"]
mod array;
#[path = "clif/agg.rs"]
mod agg;
#[path = "clif/bind.rs"]
mod bind;
#[path = "clif/linear.rs"]
mod linear;
#[path = "clif/expr.rs"]
mod expr;
#[path = "clif/ty.rs"]
mod ty;

pub(super) use self::agg::*;
pub(super) use self::array::*;
pub(super) use self::bind::*;
pub(super) use self::expr::*;
pub(super) use self::linear::*;
pub(super) use self::simd::*;
pub(super) use self::ty::*;
