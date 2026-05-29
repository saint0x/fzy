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
    pub(super) local_types: BTreeMap<String, ast::Type>,
    pub(super) struct_defs: &'a HashMap<String, ast::Struct>,
    pub(super) enum_defs: &'a HashMap<String, ast::Enum>,
    pub(super) mutable_globals: &'a HashMap<String, cranelift_module::DataId>,
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
    local_types: BTreeMap<String, ast::Type>,
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
        struct_defs,
        enum_defs,
        mutable_globals,
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
        ast::Expr::Ident(name) => matches!(ctx.local_types.get(name), Some(ast::Type::Str)),
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

fn clif_parse_simd_intrinsic(callee: &str) -> Option<(&str, &str)> {
    let body = callee.strip_prefix("simd.__")?;
    for kind in ["i32x4", "u32x4", "f32x4", "mask32x4"] {
        if let Some(op) = body.strip_prefix(kind) {
            return Some((kind, op));
        }
    }
    None
}

fn clif_simd_vector_type(kind: &str) -> Option<ClifType> {
    match kind {
        "i32x4" | "u32x4" | "mask32x4" => Some(types::I32X4),
        "f32x4" => Some(types::F32X4),
        _ => None,
    }
}

fn clif_simd_lane_type(kind: &str) -> Option<ClifType> {
    match kind {
        "i32x4" | "u32x4" | "mask32x4" => Some(types::I32),
        "f32x4" => Some(types::F32),
        _ => None,
    }
}

fn clif_simd_ptr_alignment(kind: &str, op: &str) -> Option<i64> {
    if !op.contains("_aligned_") {
        return None;
    }
    Some(if kind == "mask32x4" { 4 } else { 16 })
}

fn clif_emit_simd_ptr_alignment_check(
    builder: &mut FunctionBuilder,
    ptr: cranelift_codegen::ir::Value,
    align: i64,
) {
    let masked = builder.ins().band_imm(ptr, align - 1);
    let zero = builder.ins().iconst(pointer_sized_clif_type(), 0);
    let aligned = builder.ins().icmp(IntCC::Equal, masked, zero);
    builder.ins().trapz(aligned, TrapCode::unwrap_user(1));
}

fn clif_emit_simd_ptr_memory(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    kind: &str,
    op: &str,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let base_ptr_expr = clif_emit_expr(builder, ctx, &args[0], locals, next_var)?;
    let base_ptr = cast_clif_value(builder, base_ptr_expr, pointer_sized_clif_type())?.value;
    if let Some(align) = clif_simd_ptr_alignment(kind, op) {
        clif_emit_simd_ptr_alignment_check(builder, base_ptr, align);
    }
    if op.starts_with("_load_") {
        if kind == "mask32x4" {
            let mut lanes = Vec::with_capacity(4);
            for index in 0..4 {
                let addr = if index == 0 {
                    base_ptr
                } else {
                    builder.ins().iadd_imm(base_ptr, index as i64)
                };
                let loaded = builder.ins().load(types::I8, MemFlags::new(), addr, 0);
                let zero = builder.ins().iconst(types::I8, 0);
                let pred = builder.ins().icmp(IntCC::NotEqual, loaded, zero);
                let true_lane = clif_simd_true_lane(builder);
                let false_lane = clif_simd_false_lane(builder);
                lanes.push(ClifValue {
                    value: builder.ins().select(pred, true_lane, false_lane),
                    ty: types::I32,
                });
            }
            return clif_emit_simd_vector_from_lanes(builder, kind, &lanes);
        }
        let vec_ty = clif_simd_vector_type(kind)
            .ok_or_else(|| anyhow!("unsupported cranelift simd vector type for `{kind}`"))?;
        return Ok(ClifValue {
            value: builder.ins().load(vec_ty, MemFlags::new(), base_ptr, 0),
            ty: vec_ty,
        });
    }

    let vector = clif_emit_expr(builder, ctx, &args[1], locals, next_var)?;
    if kind == "mask32x4" {
        let lanes = clif_emit_simd_lanes(builder, vector, kind)?;
        for (index, lane) in lanes.into_iter().enumerate() {
            let addr = if index == 0 {
                base_ptr
            } else {
                builder.ins().iadd_imm(base_ptr, index as i64)
            };
            let pred = clif_emit_simd_mask_pred(builder, lane);
            let one = builder.ins().iconst(types::I8, 1);
            let zero = builder.ins().iconst(types::I8, 0);
            let stored = builder.ins().select(pred, one, zero);
            builder.ins().store(MemFlags::new(), stored, addr, 0);
        }
    } else {
        let vec_ty = clif_simd_vector_type(kind)
            .ok_or_else(|| anyhow!("unsupported cranelift simd vector type for `{kind}`"))?;
        let vector = cast_clif_value(builder, vector, vec_ty)?;
        builder
            .ins()
            .store(MemFlags::new(), vector.value, base_ptr, 0);
    }
    Ok(ClifValue {
        value: builder.ins().iconst(default_int_clif_type(), 0),
        ty: default_int_clif_type(),
    })
}

fn clif_simd_true_lane(builder: &mut FunctionBuilder) -> cranelift_codegen::ir::Value {
    builder.ins().iconst(types::I32, -1)
}

fn clif_simd_false_lane(builder: &mut FunctionBuilder) -> cranelift_codegen::ir::Value {
    builder.ins().iconst(types::I32, 0)
}

fn clif_emit_simd_lane_from_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    arg: &ast::Expr,
    kind: &str,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    if kind == "mask32x4" {
        let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
        let pred = clif_truthy_pred(builder, lowered);
        let true_lane = clif_simd_true_lane(builder);
        let false_lane = clif_simd_false_lane(builder);
        return Ok(ClifValue {
            value: builder.ins().select(pred, true_lane, false_lane),
            ty: types::I32,
        });
    }
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane type for `{kind}`"))?;
    let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
    cast_clif_value(builder, lowered, lane_ty)
}

fn clif_emit_simd_vector_from_lanes(
    builder: &mut FunctionBuilder,
    kind: &str,
    lanes: &[ClifValue],
) -> Result<ClifValue> {
    let vec_ty = clif_simd_vector_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd vector type for `{kind}`"))?;
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane type for `{kind}`"))?;
    if lanes.len() != 4 {
        bail!(
            "expected exactly 4 SIMD lanes for `{kind}`, found {}",
            lanes.len()
        );
    }
    let first = if lanes[0].ty == lane_ty {
        lanes[0].value
    } else {
        bail!("lane type mismatch while building `{kind}`");
    };
    let mut current = builder.ins().scalar_to_vector(vec_ty, first);
    for (index, lane) in lanes.iter().enumerate().skip(1) {
        if lane.ty != lane_ty {
            bail!("lane type mismatch while building `{kind}`");
        }
        current = builder.ins().insertlane(current, lane.value, index as u8);
    }
    Ok(ClifValue {
        value: current,
        ty: vec_ty,
    })
}

fn clif_emit_simd_lanes(
    builder: &mut FunctionBuilder,
    value: ClifValue,
    kind: &str,
) -> Result<Vec<ClifValue>> {
    let mut lanes = Vec::with_capacity(4);
    for lane in 0..4 {
        lanes.push(clif_emit_simd_extract_lane(builder, value, kind, lane)?);
    }
    Ok(lanes)
}

fn clif_emit_simd_ctor_from_args(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    kind: &str,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let mut lanes = Vec::with_capacity(args.len());
    for arg in args {
        lanes.push(clif_emit_simd_lane_from_expr(
            builder, ctx, arg, kind, locals, next_var,
        )?);
    }
    clif_emit_simd_vector_from_lanes(builder, kind, &lanes)
}

fn clif_emit_simd_extract_lane(
    builder: &mut FunctionBuilder,
    value: ClifValue,
    kind: &str,
    lane: u8,
) -> Result<ClifValue> {
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane type for `{kind}`"))?;
    Ok(ClifValue {
        value: builder.ins().extractlane(value.value, lane),
        ty: lane_ty,
    })
}

fn clif_emit_simd_mask_pred(
    builder: &mut FunctionBuilder,
    lane: ClifValue,
) -> cranelift_codegen::ir::Value {
    let zero = builder.ins().iconst(types::I32, 0);
    builder.ins().icmp(IntCC::NotEqual, lane.value, zero)
}

fn clif_emit_simd_shuffle_lane(
    builder: &mut FunctionBuilder,
    selector: ClifValue,
    candidates: &[ClifValue],
) -> Result<ClifValue> {
    if candidates.len() != 8 {
        bail!(
            "cranelift simd shuffle expected 8 lane candidates, found {}",
            candidates.len()
        );
    }
    let selector = cast_clif_value(builder, selector, types::I32)?;
    let zero = builder.ins().iconst(types::I32, 0);
    let eight = builder.ins().iconst(types::I32, 8);
    let non_negative = builder
        .ins()
        .icmp(IntCC::SignedGreaterThanOrEqual, selector.value, zero);
    let below_upper = builder
        .ins()
        .icmp(IntCC::SignedLessThan, selector.value, eight);
    let valid = builder.ins().band(non_negative, below_upper);
    builder.ins().trapz(valid, TrapCode::unwrap_user(1));

    let mut current = candidates[0].clone();
    for (index, candidate) in candidates.iter().enumerate().skip(1) {
        let lane_index = builder.ins().iconst(types::I32, index as i64);
        let pick = builder.ins().icmp(IntCC::Equal, selector.value, lane_index);
        current = ClifValue {
            value: builder.ins().select(pick, candidate.value, current.value),
            ty: current.ty,
        };
    }
    Ok(current)
}

fn clif_emit_simd_compare_lane(
    builder: &mut FunctionBuilder,
    kind: &str,
    op: &str,
    left: ClifValue,
    right: ClifValue,
) -> Result<ClifValue> {
    let pred = match kind {
        "f32x4" => {
            let cc = match op {
                "_eq" => FloatCC::Equal,
                "_ne" => FloatCC::NotEqual,
                "_lt" => FloatCC::LessThan,
                "_le" => FloatCC::LessThanOrEqual,
                "_gt" => FloatCC::GreaterThan,
                "_ge" => FloatCC::GreaterThanOrEqual,
                _ => bail!("unsupported cranelift simd comparison `{kind}{op}`"),
            };
            builder.ins().fcmp(cc, left.value, right.value)
        }
        "u32x4" => {
            let cc = match op {
                "_eq" => IntCC::Equal,
                "_ne" => IntCC::NotEqual,
                "_lt" => IntCC::UnsignedLessThan,
                "_le" => IntCC::UnsignedLessThanOrEqual,
                "_gt" => IntCC::UnsignedGreaterThan,
                "_ge" => IntCC::UnsignedGreaterThanOrEqual,
                _ => bail!("unsupported cranelift simd comparison `{kind}{op}`"),
            };
            builder.ins().icmp(cc, left.value, right.value)
        }
        _ => {
            let cc = match op {
                "_eq" => IntCC::Equal,
                "_ne" => IntCC::NotEqual,
                "_lt" => IntCC::SignedLessThan,
                "_le" => IntCC::SignedLessThanOrEqual,
                "_gt" => IntCC::SignedGreaterThan,
                "_ge" => IntCC::SignedGreaterThanOrEqual,
                _ => bail!("unsupported cranelift simd comparison `{kind}{op}`"),
            };
            builder.ins().icmp(cc, left.value, right.value)
        }
    };
    Ok(ClifValue {
        value: {
            let true_lane = clif_simd_true_lane(builder);
            let false_lane = clif_simd_false_lane(builder);
            builder.ins().select(pred, true_lane, false_lane)
        },
        ty: types::I32,
    })
}

fn clif_emit_simd_saturating_lane(
    builder: &mut FunctionBuilder,
    kind: &str,
    op: &str,
    left: ClifValue,
    right: ClifValue,
) -> Result<ClifValue> {
    let lane_ty = types::I32;
    match kind {
        "i32x4" => {
            let wide_left = builder.ins().sextend(types::I64, left.value);
            let wide_right = builder.ins().sextend(types::I64, right.value);
            let wide = if op == "_saturating_add" {
                builder.ins().iadd(wide_left, wide_right)
            } else {
                builder.ins().isub(wide_left, wide_right)
            };
            let min_val = builder.ins().iconst(types::I64, i64::from(i32::MIN));
            let max_val = builder.ins().iconst(types::I64, i64::from(i32::MAX));
            let below = builder.ins().icmp(IntCC::SignedLessThan, wide, min_val);
            let above = builder.ins().icmp(IntCC::SignedGreaterThan, wide, max_val);
            let bounded_low = builder.ins().select(below, min_val, wide);
            let bounded = builder.ins().select(above, max_val, bounded_low);
            Ok(ClifValue {
                value: builder.ins().ireduce(lane_ty, bounded),
                ty: lane_ty,
            })
        }
        "u32x4" => {
            let wide_left = builder.ins().uextend(types::I64, left.value);
            let wide_right = builder.ins().uextend(types::I64, right.value);
            let max_val = builder.ins().iconst(types::I64, u32::MAX as i64);
            let wide = if op == "_saturating_add" {
                let sum = builder.ins().iadd(wide_left, wide_right);
                let above = builder.ins().icmp(IntCC::UnsignedGreaterThan, sum, max_val);
                builder.ins().select(above, max_val, sum)
            } else {
                let underflow = builder
                    .ins()
                    .icmp(IntCC::UnsignedLessThan, wide_left, wide_right);
                let diff = builder.ins().isub(wide_left, wide_right);
                let zero = builder.ins().iconst(types::I64, 0);
                builder.ins().select(underflow, zero, diff)
            };
            Ok(ClifValue {
                value: builder.ins().ireduce(lane_ty, wide),
                ty: lane_ty,
            })
        }
        _ => bail!("unsupported cranelift simd saturating op `{kind}{op}`"),
    }
}

fn clif_emit_simd_reduce_lanes(
    builder: &mut FunctionBuilder,
    kind: &str,
    op: &str,
    lanes: &[ClifValue],
) -> Result<ClifValue> {
    if lanes.is_empty() {
        bail!("cannot reduce empty SIMD lane set for `{kind}{op}`");
    }
    let mut current = lanes[0].clone();
    for lane in lanes.iter().skip(1) {
        current = match (kind, op) {
            ("f32x4", "_reduce_add") => ClifValue {
                value: builder.ins().fadd(current.value, lane.value),
                ty: types::F32,
            },
            ("f32x4", "_reduce_min") => ClifValue {
                value: builder.ins().fmin(current.value, lane.value),
                ty: types::F32,
            },
            ("f32x4", "_reduce_max") => ClifValue {
                value: builder.ins().fmax(current.value, lane.value),
                ty: types::F32,
            },
            ("u32x4", "_reduce_add") => ClifValue {
                value: builder.ins().iadd(current.value, lane.value),
                ty: types::I32,
            },
            ("u32x4", "_reduce_min") => ClifValue {
                value: builder.ins().umin(current.value, lane.value),
                ty: types::I32,
            },
            ("u32x4", "_reduce_max") => ClifValue {
                value: builder.ins().umax(current.value, lane.value),
                ty: types::I32,
            },
            (_, "_reduce_add") => ClifValue {
                value: builder.ins().iadd(current.value, lane.value),
                ty: types::I32,
            },
            (_, "_reduce_min") => ClifValue {
                value: builder.ins().smin(current.value, lane.value),
                ty: types::I32,
            },
            (_, "_reduce_max") => ClifValue {
                value: builder.ins().smax(current.value, lane.value),
                ty: types::I32,
            },
            _ => bail!("unsupported cranelift simd reduction `{kind}{op}`"),
        };
    }
    Ok(current)
}

fn clif_emit_simd_intrinsic(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    kind: &str,
    op: &str,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let vec_ty = clif_simd_vector_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd type family `{kind}`"))?;
    let lane_ty = clif_simd_lane_type(kind)
        .ok_or_else(|| anyhow!("unsupported cranelift simd lane family `{kind}`"))?;
    match op {
        "" => return clif_emit_simd_ctor_from_args(builder, ctx, kind, args, locals, next_var),
        "_splat" => {
            let lane =
                clif_emit_simd_lane_from_expr(builder, ctx, &args[0], kind, locals, next_var)?;
            return Ok(ClifValue {
                value: builder.ins().splat(vec_ty, lane.value),
                ty: vec_ty,
            });
        }
        "_load" => {
            if let ast::Expr::ArrayLiteral(items) = &args[0] {
                return clif_emit_simd_ctor_from_args(builder, ctx, kind, items, locals, next_var);
            }
            if let ast::Expr::Ident(name) = &args[0] {
                if let Some(binding) = ctx.array_bindings.get(name).cloned() {
                    let mut lanes = Vec::with_capacity(binding.len.min(4));
                    for index in 0..binding.len.min(4) {
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            binding.stack_slot,
                            (index as i32) * i32::from(binding.element_stride),
                        );
                        let loaded =
                            builder
                                .ins()
                                .load(binding.element_ty, MemFlags::new(), ptr, 0);
                        let lane = if kind == "mask32x4" {
                            let zero = builder.ins().iconst(binding.element_ty, 0);
                            let pred = builder.ins().icmp(IntCC::NotEqual, loaded, zero);
                            let true_lane = clif_simd_true_lane(builder);
                            let false_lane = clif_simd_false_lane(builder);
                            ClifValue {
                                value: builder.ins().select(pred, true_lane, false_lane),
                                ty: types::I32,
                            }
                        } else {
                            cast_clif_value(
                                builder,
                                ClifValue {
                                    value: loaded,
                                    ty: binding.element_ty,
                                },
                                lane_ty,
                            )?
                        };
                        lanes.push(lane);
                    }
                    return clif_emit_simd_vector_from_lanes(builder, kind, &lanes);
                }
                if let Some(ast::Type::Array { elem, len }) = ctx.local_types.get(name) {
                    if *len == 4 {
                        if let Some(ptr_binding) = locals.get(name).copied() {
                            let element_ty = ast_signature_type_to_clif_type(elem.as_ref())
                                .ok_or_else(|| {
                                    anyhow!("unsupported array element type for `{name}`")
                                })?;
                            let element_stride = if element_ty == types::I8 {
                                1
                            } else if element_ty == types::I16 {
                                2
                            } else {
                                4
                            };
                            let base_ptr = builder.use_var(ptr_binding.var);
                            let mut lanes = Vec::with_capacity(4);
                            for index in 0..4 {
                                let addr = if index == 0 {
                                    base_ptr
                                } else {
                                    builder.ins().iadd_imm(
                                        base_ptr,
                                        (index as i64) * i64::from(element_stride),
                                    )
                                };
                                let loaded =
                                    builder.ins().load(element_ty, MemFlags::new(), addr, 0);
                                let lane = if kind == "mask32x4" {
                                    let zero = builder.ins().iconst(element_ty, 0);
                                    let pred = builder.ins().icmp(IntCC::NotEqual, loaded, zero);
                                    let true_lane = clif_simd_true_lane(builder);
                                    let false_lane = clif_simd_false_lane(builder);
                                    ClifValue {
                                        value: builder.ins().select(pred, true_lane, false_lane),
                                        ty: types::I32,
                                    }
                                } else {
                                    cast_clif_value(
                                        builder,
                                        ClifValue {
                                            value: loaded,
                                            ty: element_ty,
                                        },
                                        lane_ty,
                                    )?
                                };
                                lanes.push(lane);
                            }
                            return clif_emit_simd_vector_from_lanes(builder, kind, &lanes);
                        }
                    }
                }
            }
            bail!("cranelift simd load currently requires fixed-array-backed values")
        }
        "_load_aligned_ptr"
        | "_load_unaligned_ptr"
        | "_store_aligned_ptr"
        | "_store_unaligned_ptr" => {
            return clif_emit_simd_ptr_memory(builder, ctx, kind, op, args, locals, next_var);
        }
        _ => {}
    }

    let vector_args = match op {
        "_add" | "_sub" | "_mul" | "_min" | "_max" | "_and" | "_or" | "_xor"
        | "_saturating_add" | "_saturating_sub" | "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" => {
            2
        }
        "_select" => 3,
        "_shuffle" => 2,
        "_shl" | "_shr" | "_not" | "_as_u32x4" | "_as_i32x4" | "_bitcast_f32x4"
        | "_bitcast_i32x4" | "_bitcast_u32x4" | "_reduce_add" | "_reduce_min" | "_reduce_max"
        | "_any" | "_all" | "_none" | "_bitmask" | "_lane0" | "_lane1" | "_lane2" | "_lane3" => 1,
        _ => args.len(),
    };
    let mut lowered = Vec::with_capacity(vector_args);
    for arg in args.iter().take(vector_args) {
        lowered.push(clif_emit_expr(builder, ctx, arg, locals, next_var)?);
    }

    match op {
        "_add" | "_sub" | "_mul" | "_min" | "_max" | "_and" | "_or" | "_xor" | "_not" | "_shl"
        | "_shr" | "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" | "_select" | "_shuffle"
        | "_saturating_add" | "_saturating_sub" | "_reduce_add" | "_reduce_min" | "_reduce_max"
        | "_any" | "_all" | "_none" | "_bitmask" | "_lane0" | "_lane1" | "_lane2" | "_lane3" => {}
        "_as_u32x4" | "_as_i32x4" => {
            return Ok(ClifValue {
                value: lowered[0].value,
                ty: vec_ty,
            });
        }
        "_bitcast_f32x4" | "_bitcast_i32x4" | "_bitcast_u32x4" => {
            return Ok(ClifValue {
                value: builder
                    .ins()
                    .bitcast(vec_ty, MemFlags::new(), lowered[0].value),
                ty: vec_ty,
            });
        }
        _ => {
            bail!("cranelift lowering does not support `simd.__{kind}{op}` yet");
        }
    }

    if matches!(
        op,
        "_reduce_add"
            | "_reduce_min"
            | "_reduce_max"
            | "_any"
            | "_all"
            | "_none"
            | "_bitmask"
            | "_lane0"
            | "_lane1"
            | "_lane2"
            | "_lane3"
    ) {
        let lanes = clif_emit_simd_lanes(builder, lowered[0], kind)?;
        return match op {
            "_reduce_add" | "_reduce_min" | "_reduce_max" => {
                clif_emit_simd_reduce_lanes(builder, kind, op, &lanes)
            }
            "_any" => {
                let mut pred = clif_emit_simd_mask_pred(builder, lanes[0].clone());
                for lane in lanes.iter().skip(1) {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    pred = builder.ins().bor(pred, lane_pred);
                }
                Ok(bool_to_i8(builder, pred))
            }
            "_all" => {
                let mut pred = clif_emit_simd_mask_pred(builder, lanes[0].clone());
                for lane in lanes.iter().skip(1) {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    pred = builder.ins().band(pred, lane_pred);
                }
                Ok(bool_to_i8(builder, pred))
            }
            "_none" => {
                let mut pred = clif_emit_simd_mask_pred(builder, lanes[0].clone());
                for lane in lanes.iter().skip(1) {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    pred = builder.ins().bor(pred, lane_pred);
                }
                let zero = builder.ins().iconst(types::I8, 0);
                let not_pred = builder.ins().icmp(IntCC::Equal, pred, zero);
                Ok(bool_to_i8(builder, not_pred))
            }
            "_bitmask" => {
                let mut mask = builder.ins().iconst(types::I32, 0);
                for (index, lane) in lanes.iter().enumerate() {
                    let lane_pred = clif_emit_simd_mask_pred(builder, lane.clone());
                    let bit = bool_to_i8(builder, lane_pred);
                    let wide = builder.ins().uextend(types::I32, bit.value);
                    let shifted = if index == 0 {
                        wide
                    } else {
                        builder.ins().ishl_imm(wide, index as i64)
                    };
                    mask = builder.ins().bor(mask, shifted);
                }
                Ok(ClifValue {
                    value: mask,
                    ty: types::I32,
                })
            }
            "_lane0" | "_lane1" | "_lane2" | "_lane3" => {
                let index = match op {
                    "_lane0" => 0,
                    "_lane1" => 1,
                    "_lane2" => 2,
                    _ => 3,
                };
                if kind == "mask32x4" {
                    let pred = clif_emit_simd_mask_pred(builder, lanes[index].clone());
                    Ok(bool_to_i8(builder, pred))
                } else {
                    Ok(lanes[index].clone())
                }
            }
            _ => unreachable!(),
        };
    }

    if op == "_select" {
        let mask_vec = cast_clif_value(
            builder,
            lowered[0],
            clif_simd_vector_type("mask32x4").unwrap_or(types::I32X4),
        )?;
        let then_bits = cast_clif_value(builder, lowered[1], types::I32X4)?;
        let else_bits = cast_clif_value(builder, lowered[2], types::I32X4)?;
        let inverted_mask = builder.ins().bnot(mask_vec.value);
        let masked_then = builder.ins().band(mask_vec.value, then_bits.value);
        let masked_else = builder.ins().band(inverted_mask, else_bits.value);
        let blended_bits = builder.ins().bor(masked_then, masked_else);
        return if kind == "f32x4" {
            Ok(ClifValue {
                value: builder.ins().bitcast(vec_ty, MemFlags::new(), blended_bits),
                ty: vec_ty,
            })
        } else {
            Ok(ClifValue {
                value: blended_bits,
                ty: vec_ty,
            })
        };
    }

    let lhs_lanes = clif_emit_simd_lanes(builder, lowered[0], kind)?;
    let rhs_lanes = if lowered.len() > 1 {
        Some(clif_emit_simd_lanes(builder, lowered[1], kind)?)
    } else {
        None
    };
    let shift_amount = if matches!(op, "_shl" | "_shr") {
        let shift_expr = clif_emit_expr(builder, ctx, &args[1], locals, next_var)?;
        Some(cast_clif_value(builder, shift_expr, types::I32)?)
    } else {
        None
    };
    let shuffle_selectors = if op == "_shuffle" {
        let mut selectors = Vec::with_capacity(4);
        for lane_index in 0..4 {
            let selector_expr =
                clif_emit_expr(builder, ctx, &args[lane_index + 2], locals, next_var)?;
            selectors.push(cast_clif_value(builder, selector_expr, types::I32)?);
        }
        Some(selectors)
    } else {
        None
    };
    let mut out_lanes = Vec::with_capacity(4);
    for lane_index in 0..4 {
        let lhs_lane = lhs_lanes[lane_index].clone();
        let lane = match op {
            "_add" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fadd(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().iadd(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_sub" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fsub(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().isub(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_mul" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fmul(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().imul(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_min" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fmin(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                "u32x4" => ClifValue {
                    value: builder.ins().umin(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().smin(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_max" => match kind {
                "f32x4" => ClifValue {
                    value: builder.ins().fmax(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                "u32x4" => ClifValue {
                    value: builder.ins().umax(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
                _ => ClifValue {
                    value: builder.ins().smax(
                        lhs_lane.value,
                        rhs_lanes.as_ref().unwrap()[lane_index].value,
                    ),
                    ty: lane_ty,
                },
            },
            "_and" => ClifValue {
                value: builder.ins().band(
                    lhs_lane.value,
                    rhs_lanes.as_ref().unwrap()[lane_index].value,
                ),
                ty: lane_ty,
            },
            "_or" => ClifValue {
                value: builder.ins().bor(
                    lhs_lane.value,
                    rhs_lanes.as_ref().unwrap()[lane_index].value,
                ),
                ty: lane_ty,
            },
            "_xor" => ClifValue {
                value: builder.ins().bxor(
                    lhs_lane.value,
                    rhs_lanes.as_ref().unwrap()[lane_index].value,
                ),
                ty: lane_ty,
            },
            "_not" => ClifValue {
                value: builder.ins().bnot(lhs_lane.value),
                ty: lane_ty,
            },
            "_shl" => {
                let amount = shift_amount
                    .clone()
                    .ok_or_else(|| anyhow!("missing cranelift simd shift amount"))?;
                ClifValue {
                    value: builder.ins().ishl(lhs_lane.value, amount.value),
                    ty: lane_ty,
                }
            }
            "_shr" => {
                let amount = shift_amount
                    .clone()
                    .ok_or_else(|| anyhow!("missing cranelift simd shift amount"))?;
                let value = if kind == "u32x4" {
                    builder.ins().ushr(lhs_lane.value, amount.value)
                } else {
                    builder.ins().sshr(lhs_lane.value, amount.value)
                };
                ClifValue { value, ty: lane_ty }
            }
            "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" => clif_emit_simd_compare_lane(
                builder,
                kind,
                op,
                lhs_lane,
                rhs_lanes.as_ref().unwrap()[lane_index].clone(),
            )?,
            "_select" => {
                bail!("cranelift lane-wise simd select should have been handled earlier")
            }
            "_shuffle" => {
                let selector = shuffle_selectors
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing cranelift simd shuffle selectors"))?
                    [lane_index]
                    .clone();
                let mut candidates = lhs_lanes.clone();
                candidates.extend(rhs_lanes.as_ref().unwrap().iter().cloned());
                clif_emit_simd_shuffle_lane(builder, selector, &candidates)?
            }
            "_saturating_add" | "_saturating_sub" => clif_emit_simd_saturating_lane(
                builder,
                kind,
                op,
                lhs_lane,
                rhs_lanes.as_ref().unwrap()[lane_index].clone(),
            )?,
            _ => bail!("unsupported cranelift simd op `{kind}{op}`"),
        };
        out_lanes.push(lane);
    }
    let result_kind = if matches!(op, "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge") {
        "mask32x4"
    } else {
        kind
    };
    clif_emit_simd_vector_from_lanes(builder, result_kind, &out_lanes)
}

fn clif_parse_simd_store_wrapper(callee: &str) -> Option<&'static str> {
    match callee {
        "simd.i32x4_store" => Some("i32x4"),
        "simd.u32x4_store" => Some("u32x4"),
        "simd.f32x4_store" => Some("f32x4"),
        "simd.mask32x4_store" => Some("mask32x4"),
        _ => None,
    }
}

fn clif_materialize_simd_store_binding(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    name: &str,
    kind: &str,
    value_expr: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let vector = clif_emit_expr(builder, ctx, value_expr, locals, next_var)?;
    let lanes = clif_emit_simd_lanes(builder, vector, kind)?;
    let (element_ty, element_bits, element_align, element_stride): (ClifType, u16, u8, u8) =
        match kind {
            "i32x4" | "u32x4" | "f32x4" => {
                (clif_simd_lane_type(kind).unwrap_or(types::I32), 32, 4, 4)
            }
            "mask32x4" => (types::I8, 8, 1, 1),
            _ => bail!("unsupported simd store wrapper `{kind}`"),
        };
    let slot_size = 4u32 * u32::from(element_stride);
    let align_shift = element_align.trailing_zeros() as u8;
    let stack_slot = builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
        cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
        slot_size,
        align_shift,
    ));
    for (idx, lane) in lanes.into_iter().enumerate() {
        let stored = if kind == "mask32x4" {
            let pred = clif_emit_simd_mask_pred(builder, lane);
            let one = builder.ins().iconst(types::I8, 1);
            let zero = builder.ins().iconst(types::I8, 0);
            ClifValue {
                value: builder.ins().select(pred, one, zero),
                ty: types::I8,
            }
        } else {
            cast_clif_value(builder, lane, element_ty)?
        };
        let ptr = builder.ins().stack_addr(
            pointer_sized_clif_type(),
            stack_slot,
            (idx as i32) * i32::from(element_stride),
        );
        builder.ins().store(MemFlags::new(), stored.value, ptr, 0);
    }
    ctx.array_bindings.insert(
        name.to_string(),
        ClifArrayBinding {
            stack_slot,
            len: 4,
            element_ty,
            element_bits,
            element_align,
            element_stride,
        },
    );
    let ptr = builder
        .ins()
        .stack_addr(pointer_sized_clif_type(), stack_slot, 0);
    clif_bind_local(
        builder,
        locals,
        next_var,
        name,
        pointer_sized_clif_type(),
        ptr,
    );
    ctx.aggregate_bindings.remove(name);
    ctx.const_strings.remove(name);
    ctx.closures.remove(name);
    Ok(())
}

fn clif_emit_array_argument_pointer(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    arg: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<Option<ClifValue>> {
    match arg {
        ast::Expr::Ident(name) => {
            if matches!(ctx.local_types.get(name), Some(ast::Type::Array { .. })) {
                if let Some(binding) = locals.get(name).copied() {
                    return Ok(Some(ClifValue {
                        value: builder.use_var(binding.var),
                        ty: binding.ty,
                    }));
                }
            }
            if let Some(binding) = ctx.array_bindings.get(name) {
                return Ok(Some(ClifValue {
                    value: builder.ins().stack_addr(
                        pointer_sized_clif_type(),
                        binding.stack_slot,
                        0,
                    ),
                    ty: pointer_sized_clif_type(),
                }));
            }
            Ok(None)
        }
        ast::Expr::ArrayLiteral(items) => {
            let mut lowered_items = Vec::with_capacity(items.len());
            for item in items {
                lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
            }
            let (element_ty, _element_bits, element_align, element_stride) =
                clif_array_layout_from_values(&lowered_items);
            let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
            let align_shift = element_align.trailing_zeros() as u8;
            let stack_slot =
                builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                    cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                    slot_size,
                    align_shift,
                ));
            for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                item_val = cast_clif_value(builder, item_val, element_ty)?;
                let ptr = builder.ins().stack_addr(
                    pointer_sized_clif_type(),
                    stack_slot,
                    (idx as i32) * i32::from(element_stride),
                );
                builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
            }
            Ok(Some(ClifValue {
                value: builder
                    .ins()
                    .stack_addr(pointer_sized_clif_type(), stack_slot, 0),
                ty: pointer_sized_clif_type(),
            }))
        }
        ast::Expr::Call { callee, args } => {
            if let Some(kind) = clif_parse_simd_store_wrapper(callee) {
                if let Some(vector_expr) = args.first() {
                    let vector = clif_emit_expr(builder, ctx, vector_expr, locals, next_var)?;
                    let lanes = clif_emit_simd_lanes(builder, vector, kind)?;
                    let (element_ty, element_align, element_stride): (ClifType, u8, u8) = match kind
                    {
                        "i32x4" | "u32x4" | "f32x4" => {
                            (clif_simd_lane_type(kind).unwrap_or(types::I32), 4, 4)
                        }
                        "mask32x4" => (types::I8, 1, 1),
                        _ => bail!("unsupported simd store wrapper `{kind}`"),
                    };
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            4u32 * u32::from(element_stride),
                            element_align.trailing_zeros() as u8,
                        ));
                    for (idx, lane) in lanes.into_iter().enumerate() {
                        let stored = if kind == "mask32x4" {
                            let pred = clif_emit_simd_mask_pred(builder, lane);
                            let one = builder.ins().iconst(types::I8, 1);
                            let zero = builder.ins().iconst(types::I8, 0);
                            ClifValue {
                                value: builder.ins().select(pred, one, zero),
                                ty: types::I8,
                            }
                        } else {
                            cast_clif_value(builder, lane, element_ty)?
                        };
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), stored.value, ptr, 0);
                    }
                    return Ok(Some(ClifValue {
                        value: builder
                            .ins()
                            .stack_addr(pointer_sized_clif_type(), stack_slot, 0),
                        ty: pointer_sized_clif_type(),
                    }));
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn clif_create_stack_slot_for_array_abi(
    builder: &mut FunctionBuilder,
    abi: ClifArrayAbi,
) -> cranelift_codegen::ir::StackSlot {
    let slot_size = (abi.len as u32) * u32::from(abi.element_stride);
    builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
        cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
        slot_size,
        abi.element_align.trailing_zeros() as u8,
    ))
}

fn clif_copy_array_memory(
    builder: &mut FunctionBuilder,
    src_ptr: cranelift_codegen::ir::Value,
    dest_ptr: cranelift_codegen::ir::Value,
    abi: ClifArrayAbi,
) {
    for index in 0..abi.len {
        let offset = (index as i32) * i32::from(abi.element_stride);
        let src_addr = if offset == 0 {
            src_ptr
        } else {
            builder.ins().iadd_imm(src_ptr, i64::from(offset))
        };
        let dest_addr = if offset == 0 {
            dest_ptr
        } else {
            builder.ins().iadd_imm(dest_ptr, i64::from(offset))
        };
        let loaded = builder
            .ins()
            .load(abi.element_ty, MemFlags::new(), src_addr, 0);
        builder.ins().store(MemFlags::new(), loaded, dest_addr, 0);
    }
}

fn clif_zero_fill_array_memory(
    builder: &mut FunctionBuilder,
    dest_ptr: cranelift_codegen::ir::Value,
    abi: ClifArrayAbi,
) {
    let zero = zero_for_type(builder, abi.element_ty);
    for index in 0..abi.len {
        let offset = (index as i32) * i32::from(abi.element_stride);
        let dest_addr = if offset == 0 {
            dest_ptr
        } else {
            builder.ins().iadd_imm(dest_ptr, i64::from(offset))
        };
        builder.ins().store(MemFlags::new(), zero, dest_addr, 0);
    }
}

fn clif_emit_array_expr_to_ptr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    expr: &ast::Expr,
    dest_ptr: cranelift_codegen::ir::Value,
    abi: ClifArrayAbi,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    match expr {
        ast::Expr::Ident(name) => {
            if let Some(binding) = ctx.array_bindings.get(name) {
                let src_ptr =
                    builder
                        .ins()
                        .stack_addr(pointer_sized_clif_type(), binding.stack_slot, 0);
                clif_copy_array_memory(builder, src_ptr, dest_ptr, abi);
                return Ok(());
            }
            if matches!(ctx.local_types.get(name), Some(ast::Type::Array { .. })) {
                if let Some(binding) = locals.get(name).copied() {
                    let src_ptr = builder.use_var(binding.var);
                    clif_copy_array_memory(builder, src_ptr, dest_ptr, abi);
                    return Ok(());
                }
            }
        }
        ast::Expr::ArrayLiteral(items) => {
            for (index, item) in items.iter().take(abi.len).enumerate() {
                let item_value = clif_emit_expr(builder, ctx, item, locals, next_var)?;
                let lowered = cast_clif_value(builder, item_value, abi.element_ty)?;
                let offset = (index as i32) * i32::from(abi.element_stride);
                let addr = if offset == 0 {
                    dest_ptr
                } else {
                    builder.ins().iadd_imm(dest_ptr, i64::from(offset))
                };
                builder.ins().store(MemFlags::new(), lowered.value, addr, 0);
            }
            let zero = zero_for_type(builder, abi.element_ty);
            for index in items.len()..abi.len {
                let offset = (index as i32) * i32::from(abi.element_stride);
                let addr = if offset == 0 {
                    dest_ptr
                } else {
                    builder.ins().iadd_imm(dest_ptr, i64::from(offset))
                };
                builder.ins().store(MemFlags::new(), zero, addr, 0);
            }
            return Ok(());
        }
        ast::Expr::Call { callee, args } => {
            if let Some(kind) = clif_parse_simd_store_wrapper(callee) {
                if let Some(vector_expr) = args.first() {
                    let vector = clif_emit_expr(builder, ctx, vector_expr, locals, next_var)?;
                    let lanes = clif_emit_simd_lanes(builder, vector, kind)?;
                    for (index, lane) in lanes.into_iter().enumerate().take(abi.len) {
                        let stored = if kind == "mask32x4" {
                            let pred = clif_emit_simd_mask_pred(builder, lane);
                            let one = builder.ins().iconst(types::I8, 1);
                            let zero = builder.ins().iconst(types::I8, 0);
                            ClifValue {
                                value: builder.ins().select(pred, one, zero),
                                ty: types::I8,
                            }
                        } else {
                            cast_clif_value(builder, lane, abi.element_ty)?
                        };
                        let offset = (index as i32) * i32::from(abi.element_stride);
                        let addr = if offset == 0 {
                            dest_ptr
                        } else {
                            builder.ins().iadd_imm(dest_ptr, i64::from(offset))
                        };
                        builder.ins().store(MemFlags::new(), stored.value, addr, 0);
                    }
                    return Ok(());
                }
            }
            if let Some(function_id) = ctx.function_ids.get(callee).copied() {
                if let Some(signature) = ctx.function_signatures.get(callee) {
                    if signature.sret.is_some() {
                        let mut values = Vec::with_capacity(args.len() + 1);
                        values.push(dest_ptr);
                        for (index, arg) in args.iter().enumerate() {
                            let target = signature.params.get(index + 1).copied();
                            let mut lowered = if target == Some(pointer_sized_clif_type()) {
                                if let Some(array_ptr) = clif_emit_array_argument_pointer(
                                    builder, ctx, arg, locals, next_var,
                                )? {
                                    array_ptr
                                } else {
                                    clif_emit_expr(builder, ctx, arg, locals, next_var)?
                                }
                            } else {
                                clif_emit_expr(builder, ctx, arg, locals, next_var)?
                            };
                            if let Some(target) = target {
                                lowered = cast_clif_value(builder, lowered, target)?;
                            }
                            values.push(lowered.value);
                        }
                        let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
                        let _ = builder.ins().call(func_ref, &values);
                        return Ok(());
                    }
                }
            }
        }
        _ => {}
    }

    let lowered = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
    let src_ptr = cast_clif_value(builder, lowered, pointer_sized_clif_type())?.value;
    clif_copy_array_memory(builder, src_ptr, dest_ptr, abi);
    Ok(())
}

fn clif_emit_aggregate_handle(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    tag: i32,
    items: &[ClifValue],
) -> Result<ClifValue> {
    let agg_new_id = ctx
        .function_ids
        .get(NATIVE_AGG_NEW)
        .copied()
        .ok_or_else(|| anyhow!("missing runtime import lowering for `{NATIVE_AGG_NEW}`"))?;
    let agg_set_id = ctx
        .function_ids
        .get(NATIVE_AGG_SET_I64)
        .copied()
        .ok_or_else(|| anyhow!("missing runtime import lowering for `{NATIVE_AGG_SET_I64}`"))?;
    let new_ref = ctx.module.declare_func_in_func(agg_new_id, builder.func);
    let tag_value = builder.ins().iconst(types::I32, i64::from(tag));
    let count_value = builder.ins().iconst(types::I32, items.len() as i64);
    let handle_call = builder.ins().call(new_ref, &[tag_value, count_value]);
    let handle = builder.inst_results(handle_call)[0];
    let set_ref = ctx.module.declare_func_in_func(agg_set_id, builder.func);
    for (index, item) in items.iter().cloned().enumerate() {
        let raw = clif_cast_scalar_to_i64(builder, item)?;
        let index_value = builder.ins().iconst(types::I32, index as i64);
        let _ = builder
            .ins()
            .call(set_ref, &[handle, index_value, raw.value]);
    }
    Ok(ClifValue {
        value: handle,
        ty: types::I64,
    })
}

fn clif_emit_aggregate_get(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    handle: ClifValue,
    index: usize,
    target_ty: ClifType,
) -> Result<ClifValue> {
    let agg_get_id = ctx
        .function_ids
        .get(NATIVE_AGG_GET_I64)
        .copied()
        .ok_or_else(|| anyhow!("missing runtime import lowering for `{NATIVE_AGG_GET_I64}`"))?;
    let agg_get_ref = ctx.module.declare_func_in_func(agg_get_id, builder.func);
    let index_value = builder.ins().iconst(types::I32, index as i64);
    let raw_call = builder
        .ins()
        .call(agg_get_ref, &[handle.value, index_value]);
    let raw = builder.inst_results(raw_call)[0];
    clif_cast_i64_to_ty(builder, raw, target_ty)
}

fn clif_record_aggregate_binding(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    name: &str,
    value: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let mut binding = ClifAggregateBinding::default();
    match value {
        ast::Expr::StructInit { fields, .. } => {
            for (index, (field, field_expr)) in fields.iter().enumerate() {
                let field_value = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                binding.items.insert(
                    field.clone(),
                    ClifAggregateItemBinding {
                        index,
                        ty: field_value.ty,
                    },
                );
            }
        }
        ast::Expr::Tuple(items) => {
            for (index, item_expr) in items.iter().enumerate() {
                let item_value = clif_emit_expr(builder, ctx, item_expr, locals, next_var)?;
                binding.items.insert(
                    format!("__tuple{index}"),
                    ClifAggregateItemBinding {
                        index,
                        ty: item_value.ty,
                    },
                );
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for (index, payload_expr) in payload.iter().enumerate() {
                let payload_value = clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                binding.items.insert(
                    format!("__payload{index}"),
                    ClifAggregateItemBinding {
                        index,
                        ty: payload_value.ty,
                    },
                );
            }
            for (offset, (field, field_expr)) in named_payload.iter().enumerate() {
                let field_value = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                binding.items.insert(
                    field.clone(),
                    ClifAggregateItemBinding {
                        index: payload.len() + offset,
                        ty: field_value.ty,
                    },
                );
            }
        }
        _ => {
            ctx.aggregate_bindings.remove(name);
            return Ok(());
        }
    }
    ctx.aggregate_bindings.insert(name.to_string(), binding);
    Ok(())
}

fn clif_tuple_item_binding_for_local(
    name: &str,
    index: usize,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Tuple(items) = ctx.local_types.get(name)? else {
        return None;
    };
    let item_ty = items.get(index)?;
    Some(ClifAggregateItemBinding {
        index,
        ty: ast_signature_type_to_clif_type(item_ty)?,
    })
}

fn clif_struct_field_binding_for_local(
    name: &str,
    field: &str,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    let struct_def = ctx.struct_defs.get(ty_name.as_str())?;
    let (index, struct_field) = struct_def
        .fields
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == field)?;
    Some(ClifAggregateItemBinding {
        index,
        ty: ast_signature_type_to_clif_type(&struct_field.ty)?,
    })
}

fn clif_enum_payload_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    index: usize,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    if ty_name != enum_name {
        return None;
    }
    let enum_def = ctx.enum_defs.get(enum_name)?;
    let variant_def = enum_def.variants.iter().find(|item| item.name == variant)?;
    let payload_ty = variant_def.payload.get(index)?;
    Some(ClifAggregateItemBinding {
        index,
        ty: ast_signature_type_to_clif_type(payload_ty)?,
    })
}

fn clif_enum_named_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    field: &str,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<ClifAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    if ty_name != enum_name {
        return None;
    }
    let enum_def = ctx.enum_defs.get(enum_name)?;
    let variant_def = enum_def.variants.iter().find(|item| item.name == variant)?;
    let (offset, named_field) = variant_def
        .named_payload
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == field)?;
    Some(ClifAggregateItemBinding {
        index: variant_def.payload.len() + offset,
        ty: ast_signature_type_to_clif_type(&named_field.ty)?,
    })
}

fn clif_local_is_aggregate(name: &str, ctx: &ClifLoweringCtx<'_>) -> bool {
    matches!(
        ctx.local_types.get(name),
        Some(ast::Type::Tuple(_)) | Some(ast::Type::Named { .. })
    )
}

pub(super) fn clif_emit_inlined_closure_call(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    binding: ClifClosureBinding,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let mut cast_args = Vec::with_capacity(binding.params.len());
    for (index, param) in binding.params.iter().enumerate() {
        let arg = args.get(index).cloned().unwrap_or(ast::Expr::Int(0));
        let mut lowered = clif_emit_expr(builder, ctx, &arg, locals, next_var)?;
        if let Some(target_ty) = ast_signature_type_to_clif_type(&param.ty) {
            lowered = cast_clif_value(builder, lowered, target_ty)?;
        }
        cast_args.push(lowered);
    }

    let mut saved = HashMap::<String, Option<LocalBinding>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), locals.get(name).copied());
        }
        locals.insert(name.clone(), *capture);
        inserted.insert(name.clone());
    }

    for (index, param) in binding.params.iter().enumerate() {
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), locals.get(&param.name).copied());
        }
        let target_ty = ast_signature_type_to_clif_type(&param.ty).unwrap_or(cast_args[index].ty);
        let var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(var, target_ty);
        let value = cast_clif_value(builder, cast_args[index], target_ty)?;
        builder.def_var(var, value.value);
        locals.insert(param.name.clone(), LocalBinding { var, ty: target_ty });
        inserted.insert(param.name.clone());
    }

    let mut result = clif_emit_expr(builder, ctx, &binding.body, locals, next_var)?;
    if let Some(return_ty) = &binding.return_type {
        if let Some(target_ty) = ast_signature_type_to_clif_type(return_ty) {
            result = cast_clif_value(builder, result, target_ty)?;
        }
    }
    clif_restore_shadowed_locals(locals, saved, inserted);
    Ok(result)
}

pub(super) fn clif_emit_let_pattern(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    pattern: &ast::Pattern,
    value: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let lowered = clif_emit_expr(builder, ctx, value, locals, next_var)?;
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let var = Variable::from_u32(*next_var as u32);
            *next_var += 1;
            builder.declare_var(var, lowered.ty);
            builder.def_var(var, lowered.value);
            locals.insert(
                name.clone(),
                LocalBinding {
                    var,
                    ty: lowered.ty,
                },
            );
        }
        ast::Pattern::Tuple(items) => {
            if let ast::Expr::Tuple(values) = value {
                if items.len() != values.len() {
                    bail!("native backend requires tuple pattern arity to match tuple initializer arity");
                }
                for (item, value) in items.iter().zip(values.iter()) {
                    clif_emit_let_pattern(builder, ctx, item, value, locals, next_var)?;
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, item) in items.iter().enumerate() {
                    let synthetic = format!("{name}.__tuple{index}");
                    if locals.contains_key(&synthetic) {
                        clif_emit_let_pattern(
                            builder,
                            ctx,
                            item,
                            &ast::Expr::Ident(synthetic),
                            locals,
                            next_var,
                        )?;
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&format!("__tuple{index}")).cloned())
                            .or_else(|| clif_tuple_item_binding_for_local(name, index, ctx))
                            .ok_or_else(|| anyhow!("native backend requires tuple-bound aggregate metadata for `let` tuple destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let temp_name = format!("__agg_tuple_extract_{}_{}", name, index);
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            temp_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                        clif_emit_let_pattern(
                            builder,
                            ctx,
                            item,
                            &ast::Expr::Ident(temp_name),
                            locals,
                            next_var,
                        )?;
                    }
                }
            } else {
                bail!("native backend requires tuple initializer or tuple-bound local for `let` tuple destructuring");
            }
        }
        ast::Pattern::Int(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, *expected as i64);
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Bool(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, i64::from(*expected));
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Struct { name, fields } => {
            if let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = value
            {
                if value_name != name {
                    bail!(
                        "native backend requires exact literal struct type match for `let` struct destructuring"
                    );
                }
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    let Some((_, field_expr)) =
                        value_fields.iter().find(|(field, _)| field == field_name)
                    else {
                        bail!("native backend requires struct literal fields to cover every bound pattern field");
                    };
                    let payload_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, payload_val.ty);
                    builder.def_var(var, payload_val.value);
                    locals.insert(
                        binding_name.clone(),
                        LocalBinding {
                            var,
                            ty: payload_val.ty,
                        },
                    );
                }
            } else if let ast::Expr::Ident(name) = value {
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some(binding) = locals.get(&format!("{name}.{field_name}")).copied() {
                        locals.insert(binding_name.clone(), binding);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| clif_struct_field_binding_for_local(name, field_name, ctx))
                            .ok_or_else(|| anyhow!("native backend requires struct-bound aggregate metadata for `let` struct destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                    }
                }
            } else {
                bail!("native backend requires struct initializer or struct-bound local for `let` struct destructuring");
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } => {
            let key = format!("{enum_name}::{variant}");
            let (cmp_ty, cmp_value) = if lowered.ty == types::I64 {
                let agg_tag_id =
                    ctx.function_ids
                        .get(NATIVE_AGG_TAG)
                        .copied()
                        .ok_or_else(|| {
                            anyhow!("missing runtime import lowering for `{NATIVE_AGG_TAG}`")
                        })?;
                let agg_tag_ref = ctx.module.declare_func_in_func(agg_tag_id, builder.func);
                let tag_call = builder.ins().call(agg_tag_ref, &[lowered.value]);
                (types::I32, builder.inst_results(tag_call)[0])
            } else {
                (lowered.ty, lowered.value)
            };
            let expected_tag = builder
                .ins()
                .iconst(cmp_ty, variant_tag_for_key(&key, ctx.variant_tags) as i64);
            let _ = builder.ins().icmp(IntCC::Equal, cmp_value, expected_tag);
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
                named_payload,
                ..
            } = value
            {
                if value_enum == enum_name
                    && value_variant == variant
                    && payload.len() == bindings.len()
                {
                    for (binding_name, payload_expr) in bindings.iter().zip(payload.iter()) {
                        let payload_val =
                            clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, payload_val.ty);
                        builder.def_var(var, payload_val.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                    for (field_name, binding_name) in named_bindings {
                        if binding_name == "_" {
                            continue;
                        }
                        let Some((_, field_expr)) =
                            named_payload.iter().find(|(field, _)| field == field_name)
                        else {
                            bail!("native backend requires enum literal named payload fields to cover every bound pattern field");
                        };
                        let payload_val =
                            clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, payload_val.ty);
                        builder.def_var(var, payload_val.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, binding_name) in bindings.iter().enumerate() {
                    let key = format!("{name}.__payload{index}");
                    if let Some(binding) = locals.get(&key).copied() {
                        locals.insert(binding_name.clone(), binding);
                    } else {
                        let payload_key = format!("__payload{index}");
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&payload_key).cloned())
                            .or_else(|| {
                                clif_enum_payload_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    index,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local payloads for `let` variant destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                    }
                }
                for (field_name, binding_name) in named_bindings {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some(binding) = locals.get(&format!("{name}.{field_name}")).copied() {
                        locals.insert(binding_name.clone(), binding);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| {
                                clif_enum_named_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    field_name,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local named payloads for `let` variant destructuring"))?;
                        let handle = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                        let extracted = clif_emit_aggregate_get(
                            builder,
                            ctx,
                            handle,
                            item_binding.index,
                            item_binding.ty,
                        )?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, extracted.ty);
                        builder.def_var(var, extracted.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: extracted.ty,
                            },
                        );
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, value, ctx.variant_tags)
            }) {
                return clif_emit_let_pattern(builder, ctx, matched, value, locals, next_var);
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable initializer for payload or struct-field bindings in `let` or-patterns"
                );
            }
        }
    }
    Ok(())
}

pub(super) fn clif_emit_linear_stmts(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    body: &[ast::Stmt],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<bool> {
    let mut deferred = Vec::<ast::Expr>::new();
    for stmt in body {
        match stmt {
            ast::Stmt::Let {
                name, value, ty, ..
            } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(name.clone(), const_value);
                    ctx.array_bindings.remove(name);
                    ctx.aggregate_bindings.remove(name);
                }
                if let ast::Expr::Call { callee, args } = value {
                    if let Some(kind) = clif_parse_simd_store_wrapper(callee) {
                        if let Some(vector_expr) = args.first() {
                            clif_materialize_simd_store_binding(
                                builder,
                                ctx,
                                name,
                                kind,
                                vector_expr,
                                locals,
                                next_var,
                            )?;
                            continue;
                        }
                    }
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        name.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    let ptr = builder
                        .ins()
                        .stack_addr(pointer_sized_clif_type(), stack_slot, 0);
                    clif_bind_local(
                        builder,
                        locals,
                        next_var,
                        name,
                        pointer_sized_clif_type(),
                        ptr,
                    );
                    ctx.aggregate_bindings.remove(name);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = ctx.local_types.get(source).cloned() {
                        ctx.local_types.insert(name.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(name.clone(), binding);
                    }
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(name.clone(), source_bindings);
                        if let Some(binding) = locals.get(source).copied() {
                            locals.insert(name.clone(), binding);
                        }
                        continue;
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        name.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    ctx.aggregate_bindings.remove(name);
                    continue;
                }
                let mut val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                let target_ty = ty
                    .as_ref()
                    .and_then(ast_signature_type_to_clif_type)
                    .unwrap_or(val.ty);
                val = cast_clif_value(builder, val, target_ty)?;
                let binding = if let Some(existing) = locals.get(name).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, target_ty);
                    let binding = LocalBinding { var, ty: target_ty };
                    locals.insert(name.clone(), binding);
                    binding
                };
                let val = cast_clif_value(builder, val, binding.ty)?;
                builder.def_var(binding.var, val.value);
                clif_record_aggregate_binding(builder, ctx, name, value, locals, next_var)?;
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::Tuple(items) = value {
                    for (index, item_expr) in items.iter().enumerate() {
                        let item_val = clif_emit_expr(builder, ctx, item_expr, locals, next_var)?;
                        let item_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(item_var, item_val.ty);
                        builder.def_var(item_var, item_val.value);
                        locals.insert(
                            format!("{name}.__tuple{index}"),
                            LocalBinding {
                                var: item_var,
                                ty: item_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::EnumInit {
                    enum_name: _,
                    variant: _,
                    payload,
                    named_payload,
                } = value
                {
                    for (index, payload_expr) in payload.iter().enumerate() {
                        let payload_val =
                            clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                        let payload_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(payload_var, payload_val.ty);
                        builder.def_var(payload_var, payload_val.value);
                        locals.insert(
                            format!("{name}.__payload{index}"),
                            LocalBinding {
                                var: payload_var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                    for (field, field_expr) in named_payload {
                        let field_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                    let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                    let inclusive_val = ClifValue {
                        value: builder
                            .ins()
                            .iconst(default_int_clif_type(), i64::from(*inclusive)),
                        ty: default_int_clif_type(),
                    };
                    for (field, field_val) in [
                        ("start", start_val),
                        ("end", end_val),
                        ("inclusive", inclusive_val),
                    ] {
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                ctx.array_bindings.remove(name);
                ctx.const_strings.remove(name);
                ctx.closures.remove(name);
            }
            ast::Stmt::LetPattern { pattern, value, .. } => {
                clif_emit_let_pattern(builder, ctx, pattern, value, locals, next_var)?;
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(target.clone(), const_value);
                    ctx.array_bindings.remove(target);
                    ctx.aggregate_bindings.remove(target);
                }
                if let ast::Expr::Call { callee, args } = value {
                    if let Some(kind) = clif_parse_simd_store_wrapper(callee) {
                        if let Some(vector_expr) = args.first() {
                            clif_materialize_simd_store_binding(
                                builder,
                                ctx,
                                target,
                                kind,
                                vector_expr,
                                locals,
                                next_var,
                            )?;
                            continue;
                        }
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        target.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    ctx.aggregate_bindings.remove(target);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        target.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    let ptr = builder
                        .ins()
                        .stack_addr(pointer_sized_clif_type(), stack_slot, 0);
                    clif_bind_local(
                        builder,
                        locals,
                        next_var,
                        target,
                        pointer_sized_clif_type(),
                        ptr,
                    );
                    ctx.aggregate_bindings.remove(target);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = ctx.local_types.get(source).cloned() {
                        ctx.local_types.insert(target.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(target.clone(), binding);
                    }
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(target.clone(), source_bindings);
                        if let Some(binding) = locals.get(source).copied() {
                            locals.insert(target.clone(), binding);
                        }
                        continue;
                    }
                }
                let val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                    clif_record_aggregate_binding(builder, ctx, target, value, locals, next_var)?;
                    if let ast::Expr::StructInit { fields, .. } = value {
                        for (field, field_expr) in fields {
                            let field_val =
                                clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::Tuple(items) = value {
                        for (index, item_expr) in items.iter().enumerate() {
                            let item_val =
                                clif_emit_expr(builder, ctx, item_expr, locals, next_var)?;
                            let item_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(item_var, item_val.ty);
                            builder.def_var(item_var, item_val.value);
                            locals.insert(
                                format!("{target}.__tuple{index}"),
                                LocalBinding {
                                    var: item_var,
                                    ty: item_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::EnumInit {
                        enum_name: _,
                        variant: _,
                        payload,
                        named_payload,
                    } = value
                    {
                        for (index, payload_expr) in payload.iter().enumerate() {
                            let payload_val =
                                clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                            let payload_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(payload_var, payload_val.ty);
                            builder.def_var(payload_var, payload_val.value);
                            locals.insert(
                                format!("{target}.__payload{index}"),
                                LocalBinding {
                                    var: payload_var,
                                    ty: payload_val.ty,
                                },
                            );
                        }
                        for (field, field_expr) in named_payload {
                            let field_val =
                                clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::Range {
                        start,
                        end,
                        inclusive,
                    } = value
                    {
                        let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                        let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                        let inclusive_val = ClifValue {
                            value: builder
                                .ins()
                                .iconst(default_int_clif_type(), i64::from(*inclusive)),
                            ty: default_int_clif_type(),
                        };
                        for (field, field_val) in [
                            ("start", start_val),
                            ("end", end_val),
                            ("inclusive", inclusive_val),
                        ] {
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::CompoundAssign { target, op, value } => {
                let combined_expr = ast::Expr::Binary {
                    op: *op,
                    left: Box::new(ast::Expr::Ident(target.clone())),
                    right: Box::new(value.clone()),
                };
                let val = clif_emit_expr(builder, ctx, &combined_expr, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
                ctx.aggregate_bindings.remove(target);
            }
            ast::Stmt::Defer(expr) => {
                deferred.push(expr.clone());
            }
            ast::Stmt::Expr(expr) | ast::Stmt::Requires(expr) | ast::Stmt::Ensures(expr) => {
                let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
            }
            ast::Stmt::Return(value) => {
                match (value, ctx.current_return_ty) {
                    (Some(expr), _) if ctx.current_return_array.is_some() => {
                        let return_array = ctx.current_return_array.unwrap();
                        let return_ptr = ctx
                            .current_return_ptr
                            .ok_or_else(|| anyhow!("missing cranelift array return pointer"))?;
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
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[]);
                    }
                    (Some(expr), Some(ret_ty)) => {
                        let lowered = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        let lowered = cast_clif_value(builder, lowered, ret_ty)?;
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[lowered.value]);
                    }
                    (Some(expr), None) => {
                        let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[]);
                    }
                    (None, _) if ctx.current_return_array.is_some() => {
                        let return_array = ctx.current_return_array.unwrap();
                        let return_ptr = ctx
                            .current_return_ptr
                            .ok_or_else(|| anyhow!("missing cranelift array return pointer"))?;
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        let dest_ptr = builder.use_var(return_ptr.var);
                        clif_zero_fill_array_memory(builder, dest_ptr, return_array);
                        builder.ins().return_(&[]);
                    }
                    (None, Some(ret_ty)) => {
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        let fallback = zero_for_type(builder, ret_ty);
                        builder.ins().return_(&[fallback]);
                    }
                    (None, None) => {
                        for expr in deferred.iter().rev() {
                            let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                        }
                        builder.ins().return_(&[]);
                    }
                }
                return Ok(true);
            }
            ast::Stmt::If { .. }
            | ast::Stmt::While { .. }
            | ast::Stmt::For { .. }
            | ast::Stmt::ForIn { .. }
            | ast::Stmt::Loop { .. }
            | ast::Stmt::Break(_)
            | ast::Stmt::Continue
            | ast::Stmt::Match { .. } => {
                bail!("cranelift linear emission received non-linear control-flow statement");
            }
        }
    }
    for expr in deferred.iter().rev() {
        let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
    }
    Ok(false)
}

pub(super) fn clif_emit_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    expr: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    Ok(match expr {
        ast::Expr::Int(v) => {
            let ty = if i32::try_from(*v).is_ok() {
                types::I32
            } else {
                types::I64
            };
            ClifValue {
                value: builder.ins().iconst(ty, *v as i64),
                ty,
            }
        }
        ast::Expr::Float { value, bits } => {
            if bits.unwrap_or(64) == 32 {
                ClifValue {
                    value: builder.ins().f32const(*value as f32),
                    ty: types::F32,
                }
            } else {
                ClifValue {
                    value: builder.ins().f64const(*value),
                    ty: types::F64,
                }
            }
        }
        ast::Expr::Char(v) => ClifValue {
            value: builder.ins().iconst(types::I32, *v as i64),
            ty: types::I32,
        },
        ast::Expr::Bool(v) => ClifValue {
            value: builder.ins().iconst(types::I8, if *v { 1 } else { 0 }),
            ty: types::I8,
        },
        ast::Expr::Str(value) => ClifValue {
            value: builder.ins().iconst(
                pointer_sized_clif_type(),
                ctx.string_literal_ids.get(value).copied().unwrap_or(0) as i64,
            ),
            ty: pointer_sized_clif_type(),
        },
        ast::Expr::Ident(name) => {
            if let Some(binding) = locals.get(name).copied() {
                ClifValue {
                    value: builder.use_var(binding.var),
                    ty: binding.ty,
                }
            } else if let Some(value) =
                resolve_native_global_const_i32_expr(expr, ctx.current_namespace, ctx.globals)
            {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                }
            } else if let Some(data_id) = ctx.mutable_globals.get(name).copied() {
                let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                ClifValue {
                    value: builder.ins().load(types::I32, MemFlags::new(), ptr, 0),
                    ty: types::I32,
                }
            } else if let Some(value) = ctx.globals.get(name).copied() {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                }
            } else if let Some(task_ref) = ctx.task_ref_ids.get(name).copied() {
                ClifValue {
                    value: builder
                        .ins()
                        .iconst(default_int_clif_type(), task_ref as i64),
                    ty: default_int_clif_type(),
                }
            } else {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), 0),
                    ty: default_int_clif_type(),
                }
            }
        }
        ast::Expr::Group(inner) => clif_emit_expr(builder, ctx, inner, locals, next_var)?,
        ast::Expr::Await(inner) => clif_emit_expr(builder, ctx, inner, locals, next_var)?,
        ast::Expr::Discard(inner) => {
            let _ = clif_emit_expr(builder, ctx, inner, locals, next_var)?;
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Closure {
            params,
            return_type,
            body,
        } => {
            let captures = clif_snapshot_closure_captures(builder, locals, next_var);
            let name = format!("__closure_{}", *next_var);
            ctx.closures.insert(
                name,
                ClifClosureBinding {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    body: (**body).clone(),
                    captures,
                },
            );
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Unary { op, expr } => {
            let value = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
            match op {
                ast::UnaryOp::Plus => value,
                ast::UnaryOp::Neg => {
                    if value.ty == types::F32 || value.ty == types::F64 {
                        let zero = if value.ty == types::F32 {
                            builder.ins().f32const(0.0)
                        } else {
                            builder.ins().f64const(0.0)
                        };
                        let lowered = builder.ins().fsub(zero, value.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: value.ty,
                            },
                        )
                    } else {
                        let zero = builder.ins().iconst(value.ty, 0);
                        ClifValue {
                            value: builder.ins().isub(zero, value.value),
                            ty: value.ty,
                        }
                    }
                }
                ast::UnaryOp::Not => {
                    let pred = clif_truthy_pred(builder, value);
                    let pred = builder.ins().bnot(pred);
                    bool_to_i8(builder, pred)
                }
                ast::UnaryOp::BitNot => {
                    if !value.ty.is_int() {
                        bail!("native backend bitwise not requires integer operand");
                    }
                    let all_ones = builder.ins().iconst(value.ty, -1);
                    ClifValue {
                        value: builder.ins().bxor(value.value, all_ones),
                        ty: value.ty,
                    }
                }
            }
        }
        ast::Expr::FieldAccess { base, field } => {
            if let Some(value) =
                resolve_native_global_const_i32_expr(expr, ctx.current_namespace, ctx.globals)
            {
                return Ok(ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                });
            }
            if let Some(field_expr) = resolve_field_expr(base, field) {
                return clif_emit_expr(builder, ctx, &field_expr, locals, next_var);
            }
            if let Some(task_ref_name) = expr_task_ref_name(expr) {
                if let Some(task_ref) = ctx.task_ref_ids.get(&task_ref_name).copied() {
                    return Ok(ClifValue {
                        value: builder
                            .ins()
                            .iconst(default_int_clif_type(), task_ref as i64),
                        ty: default_int_clif_type(),
                    });
                }
            }
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = locals.get(&format!("{name}.{field}")).copied() {
                    ClifValue {
                        value: builder.use_var(binding.var),
                        ty: binding.ty,
                    }
                } else if let Some(binding) = ctx.aggregate_bindings.get(name).cloned() {
                    if let Some(item) = binding.items.get(field) {
                        let handle = clif_emit_expr(builder, ctx, base, locals, next_var)?;
                        return clif_emit_aggregate_get(builder, ctx, handle, item.index, item.ty);
                    } else {
                        clif_emit_expr(builder, ctx, base, locals, next_var)?
                    }
                } else if let Some(item) = clif_struct_field_binding_for_local(name, field, ctx) {
                    let handle = clif_emit_expr(builder, ctx, base, locals, next_var)?;
                    return clif_emit_aggregate_get(builder, ctx, handle, item.index, item.ty);
                } else {
                    clif_emit_expr(builder, ctx, base, locals, next_var)?
                }
            } else {
                clif_emit_expr(builder, ctx, base, locals, next_var)?
            }
        }
        ast::Expr::Tuple(items) => {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
            }
            clif_emit_aggregate_handle(builder, ctx, 0, &rendered)?
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut rendered = Vec::with_capacity(fields.len());
            for (_, value) in fields {
                rendered.push(clif_emit_expr(builder, ctx, value, locals, next_var)?);
            }
            clif_emit_aggregate_handle(builder, ctx, 0, &rendered)?
        }
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => {
            let mut rendered = Vec::with_capacity(payload.len() + named_payload.len());
            for value in payload {
                rendered.push(clif_emit_expr(builder, ctx, value, locals, next_var)?);
            }
            for (_, value) in named_payload {
                rendered.push(clif_emit_expr(builder, ctx, value, locals, next_var)?);
            }
            let key = format!("{enum_name}::{variant}");
            clif_emit_aggregate_handle(
                builder,
                ctx,
                variant_tag_for_key(&key, ctx.variant_tags),
                &rendered,
            )?
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr: _,
        } => clif_emit_expr(builder, ctx, try_expr, locals, next_var)?,
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let cond = clif_emit_expr(builder, ctx, condition, locals, next_var)?;
            let cond_pred = clif_truthy_pred(builder, cond);

            let then_block = builder.create_block();
            let else_block = builder.create_block();
            let merge_block = builder.create_block();
            builder
                .ins()
                .brif(cond_pred, then_block, &[], else_block, &[]);

            builder.switch_to_block(then_block);
            let then_value = clif_emit_expr(builder, ctx, then_expr, locals, next_var)?;
            builder.append_block_param(merge_block, then_value.ty);
            builder.ins().jump(merge_block, &[then_value.value]);

            builder.switch_to_block(else_block);
            let else_value = clif_emit_expr(builder, ctx, else_expr, locals, next_var)?;
            let else_value = cast_clif_value(builder, else_value, then_value.ty)?;
            builder.ins().jump(merge_block, &[else_value.value]);

            builder.seal_block(then_block);
            builder.seal_block(else_block);
            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            ClifValue {
                value: builder.block_params(merge_block)[0],
                ty: then_value.ty,
            }
        }
        ast::Expr::Range { start, .. } => clif_emit_expr(builder, ctx, start, locals, next_var)?,
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                let _ = clif_emit_expr(builder, ctx, item, locals, next_var)?;
            }
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            let map_new = ctx
                .function_ids
                .get("map.new")
                .copied()
                .ok_or_else(|| anyhow!("missing runtime import lowering for `map.new`"))?;
            let map_set = ctx
                .function_ids
                .get("map.set")
                .copied()
                .ok_or_else(|| anyhow!("missing runtime import lowering for `map.set`"))?;
            let map_ref = ctx.module.declare_func_in_func(map_new, builder.func);
            let map_call = builder.ins().call(map_ref, &[]);
            let map_handle = builder.inst_results(map_call)[0];
            let set_ref = ctx.module.declare_func_in_func(map_set, builder.func);
            for (key, value) in fields {
                let key_id = i64::from(ctx.string_literal_ids.get(key).copied().unwrap_or(0));
                let key_value = builder.ins().iconst(default_int_clif_type(), key_id);
                let lowered = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                let lowered = cast_clif_value(builder, lowered, default_int_clif_type())?;
                let _ = builder
                    .ins()
                    .call(set_ref, &[map_handle, key_value, lowered.value]);
            }
            ClifValue {
                value: map_handle,
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Index { base, index } => {
            let index_value =
                if let Some((base_name, offset)) = canonicalize_array_index_window(index) {
                    if let Some(binding) = locals.get(&base_name).copied() {
                        let base_raw = builder.use_var(binding.var);
                        let base = cast_clif_value(
                            builder,
                            ClifValue {
                                value: base_raw,
                                ty: binding.ty,
                            },
                            default_int_clif_type(),
                        )?
                        .value;
                        let value = if offset == 0 {
                            base
                        } else {
                            builder.ins().iadd_imm(base, i64::from(offset))
                        };
                        ClifValue {
                            value,
                            ty: default_int_clif_type(),
                        }
                    } else {
                        let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
                        cast_clif_value(builder, value, default_int_clif_type())?
                    }
                } else {
                    let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
                    cast_clif_value(builder, value, default_int_clif_type())?
                };
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = ctx.array_bindings.get(name) {
                    if binding.len == 0 {
                        return Ok(ClifValue {
                            value: builder.ins().iconst(binding.element_ty, 0),
                            ty: binding.element_ty,
                        });
                    }
                    if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
                        if const_idx >= 0 && (const_idx as usize) < binding.len {
                            let ptr = builder.ins().stack_addr(
                                pointer_sized_clif_type(),
                                binding.stack_slot,
                                const_idx * i32::from(binding.element_stride),
                            );
                            let loaded =
                                builder
                                    .ins()
                                    .load(binding.element_ty, MemFlags::new(), ptr, 0);
                            return Ok(ClifValue {
                                value: loaded,
                                ty: binding.element_ty,
                            });
                        }
                    }
                    let in_block = builder.create_block();
                    let out_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, binding.element_ty);

                    let zero = builder.ins().iconst(default_int_clif_type(), 0);
                    let len_const = builder
                        .ins()
                        .iconst(default_int_clif_type(), binding.len as i64);
                    let nonneg = builder.ins().icmp(
                        IntCC::SignedGreaterThanOrEqual,
                        index_value.value,
                        zero,
                    );
                    let below_len =
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThan, index_value.value, len_const);
                    let in_range = builder.ins().band(nonneg, below_len);
                    builder.ins().brif(in_range, in_block, &[], out_block, &[]);

                    builder.switch_to_block(in_block);
                    let base_ptr =
                        builder
                            .ins()
                            .stack_addr(pointer_sized_clif_type(), binding.stack_slot, 0);
                    let idx_ptr = if pointer_sized_clif_type() == default_int_clif_type() {
                        index_value.value
                    } else {
                        builder
                            .ins()
                            .uextend(pointer_sized_clif_type(), index_value.value)
                    };
                    let byte_offset = builder
                        .ins()
                        .imul_imm(idx_ptr, i64::from(binding.element_stride));
                    let addr = builder.ins().iadd(base_ptr, byte_offset);
                    let loaded = builder
                        .ins()
                        .load(binding.element_ty, MemFlags::new(), addr, 0);
                    builder.ins().jump(merge_block, &[loaded]);

                    builder.switch_to_block(out_block);
                    let zero_default = zero_for_type(builder, binding.element_ty);
                    builder.ins().jump(merge_block, &[zero_default]);

                    builder.seal_block(in_block);
                    builder.seal_block(out_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    let selected = builder.block_params(merge_block)[0];
                    let _ = (
                        binding.element_bits,
                        binding.element_align,
                        binding.element_stride,
                    );
                    return Ok(ClifValue {
                        value: selected,
                        ty: binding.element_ty,
                    });
                }
                if let Some(ast::Type::Array { elem, len }) = ctx.local_types.get(name) {
                    if let Some(ptr_binding) = locals.get(name).copied() {
                        let element_ty = ast_signature_type_to_clif_type(elem.as_ref())
                            .ok_or_else(|| {
                                anyhow!("unsupported array element type for `{name}`")
                            })?;
                        let element_stride = if element_ty == types::I8 {
                            1
                        } else if element_ty == types::I16 {
                            2
                        } else if element_ty == types::I64 || element_ty == types::F64 {
                            8
                        } else {
                            4
                        };
                        if *len == 0 {
                            return Ok(ClifValue {
                                value: builder.ins().iconst(element_ty, 0),
                                ty: element_ty,
                            });
                        }
                        if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
                            if const_idx >= 0 && (const_idx as usize) < *len {
                                let base_ptr = builder.use_var(ptr_binding.var);
                                let addr = if const_idx == 0 {
                                    base_ptr
                                } else {
                                    builder.ins().iadd_imm(
                                        base_ptr,
                                        i64::from(const_idx * i32::from(element_stride)),
                                    )
                                };
                                let loaded =
                                    builder.ins().load(element_ty, MemFlags::new(), addr, 0);
                                return Ok(ClifValue {
                                    value: loaded,
                                    ty: element_ty,
                                });
                            }
                        }
                        let in_block = builder.create_block();
                        let out_block = builder.create_block();
                        let merge_block = builder.create_block();
                        builder.append_block_param(merge_block, element_ty);

                        let zero = builder.ins().iconst(default_int_clif_type(), 0);
                        let len_const = builder.ins().iconst(default_int_clif_type(), *len as i64);
                        let nonneg = builder.ins().icmp(
                            IntCC::SignedGreaterThanOrEqual,
                            index_value.value,
                            zero,
                        );
                        let below_len =
                            builder
                                .ins()
                                .icmp(IntCC::SignedLessThan, index_value.value, len_const);
                        let in_range = builder.ins().band(nonneg, below_len);
                        builder.ins().brif(in_range, in_block, &[], out_block, &[]);

                        builder.switch_to_block(in_block);
                        let base_ptr = builder.use_var(ptr_binding.var);
                        let idx_ptr = if pointer_sized_clif_type() == default_int_clif_type() {
                            index_value.value
                        } else {
                            builder
                                .ins()
                                .uextend(pointer_sized_clif_type(), index_value.value)
                        };
                        let byte_offset =
                            builder.ins().imul_imm(idx_ptr, i64::from(element_stride));
                        let addr = builder.ins().iadd(base_ptr, byte_offset);
                        let loaded = builder.ins().load(element_ty, MemFlags::new(), addr, 0);
                        builder.ins().jump(merge_block, &[loaded]);

                        builder.switch_to_block(out_block);
                        let zero_default = zero_for_type(builder, element_ty);
                        builder.ins().jump(merge_block, &[zero_default]);

                        builder.seal_block(in_block);
                        builder.seal_block(out_block);
                        builder.switch_to_block(merge_block);
                        builder.seal_block(merge_block);
                        return Ok(ClifValue {
                            value: builder.block_params(merge_block)[0],
                            ty: element_ty,
                        });
                    }
                }
            }
            clif_emit_expr(builder, ctx, base, locals, next_var)?
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = clif_emit_expr(builder, ctx, left, locals, next_var)?;
            match op {
                ast::BinaryOp::Add => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fadd(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().iadd(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Sub => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fsub(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().isub(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Mul => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fmul(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().imul(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Div => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        let lowered = builder.ins().fdiv(lhs.value, rhs.value);
                        clif_assert_finite(
                            builder,
                            ClifValue {
                                value: lowered,
                                ty: lhs.ty,
                            },
                        )
                    } else {
                        ClifValue {
                            value: builder.ins().sdiv(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Mod => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().srem(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitAnd => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().band(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitOr => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().bor(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitXor => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().bxor(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::Shl => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().ishl(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::Shr => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().sshr(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::And => {
                    let lhs_pred = clif_truthy_pred(builder, lhs);
                    let rhs_block = builder.create_block();
                    let short_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, types::I8);
                    builder
                        .ins()
                        .brif(lhs_pred, rhs_block, &[], short_block, &[]);

                    builder.switch_to_block(short_block);
                    let false_val = builder.ins().iconst(types::I8, 0);
                    builder.ins().jump(merge_block, &[false_val]);

                    builder.switch_to_block(rhs_block);
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs_pred = clif_truthy_pred(builder, rhs);
                    let rhs_bool = bool_to_i8(builder, rhs_pred);
                    builder.ins().jump(merge_block, &[rhs_bool.value]);

                    builder.seal_block(short_block);
                    builder.seal_block(rhs_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    ClifValue {
                        value: builder.block_params(merge_block)[0],
                        ty: types::I8,
                    }
                }
                ast::BinaryOp::Or => {
                    let lhs_pred = clif_truthy_pred(builder, lhs);
                    let rhs_block = builder.create_block();
                    let short_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, types::I8);
                    builder
                        .ins()
                        .brif(lhs_pred, short_block, &[], rhs_block, &[]);

                    builder.switch_to_block(short_block);
                    let true_val = builder.ins().iconst(types::I8, 1);
                    builder.ins().jump(merge_block, &[true_val]);

                    builder.switch_to_block(rhs_block);
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs_pred = clif_truthy_pred(builder, rhs);
                    let rhs_bool = bool_to_i8(builder, rhs_pred);
                    builder.ins().jump(merge_block, &[rhs_bool.value]);

                    builder.seal_block(short_block);
                    builder.seal_block(rhs_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    ClifValue {
                        value: builder.block_params(merge_block)[0],
                        ty: types::I8,
                    }
                }
                ast::BinaryOp::Eq => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder.ins().fcmp(FloatCC::Equal, lhs.value, rhs.value)
                    } else {
                        builder.ins().icmp(IntCC::Equal, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Neq => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder.ins().fcmp(FloatCC::NotEqual, lhs.value, rhs.value)
                    } else {
                        builder.ins().icmp(IntCC::NotEqual, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Lt => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder.ins().fcmp(FloatCC::LessThan, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThan, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Lte => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder
                            .ins()
                            .fcmp(FloatCC::LessThanOrEqual, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThanOrEqual, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Gt => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder
                            .ins()
                            .fcmp(FloatCC::GreaterThan, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedGreaterThan, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Gte => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        builder
                            .ins()
                            .fcmp(FloatCC::GreaterThanOrEqual, lhs.value, rhs.value)
                    } else {
                        builder
                            .ins()
                            .icmp(IntCC::SignedGreaterThanOrEqual, lhs.value, rhs.value)
                    };
                    bool_to_i8(builder, pred)
                }
            }
        }
        ast::Expr::Call { callee, args } => {
            if let Some(value) = eval_const_i32_call(callee, args, &ctx.const_strings) {
                return Ok(ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                });
            }
            if let Some(value) = eval_const_string_call(callee, args, &ctx.const_strings) {
                if let Some(id) = ctx.string_literal_ids.get(&value).copied() {
                    return Ok(ClifValue {
                        value: builder.ins().iconst(default_int_clif_type(), id as i64),
                        ty: default_int_clif_type(),
                    });
                }
            }
            if let Some((kind, op)) = clif_parse_simd_intrinsic(callee) {
                return clif_emit_simd_intrinsic(builder, ctx, kind, op, args, locals, next_var);
            }
            if callee == "str.concat" && args.len() >= 2 {
                let function_id = ctx
                    .function_ids
                    .get("str.concat")
                    .copied()
                    .or_else(|| ctx.function_ids.get("str.concat2").copied())
                    .ok_or_else(|| {
                        anyhow!("missing native function signature metadata for `str.concat`")
                    })?;
                let signature = ctx
                    .function_signatures
                    .get("str.concat")
                    .or_else(|| ctx.function_signatures.get("str.concat2"))
                    .ok_or_else(|| {
                        anyhow!("missing native function signature metadata for `str.concat`")
                    })?;
                let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
                let mut acc = clif_emit_expr(builder, ctx, &args[0], locals, next_var)?;
                if let Some(target) = signature.params.first().copied() {
                    acc = cast_clif_value(builder, acc, target)?;
                }
                for arg in args.iter().skip(1) {
                    let mut rhs = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
                    if let Some(target) = signature.params.get(1).copied() {
                        rhs = cast_clif_value(builder, rhs, target)?;
                    }
                    let call = builder.ins().call(func_ref, &[acc.value, rhs.value]);
                    let value = builder.inst_results(call)[0];
                    acc = clif_assert_finite(
                        builder,
                        ClifValue {
                            value,
                            ty: signature.ret.unwrap_or(default_int_clif_type()),
                        },
                    );
                }
                return Ok(acc);
            }
            if let Some(binding) = ctx.closures.get(callee).cloned() {
                return clif_emit_inlined_closure_call(
                    builder, ctx, binding, args, locals, next_var,
                );
            }
            let mut values = Vec::with_capacity(args.len());
            if let Some(function_id) = ctx.function_ids.get(callee).copied() {
                let signature = ctx.function_signatures.get(callee).ok_or_else(|| {
                    anyhow!("missing native function signature metadata for `{callee}`")
                })?;
                if let Some(sret) = signature.sret {
                    let stack_slot = clif_create_stack_slot_for_array_abi(builder, sret);
                    let result_ptr =
                        builder
                            .ins()
                            .stack_addr(pointer_sized_clif_type(), stack_slot, 0);
                    values.push(result_ptr);
                    for (index, arg) in args.iter().enumerate() {
                        let target = signature.params.get(index + 1).copied();
                        let mut lowered = if clif_is_extern_c_borrowed_ptr_param(signature, index)
                            && clif_expr_is_fzy_str(arg, ctx)
                        {
                            clif_emit_borrowed_str_ptr_arg(builder, ctx, arg, locals, next_var)?
                        } else if target == Some(pointer_sized_clif_type()) {
                            if let Some(array_ptr) = clif_emit_array_argument_pointer(
                                builder, ctx, arg, locals, next_var,
                            )? {
                                array_ptr
                            } else {
                                clif_emit_expr(builder, ctx, arg, locals, next_var)?
                            }
                        } else {
                            clif_emit_expr(builder, ctx, arg, locals, next_var)?
                        };
                        if let Some(target) = target {
                            lowered = cast_clif_value(builder, lowered, target)?;
                        }
                        values.push(lowered.value);
                    }
                    let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
                    let _ = builder.ins().call(func_ref, &values);
                    return Ok(ClifValue {
                        value: result_ptr,
                        ty: pointer_sized_clif_type(),
                    });
                }
                for (index, arg) in args.iter().enumerate() {
                    let target = signature.params.get(index).copied();
                    let mut lowered = if clif_is_extern_c_borrowed_ptr_param(signature, index)
                        && clif_expr_is_fzy_str(arg, ctx)
                    {
                        clif_emit_borrowed_str_ptr_arg(builder, ctx, arg, locals, next_var)?
                    } else if target == Some(pointer_sized_clif_type()) {
                        if let Some(array_ptr) =
                            clif_emit_array_argument_pointer(builder, ctx, arg, locals, next_var)?
                        {
                            array_ptr
                        } else {
                            clif_emit_expr(builder, ctx, arg, locals, next_var)?
                        }
                    } else {
                        clif_emit_expr(builder, ctx, arg, locals, next_var)?
                    };
                    if let Some(target) = target {
                        lowered = cast_clif_value(builder, lowered, target)?;
                    }
                    values.push(lowered.value);
                }
                let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
                let call = builder.ins().call(func_ref, &values);
                if let Some(value) = builder.inst_results(call).first().copied() {
                    clif_assert_finite(
                        builder,
                        ClifValue {
                            value,
                            ty: signature.ret.unwrap_or(default_int_clif_type()),
                        },
                    )
                } else {
                    ClifValue {
                        value: builder.ins().iconst(default_int_clif_type(), 0),
                        ty: default_int_clif_type(),
                    }
                }
            } else {
                for arg in args {
                    let _ = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
                }
                return Err(anyhow!(
                    "native backend cannot lower unresolved call target `{}`",
                    callee
                ));
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            let linear_terminated = clif_emit_linear_stmts(builder, ctx, body, locals, next_var)?;
            if linear_terminated {
                let continuation = builder.create_block();
                builder.switch_to_block(continuation);
                builder.seal_block(continuation);
            }
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        _ => ClifValue {
            value: builder.ins().iconst(default_int_clif_type(), 0),
            ty: default_int_clif_type(),
        },
    })
}

pub(super) fn ast_signature_type_to_clif_type(ty: &ast::Type) -> Option<ClifType> {
    match ty {
        ast::Type::Void | ast::Type::Never => None,
        ast::Type::Bool => Some(types::I8),
        ast::Type::ISize | ast::Type::USize => Some(pointer_sized_clif_type()),
        ast::Type::Int { bits, .. } => match bits {
            8 => Some(types::I8),
            16 => Some(types::I16),
            32 => Some(types::I32),
            64 => Some(types::I64),
            128 => Some(types::I128),
            _ => None,
        },
        ast::Type::BigInt | ast::Type::BigUint | ast::Type::Decimal128 => {
            Some(pointer_sized_clif_type())
        }
        ast::Type::Float { bits } => match bits {
            32 => Some(types::F32),
            64 => Some(types::F64),
            _ => None,
        },
        ast::Type::Char
        | ast::Type::Str
        | ast::Type::Bytes
        | ast::Type::Uuid
        | ast::Type::DynTrait(_)
        | ast::Type::Map { .. }
        | ast::Type::Set(_)
        | ast::Type::Deque(_)
        | ast::Type::Ring(_)
        | ast::Type::Ptr { .. }
        | ast::Type::Ref { .. }
        | ast::Type::Slice(_)
        | ast::Type::Array { .. }
        | ast::Type::Result { .. }
        | ast::Type::Option(_)
        | ast::Type::Vec(_)
        | ast::Type::Future(_)
        | ast::Type::Path
        | ast::Type::PathBuf
        | ast::Type::Url
        | ast::Type::SocketAddr
        | ast::Type::Duration
        | ast::Type::Instant
        | ast::Type::Decimal
        | ast::Type::DateTimeTz
        | ast::Type::ExitStatus
        | ast::Type::Tuple(_)
        | ast::Type::Function { .. }
        | ast::Type::Named { .. }
        | ast::Type::TypeVar(_) => Some(pointer_sized_clif_type()),
        ast::Type::SimdVector(shape) => match (shape.element, shape.lanes) {
            (ast::SimdElement::I32, 4) | (ast::SimdElement::U32, 4) => Some(types::I32X4),
            (ast::SimdElement::F32, 4) => Some(types::F32X4),
            _ => None,
        },
        ast::Type::SimdMask(shape) => match (shape.lane_bits, shape.lanes) {
            (32, 4) => Some(types::I32X4),
            _ => None,
        },
    }
}

pub(super) fn clif_array_abi_from_type(ty: &ast::Type) -> Option<ClifArrayAbi> {
    let ast::Type::Array { elem, len } = ty else {
        return None;
    };
    let element_ty = ast_signature_type_to_clif_type(elem.as_ref())?;
    let (element_align, element_stride) = if element_ty == types::I8 {
        (1, 1)
    } else if element_ty == types::I16 {
        (2, 2)
    } else if element_ty == types::I64 || element_ty == types::F64 {
        (8, 8)
    } else {
        (4, 4)
    };
    Some(ClifArrayAbi {
        len: *len,
        element_ty,
        element_align,
        element_stride,
    })
}

pub(super) fn pointer_sized_clif_type() -> ClifType {
    if std::mem::size_of::<usize>() == 8 {
        types::I64
    } else {
        types::I32
    }
}

pub(super) fn default_int_clif_type() -> ClifType {
    types::I32
}

pub(super) fn clif_array_layout_from_values(values: &[ClifValue]) -> (ClifType, u16, u8, u8) {
    let element_ty = if values.iter().any(|value| value.ty == types::F64) {
        types::F64
    } else if values.iter().any(|value| value.ty == types::F32) {
        types::F32
    } else if values.iter().any(|value| value.ty == types::I64) {
        types::I64
    } else if values.iter().any(|value| value.ty == types::I32) {
        types::I32
    } else if values.iter().any(|value| value.ty == types::I16) {
        types::I16
    } else {
        types::I8
    };
    let element_bits = element_ty.bits() as u16;
    let element_stride = (element_bits / 8) as u8;
    let element_align = element_stride;
    (element_ty, element_bits, element_align, element_stride)
}

pub(super) fn zero_for_type(
    builder: &mut FunctionBuilder,
    ty: ClifType,
) -> cranelift_codegen::ir::Value {
    if ty.is_int() {
        builder.ins().iconst(ty, 0)
    } else if ty.is_vector() {
        let scalar = if ty.lane_type() == types::F32 {
            builder.ins().f32const(0.0)
        } else {
            builder.ins().iconst(ty.lane_type(), 0)
        };
        builder.ins().splat(ty, scalar)
    } else if ty == types::F32 {
        builder.ins().f32const(0.0)
    } else if ty == types::F64 {
        builder.ins().f64const(0.0)
    } else {
        builder.ins().iconst(default_int_clif_type(), 0)
    }
}

pub(super) fn clif_truthy_pred(
    builder: &mut FunctionBuilder,
    value: ClifValue,
) -> cranelift_codegen::ir::Value {
    if value.ty == types::F32 {
        let zero = builder.ins().f32const(0.0);
        builder.ins().fcmp(FloatCC::NotEqual, value.value, zero)
    } else if value.ty == types::F64 {
        let zero = builder.ins().f64const(0.0);
        builder.ins().fcmp(FloatCC::NotEqual, value.value, zero)
    } else {
        let zero = zero_for_type(builder, value.ty);
        builder.ins().icmp(IntCC::NotEqual, value.value, zero)
    }
}

pub(super) fn clif_assert_finite(builder: &mut FunctionBuilder, value: ClifValue) -> ClifValue {
    if value.ty != types::F32 && value.ty != types::F64 {
        return value;
    }
    let (neg_limit, pos_limit) = if value.ty == types::F32 {
        (
            builder.ins().f32const(-f32::MAX),
            builder.ins().f32const(f32::MAX),
        )
    } else {
        (
            builder.ins().f64const(-f64::MAX),
            builder.ins().f64const(f64::MAX),
        )
    };
    let lower = builder
        .ins()
        .fcmp(FloatCC::GreaterThanOrEqual, value.value, neg_limit);
    let upper = builder
        .ins()
        .fcmp(FloatCC::LessThanOrEqual, value.value, pos_limit);
    let ok = builder.ins().band(lower, upper);
    let continue_block = builder.create_block();
    let trap_block = builder.create_block();
    builder.ins().brif(ok, continue_block, &[], trap_block, &[]);
    builder.switch_to_block(trap_block);
    builder.ins().trap(TrapCode::unwrap_user(1));
    builder.seal_block(trap_block);
    builder.switch_to_block(continue_block);
    builder.seal_block(continue_block);
    value
}

pub(super) fn bool_to_i8(
    builder: &mut FunctionBuilder,
    pred: cranelift_codegen::ir::Value,
) -> ClifValue {
    let one = builder.ins().iconst(types::I8, 1);
    let zero = builder.ins().iconst(types::I8, 0);
    ClifValue {
        value: builder.ins().select(pred, one, zero),
        ty: types::I8,
    }
}

pub(super) fn cast_clif_value(
    builder: &mut FunctionBuilder,
    value: ClifValue,
    target: ClifType,
) -> Result<ClifValue> {
    if value.ty == target {
        return Ok(value);
    }
    if value.ty.is_int() && target.is_int() {
        if value.ty.bits() < target.bits() {
            return Ok(ClifValue {
                value: builder.ins().sextend(target, value.value),
                ty: target,
            });
        }
        if value.ty.bits() > target.bits() {
            return Ok(ClifValue {
                value: builder.ins().ireduce(target, value.value),
                ty: target,
            });
        }
    }
    if value.ty.is_int() && (target == types::F32 || target == types::F64) {
        let out = if target == types::F32 {
            builder.ins().fcvt_from_sint(types::F32, value.value)
        } else {
            builder.ins().fcvt_from_sint(types::F64, value.value)
        };
        return Ok(ClifValue {
            value: out,
            ty: target,
        });
    }
    if (value.ty == types::F32 || value.ty == types::F64) && target.is_int() {
        let value = clif_assert_finite(builder, value);
        return Ok(ClifValue {
            value: builder.ins().fcvt_to_sint(target, value.value),
            ty: target,
        });
    }
    if value.ty == types::F32 && target == types::F64 {
        return Ok(ClifValue {
            value: builder.ins().fpromote(types::F64, value.value),
            ty: types::F64,
        });
    }
    if value.ty == types::F64 && target == types::F32 {
        return Ok(ClifValue {
            value: builder.ins().fdemote(types::F32, value.value),
            ty: types::F32,
        });
    }
    if value.ty.is_vector() && target.is_vector() && value.ty.bytes() == target.bytes() {
        return Ok(ClifValue {
            value: builder.ins().bitcast(target, MemFlags::new(), value.value),
            ty: target,
        });
    }
    bail!(
        "unsupported native cast from `{}` to `{}`",
        value.ty,
        target
    );
}
