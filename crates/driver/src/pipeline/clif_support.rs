use super::*;
use anyhow::{bail, Result};
use std::collections::HashMap;

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
    pub(super) mutable_globals: &'a HashMap<String, cranelift_module::DataId>,
    pub(super) current_return_ty: Option<ClifType>,
    pub(super) closures: HashMap<String, ClifClosureBinding>,
    pub(super) array_bindings: HashMap<String, ClifArrayBinding>,
    pub(super) const_strings: HashMap<String, String>,
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
    current_return_ty: Option<ClifType>,
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
        mutable_globals,
        current_return_ty,
        closures: HashMap::new(),
        array_bindings: HashMap::new(),
        const_strings: HashMap::new(),
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
                if let Some(return_ty) = return_ty {
                    let value = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                    let value = cast_clif_value(builder, value, return_ty)?;
                    builder.ins().return_(&[value.value]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
            ControlFlowTerminator::Return(None) => {
                if let Some(return_ty) = return_ty {
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
                let cond_val = clif_emit_expr(builder, ctx, scrutinee, locals, next_var)?;
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
    }
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
    } else {
        types::I32
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
    builder
        .ins()
        .brif(ok, continue_block, &[], trap_block, &[]);
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
    bail!(
        "unsupported native cast from `{}` to `{}`",
        value.ty,
        target
    );
}
