use super::*;

pub(crate) fn clif_emit_array_argument_pointer(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    arg: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<Option<ClifValue>> {
    match arg {
        ast::Expr::Ident(name) => {
            if matches!(clif_local_type(ctx, name), Some(ast::Type::Array { .. })) {
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

pub(crate) fn clif_emit_array_argument_parts(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    arg: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<Option<(ClifValue, ClifValue)>> {
    fn pointer_element_stride(ty: &ast::Type) -> Option<u8> {
        let ast::Type::Ptr { to, .. } = ty else {
            return None;
        };
        let element_ty = ast_signature_type_to_clif_type(to.as_ref())?;
        let bytes = element_ty.bytes();
        Some(if bytes == 0 { 1 } else { bytes as u8 })
    }
    fn sibling_len_binding_name(name: &str) -> Option<String> {
        for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
            if let Some(stem) = name.strip_suffix(suffix) {
                return Some(format!("{stem}_len"));
            }
        }
        if let Some(stem) = name.strip_suffix("_ptr") {
            return Some(format!("{stem}_len"));
        }
        Some(format!("{name}_len"))
    }
    match arg {
        ast::Expr::Ident(name) => {
            if let Some(binding) = ctx.array_bindings.get(name) {
                let ptr =
                    builder
                        .ins()
                        .stack_addr(pointer_sized_clif_type(), binding.stack_slot, 0);
                let len = builder.ins().iconst(types::I32, binding.len as i64);
                return Ok(Some((
                    ClifValue {
                        value: ptr,
                        ty: pointer_sized_clif_type(),
                    },
                    ClifValue {
                        value: len,
                        ty: types::I32,
                    },
                )));
            }
            if let Some(ast::Type::Array { len, .. }) = ctx.local_types.get(name) {
                if let Some(binding) = locals.get(name).copied() {
                    let ptr = builder.use_var(binding.var);
                    let len = builder.ins().iconst(types::I32, *len as i64);
                    return Ok(Some((
                        ClifValue {
                            value: ptr,
                            ty: binding.ty,
                        },
                        ClifValue {
                            value: len,
                            ty: types::I32,
                        },
                    )));
                }
            }
            if let Some(ptr_ty) = clif_local_type(ctx, name) {
                if !matches!(ptr_ty, ast::Type::Ptr { .. }) {
                    return Ok(None);
                }
                let element_stride = pointer_element_stride(ptr_ty);
                if let Some(len_name) = sibling_len_binding_name(name) {
                    if clif_local_type(ctx, &len_name).is_some() {
                        let ptr = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
                        let ptr = cast_clif_value(builder, ptr, pointer_sized_clif_type())?;
                        let len = clif_emit_expr(
                            builder,
                            ctx,
                            &ast::Expr::Ident(len_name),
                            locals,
                            next_var,
                        )?;
                        let mut len = cast_clif_value(builder, len, types::I32)?;
                        if let Some(element_stride) = element_stride {
                            if element_stride > 1 {
                                let stride =
                                    builder.ins().iconst(types::I32, i64::from(element_stride));
                                len = ClifValue {
                                    value: builder.ins().udiv(len.value, stride),
                                    ty: types::I32,
                                };
                            }
                        }
                        return Ok(Some((ptr, len)));
                    }
                }
            }
            Ok(None)
        }
        ast::Expr::ArrayLiteral(items) => {
            let ptr = clif_emit_array_argument_pointer(builder, ctx, arg, locals, next_var)?;
            let Some(ptr) = ptr else {
                return Ok(None);
            };
            let len = builder.ins().iconst(types::I32, items.len() as i64);
            Ok(Some((
                ptr,
                ClifValue {
                    value: len,
                    ty: types::I32,
                },
            )))
        }
        _ => Ok(None),
    }
}

pub(crate) fn clif_vec_element_type(
    expr: &ast::Expr,
    ctx: &ClifLoweringCtx<'_>,
) -> Option<&'static str> {
    match expr {
        ast::Expr::Ident(name) => match ctx.local_types.get(name) {
            Some(ast::Type::Vec(inner)) => match inner.as_ref() {
                ast::Type::Float { bits: 32 } => Some("f32"),
                ast::Type::Int {
                    signed: true,
                    bits: 32,
                } => Some("i32"),
                ast::Type::Int {
                    signed: false,
                    bits: 32,
                } => Some("u32"),
                _ => None,
            },
            _ => None,
        },
        ast::Expr::Group(inner) | ast::Expr::Discard(inner) => clif_vec_element_type(inner, ctx),
        ast::Expr::Call { callee, .. } => match callee.as_str() {
            "gpu.download_f32" => Some("f32"),
            "gpu.download_i32" => Some("i32"),
            "gpu.download_u32" => Some("u32"),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn clif_create_stack_slot_for_array_abi(
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

pub(crate) fn clif_copy_array_memory(
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

pub(crate) fn clif_zero_fill_array_memory(
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

pub(crate) fn clif_emit_array_expr_to_ptr(
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
            if matches!(clif_local_type(ctx, name), Some(ast::Type::Array { .. })) {
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

pub(crate) fn clif_emit_index_assign(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    base: &ast::Expr,
    index: &ast::Expr,
    value: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let raw_index = clif_emit_expr(builder, ctx, index, locals, next_var)?;
    let index_value = cast_clif_value(builder, raw_index, default_int_clif_type())?;
    if let ast::Expr::Ident(name) = base {
        if let Some(binding) = ctx.array_bindings.get(name).cloned() {
            let idx_ptr = if pointer_sized_clif_type() == index_value.ty {
                index_value.value
            } else {
                builder
                    .ins()
                    .uextend(pointer_sized_clif_type(), index_value.value)
            };
            let byte_offset = if binding.element_stride == 1 {
                idx_ptr
            } else {
                builder
                    .ins()
                    .imul_imm(idx_ptr, i64::from(binding.element_stride))
            };
            let base_ptr =
                builder
                    .ins()
                    .stack_addr(pointer_sized_clif_type(), binding.stack_slot, 0);
            let addr = builder.ins().iadd(base_ptr, byte_offset);
            let raw_value = clif_emit_expr(builder, ctx, value, locals, next_var)?;
            let stored = cast_clif_value(builder, raw_value, binding.element_ty)?;
            builder.ins().store(MemFlags::new(), stored.value, addr, 0);
            return Ok(());
        }
    }
    if let Some(element_ty) = clif_ptr_element_type(base, ctx) {
        let raw_base = clif_emit_expr(builder, ctx, base, locals, next_var)?;
        let base_ptr = cast_clif_value(builder, raw_base, pointer_sized_clif_type())?;
        let idx_ptr = if pointer_sized_clif_type() == index_value.ty {
            index_value.value
        } else {
            builder
                .ins()
                .uextend(pointer_sized_clif_type(), index_value.value)
        };
        let addr = if element_ty.bytes() == 1 {
            builder.ins().iadd(base_ptr.value, idx_ptr)
        } else {
            let byte_offset = builder
                .ins()
                .imul_imm(idx_ptr, i64::from(element_ty.bytes()));
            builder.ins().iadd(base_ptr.value, byte_offset)
        };
        let raw_value = clif_emit_expr(builder, ctx, value, locals, next_var)?;
        let stored = cast_clif_value(builder, raw_value, element_ty)?;
        builder.ins().store(MemFlags::new(), stored.value, addr, 0);
        return Ok(());
    }
    bail!("native backend cannot lower indexed assignment target")
}
