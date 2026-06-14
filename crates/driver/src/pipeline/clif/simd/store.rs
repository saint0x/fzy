use super::*;

pub(crate) fn clif_materialize_simd_store_binding(
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
