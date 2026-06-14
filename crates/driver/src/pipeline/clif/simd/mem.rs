use super::*;

pub(crate) fn clif_emit_simd_ptr_alignment_check(
    builder: &mut FunctionBuilder,
    ptr: cranelift_codegen::ir::Value,
    align: i64,
) {
    let masked = builder.ins().band_imm(ptr, align - 1);
    let zero = builder.ins().iconst(pointer_sized_clif_type(), 0);
    let aligned = builder.ins().icmp(IntCC::Equal, masked, zero);
    builder.ins().trapz(aligned, TrapCode::unwrap_user(1));
}

pub(crate) fn clif_emit_simd_ptr_memory(
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
