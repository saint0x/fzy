use super::*;

pub(crate) fn ast_signature_type_to_clif_type(ty: &ast::Type) -> Option<ClifType> {
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

pub(crate) fn clif_array_abi_from_type(ty: &ast::Type) -> Option<ClifArrayAbi> {
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

pub(crate) fn pointer_sized_clif_type() -> ClifType {
    if std::mem::size_of::<usize>() == 8 {
        types::I64
    } else {
        types::I32
    }
}

pub(crate) fn default_int_clif_type() -> ClifType {
    types::I32
}

pub(crate) fn clif_array_layout_from_values(values: &[ClifValue]) -> (ClifType, u16, u8, u8) {
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

pub(crate) fn zero_for_type(
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

pub(crate) fn clif_truthy_pred(
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

pub(crate) fn clif_assert_finite(builder: &mut FunctionBuilder, value: ClifValue) -> ClifValue {
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

pub(crate) fn bool_to_i8(
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

pub(crate) fn cast_clif_value(
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

pub(crate) fn clif_encode_gpu_launch_arg(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    arg: &ast::Expr,
    layout: &str,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let ptr_ty = pointer_sized_clif_type();
    match layout {
        "i32" => {
            let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
            let value = cast_clif_value(builder, lowered, types::I32)?;
            Ok(ClifValue {
                value: if ptr_ty == types::I64 {
                    builder.ins().sextend(ptr_ty, value.value)
                } else {
                    value.value
                },
                ty: ptr_ty,
            })
        }
        "u32" => {
            let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
            let value = cast_clif_value(builder, lowered, types::I32)?;
            Ok(ClifValue {
                value: if ptr_ty == types::I64 {
                    builder.ins().uextend(ptr_ty, value.value)
                } else {
                    value.value
                },
                ty: ptr_ty,
            })
        }
        "f32" => {
            let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
            let value = cast_clif_value(builder, lowered, types::F32)?;
            let bits = builder
                .ins()
                .bitcast(types::I32, MemFlags::new(), value.value);
            Ok(ClifValue {
                value: if ptr_ty == types::I64 {
                    builder.ins().uextend(ptr_ty, bits)
                } else {
                    bits
                },
                ty: ptr_ty,
            })
        }
        layout if layout.starts_with("slice_") => {
            let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
            cast_clif_value(builder, lowered, ptr_ty)
        }
        _ => {
            let lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
            cast_clif_value(builder, lowered, ptr_ty)
        }
    }
}
