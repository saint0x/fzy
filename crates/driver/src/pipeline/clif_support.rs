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
