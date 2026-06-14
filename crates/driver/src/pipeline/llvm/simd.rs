use super::*;

#[path = "simd/base.rs"]
mod base;
#[path = "simd/array.rs"]
mod array;
#[path = "simd/ops.rs"]
mod ops;

pub(crate) use self::array::{
    llvm_array_binding_from_ir_type, llvm_array_binding_from_type,
    llvm_emit_array_argument_parts, llvm_emit_array_index_from_binding,
    llvm_emit_array_literal_value, llvm_emit_index_assign,
};
pub(crate) use self::base::{
    llvm_emit_borrowed_str_ptr_arg, llvm_expr_is_fzy_str,
    llvm_is_extern_c_borrowed_ptr_param, llvm_parse_simd_intrinsic, llvm_pointer_int_type,
    llvm_ptr_element_type, llvm_simd_bool_splat_literal, llvm_simd_i32_all_ones_literal,
    llvm_simd_scalar_type, llvm_simd_vector_type, llvm_vec_element_type,
};
pub(crate) use self::ops::llvm_emit_simd_intrinsic_call;
