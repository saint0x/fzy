use super::*;

pub(crate) fn clif_parse_simd_intrinsic(callee: &str) -> Option<(&str, &str)> {
    let body = callee.strip_prefix("simd.__")?;
    for kind in ["i32x4", "u32x4", "f32x4", "mask32x4"] {
        if let Some(op) = body.strip_prefix(kind) {
            return Some((kind, op));
        }
    }
    None
}

pub(crate) fn clif_simd_vector_type(kind: &str) -> Option<ClifType> {
    match kind {
        "i32x4" | "u32x4" | "mask32x4" => Some(types::I32X4),
        "f32x4" => Some(types::F32X4),
        _ => None,
    }
}

pub(crate) fn clif_simd_lane_type(kind: &str) -> Option<ClifType> {
    match kind {
        "i32x4" | "u32x4" | "mask32x4" => Some(types::I32),
        "f32x4" => Some(types::F32),
        _ => None,
    }
}

pub(crate) fn clif_simd_ptr_alignment(kind: &str, op: &str) -> Option<i64> {
    if !op.contains("_aligned_") {
        return None;
    }
    Some(if kind == "mask32x4" { 4 } else { 16 })
}

pub(crate) fn clif_parse_simd_store_wrapper(callee: &str) -> Option<&'static str> {
    match callee {
        "simd.i32x4_store" => Some("i32x4"),
        "simd.u32x4_store" => Some("u32x4"),
        "simd.f32x4_store" => Some("f32x4"),
        "simd.mask32x4_store" => Some("mask32x4"),
        _ => None,
    }
}
