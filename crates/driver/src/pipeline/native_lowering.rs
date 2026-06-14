use super::*;
use super::clif::lower_cranelift_ir;
use super::llvm::lower_llvm_ir;

pub(super) fn lower_backend_ir(fir: &fir::FirModule, backend: BackendKind) -> Result<String> {
    let plan = build_native_canonical_plan(fir, true);
    drop(plan);
    match backend {
        BackendKind::Llvm => lower_llvm_ir(fir, true),
        BackendKind::Cranelift => lower_cranelift_ir(fir, true),
    }
}

#[derive(Clone)]
pub(super) struct NativeCanonicalPlan {
    pub(super) forced_main_return: Option<i32>,
    pub(super) string_literal_ids: HashMap<String, i32>,
    pub(super) global_const_i32: HashMap<String, i32>,
    pub(super) variant_tags: HashMap<String, i32>,
    pub(super) mutable_static_i32: HashMap<String, i32>,
    pub(super) task_ref_ids: HashMap<String, i32>,
    pub(super) cfg_by_function: HashMap<String, Result<ControlFlowCfg, String>>,
    pub(super) data_ops_by_function: HashMap<String, Vec<NativeDataOp>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(super) enum NativeMemoryClass {
    Stack,
    Static,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(super) enum NativeAliasClass {
    LocalNoEscape,
    Escapes,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum NativeBoundsPolicy {
    Checked,
    ProvenInRange,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum NativeEffectBoundary {
    Local,
    CapabilityRuntimeImport,
}

#[derive(Debug, Clone)]
pub(super) enum NativeDataOpKind {
    ArrayLiteral {
        binding: String,
        len: usize,
        element_bits: u16,
        element_align: u8,
        element_stride: u8,
        memory: NativeMemoryClass,
        alias: NativeAliasClass,
    },
    ArrayIndexLoad {
        binding: String,
        index: String,
        bounds: NativeBoundsPolicy,
    },
    StringViewCall {
        callee: String,
        foldable: bool,
        alias: NativeAliasClass,
    },
    RuntimeBoundaryCall {
        callee: String,
        arity: usize,
    },
}

#[derive(Debug, Clone)]
pub(super) struct NativeDataOp {
    pub(super) kind: NativeDataOpKind,
    pub(super) effect_boundary: NativeEffectBoundary,
}

#[path = "native_lowering/data.rs"]
mod data;
#[path = "native_lowering/contract.rs"]
mod contract;
#[path = "native_lowering/plan.rs"]
mod plan;
#[path = "native_lowering/eval.rs"]
mod eval;

pub(super) use self::contract::*;
pub(super) use self::data::*;
pub(super) use self::eval::*;
pub(super) use self::plan::*;
