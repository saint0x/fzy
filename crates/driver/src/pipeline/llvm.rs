use super::gpu_kernel_metal::{metal_kernel_launch_descriptors, MetalKernelLaunchDescriptor};
use super::*;
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct LlvmClosureBinding {
    pub(super) params: Vec<ast::Param>,
    pub(super) return_type: Option<ast::Type>,
    pub(super) body: ast::Expr,
    pub(super) captures: HashMap<String, LlvmCaptureBinding>,
}

#[derive(Clone)]
pub(super) struct LlvmCaptureBinding {
    pub(super) slot: String,
    pub(super) ty: String,
}

#[derive(Clone)]
pub(super) struct LlvmValue {
    pub(super) value: String,
    pub(super) ty: String,
}

#[derive(Clone)]
pub(super) struct LlvmArrayBinding {
    pub(super) storage: String,
    pub(super) len: usize,
    pub(super) element_ty: String,
    pub(super) element_bits: u16,
    pub(super) element_align: u8,
    pub(super) element_stride: u8,
}

#[derive(Clone)]
pub(super) struct LlvmFunctionSig {
    pub(super) params: Vec<String>,
    pub(super) ret: Option<String>,
    pub(super) param_names: Vec<String>,
    pub(super) is_extern_c_import: bool,
}

#[derive(Clone)]
pub(super) struct LlvmAggregateItemBinding {
    pub(super) index: usize,
    pub(super) ty: String,
}

#[derive(Clone, Default)]
pub(super) struct LlvmAggregateBinding {
    pub(super) items: HashMap<String, LlvmAggregateItemBinding>,
}

pub(super) struct LlvmFuncCtx {
    pub(super) next_value: usize,
    pub(super) next_label: usize,
    pub(super) slots: HashMap<String, String>,
    pub(super) slot_tys: HashMap<String, String>,
    pub(super) array_slots: HashMap<String, LlvmArrayBinding>,
    pub(super) const_strings: HashMap<String, String>,
    pub(super) direct_values: HashMap<String, LlvmValue>,
    pub(super) aggregate_bindings: HashMap<String, LlvmAggregateBinding>,
    pub(super) wrapped_indices: HashMap<String, HashSet<usize>>,
    pub(super) extern_link_symbols: HashMap<String, String>,
    pub(super) closures: HashMap<String, LlvmClosureBinding>,
    pub(super) function_sigs: HashMap<String, LlvmFunctionSig>,
    pub(super) globals: HashMap<String, i32>,
    pub(super) variant_tags: HashMap<String, i32>,
    pub(super) mutable_globals: HashMap<String, String>,
    pub(super) local_types: BTreeMap<String, ast::Type>,
    pub(super) struct_defs: HashMap<String, ast::Struct>,
    pub(super) enum_defs: HashMap<String, ast::Enum>,
    pub(super) gpu_kernel_launch_descriptors: HashMap<String, MetalKernelLaunchDescriptor>,
    pub(super) current_namespace: String,
    pub(super) function_return_ty: String,
    pub(super) alloca_prologue: String,
    pub(super) declared_allocas: HashSet<String>,
    pub(super) code: String,
}

impl LlvmFuncCtx {
    pub(super) fn new(
        current_function_name: &str,
        globals: HashMap<String, i32>,
        variant_tags: HashMap<String, i32>,
        mutable_globals: HashMap<String, String>,
        local_types: BTreeMap<String, ast::Type>,
        struct_defs: HashMap<String, ast::Struct>,
        enum_defs: HashMap<String, ast::Enum>,
        gpu_kernel_launch_descriptors: HashMap<String, MetalKernelLaunchDescriptor>,
        function_return_ty: String,
        wrapped_indices: HashMap<String, HashSet<usize>>,
        extern_link_symbols: HashMap<String, String>,
        function_sigs: HashMap<String, LlvmFunctionSig>,
    ) -> Self {
        Self {
            next_value: 0,
            next_label: 0,
            slots: HashMap::new(),
            slot_tys: HashMap::new(),
            array_slots: HashMap::new(),
            const_strings: HashMap::new(),
            direct_values: HashMap::new(),
            aggregate_bindings: HashMap::new(),
            wrapped_indices,
            extern_link_symbols,
            closures: HashMap::new(),
            function_sigs,
            globals,
            variant_tags,
            mutable_globals,
            local_types,
            struct_defs,
            enum_defs,
            gpu_kernel_launch_descriptors,
            current_namespace: native_current_namespace(current_function_name).to_string(),
            function_return_ty,
            alloca_prologue: String::new(),
            declared_allocas: HashSet::new(),
            code: String::new(),
        }
    }

    pub(super) fn value(&mut self) -> String {
        let id = self.next_value;
        self.next_value += 1;
        format!("%v{id}")
    }

    pub(super) fn label(&mut self, prefix: &str) -> String {
        let id = self.next_label;
        self.next_label += 1;
        format!("{prefix}.{id}")
    }

    pub(super) fn declare_alloca(&mut self, slot: &str, ty: &str) {
        if self.declared_allocas.insert(slot.to_string()) {
            let _ = writeln!(&mut self.alloca_prologue, "  {slot} = alloca {ty}");
        }
    }

    pub(super) fn emit(&mut self, args: std::fmt::Arguments<'_>) {
        self.code
            .write_fmt(args)
            .expect("llvm function buffer writes should not fail");
    }
}

#[path = "llvm/agg.rs"]
mod agg;
#[path = "llvm/emit.rs"]
mod emit;
#[path = "llvm/expr.rs"]
mod expr;
#[path = "llvm/linear.rs"]
mod linear;
#[path = "llvm/simd.rs"]
mod simd;
#[path = "llvm/ty.rs"]
mod ty;

pub(super) use self::agg::*;
pub(super) use self::emit::*;
pub(super) use self::expr::*;
pub(super) use self::linear::*;
pub(super) use self::simd::*;
pub(super) use self::ty::*;
