use std::collections::BTreeSet;

use anyhow::{bail, Result};
use serde_json::Value;

pub(crate) const SHARED_GPU_LAUNCH_ABI_VERSION: &str = "fozzylang.gpu_launch_abi.v1";

#[derive(Debug, Clone)]
pub(crate) struct SharedGpuLayoutClass {
    pub(crate) name: String,
    pub(crate) value_type: String,
    pub(crate) access_mode: Option<&'static str>,
    pub(crate) wire_slots: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub(crate) struct SharedGpuKernelContract {
    pub(crate) abi_version: &'static str,
    pub(crate) param_layout: String,
    pub(crate) layout_classes: Vec<SharedGpuLayoutClass>,
    pub(crate) capability_flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SharedGpuLaunchGeometry {
    pub(crate) grid_dimensions: Vec<&'static str>,
    pub(crate) block_dimensions: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub(crate) struct SharedGpuBackendLimitProfile {
    pub(crate) module_format: &'static str,
    pub(crate) execution_model: Option<&'static str>,
    pub(crate) entry_point_encoding: Option<&'static str>,
    pub(crate) entry_directive: Option<&'static str>,
    pub(crate) parameter_state_space: Option<&'static str>,
    pub(crate) launch_geometry: SharedGpuLaunchGeometry,
    pub(crate) argument_encoding: &'static str,
    pub(crate) supported_layout_class_version: &'static str,
    pub(crate) supported_scalar_param_types: Vec<&'static str>,
    pub(crate) supported_slice_element_types: Vec<&'static str>,
    pub(crate) unsupported_shape_policy: &'static str,
    pub(crate) runtime_status: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct SharedGpuBackendLimitProfiles {
    pub(crate) metal: SharedGpuBackendLimitProfile,
    pub(crate) rocm: SharedGpuBackendLimitProfile,
    pub(crate) cuda: SharedGpuBackendLimitProfile,
    pub(crate) spirv: SharedGpuBackendLimitProfile,
    pub(crate) nvptx: SharedGpuBackendLimitProfile,
}

impl SharedGpuLayoutClass {
    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "name": self.name,
            "valueType": self.value_type,
            "accessMode": self.access_mode,
            "wireSlots": self.wire_slots,
        })
    }
}

impl SharedGpuKernelContract {
    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "abiVersion": self.abi_version,
            "paramLayout": self.param_layout,
            "layoutClasses": self.layout_classes.iter().map(SharedGpuLayoutClass::to_json).collect::<Vec<_>>(),
            "layoutClassRefs": self.layout_classes.iter().map(|class| class.name.clone()).collect::<Vec<_>>(),
            "kernelCapabilityFlags": self.capability_flags,
        })
    }
}

impl SharedGpuLaunchGeometry {
    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "gridDimensions": self.grid_dimensions,
            "blockDimensions": self.block_dimensions,
        })
    }
}

impl SharedGpuBackendLimitProfile {
    pub(crate) fn to_json(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert(
            "moduleFormat".to_string(),
            Value::String(self.module_format.to_string()),
        );
        if let Some(execution_model) = self.execution_model {
            object.insert(
                "executionModel".to_string(),
                Value::String(execution_model.to_string()),
            );
        }
        if let Some(entry_point_encoding) = self.entry_point_encoding {
            object.insert(
                "entryPointEncoding".to_string(),
                Value::String(entry_point_encoding.to_string()),
            );
        }
        if let Some(entry_directive) = self.entry_directive {
            object.insert(
                "entryDirective".to_string(),
                Value::String(entry_directive.to_string()),
            );
        }
        if let Some(parameter_state_space) = self.parameter_state_space {
            object.insert(
                "parameterStateSpace".to_string(),
                Value::String(parameter_state_space.to_string()),
            );
        }
        object.insert("launchGeometry".to_string(), self.launch_geometry.to_json());
        object.insert(
            "argumentEncoding".to_string(),
            Value::String(self.argument_encoding.to_string()),
        );
        object.insert(
            "supportedLayoutClassVersion".to_string(),
            Value::String(self.supported_layout_class_version.to_string()),
        );
        object.insert(
            "supportedScalarParamTypes".to_string(),
            serde_json::json!(self.supported_scalar_param_types),
        );
        object.insert(
            "supportedSliceElementTypes".to_string(),
            serde_json::json!(self.supported_slice_element_types),
        );
        object.insert(
            "unsupportedShapePolicy".to_string(),
            Value::String(self.unsupported_shape_policy.to_string()),
        );
        object.insert(
            "runtimeStatus".to_string(),
            Value::String(self.runtime_status.to_string()),
        );
        Value::Object(object)
    }
}

impl SharedGpuBackendLimitProfiles {
    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({
            "metal": self.metal.to_json(),
            "rocm": self.rocm.to_json(),
            "cuda": self.cuda.to_json(),
            "spirv": self.spirv.to_json(),
            "nvptx": self.nvptx.to_json(),
        })
    }

    pub(crate) fn for_backend(
        &self,
        kind: super::gpu_backend::GpuBackendKind,
    ) -> &SharedGpuBackendLimitProfile {
        match kind {
            super::gpu_backend::GpuBackendKind::Metal => &self.metal,
            super::gpu_backend::GpuBackendKind::Rocm => &self.rocm,
            super::gpu_backend::GpuBackendKind::Cuda => &self.cuda,
            super::gpu_backend::GpuBackendKind::Spirv => &self.spirv,
            super::gpu_backend::GpuBackendKind::Nvptx => &self.nvptx,
        }
    }
}

pub(crate) fn shared_gpu_kernel_contract(
    function: &kernel_ir::KernelFunction,
) -> Result<SharedGpuKernelContract> {
    let layout_classes = function
        .params
        .iter()
        .map(|param| shared_gpu_layout_class(function, param))
        .collect::<Result<Vec<_>>>()?;
    let param_layout = layout_classes
        .iter()
        .map(|class| class.name.clone())
        .collect::<Vec<_>>()
        .join(",");
    Ok(SharedGpuKernelContract {
        abi_version: SHARED_GPU_LAUNCH_ABI_VERSION,
        param_layout,
        layout_classes,
        capability_flags: shared_gpu_kernel_capability_flags(function),
    })
}

pub(crate) fn shared_gpu_layout_catalog() -> Vec<SharedGpuLayoutClass> {
    vec![
        shared_gpu_scalar_layout_class("i32"),
        shared_gpu_scalar_layout_class("u32"),
        shared_gpu_scalar_layout_class("f32"),
        shared_gpu_slice_layout_class("f32", "readonly", "ro"),
        shared_gpu_slice_layout_class("f32", "writeonly", "wo"),
        shared_gpu_slice_layout_class("f32", "readwrite", "rw"),
        shared_gpu_slice_layout_class("i32", "readonly", "ro"),
        shared_gpu_slice_layout_class("i32", "writeonly", "wo"),
        shared_gpu_slice_layout_class("i32", "readwrite", "rw"),
        shared_gpu_slice_layout_class("u32", "readonly", "ro"),
        shared_gpu_slice_layout_class("u32", "writeonly", "wo"),
        shared_gpu_slice_layout_class("u32", "readwrite", "rw"),
    ]
}

pub(crate) fn shared_gpu_backend_limit_profiles() -> SharedGpuBackendLimitProfiles {
    SharedGpuBackendLimitProfiles {
        metal: shared_gpu_backend_limit_profile(
            "metal.compute_source",
            Some("host_lifecycle_and_kernel_launch_live"),
        ),
        rocm: shared_gpu_backend_limit_profile(
            "hiprtc.source",
            Some("host_lifecycle_and_kernel_launch_live"),
        ),
        cuda: shared_gpu_backend_limit_profile("nvrtc.cuda_source", None),
        spirv: SharedGpuBackendLimitProfile {
            module_format: "spirv.binary_module",
            execution_model: Some("GLCompute"),
            entry_point_encoding: Some("OpEntryPoint"),
            entry_directive: None,
            parameter_state_space: None,
            launch_geometry: shared_launch_geometry(),
            argument_encoding: "fzy_native_scalar_and_handle_abi",
            supported_layout_class_version: SHARED_GPU_LAUNCH_ABI_VERSION,
            supported_scalar_param_types: vec!["i32", "u32", "f32"],
            supported_slice_element_types: vec!["f32", "i32", "u32"],
            unsupported_shape_policy: "reject_outside_shared_contract",
            runtime_status: "declared_not_executable",
        },
        nvptx: SharedGpuBackendLimitProfile {
            module_format: "ptx.assembly_text",
            execution_model: None,
            entry_point_encoding: None,
            entry_directive: Some(".entry"),
            parameter_state_space: Some(".param"),
            launch_geometry: shared_launch_geometry(),
            argument_encoding: "fzy_native_scalar_and_handle_abi",
            supported_layout_class_version: SHARED_GPU_LAUNCH_ABI_VERSION,
            supported_scalar_param_types: vec!["i32", "u32", "f32"],
            supported_slice_element_types: vec!["f32", "i32", "u32"],
            unsupported_shape_policy: "reject_outside_shared_contract",
            runtime_status: "declared_not_executable",
        },
    }
}

fn shared_gpu_backend_limit_profile(
    module_format: &'static str,
    runtime_status: Option<&'static str>,
) -> SharedGpuBackendLimitProfile {
    SharedGpuBackendLimitProfile {
        module_format,
        execution_model: None,
        entry_point_encoding: None,
        entry_directive: None,
        parameter_state_space: None,
        launch_geometry: shared_launch_geometry(),
        argument_encoding: "fzy_native_scalar_and_handle_abi",
        supported_layout_class_version: SHARED_GPU_LAUNCH_ABI_VERSION,
        supported_scalar_param_types: vec!["i32", "u32", "f32"],
        supported_slice_element_types: vec!["f32", "i32", "u32"],
        unsupported_shape_policy: "reject_outside_shared_contract",
        runtime_status: runtime_status.unwrap_or("declared_not_executable"),
    }
}

fn shared_launch_geometry() -> SharedGpuLaunchGeometry {
    SharedGpuLaunchGeometry {
        grid_dimensions: vec!["x"],
        block_dimensions: vec!["x"],
    }
}

fn shared_gpu_layout_class(
    function: &kernel_ir::KernelFunction,
    param: &ast::Param,
) -> Result<SharedGpuLayoutClass> {
    match &param.ty {
        ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
            let access_mode = function
                .slice_access
                .get(&param.name)
                .copied()
                .unwrap_or(kernel_ir::KernelSliceAccessMode::Observe);
            let access_name = match access_mode {
                kernel_ir::KernelSliceAccessMode::Observe
                | kernel_ir::KernelSliceAccessMode::ReadOnly => "readonly",
                kernel_ir::KernelSliceAccessMode::WriteOnly => "writeonly",
                kernel_ir::KernelSliceAccessMode::ReadWrite => "readwrite",
            };
            let suffix = access_mode.layout_suffix();
            match &args[0] {
                ast::Type::Float { bits: 32 } => {
                    Ok(shared_gpu_slice_layout_class("f32", access_name, suffix))
                }
                ast::Type::Int {
                    signed: true,
                    bits: 32,
                } => Ok(shared_gpu_slice_layout_class("i32", access_name, suffix)),
                ast::Type::Int {
                    signed: false,
                    bits: 32,
                } => Ok(shared_gpu_slice_layout_class("u32", access_name, suffix)),
                other => bail!(
                    "shared GPU launch layout does not yet support slice element type `{other}`"
                ),
            }
        }
        ast::Type::Int {
            signed: true,
            bits: 32,
        } => Ok(shared_gpu_scalar_layout_class("i32")),
        ast::Type::Int {
            signed: false,
            bits: 32,
        } => Ok(shared_gpu_scalar_layout_class("u32")),
        ast::Type::Float { bits: 32 } => Ok(shared_gpu_scalar_layout_class("f32")),
        other => bail!("shared GPU launch layout does not yet support kernel param `{other}`"),
    }
}

fn shared_gpu_scalar_layout_class(name: &'static str) -> SharedGpuLayoutClass {
    SharedGpuLayoutClass {
        name: name.to_string(),
        value_type: name.to_string(),
        access_mode: None,
        wire_slots: vec!["scalar_value"],
    }
}

fn shared_gpu_slice_layout_class(
    value_type: &'static str,
    access_mode: &'static str,
    suffix: &'static str,
) -> SharedGpuLayoutClass {
    SharedGpuLayoutClass {
        name: format!("slice_{value_type}_{suffix}"),
        value_type: format!("GpuSlice<{value_type}>"),
        access_mode: Some(access_mode),
        wire_slots: vec!["buffer_handle", "i32_offset", "i32_len"],
    }
}

fn shared_gpu_kernel_capability_flags(function: &kernel_ir::KernelFunction) -> Vec<String> {
    let mut flags = BTreeSet::new();
    for stmt in &function.body {
        collect_stmt_capabilities(stmt, &mut flags);
    }
    flags.into_iter().collect()
}

fn collect_stmt_capabilities(stmt: &kernel_ir::KernelStmt, out: &mut BTreeSet<String>) {
    match stmt {
        kernel_ir::KernelStmt::Let { value, .. } => collect_expr_capabilities(value, out),
        kernel_ir::KernelStmt::Assign { value, .. } => collect_expr_capabilities(value, out),
        kernel_ir::KernelStmt::Store { base, index, value } => {
            collect_expr_capabilities(base, out);
            collect_expr_capabilities(index, out);
            collect_expr_capabilities(value, out);
        }
        kernel_ir::KernelStmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_expr_capabilities(condition, out);
            for stmt in then_body {
                collect_stmt_capabilities(stmt, out);
            }
            for stmt in else_body {
                collect_stmt_capabilities(stmt, out);
            }
        }
        kernel_ir::KernelStmt::While { condition, body } => {
            collect_expr_capabilities(condition, out);
            for stmt in body {
                collect_stmt_capabilities(stmt, out);
            }
        }
        kernel_ir::KernelStmt::Loop { body } => {
            for stmt in body {
                collect_stmt_capabilities(stmt, out);
            }
        }
        kernel_ir::KernelStmt::Break(value) | kernel_ir::KernelStmt::Return(value) => {
            if let Some(value) = value {
                collect_expr_capabilities(value, out);
            }
        }
        kernel_ir::KernelStmt::Continue => {}
        kernel_ir::KernelStmt::Expr(expr) => collect_expr_capabilities(expr, out),
    }
}

fn collect_expr_capabilities(expr: &kernel_ir::KernelExpr, out: &mut BTreeSet<String>) {
    match expr {
        kernel_ir::KernelExpr::Unary { expr, .. } | kernel_ir::KernelExpr::Group(expr) => {
            collect_expr_capabilities(expr, out);
        }
        kernel_ir::KernelExpr::Binary { left, right, .. } => {
            collect_expr_capabilities(left, out);
            collect_expr_capabilities(right, out);
        }
        kernel_ir::KernelExpr::Call { args, .. }
        | kernel_ir::KernelExpr::Intrinsic { args, .. } => {
            if let kernel_ir::KernelExpr::Intrinsic { op, .. } = expr {
                out.insert(op.as_str().to_string());
            }
            for arg in args {
                collect_expr_capabilities(arg, out);
            }
        }
        kernel_ir::KernelExpr::Load { base, index } => {
            collect_expr_capabilities(base, out);
            collect_expr_capabilities(index, out);
        }
        kernel_ir::KernelExpr::ArrayLiteral(items) => {
            for item in items {
                collect_expr_capabilities(item, out);
            }
        }
        kernel_ir::KernelExpr::Int(_)
        | kernel_ir::KernelExpr::Float { .. }
        | kernel_ir::KernelExpr::Bool(_)
        | kernel_ir::KernelExpr::Char(_)
        | kernel_ir::KernelExpr::Ident(_) => {}
    }
}
