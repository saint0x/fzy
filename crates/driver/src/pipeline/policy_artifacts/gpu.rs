#[derive(Debug, Clone)]
pub(super) struct GpuKernelPackage {
    schema_version: &'static str,
    versions: super::compat::CompatibilityVersions,
    status: &'static str,
    module: String,
    kernels: Vec<String>,
    functions: Vec<GpuKernelFunctionReport>,
    backend_neutral_abi: GpuKernelBackendNeutralAbi,
    backend_adapters: GpuKernelBackendAdapters,
    rendered_kernel_ir: String,
    diagnostics: Vec<GpuKernelDiagnosticReport>,
}

#[derive(Debug, Clone)]
struct GpuKernelFunctionReport {
    name: String,
    execution_space: &'static str,
    params: Vec<GpuKernelParamReport>,
    return_type: String,
    kernel_capability_flags: Vec<String>,
}

#[derive(Debug, Clone)]
struct GpuKernelParamReport {
    name: String,
    ty: String,
    access_mode: Option<&'static str>,
    layout_class: Option<String>,
}

#[derive(Debug, Clone)]
struct GpuKernelBackendNeutralAbi {
    abi_version: &'static str,
    package_format: &'static str,
    kernel_identity: &'static str,
    argument_layout_classes: Vec<super::gpu_kernel_layout::SharedGpuLayoutClass>,
    backend_limit_profiles: super::gpu_kernel_layout::SharedGpuBackendLimitProfiles,
    launch_packet: GpuKernelLaunchPacket,
}

#[derive(Debug, Clone)]
struct GpuKernelLaunchPacket {
    grid_dimensions: Vec<&'static str>,
    block_dimensions: Vec<&'static str>,
    argument_encoding: &'static str,
    shared_argument_handles: Vec<&'static str>,
}

#[derive(Debug, Clone)]
struct GpuKernelBackendAdapters {
    metal: GpuKernelBackendAdapterReport,
    rocm: GpuKernelBackendAdapterReport,
    cuda: GpuKernelBackendAdapterReport,
    spirv: GpuKernelBackendAdapterReport,
    nvptx: GpuKernelBackendAdapterReport,
}

#[derive(Debug, Clone)]
struct GpuKernelBackendAdapterReport {
    architecture_status: &'static str,
    descriptor_status: &'static str,
    module_format: &'static str,
    executable_now: bool,
    reason: Option<&'static str>,
    kernels: Vec<GpuKernelBackendKernelReport>,
}

#[derive(Debug, Clone)]
struct GpuKernelBackendKernelReport {
    kernel_name: String,
    entry_point: Option<String>,
    entry_symbol: Option<String>,
    param_layout: String,
    module_format: Option<String>,
    execution_model: Option<String>,
    entry_directive: Option<String>,
    parameter_state_space: Option<String>,
    shared_contract: super::gpu_kernel_layout::SharedGpuKernelContract,
    backend_limits: super::gpu_kernel_layout::SharedGpuBackendLimitProfile,
}

#[derive(Debug, Clone)]
struct GpuKernelDiagnosticReport {
    severity: String,
    message: String,
    help: Option<String>,
    catalog_key: Option<String>,
}

impl GpuKernelPackage {
    fn function_count(&self) -> usize {
        self.functions.len()
    }

    pub(super) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": self.schema_version,
            "versions": self.versions,
            "status": self.status,
            "module": self.module,
            "kernels": self.kernels,
            "functionCount": self.function_count(),
            "functions": self.functions.iter().map(GpuKernelFunctionReport::to_json).collect::<Vec<_>>(),
            "backendNeutralAbi": self.backend_neutral_abi.to_json(),
            "backendAdapters": self.backend_adapters.to_json(),
            "renderedKernelIr": self.rendered_kernel_ir,
            "diagnostics": self.diagnostics.iter().map(GpuKernelDiagnosticReport::to_json).collect::<Vec<_>>(),
        })
    }
}

impl GpuKernelFunctionReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "executionSpace": self.execution_space,
            "params": self.params.iter().map(GpuKernelParamReport::to_json).collect::<Vec<_>>(),
            "returnType": self.return_type,
            "kernelCapabilityFlags": self.kernel_capability_flags,
        })
    }
}

impl GpuKernelParamReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "type": self.ty,
            "accessMode": self.access_mode,
            "layoutClass": self.layout_class,
        })
    }
}

impl GpuKernelBackendNeutralAbi {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "abiVersion": self.abi_version,
            "packageFormat": self.package_format,
            "kernelIdentity": self.kernel_identity,
            "argumentLayoutClasses": self.argument_layout_classes.iter().map(|class| class.to_json()).collect::<Vec<_>>(),
            "backendLimitProfiles": self.backend_limit_profiles.to_json(),
            "launchPacket": self.launch_packet.to_json(),
        })
    }
}

impl GpuKernelLaunchPacket {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "gridDimensions": self.grid_dimensions,
            "blockDimensions": self.block_dimensions,
            "argumentEncoding": self.argument_encoding,
            "sharedArgumentHandles": self.shared_argument_handles,
        })
    }
}

impl GpuKernelBackendAdapters {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "metal": self.metal.to_json(),
            "rocm": self.rocm.to_json(),
            "cuda": self.cuda.to_json(),
            "spirv": self.spirv.to_json(),
            "nvptx": self.nvptx.to_json(),
        })
    }
}

impl GpuKernelBackendAdapterReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "architectureStatus": self.architecture_status,
            "descriptorStatus": self.descriptor_status,
            "moduleFormat": self.module_format,
            "executableNow": self.executable_now,
            "reason": self.reason,
            "kernels": self.kernels.iter().map(GpuKernelBackendKernelReport::to_json).collect::<Vec<_>>(),
        })
    }
}

impl GpuKernelBackendKernelReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kernelName": self.kernel_name,
            "entryPoint": self.entry_point,
            "entrySymbol": self.entry_symbol,
            "paramLayout": self.param_layout,
            "moduleFormat": self.module_format,
            "executionModel": self.execution_model,
            "entryDirective": self.entry_directive,
            "parameterStateSpace": self.parameter_state_space,
            "sharedContract": self.shared_contract.to_json(),
            "backendLimits": self.backend_limits.to_json(),
        })
    }
}

impl GpuKernelDiagnosticReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "severity": self.severity,
            "message": self.message,
            "help": self.help,
            "catalogKey": self.catalog_key,
        })
    }
}

pub(super) fn build_gpu_kernel_package(typed: &hir::TypedModule) -> GpuKernelPackage {
    let backend_limit_profiles = super::gpu_kernel_layout::shared_gpu_backend_limit_profiles();
    let backend_neutral_abi = GpuKernelBackendNeutralAbi {
        abi_version: super::gpu_kernel_layout::SHARED_GPU_LAUNCH_ABI_VERSION,
        package_format: "kernel_ir",
        kernel_identity: "function_name",
        argument_layout_classes: super::gpu_kernel_layout::shared_gpu_layout_catalog(),
        backend_limit_profiles: backend_limit_profiles.clone(),
        launch_packet: GpuKernelLaunchPacket {
            grid_dimensions: vec!["x"],
            block_dimensions: vec!["x"],
            argument_encoding: "fzy_native_scalar_and_handle_abi",
            shared_argument_handles: vec!["GpuDevice", "GpuBuffer", "GpuSlice", "GpuEvent"],
        },
    };

    match kernel_ir::lower(typed) {
        Ok(kernel_module) => {
            let rendered = kernel_ir::render(&kernel_module);
            let metal_descriptors = super::gpu_kernel_source::gpu_kernel_launch_descriptors_from_kernel_module(
                &kernel_module,
                super::gpu_backend::GpuBackendKind::Metal,
            )
            .unwrap_or_default();
            let rocm_descriptors = super::gpu_kernel_source::gpu_kernel_launch_descriptors_from_kernel_module(
                &kernel_module,
                super::gpu_backend::GpuBackendKind::Rocm,
            )
            .unwrap_or_default();
            let cuda_descriptors = super::gpu_kernel_source::gpu_kernel_launch_descriptors_from_kernel_module(
                &kernel_module,
                super::gpu_backend::GpuBackendKind::Cuda,
            )
            .unwrap_or_default();
            let spirv_descriptors =
                super::gpu_kernel_spirv::spirv_kernel_contract_descriptors_from_kernel_module(
                    &kernel_module,
                )
                .unwrap_or_default();
            let nvptx_descriptors =
                super::gpu_kernel_nvptx::nvptx_kernel_contract_descriptors_from_kernel_module(
                    &kernel_module,
                )
                .unwrap_or_default();
            let functions = kernel_module
                .functions
                .iter()
                .map(build_gpu_kernel_function_report)
                .collect::<Vec<_>>();

            GpuKernelPackage {
                schema_version: "fozzylang.gpu_kernel_package.v1",
                versions: super::compat::compatibility_versions(),
                status: if kernel_module.functions.is_empty() {
                    "empty"
                } else {
                    "ok"
                },
                module: kernel_module.name.clone(),
                kernels: kernel_module.kernels.clone(),
                functions,
                backend_neutral_abi,
                backend_adapters: GpuKernelBackendAdapters {
                    metal: GpuKernelBackendAdapterReport {
                        architecture_status: "declared",
                        descriptor_status: "shared_contract_bound",
                        module_format: "metal.compute_source",
                        executable_now: cfg!(target_vendor = "apple"),
                        reason: None,
                        kernels: kernel_module
                            .kernels
                            .iter()
                            .filter_map(|name| {
                                metal_descriptors.get(name).map(|descriptor| {
                                    GpuKernelBackendKernelReport {
                                        kernel_name: descriptor.kernel_name.clone(),
                                        entry_point: Some(descriptor.kernel_name.clone()),
                                        entry_symbol: None,
                                        param_layout: descriptor.param_layout.clone(),
                                        module_format: None,
                                        execution_model: None,
                                        entry_directive: None,
                                        parameter_state_space: None,
                                        shared_contract: descriptor.shared_contract.clone(),
                                        backend_limits: backend_limit_profiles
                                            .for_backend(super::gpu_backend::GpuBackendKind::Metal)
                                            .clone(),
                                    }
                                })
                            })
                            .collect(),
                    },
                    rocm: GpuKernelBackendAdapterReport {
                        architecture_status: "declared",
                        descriptor_status: "shared_contract_bound",
                        module_format: "hiprtc.source",
                        executable_now: cfg!(target_os = "linux"),
                        reason: None,
                        kernels: kernel_module
                            .kernels
                            .iter()
                            .filter_map(|name| {
                                rocm_descriptors.get(name).map(|descriptor| {
                                    GpuKernelBackendKernelReport {
                                        kernel_name: descriptor.kernel_name.clone(),
                                        entry_point: Some(descriptor.kernel_name.clone()),
                                        entry_symbol: None,
                                        param_layout: descriptor.param_layout.clone(),
                                        module_format: None,
                                        execution_model: None,
                                        entry_directive: None,
                                        parameter_state_space: None,
                                        shared_contract: descriptor.shared_contract.clone(),
                                        backend_limits: backend_limit_profiles
                                            .for_backend(super::gpu_backend::GpuBackendKind::Rocm)
                                            .clone(),
                                    }
                                })
                            })
                            .collect(),
                    },
                    cuda: GpuKernelBackendAdapterReport {
                        architecture_status: "declared",
                        descriptor_status: "shared_contract_bound",
                        module_format: "nvrtc.cuda_source",
                        executable_now: false,
                        reason: Some(
                            "CUDA source/kernel package shape is first-class, but live CUDA runtime execution waits for NVIDIA hardware validation.",
                        ),
                        kernels: kernel_module
                            .kernels
                            .iter()
                            .filter_map(|name| {
                                cuda_descriptors.get(name).map(|descriptor| {
                                    GpuKernelBackendKernelReport {
                                        kernel_name: descriptor.kernel_name.clone(),
                                        entry_point: Some(descriptor.kernel_name.clone()),
                                        entry_symbol: None,
                                        param_layout: descriptor.param_layout.clone(),
                                        module_format: None,
                                        execution_model: None,
                                        entry_directive: None,
                                        parameter_state_space: None,
                                        shared_contract: descriptor.shared_contract.clone(),
                                        backend_limits: backend_limit_profiles
                                            .for_backend(super::gpu_backend::GpuBackendKind::Cuda)
                                            .clone(),
                                    }
                                })
                            })
                            .collect(),
                    },
                    spirv: GpuKernelBackendAdapterReport {
                        architecture_status: "declared",
                        descriptor_status: "shared_contract_bound_not_executable",
                        module_format: "spirv.binary_module",
                        executable_now: false,
                        reason: Some(
                            "SPIR-V/Vulkan codegen and runtime are not live yet, but this adapter now consumes the shared kernel package and launch layout contract.",
                        ),
                        kernels: kernel_module
                            .kernels
                            .iter()
                            .filter_map(|name| {
                                spirv_descriptors.get(name).map(|descriptor| {
                                    GpuKernelBackendKernelReport {
                                        kernel_name: descriptor.kernel_name.clone(),
                                        entry_point: Some(descriptor.entry_point.clone()),
                                        entry_symbol: None,
                                        param_layout: descriptor.param_layout.clone(),
                                        module_format: Some(descriptor.module_format.to_string()),
                                        execution_model: Some(
                                            descriptor.execution_model.to_string(),
                                        ),
                                        entry_directive: None,
                                        parameter_state_space: None,
                                        shared_contract: descriptor.shared_contract.clone(),
                                        backend_limits: backend_limit_profiles
                                            .for_backend(super::gpu_backend::GpuBackendKind::Spirv)
                                            .clone(),
                                    }
                                })
                            })
                            .collect(),
                    },
                    nvptx: GpuKernelBackendAdapterReport {
                        architecture_status: "declared",
                        descriptor_status: "shared_contract_bound_not_executable",
                        module_format: "ptx.assembly_text",
                        executable_now: false,
                        reason: Some(
                            "NVPTX/CUDA codegen and runtime are not live yet, but this adapter now consumes the shared kernel package and launch layout contract.",
                        ),
                        kernels: kernel_module
                            .kernels
                            .iter()
                            .filter_map(|name| {
                                nvptx_descriptors.get(name).map(|descriptor| {
                                    GpuKernelBackendKernelReport {
                                        kernel_name: descriptor.kernel_name.clone(),
                                        entry_point: None,
                                        entry_symbol: Some(descriptor.entry_symbol.clone()),
                                        param_layout: descriptor.param_layout.clone(),
                                        module_format: Some(descriptor.module_format.to_string()),
                                        execution_model: None,
                                        entry_directive: Some(
                                            descriptor.entry_directive.to_string(),
                                        ),
                                        parameter_state_space: Some(
                                            descriptor.parameter_state_space.to_string(),
                                        ),
                                        shared_contract: descriptor.shared_contract.clone(),
                                        backend_limits: backend_limit_profiles
                                            .for_backend(super::gpu_backend::GpuBackendKind::Nvptx)
                                            .clone(),
                                    }
                                })
                            })
                            .collect(),
                    },
                },
                rendered_kernel_ir: rendered,
                diagnostics: Vec::new(),
            }
        }
        Err(diagnostics) => GpuKernelPackage {
            schema_version: "fozzylang.gpu_kernel_package.v1",
            versions: super::compat::compatibility_versions(),
            status: "error",
            module: typed.name.clone(),
            kernels: Vec::new(),
            functions: Vec::new(),
            backend_neutral_abi,
            backend_adapters: GpuKernelBackendAdapters {
                metal: GpuKernelBackendAdapterReport {
                    architecture_status: "declared",
                    descriptor_status: "shared_contract_bound",
                    module_format: "metal.compute_source",
                    executable_now: cfg!(target_vendor = "apple"),
                    reason: None,
                    kernels: Vec::new(),
                },
                rocm: GpuKernelBackendAdapterReport {
                    architecture_status: "declared",
                    descriptor_status: "shared_contract_bound",
                    module_format: "hiprtc.source",
                    executable_now: cfg!(target_os = "linux"),
                    reason: None,
                    kernels: Vec::new(),
                },
                cuda: GpuKernelBackendAdapterReport {
                    architecture_status: "declared",
                    descriptor_status: "shared_contract_bound",
                    module_format: "nvrtc.cuda_source",
                    executable_now: false,
                    reason: Some(
                        "CUDA source/kernel package shape is first-class, but live CUDA runtime execution waits for NVIDIA hardware validation.",
                    ),
                    kernels: Vec::new(),
                },
                spirv: GpuKernelBackendAdapterReport {
                    architecture_status: "declared",
                    descriptor_status: "shared_contract_bound_not_executable",
                    module_format: "spirv.binary_module",
                    executable_now: false,
                    reason: Some(
                        "SPIR-V/Vulkan codegen and runtime are not live yet, but this adapter now consumes the shared kernel package and launch layout contract.",
                    ),
                    kernels: Vec::new(),
                },
                nvptx: GpuKernelBackendAdapterReport {
                    architecture_status: "declared",
                    descriptor_status: "shared_contract_bound_not_executable",
                    module_format: "ptx.assembly_text",
                    executable_now: false,
                    reason: Some(
                        "NVPTX/CUDA codegen and runtime are not live yet, but this adapter now consumes the shared kernel package and launch layout contract.",
                    ),
                    kernels: Vec::new(),
                },
            },
            rendered_kernel_ir: String::new(),
            diagnostics: diagnostics
                .into_iter()
                .map(|diagnostic| GpuKernelDiagnosticReport {
                    severity: format!("{:?}", diagnostic.severity),
                    message: diagnostic.message,
                    help: diagnostic.help,
                    catalog_key: diagnostic.catalog_key,
                })
                .collect(),
        },
    }
}

fn build_gpu_kernel_function_report(
    function: &kernel_ir::KernelFunction,
) -> GpuKernelFunctionReport {
    GpuKernelFunctionReport {
        name: function.name.clone(),
        execution_space: function.execution_space.as_str(),
        params: function
            .params
            .iter()
            .map(|param| build_gpu_kernel_param_report(function, param))
            .collect(),
        return_type: function.return_type.to_string(),
        kernel_capability_flags: super::gpu_kernel_layout::shared_gpu_kernel_contract(function)
            .map(|contract| contract.capability_flags)
            .unwrap_or_default(),
    }
}

fn build_gpu_kernel_param_report(
    function: &kernel_ir::KernelFunction,
    param: &ast::Param,
) -> GpuKernelParamReport {
    let access_mode = function
        .slice_access
        .get(&param.name)
        .copied()
        .map(kernel_ir::KernelSliceAccessMode::as_str);
    GpuKernelParamReport {
        name: param.name.clone(),
        ty: param.ty.to_string(),
        access_mode,
        layout_class: gpu_kernel_layout_class_name(&param.ty, access_mode),
    }
}

fn gpu_kernel_layout_class_name(
    ty: &ast::Type,
    access_mode: Option<&'static str>,
) -> Option<String> {
    match ty {
        ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
            let elem = match &args[0] {
                ast::Type::Float { bits: 32 } => Some("slice_f32"),
                ast::Type::Int {
                    signed: true,
                    bits: 32,
                } => Some("slice_i32"),
                ast::Type::Int {
                    signed: false,
                    bits: 32,
                } => Some("slice_u32"),
                _ => None,
            };
            elem.and_then(|elem| {
                let suffix = match access_mode.unwrap_or("observe") {
                    "observe" | "readonly" => "ro",
                    "writeonly" => "wo",
                    "readwrite" => "rw",
                    _ => return None,
                };
                Some(format!("{elem}_{suffix}"))
            })
        }
        ast::Type::Int {
            signed: true,
            bits: 32,
        } => Some("i32".to_string()),
        ast::Type::Int {
            signed: false,
            bits: 32,
        } => Some("u32".to_string()),
        ast::Type::Float { bits: 32 } => Some("f32".to_string()),
        _ => None,
    }
}

pub(super) fn render_gpu_kernel_package_markdown(package: &GpuKernelPackage) -> String {
    let mut out = String::from("# GPU Kernel Package\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Status: `{}`\n- Module: `{}`\n- Kernels: `{}`\n- Functions: `{}`\n\n",
        package.schema_version,
        package.status,
        package.module,
        package.kernels.len(),
        package.function_count(),
    ));
    out.push_str("## Launch ABI\n\n");
    out.push_str(&format!(
        "- ABI version: `{}`\n- Package format: `{}`\n- Kernel identity: `{}`\n- Grid dimensions: `{}`\n- Block dimensions: `{}`\n- Argument encoding: `{}`\n\n",
        package.backend_neutral_abi.abi_version,
        package.backend_neutral_abi.package_format,
        package.backend_neutral_abi.kernel_identity,
        package
            .backend_neutral_abi
            .launch_packet
            .grid_dimensions
            .join(", "),
        package
            .backend_neutral_abi
            .launch_packet
            .block_dimensions
            .join(", "),
        package.backend_neutral_abi.launch_packet.argument_encoding,
    ));
    out.push_str("## Layout Classes\n\n");
    out.push_str("| Class | Value Type | Access | Wire Slots |\n|---|---|---|---|\n");
    for class in &package.backend_neutral_abi.argument_layout_classes {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` |\n",
            class.name,
            class.value_type,
            class.access_mode.unwrap_or("-"),
            class.wire_slots.join(", "),
        ));
    }
    out.push('\n');
    out.push_str("## Functions\n\n");
    out.push_str("| Function | Space | Params | Capabilities | Return |\n|---|---|---|---|---|\n");
    for function in &package.functions {
        let params = function
            .params
            .iter()
            .map(|param| format!("{}: {}", param.name, param.ty))
            .collect::<Vec<_>>()
            .join(", ");
        let capabilities = function.kernel_capability_flags.join(", ");
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` |\n",
            function.name, function.execution_space, params, capabilities, function.return_type,
        ));
    }
    if !package.diagnostics.is_empty() {
        out.push_str("\n## Diagnostics\n\n");
        for diagnostic in &package.diagnostics {
            out.push_str(&format!(
                "- `{}`: {}\n",
                diagnostic.severity, diagnostic.message,
            ));
        }
    }
    if !package.rendered_kernel_ir.is_empty() {
        out.push_str("\n## Rendered Kernel IR\n\n```text\n");
        out.push_str(&package.rendered_kernel_ir);
        if !package.rendered_kernel_ir.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n");
    }
    out
}
