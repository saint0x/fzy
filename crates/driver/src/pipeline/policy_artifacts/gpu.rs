pub(super) fn build_gpu_kernel_package_json(typed: &hir::TypedModule) -> serde_json::Value {
    match kernel_ir::lower(typed) {
        Ok(kernel_module) => {
            let rendered = kernel_ir::render(&kernel_module);
            let backend_limit_profiles =
                super::gpu_kernel_layout::shared_gpu_backend_limit_profiles_json();
            let layout_catalog = super::gpu_kernel_layout::shared_gpu_layout_catalog_json();
            let metal_descriptors =
                super::gpu_kernel_metal::metal_kernel_launch_descriptors_from_kernel_module(
                    &kernel_module,
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
                .map(|function| {
                    serde_json::json!({
                        "name": function.name,
                        "executionSpace": function.execution_space.as_str(),
                        "params": function.params.iter().map(|param| {
                            let access_mode = function
                                .slice_access
                                .get(&param.name)
                                .copied()
                                .map(kernel_ir::KernelSliceAccessMode::as_str);
                            serde_json::json!({
                                "name": param.name,
                                "type": param.ty.to_string(),
                                "accessMode": access_mode,
                                "layoutClass": match &param.ty {
                                    ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
                                        let elem = match &args[0] {
                                            ast::Type::Float { bits: 32 } => Some("slice_f32"),
                                            ast::Type::Int { signed: true, bits: 32 } => Some("slice_i32"),
                                            ast::Type::Int { signed: false, bits: 32 } => Some("slice_u32"),
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
                                    ast::Type::Int { signed: true, bits: 32 } => Some("i32".to_string()),
                                    ast::Type::Int { signed: false, bits: 32 } => Some("u32".to_string()),
                                    ast::Type::Float { bits: 32 } => Some("f32".to_string()),
                                    _ => None,
                                },
                            })
                        }).collect::<Vec<_>>(),
                        "returnType": function.return_type.to_string(),
                        "kernelCapabilityFlags": super::gpu_kernel_layout::shared_gpu_kernel_contract(function)
                            .map(|contract| contract.capability_flags)
                            .unwrap_or_default(),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "schemaVersion": "fozzylang.gpu_kernel_package.v1",
                "versions": super::compat::compatibility_versions_json(),
                "status": if kernel_module.functions.is_empty() { "empty" } else { "ok" },
                "module": kernel_module.name,
                "kernels": kernel_module.kernels,
                "functionCount": functions.len(),
                "functions": functions,
                "backendNeutralAbi": {
                    "abiVersion": super::gpu_kernel_layout::SHARED_GPU_LAUNCH_ABI_VERSION,
                    "packageFormat": "kernel_ir",
                    "kernelIdentity": "function_name",
                    "argumentLayoutClasses": layout_catalog,
                    "backendLimitProfiles": backend_limit_profiles,
                    "launchPacket": {
                        "gridDimensions": ["x"],
                        "blockDimensions": ["x"],
                        "argumentEncoding": "fzy_native_scalar_and_handle_abi",
                        "sharedArgumentHandles": ["GpuDevice", "GpuBuffer", "GpuSlice", "GpuEvent"],
                    },
                },
                "backendAdapters": {
                    "metal": {
                        "architectureStatus": "declared",
                        "descriptorStatus": "shared_contract_bound",
                        "moduleFormat": "metal.compute_source",
                        "executableNow": cfg!(target_vendor = "apple"),
                        "kernels": kernel_module.kernels.iter().filter_map(|name| {
                            metal_descriptors.get(name).map(|descriptor| serde_json::json!({
                                "kernelName": descriptor.kernel_name,
                                "entryPoint": descriptor.kernel_name,
                                "paramLayout": descriptor.param_layout,
                                "sharedContract": descriptor.shared_contract.to_json(),
                                "backendLimits": backend_limit_profiles["metal"].clone(),
                            }))
                        }).collect::<Vec<_>>(),
                    },
                    "spirv": {
                        "architectureStatus": "declared",
                        "descriptorStatus": "shared_contract_bound_not_executable",
                        "moduleFormat": "spirv.binary_module",
                        "executableNow": false,
                        "reason": "SPIR-V/Vulkan codegen and runtime are not live yet, but this adapter now consumes the shared kernel package and launch layout contract.",
                        "kernels": kernel_module.kernels.iter().filter_map(|name| {
                            spirv_descriptors.get(name).map(|descriptor| serde_json::json!({
                                "kernelName": descriptor.kernel_name,
                                "entryPoint": descriptor.entry_point,
                                "paramLayout": descriptor.param_layout,
                                "moduleFormat": descriptor.module_format,
                                "executionModel": descriptor.execution_model,
                                "sharedContract": descriptor.shared_contract.to_json(),
                                "backendLimits": backend_limit_profiles["spirv"].clone(),
                            }))
                        }).collect::<Vec<_>>(),
                    },
                    "nvptx": {
                        "architectureStatus": "declared",
                        "descriptorStatus": "shared_contract_bound_not_executable",
                        "moduleFormat": "ptx.assembly_text",
                        "executableNow": false,
                        "reason": "NVPTX/CUDA codegen and runtime are not live yet, but this adapter now consumes the shared kernel package and launch layout contract.",
                        "kernels": kernel_module.kernels.iter().filter_map(|name| {
                            nvptx_descriptors.get(name).map(|descriptor| serde_json::json!({
                                "kernelName": descriptor.kernel_name,
                                "entrySymbol": descriptor.entry_symbol,
                                "paramLayout": descriptor.param_layout,
                                "moduleFormat": descriptor.module_format,
                                "entryDirective": descriptor.entry_directive,
                                "parameterStateSpace": descriptor.parameter_state_space,
                                "sharedContract": descriptor.shared_contract.to_json(),
                                "backendLimits": backend_limit_profiles["nvptx"].clone(),
                            }))
                        }).collect::<Vec<_>>(),
                    }
                },
                "renderedKernelIr": rendered,
            })
        }
        Err(diagnostics) => serde_json::json!({
            "schemaVersion": "fozzylang.gpu_kernel_package.v1",
            "versions": super::compat::compatibility_versions_json(),
            "status": "error",
            "module": typed.name,
            "kernels": [],
            "functionCount": 0,
            "functions": [],
            "backendNeutralAbi": {
                "abiVersion": super::gpu_kernel_layout::SHARED_GPU_LAUNCH_ABI_VERSION,
                "packageFormat": "kernel_ir",
                "kernelIdentity": "function_name",
                "argumentLayoutClasses": super::gpu_kernel_layout::shared_gpu_layout_catalog_json(),
                "backendLimitProfiles": super::gpu_kernel_layout::shared_gpu_backend_limit_profiles_json(),
                "launchPacket": {
                    "gridDimensions": ["x"],
                    "blockDimensions": ["x"],
                    "argumentEncoding": "fzy_native_scalar_and_handle_abi",
                    "sharedArgumentHandles": ["GpuDevice", "GpuBuffer", "GpuSlice", "GpuEvent"],
                },
            },
            "renderedKernelIr": "",
            "diagnostics": diagnostics
                .into_iter()
                .map(|diagnostic| {
                    serde_json::json!({
                        "severity": format!("{:?}", diagnostic.severity),
                        "message": diagnostic.message,
                        "help": diagnostic.help,
                        "catalogKey": diagnostic.catalog_key,
                    })
                })
                .collect::<Vec<_>>(),
        }),
    }
}

pub(super) fn render_gpu_kernel_package_markdown(value: &serde_json::Value) -> String {
    let mut out = String::from("# GPU Kernel Package\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Status: `{}`\n- Module: `{}`\n- Kernels: `{}`\n- Functions: `{}`\n\n",
        value["schemaVersion"].as_str().unwrap_or("unknown"),
        value["status"].as_str().unwrap_or("unknown"),
        value["module"].as_str().unwrap_or("?"),
        value["kernels"]
            .as_array()
            .map(|items| items.len())
            .unwrap_or(0),
        value["functionCount"].as_u64().unwrap_or(0),
    ));
    out.push_str("## Launch ABI\n\n");
    out.push_str(&format!(
        "- ABI version: `{}`\n- Package format: `{}`\n- Kernel identity: `{}`\n- Grid dimensions: `{}`\n- Block dimensions: `{}`\n- Argument encoding: `{}`\n\n",
        value["backendNeutralAbi"]["abiVersion"].as_str().unwrap_or("?"),
        value["backendNeutralAbi"]["packageFormat"].as_str().unwrap_or("?"),
        value["backendNeutralAbi"]["kernelIdentity"].as_str().unwrap_or("?"),
        value["backendNeutralAbi"]["launchPacket"]["gridDimensions"]
            .as_array()
            .map(|items| items.iter().filter_map(|item| item.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default(),
        value["backendNeutralAbi"]["launchPacket"]["blockDimensions"]
            .as_array()
            .map(|items| items.iter().filter_map(|item| item.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default(),
        value["backendNeutralAbi"]["launchPacket"]["argumentEncoding"]
            .as_str()
            .unwrap_or("?"),
    ));
    out.push_str("## Layout Classes\n\n");
    out.push_str("| Class | Value Type | Access | Wire Slots |\n|---|---|---|---|\n");
    if let Some(classes) = value["backendNeutralAbi"]["argumentLayoutClasses"].as_array() {
        for class in classes {
            let wire_slots = class["wireSlots"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` |\n",
                class["name"].as_str().unwrap_or("?"),
                class["valueType"].as_str().unwrap_or("?"),
                class["accessMode"].as_str().unwrap_or("-"),
                wire_slots,
            ));
        }
    }
    out.push('\n');
    out.push_str("## Functions\n\n");
    out.push_str("| Function | Space | Params | Capabilities | Return |\n|---|---|---|---|---|\n");
    if let Some(functions) = value["functions"].as_array() {
        for function in functions {
            let params = function["params"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            format!(
                                "{}: {}",
                                item["name"].as_str().unwrap_or("?"),
                                item["type"].as_str().unwrap_or("?")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let capabilities = function["kernelCapabilityFlags"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` |\n",
                function["name"].as_str().unwrap_or("?"),
                function["executionSpace"].as_str().unwrap_or("?"),
                params,
                capabilities,
                function["returnType"].as_str().unwrap_or("?"),
            ));
        }
    }
    if let Some(diagnostics) = value["diagnostics"].as_array() {
        out.push_str("\n## Diagnostics\n\n");
        if diagnostics.is_empty() {
            out.push_str("_No diagnostics._\n");
        } else {
            for diagnostic in diagnostics {
                out.push_str(&format!(
                    "- `{}`: {}\n",
                    diagnostic["severity"].as_str().unwrap_or("unknown"),
                    diagnostic["message"].as_str().unwrap_or("missing"),
                ));
            }
        }
    }
    let rendered = value["renderedKernelIr"].as_str().unwrap_or_default();
    if !rendered.is_empty() {
        out.push_str("\n## Rendered Kernel IR\n\n```text\n");
        out.push_str(rendered);
        if !rendered.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n");
    }
    out
}
