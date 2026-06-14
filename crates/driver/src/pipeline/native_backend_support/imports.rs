use super::*;

pub(crate) fn declare_native_runtime_imports(
    module: &mut ObjectModule,
    function_ids: &mut HashMap<String, cranelift_module::FuncId>,
    function_signatures: &mut HashMap<String, ClifFunctionSignature>,
) -> Result<()> {
    for import in native_runtime_imports() {
        if function_ids.contains_key(import.callee) {
            continue;
        }
        let mut sig = module.make_signature();
        let mut params = Vec::with_capacity(import.arity);
        let mut ret = Some(types::I32);
        match import.callee {
            "alloc" => {
                params.push(pointer_sized_clif_type());
                sig.params.push(AbiParam::new(pointer_sized_clif_type()));
                sig.returns.push(AbiParam::new(pointer_sized_clif_type()));
                ret = Some(pointer_sized_clif_type());
            }
            "free" => {
                params.push(pointer_sized_clif_type());
                sig.params.push(AbiParam::new(pointer_sized_clif_type()));
                ret = None;
            }
            "gpu.device_memory_bytes" => {
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                sig.returns.push(AbiParam::new(types::I64));
                ret = Some(types::I64);
            }
            "gpu.upload_f32" | "gpu.upload_i32" | "gpu.upload_u32" => {
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                params.push(pointer_sized_clif_type());
                sig.params.push(AbiParam::new(pointer_sized_clif_type()));
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                sig.returns.push(AbiParam::new(types::I32));
            }
            "gpu.download_f32" | "gpu.download_i32" | "gpu.download_u32" => {
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                sig.returns.push(AbiParam::new(pointer_sized_clif_type()));
                ret = Some(pointer_sized_clif_type());
            }
            "gpu.slice" => {
                for _ in 0..import.arity {
                    params.push(types::I32);
                    sig.params.push(AbiParam::new(types::I32));
                }
                sig.returns.push(AbiParam::new(pointer_sized_clif_type()));
                ret = Some(pointer_sized_clif_type());
            }
            "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4" => {
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                params.push(types::I32);
                sig.params.push(AbiParam::new(types::I32));
                for _ in 5..import.arity {
                    params.push(pointer_sized_clif_type());
                    sig.params.push(AbiParam::new(pointer_sized_clif_type()));
                }
                sig.returns.push(AbiParam::new(types::I32));
            }
            _ => {
                for _ in 0..import.arity {
                    params.push(types::I32);
                    sig.params.push(AbiParam::new(types::I32));
                }
                sig.returns.push(AbiParam::new(types::I32));
            }
        }
        let id = module
            .declare_function(import.symbol, Linkage::Import, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring native runtime import `{}` for `{}`: {error}",
                    import.symbol,
                    import.callee
                )
            })?;
        function_ids.insert(import.callee.to_string(), id);
        function_signatures.insert(
            import.callee.to_string(),
            ClifFunctionSignature {
                params,
                ret,
                sret: None,
                param_names: Vec::new(),
                is_extern_c_import: false,
            },
        );
    }

    let internal_helpers = [
        (
            NATIVE_AGG_NEW,
            NATIVE_AGG_NEW_SYMBOL,
            vec![types::I32, types::I32],
            Some(types::I64),
        ),
        (
            NATIVE_AGG_SET_I64,
            NATIVE_AGG_SET_I64_SYMBOL,
            vec![types::I64, types::I32, types::I64],
            Some(types::I32),
        ),
        (
            NATIVE_AGG_GET_I64,
            NATIVE_AGG_GET_I64_SYMBOL,
            vec![types::I64, types::I32],
            Some(types::I64),
        ),
        (
            NATIVE_AGG_TAG,
            NATIVE_AGG_TAG_SYMBOL,
            vec![types::I64],
            Some(types::I32),
        ),
        (
            NATIVE_STR_PTR,
            NATIVE_STR_PTR_SYMBOL,
            vec![types::I32],
            Some(pointer_sized_clif_type()),
        ),
        (
            NATIVE_VEC_LEN,
            NATIVE_VEC_LEN_SYMBOL,
            vec![pointer_sized_clif_type()],
            Some(types::I32),
        ),
        (
            NATIVE_VEC_GET_I32,
            NATIVE_VEC_GET_I32_SYMBOL,
            vec![pointer_sized_clif_type(), types::I32],
            Some(types::I32),
        ),
        (
            NATIVE_VEC_GET_U32,
            NATIVE_VEC_GET_U32_SYMBOL,
            vec![pointer_sized_clif_type(), types::I32],
            Some(types::I32),
        ),
        (
            NATIVE_VEC_GET_F32,
            NATIVE_VEC_GET_F32_SYMBOL,
            vec![pointer_sized_clif_type(), types::I32],
            Some(types::F32),
        ),
    ];
    for (callee, symbol, params, ret) in internal_helpers {
        if function_ids.contains_key(callee) {
            continue;
        }
        let mut sig = module.make_signature();
        for param in &params {
            sig.params.push(AbiParam::new(*param));
        }
        if let Some(ret_ty) = ret {
            sig.returns.push(AbiParam::new(ret_ty));
        }
        let id = module
            .declare_function(symbol, Linkage::Import, &sig)
            .map_err(|error| {
                anyhow!("failed declaring internal native helper `{symbol}`: {error}")
            })?;
        function_ids.insert(callee.to_string(), id);
        function_signatures.insert(
            callee.to_string(),
            ClifFunctionSignature {
                params,
                ret,
                sret: None,
                param_names: Vec::new(),
                is_extern_c_import: false,
            },
        );
    }
    Ok(())
}

pub(crate) fn declare_native_data_plane_imports(
    module: &mut ObjectModule,
    function_ids: &mut HashMap<String, cranelift_module::FuncId>,
    function_signatures: &mut HashMap<String, ClifFunctionSignature>,
) -> Result<()> {
    for import in NATIVE_DATA_PLANE_IMPORTS {
        if function_ids.contains_key(import.callee) {
            continue;
        }
        let mut sig = module.make_signature();
        for _ in 0..import.arity {
            sig.params.push(AbiParam::new(types::I32));
        }
        sig.returns.push(AbiParam::new(types::I32));
        let id = module
            .declare_function(import.symbol, Linkage::Import, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring native data-plane import `{}` for `{}`: {error}",
                    import.symbol,
                    import.callee
                )
            })?;
        function_ids.insert(import.callee.to_string(), id);
        function_signatures.insert(
            import.callee.to_string(),
            ClifFunctionSignature {
                params: (0..import.arity).map(|_| types::I32).collect(),
                ret: Some(types::I32),
                sret: None,
                param_names: Vec::new(),
                is_extern_c_import: false,
            },
        );
    }
    Ok(())
}
