use std::collections::{BTreeMap, HashMap};

use anyhow::Result;

use super::gpu_kernel_layout::{shared_gpu_kernel_contract, SharedGpuKernelContract};

#[derive(Debug, Clone)]
pub(crate) struct SpirvKernelContractDescriptor {
    pub(crate) kernel_name: String,
    pub(crate) entry_point: String,
    pub(crate) param_layout: String,
    pub(crate) module_format: &'static str,
    pub(crate) execution_model: &'static str,
    pub(crate) shared_contract: SharedGpuKernelContract,
}

pub(crate) fn spirv_kernel_contract_descriptors_from_kernel_module(
    module: &kernel_ir::KernelModule,
) -> Result<HashMap<String, SpirvKernelContractDescriptor>> {
    let function_map = module
        .functions
        .iter()
        .map(|function| (function.name.clone(), function))
        .collect::<BTreeMap<_, _>>();
    let mut descriptors = HashMap::new();
    for kernel_name in &module.kernels {
        let Some(kernel) = function_map.get(kernel_name) else {
            continue;
        };
        descriptors.insert(kernel_name.clone(), {
            let shared_contract = shared_gpu_kernel_contract(kernel)?;
            SpirvKernelContractDescriptor {
                kernel_name: kernel_name.clone(),
                entry_point: kernel.name.clone(),
                param_layout: shared_contract.param_layout.clone(),
                module_format: "spirv.binary_module",
                execution_model: "GLCompute",
                shared_contract,
            }
        });
    }
    Ok(descriptors)
}
