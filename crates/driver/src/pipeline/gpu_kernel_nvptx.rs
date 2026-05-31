use std::collections::{BTreeMap, HashMap};

use anyhow::Result;

use super::gpu_kernel_layout::render_shared_param_layout;

#[derive(Debug, Clone)]
pub(crate) struct NvptxKernelContractDescriptor {
    pub(crate) kernel_name: String,
    pub(crate) entry_symbol: String,
    pub(crate) param_layout: String,
    pub(crate) module_format: &'static str,
    pub(crate) entry_directive: &'static str,
    pub(crate) parameter_state_space: &'static str,
}

pub(crate) fn nvptx_kernel_contract_descriptors_from_kernel_module(
    module: &kernel_ir::KernelModule,
) -> Result<HashMap<String, NvptxKernelContractDescriptor>> {
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
        descriptors.insert(
            kernel_name.clone(),
            NvptxKernelContractDescriptor {
                kernel_name: kernel_name.clone(),
                entry_symbol: kernel.name.clone(),
                param_layout: render_shared_param_layout(kernel)?,
                module_format: "ptx.assembly_text",
                entry_directive: ".entry",
                parameter_state_space: ".param",
            },
        );
    }
    Ok(descriptors)
}
