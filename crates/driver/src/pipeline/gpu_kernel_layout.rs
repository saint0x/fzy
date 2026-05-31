use anyhow::{bail, Result};

pub(crate) fn render_shared_param_layout(function: &kernel_ir::KernelFunction) -> Result<String> {
    let mut parts = Vec::with_capacity(function.params.len());
    for param in &function.params {
        parts.push(match &param.ty {
            ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
                let suffix = function
                    .slice_access
                    .get(&param.name)
                    .copied()
                    .unwrap_or(kernel_ir::KernelSliceAccessMode::Observe)
                    .layout_suffix();
                match &args[0] {
                    ast::Type::Float { bits: 32 } => format!("slice_f32_{suffix}"),
                    ast::Type::Int {
                        signed: true,
                        bits: 32,
                    } => format!("slice_i32_{suffix}"),
                    ast::Type::Int {
                        signed: false,
                        bits: 32,
                    } => format!("slice_u32_{suffix}"),
                    other => bail!(
                        "shared GPU launch layout does not yet support slice element type `{other}`"
                    ),
                }
            }
            ast::Type::Int {
                signed: true,
                bits: 32,
            } => "i32".to_string(),
            ast::Type::Int {
                signed: false,
                bits: 32,
            } => "u32".to_string(),
            ast::Type::Float { bits: 32 } => "f32".to_string(),
            other => bail!("shared GPU launch layout does not yet support kernel param `{other}`"),
        });
    }
    Ok(parts.join(","))
}
