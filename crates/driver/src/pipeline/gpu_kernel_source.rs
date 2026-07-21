use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, bail, Result};

use super::gpu_backend::GpuBackendKind;
use super::gpu_kernel_layout::{shared_gpu_kernel_contract, SharedGpuKernelContract};

#[derive(Debug, Clone)]
pub(crate) struct GpuKernelLaunchDescriptor {
    pub(crate) kernel_name: String,
    pub(crate) source: String,
    pub(crate) param_layout: String,
    pub(crate) shared_contract: SharedGpuKernelContract,
}

pub(crate) fn gpu_kernel_launch_descriptors(
    fir: &fir::FirModule,
    backend: GpuBackendKind,
) -> Result<HashMap<String, GpuKernelLaunchDescriptor>> {
    let typed = synthesize_typed_module(fir);
    let module = kernel_ir::lower(&typed)
        .map_err(|diagnostics| anyhow!(render_kernel_ir_diagnostics(&diagnostics)))?;
    gpu_kernel_launch_descriptors_from_kernel_module(&module, backend)
}

pub(crate) fn gpu_kernel_launch_descriptors_from_kernel_module(
    module: &kernel_ir::KernelModule,
    backend: GpuBackendKind,
) -> Result<HashMap<String, GpuKernelLaunchDescriptor>> {
    if module.kernels.is_empty() {
        return Ok(HashMap::new());
    }
    let function_map = module
        .functions
        .iter()
        .map(|function| (function.name.clone(), function))
        .collect::<BTreeMap<_, _>>();
    let mut descriptors = HashMap::new();
    for kernel_name in &module.kernels {
        let kernel = function_map
            .get(kernel_name)
            .ok_or_else(|| anyhow!("kernel package missing entry `{kernel_name}`"))?;
        let source = render_gpu_module(&module, &function_map, kernel, backend)?;
        descriptors.insert(kernel_name.clone(), {
            let shared_contract = shared_gpu_kernel_contract(kernel)?;
            GpuKernelLaunchDescriptor {
                kernel_name: render_function_name(kernel_name),
                source,
                param_layout: shared_contract.param_layout.clone(),
                shared_contract,
            }
        });
    }
    Ok(descriptors)
}

pub(crate) fn gpu_kernel_descriptor_strings(fir: &fir::FirModule) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let typed = synthesize_typed_module(fir);
    let module = kernel_ir::lower(&typed)
        .map_err(|diagnostics| anyhow!(render_kernel_ir_diagnostics(&diagnostics)))?;
    for backend in [GpuBackendKind::Metal, GpuBackendKind::Rocm, GpuBackendKind::Cuda] {
        for descriptor in gpu_kernel_launch_descriptors_from_kernel_module(&module, backend)?
            .into_values()
        {
            values.push(descriptor.kernel_name);
            values.push(descriptor.source);
            values.push(descriptor.param_layout);
        }
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn synthesize_typed_module(fir: &fir::FirModule) -> hir::TypedModule {
    hir::TypedModule {
        name: fir.name.clone(),
        symbol_count: 0,
        capabilities: Vec::new(),
        inferred_capabilities: Vec::new(),
        entry_return_type: fir.entry_return_type.clone(),
        entry_return_const_i32: fir.entry_return_const_i32,
        entry_has_return_expr: fir.entry_has_return_expr,
        linear_resources: fir.linear_resources.clone(),
        deferred_resources: fir.deferred_resources.clone(),
        matches_without_wildcard: fir.matches_without_wildcard,
        match_unreachable_arms: fir.match_unreachable_arms,
        match_duplicate_catchall_arms: fir.match_duplicate_catchall_arms,
        entry_requires: fir.entry_requires.clone(),
        entry_ensures: fir.entry_ensures.clone(),
        host_syscall_sites: fir.host_syscall_sites,
        unsafe_sites: fir.unsafe_sites,
        unsafe_reasoned_sites: fir.unsafe_reasoned_sites,
        unsafe_contract_sites: fir.unsafe_contract_sites.clone(),
        reference_sites: fir.reference_sites,
        alloc_sites: fir.alloc_sites,
        free_sites: fir.free_sites,
        extern_c_abi_functions: fir.extern_c_abi_functions,
        repr_c_layout_items: fir.repr_c_layout_items,
        generic_instantiations: fir.generic_instantiations.clone(),
        generic_specializations: fir.generic_specializations.clone(),
        call_graph: fir.call_graph.clone(),
        typed_functions: fir.typed_functions.clone(),
        typed_globals: fir.typed_globals.clone(),
        struct_defs: fir.struct_defs.clone(),
        enum_defs: fir.enum_defs.clone(),
        type_errors: fir.type_errors,
        type_error_details: fir.type_error_details.clone(),
        function_capability_requirements: fir.function_capability_requirements.clone(),
        ownership_violations: fir.ownership_violations.clone(),
        unsafe_context_violations: fir.unsafe_context_violations.clone(),
        capability_token_violations: fir.capability_token_violations.clone(),
        thread_boundary_violations: fir.thread_boundary_violations.clone(),
        trait_violations: fir.trait_violations.clone(),
        reference_lifetime_violations: fir.reference_lifetime_violations.clone(),
        linear_type_violations: fir.linear_type_violations.clone(),
    }
}

fn render_kernel_ir_diagnostics(diagnostics: &[diagnostics::Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join("; ")
}

fn render_gpu_module(
    module: &kernel_ir::KernelModule,
    function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
    kernel: &kernel_ir::KernelFunction,
    backend: GpuBackendKind,
) -> Result<String> {
    let mut out = String::new();
    match backend {
        GpuBackendKind::Metal => out.push_str("#include <metal_stdlib>\nusing namespace metal;\n\n"),
        GpuBackendKind::Rocm | GpuBackendKind::Cuda => {
            out.push_str(
                "#include <stdint.h>\n#define uint unsigned int\ntypedef struct { unsigned int x; unsigned int y; unsigned int z; } fz_dim3;\n\n",
            );
        }
        GpuBackendKind::Spirv | GpuBackendKind::Nvptx => {
            bail!(
                "gpu backend `{}` has a declared package contract but no executable kernel source renderer",
                backend.as_str()
            );
        }
    }
    for (name, value) in &module.const_i32_globals {
        if backend == GpuBackendKind::Metal {
            out.push_str("constant int ");
        } else {
            out.push_str("static const int ");
        }
        out.push_str(name);
        out.push_str(" = ");
        out.push_str(&value.to_string());
        out.push_str(";\n");
    }
    if !module.const_i32_globals.is_empty() {
        out.push('\n');
    }
    for function in &module.functions {
        if backend != GpuBackendKind::Metal && function.name == kernel.name {
            continue;
        }
        out.push_str(&render_function_signature(
            function,
            false,
            backend,
            function_map,
        )?);
        out.push_str(";\n");
    }
    out.push('\n');
    for function in &module.functions {
        let is_kernel = function.name == kernel.name;
        out.push_str(&render_function_signature(
            function,
            is_kernel,
            backend,
            function_map,
        )?);
        out.push_str(" {\n");
        if is_kernel && backend != GpuBackendKind::Metal {
            out.push_str("    fz_dim3 fz_gid = {blockIdx.x * blockDim.x + threadIdx.x, blockIdx.y * blockDim.y + threadIdx.y, blockIdx.z * blockDim.z + threadIdx.z};\n");
            out.push_str("    fz_dim3 fz_tid = {threadIdx.x, threadIdx.y, threadIdx.z};\n");
            out.push_str("    fz_dim3 fz_tg_id = {blockIdx.x, blockIdx.y, blockIdx.z};\n");
            out.push_str("    fz_dim3 fz_tg_size = {blockDim.x, blockDim.y, blockDim.z};\n");
            out.push_str("    fz_dim3 fz_grid_size = {gridDim.x * blockDim.x, gridDim.y * blockDim.y, gridDim.z * blockDim.z};\n");
        }
        let mut scope = function
            .params
            .iter()
            .map(|param| (param.name.clone(), param.ty.clone()))
            .collect::<HashMap<_, _>>();
        render_stmts(&function.body, 1, backend, &mut scope, function_map, &mut out)?;
        out.push_str("}\n\n");
    }
    Ok(out)
}

fn render_function_signature(
    function: &kernel_ir::KernelFunction,
    is_kernel: bool,
    backend: GpuBackendKind,
    function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
) -> Result<String> {
    let mut out = String::new();
    match (backend, is_kernel) {
        (GpuBackendKind::Metal, true) => out.push_str("kernel void "),
        (GpuBackendKind::Rocm | GpuBackendKind::Cuda, true) => out.push_str("extern \"C\" __global__ void "),
        (_, false) => {
            if backend != GpuBackendKind::Metal {
                out.push_str("__device__ ");
            }
            out.push_str(render_scalar_type(&function.return_type, backend)?);
            out.push(' ');
        }
        (GpuBackendKind::Spirv | GpuBackendKind::Nvptx, true) => unreachable!("non-executable GPU backend should not render kernel source"),
    }
    out.push_str(&render_function_name(&function.name));
    out.push('(');
    let mut parts = Vec::new();
    let mut buffer_index = 0usize;
    for param in &function.params {
        render_param_parts(
            param,
            function,
            is_kernel,
            backend,
            &mut buffer_index,
            &mut parts,
            function_map,
        )?;
    }
    if !is_kernel || backend == GpuBackendKind::Metal {
        parts.extend(render_context_params(is_kernel, backend));
    }
    out.push_str(&parts.join(", "));
    out.push(')');
    Ok(out)
}

fn render_function_name(name: &str) -> String {
    format!("fz_{}", name)
}

fn render_param_parts(
    param: &ast::Param,
    function: &kernel_ir::KernelFunction,
    is_kernel: bool,
    backend: GpuBackendKind,
    buffer_index: &mut usize,
    out: &mut Vec<String>,
    _function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
) -> Result<()> {
    match &param.ty {
        ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
            let element_ty = render_scalar_type(&args[0], backend)?;
            let qualifier = if function
                .slice_access
                .get(&param.name)
                .copied()
                .unwrap_or(kernel_ir::KernelSliceAccessMode::Observe)
                .is_read_only_like()
            {
                if backend == GpuBackendKind::Metal {
                    "const device"
                } else {
                    "const"
                }
            } else {
                if backend == GpuBackendKind::Metal {
                    "device"
                } else {
                    ""
                }
            };
            if is_kernel {
                if backend == GpuBackendKind::Metal {
                    out.push(format!(
                        "{qualifier} {element_ty}* {}_data [[buffer({})]]",
                        param.name, *buffer_index
                    ));
                    *buffer_index += 1;
                    out.push(format!(
                        "constant uint& {}_len [[buffer({})]]",
                        param.name, *buffer_index
                    ));
                    *buffer_index += 1;
                } else {
                    out.push(format!("{qualifier} {element_ty}* {}_data", param.name));
                    out.push(format!("uint {}_len", param.name));
                }
            } else {
                let prefix = if qualifier.is_empty() {
                    String::new()
                } else {
                    format!("{qualifier} ")
                };
                out.push(format!("{prefix}{element_ty}* {}_data", param.name));
                out.push(format!("uint {}_len", param.name));
            }
        }
        ast::Type::Ptr { to, .. } => {
            let rendered = render_scalar_type(to, backend)?;
            if backend == GpuBackendKind::Metal {
                out.push(format!("thread {rendered}* {}", param.name));
            } else {
                out.push(format!("{rendered}* {}", param.name));
            }
        }
        _ => {
            let rendered = render_scalar_type(&param.ty, backend)?;
            if is_kernel {
                if backend == GpuBackendKind::Metal {
                    out.push(format!(
                        "constant {rendered}& {} [[buffer({})]]",
                        param.name, *buffer_index
                    ));
                    *buffer_index += 1;
                } else {
                    out.push(format!("{rendered} {}", param.name));
                }
            } else {
                out.push(format!("{rendered} {}", param.name));
            }
        }
    }
    Ok(())
}

fn render_context_params(is_kernel: bool, backend: GpuBackendKind) -> Vec<String> {
    if backend == GpuBackendKind::Metal {
        let attrs = [
            ("uint3 fz_gid", "[[thread_position_in_grid]]"),
            ("uint3 fz_tid", "[[thread_position_in_threadgroup]]"),
            ("uint3 fz_tg_id", "[[threadgroup_position_in_grid]]"),
            ("uint3 fz_tg_size", "[[threads_per_threadgroup]]"),
            ("uint3 fz_grid_size", "[[threads_per_grid]]"),
        ];
        return attrs
            .into_iter()
            .map(|(decl, attr)| {
                if is_kernel {
                    format!("{decl} {attr}")
                } else {
                    decl.to_string()
                }
            })
            .collect();
    }
    vec![
        "fz_dim3 fz_gid".to_string(),
        "fz_dim3 fz_tid".to_string(),
        "fz_dim3 fz_tg_id".to_string(),
        "fz_dim3 fz_tg_size".to_string(),
        "fz_dim3 fz_grid_size".to_string(),
    ]
}

fn render_stmts(
    stmts: &[kernel_ir::KernelStmt],
    indent: usize,
    backend: GpuBackendKind,
    scope: &mut HashMap<String, ast::Type>,
    function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
    out: &mut String,
) -> Result<()> {
    let pad = "    ".repeat(indent);
    for stmt in stmts {
        match stmt {
            kernel_ir::KernelStmt::Let { name, ty, value } => {
                out.push_str(&pad);
                if let Some(ty) = ty {
                    scope.insert(name.clone(), ty.clone());
                    if let ast::Type::Array { elem, len } = ty {
                        out.push_str(render_scalar_type(elem, backend)?);
                        out.push(' ');
                        out.push_str(name);
                        out.push('[');
                        out.push_str(&len.to_string());
                        out.push_str("] = ");
                        out.push_str(&render_expr(value, backend, scope, function_map)?);
                        out.push_str(";\n");
                        continue;
                    }
                    out.push_str(render_scalar_type(ty, backend)?);
                } else {
                    out.push_str("auto");
                }
                out.push(' ');
                out.push_str(name);
                out.push_str(" = ");
                out.push_str(&render_expr(value, backend, scope, function_map)?);
                out.push_str(";\n");
            }
            kernel_ir::KernelStmt::Assign { target, value } => {
                out.push_str(&pad);
                out.push_str(target);
                out.push_str(" = ");
                out.push_str(&render_expr(value, backend, scope, function_map)?);
                out.push_str(";\n");
            }
            kernel_ir::KernelStmt::Store { base, index, value } => {
                out.push_str(&pad);
                out.push_str(&render_slice_access(base, index, backend, scope, function_map)?);
                out.push_str(" = ");
                out.push_str(&render_expr(value, backend, scope, function_map)?);
                out.push_str(";\n");
            }
            kernel_ir::KernelStmt::If {
                condition,
                then_body,
                else_body,
            } => {
                out.push_str(&pad);
                out.push_str("if (");
                out.push_str(&render_expr(condition, backend, scope, function_map)?);
                out.push_str(") {\n");
                render_stmts(then_body, indent + 1, backend, &mut scope.clone(), function_map, out)?;
                out.push_str(&pad);
                out.push('}');
                if !else_body.is_empty() {
                    out.push_str(" else {\n");
                    render_stmts(else_body, indent + 1, backend, &mut scope.clone(), function_map, out)?;
                    out.push_str(&pad);
                    out.push('}');
                }
                out.push('\n');
            }
            kernel_ir::KernelStmt::While { condition, body } => {
                out.push_str(&pad);
                out.push_str("while (");
                out.push_str(&render_expr(condition, backend, scope, function_map)?);
                out.push_str(") {\n");
                render_stmts(body, indent + 1, backend, &mut scope.clone(), function_map, out)?;
                out.push_str(&pad);
                out.push_str("}\n");
            }
            kernel_ir::KernelStmt::Loop { body } => {
                out.push_str(&pad);
                out.push_str("while (true) {\n");
                render_stmts(body, indent + 1, backend, &mut scope.clone(), function_map, out)?;
                out.push_str(&pad);
                out.push_str("}\n");
            }
            kernel_ir::KernelStmt::Break(value) => {
                if value.is_some() {
                bail!("GPU kernel lowering does not yet support valued `break`");
                }
                out.push_str(&pad);
                out.push_str("break;\n");
            }
            kernel_ir::KernelStmt::Continue => {
                out.push_str(&pad);
                out.push_str("continue;\n");
            }
            kernel_ir::KernelStmt::Return(value) => {
                out.push_str(&pad);
                match value {
                    Some(value) => {
                        out.push_str("return ");
                        out.push_str(&render_expr(value, backend, scope, function_map)?);
                        out.push_str(";\n");
                    }
                    None => out.push_str("return;\n"),
                }
            }
            kernel_ir::KernelStmt::Expr(expr) => {
                out.push_str(&pad);
                out.push_str(&render_expr(expr, backend, scope, function_map)?);
                out.push_str(";\n");
            }
        }
    }
    Ok(())
}

fn render_expr(
    expr: &kernel_ir::KernelExpr,
    backend: GpuBackendKind,
    scope: &HashMap<String, ast::Type>,
    function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
) -> Result<String> {
    Ok(match expr {
        kernel_ir::KernelExpr::Int(value) => value.to_string(),
        kernel_ir::KernelExpr::Float { value, .. } => {
            if value.fract() == 0.0 {
                format!("{value:.1}")
            } else {
                value.to_string()
            }
        }
        kernel_ir::KernelExpr::Bool(value) => value.to_string(),
        kernel_ir::KernelExpr::Char(value) => format!("'{}'", value),
        kernel_ir::KernelExpr::Ident(name) => name.clone(),
        kernel_ir::KernelExpr::ArrayLiteral(items) => format!(
            "{{{}}}",
            items
                .iter()
                .map(|item| render_expr(item, backend, scope, function_map))
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        kernel_ir::KernelExpr::Unary { op, expr } => {
            format!(
                "({}{})",
                render_unary_op(*op),
                render_expr(expr, backend, scope, function_map)?
            )
        }
        kernel_ir::KernelExpr::Binary { op, left, right } => format!(
            "({} {} {})",
            render_expr(left, backend, scope, function_map)?,
            render_binary_op(*op),
            render_expr(right, backend, scope, function_map)?
        ),
        kernel_ir::KernelExpr::Call { callee, args } => {
            let target = function_map
                .get(callee)
                .ok_or_else(|| anyhow!("GPU kernel lowering could not resolve `{callee}`"))?;
            let mut rendered = Vec::new();
            for (arg, param) in args.iter().zip(target.params.iter()) {
                rendered.extend(render_call_arg(arg, &param.ty, backend, scope, function_map)?);
            }
            rendered.extend([
                "fz_gid".to_string(),
                "fz_tid".to_string(),
                "fz_tg_id".to_string(),
                "fz_tg_size".to_string(),
                "fz_grid_size".to_string(),
            ]);
            format!("{}({})", render_function_name(callee), rendered.join(", "))
        }
        kernel_ir::KernelExpr::Intrinsic { op, args } => {
            render_intrinsic(*op, args, backend, scope, function_map)?
        }
        kernel_ir::KernelExpr::Load { base, index } => {
            render_slice_access(base, index, backend, scope, function_map)?
        }
        kernel_ir::KernelExpr::Group(inner) => {
            format!("({})", render_expr(inner, backend, scope, function_map)?)
        }
    })
}

fn render_call_arg(
    expr: &kernel_ir::KernelExpr,
    param_ty: &ast::Type,
    backend: GpuBackendKind,
    scope: &HashMap<String, ast::Type>,
    function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
) -> Result<Vec<String>> {
    if is_gpu_slice_type(param_ty) {
        let name = slice_ident(expr)?;
        Ok(vec![format!("{name}_data"), format!("{name}_len")])
    } else if matches!(param_ty, ast::Type::Ptr { .. }) {
        Ok(vec![render_expr(expr, backend, scope, function_map)?])
    } else {
        Ok(vec![render_expr(expr, backend, scope, function_map)?])
    }
}

fn render_intrinsic(
    op: kernel_ir::KernelIntrinsic,
    args: &[kernel_ir::KernelExpr],
    backend: GpuBackendKind,
    scope: &HashMap<String, ast::Type>,
    function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
) -> Result<String> {
    Ok(match op {
        kernel_ir::KernelIntrinsic::GlobalIdX => "((int)fz_gid.x)".to_string(),
        kernel_ir::KernelIntrinsic::GlobalIdY => "((int)fz_gid.y)".to_string(),
        kernel_ir::KernelIntrinsic::GlobalIdZ => "((int)fz_gid.z)".to_string(),
        kernel_ir::KernelIntrinsic::ThreadIdX => "((int)fz_tid.x)".to_string(),
        kernel_ir::KernelIntrinsic::ThreadIdY => "((int)fz_tid.y)".to_string(),
        kernel_ir::KernelIntrinsic::ThreadIdZ => "((int)fz_tid.z)".to_string(),
        kernel_ir::KernelIntrinsic::BlockIdX => "((int)fz_tg_id.x)".to_string(),
        kernel_ir::KernelIntrinsic::BlockIdY => "((int)fz_tg_id.y)".to_string(),
        kernel_ir::KernelIntrinsic::BlockIdZ => "((int)fz_tg_id.z)".to_string(),
        kernel_ir::KernelIntrinsic::BlockDimX => "((int)fz_tg_size.x)".to_string(),
        kernel_ir::KernelIntrinsic::BlockDimY => "((int)fz_tg_size.y)".to_string(),
        kernel_ir::KernelIntrinsic::BlockDimZ => "((int)fz_tg_size.z)".to_string(),
        kernel_ir::KernelIntrinsic::GridDimX => {
            "((int)((fz_grid_size.x + fz_tg_size.x - 1u) / fz_tg_size.x))".to_string()
        }
        kernel_ir::KernelIntrinsic::GridDimY => {
            "((int)((fz_grid_size.y + fz_tg_size.y - 1u) / fz_tg_size.y))".to_string()
        }
        kernel_ir::KernelIntrinsic::GridDimZ => {
            "((int)((fz_grid_size.z + fz_tg_size.z - 1u) / fz_tg_size.z))".to_string()
        }
        kernel_ir::KernelIntrinsic::Barrier => {
            "threadgroup_barrier(mem_flags::mem_device)".to_string()
        }
        kernel_ir::KernelIntrinsic::SliceLen => format!("((int){}_len)", slice_ident(&args[0])?),
        kernel_ir::KernelIntrinsic::LoadF32
        | kernel_ir::KernelIntrinsic::LoadI32
        | kernel_ir::KernelIntrinsic::LoadU32 => {
            render_slice_access(&args[0], &args[1], backend, scope, function_map)?
        }
        kernel_ir::KernelIntrinsic::StoreF32
        | kernel_ir::KernelIntrinsic::StoreI32
        | kernel_ir::KernelIntrinsic::StoreU32 => format!(
            "({} = {})",
            render_slice_access(&args[0], &args[1], backend, scope, function_map)?,
            render_expr(&args[2], backend, scope, function_map)?
        ),
        kernel_ir::KernelIntrinsic::SimdF32x4Splat => {
            format!("float4({})", render_expr(&args[0], backend, scope, function_map)?)
        }
        kernel_ir::KernelIntrinsic::SimdF32x4Load => {
            let kernel_ir::KernelExpr::ArrayLiteral(items) = &args[0] else {
                bail!("Metal GPU kernel lowering expected `simd.f32x4_load` to receive a 4-lane array literal");
            };
            if items.len() != 4 {
                bail!("Metal GPU kernel lowering expected `simd.f32x4_load` to receive exactly 4 lanes");
            }
            format!(
                "float4({})",
                items
                    .iter()
                    .map(|item| render_expr(item, backend, scope, function_map))
                    .collect::<Result<Vec<_>>>()?
                    .join(", ")
            )
        }
        kernel_ir::KernelIntrinsic::SimdF32x4Store => {
            let value = render_expr(&args[0], backend, scope, function_map)?;
            format!("{{{value}[0], {value}[1], {value}[2], {value}[3]}}")
        }
        kernel_ir::KernelIntrinsic::SimdF32x4Add => format!(
            "({} + {})",
            render_expr(&args[0], backend, scope, function_map)?,
            render_expr(&args[1], backend, scope, function_map)?
        ),
        kernel_ir::KernelIntrinsic::SimdF32x4Mul => format!(
            "({} * {})",
            render_expr(&args[0], backend, scope, function_map)?,
            render_expr(&args[1], backend, scope, function_map)?
        ),
        kernel_ir::KernelIntrinsic::SimdF32x4ReduceAdd => {
            let value = render_expr(&args[0], backend, scope, function_map)?;
            format!("(({value}[0] + {value}[1]) + ({value}[2] + {value}[3]))")
        }
        kernel_ir::KernelIntrinsic::SimdF32x4Lane0 => {
            format!("({}[0])", render_expr(&args[0], backend, scope, function_map)?)
        }
        kernel_ir::KernelIntrinsic::SimdF32x4Lane1 => {
            format!("({}[1])", render_expr(&args[0], backend, scope, function_map)?)
        }
        kernel_ir::KernelIntrinsic::SimdF32x4Lane2 => {
            format!("({}[2])", render_expr(&args[0], backend, scope, function_map)?)
        }
        kernel_ir::KernelIntrinsic::SimdF32x4Lane3 => {
            format!("({}[3])", render_expr(&args[0], backend, scope, function_map)?)
        }
    })
}

fn render_slice_access(
    base: &kernel_ir::KernelExpr,
    index: &kernel_ir::KernelExpr,
    backend: GpuBackendKind,
    scope: &HashMap<String, ast::Type>,
    function_map: &BTreeMap<String, &kernel_ir::KernelFunction>,
) -> Result<String> {
    let name = ident_name(base)?;
    let rendered_index = render_expr(index, backend, scope, function_map)?;
    let Some(base_ty) = scope.get(&name) else {
        bail!("Metal GPU kernel lowering could not resolve indexed base `{name}`");
    };
    if is_gpu_slice_type(base_ty) {
        return Ok(format!("{name}_data[(uint)({rendered_index})]"));
    }
    if matches!(base_ty, ast::Type::Array { .. } | ast::Type::Ptr { .. }) {
        return Ok(format!("{name}[((int)({rendered_index}))]"));
    }
    bail!("Metal GPU kernel lowering does not support indexed access on type `{base_ty}`")
}

fn ident_name(expr: &kernel_ir::KernelExpr) -> Result<String> {
    match expr {
        kernel_ir::KernelExpr::Ident(name) => Ok(name.clone()),
        _ => bail!("Metal GPU kernel lowering currently requires direct identifiers for by-reference values"),
    }
}

fn slice_ident(expr: &kernel_ir::KernelExpr) -> Result<String> {
    ident_name(expr)
}

fn is_gpu_slice_type(ty: &ast::Type) -> bool {
    matches!(ty, ast::Type::Named { name, args } if name == "GpuSlice" && args.len() == 1)
}

fn render_scalar_type(ty: &ast::Type, backend: GpuBackendKind) -> Result<&'static str> {
    match ty {
        ast::Type::Void => Ok("void"),
        ast::Type::Bool => Ok("bool"),
        ast::Type::Float { bits: 32 } => Ok("float"),
        ast::Type::SimdVector(ast::SimdVectorType {
            element: ast::SimdElement::F32,
            lanes: 4,
        }) if backend == GpuBackendKind::Metal => Ok("float4"),
        ast::Type::SimdVector(ast::SimdVectorType {
            element: ast::SimdElement::F32,
            lanes: 4,
        }) => Ok("float4"),
        ast::Type::Int {
            signed: true,
            bits: 32,
        } => Ok("int"),
        ast::Type::Int {
            signed: false,
            bits: 32,
        } => Ok("uint"),
        other => bail!("GPU kernel lowering does not yet support type `{other}`"),
    }
}

fn render_unary_op(op: ast::UnaryOp) -> &'static str {
    match op {
        ast::UnaryOp::Not => "!",
        ast::UnaryOp::Plus => "+",
        ast::UnaryOp::Neg => "-",
        ast::UnaryOp::BitNot => "~",
    }
}

fn render_binary_op(op: ast::BinaryOp) -> &'static str {
    match op {
        ast::BinaryOp::Add => "+",
        ast::BinaryOp::Sub => "-",
        ast::BinaryOp::Mul => "*",
        ast::BinaryOp::Div => "/",
        ast::BinaryOp::Mod => "%",
        ast::BinaryOp::BitAnd => "&",
        ast::BinaryOp::BitOr => "|",
        ast::BinaryOp::BitXor => "^",
        ast::BinaryOp::Shl => "<<",
        ast::BinaryOp::Shr => ">>",
        ast::BinaryOp::And => "&&",
        ast::BinaryOp::Or => "||",
        ast::BinaryOp::Lt => "<",
        ast::BinaryOp::Lte => "<=",
        ast::BinaryOp::Gt => ">",
        ast::BinaryOp::Gte => ">=",
        ast::BinaryOp::Eq => "==",
        ast::BinaryOp::Neq => "!=",
    }
}
