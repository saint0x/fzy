use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use diagnostics::{Diagnostic, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GpuBackendKind {
    Metal,
    Spirv,
    Nvptx,
}

impl GpuBackendKind {
    pub(crate) const ALL: [Self; 3] = [Self::Metal, Self::Spirv, Self::Nvptx];

    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "metal" => Some(Self::Metal),
            "spirv" => Some(Self::Spirv),
            "nvptx" => Some(Self::Nvptx),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Metal => "metal",
            Self::Spirv => "spirv",
            Self::Nvptx => "nvptx",
        }
    }

    pub(crate) fn adapter(self) -> GpuBackendAdapter {
        match self {
            Self::Metal => GpuBackendAdapter {
                kind: self,
                architecture_status: "declared",
                execution_status: "host_lifecycle_and_kernel_launch_live",
                host_support: if cfg!(target_vendor = "apple") {
                    "host_supported"
                } else {
                    "host_unsupported"
                },
                executable_now: cfg!(target_vendor = "apple"),
                reason: if cfg!(target_vendor = "apple") {
                    "Metal host GPU lifecycle and first live kernel launch/wait execution are available on Apple in this checkout through the shared GPU backend contract."
                } else {
                    "Metal requires an Apple host/runtime and the current target is not Apple."
                },
            },
            Self::Spirv => GpuBackendAdapter {
                kind: self,
                architecture_status: "declared",
                execution_status: "shared_contract_bound_not_executable",
                host_support: "toolchain_not_integrated",
                executable_now: false,
                reason: "SPIR-V/Vulkan adapter architecture is declared and now consumes the shared kernel package/launch layout contract, but codegen/runtime/toolchain integration is not landed yet.",
            },
            Self::Nvptx => GpuBackendAdapter {
                kind: self,
                architecture_status: "declared",
                execution_status: "shared_contract_bound_not_executable",
                host_support: "toolchain_not_integrated",
                executable_now: false,
                reason: "NVPTX/CUDA adapter architecture is declared and now consumes the shared kernel package/launch layout contract, but codegen/runtime/toolchain integration is not landed yet.",
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GpuBackendAdapter {
    pub(crate) kind: GpuBackendKind,
    pub(crate) architecture_status: &'static str,
    pub(crate) execution_status: &'static str,
    pub(crate) host_support: &'static str,
    pub(crate) executable_now: bool,
    pub(crate) reason: &'static str,
}

pub(crate) fn gpu_backend_report_json() -> serde_json::Value {
    let adapters = GpuBackendKind::ALL
        .into_iter()
        .map(|kind| {
            let adapter = kind.adapter();
            (
                kind.as_str().to_string(),
                serde_json::json!({
                    "architectureStatus": adapter.architecture_status,
                    "executionStatus": adapter.execution_status,
                    "hostSupport": adapter.host_support,
                    "executableNow": adapter.executable_now,
                    "reason": adapter.reason,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::Value::Object(adapters)
}

pub(crate) fn resolve_gpu_backend(
    module_uses_gpu: bool,
    backend_override: Option<&str>,
) -> Result<Option<GpuBackendAdapter>> {
    let explicit = backend_override
        .map(|value| value.to_string())
        .or_else(|| std::env::var("FZ_GPU_BACKEND").ok());
    let Some(explicit) = explicit else {
        return Ok(module_uses_gpu.then_some(GpuBackendKind::Metal.adapter()));
    };
    let kind = GpuBackendKind::parse(&explicit).ok_or_else(|| {
        anyhow!(
            "unknown GPU backend `{}`; expected `metal`, `spirv`, or `nvptx`",
            explicit.trim()
        )
    })?;
    Ok(Some(kind.adapter()))
}

pub(crate) fn gpu_backend_execution_diagnostics(
    typed: &hir::TypedModule,
    selected: Option<GpuBackendAdapter>,
) -> Vec<Diagnostic> {
    if !module_uses_gpu(typed) {
        return Vec::new();
    }
    let Some(adapter) = selected else {
        return Vec::new();
    };
    if !adapter.executable_now {
        let mut diagnostic = Diagnostic::new(
            Severity::Error,
            format!(
                "gpu backend `{}` is declared in the architecture but not yet executable",
                adapter.kind.as_str()
            ),
            Some(adapter.reason.to_string()),
        )
        .with_catalog_key("gpu.backend_declared_not_executable");
        if adapter.kind == GpuBackendKind::Metal && adapter.host_support == "host_unsupported" {
            diagnostic = diagnostic.with_fix(
                "build on an Apple host for `metal`, or choose `spirv` / `nvptx` once those live adapters land",
            );
        } else {
            diagnostic = diagnostic.with_fix(
                "keep the shared GPU surface, but do not ship native GPU execution until the selected adapter's codegen/runtime path is live",
            );
        }
        return vec![diagnostic];
    }

    let unsupported = unsupported_gpu_operations(typed, adapter.kind);
    if unsupported.is_empty() {
        return Vec::new();
    }
    let unsupported_list = unsupported.into_iter().collect::<Vec<_>>().join(", ");
    vec![
        Diagnostic::new(
            Severity::Error,
            format!(
                "gpu backend `{}` does not yet execute these GPU operations: {}",
                adapter.kind.as_str(),
                unsupported_list
            ),
            Some(match adapter.kind {
                GpuBackendKind::Metal => "This chunk makes the Metal host/runtime path live for device enumeration, device info, GPU buffer allocation/free, host uploads/downloads, downloaded Vec indexing, and host-side slice/view construction. Kernel launch, waits, and device-side execution remain blocked until the next backend/runtime slice.".to_string(),
                GpuBackendKind::Spirv | GpuBackendKind::Nvptx => adapter.reason.to_string(),
            }),
        )
        .with_catalog_key("gpu.backend_operation_unsupported")
        .with_fix(
            "limit native GPU use to the currently live host lifecycle surface, or wait for the next backend chunk before shipping launch/device execution",
        ),
    ]
}

pub(crate) fn module_uses_gpu(typed: &hir::TypedModule) -> bool {
    typed.capabilities.iter().any(|cap| cap == "gpu")
        || typed.inferred_capabilities.iter().any(|cap| cap == "gpu")
        || typed.typed_functions.iter().any(|function| {
            function
                .required_capabilities
                .iter()
                .any(|cap| cap == "gpu")
        })
}

pub(crate) fn fir_module_uses_gpu(fir: &fir::FirModule) -> bool {
    fir.typed_functions.iter().any(|function| {
        function
            .required_capabilities
            .iter()
            .any(|cap| cap == "gpu")
    })
}

fn unsupported_gpu_operations(
    typed: &hir::TypedModule,
    backend: GpuBackendKind,
) -> BTreeSet<String> {
    let mut unsupported = BTreeSet::new();
    let supported_calls = supported_gpu_calls(backend);
    for function in &typed.typed_functions {
        match function.execution_space {
            ast::ExecutionSpace::Kernel => {
                if backend != GpuBackendKind::Metal {
                    unsupported.insert("kernel_fn".to_string());
                }
            }
            ast::ExecutionSpace::Device => {
                if backend != GpuBackendKind::Metal {
                    unsupported.insert("device_fn".to_string());
                }
            }
            _ => {}
        }
        for stmt in &function.body {
            collect_unsupported_gpu_calls_from_stmt(stmt, &supported_calls, &mut unsupported);
        }
    }
    unsupported
}

fn supported_gpu_calls(backend: GpuBackendKind) -> BTreeSet<&'static str> {
    match backend {
        GpuBackendKind::Metal => BTreeSet::from([
            "gpu.device_count",
            "gpu.default_device",
            "gpu.device_name",
            "gpu.device_memory_bytes",
            "gpu.alloc_f32",
            "gpu.alloc_i32",
            "gpu.alloc_u32",
            "gpu.upload_f32",
            "gpu.upload_i32",
            "gpu.upload_u32",
            "gpu.download_f32",
            "gpu.download_i32",
            "gpu.download_u32",
            "gpu.free",
            "gpu.slice",
            "gpu.launch0",
            "gpu.launch1",
            "gpu.launch2",
            "gpu.launch3",
            "gpu.launch4",
            "gpu.wait",
            "gpu.wait_async",
            "gpu.global_id_x",
            "gpu.global_id_y",
            "gpu.global_id_z",
            "gpu.thread_id_x",
            "gpu.thread_id_y",
            "gpu.thread_id_z",
            "gpu.block_id_x",
            "gpu.block_id_y",
            "gpu.block_id_z",
            "gpu.block_dim_x",
            "gpu.block_dim_y",
            "gpu.block_dim_z",
            "gpu.grid_dim_x",
            "gpu.grid_dim_y",
            "gpu.grid_dim_z",
            "gpu.barrier",
            "gpu.slice_len",
            "gpu.load_f32",
            "gpu.load_i32",
            "gpu.load_u32",
            "gpu.store_f32",
            "gpu.store_i32",
            "gpu.store_u32",
        ]),
        GpuBackendKind::Spirv | GpuBackendKind::Nvptx => BTreeSet::new(),
    }
}

fn collect_unsupported_gpu_calls_from_stmt(
    stmt: &ast::Stmt,
    supported_calls: &BTreeSet<&'static str>,
    unsupported: &mut BTreeSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => {
            collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported)
        }
        ast::Stmt::Return(value) | ast::Stmt::Break(value) => {
            if let Some(value) = value {
                collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_unsupported_gpu_calls_from_expr(condition, supported_calls, unsupported);
            for stmt in then_body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
            for stmt in else_body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_unsupported_gpu_calls_from_expr(condition, supported_calls, unsupported);
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_unsupported_gpu_calls_from_stmt(init, supported_calls, unsupported);
            }
            if let Some(condition) = condition {
                collect_unsupported_gpu_calls_from_expr(condition, supported_calls, unsupported);
            }
            if let Some(step) = step {
                collect_unsupported_gpu_calls_from_stmt(step, supported_calls, unsupported);
            }
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_unsupported_gpu_calls_from_expr(iterable, supported_calls, unsupported);
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Stmt::Loop { body } => {
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_unsupported_gpu_calls_from_expr(scrutinee, supported_calls, unsupported);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unsupported_gpu_calls_from_expr(guard, supported_calls, unsupported);
                }
                collect_unsupported_gpu_calls_from_expr(&arm.value, supported_calls, unsupported);
            }
        }
        ast::Stmt::Continue => {}
    }
}

fn collect_unsupported_gpu_calls_from_expr(
    expr: &ast::Expr,
    supported_calls: &BTreeSet<&'static str>,
    unsupported: &mut BTreeSet<String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if callee.starts_with("gpu.") && !supported_calls.contains(callee.as_str()) {
                unsupported.insert(callee.clone());
            }
            for arg in args {
                collect_unsupported_gpu_calls_from_expr(arg, supported_calls, unsupported);
            }
        }
        ast::Expr::FieldAccess { base, .. }
        | ast::Expr::Group(base)
        | ast::Expr::Await(base)
        | ast::Expr::Discard(base)
        | ast::Expr::Unary { expr: base, .. } => {
            collect_unsupported_gpu_calls_from_expr(base, supported_calls, unsupported);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported);
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for value in payload {
                collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported);
            }
            for (_, value) in named_payload {
                collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported);
            }
        }
        ast::Expr::ObjectLiteral(fields) => {
            for (_, value) in fields {
                collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported);
            }
        }
        ast::Expr::ArrayLiteral(values) | ast::Expr::Tuple(values) => {
            for value in values {
                collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_unsupported_gpu_calls_from_expr(body, supported_calls, unsupported);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_unsupported_gpu_calls_from_expr(try_expr, supported_calls, unsupported);
            collect_unsupported_gpu_calls_from_expr(catch_expr, supported_calls, unsupported);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_unsupported_gpu_calls_from_expr(condition, supported_calls, unsupported);
            collect_unsupported_gpu_calls_from_expr(then_expr, supported_calls, unsupported);
            collect_unsupported_gpu_calls_from_expr(else_expr, supported_calls, unsupported);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_unsupported_gpu_calls_from_expr(left, supported_calls, unsupported);
            collect_unsupported_gpu_calls_from_expr(right, supported_calls, unsupported);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_unsupported_gpu_calls_from_expr(start, supported_calls, unsupported);
            collect_unsupported_gpu_calls_from_expr(end, supported_calls, unsupported);
        }
        ast::Expr::Index { base, index } => {
            collect_unsupported_gpu_calls_from_expr(base, supported_calls, unsupported);
            collect_unsupported_gpu_calls_from_expr(index, supported_calls, unsupported);
        }
        ast::Expr::Match { scrutinee, arms } => {
            collect_unsupported_gpu_calls_from_expr(scrutinee, supported_calls, unsupported);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unsupported_gpu_calls_from_expr(guard, supported_calls, unsupported);
                }
                collect_unsupported_gpu_calls_from_expr(&arm.value, supported_calls, unsupported);
            }
        }
        ast::Expr::While { condition, body } => {
            collect_unsupported_gpu_calls_from_expr(condition, supported_calls, unsupported);
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_unsupported_gpu_calls_from_stmt(init, supported_calls, unsupported);
            }
            if let Some(condition) = condition {
                collect_unsupported_gpu_calls_from_expr(condition, supported_calls, unsupported);
            }
            if let Some(step) = step {
                collect_unsupported_gpu_calls_from_stmt(step, supported_calls, unsupported);
            }
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Expr::ForIn { iterable, body, .. } => {
            collect_unsupported_gpu_calls_from_expr(iterable, supported_calls, unsupported);
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Expr::Loop { body } => {
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Expr::Break(value) | ast::Expr::Return(value) => {
            if let Some(value) = value {
                collect_unsupported_gpu_calls_from_expr(value, supported_calls, unsupported);
            }
        }
        ast::Expr::Continue => {}
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_unsupported_gpu_calls_from_stmt(stmt, supported_calls, unsupported);
            }
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
    }
}
