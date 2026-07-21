use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use cranelift_codegen::ir::{types, AbiParam, MemFlags, Type as ClifType};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Switch, Variable};
use cranelift_module::{default_libcall_names, DataDescription, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Once, OnceLock, RwLock};
use std::time::{Instant, UNIX_EPOCH};

use ast::AstVisitor;

#[path = "pipeline/clif.rs"]
mod clif;
#[path = "pipeline/gpu_backend.rs"]
mod gpu_backend;
#[path = "pipeline/gpu_kernel_layout.rs"]
mod gpu_kernel_layout;
#[path = "pipeline/gpu_kernel_source.rs"]
mod gpu_kernel_source;
#[path = "pipeline/gpu_kernel_nvptx.rs"]
mod gpu_kernel_nvptx;
#[path = "pipeline/gpu_kernel_spirv.rs"]
mod gpu_kernel_spirv;
#[path = "pipeline/graph.rs"]
mod graph;
#[path = "pipeline/linker_support.rs"]
mod linker_support;
#[path = "pipeline/llvm.rs"]
mod llvm;
#[path = "pipeline/native_backend_support.rs"]
mod native_backend_support;
#[path = "pipeline/native_metadata.rs"]
mod native_metadata;
#[path = "pipeline/native_runtime_support.rs"]
mod native_runtime_support;
#[path = "pipeline/native_runtime_tables.rs"]
mod native_runtime_tables;
#[path = "pipeline/policy_artifacts.rs"]
mod policy_artifacts;

use self::audit::*;
use self::compile::*;
pub use self::compile::{
    check_file, compile_file, compile_file_incremental_with_backend, compile_file_with_backend,
    compile_library_incremental_with_backend, compile_library_with_backend, emit_ir,
    lower_fir_cached, parse_program, parse_program_with_root_source, verify_file,
    verify_file_with_root_source,
};
pub(crate) use self::compile::{lower_fir_cached_with_metadata, parse_program_with_metadata};
use self::flow::*;
pub(crate) use self::gpu_backend::gpu_backend_report_json;
use self::gpu_backend::{
    fir_module_uses_gpu, gpu_backend_execution_diagnostics, module_uses_gpu, resolve_gpu_backend,
};
use self::gpu_kernel_source::{gpu_kernel_descriptor_strings, gpu_kernel_launch_descriptors};
pub(crate) use self::graph::embedded_core_stdlib_module_source;
use self::graph::*;
use self::linker_support::{
    apply_extra_linker_args, apply_manifest_link_args, apply_pgo_flags,
    apply_profile_optimization_flags, apply_target_link_flags, archiver_candidates,
    linker_candidates, profile_config, unsafe_contracts_enforced, unsafe_scope_policy,
};
use self::native_backend_support::{
    backend_capability_diagnostics, declare_native_data_plane_imports,
    declare_native_runtime_imports, experimental_feature_diagnostics,
    native_lowerability_diagnostics,
};
use self::native_emit::*;
use self::native_lowering::*;
use self::native_metadata::{
    build_global_const_i32_map, build_mutable_static_i32_map, build_string_literal_ids,
    build_variant_tag_map, collect_native_string_literals,
    collect_pattern_source_function_map_from_module,
    collect_pattern_source_function_map_from_typed, collect_spawn_task_symbols,
    collect_variant_keys_from_stmt, llvm_static_symbol_name, PatternSourceFunction,
};
use self::native_runtime_support::{
    build_native_runtime_shim_plan, collect_async_c_exports, collect_extern_c_imports,
    collect_used_native_data_plane_imports, collect_used_native_runtime_imports,
    compile_runtime_shim_object, ensure_native_runtime_shim, is_extern_c_abi_function,
    is_extern_c_import_decl, native_link_symbol_for_function,
    native_runtime_import_contract_errors, native_runtime_shim_uses_objc,
};
use self::native_runtime_tables::{
    native_data_plane_import_for_callee, native_runtime_contracts,
    native_runtime_import_for_callee, NativeRuntimeImport, NATIVE_DATA_PLANE_IMPORTS,
};
use self::reports::*;
pub(crate) use self::snapshot::prepare_build_snapshot;
use self::snapshot::*;
use self::source_graph::*;
pub(crate) use self::source_graph::{
    normalize_rel_path, resolve_local_dependency, stable_relative_path, DependencyResolutionKind,
};
pub use self::source_graph::{refresh_lockfile, verify_lockfile};
use self::task::*;

#[derive(Clone, Copy)]
struct LocalBinding {
    var: Variable,
    ty: ClifType,
}

#[derive(Clone, Copy)]
struct ClifValue {
    value: cranelift_codegen::ir::Value,
    ty: ClifType,
}

#[derive(Clone)]
struct ClifFunctionSignature {
    params: Vec<ClifType>,
    ret: Option<ClifType>,
    sret: Option<ClifArrayAbi>,
    param_names: Vec<String>,
    is_extern_c_import: bool,
}

#[derive(Clone, Copy)]
struct ClifArrayAbi {
    len: usize,
    element_ty: ClifType,
    element_align: u8,
    element_stride: u8,
}

#[derive(Clone)]
struct ClifClosureBinding {
    params: Vec<ast::Param>,
    return_type: Option<ast::Type>,
    body: ast::Expr,
    captures: HashMap<String, LocalBinding>,
}

#[derive(Clone)]
struct ClifArrayBinding {
    stack_slot: cranelift_codegen::ir::StackSlot,
    len: usize,
    element_ty: ClifType,
    element_bits: u16,
    element_align: u8,
    element_stride: u8,
}

fn declare_clif_functions<F>(
    module: &mut ObjectModule,
    fir: &fir::FirModule,
    mut linkage_for: F,
    error_label: &str,
) -> Result<(
    HashMap<String, cranelift_module::FuncId>,
    HashMap<String, ClifFunctionSignature>,
)>
where
    F: FnMut(&hir::TypedFunction) -> Linkage,
{
    let mut function_ids = HashMap::new();
    let mut function_signatures = HashMap::new();
    for function in &fir.typed_functions {
        if matches!(
            function.execution_space,
            ast::ExecutionSpace::Kernel | ast::ExecutionSpace::Device
        ) {
            continue;
        }
        let mut sig = module.make_signature();
        let mut param_tys = Vec::new();
        let sret = self::clif::clif_array_abi_from_type(&function.return_type);
        if sret.is_some() {
            sig.params
                .push(AbiParam::new(self::clif::pointer_sized_clif_type()));
            param_tys.push(self::clif::pointer_sized_clif_type());
        }
        for param in &function.params {
            let ty = self::clif::ast_signature_type_to_clif_type(&param.ty)
                .ok_or_else(|| anyhow!("unsupported native parameter type `{}`", param.ty))?;
            sig.params.push(AbiParam::new(ty));
            param_tys.push(ty);
        }
        let ret_ty = if sret.is_some() {
            None
        } else {
            self::clif::ast_signature_type_to_clif_type(&function.return_type)
        };
        if let Some(ret_ty) = ret_ty {
            sig.returns.push(AbiParam::new(ret_ty));
        }
        let symbol_name = native_link_symbol_for_function(function);
        let id = module
            .declare_function(symbol_name.as_str(), linkage_for(function), &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring {error_label} `{}`: {error}",
                    function.name
                )
            })?;
        function_ids.insert(function.name.clone(), id);
        function_signatures.insert(
            function.name.clone(),
            ClifFunctionSignature {
                params: param_tys,
                ret: ret_ty,
                sret,
                param_names: function
                    .params
                    .iter()
                    .map(|param| param.name.clone())
                    .collect(),
                is_extern_c_import: is_extern_c_import_decl(function),
            },
        );
    }
    Ok((function_ids, function_signatures))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    Dev,
    Release,
    Verify,
    Strict,
}

impl BuildProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
            Self::Verify => "verify",
            Self::Strict => "strict",
        }
    }
}

const NATIVE_AGG_NEW: &str = "__fz_native_agg_new";
const NATIVE_AGG_SET_I64: &str = "__fz_native_agg_set_i64";
const NATIVE_AGG_GET_I64: &str = "__fz_native_agg_get_i64";
const NATIVE_AGG_TAG: &str = "__fz_native_agg_tag";

#[path = "pipeline/audit.rs"]
mod audit;
#[path = "pipeline/compile.rs"]
mod compile;
#[path = "pipeline/flow.rs"]
mod flow;
#[path = "pipeline/native_emit.rs"]
mod native_emit;
#[path = "pipeline/native_lowering.rs"]
mod native_lowering;
#[path = "pipeline/reports.rs"]
mod reports;
#[path = "pipeline/snapshot.rs"]
mod snapshot;
#[path = "pipeline/source_graph.rs"]
mod source_graph;
#[path = "pipeline/task.rs"]
mod task;

#[cfg(test)]
#[path = "pipeline/tests.rs"]
mod tests;
const NATIVE_STR_PTR: &str = "__fz_native_str_ptr";
const NATIVE_VEC_LEN: &str = "__fz_native_vec_len";
const NATIVE_VEC_GET_I32: &str = "__fz_native_vec_get_i32";
const NATIVE_VEC_GET_U32: &str = "__fz_native_vec_get_u32";
const NATIVE_VEC_GET_F32: &str = "__fz_native_vec_get_f32";
const NATIVE_AGG_NEW_SYMBOL: &str = "fz_native_agg_new";
const NATIVE_AGG_SET_I64_SYMBOL: &str = "fz_native_agg_set_i64";
const NATIVE_AGG_GET_I64_SYMBOL: &str = "fz_native_agg_get_i64";
const NATIVE_AGG_TAG_SYMBOL: &str = "fz_native_agg_tag";
const NATIVE_STR_PTR_SYMBOL: &str = "fz_native_str_ptr";
const NATIVE_VEC_LEN_SYMBOL: &str = "fz_native_vec_len";
const NATIVE_VEC_GET_I32_SYMBOL: &str = "fz_native_vec_get_i32";
const NATIVE_VEC_GET_U32_SYMBOL: &str = "fz_native_vec_get_u32";
const NATIVE_VEC_GET_F32_SYMBOL: &str = "fz_native_vec_get_f32";

#[derive(Debug, Clone)]
pub struct BuildArtifact {
    pub module: String,
    pub profile: BuildProfile,
    pub status: &'static str,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub output: Option<PathBuf>,
    pub dependency_graph_hash: Option<String>,
    pub incremental: Option<IncrementalBuildReport>,
}

#[derive(Debug, Clone)]
pub struct LibraryArtifact {
    pub module: String,
    pub profile: BuildProfile,
    pub status: &'static str,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub static_lib: Option<PathBuf>,
    pub shared_lib: Option<PathBuf>,
    pub dependency_graph_hash: Option<String>,
    pub incremental: Option<IncrementalBuildReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncrementalBuildReport {
    pub enabled: bool,
    pub module_count: usize,
    pub rebuilt_modules: usize,
    pub reused_modules: usize,
    pub global_interface_fingerprint: String,
    pub module_details: Vec<IncrementalModuleReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncrementalModuleReport {
    pub path: String,
    pub namespace: String,
    pub source_fingerprint: String,
    pub rebuilt: bool,
    pub object: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct IncrementalModuleUnitPlan {
    pub path: PathBuf,
    pub identity: String,
    pub namespace: String,
    pub source_fingerprint: String,
    pub local_functions: HashSet<String>,
    pub local_mutable_globals: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub module: String,
    pub nodes: usize,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub backend_ir: Option<String>,
    pub validation_tier: ValidationTier,
    pub telemetry: ValidationTelemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationTier {
    Check,
    Verify,
}

impl ValidationTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Verify => "verify",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ValidationTelemetry {
    pub total_ms: u64,
    pub parse_ms: u64,
    pub lower_ms: u64,
    pub verify_ms: u64,
    pub backend_ms: u64,
    pub contract_ms: u64,
    pub parse_cache_hit: bool,
    pub lower_cache_hit: bool,
    pub input_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModuleStamp {
    path: PathBuf,
    bytes: u64,
    modified_ns: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SuccessfulBuildCacheEntry {
    schema_version: String,
    source_path: PathBuf,
    module_name: String,
    profile: String,
    backend: String,
    #[serde(rename = "compilerFingerprint", default)]
    compiler_fingerprint: String,
    manifest_fingerprint: Option<String>,
    dependency_graph_hash: Option<String>,
    pgo_signature: String,
    source_stamps: Vec<ModuleStamp>,
    output: Option<PathBuf>,
    static_lib: Option<PathBuf>,
    shared_lib: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ParsedProgramCacheEntry {
    parsed: Arc<ParsedProgram>,
    stamps: Vec<ModuleStamp>,
}

#[derive(Debug, Clone)]
struct LowerCacheEntry {
    typed: Arc<hir::TypedModule>,
    fir: Arc<fir::FirModule>,
}

#[derive(Debug, Clone)]
struct DependencySourceCacheEntry {
    manifest_stamp: ModuleStamp,
    manifest_hash: String,
    package_name: String,
    package_version: String,
    source_hash: String,
    source_stamps: Vec<ModuleStamp>,
}

#[derive(Clone)]
struct SharedLoweredProgram {
    typed: Arc<hir::TypedModule>,
    fir: Arc<fir::FirModule>,
}

static PARSED_PROGRAM_CACHE: OnceLock<RwLock<HashMap<PathBuf, ParsedProgramCacheEntry>>> =
    OnceLock::new();
static LOWER_CACHE: OnceLock<RwLock<HashMap<String, LowerCacheEntry>>> = OnceLock::new();
static DEPENDENCY_SOURCE_CACHE: OnceLock<RwLock<HashMap<PathBuf, DependencySourceCacheEntry>>> =
    OnceLock::new();
static CODEGEN_POOL_INIT: Once = Once::new();

#[derive(Debug, Clone)]
struct PgoConfig {
    generate_dir: Option<PathBuf>,
    use_profile: Option<PathBuf>,
}

fn configured_codegen_jobs() -> Option<usize> {
    std::env::var("FZ_CODEGEN_JOBS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn ensure_codegen_pool_configured() {
    CODEGEN_POOL_INIT.call_once(|| {
        let Some(threads) = configured_codegen_jobs() else {
            return;
        };
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global();
    });
}

fn configured_pgo() -> PgoConfig {
    let generate_dir = std::env::var("FZ_PGO_GENERATE")
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty());
    let use_profile = std::env::var("FZ_PGO_USE")
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty());
    PgoConfig {
        generate_dir,
        use_profile,
    }
}
