use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{types, AbiParam, InstBuilder, MemFlags, Type as ClifType};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Switch, Variable};
use cranelift_module::{default_libcall_names, DataDescription, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Mutex, Once, OnceLock};
use std::time::UNIX_EPOCH;

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
}

#[derive(Clone)]
struct LlvmClosureBinding {
    params: Vec<ast::Param>,
    return_type: Option<ast::Type>,
    body: ast::Expr,
    captures: HashMap<String, String>,
}

#[derive(Clone)]
struct ClifClosureBinding {
    params: Vec<ast::Param>,
    return_type: Option<ast::Type>,
    body: ast::Expr,
    captures: HashMap<String, LocalBinding>,
}

#[derive(Clone)]
struct LlvmArrayBinding {
    storage: String,
    len: usize,
    element_bits: u16,
    element_align: u8,
    element_stride: u8,
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

#[derive(Debug, Clone, Copy)]
struct NativeRuntimeImport {
    callee: &'static str,
    symbol: &'static str,
    arity: usize,
}

const NATIVE_RUNTIME_IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "http.bind",
        symbol: "fz_native_net_bind",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.listen",
        symbol: "fz_native_net_listen",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.accept",
        symbol: "fz_native_net_accept",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.read",
        symbol: "fz_native_net_read",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "env.get",
        symbol: "fz_native_env_get",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.now",
        symbol: "fz_native_time_now",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.post_json",
        symbol: "fz_native_http_post_json",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.post_json_capture",
        symbol: "fz_native_http_post_json_capture",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.last_status",
        symbol: "fz_native_http_last_status",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.last_error",
        symbol: "fz_native_http_last_error",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "json.escape",
        symbol: "fz_native_json_escape",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.str",
        symbol: "fz_native_json_str",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.raw",
        symbol: "fz_native_json_raw",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.array1",
        symbol: "fz_native_json_array1",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.array2",
        symbol: "fz_native_json_array2",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.array3",
        symbol: "fz_native_json_array3",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "json.array4",
        symbol: "fz_native_json_array4",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "json.object1",
        symbol: "fz_native_json_object1",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.object2",
        symbol: "fz_native_json_object2",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "json.object3",
        symbol: "fz_native_json_object3",
        arity: 6,
    },
    NativeRuntimeImport {
        callee: "json.object4",
        symbol: "fz_native_json_object4",
        arity: 8,
    },
    NativeRuntimeImport {
        callee: "json.from_list",
        symbol: "fz_native_json_from_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.from_map",
        symbol: "fz_native_json_from_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.to_list",
        symbol: "fz_native_json_to_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.to_map",
        symbol: "fz_native_json_to_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.parse",
        symbol: "fz_native_json_parse",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.get",
        symbol: "fz_native_json_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.get_str",
        symbol: "fz_native_json_get_str",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.has",
        symbol: "fz_native_json_has",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.path",
        symbol: "fz_native_json_path",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.method",
        symbol: "fz_native_net_method",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.path",
        symbol: "fz_native_net_path",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body",
        symbol: "fz_native_net_body",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body_json",
        symbol: "fz_native_net_body_json",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body_bind",
        symbol: "fz_native_net_body_bind",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.header",
        symbol: "fz_native_net_header",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.query",
        symbol: "fz_native_net_query",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.param",
        symbol: "fz_native_net_param",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.headers",
        symbol: "fz_native_net_headers",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.request_id",
        symbol: "fz_native_net_request_id",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.remote_addr",
        symbol: "fz_native_net_remote_addr",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.write",
        symbol: "fz_native_net_write",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.write_json",
        symbol: "fz_native_net_write_json",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.write_response",
        symbol: "fz_native_net_write_response",
        arity: 5,
    },
    NativeRuntimeImport {
        callee: "http.close",
        symbol: "fz_native_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "route.match",
        symbol: "fz_native_route_match",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "route.write_404",
        symbol: "fz_native_route_write_404",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "route.write_405",
        symbol: "fz_native_route_write_405",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.open",
        symbol: "fz_native_fs_open",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.write",
        symbol: "fz_native_fs_write",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.read",
        symbol: "fz_native_fs_read",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.flush",
        symbol: "fz_native_fs_flush",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.fsync",
        symbol: "fz_native_fs_fsync",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.atomic_write",
        symbol: "fz_native_fs_atomic_write",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.rename_atomic",
        symbol: "fz_native_fs_rename_atomic",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "fs.read_file",
        symbol: "fz_native_fs_read_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.write_file",
        symbol: "fz_native_fs_write_file",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.mkdir",
        symbol: "fz_native_fs_mkdir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.exists",
        symbol: "fz_native_fs_exists",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.stat_size",
        symbol: "fz_native_fs_stat_size",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.listdir",
        symbol: "fz_native_fs_listdir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.remove_file",
        symbol: "fz_native_fs_remove_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.temp_file",
        symbol: "fz_native_fs_temp_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.join",
        symbol: "fz_native_path_join",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "path.normalize",
        symbol: "fz_native_path_normalize",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.info",
        symbol: "fz_native_log_info",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.warn",
        symbol: "fz_native_log_warn",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.error",
        symbol: "fz_native_log_error",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.fields1",
        symbol: "fz_native_log_fields1",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.fields2",
        symbol: "fz_native_log_fields2",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "log.fields3",
        symbol: "fz_native_log_fields3",
        arity: 6,
    },
    NativeRuntimeImport {
        callee: "log.fields4",
        symbol: "fz_native_log_fields4",
        arity: 8,
    },
    NativeRuntimeImport {
        callee: "log.set_json",
        symbol: "fz_native_log_set_json",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.correlation_id",
        symbol: "fz_native_log_correlation_id",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "error.code",
        symbol: "fz_native_error_code",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.class",
        symbol: "fz_native_error_class",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.message",
        symbol: "fz_native_error_message",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.context",
        symbol: "fz_native_error_context",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.monotonic_ms",
        symbol: "fz_native_time_now",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "time.sleep_ms",
        symbol: "fz_native_time_sleep_ms",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.interval",
        symbol: "fz_native_time_interval",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.tick",
        symbol: "fz_native_time_tick",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.elapsed_ms",
        symbol: "fz_native_time_elapsed_ms",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.deadline_after",
        symbol: "fz_native_time_deadline_after",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "close",
        symbol: "fz_native_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "spawn",
        symbol: "fz_native_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "thread.spawn",
        symbol: "fz_native_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "spawn_ctx",
        symbol: "fz_native_spawn_ctx",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "join",
        symbol: "fz_native_join",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "detach",
        symbol: "fz_native_detach",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "cancel_task",
        symbol: "fz_native_cancel_task",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task_result",
        symbol: "fz_native_task_result",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.context",
        symbol: "fz_native_task_context",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "task.group_begin",
        symbol: "fz_native_task_group_begin",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "task.group_spawn",
        symbol: "fz_native_task_group_spawn",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "task.group_join",
        symbol: "fz_native_task_group_join",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.group_cancel",
        symbol: "fz_native_task_group_cancel",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "timeout",
        symbol: "fz_native_timeout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "deadline",
        symbol: "fz_native_deadline",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "cancel",
        symbol: "fz_native_cancel",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "recv",
        symbol: "fz_native_recv",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "yield",
        symbol: "fz_native_yield",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "checkpoint",
        symbol: "fz_native_checkpoint",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "pulse",
        symbol: "fz_native_pulse",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "http.poll_next",
        symbol: "fz_native_net_poll_next",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.run",
        symbol: "fz_native_proc_run",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.runv",
        symbol: "fz_native_proc_runv",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.runl",
        symbol: "fz_native_proc_runl",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.spawnv",
        symbol: "fz_native_proc_spawnv",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.spawnl",
        symbol: "fz_native_proc_spawnl",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.spawn",
        symbol: "fz_native_proc_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exec_timeout",
        symbol: "fz_native_proc_exec_timeout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exit_class",
        symbol: "fz_native_proc_exit_class",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.wait",
        symbol: "fz_native_proc_wait",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.poll",
        symbol: "fz_native_proc_poll",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.event",
        symbol: "fz_native_proc_event",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.read_stdout",
        symbol: "fz_native_proc_read_stdout",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.read_stderr",
        symbol: "fz_native_proc_read_stderr",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.stdout",
        symbol: "fz_native_proc_stdout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.stderr",
        symbol: "fz_native_proc_stderr",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exit_code",
        symbol: "fz_native_proc_exit_code",
        arity: 1,
    },
];

const NATIVE_DATA_PLANE_IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "str.concat2",
        symbol: "fz_native_str_concat2",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.concat3",
        symbol: "fz_native_str_concat3",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.concat4",
        symbol: "fz_native_str_concat4",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "str.contains",
        symbol: "fz_native_str_contains",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.starts_with",
        symbol: "fz_native_str_starts_with",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.ends_with",
        symbol: "fz_native_str_ends_with",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.replace",
        symbol: "fz_native_str_replace",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.trim",
        symbol: "fz_native_str_trim",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.split",
        symbol: "fz_native_str_split",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.len",
        symbol: "fz_native_str_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.slice",
        symbol: "fz_native_str_slice",
        arity: 3,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    Dev,
    Release,
    Verify,
}

#[derive(Debug, Clone)]
pub struct BuildArtifact {
    pub module: String,
    pub profile: BuildProfile,
    pub status: &'static str,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub output: Option<PathBuf>,
    pub dependency_graph_hash: Option<String>,
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
}

#[derive(Debug, Clone)]
pub struct Output {
    pub module: String,
    pub nodes: usize,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub backend_ir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedProgram {
    pub module: ast::Module,
    pub combined_source: String,
    pub module_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct ModuleStamp {
    path: PathBuf,
    bytes: u64,
    modified_ns: u128,
}

#[derive(Debug, Clone)]
struct ParsedProgramCacheEntry {
    parsed: ParsedProgram,
    stamps: Vec<ModuleStamp>,
}

#[derive(Debug, Clone)]
struct LowerCacheEntry {
    typed: hir::TypedModule,
    fir: fir::FirModule,
}

static PARSED_PROGRAM_CACHE: OnceLock<Mutex<HashMap<PathBuf, ParsedProgramCacheEntry>>> =
    OnceLock::new();
static LOWER_CACHE: OnceLock<Mutex<HashMap<String, LowerCacheEntry>>> = OnceLock::new();
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

pub fn compile_file(path: &Path, profile: BuildProfile) -> Result<BuildArtifact> {
    compile_file_with_backend(path, profile, None)
}

pub fn compile_file_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    let resolved = resolve_source_path(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    let backend = resolve_native_backend(profile, backend_override)?;
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
    let backend_risks = backend_capability_diagnostics(&parsed.module, &backend);
    let (_typed, fir) = lower_fir_cached(&parsed);
    let strict_unsafe_contracts = unsafe_contracts_enforced(resolved.manifest.as_ref(), profile);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
            production_memory_safety: true,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let has_verifier_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_experimental_errors = experimental_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_native_lowerability_errors = !native_lowerability_errors.is_empty();
    let has_backend_risks = backend_risks
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if has_experimental_errors
        || has_native_lowerability_errors
        || has_backend_risks
        || (checks_enabled && has_verifier_errors)
    {
        "error"
    } else {
        "ok"
    };
    let mut diagnostic_details = experimental_diagnostics;
    diagnostic_details.extend(native_lowerability_errors);
    diagnostic_details.extend(backend_risks);
    diagnostic_details.extend(report.diagnostics);
    normalize_diagnostics_for_path(&resolved.source_path, &mut diagnostic_details);
    let output = if status == "ok" {
        Some(emit_native_artifact(
            &fir,
            &resolved.project_root,
            profile,
            resolved.manifest.as_ref(),
            Some(backend.as_str()),
        )?)
    } else {
        None
    };

    Ok(BuildArtifact {
        module: fir.name,
        profile,
        status,
        diagnostics: diagnostic_details.len(),
        diagnostic_details,
        output,
        dependency_graph_hash: resolved.dependency_graph_hash,
    })
}

pub fn compile_library_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<LibraryArtifact> {
    let resolved = resolve_source_path_with_target(path, true)?;
    let parsed = parse_program(&resolved.source_path)?;
    let experimental_diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    let backend = resolve_native_backend(profile, backend_override)?;
    let pgo = configured_pgo();
    if (pgo.generate_dir.is_some() || pgo.use_profile.is_some()) && backend != "llvm" {
        bail!(
            "PGO is only supported with backend `llvm`; current backend is `{}`",
            backend
        );
    }
    let native_lowerability_errors = native_lowerability_diagnostics(&parsed.module);
    let backend_risks = backend_capability_diagnostics(&parsed.module, &backend);
    let (_typed, fir) = lower_fir_cached(&parsed);
    let strict_unsafe_contracts = unsafe_contracts_enforced(resolved.manifest.as_ref(), profile);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
            production_memory_safety: true,
            strict_unsafe_contracts,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let has_verifier_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_experimental_errors = experimental_diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let has_native_lowerability_errors = !native_lowerability_errors.is_empty();
    let has_backend_risks = backend_risks
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if has_experimental_errors
        || has_native_lowerability_errors
        || has_backend_risks
        || (checks_enabled && has_verifier_errors)
    {
        "error"
    } else {
        "ok"
    };
    let mut diagnostic_details = experimental_diagnostics;
    diagnostic_details.extend(native_lowerability_errors);
    diagnostic_details.extend(backend_risks);
    diagnostic_details.extend(report.diagnostics);
    normalize_diagnostics_for_path(&resolved.source_path, &mut diagnostic_details);
    let (static_lib, shared_lib) = if status == "ok" {
        emit_native_libraries(
            &fir,
            &resolved.project_root,
            profile,
            resolved.manifest.as_ref(),
            Some(backend.as_str()),
        )?
    } else {
        (None, None)
    };

    Ok(LibraryArtifact {
        module: fir.name,
        profile,
        status,
        diagnostics: diagnostic_details.len(),
        diagnostic_details,
        static_lib,
        shared_lib,
        dependency_graph_hash: resolved.dependency_graph_hash,
    })
}

pub fn verify_file(path: &Path) -> Result<Output> {
    let resolved = resolve_source_path(path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let parsed = match parse_program(&resolved.source_path) {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut diagnostics =
                collect_parse_diagnostics(&resolved.source_path).unwrap_or_else(|_| {
                    vec![diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        error.to_string(),
                        None,
                    )]
                });
            for diagnostic in &mut diagnostics {
                if diagnostic.path.is_none() {
                    diagnostic.path = Some(resolved.source_path.display().to_string());
                }
            }
            enrich_diagnostics_context(&mut diagnostics);
            diagnostics::assign_stable_codes(
                &mut diagnostics,
                diagnostics::DiagnosticDomain::Driver,
            );
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: diagnostics.len(),
                diagnostic_details: diagnostics,
                backend_ir: None,
            });
        }
    };
    let mut diagnostics =
        experimental_feature_diagnostics(&parsed.module, resolved.manifest.as_ref());
    diagnostics.extend(native_lowerability_diagnostics(&parsed.module));
    let (_typed, fir) = lower_fir_cached(&parsed);
    let (deny_unsafe_in, allow_unsafe_in) = unsafe_scope_policy(resolved.manifest.as_ref());
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: false,
            production_memory_safety: true,
            strict_unsafe_contracts: true,
            deny_unsafe_in,
            allow_unsafe_in,
        },
    );
    diagnostics.extend(report.diagnostics);
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(resolved.source_path.display().to_string());
        }
    }
    enrich_diagnostics_context(&mut diagnostics);
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Driver);

    Ok(Output {
        module: fir.name,
        nodes: fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: None,
    })
}

fn normalize_diagnostics_for_path(path: &Path, diagnostics: &mut [diagnostics::Diagnostic]) {
    for diagnostic in diagnostics.iter_mut() {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(path.display().to_string());
        }
    }
    enrich_diagnostics_context(diagnostics);
    diagnostics::assign_stable_codes(diagnostics, diagnostics::DiagnosticDomain::Driver);
}

pub fn emit_ir(path: &Path) -> Result<Output> {
    let resolved = resolve_source_path(path)?;
    let source_path = resolved.source_path;
    let module_name = source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;

    let parsed = match parse_program(&source_path) {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut diagnostics = vec![diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                error.to_string(),
                None,
            )];
            for diagnostic in &mut diagnostics {
                if diagnostic.path.is_none() {
                    diagnostic.path = Some(source_path.display().to_string());
                }
            }
            enrich_diagnostics_context(&mut diagnostics);
            diagnostics::assign_stable_codes(
                &mut diagnostics,
                diagnostics::DiagnosticDomain::Driver,
            );
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: diagnostics.len(),
                diagnostic_details: diagnostics,
                backend_ir: None,
            });
        }
    };
    let mut diagnostics = native_lowerability_diagnostics(&parsed.module);
    let (_typed, fir) = lower_fir_cached(&parsed);
    let report = verifier::verify(&fir);
    diagnostics.extend(report.diagnostics);
    for diagnostic in &mut diagnostics {
        if diagnostic.path.is_none() {
            diagnostic.path = Some(source_path.display().to_string());
        }
    }
    enrich_diagnostics_context(&mut diagnostics);
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Driver);
    let llvm = lower_backend_ir(&fir, BackendKind::Llvm)?;
    let cranelift = lower_backend_ir(&fir, BackendKind::Cranelift)?;

    Ok(Output {
        module: fir.name,
        nodes: fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: Some(format!(
            "; backend=llvm\n{llvm}\n; backend=cranelift\n{cranelift}\n"
        )),
    })
}

pub fn parse_program(source_path: &Path) -> Result<ParsedProgram> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    if let Some(cached) = cached_parsed_program(&canonical) {
        return Ok(cached);
    }
    let parsed = parse_program_uncached(&canonical)?;
    store_parsed_program_cache(&canonical, &parsed);
    Ok(parsed)
}

pub fn lower_fir_cached(parsed: &ParsedProgram) -> (hir::TypedModule, fir::FirModule) {
    let module_hash = sha256_hex(parsed.combined_source.as_bytes());
    let cache = LOWER_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(cached) = guard.get(&module_hash) {
            return (cached.typed.clone(), cached.fir.clone());
        }
    }
    let typed = hir::lower(&parsed.module);
    let fir_module = fir::build_owned(typed.clone());
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            module_hash,
            LowerCacheEntry {
                typed: typed.clone(),
                fir: fir_module.clone(),
            },
        );
    }
    (typed, fir_module)
}

fn parse_program_uncached(canonical: &Path) -> Result<ParsedProgram> {
    let mut state = ModuleLoadState::default();
    discover_module_graph_recursive(canonical, &mut state)?;

    let loaded_modules = state
        .load_order
        .par_iter()
        .map(|path| parse_and_qualify_module(path, canonical, &state.discovered))
        .collect::<Result<Vec<_>>>()?;
    state.loaded = loaded_modules.into_iter().collect();

    let mut combined_source = String::new();
    for path in &state.load_order {
        let loaded = state
            .loaded
            .get(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        combined_source.push_str("// module: ");
        combined_source.push_str(&path.display().to_string());
        combined_source.push('\n');
        combined_source.push_str(&loaded.source);
        if !loaded.source.ends_with('\n') {
            combined_source.push('\n');
        }
    }
    let mut merged = state
        .loaded
        .remove(canonical)
        .map(|module| module.ast)
        .ok_or_else(|| anyhow!("failed to load root module {}", canonical.display()))?;
    for path in &state.load_order {
        if path == canonical {
            continue;
        }
        let loaded = state
            .loaded
            .remove(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        merge_module_owned(&mut merged, loaded.ast);
    }
    canonicalize_call_targets(&mut merged);
    Ok(ParsedProgram {
        module: merged,
        combined_source,
        module_paths: state.load_order,
    })
}

fn module_stamp(path: &Path) -> Option<ModuleStamp> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let modified_ns = modified.duration_since(UNIX_EPOCH).ok()?.as_nanos();
    Some(ModuleStamp {
        path: path.to_path_buf(),
        bytes: meta.len(),
        modified_ns,
    })
}

fn cached_parsed_program(canonical: &Path) -> Option<ParsedProgram> {
    let cache = PARSED_PROGRAM_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = cache.lock().ok()?;
    let entry = guard.get(canonical)?;
    if entry.stamps.iter().all(|stamp| {
        module_stamp(&stamp.path).is_some_and(|current| {
            current.bytes == stamp.bytes && current.modified_ns == stamp.modified_ns
        })
    }) {
        return Some(entry.parsed.clone());
    }
    None
}

fn store_parsed_program_cache(canonical: &Path, parsed: &ParsedProgram) {
    let stamps = parsed
        .module_paths
        .iter()
        .filter_map(|path| module_stamp(path))
        .collect::<Vec<_>>();
    let cache = PARSED_PROGRAM_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            canonical.to_path_buf(),
            ParsedProgramCacheEntry {
                parsed: parsed.clone(),
                stamps,
            },
        );
    }
}

#[derive(Debug, Clone)]
struct LoadedModule {
    ast: ast::Module,
    source: String,
}

#[derive(Debug, Clone)]
struct DiscoveredModule {
    source: String,
    module_decls: Vec<String>,
}

#[derive(Debug, Default)]
struct ModuleLoadState {
    discovered: HashMap<PathBuf, DiscoveredModule>,
    loaded: HashMap<PathBuf, LoadedModule>,
    load_order: Vec<PathBuf>,
    visiting: Vec<PathBuf>,
    visiting_set: HashSet<PathBuf>,
}

fn discover_module_graph_recursive(
    path: &Path,
    state: &mut ModuleLoadState,
) -> Result<()> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if state.discovered.contains_key(&canonical) {
        return Ok(());
    }
    if state.visiting_set.contains(&canonical) {
        let cycle = format_module_cycle(&state.visiting, &canonical);
        return Err(anyhow!("cyclic module declaration detected: {}", cycle));
    }

    state.visiting_set.insert(canonical.clone());
    state.visiting.push(canonical.clone());

    let source = std::fs::read_to_string(&canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = parser::parse(&source, module_name)
        .map_err(|diagnostics| anyhow!(render_parse_failure(&canonical, &diagnostics)))?;

    let base_dir = canonical
        .parent()
        .ok_or_else(|| anyhow!("module has no parent directory: {}", canonical.display()))?;
    for module_decl in &ast.modules {
        let module_path = resolve_declared_module(base_dir, module_decl).with_context(|| {
            format!(
                "while resolving module `{}` from {}",
                module_decl,
                canonical.display()
            )
        })?;
        discover_module_graph_recursive(&module_path, state)?;
    }

    state.visiting.pop();
    state.visiting_set.remove(&canonical);
    state.load_order.push(canonical.clone());
    state.discovered.insert(
        canonical,
        DiscoveredModule {
            source,
            module_decls: ast.modules,
        },
    );
    Ok(())
}

fn parse_and_qualify_module(
    module_path: &Path,
    root_source: &Path,
    discovered: &HashMap<PathBuf, DiscoveredModule>,
) -> Result<(PathBuf, LoadedModule)> {
    let discovered_module = discovered
        .get(module_path)
        .ok_or_else(|| anyhow!("internal discovered module cache miss for {}", module_path.display()))?;
    let module_name = module_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", module_path.display()))?;
    let mut ast = parser::parse(&discovered_module.source, module_name)
        .map_err(|diagnostics| anyhow!(render_parse_failure(module_path, &diagnostics)))?;
    let namespace = module_namespace(root_source, module_path)?;
    qualify_module_symbols(&mut ast, &namespace);
    ast.modules = discovered_module.module_decls.clone();
    Ok((
        module_path.to_path_buf(),
        LoadedModule {
            ast,
            source: discovered_module.source.clone(),
        },
    ))
}

fn module_namespace(root_source: &Path, module_path: &Path) -> Result<String> {
    if module_path == root_source {
        return Ok(String::new());
    }
    let root_dir = root_source.parent().ok_or_else(|| {
        anyhow!(
            "root source has no parent directory: {}",
            root_source.display()
        )
    })?;
    let relative = module_path
        .strip_prefix(root_dir)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| module_path.to_path_buf());
    let mut components = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(|component| component.to_string())
        .collect::<Vec<_>>();
    if components.is_empty() {
        return Ok(String::new());
    }
    let tail = components.pop().unwrap_or_default();
    let stem = Path::new(&tail)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !stem.is_empty() && stem != "mod" {
        components.push(stem.to_string());
    }
    Ok(components.join("."))
}

fn qualify_module_symbols(module: &mut ast::Module, namespace: &str) {
    let local_functions = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut module_aliases = module
        .modules
        .iter()
        .map(|module_name| {
            (
                module_name.clone(),
                qualify_name(namespace, module_name.as_str()),
            )
        })
        .collect::<HashMap<_, _>>();
    for (alias, target) in import_aliases(module, &module_aliases) {
        module_aliases.insert(alias, target);
    }

    for item in &mut module.items {
        match item {
            ast::Item::Function(function) => {
                qualify_function(function, namespace, &local_functions, &module_aliases);
            }
            ast::Item::Test(test) => {
                for stmt in &mut test.body {
                    qualify_stmt(stmt, namespace, &local_functions, &module_aliases);
                }
            }
            _ => {}
        }
    }
}

fn import_aliases(
    module: &ast::Module,
    module_aliases: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for import in &module.imports {
        if import.wildcard || import.path.is_empty() {
            continue;
        }
        let Some(leaf) = import.path.last().cloned() else {
            continue;
        };
        let canonical = canonicalize_import_path(&import.path, module_aliases);
        let alias = import.alias.clone().unwrap_or(leaf);
        aliases.insert(alias, canonical);
    }
    aliases
}

fn canonicalize_import_path(path: &[String], module_aliases: &HashMap<String, String>) -> String {
    let mut segments = path.to_vec();
    if let Some(head) = segments.first_mut() {
        if let Some(replacement) = module_aliases.get(head) {
            *head = replacement.clone();
        }
    }
    segments.join(".")
}

fn qualify_function(
    function: &mut ast::Function,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    if !function.is_extern {
        function.name = qualify_name(namespace, &function.name);
    }
    for stmt in &mut function.body {
        qualify_stmt(stmt, namespace, local_functions, module_aliases);
    }
}

fn qualify_stmt(
    stmt: &mut ast::Stmt,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => qualify_expr(value, namespace, local_functions, module_aliases),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                qualify_expr(value, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            qualify_expr(condition, namespace, local_functions, module_aliases);
            for nested in then_body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
            for nested in else_body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::While { condition, body } => {
            qualify_expr(condition, namespace, local_functions, module_aliases);
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                qualify_stmt(init, namespace, local_functions, module_aliases);
            }
            if let Some(condition) = condition {
                qualify_expr(condition, namespace, local_functions, module_aliases);
            }
            if let Some(step) = step {
                qualify_stmt(step, namespace, local_functions, module_aliases);
            }
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            qualify_expr(iterable, namespace, local_functions, module_aliases);
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                qualify_stmt(nested, namespace, local_functions, module_aliases);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            qualify_expr(scrutinee, namespace, local_functions, module_aliases);
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    qualify_expr(guard, namespace, local_functions, module_aliases);
                }
                qualify_expr(&mut arm.value, namespace, local_functions, module_aliases);
            }
        }
    }
}

fn qualify_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            *callee = qualify_callee(callee, namespace, local_functions, module_aliases);
            for arg in args {
                qualify_expr(arg, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                qualify_stmt(stmt, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            qualify_expr(base, namespace, local_functions, module_aliases);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                qualify_expr(value, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                qualify_expr(value, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::Closure { body, .. } => {
            qualify_expr(body, namespace, local_functions, module_aliases);
        }
        ast::Expr::Group(inner) => {
            qualify_expr(inner, namespace, local_functions, module_aliases);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            qualify_expr(inner, namespace, local_functions, module_aliases);
        }
        ast::Expr::Unary { expr, .. } => {
            qualify_expr(expr, namespace, local_functions, module_aliases);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            qualify_expr(try_expr, namespace, local_functions, module_aliases);
            qualify_expr(catch_expr, namespace, local_functions, module_aliases);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            qualify_expr(condition, namespace, local_functions, module_aliases);
            qualify_expr(then_expr, namespace, local_functions, module_aliases);
            qualify_expr(else_expr, namespace, local_functions, module_aliases);
        }
        ast::Expr::Binary { left, right, .. } => {
            qualify_expr(left, namespace, local_functions, module_aliases);
            qualify_expr(right, namespace, local_functions, module_aliases);
        }
        ast::Expr::Range { start, end, .. } => {
            qualify_expr(start, namespace, local_functions, module_aliases);
            qualify_expr(end, namespace, local_functions, module_aliases);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                qualify_expr(item, namespace, local_functions, module_aliases);
            }
        }
        ast::Expr::Index { base, index } => {
            qualify_expr(base, namespace, local_functions, module_aliases);
            qualify_expr(index, namespace, local_functions, module_aliases);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn qualify_callee(
    callee: &str,
    namespace: &str,
    local_functions: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    let qualified_base = if let Some(exact_alias) = module_aliases.get(base) {
        exact_alias.clone()
    } else if let Some((head, tail)) = base.split_once('.') {
        if let Some(qualified_head) = module_aliases.get(head) {
            format!("{qualified_head}.{tail}")
        } else {
            base.to_string()
        }
    } else if local_functions.contains(base) {
        qualify_name(namespace, base)
    } else {
        base.to_string()
    };
    format!("{qualified_base}{generic_suffix}")
}

fn split_generic_suffix(callee: &str) -> (&str, &str) {
    if let Some(index) = callee.find('<') {
        (&callee[..index], &callee[index..])
    } else {
        (callee, "")
    }
}

fn qualify_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn canonicalize_call_targets(module: &mut ast::Module) {
    let known_functions = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    for item in &mut module.items {
        if let ast::Item::Function(function) = item {
            let namespace = function
                .name
                .rsplit_once('.')
                .map(|(prefix, _)| prefix)
                .unwrap_or("");
            for stmt in &mut function.body {
                canonicalize_stmt_calls(stmt, namespace, &known_functions);
            }
        }
    }
}

fn canonicalize_stmt_calls(
    stmt: &mut ast::Stmt,
    namespace: &str,
    known_functions: &HashSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => canonicalize_expr_calls(value, namespace, known_functions),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                canonicalize_expr_calls(value, namespace, known_functions);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            canonicalize_expr_calls(condition, namespace, known_functions);
            for nested in then_body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
            for nested in else_body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::While { condition, body } => {
            canonicalize_expr_calls(condition, namespace, known_functions);
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                canonicalize_stmt_calls(init, namespace, known_functions);
            }
            if let Some(condition) = condition {
                canonicalize_expr_calls(condition, namespace, known_functions);
            }
            if let Some(step) = step {
                canonicalize_stmt_calls(step, namespace, known_functions);
            }
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            canonicalize_expr_calls(iterable, namespace, known_functions);
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                canonicalize_stmt_calls(nested, namespace, known_functions);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            canonicalize_expr_calls(scrutinee, namespace, known_functions);
            for arm in arms {
                if let Some(guard) = &mut arm.guard {
                    canonicalize_expr_calls(guard, namespace, known_functions);
                }
                canonicalize_expr_calls(&mut arm.value, namespace, known_functions);
            }
        }
    }
}

fn canonicalize_expr_calls(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            *callee = canonicalize_callee(callee, namespace, known_functions);
            if matches!(
                callee.as_str(),
                "spawn" | "spawn_ctx" | "task.group_spawn" | "thread.spawn"
            ) {
                if let Some(task_ref) = args.first_mut() {
                    canonicalize_task_ref_expr(task_ref, namespace, known_functions);
                }
            }
            for arg in args {
                canonicalize_expr_calls(arg, namespace, known_functions);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                canonicalize_stmt_calls(stmt, namespace, known_functions);
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            canonicalize_expr_calls(base, namespace, known_functions);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                canonicalize_expr_calls(value, namespace, known_functions);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                canonicalize_expr_calls(value, namespace, known_functions);
            }
        }
        ast::Expr::Closure { body, .. } => {
            canonicalize_expr_calls(body, namespace, known_functions);
        }
        ast::Expr::Group(inner) => {
            canonicalize_expr_calls(inner, namespace, known_functions);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            canonicalize_expr_calls(inner, namespace, known_functions);
        }
        ast::Expr::Unary { expr, .. } => {
            canonicalize_expr_calls(expr, namespace, known_functions);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            canonicalize_expr_calls(try_expr, namespace, known_functions);
            canonicalize_expr_calls(catch_expr, namespace, known_functions);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            canonicalize_expr_calls(condition, namespace, known_functions);
            canonicalize_expr_calls(then_expr, namespace, known_functions);
            canonicalize_expr_calls(else_expr, namespace, known_functions);
        }
        ast::Expr::Binary { left, right, .. } => {
            canonicalize_expr_calls(left, namespace, known_functions);
            canonicalize_expr_calls(right, namespace, known_functions);
        }
        ast::Expr::Range { start, end, .. } => {
            canonicalize_expr_calls(start, namespace, known_functions);
            canonicalize_expr_calls(end, namespace, known_functions);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                canonicalize_expr_calls(item, namespace, known_functions);
            }
        }
        ast::Expr::Index { base, index } => {
            canonicalize_expr_calls(base, namespace, known_functions);
            canonicalize_expr_calls(index, namespace, known_functions);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn canonicalize_callee(callee: &str, namespace: &str, known_functions: &HashSet<String>) -> String {
    let (base, generic_suffix) = split_generic_suffix(callee);
    if known_functions.contains(base) {
        return callee.to_string();
    }
    if base.contains('.') {
        let mut scope = Some(namespace);
        while let Some(current) = scope {
            if !current.is_empty() {
                let candidate = format!("{current}.{base}");
                if known_functions.contains(&candidate) {
                    return format!("{candidate}{generic_suffix}");
                }
            }
            scope = current.rsplit_once('.').map(|(parent, _)| parent);
        }
    } else {
        let candidate = qualify_name(namespace, base);
        if known_functions.contains(&candidate) {
            return format!("{candidate}{generic_suffix}");
        }
    }
    callee.to_string()
}

fn canonicalize_task_ref_expr(
    expr: &mut ast::Expr,
    namespace: &str,
    known_functions: &HashSet<String>,
) {
    let Some(task_ref) = expr_task_ref_name(expr) else {
        return;
    };
    let canonical = canonicalize_callee(&task_ref, namespace, known_functions);
    if canonical == task_ref {
        return;
    }
    *expr = task_ref_expr_from_name(&canonical);
}

fn task_ref_expr_from_name(name: &str) -> ast::Expr {
    let mut segments = name.split('.');
    let head = segments.next().unwrap_or_default().to_string();
    let mut expr = ast::Expr::Ident(head);
    for segment in segments {
        expr = ast::Expr::FieldAccess {
            base: Box::new(expr),
            field: segment.to_string(),
        };
    }
    expr
}

fn collect_parse_diagnostics(source_path: &Path) -> Result<Vec<diagnostics::Diagnostic>> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut visited = HashSet::<PathBuf>::new();
    let mut visiting = HashSet::<PathBuf>::new();
    match collect_parse_diagnostics_recursive(&canonical, &mut visited, &mut visiting)? {
        Some((failed_path, import_chain, diagnostics)) => Ok(diagnostics
            .into_iter()
            .map(|diagnostic| annotate_parse_diagnostic(diagnostic, &failed_path, &import_chain))
            .collect()),
        None => Ok(Vec::new()),
    }
}

type ParseDiagnosticsHit = (PathBuf, Vec<PathBuf>, Vec<diagnostics::Diagnostic>);

fn collect_parse_diagnostics_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    visiting: &mut HashSet<PathBuf>,
) -> Result<Option<ParseDiagnosticsHit>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if visited.contains(&canonical) || visiting.contains(&canonical) {
        return Ok(None);
    }
    visiting.insert(canonical.clone());
    let source = std::fs::read_to_string(&canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = match parser::parse(&source, module_name) {
        Ok(ast) => ast,
        Err(diagnostics) => {
            return Ok(Some((
                canonical.clone(),
                vec![canonical.clone()],
                diagnostics,
            )))
        }
    };
    visited.insert(canonical.clone());

    let base_dir = canonical
        .parent()
        .ok_or_else(|| anyhow!("module has no parent directory: {}", canonical.display()))?;
    for module_decl in &ast.modules {
        let module_path = resolve_declared_module(base_dir, module_decl).with_context(|| {
            format!(
                "while resolving module `{}` from {}",
                module_decl,
                canonical.display()
            )
        })?;
        if let Some((failed_path, mut import_chain, diagnostics)) =
            collect_parse_diagnostics_recursive(&module_path, visited, visiting)?
        {
            import_chain.insert(0, canonical.clone());
            return Ok(Some((failed_path, import_chain, diagnostics)));
        }
    }
    visiting.remove(&canonical);
    Ok(None)
}

fn annotate_parse_diagnostic(
    mut diagnostic: diagnostics::Diagnostic,
    module_path: &Path,
    import_chain: &[PathBuf],
) -> diagnostics::Diagnostic {
    diagnostic.path = Some(module_path.display().to_string());
    let mut help = diagnostic.help.unwrap_or_default();
    if !help.is_empty() {
        help.push(' ');
    }
    help.push_str(&format!("source: {}", module_path.display()));
    if import_chain.len() > 1 {
        let chain = import_chain
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        if !help.is_empty() {
            help.push(' ');
        }
        help.push_str(&format!("import chain: {chain}"));
        diagnostic.notes.push(format!("import chain: {chain}"));
    }
    diagnostic.help = Some(help);
    diagnostic
}

fn render_parse_failure(path: &Path, diagnostics: &[diagnostics::Diagnostic]) -> String {
    let mut summary = format!(
        "parse failed for {} with {} diagnostics",
        path.display(),
        diagnostics.len()
    );
    if diagnostics.is_empty() {
        return summary;
    }
    let details = diagnostics
        .iter()
        .map(|diagnostic| {
            if let Some(span) = &diagnostic.span {
                format!(
                    "{}:{}-{}:{} {}",
                    span.start_line,
                    span.start_col,
                    span.end_line,
                    span.end_col,
                    diagnostic.message
                )
            } else {
                diagnostic.message.clone()
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    summary.push_str(": ");
    summary.push_str(&details);
    summary
}

fn enrich_diagnostics_context(diagnostics: &mut [diagnostics::Diagnostic]) {
    let mut source_cache = HashMap::<String, Vec<String>>::new();
    for diagnostic in diagnostics {
        if let Some(path) = &diagnostic.path {
            let lines = if let Some(lines) = source_cache.get(path) {
                lines
            } else if let Ok(source) = std::fs::read_to_string(path) {
                source_cache.insert(
                    path.clone(),
                    source.lines().map(ToString::to_string).collect::<Vec<_>>(),
                );
                source_cache
                    .get(path)
                    .expect("inserted path is retrievable")
            } else {
                continue;
            };
            if let Some(span) = &diagnostic.span {
                if span.start_line > 0
                    && span.start_line <= lines.len()
                    && diagnostic.snippet.is_none()
                {
                    diagnostic.snippet = Some(lines[span.start_line - 1].clone());
                }
                if diagnostic.labels.is_empty() {
                    diagnostic.labels.push(diagnostics::Label {
                        message: diagnostic.message.clone(),
                        primary: true,
                        span: Some(span.clone()),
                    });
                }
            } else if let Some(anchors) = derive_anchors_from_message(&diagnostic.message, lines) {
                if let Some((primary_token, primary_span)) = anchors.first() {
                    diagnostic.span = Some(primary_span.clone());
                    diagnostic.snippet = Some(lines[primary_span.start_line - 1].clone());
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("while analyzing `{primary_token}`"),
                        primary: true,
                        span: Some(primary_span.clone()),
                    });
                }
                for (token, span) in anchors.iter().skip(1) {
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("related context `{token}`"),
                        primary: false,
                        span: Some(span.clone()),
                    });
                }
                diagnostic.notes.push(
                    "source anchors derived from diagnostic evidence when explicit semantic spans are unavailable"
                        .to_string(),
                );
            }
        }
    }
}

fn derive_anchors_from_message(
    message: &str,
    lines: &[String],
) -> Option<Vec<(String, diagnostics::Span)>> {
    let quoted = extract_backticked_tokens(message);
    let mut out = Vec::new();
    for token in quoted {
        if token.trim().is_empty() {
            continue;
        }
        if let Some(span) = find_token_span(lines, &token) {
            out.push((token, span));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_backticked_tokens(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (idx, ch) in message.char_indices() {
        if ch == '`' {
            if let Some(open) = start.take() {
                if idx > open + 1 {
                    out.push(message[open + 1..idx].to_string());
                }
            } else {
                start = Some(idx);
            }
        }
    }
    out
}

fn find_token_span(lines: &[String], token: &str) -> Option<diagnostics::Span> {
    for (line_idx, line) in lines.iter().enumerate() {
        if let Some(col_idx) = line.find(token) {
            return Some(diagnostics::Span {
                start_line: line_idx + 1,
                start_col: col_idx + 1,
                end_line: line_idx + 1,
                end_col: col_idx + token.len().max(1),
            });
        }
    }
    None
}

fn resolve_declared_module(base_dir: &Path, module_decl: &str) -> Result<PathBuf> {
    let normalized = module_decl.trim().replace("::", "/");
    if normalized.is_empty() {
        return Err(anyhow!("empty module declaration"));
    }
    if normalized
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '/'))
    {
        return Err(anyhow!(
            "invalid module declaration `{}` (allowed: [A-Za-z0-9_::])",
            module_decl
        ));
    }

    let file_candidate = base_dir.join(format!("{normalized}.fzy"));
    if file_candidate.is_file() {
        return Ok(file_candidate);
    }
    let mod_candidate = base_dir.join(&normalized).join("mod.fzy");
    if mod_candidate.is_file() {
        return Ok(mod_candidate);
    }
    Err(anyhow!(
        "module `{}` not found; expected {} or {}",
        module_decl,
        file_candidate.display(),
        mod_candidate.display()
    ))
}

fn merge_module_owned(root: &mut ast::Module, mut module: ast::Module) {
    root.items.append(&mut module.items);
    root.modules.append(&mut module.modules);
    root.imports.append(&mut module.imports);
    root.capabilities.append(&mut module.capabilities);
    root.host_syscall_sites += module.host_syscall_sites;
    root.unsafe_reasoned_sites += module.unsafe_reasoned_sites;
}

fn format_module_cycle(stack: &[PathBuf], repeated: &Path) -> String {
    if let Some(start) = stack.iter().position(|entry| entry == repeated) {
        let mut parts = stack[start..]
            .iter()
            .map(|entry| entry.display().to_string())
            .collect::<Vec<_>>();
        parts.push(repeated.display().to_string());
        return parts.join(" -> ");
    }
    repeated.display().to_string()
}

#[derive(Debug, Clone, Copy)]
enum BackendKind {
    Llvm,
    Cranelift,
}

type CfgBlockId = usize;

#[derive(Debug, Clone)]
struct ControlFlowCfg {
    entry: CfgBlockId,
    blocks: Vec<ControlFlowBlock>,
    loops: Vec<ControlFlowLoop>,
}

#[derive(Debug, Clone)]
struct ControlFlowLoop {
    id: usize,
    break_target: CfgBlockId,
    continue_target: CfgBlockId,
}

#[derive(Debug, Clone)]
struct ControlFlowBlock {
    stmts: Vec<ast::Stmt>,
    terminator: ControlFlowTerminator,
}

#[derive(Debug, Clone)]
enum ControlFlowTerminator {
    Return(Option<ast::Expr>),
    Jump {
        target: CfgBlockId,
        edge: ControlFlowEdge,
    },
    Branch {
        condition: ast::Expr,
        then_target: CfgBlockId,
        else_target: CfgBlockId,
    },
    Switch {
        scrutinee: ast::Expr,
        cases: Vec<(i32, CfgBlockId)>,
        default_target: CfgBlockId,
    },
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlFlowEdge {
    Normal,
    LoopBack { loop_id: usize },
    Break { loop_id: usize },
    Continue { loop_id: usize },
}

#[derive(Clone, Copy)]
struct ActiveLoop {
    id: usize,
    break_target: CfgBlockId,
    continue_target: CfgBlockId,
}

#[derive(Clone)]
struct CfgBuildBlock {
    stmts: Vec<ast::Stmt>,
    terminator: Option<ControlFlowTerminator>,
}

struct ControlFlowBuilder {
    blocks: Vec<CfgBuildBlock>,
    loops: Vec<ControlFlowLoop>,
    active_loops: Vec<ActiveLoop>,
    next_loop_id: usize,
    next_temp: usize,
    variant_tags: HashMap<String, i32>,
    passthrough_functions: HashMap<String, usize>,
    known_pattern_values: HashMap<String, ast::Expr>,
}

impl ControlFlowBuilder {
    fn new(
        variant_tags: HashMap<String, i32>,
        passthrough_functions: HashMap<String, usize>,
    ) -> Self {
        Self {
            blocks: vec![CfgBuildBlock {
                stmts: Vec::new(),
                terminator: None,
            }],
            loops: Vec::new(),
            active_loops: Vec::new(),
            next_loop_id: 0,
            next_temp: 0,
            variant_tags,
            passthrough_functions,
            known_pattern_values: HashMap::new(),
        }
    }

    fn new_block(&mut self) -> CfgBlockId {
        let id = self.blocks.len();
        self.blocks.push(CfgBuildBlock {
            stmts: Vec::new(),
            terminator: None,
        });
        id
    }

    fn append_stmt(&mut self, block: CfgBlockId, stmt: ast::Stmt) -> Result<()> {
        let current = self
            .blocks
            .get_mut(block)
            .ok_or_else(|| anyhow!("control-flow builder referenced missing block {}", block))?;
        if current.terminator.is_some() {
            bail!("control-flow builder attempted to append into terminated block {block}");
        }
        current.stmts.push(stmt);
        Ok(())
    }

    fn terminate(&mut self, block: CfgBlockId, terminator: ControlFlowTerminator) -> Result<()> {
        let current = self
            .blocks
            .get_mut(block)
            .ok_or_else(|| anyhow!("control-flow builder referenced missing block {}", block))?;
        if current.terminator.is_some() {
            bail!("control-flow builder attempted to re-terminate block {block}");
        }
        current.terminator = Some(terminator);
        Ok(())
    }

    fn next_temp_name(&mut self, prefix: &str) -> String {
        let name = format!("__cfg_{prefix}_{}", self.next_temp);
        self.next_temp += 1;
        name
    }

    fn lower_stmt_seq(
        &mut self,
        mut current: CfgBlockId,
        body: &[ast::Stmt],
    ) -> Result<Option<CfgBlockId>> {
        for stmt in body {
            match stmt {
                ast::Stmt::Let {
                    name,
                    mutable,
                    ty,
                    value,
                } => {
                    if let Some(resolved) = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    ) {
                        self.known_pattern_values.insert(name.clone(), resolved);
                    } else {
                        self.known_pattern_values.remove(name);
                    }
                    self.append_stmt(
                        current,
                        ast::Stmt::Let {
                            name: name.clone(),
                            mutable: *mutable,
                            ty: ty.clone(),
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::LetPattern {
                    pattern,
                    value,
                    mutable,
                    ty,
                } => {
                    let resolved = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    )
                    .unwrap_or_else(|| value.clone());
                    self.append_stmt(
                        current,
                        ast::Stmt::LetPattern {
                            pattern: pattern.clone(),
                            value: resolved,
                            mutable: *mutable,
                            ty: ty.clone(),
                        },
                    )?;
                }
                ast::Stmt::Assign { target, value } => {
                    if let Some(resolved) = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    ) {
                        self.known_pattern_values.insert(target.clone(), resolved);
                    } else {
                        self.known_pattern_values.remove(target);
                    }
                    self.append_stmt(
                        current,
                        ast::Stmt::Assign {
                            target: target.clone(),
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::CompoundAssign { target, op, value } => {
                    self.known_pattern_values.remove(target);
                    self.append_stmt(
                        current,
                        ast::Stmt::CompoundAssign {
                            target: target.clone(),
                            op: *op,
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::Defer(_)
                | ast::Stmt::Requires(_)
                | ast::Stmt::Ensures(_)
                | ast::Stmt::Expr(_) => {
                    self.append_stmt(current, stmt.clone())?;
                }
                ast::Stmt::Return(expr) => {
                    self.terminate(current, ControlFlowTerminator::Return(expr.clone()))?;
                    return Ok(None);
                }
                ast::Stmt::Break(_) => {
                    let active = self.active_loops.last().copied().ok_or_else(|| {
                        anyhow!("control-flow lowering encountered `break` outside loop scope")
                    })?;
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: active.break_target,
                            edge: ControlFlowEdge::Break { loop_id: active.id },
                        },
                    )?;
                    return Ok(None);
                }
                ast::Stmt::Continue => {
                    let active = self.active_loops.last().copied().ok_or_else(|| {
                        anyhow!("control-flow lowering encountered `continue` outside loop scope")
                    })?;
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: active.continue_target,
                            edge: ControlFlowEdge::Continue { loop_id: active.id },
                        },
                    )?;
                    return Ok(None);
                }
                ast::Stmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.known_pattern_values.clear();
                    let then_block = self.new_block();
                    let else_block = self.new_block();
                    self.terminate(
                        current,
                        ControlFlowTerminator::Branch {
                            condition: condition.clone(),
                            then_target: then_block,
                            else_target: else_block,
                        },
                    )?;
                    let then_tail = self.lower_stmt_seq(then_block, then_body)?;
                    let else_tail = self.lower_stmt_seq(else_block, else_body)?;
                    match (then_tail, else_tail) {
                        (None, None) => return Ok(None),
                        (then_tail, else_tail) => {
                            let cont = self.new_block();
                            if let Some(tail) = then_tail {
                                self.terminate(
                                    tail,
                                    ControlFlowTerminator::Jump {
                                        target: cont,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                            if let Some(tail) = else_tail {
                                self.terminate(
                                    tail,
                                    ControlFlowTerminator::Jump {
                                        target: cont,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                            current = cont;
                        }
                    }
                }
                ast::Stmt::While { condition, body } => {
                    self.known_pattern_values.clear();
                    let head = self.new_block();
                    let loop_body = self.new_block();
                    let exit = self.new_block();
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: head,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    self.terminate(
                        head,
                        ControlFlowTerminator::Branch {
                            condition: condition.clone(),
                            then_target: loop_body,
                            else_target: exit,
                        },
                    )?;
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: head,
                    });
                    let body_tail = self.lower_stmt_seq(loop_body, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    current = exit;
                }
                ast::Stmt::For {
                    init,
                    condition,
                    step,
                    body,
                } => {
                    self.known_pattern_values.clear();
                    if let Some(init) = init {
                        let Some(next) =
                            self.lower_stmt_seq(current, std::slice::from_ref(init.as_ref()))?
                        else {
                            return Ok(None);
                        };
                        current = next;
                    }
                    let head = self.new_block();
                    let loop_body = self.new_block();
                    let step_block = self.new_block();
                    let exit = self.new_block();
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: step_block,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    if let Some(condition) = condition {
                        self.terminate(
                            head,
                            ControlFlowTerminator::Branch {
                                condition: condition.clone(),
                                then_target: loop_body,
                                else_target: exit,
                            },
                        )?;
                    } else {
                        self.terminate(
                            head,
                            ControlFlowTerminator::Jump {
                                target: loop_body,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: step_block,
                    });
                    let body_tail = self.lower_stmt_seq(loop_body, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: step_block,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                    }
                    if let Some(step) = step {
                        if let Some(step_tail) =
                            self.lower_stmt_seq(step_block, std::slice::from_ref(step.as_ref()))?
                        {
                            self.terminate(
                                step_tail,
                                ControlFlowTerminator::Jump {
                                    target: head,
                                    edge: ControlFlowEdge::LoopBack { loop_id },
                                },
                            )?;
                        }
                    } else {
                        self.terminate(
                            step_block,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    current = exit;
                }
                ast::Stmt::ForIn {
                    binding,
                    iterable,
                    body,
                } => {
                    self.known_pattern_values.clear();
                    if let ast::Expr::Range {
                        start,
                        end,
                        inclusive,
                    } = iterable
                    {
                        self.append_stmt(
                            current,
                            ast::Stmt::Let {
                                name: binding.clone(),
                                mutable: true,
                                ty: Some(ast::Type::Int {
                                    signed: true,
                                    bits: 32,
                                }),
                                value: *start.clone(),
                            },
                        )?;
                        let head = self.new_block();
                        let loop_body = self.new_block();
                        let step_block = self.new_block();
                        let exit = self.new_block();
                        let loop_id = self.next_loop_id;
                        self.next_loop_id += 1;
                        self.loops.push(ControlFlowLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: step_block,
                        });
                        self.terminate(
                            current,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                        let cond_expr = ast::Expr::Binary {
                            op: if *inclusive {
                                ast::BinaryOp::Lte
                            } else {
                                ast::BinaryOp::Lt
                            },
                            left: Box::new(ast::Expr::Ident(binding.clone())),
                            right: Box::new(*end.clone()),
                        };
                        self.terminate(
                            head,
                            ControlFlowTerminator::Branch {
                                condition: cond_expr,
                                then_target: loop_body,
                                else_target: exit,
                            },
                        )?;
                        self.active_loops.push(ActiveLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: step_block,
                        });
                        let body_tail = self.lower_stmt_seq(loop_body, body)?;
                        let _ = self.active_loops.pop();
                        if let Some(tail) = body_tail {
                            self.terminate(
                                tail,
                                ControlFlowTerminator::Jump {
                                    target: step_block,
                                    edge: ControlFlowEdge::Normal,
                                },
                            )?;
                        }
                        let step_stmt = ast::Stmt::CompoundAssign {
                            target: binding.clone(),
                            op: ast::BinaryOp::Add,
                            value: ast::Expr::Int(1),
                        };
                        self.append_stmt(step_block, step_stmt)?;
                        self.terminate(
                            step_block,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                        current = exit;
                    } else {
                        let body_block = self.new_block();
                        let exit = self.new_block();
                        let loop_id = self.next_loop_id;
                        self.next_loop_id += 1;
                        self.loops.push(ControlFlowLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: exit,
                        });
                        self.terminate(
                            current,
                            ControlFlowTerminator::Jump {
                                target: body_block,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                        self.active_loops.push(ActiveLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: exit,
                        });
                        let body_tail = self.lower_stmt_seq(body_block, body)?;
                        let _ = self.active_loops.pop();
                        if let Some(tail) = body_tail {
                            self.terminate(
                                tail,
                                ControlFlowTerminator::Jump {
                                    target: exit,
                                    edge: ControlFlowEdge::Normal,
                                },
                            )?;
                        }
                        current = exit;
                    }
                }
                ast::Stmt::Loop { body } => {
                    self.known_pattern_values.clear();
                    let head = self.new_block();
                    let has_loop_break = body_contains_break_at_depth(body, 0);
                    let exit = if has_loop_break {
                        Some(self.new_block())
                    } else {
                        None
                    };
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit.unwrap_or(head),
                        continue_target: head,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit.unwrap_or(head),
                        continue_target: head,
                    });
                    let body_tail = self.lower_stmt_seq(head, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    if let Some(exit) = exit {
                        current = exit;
                    } else {
                        return Ok(None);
                    }
                }
                ast::Stmt::Match { scrutinee, arms } => {
                    let resolved_scrutinee = resolve_pattern_source_expr(
                        scrutinee,
                        &self.known_pattern_values,
                        &self.passthrough_functions,
                    )
                    .unwrap_or_else(|| scrutinee.clone());
                    if arms.is_empty() {
                        self.terminate(current, ControlFlowTerminator::Unreachable)?;
                        return Ok(None);
                    }
                    let scrutinee_name = self.next_temp_name("match");
                    self.append_stmt(
                        current,
                        ast::Stmt::Let {
                            name: scrutinee_name.clone(),
                            mutable: false,
                            ty: None,
                            value: resolved_scrutinee.clone(),
                        },
                    )?;
                    let all_returning = arms.iter().all(|arm| arm.returns);
                    let end_block = if all_returning {
                        None
                    } else {
                        Some(self.new_block())
                    };
                    let has_terminal_catchall = arms.last().is_some_and(|arm| {
                        arm.guard.is_none() && pattern_is_catchall(&arm.pattern)
                    });
                    let mut fallback_block = if let Some(end_block) = end_block {
                        end_block
                    } else if has_terminal_catchall {
                        usize::MAX
                    } else {
                        let unreachable_block = self.new_block();
                        self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                        unreachable_block
                    };
                    let mut switch_cases = Vec::<(i32, CfgBlockId)>::new();
                    let mut switch_default = fallback_block;
                    let mut switch_seen = HashSet::<i32>::new();
                    let mut switch_viable = true;
                    let mut arm_blocks = Vec::<CfgBlockId>::with_capacity(arms.len());
                    for (index, arm) in arms.iter().enumerate() {
                        let arm_block = self.new_block();
                        arm_blocks.push(arm_block);
                        if arm.guard.is_some() {
                            switch_viable = false;
                        } else if pattern_is_catchall(&arm.pattern) {
                            if index + 1 != arms.len() || switch_default != fallback_block {
                                switch_viable = false;
                            } else {
                                switch_default = arm_block;
                            }
                        } else if let Some(values) =
                            pattern_switch_values(&arm.pattern, &self.variant_tags)
                        {
                            for value in values {
                                if !switch_seen.insert(value) {
                                    switch_viable = false;
                                    break;
                                }
                                switch_cases.push((value, arm_block));
                            }
                        } else {
                            switch_viable = false;
                        }
                    }

                    if switch_viable && !switch_cases.is_empty() {
                        if switch_default == usize::MAX {
                            let unreachable_block = self.new_block();
                            self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                            switch_default = unreachable_block;
                        }
                        self.terminate(
                            current,
                            ControlFlowTerminator::Switch {
                                scrutinee: ast::Expr::Ident(scrutinee_name.clone()),
                                cases: switch_cases,
                                default_target: switch_default,
                            },
                        )?;
                        for (arm, arm_block) in arms.iter().zip(arm_blocks.iter().copied()) {
                            let binding_stmts = bindings_for_match_arm_pattern(
                                &arm.pattern,
                                &resolved_scrutinee,
                                &self.variant_tags,
                            )?;
                            for stmt in binding_stmts {
                                self.append_stmt(arm_block, stmt)?;
                            }
                            if arm.returns {
                                self.terminate(
                                    arm_block,
                                    ControlFlowTerminator::Return(Some(arm.value.clone())),
                                )?;
                            } else {
                                let end_block =
                                    end_block.expect("non-returning match must have end block");
                                self.append_stmt(arm_block, ast::Stmt::Expr(arm.value.clone()))?;
                                self.terminate(
                                    arm_block,
                                    ControlFlowTerminator::Jump {
                                        target: end_block,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                        }
                        if let Some(end_block) = end_block {
                            current = end_block;
                        } else {
                            return Ok(None);
                        }
                    } else {
                        if fallback_block == usize::MAX {
                            let unreachable_block = self.new_block();
                            self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                            fallback_block = unreachable_block;
                        }
                        let mut dispatch = current;
                        for (index, arm) in arms.iter().enumerate() {
                            let arm_block = arm_blocks[index];
                            let is_last = index + 1 == arms.len();
                            let else_block = if is_last {
                                fallback_block
                            } else {
                                self.new_block()
                            };
                            self.terminate(
                                dispatch,
                                ControlFlowTerminator::Branch {
                                    condition: pattern_to_expr(
                                        &scrutinee_name,
                                        &arm.pattern,
                                        &self.variant_tags,
                                    ),
                                    then_target: arm_block,
                                    else_target: else_block,
                                },
                            )?;
                            let binding_stmts = bindings_for_match_arm_pattern(
                                &arm.pattern,
                                &resolved_scrutinee,
                                &self.variant_tags,
                            )?;
                            for stmt in binding_stmts {
                                self.append_stmt(arm_block, stmt)?;
                            }
                            let value_block = if let Some(guard) = &arm.guard {
                                let guarded_value_block = self.new_block();
                                self.terminate(
                                    arm_block,
                                    ControlFlowTerminator::Branch {
                                        condition: guard.clone(),
                                        then_target: guarded_value_block,
                                        else_target: else_block,
                                    },
                                )?;
                                guarded_value_block
                            } else {
                                arm_block
                            };
                            if arm.returns {
                                self.terminate(
                                    value_block,
                                    ControlFlowTerminator::Return(Some(arm.value.clone())),
                                )?;
                            } else {
                                let end_block =
                                    end_block.expect("non-returning match must have end block");
                                self.append_stmt(
                                    value_block,
                                    ast::Stmt::Expr(arm.value.clone()),
                                )?;
                                self.terminate(
                                    value_block,
                                    ControlFlowTerminator::Jump {
                                        target: end_block,
                                        edge: ControlFlowEdge::Normal,
                                    },
                                )?;
                            }
                            dispatch = else_block;
                        }
                        if let Some(end_block) = end_block {
                            current = end_block;
                            self.known_pattern_values.clear();
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }
        }
        Ok(Some(current))
    }

    fn finish(mut self, body: &[ast::Stmt]) -> Result<ControlFlowCfg> {
        if let Some(tail) = self.lower_stmt_seq(0, body)? {
            self.terminate(tail, ControlFlowTerminator::Return(None))?;
        }
        let blocks = self
            .blocks
            .into_iter()
            .enumerate()
            .map(|(id, block)| {
                let terminator = block.terminator.ok_or_else(|| {
                    anyhow!("control-flow builder emitted block {id} without terminator")
                })?;
                Ok(ControlFlowBlock {
                    stmts: block.stmts,
                    terminator,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ControlFlowCfg {
            entry: 0,
            blocks,
            loops: self.loops,
        })
    }
}

fn build_control_flow_cfg(
    body: &[ast::Stmt],
    variant_tags: &HashMap<String, i32>,
    passthrough_functions: &HashMap<String, usize>,
) -> Result<ControlFlowCfg> {
    ControlFlowBuilder::new(variant_tags.clone(), passthrough_functions.clone()).finish(body)
}

fn body_contains_break_at_depth(body: &[ast::Stmt], depth: usize) -> bool {
    body.iter()
        .any(|stmt| stmt_contains_break_at_depth(stmt, depth))
}

fn stmt_contains_break_at_depth(stmt: &ast::Stmt, depth: usize) -> bool {
    match stmt {
        ast::Stmt::Break(_) => depth == 0,
        ast::Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_contains_break_at_depth(then_body, depth)
                || body_contains_break_at_depth(else_body, depth)
        }
        ast::Stmt::While { body, .. }
        | ast::Stmt::For { body, .. }
        | ast::Stmt::ForIn { body, .. }
        | ast::Stmt::Loop { body } => body_contains_break_at_depth(body, depth + 1),
        ast::Stmt::Match { .. }
        | ast::Stmt::Continue
        | ast::Stmt::Return(_)
        | ast::Stmt::Defer(_)
        | ast::Stmt::Requires(_)
        | ast::Stmt::Ensures(_)
        | ast::Stmt::Expr(_)
        | ast::Stmt::Let { .. }
        | ast::Stmt::LetPattern { .. }
        | ast::Stmt::Assign { .. }
        | ast::Stmt::CompoundAssign { .. } => false,
    }
}

fn pattern_to_expr(
    scrutinee_name: &str,
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> ast::Expr {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => ast::Expr::Bool(true),
        ast::Pattern::Int(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Int(*value)),
        },
        ast::Pattern::Bool(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Bool(*value)),
        },
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            ast::Expr::Binary {
                op: ast::BinaryOp::Eq,
                left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
                right: Box::new(ast::Expr::Int(
                    variant_tag_for_key(&key, variant_tags) as i128
                )),
            }
        }
        ast::Pattern::Struct { .. } => ast::Expr::Bool(true),
        ast::Pattern::Or(patterns) => {
            let mut iter = patterns.iter();
            let first = iter
                .next()
                .map(|pattern| pattern_to_expr(scrutinee_name, pattern, variant_tags))
                .unwrap_or(ast::Expr::Bool(true));
            iter.fold(first, |acc, pattern| ast::Expr::Binary {
                op: ast::BinaryOp::Or,
                left: Box::new(acc),
                right: Box::new(pattern_to_expr(scrutinee_name, pattern, variant_tags)),
            })
        }
    }
}

fn pattern_is_catchall(pattern: &ast::Pattern) -> bool {
    matches!(pattern, ast::Pattern::Wildcard | ast::Pattern::Ident(_))
}

fn pattern_switch_values(
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> Option<Vec<i32>> {
    match pattern {
        ast::Pattern::Int(value) => i32::try_from(*value).ok().map(|v| vec![v]),
        ast::Pattern::Bool(value) => Some(vec![if *value { 1 } else { 0 }]),
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            Some(vec![variant_tag_for_key(&key, variant_tags)])
        }
        ast::Pattern::Or(patterns) => {
            let mut out = Vec::new();
            for pattern in patterns {
                let mut values = pattern_switch_values(pattern, variant_tags)?;
                out.append(&mut values);
            }
            Some(out)
        }
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) | ast::Pattern::Struct { .. } => None,
    }
}

fn pattern_has_variant_payload_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Variant { bindings, .. } => !bindings.is_empty(),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_variant_payload_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Struct { .. }
        | ast::Pattern::Ident(_) => false,
    }
}

fn pattern_has_struct_field_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Struct { fields, .. } => fields.iter().any(|(_, binding)| binding != "_"),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_struct_field_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_)
        | ast::Pattern::Variant { .. } => false,
    }
}

fn pattern_matches_resolved_scrutinee(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> bool {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => true,
        ast::Pattern::Int(expected) => matches!(scrutinee, ast::Expr::Int(actual) if actual == expected),
        ast::Pattern::Bool(expected) => {
            matches!(scrutinee, ast::Expr::Bool(actual) if actual == expected)
        }
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                ..
            } = scrutinee
            {
                value_enum == enum_name && value_variant == variant
            } else if let ast::Expr::Int(value) = scrutinee {
                i32::try_from(*value).ok().is_some_and(|actual| {
                    let key = format!("{enum_name}::{variant}");
                    actual == variant_tag_for_key(&key, variant_tags)
                })
            } else {
                false
            }
        }
        ast::Pattern::Struct { name, .. } => matches!(
            scrutinee,
            ast::Expr::StructInit {
                name: value_name,
                ..
            } if value_name == name
        ),
        ast::Pattern::Or(patterns) => patterns
            .iter()
            .any(|pattern| pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags)),
    }
}

fn resolve_pattern_source_expr(
    expr: &ast::Expr,
    known_values: &HashMap<String, ast::Expr>,
    passthrough_functions: &HashMap<String, usize>,
) -> Option<ast::Expr> {
    fn resolve_inner(
        expr: &ast::Expr,
        known_values: &HashMap<String, ast::Expr>,
        passthrough_functions: &HashMap<String, usize>,
        depth: usize,
    ) -> Option<ast::Expr> {
        if depth > 32 {
            return None;
        }
        match expr {
            ast::Expr::EnumInit { .. } | ast::Expr::StructInit { .. } => Some(expr.clone()),
            ast::Expr::Group(inner) => {
                resolve_inner(inner, known_values, passthrough_functions, depth + 1)
            }
            ast::Expr::Ident(name) => known_values
                .get(name)
                .and_then(|value| resolve_inner(value, known_values, passthrough_functions, depth + 1)),
            ast::Expr::Call { callee, args } => {
                if let Some(index) = passthrough_functions.get(callee).copied() {
                    let arg = args.get(index)?;
                    resolve_inner(arg, known_values, passthrough_functions, depth + 1)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    resolve_inner(expr, known_values, passthrough_functions, 0)
}

fn resolve_field_expr(base: &ast::Expr, field: &str) -> Option<ast::Expr> {
    match base {
        ast::Expr::StructInit { fields, .. } => fields
            .iter()
            .find_map(|(name, value)| if name == field { Some(value.clone()) } else { None }),
        ast::Expr::Range {
            start,
            end,
            inclusive,
        } => match field {
            "start" => Some((**start).clone()),
            "end" => Some((**end).clone()),
            "inclusive" => Some(ast::Expr::Bool(*inclusive)),
            _ => None,
        },
        ast::Expr::FieldAccess { base, field: lhs } => {
            let resolved_base = resolve_field_expr(base, lhs)?;
            resolve_field_expr(&resolved_base, field)
        }
        ast::Expr::Group(inner) => resolve_field_expr(inner, field),
        _ => None,
    }
}

fn bindings_for_match_arm_pattern(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> Result<Vec<ast::Stmt>> {
    match pattern {
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
        } => {
            if bindings.is_empty() {
                return Ok(Vec::new());
            }
            let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
            } = scrutinee
            else {
                bail!(
                    "native backend requires literal enum scrutinee for match-arm payload bindings"
                );
            };
            if value_enum != enum_name
                || value_variant != variant
                || payload.len() != bindings.len()
            {
                bail!(
                    "native backend requires exact literal enum variant match for payload bindings"
                );
            }
            let mut stmts = Vec::with_capacity(bindings.len());
            for (name, value) in bindings.iter().zip(payload.iter()) {
                stmts.push(ast::Stmt::Let {
                    name: name.clone(),
                    mutable: false,
                    ty: None,
                    value: value.clone(),
                });
            }
            Ok(stmts)
        }
        ast::Pattern::Struct { name, fields } => {
            let binding_fields = fields
                .iter()
                .filter(|(_, binding)| binding != "_")
                .collect::<Vec<_>>();
            if binding_fields.is_empty() {
                return Ok(Vec::new());
            }
            let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = scrutinee
            else {
                bail!(
                    "native backend requires literal struct scrutinee for match-arm struct bindings"
                );
            };
            if value_name != name {
                bail!(
                    "native backend requires exact literal struct type match for struct bindings"
                );
            }
            let mut stmts = Vec::with_capacity(binding_fields.len());
            for (field_name, binding_name) in binding_fields {
                let Some((_, field_expr)) =
                    value_fields.iter().find(|(field, _)| field == field_name)
                else {
                    bail!("native backend requires struct literal fields to cover every bound pattern field");
                };
                stmts.push(ast::Stmt::Let {
                    name: binding_name.clone(),
                    mutable: false,
                    ty: None,
                    value: field_expr.clone(),
                });
            }
            Ok(stmts)
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns
                .iter()
                .find(|pattern| pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags))
            {
                return bindings_for_match_arm_pattern(matched, scrutinee, variant_tags);
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable scrutinee for payload or struct-field bindings within or-pattern match arms"
                );
            }
            Ok(Vec::new())
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_) => Ok(Vec::new()),
    }
}

fn verify_control_flow_cfg(cfg: &ControlFlowCfg) -> Result<()> {
    if cfg.blocks.is_empty() {
        bail!("control-flow cfg must include at least one block");
    }
    if cfg.entry >= cfg.blocks.len() {
        bail!(
            "control-flow cfg entry {} out of range (blocks={})",
            cfg.entry,
            cfg.blocks.len()
        );
    }
    let loop_map = cfg
        .loops
        .iter()
        .map(|loop_cfg| (loop_cfg.id, loop_cfg))
        .collect::<HashMap<_, _>>();
    let mut reachable = vec![false; cfg.blocks.len()];
    let mut stack = vec![cfg.entry];
    while let Some(block_id) = stack.pop() {
        if reachable[block_id] {
            continue;
        }
        reachable[block_id] = true;
        match &cfg.blocks[block_id].terminator {
            ControlFlowTerminator::Return(_) | ControlFlowTerminator::Unreachable => {}
            ControlFlowTerminator::Jump { target, edge } => {
                if *target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} jumps to invalid target {}",
                        block_id,
                        target
                    );
                }
                match edge {
                    ControlFlowEdge::Break { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown break loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.break_target != *target {
                            bail!(
                                "control-flow cfg block {} break edge target {} does not match loop {} break target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.break_target
                            );
                        }
                    }
                    ControlFlowEdge::Continue { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown continue loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.continue_target != *target {
                            bail!(
                                "control-flow cfg block {} continue edge target {} does not match loop {} continue target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.continue_target
                            );
                        }
                    }
                    ControlFlowEdge::Normal | ControlFlowEdge::LoopBack { .. } => {}
                }
                stack.push(*target);
            }
            ControlFlowTerminator::Branch {
                then_target,
                else_target,
                ..
            } => {
                if *then_target >= cfg.blocks.len() || *else_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid branch targets ({}, {})",
                        block_id,
                        then_target,
                        else_target
                    );
                }
                stack.push(*then_target);
                stack.push(*else_target);
            }
            ControlFlowTerminator::Switch {
                cases,
                default_target,
                ..
            } => {
                if *default_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid switch default target {}",
                        block_id,
                        default_target
                    );
                }
                for (_, target) in cases {
                    if *target >= cfg.blocks.len() {
                        bail!(
                            "control-flow cfg block {} has invalid switch case target {}",
                            block_id,
                            target
                        );
                    }
                }
                stack.push(*default_target);
                for (_, target) in cases {
                    stack.push(*target);
                }
            }
        }
    }
    for (index, is_reachable) in reachable.iter().enumerate() {
        if !is_reachable {
            bail!(
                "control-flow cfg contains unreachable declared block {}",
                index
            );
        }
    }
    Ok(())
}

fn lower_backend_ir(fir: &fir::FirModule, backend: BackendKind) -> Result<String> {
    match backend {
        BackendKind::Llvm => lower_llvm_ir(fir, true),
        BackendKind::Cranelift => lower_cranelift_ir(fir, true),
    }
}

#[derive(Clone)]
struct NativeCanonicalPlan {
    forced_main_return: Option<i32>,
    string_literal_ids: HashMap<String, i32>,
    global_const_i32: HashMap<String, i32>,
    variant_tags: HashMap<String, i32>,
    mutable_static_i32: HashMap<String, i32>,
    task_ref_ids: HashMap<String, i32>,
    cfg_by_function: HashMap<String, Result<ControlFlowCfg, String>>,
    data_ops_by_function: HashMap<String, Vec<NativeDataOp>>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum NativeMemoryClass {
    Stack,
    Static,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum NativeAliasClass {
    LocalNoEscape,
    Escapes,
}

#[derive(Debug, Clone, Copy)]
enum NativeBoundsPolicy {
    Checked,
    ProvenInRange,
}

#[derive(Debug, Clone, Copy)]
enum NativeEffectBoundary {
    Local,
    CapabilityRuntimeImport,
}

#[derive(Debug, Clone)]
enum NativeDataOpKind {
    ArrayLiteral {
        binding: String,
        len: usize,
        element_bits: u16,
        element_align: u8,
        element_stride: u8,
        memory: NativeMemoryClass,
        alias: NativeAliasClass,
    },
    ArrayIndexLoad {
        binding: String,
        index: String,
        bounds: NativeBoundsPolicy,
    },
    StringViewCall {
        callee: String,
        foldable: bool,
        alias: NativeAliasClass,
    },
    RuntimeBoundaryCall {
        callee: String,
        arity: usize,
    },
}

#[derive(Debug, Clone)]
struct NativeDataOp {
    kind: NativeDataOpKind,
    effect_boundary: NativeEffectBoundary,
}

fn render_native_data_op(op: &NativeDataOp) -> String {
    match &op.kind {
        NativeDataOpKind::ArrayLiteral {
            binding,
            len,
            element_bits,
            element_align,
            element_stride,
            memory,
            alias,
        } => format!(
            "array.literal binding={binding} len={len} bits={element_bits} align={element_align} stride={element_stride} memory={memory:?} alias={alias:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::ArrayIndexLoad {
            binding,
            index,
            bounds,
        } => format!(
            "array.index.load binding={binding} index={index} bounds={bounds:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::StringViewCall {
            callee,
            foldable,
            alias,
        } => format!(
            "string.view.call callee={callee} foldable={foldable} alias={alias:?} boundary={:?}",
            op.effect_boundary
        ),
        NativeDataOpKind::RuntimeBoundaryCall { callee, arity } => format!(
            "runtime.boundary.call callee={callee} arity={arity} boundary={:?}",
            op.effect_boundary
        ),
    }
}

fn index_expr_shape(expr: &ast::Expr) -> String {
    match expr {
        ast::Expr::Int(value) => value.to_string(),
        ast::Expr::Ident(name) => name.clone(),
        ast::Expr::Group(inner) => index_expr_shape(inner),
        _ => "<expr>".to_string(),
    }
}

fn infer_array_element_layout(items: &[ast::Expr]) -> (u16, u8, u8) {
    let mut bits = 32u16;
    for item in items {
        if let ast::Expr::Int(value) = item {
            if *value < i128::from(i32::MIN) || *value > i128::from(i32::MAX) {
                bits = bits.max(64);
            }
        }
    }
    let stride = if bits <= 8 {
        1
    } else if bits <= 16 {
        2
    } else if bits <= 32 {
        4
    } else {
        8
    };
    (bits, stride, stride)
}

fn collect_native_data_ops_from_expr(
    expr: &ast::Expr,
    array_lengths: &HashMap<String, usize>,
    const_strings: &HashMap<String, String>,
    out: &mut Vec<NativeDataOp>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(import) = native_runtime_import_for_callee(callee) {
                out.push(NativeDataOp {
                    kind: NativeDataOpKind::RuntimeBoundaryCall {
                        callee: callee.clone(),
                        arity: import.arity,
                    },
                    effect_boundary: NativeEffectBoundary::CapabilityRuntimeImport,
                });
            } else if is_native_data_plane_string_call(callee) {
                let foldable = eval_const_i32_call(callee, args, const_strings).is_some()
                    || eval_const_string_call(callee, args, const_strings).is_some();
                out.push(NativeDataOp {
                    kind: NativeDataOpKind::StringViewCall {
                        callee: callee.clone(),
                        foldable,
                        alias: NativeAliasClass::LocalNoEscape,
                    },
                    effect_boundary: NativeEffectBoundary::Local,
                });
            }
            for arg in args {
                collect_native_data_ops_from_expr(arg, array_lengths, const_strings, out);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::Index { base, index } => {
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(len) = array_lengths.get(name) {
                    let bounds = match index.as_ref() {
                        ast::Expr::Int(value) => usize::try_from(*value)
                            .ok()
                            .filter(|idx| idx < len)
                            .map(|_| NativeBoundsPolicy::ProvenInRange)
                            .unwrap_or(NativeBoundsPolicy::Checked),
                        _ => NativeBoundsPolicy::Checked,
                    };
                    out.push(NativeDataOp {
                        kind: NativeDataOpKind::ArrayIndexLoad {
                            binding: name.clone(),
                            index: index_expr_shape(index),
                            bounds,
                        },
                        effect_boundary: NativeEffectBoundary::Local,
                    });
                }
            }
            collect_native_data_ops_from_expr(base, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(index, array_lengths, const_strings, out);
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_native_data_ops_from_expr(base, array_lengths, const_strings, out)
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } | ast::Expr::ArrayLiteral(payload) => {
            for value in payload {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
        }
        ast::Expr::Closure { body, .. }
        | ast::Expr::Group(body)
        | ast::Expr::Await(body)
        | ast::Expr::Discard(body) => {
            collect_native_data_ops_from_expr(body, array_lengths, const_strings, out)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_native_data_ops_from_expr(try_expr, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(catch_expr, array_lengths, const_strings, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(then_expr, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(else_expr, array_lengths, const_strings, out);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_native_data_ops_from_expr(expr, array_lengths, const_strings, out)
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_native_data_ops_from_expr(left, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(right, array_lengths, const_strings, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_native_data_ops_from_expr(start, array_lengths, const_strings, out);
            collect_native_data_ops_from_expr(end, array_lengths, const_strings, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn collect_native_data_ops_for_function(function: &hir::TypedFunction) -> Vec<NativeDataOp> {
    let mut out = Vec::new();
    let mut array_lengths = HashMap::<String, usize>::new();
    let mut const_strings = HashMap::<String, String>::new();

    fn walk_stmt(
        stmt: &ast::Stmt,
        array_lengths: &mut HashMap<String, usize>,
        const_strings: &mut HashMap<String, String>,
        out: &mut Vec<NativeDataOp>,
    ) {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                match value {
                    ast::Expr::ArrayLiteral(items) => {
                        let (bits, align, stride) = infer_array_element_layout(items);
                        array_lengths.insert(name.clone(), items.len());
                        out.push(NativeDataOp {
                            kind: NativeDataOpKind::ArrayLiteral {
                                binding: name.clone(),
                                len: items.len(),
                                element_bits: bits,
                                element_align: align,
                                element_stride: stride,
                                memory: NativeMemoryClass::Stack,
                                alias: NativeAliasClass::LocalNoEscape,
                            },
                            effect_boundary: NativeEffectBoundary::Local,
                        });
                    }
                    ast::Expr::Str(value) => {
                        const_strings.insert(name.clone(), value.clone());
                    }
                    _ => {
                        const_strings.remove(name);
                    }
                }
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Assign { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => {
                collect_native_data_ops_from_expr(value, array_lengths, const_strings, out)
            }
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    collect_native_data_ops_from_expr(value, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
                for stmt in then_body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
                for stmt in else_body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::While { condition, body } => {
                collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    walk_stmt(init, array_lengths, const_strings, out);
                }
                if let Some(condition) = condition {
                    collect_native_data_ops_from_expr(condition, array_lengths, const_strings, out);
                }
                if let Some(step) = step {
                    walk_stmt(step, array_lengths, const_strings, out);
                }
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                collect_native_data_ops_from_expr(iterable, array_lengths, const_strings, out);
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::Loop { body } => {
                for stmt in body {
                    walk_stmt(stmt, array_lengths, const_strings, out);
                }
            }
            ast::Stmt::Match { scrutinee, arms } => {
                collect_native_data_ops_from_expr(scrutinee, array_lengths, const_strings, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_native_data_ops_from_expr(guard, array_lengths, const_strings, out);
                    }
                    collect_native_data_ops_from_expr(
                        &arm.value,
                        array_lengths,
                        const_strings,
                        out,
                    );
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }

    for stmt in &function.body {
        walk_stmt(stmt, &mut array_lengths, &mut const_strings, &mut out);
    }
    out
}

fn compute_forced_main_return(fir: &fir::FirModule, enforce_contract_checks: bool) -> Option<i32> {
    if !enforce_contract_checks {
        return None;
    }
    if fir
        .entry_requires
        .iter()
        .any(|condition| matches!(condition, Some(false)))
    {
        Some(120)
    } else if fir
        .entry_ensures
        .iter()
        .any(|condition| matches!(condition, Some(false)))
    {
        Some(121)
    } else {
        None
    }
}

fn build_native_cfg_map(
    fir: &fir::FirModule,
    variant_tags: &HashMap<String, i32>,
) -> HashMap<String, Result<ControlFlowCfg, String>> {
    let passthrough_functions = collect_passthrough_function_map_from_typed(&fir.typed_functions);
    fir.typed_functions
        .par_iter()
        .filter(|function| !is_extern_c_import_decl(function))
        .map(|function| {
            let cfg = build_control_flow_cfg(&function.body, variant_tags, &passthrough_functions)
                .and_then(|cfg| {
                verify_control_flow_cfg(&cfg)?;
                Ok(cfg)
            });
            (function.name.clone(), cfg.map_err(|error| error.to_string()))
        })
        .collect()
}

fn build_native_canonical_plan(
    fir: &fir::FirModule,
    enforce_contract_checks: bool,
) -> NativeCanonicalPlan {
    ensure_codegen_pool_configured();
    let variant_tags = build_variant_tag_map(fir);
    let cfg_by_function = build_native_cfg_map(fir, &variant_tags);
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let mut task_ref_ids = HashMap::<String, i32>::new();
    for (index, symbol) in spawn_task_symbols.iter().enumerate() {
        task_ref_ids.insert(symbol.clone(), (index + 1) as i32);
    }
    NativeCanonicalPlan {
        forced_main_return: compute_forced_main_return(fir, enforce_contract_checks),
        string_literal_ids: build_string_literal_ids(&collect_native_string_literals(fir)),
        global_const_i32: build_global_const_i32_map(fir),
        mutable_static_i32: build_mutable_static_i32_map(fir),
        variant_tags,
        task_ref_ids,
        cfg_by_function,
        data_ops_by_function: fir
            .typed_functions
            .par_iter()
            .filter(|function| !is_extern_c_import_decl(function))
            .map(|function| {
                (
                    function.name.clone(),
                    collect_native_data_ops_for_function(function),
                )
            })
            .collect(),
    }
}

fn lower_llvm_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> Result<String> {
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);
    if fir.typed_functions.is_empty() {
        let ret = plan
            .forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return Ok(format!(
            "; ModuleID = '{name}'\ndefine i32 @main() {{\nentry:\n  ret i32 {ret}\n}}\n",
            name = fir.name
        ));
    }

    let mut out = format!("; ModuleID = '{}'\n", fir.name);
    let used_imports = collect_used_native_runtime_imports(fir);
    for import in &used_imports {
        let mut params = String::new();
        for index in 0..import.arity {
            if index > 0 {
                params.push_str(", ");
            }
            params.push_str("i32");
        }
        let _ = writeln!(&mut out, "declare i32 @{}({})", import.symbol, params);
    }
    let used_data_plane_imports = collect_used_native_data_plane_imports(fir);
    for import in &used_data_plane_imports {
        let mut params = String::new();
        for index in 0..import.arity {
            if index > 0 {
                params.push_str(", ");
            }
            params.push_str("i32");
        }
        let _ = writeln!(&mut out, "declare i32 @{}({})", import.symbol, params);
    }
    let extern_imports = collect_extern_c_imports(fir);
    for import in &extern_imports {
        let params = import
            .params
            .iter()
            .map(|_| "i32")
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(&mut out, "declare i32 @{}({})", import.name, params);
    }
    if !used_imports.is_empty() || !used_data_plane_imports.is_empty() || !extern_imports.is_empty()
    {
        out.push('\n');
    }
    let mut mutable_global_symbols = HashMap::<String, String>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in &mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(name);
        let _ = writeln!(&mut out, "@{symbol} = global i32 {value}");
        mutable_global_symbols.insert(name.clone(), symbol);
    }
    if !mutable_global_symbols.is_empty() {
        out.push('\n');
    }
    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        if let Some(data_ops) = plan.data_ops_by_function.get(&function.name) {
            for op in data_ops {
                let _ = writeln!(&mut out, "; canonical.dataop {}", render_native_data_op(op));
            }
        }
        let lowered = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => llvm_emit_function(
                function,
                plan.forced_main_return.filter(|_| function.name == "main"),
                &plan.global_const_i32,
                &plan.variant_tags,
                &mutable_global_symbols,
                &plan.string_literal_ids,
                &plan.task_ref_ids,
                cfg,
            )
            .map_err(|error| {
                anyhow!(
                    "llvm backend failed lowering canonical cfg for `{}`: {}",
                    function.name,
                    error
                )
            })?,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        out.push_str(&lowered);
        out.push('\n');
    }
    Ok(out)
}

fn native_mangle_symbol(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn lower_cranelift_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> Result<String> {
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);
    let mut out = String::new();
    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        if let Some(data_ops) = plan.data_ops_by_function.get(&function.name) {
            for op in data_ops {
                let _ = writeln!(&mut out, "; canonical.dataop {}", render_native_data_op(op));
            }
        }
        let _ = writeln!(
            &mut out,
            "function %{}() -> i32 {{",
            native_mangle_symbol(&function.name)
        );
        match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => {
                for (block_id, block) in cfg.blocks.iter().enumerate() {
                    let _ = writeln!(&mut out, "block{block_id}:");
                    for stmt in &block.stmts {
                        let _ = writeln!(&mut out, "  ; {:?}", stmt);
                    }
                    match &block.terminator {
                        ControlFlowTerminator::Return(Some(expr)) => {
                            let _ = writeln!(&mut out, "  return {:?}", expr);
                        }
                        ControlFlowTerminator::Return(None) => {
                            if function.name == "main" {
                                let fallback = plan
                                    .forced_main_return
                                    .or(fir.entry_return_const_i32)
                                    .unwrap_or(0);
                                let _ = writeln!(&mut out, "  return {}", fallback);
                            } else {
                                let _ = writeln!(&mut out, "  return 0");
                            }
                        }
                        ControlFlowTerminator::Jump { target, edge } => {
                            let _ = writeln!(&mut out, "  jump block{} ; {:?}", target, edge);
                        }
                        ControlFlowTerminator::Branch {
                            condition,
                            then_target,
                            else_target,
                        } => {
                            let _ = writeln!(
                                &mut out,
                                "  br {:?}, block{}, block{}",
                                condition, then_target, else_target
                            );
                        }
                        ControlFlowTerminator::Switch {
                            scrutinee,
                            cases,
                            default_target,
                        } => {
                            let rendered_cases = cases
                                .iter()
                                .map(|(value, target)| format!("{value}->block{target}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            let _ = writeln!(
                                &mut out,
                                "  switch {:?}, [{}], default=block{}",
                                scrutinee, rendered_cases, default_target
                            );
                        }
                        ControlFlowTerminator::Unreachable => {
                            let _ = writeln!(&mut out, "  trap");
                        }
                    }
                }
            }
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        }
        out.push_str("}\n\n");
    }
    if out.is_empty() {
        let fallback = plan
            .forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return Ok(format!(
            "function %main() -> i32 {{\nblock0:\n  return {fallback}\n}}\n"
        ));
    }
    Ok(out)
}

struct LlvmFuncCtx {
    next_value: usize,
    next_label: usize,
    slots: HashMap<String, String>,
    array_slots: HashMap<String, LlvmArrayBinding>,
    const_strings: HashMap<String, String>,
    closures: HashMap<String, LlvmClosureBinding>,
    globals: HashMap<String, i32>,
    variant_tags: HashMap<String, i32>,
    mutable_globals: HashMap<String, String>,
    code: String,
}

impl LlvmFuncCtx {
    fn new(
        globals: HashMap<String, i32>,
        variant_tags: HashMap<String, i32>,
        mutable_globals: HashMap<String, String>,
    ) -> Self {
        Self {
            next_value: 0,
            next_label: 0,
            slots: HashMap::new(),
            array_slots: HashMap::new(),
            const_strings: HashMap::new(),
            closures: HashMap::new(),
            globals,
            variant_tags,
            mutable_globals,
            code: String::new(),
        }
    }

    fn value(&mut self) -> String {
        let id = self.next_value;
        self.next_value += 1;
        format!("%v{id}")
    }

    fn label(&mut self, prefix: &str) -> String {
        let id = self.next_label;
        self.next_label += 1;
        format!("{prefix}.{id}")
    }
}

fn llvm_emit_function(
    function: &hir::TypedFunction,
    forced_return: Option<i32>,
    globals: &HashMap<String, i32>,
    variant_tags: &HashMap<String, i32>,
    mutable_globals: &HashMap<String, String>,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    cfg: &ControlFlowCfg,
) -> Result<String> {
    let params = function
        .params
        .iter()
        .enumerate()
        .map(|(i, _)| format!("i32 %arg{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut ctx = LlvmFuncCtx::new(
        globals.clone(),
        variant_tags.clone(),
        mutable_globals.clone(),
    );
    let mut out = format!(
        "define i32 @{}({params}) {{\nentry:\n",
        native_mangle_symbol(&function.name)
    );
    for (index, param) in function.params.iter().enumerate() {
        let slot = format!("%slot_{}", param.name);
        ctx.code.push_str(&format!(
            "  {slot} = alloca i32\n  store i32 %arg{index}, ptr {slot}\n"
        ));
        ctx.slots.insert(param.name.clone(), slot);
    }
    let labels = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(id, _)| (id, format!("bb{id}")))
        .collect::<HashMap<_, _>>();
    let entry = labels
        .get(&cfg.entry)
        .ok_or_else(|| anyhow!("missing llvm label for cfg entry block {}", cfg.entry))?;
    if cfg.entry != 0 {
        ctx.code.push_str(&format!("  br label %{entry}\n"));
    }
    for (block_id, block) in cfg.blocks.iter().enumerate() {
        let label = labels
            .get(&block_id)
            .ok_or_else(|| anyhow!("missing llvm label for cfg block {}", block_id))?;
        if !(block_id == cfg.entry && cfg.entry == 0) {
            ctx.code.push_str(&format!("{label}:\n"));
        }
        llvm_emit_linear_stmts(&block.stmts, &mut ctx, string_literal_ids, task_ref_ids)?;
        match &block.terminator {
            ControlFlowTerminator::Return(Some(expr)) => {
                let value = llvm_emit_expr(expr, &mut ctx, string_literal_ids, task_ref_ids);
                ctx.code.push_str(&format!("  ret i32 {value}\n"));
            }
            ControlFlowTerminator::Return(None) => {
                let fallback = forced_return.unwrap_or(0);
                ctx.code.push_str(&format!("  ret i32 {fallback}\n"));
            }
            ControlFlowTerminator::Jump { target, .. } => {
                let target_label = labels
                    .get(target)
                    .ok_or_else(|| anyhow!("missing llvm label for cfg jump target {target}"))?;
                ctx.code.push_str(&format!("  br label %{target_label}\n"));
            }
            ControlFlowTerminator::Branch {
                condition,
                then_target,
                else_target,
            } => {
                let cond = llvm_emit_expr(condition, &mut ctx, string_literal_ids, task_ref_ids);
                let pred = ctx.value();
                let then_label = labels.get(then_target).ok_or_else(|| {
                    anyhow!("missing llvm label for cfg branch target {}", then_target)
                })?;
                let else_label = labels.get(else_target).ok_or_else(|| {
                    anyhow!("missing llvm label for cfg branch target {}", else_target)
                })?;
                ctx.code.push_str(&format!(
                    "  {pred} = icmp ne i32 {cond}, 0\n  br i1 {pred}, label %{then_label}, label %{else_label}\n"
                ));
            }
            ControlFlowTerminator::Switch {
                scrutinee,
                cases,
                default_target,
            } => {
                let value = llvm_emit_expr(scrutinee, &mut ctx, string_literal_ids, task_ref_ids);
                let default_label = labels.get(default_target).ok_or_else(|| {
                    anyhow!(
                        "missing llvm label for cfg switch default target {}",
                        default_target
                    )
                })?;
                ctx.code
                    .push_str(&format!("  switch i32 {value}, label %{default_label} [\n"));
                for (case_value, target) in cases {
                    let target_label = labels.get(target).ok_or_else(|| {
                        anyhow!("missing llvm label for cfg switch target {}", target)
                    })?;
                    ctx.code
                        .push_str(&format!("    i32 {case_value}, label %{target_label}\n"));
                }
                ctx.code.push_str("  ]\n");
            }
            ControlFlowTerminator::Unreachable => {
                ctx.code.push_str("  unreachable\n");
            }
        }
    }
    out.push_str(&ctx.code);
    out.push_str("}\n");
    Ok(out)
}

fn llvm_snapshot_closure_captures(ctx: &mut LlvmFuncCtx) -> HashMap<String, String> {
    let visible = ctx.slots.clone();
    let mut captures = HashMap::new();
    for (name, slot) in visible {
        let loaded = ctx.value();
        ctx.code
            .push_str(&format!("  {loaded} = load i32, ptr {slot}\n"));
        let capture_slot = format!(
            "%slot_cap_{}_{}",
            native_mangle_symbol(&name),
            ctx.next_value
        );
        ctx.code.push_str(&format!(
            "  {capture_slot} = alloca i32\n  store i32 {loaded}, ptr {capture_slot}\n"
        ));
        captures.insert(name, capture_slot);
    }
    captures
}

fn llvm_restore_shadowed_slots(
    ctx: &mut LlvmFuncCtx,
    saved: HashMap<String, Option<String>>,
    inserted_names: HashSet<String>,
) {
    for (name, prior) in saved {
        if let Some(slot) = prior {
            ctx.slots.insert(name, slot);
        } else if inserted_names.contains(&name) {
            ctx.slots.remove(&name);
        }
    }
}

fn llvm_emit_inlined_closure_call(
    binding: LlvmClosureBinding,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> String {
    let mut saved = HashMap::<String, Option<String>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture_slot) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), ctx.slots.get(name).cloned());
        }
        ctx.slots.insert(name.clone(), capture_slot.clone());
        inserted.insert(name.clone());
    }

    for (index, param) in binding.params.iter().enumerate() {
        let arg = args.get(index).cloned().unwrap_or(ast::Expr::Int(0));
        let rendered = llvm_emit_expr(&arg, ctx, string_literal_ids, task_ref_ids);
        let param_slot = format!(
            "%slot_closure_param_{}_{}",
            native_mangle_symbol(&param.name),
            ctx.next_value
        );
        ctx.code.push_str(&format!(
            "  {param_slot} = alloca i32\n  store i32 {rendered}, ptr {param_slot}\n"
        ));
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), ctx.slots.get(&param.name).cloned());
        }
        ctx.slots.insert(param.name.clone(), param_slot);
        inserted.insert(param.name.clone());
    }

    let mut value = llvm_emit_expr(&binding.body, ctx, string_literal_ids, task_ref_ids);
    if binding
        .return_type
        .as_ref()
        .is_some_and(|ty| *ty == ast::Type::Void)
    {
        value = "0".to_string();
    }
    llvm_restore_shadowed_slots(ctx, saved, inserted);
    value
}

fn llvm_emit_let_pattern(
    pattern: &ast::Pattern,
    value: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids);
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let slot = format!("%slot_{}_{}", native_mangle_symbol(name), ctx.next_value);
            ctx.code.push_str(&format!(
                "  {slot} = alloca i32\n  store i32 {rendered}, ptr {slot}\n"
            ));
            ctx.slots.insert(name.clone(), slot);
        }
        ast::Pattern::Int(expected) => {
            let cmp = ctx.value();
            ctx.code
                .push_str(&format!("  {cmp} = icmp eq i32 {rendered}, {expected}\n"));
        }
        ast::Pattern::Bool(expected) => {
            let cmp = ctx.value();
            let expected_i32 = if *expected { 1 } else { 0 };
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq i32 {rendered}, {expected_i32}\n"
            ));
        }
        ast::Pattern::Struct { name, fields } => {
            let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = value
            else {
                bail!("native backend requires literal struct initializer for `let` struct destructuring");
            };
            if value_name != name {
                bail!(
                    "native backend requires exact literal struct type match for `let` struct destructuring"
                );
            }
            for (field_name, binding_name) in fields {
                if binding_name == "_" {
                    continue;
                }
                let Some((_, field_expr)) =
                    value_fields.iter().find(|(field, _)| field == field_name)
                else {
                    bail!("native backend requires struct literal fields to cover every bound pattern field");
                };
                let field_value = llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids);
                let slot = format!(
                    "%slot_{}_{}",
                    native_mangle_symbol(binding_name),
                    ctx.next_value
                );
                ctx.code.push_str(&format!(
                    "  {slot} = alloca i32\n  store i32 {field_value}, ptr {slot}\n"
                ));
                ctx.slots.insert(binding_name.clone(), slot);
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
        } => {
            let key = format!("{enum_name}::{variant}");
            let tag = variant_tag_for_key(&key, &ctx.variant_tags);
            let cmp = ctx.value();
            ctx.code
                .push_str(&format!("  {cmp} = icmp eq i32 {rendered}, {tag}\n"));
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
            } = value
            {
                if value_enum == enum_name
                    && value_variant == variant
                    && payload.len() == bindings.len()
                {
                    for (binding_name, payload_expr) in bindings.iter().zip(payload.iter()) {
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids);
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.code.push_str(&format!(
                            "  {slot} = alloca i32\n  store i32 {payload_value}, ptr {slot}\n"
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns
                .iter()
                .find(|pattern| pattern_matches_resolved_scrutinee(pattern, value, &ctx.variant_tags))
            {
                return llvm_emit_let_pattern(
                    matched,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable initializer for payload or struct-field bindings in `let` or-patterns"
                );
            }
        }
    }
    Ok(())
}

fn llvm_emit_linear_stmts(
    body: &[ast::Stmt],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(name.clone(), const_value);
                    ctx.array_slots.remove(name);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let storage = format!("%slot_{}_arr_{}", name, ctx.next_value);
                    let len = items.len();
                    ctx.code
                        .push_str(&format!("  {storage} = alloca [{len} x i32]\n"));
                    for (idx, item) in items.iter().enumerate() {
                        let item_value =
                            llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids);
                        let element_ptr = ctx.value();
                        ctx.code.push_str(&format!(
                            "  {element_ptr} = getelementptr inbounds [{len} x i32], ptr {storage}, i32 0, i64 {idx}\n  store i32 {item_value}, ptr {element_ptr}\n"
                        ));
                    }
                    ctx.array_slots.insert(
                        name.clone(),
                        LlvmArrayBinding {
                            storage,
                            len,
                            element_bits: 32,
                            element_align: 4,
                            element_stride: 4,
                        },
                    );
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_binding) = ctx.array_slots.get(source).cloned() {
                        ctx.array_slots.insert(name.clone(), source_binding);
                        continue;
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    let captures = llvm_snapshot_closure_captures(ctx);
                    ctx.closures.insert(
                        name.clone(),
                        LlvmClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures,
                        },
                    );
                    continue;
                }
                let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids);
                let slot = format!("%slot_{}_{}", name, ctx.next_value);
                ctx.code.push_str(&format!(
                    "  {slot} = alloca i32\n  store i32 {rendered}, ptr {slot}\n"
                ));
                ctx.slots.insert(name.clone(), slot);
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids);
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.code.push_str(&format!(
                            "  {field_slot} = alloca i32\n  store i32 {field_value}, ptr {field_slot}\n"
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_value = llvm_emit_expr(start, ctx, string_literal_ids, task_ref_ids);
                    let end_value = llvm_emit_expr(end, ctx, string_literal_ids, task_ref_ids);
                    let inclusive_value = if *inclusive { "1" } else { "0" };
                    for (field, rendered) in [
                        ("start", start_value),
                        ("end", end_value),
                        ("inclusive", inclusive_value.to_string()),
                    ] {
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.code.push_str(&format!(
                            "  {field_slot} = alloca i32\n  store i32 {rendered}, ptr {field_slot}\n"
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                    }
                }
                ctx.array_slots.remove(name);
                ctx.const_strings.remove(name);
            }
            ast::Stmt::LetPattern { pattern, value, .. } => {
                llvm_emit_let_pattern(pattern, value, ctx, string_literal_ids, task_ref_ids)?;
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(target.clone(), const_value);
                    ctx.array_slots.remove(target);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let storage = format!("%slot_{}_arr_{}", target, ctx.next_value);
                    let len = items.len();
                    ctx.code
                        .push_str(&format!("  {storage} = alloca [{len} x i32]\n"));
                    for (idx, item) in items.iter().enumerate() {
                        let item_value =
                            llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids);
                        let element_ptr = ctx.value();
                        ctx.code.push_str(&format!(
                            "  {element_ptr} = getelementptr inbounds [{len} x i32], ptr {storage}, i32 0, i64 {idx}\n  store i32 {item_value}, ptr {element_ptr}\n"
                        ));
                    }
                    ctx.array_slots.insert(
                        target.clone(),
                        LlvmArrayBinding {
                            storage,
                            len,
                            element_bits: 32,
                            element_align: 4,
                            element_stride: 4,
                        },
                    );
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_binding) = ctx.array_slots.get(source).cloned() {
                        ctx.array_slots.insert(target.clone(), source_binding);
                        continue;
                    }
                }
                let rendered_value = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids);
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    let captures = llvm_snapshot_closure_captures(ctx);
                    ctx.closures.insert(
                        target.clone(),
                        LlvmClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures,
                        },
                    );
                    continue;
                }
                if let Some(symbol) = ctx.mutable_globals.get(target).cloned() {
                    ctx.code
                        .push_str(&format!("  store i32 {rendered_value}, ptr @{symbol}\n"));
                    continue;
                }
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                if !ctx.code.contains(&format!("{slot} = alloca i32")) {
                    ctx.code.push_str(&format!("  {slot} = alloca i32\n"));
                }
                ctx.code
                    .push_str(&format!("  store i32 {rendered_value}, ptr {slot}\n"));
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids);
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.code.push_str(&format!(
                            "  {field_slot} = alloca i32\n  store i32 {field_value}, ptr {field_slot}\n"
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_value =
                        llvm_emit_expr(start.as_ref(), ctx, string_literal_ids, task_ref_ids);
                    let end_value =
                        llvm_emit_expr(end.as_ref(), ctx, string_literal_ids, task_ref_ids);
                    let inclusive_value = if *inclusive { "1" } else { "0" };
                    for (field, rendered) in [
                        ("start", start_value),
                        ("end", end_value),
                        ("inclusive", inclusive_value.to_string()),
                    ] {
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.code.push_str(&format!(
                            "  {field_slot} = alloca i32\n  store i32 {rendered}, ptr {field_slot}\n"
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                    }
                }
                ctx.array_slots.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::CompoundAssign { target, op, value } => {
                let combined_expr = ast::Expr::Binary {
                    op: *op,
                    left: Box::new(ast::Expr::Ident(target.clone())),
                    right: Box::new(value.clone()),
                };
                let value = llvm_emit_expr(&combined_expr, ctx, string_literal_ids, task_ref_ids);
                if let Some(symbol) = ctx.mutable_globals.get(target).cloned() {
                    ctx.code
                        .push_str(&format!("  store i32 {value}, ptr @{symbol}\n"));
                    continue;
                }
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                if !ctx.code.contains(&format!("{slot} = alloca i32")) {
                    ctx.code.push_str(&format!("  {slot} = alloca i32\n"));
                }
                ctx.code
                    .push_str(&format!("  store i32 {value}, ptr {slot}\n"));
                ctx.array_slots.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::Expr(expr)
            | ast::Stmt::Requires(expr)
            | ast::Stmt::Ensures(expr)
            | ast::Stmt::Defer(expr) => {
                let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
            }
            ast::Stmt::Return(_)
            | ast::Stmt::If { .. }
            | ast::Stmt::While { .. }
            | ast::Stmt::For { .. }
            | ast::Stmt::ForIn { .. }
            | ast::Stmt::Loop { .. }
            | ast::Stmt::Break(_) | ast::Stmt::Continue
            | ast::Stmt::Match { .. } => {
                bail!("llvm linear emission received non-linear control-flow statement");
            }
        }
    }
    Ok(())
}

fn llvm_emit_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> String {
    match expr {
        ast::Expr::Int(v) => v.to_string(),
        ast::Expr::Float { value, .. } => (*value as i32).to_string(),
        ast::Expr::Char(value) => (*value as i32).to_string(),
        ast::Expr::Bool(v) => {
            if *v {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        ast::Expr::Str(value) => string_literal_ids
            .get(value)
            .copied()
            .unwrap_or(0)
            .to_string(),
        ast::Expr::Ident(name) => {
            if let Some(slot) = ctx.slots.get(name).cloned() {
                let val = ctx.value();
                ctx.code
                    .push_str(&format!("  {val} = load i32, ptr {slot}\n"));
                val
            } else if let Some(symbol) = ctx.mutable_globals.get(name).cloned() {
                let val = ctx.value();
                ctx.code
                    .push_str(&format!("  {val} = load i32, ptr @{symbol}\n"));
                val
            } else if let Some(value) = ctx.globals.get(name).copied() {
                value.to_string()
            } else if let Some(task_ref) = task_ref_ids.get(name).copied() {
                task_ref.to_string()
            } else {
                "0".to_string()
            }
        }
        ast::Expr::Group(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids),
        ast::Expr::Await(inner) => llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids),
        ast::Expr::Discard(inner) => {
            let _ = llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids);
            "0".to_string()
        }
        ast::Expr::Closure {
            params,
            return_type,
            body,
        } => {
            let captures = llvm_snapshot_closure_captures(ctx);
            let name = format!("__closure_{}", ctx.next_value);
            ctx.closures.insert(
                name,
                LlvmClosureBinding {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    body: (**body).clone(),
                    captures,
                },
            );
            "0".to_string()
        }
        ast::Expr::Unary { op, expr } => {
            let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
            match op {
                ast::UnaryOp::Plus => value,
                ast::UnaryOp::Neg => {
                    let out = ctx.value();
                    ctx.code
                        .push_str(&format!("  {out} = sub i32 0, {value}\n"));
                    out
                }
                ast::UnaryOp::BitNot => {
                    let out = ctx.value();
                    ctx.code
                        .push_str(&format!("  {out} = xor i32 {value}, -1\n"));
                    out
                }
                ast::UnaryOp::Not => {
                    let pred = ctx.value();
                    let out = ctx.value();
                    ctx.code
                        .push_str(&format!("  {pred} = icmp eq i32 {value}, 0\n"));
                    ctx.code
                        .push_str(&format!("  {out} = zext i1 {pred} to i32\n"));
                    out
                }
            }
        }
        ast::Expr::FieldAccess { base, field } => {
            if let Some(field_expr) = resolve_field_expr(base, field) {
                return llvm_emit_expr(&field_expr, ctx, string_literal_ids, task_ref_ids);
            }
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(slot) = ctx.slots.get(&format!("{name}.{field}")).cloned() {
                    let val = ctx.value();
                    ctx.code
                        .push_str(&format!("  {val} = load i32, ptr {slot}\n"));
                    return val;
                }
            }
            if let Some(task_ref_name) = expr_task_ref_name(expr) {
                if let Some(task_ref) = task_ref_ids.get(&task_ref_name).copied() {
                    return task_ref.to_string();
                }
            }
            llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut first = None;
            for (_, value) in fields {
                let current = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids);
                if first.is_none() {
                    first = Some(current);
                }
            }
            first.unwrap_or_else(|| "0".to_string())
        }
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
        } => {
            for value in payload {
                let _ = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids);
            }
            let key = format!("{enum_name}::{variant}");
            variant_tag_for_key(&key, &ctx.variant_tags).to_string()
        }
        ast::Expr::TryCatch { try_expr, .. } => {
            llvm_emit_expr(try_expr, ctx, string_literal_ids, task_ref_ids)
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let cond = llvm_emit_expr(condition, ctx, string_literal_ids, task_ref_ids);
            let pred = ctx.value();
            let then_label = ctx.label("if.then");
            let else_label = ctx.label("if.else");
            let merge_label = ctx.label("if.merge");
            ctx.code
                .push_str(&format!("  {pred} = icmp ne i32 {cond}, 0\n"));
            ctx.code.push_str(&format!(
                "  br i1 {pred}, label %{then_label}, label %{else_label}\n"
            ));

            ctx.code.push_str(&format!("{then_label}:\n"));
            let then_value = llvm_emit_expr(then_expr, ctx, string_literal_ids, task_ref_ids);
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));

            ctx.code.push_str(&format!("{else_label}:\n"));
            let else_value = llvm_emit_expr(else_expr, ctx, string_literal_ids, task_ref_ids);
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));

            ctx.code.push_str(&format!("{merge_label}:\n"));
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = phi i32 [ {then_value}, %{then_label} ], [ {else_value}, %{else_label} ]\n"
            ));
            out
        }
        ast::Expr::Range { start, .. } => {
            llvm_emit_expr(start, ctx, string_literal_ids, task_ref_ids)
        }
        ast::Expr::ArrayLiteral(items) => {
            // Array literals are materialized by statement lowering into element slots.
            // Expression-position array literals are unsupported in direct-memory mode.
            for item in items {
                let _ = llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids);
            }
            "0".to_string()
        }
        ast::Expr::Index { base, index } => {
            let index_value = if let Some((base_name, offset)) =
                canonicalize_array_index_window(index)
            {
                if let Some(slot) = ctx.slots.get(&base_name).cloned() {
                    let base_loaded = ctx.value();
                    ctx.code
                        .push_str(&format!("  {base_loaded} = load i32, ptr {slot}\n"));
                    if offset == 0 {
                        base_loaded
                    } else {
                        let adjusted = ctx.value();
                        let op = if offset >= 0 { "add" } else { "sub" };
                        let rhs = offset.unsigned_abs();
                        ctx.code
                            .push_str(&format!("  {adjusted} = {op} i32 {base_loaded}, {rhs}\n"));
                        adjusted
                    }
                } else {
                    llvm_emit_expr(index, ctx, string_literal_ids, task_ref_ids)
                }
            } else {
                llvm_emit_expr(index, ctx, string_literal_ids, task_ref_ids)
            };
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = ctx.array_slots.get(name).cloned() {
                    if binding.len == 0 {
                        return "0".to_string();
                    }
                    if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
                        if const_idx >= 0 && (const_idx as usize) < binding.len {
                            let elem_ptr = ctx.value();
                            let loaded = ctx.value();
                            ctx.code.push_str(&format!(
                                "  {elem_ptr} = getelementptr inbounds [{} x i32], ptr {}, i32 0, i64 {}\n",
                                binding.len, binding.storage, const_idx
                            ));
                            ctx.code
                                .push_str(&format!("  {loaded} = load i32, ptr {elem_ptr}\n"));
                            return loaded;
                        }
                    }
                    let in_label = ctx.label("idx.in");
                    let out_label = ctx.label("idx.oob");
                    let merge_label = ctx.label("idx.merge");
                    let nonneg = ctx.value();
                    let ltlen = ctx.value();
                    let ok = ctx.value();
                    ctx.code
                        .push_str(&format!("  {nonneg} = icmp sge i32 {index_value}, 0\n"));
                    ctx.code.push_str(&format!(
                        "  {ltlen} = icmp slt i32 {index_value}, {}\n",
                        binding.len
                    ));
                    ctx.code
                        .push_str(&format!("  {ok} = and i1 {nonneg}, {ltlen}\n"));
                    ctx.code.push_str(&format!(
                        "  br i1 {ok}, label %{in_label}, label %{out_label}\n"
                    ));
                    ctx.code.push_str(&format!("{in_label}:\n"));
                    let idx64 = ctx.value();
                    let elem_ptr = ctx.value();
                    let loaded = ctx.value();
                    ctx.code
                        .push_str(&format!("  {idx64} = sext i32 {index_value} to i64\n"));
                    ctx.code.push_str(&format!(
                        "  {elem_ptr} = getelementptr inbounds [{} x i32], ptr {}, i32 0, i64 {idx64}\n",
                        binding.len, binding.storage
                    ));
                    ctx.code
                        .push_str(&format!("  {loaded} = load i32, ptr {elem_ptr}\n"));
                    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                    ctx.code.push_str(&format!("{out_label}:\n"));
                    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                    ctx.code.push_str(&format!("{merge_label}:\n"));
                    let selected = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {selected} = phi i32 [ {loaded}, %{in_label} ], [ 0, %{out_label} ]\n"
                    ));
                    let _ = (
                        binding.element_bits,
                        binding.element_align,
                        binding.element_stride,
                    );
                    return selected;
                }
            }
            llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)
        }
        ast::Expr::Call { callee, args } => {
            if let Some(value) = eval_const_i32_call(callee, args, &ctx.const_strings) {
                return value.to_string();
            }
            if let Some(value) = eval_const_string_call(callee, args, &ctx.const_strings) {
                if let Some(id) = string_literal_ids.get(&value).copied() {
                    return id.to_string();
                }
            }
            if let Some(binding) = ctx.closures.get(callee).cloned() {
                return llvm_emit_inlined_closure_call(
                    binding,
                    args,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
            }
            let args = args
                .iter()
                .map(|arg| {
                    format!(
                        "i32 {}",
                        llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let symbol = native_runtime_import_for_callee(callee)
                .or_else(|| native_data_plane_import_for_callee(callee))
                .map(|import| import.symbol)
                .unwrap_or(callee.as_str());
            let symbol = native_mangle_symbol(symbol);
            let val = ctx.value();
            ctx.code
                .push_str(&format!("  {val} = call i32 @{symbol}({args})\n"));
            val
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            let _ = llvm_emit_linear_stmts(body, ctx, string_literal_ids, task_ref_ids);
            "0".to_string()
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = llvm_emit_expr(left, ctx, string_literal_ids, task_ref_ids);
            let out = ctx.value();
            match op {
                ast::BinaryOp::Add => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = add i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::Sub => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = sub i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::Mul => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = mul i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::Div => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = sdiv i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::Mod => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = srem i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::BitAnd => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = and i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::BitOr => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = or i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::BitXor => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = xor i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::Shl => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = shl i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::Shr => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    ctx.code
                        .push_str(&format!("  {out} = ashr i32 {lhs}, {rhs}\n"));
                }
                ast::BinaryOp::And | ast::BinaryOp::Or => {
                    let lhs_pred = ctx.value();
                    let rhs_label = ctx.label("logical.rhs");
                    let short_label = ctx.label("logical.short");
                    let merge_label = ctx.label("logical.merge");
                    let result_slot = format!("%slot_logical_{}", ctx.next_value);
                    ctx.next_value += 1;
                    ctx.code
                        .push_str(&format!("  {result_slot} = alloca i32\n"));
                    ctx.code
                        .push_str(&format!("  {lhs_pred} = icmp ne i32 {lhs}, 0\n"));
                    match op {
                        ast::BinaryOp::And => {
                            ctx.code.push_str(&format!(
                                "  br i1 {lhs_pred}, label %{rhs_label}, label %{short_label}\n"
                            ));
                            ctx.code.push_str(&format!("{short_label}:\n"));
                            ctx.code
                                .push_str(&format!("  store i32 0, ptr {result_slot}\n"));
                            ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                        }
                        ast::BinaryOp::Or => {
                            ctx.code.push_str(&format!(
                                "  br i1 {lhs_pred}, label %{short_label}, label %{rhs_label}\n"
                            ));
                            ctx.code.push_str(&format!("{short_label}:\n"));
                            ctx.code
                                .push_str(&format!("  store i32 1, ptr {result_slot}\n"));
                            ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                        }
                        _ => unreachable!(),
                    }
                    ctx.code.push_str(&format!("{rhs_label}:\n"));
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    let rhs_pred = ctx.value();
                    let rhs_i32 = ctx.value();
                    ctx.code
                        .push_str(&format!("  {rhs_pred} = icmp ne i32 {rhs}, 0\n"));
                    ctx.code
                        .push_str(&format!("  {rhs_i32} = zext i1 {rhs_pred} to i32\n"));
                    ctx.code
                        .push_str(&format!("  store i32 {rhs_i32}, ptr {result_slot}\n"));
                    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                    ctx.code.push_str(&format!("{merge_label}:\n"));
                    ctx.code
                        .push_str(&format!("  {out} = load i32, ptr {result_slot}\n"));
                }
                ast::BinaryOp::Eq
                | ast::BinaryOp::Neq
                | ast::BinaryOp::Lt
                | ast::BinaryOp::Lte
                | ast::BinaryOp::Gt
                | ast::BinaryOp::Gte => {
                    let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids);
                    let pred = ctx.value();
                    let cmp = match op {
                        ast::BinaryOp::Eq => "eq",
                        ast::BinaryOp::Neq => "ne",
                        ast::BinaryOp::Lt => "slt",
                        ast::BinaryOp::Lte => "sle",
                        ast::BinaryOp::Gt => "sgt",
                        ast::BinaryOp::Gte => "sge",
                        _ => unreachable!(),
                    };
                    ctx.code
                        .push_str(&format!("  {pred} = icmp {cmp} i32 {lhs}, {rhs}\n"));
                    ctx.code
                        .push_str(&format!("  {out} = zext i1 {pred} to i32\n"));
                }
            }
            out
        }
        _ => "0".to_string(),
    }
}

fn native_runtime_import_for_callee(callee: &str) -> Option<&'static NativeRuntimeImport> {
    NATIVE_RUNTIME_IMPORTS
        .iter()
        .find(|import| import.callee == callee)
}

fn native_data_plane_import_for_callee(callee: &str) -> Option<&'static NativeRuntimeImport> {
    NATIVE_DATA_PLANE_IMPORTS
        .iter()
        .find(|import| import.callee == callee)
}

fn native_runtime_import_contract_errors() -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = HashSet::<&'static str>::new();
    for import in NATIVE_RUNTIME_IMPORTS {
        if !seen.insert(import.callee) {
            errors.push(format!(
                "duplicate native runtime import callee `{}` in boundary import table",
                import.callee
            ));
        }

    }
    errors
}

fn is_extern_c_import_decl(function: &hir::TypedFunction) -> bool {
    function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        && function.body.is_empty()
}

fn collect_extern_c_imports(fir: &fir::FirModule) -> Vec<&hir::TypedFunction> {
    fir.typed_functions
        .iter()
        .filter(|function| is_extern_c_import_decl(function))
        .collect()
}

#[derive(Debug, Clone)]
struct NativeAsyncExport {
    name: String,
    mangled_symbol: String,
    params: Vec<(String, String)>,
}

fn collect_async_c_exports(fir: &fir::FirModule) -> Vec<NativeAsyncExport> {
    fir.typed_functions
        .iter()
        .filter(|function| {
            function.is_async
                && function.is_extern
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
                && !function.body.is_empty()
                && matches!(
                    function.return_type,
                    ast::Type::Int {
                        signed: true,
                        bits: 32
                    }
                )
        })
        .map(|function| NativeAsyncExport {
            name: function.name.clone(),
            mangled_symbol: native_mangle_symbol(&function.name),
            params: function
                .params
                .iter()
                .map(|param| {
                    (
                        ffi_signature_type_to_c_type(&param.ty),
                        native_mangle_symbol(&param.name),
                    )
                })
                .collect(),
        })
        .collect()
}

fn ffi_signature_type_to_c_type(ty: &ast::Type) -> String {
    match ty {
        ast::Type::Ptr { mutable, to } => {
            if *mutable {
                format!("{}*", ffi_signature_type_to_c_type(to))
            } else {
                format!("const {}*", ffi_signature_type_to_c_type(to))
            }
        }
        ast::Type::Void => "void".to_string(),
        ast::Type::Bool => "bool".to_string(),
        ast::Type::ISize => "ssize_t".to_string(),
        ast::Type::USize => "size_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 8,
        } => "int8_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 16,
        } => "int16_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 32,
        } => "int32_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 64,
        } => "int64_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 128,
        } => "__int128_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 8,
        } => "uint8_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 16,
        } => "uint16_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 32,
        } => "uint32_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 64,
        } => "uint64_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 128,
        } => "__uint128_t".to_string(),
        ast::Type::Float { bits: 32 } => "float".to_string(),
        ast::Type::Float { bits: 64 } => "double".to_string(),
        ast::Type::Char => "uint32_t".to_string(),
        ast::Type::Str => "const char*".to_string(),
        ast::Type::Named { name, .. } => name.clone(),
        _ => "void*".to_string(),
    }
}

fn collect_used_native_runtime_imports(fir: &fir::FirModule) -> Vec<&'static NativeRuntimeImport> {
    let mut seen = HashSet::<&'static str>::new();
    let mut used = Vec::<&'static NativeRuntimeImport>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_used_runtime_imports_from_stmt(stmt, &mut seen, &mut used);
        }
    }
    used
}

fn collect_used_native_data_plane_imports(
    fir: &fir::FirModule,
) -> Vec<&'static NativeRuntimeImport> {
    let mut seen = HashSet::<&'static str>::new();
    let mut used = Vec::<&'static NativeRuntimeImport>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_used_data_plane_imports_from_stmt(stmt, &mut seen, &mut used);
        }
    }
    used
}

fn collect_string_literals(fir: &fir::FirModule) -> Vec<String> {
    let mut literals = HashSet::<String>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_string_literals_from_stmt(stmt, &mut literals);
        }
    }
    let mut literals = literals.into_iter().collect::<Vec<_>>();
    literals.sort();
    literals
}

fn collect_folded_temp_string_literals(fir: &fir::FirModule) -> Vec<String> {
    fn collect_from_body(
        body: &[ast::Stmt],
        const_strings: &mut HashMap<String, String>,
        out: &mut HashSet<String>,
    ) {
        for stmt in body {
            collect_from_stmt(stmt, const_strings, out);
        }
    }

    fn collect_from_stmt(
        stmt: &ast::Stmt,
        const_strings: &mut HashMap<String, String>,
        out: &mut HashSet<String>,
    ) {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                collect_from_expr(value, const_strings, out);
                if let Some(value) = eval_const_string_expr(value, const_strings) {
                    const_strings.insert(name.clone(), value);
                } else {
                    const_strings.remove(name);
                }
            }
            ast::Stmt::Assign { target, value } => {
                collect_from_expr(value, const_strings, out);
                if let Some(value) = eval_const_string_expr(value, const_strings) {
                    const_strings.insert(target.clone(), value);
                } else {
                    const_strings.remove(target);
                }
            }
            ast::Stmt::CompoundAssign { target, value, .. } => {
                collect_from_expr(value, const_strings, out);
                const_strings.remove(target);
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => collect_from_expr(value, const_strings, out),
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    collect_from_expr(value, const_strings, out);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_from_expr(condition, const_strings, out);
                collect_from_body(then_body, &mut const_strings.clone(), out);
                collect_from_body(else_body, &mut const_strings.clone(), out);
            }
            ast::Stmt::While { condition, body } => {
                collect_from_expr(condition, const_strings, out);
                collect_from_body(body, &mut const_strings.clone(), out);
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_from_stmt(init, &mut const_strings.clone(), out);
                }
                if let Some(condition) = condition {
                    collect_from_expr(condition, const_strings, out);
                }
                if let Some(step) = step {
                    collect_from_stmt(step, &mut const_strings.clone(), out);
                }
                collect_from_body(body, &mut const_strings.clone(), out);
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                collect_from_expr(iterable, const_strings, out);
                collect_from_body(body, &mut const_strings.clone(), out);
            }
            ast::Stmt::Loop { body } => collect_from_body(body, &mut const_strings.clone(), out),
            ast::Stmt::Match { scrutinee, arms } => {
                collect_from_expr(scrutinee, const_strings, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_from_expr(guard, const_strings, out);
                    }
                    collect_from_expr(&arm.value, const_strings, out);
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }

    fn collect_from_expr(
        expr: &ast::Expr,
        const_strings: &HashMap<String, String>,
        out: &mut HashSet<String>,
    ) {
        if let Some(value) = eval_const_string_expr(expr, const_strings) {
            out.insert(value);
        }
        match expr {
            ast::Expr::Call { args, .. } => {
                for arg in args {
                    collect_from_expr(arg, const_strings, out);
                }
            }
            ast::Expr::UnsafeBlock { .. } => {}
            ast::Expr::FieldAccess { base, .. } => collect_from_expr(base, const_strings, out),
            ast::Expr::StructInit { fields, .. } => {
                for (_, value) in fields {
                    collect_from_expr(value, const_strings, out);
                }
            }
            ast::Expr::EnumInit { payload, .. } | ast::Expr::ArrayLiteral(payload) => {
                for value in payload {
                    collect_from_expr(value, const_strings, out);
                }
            }
            ast::Expr::Closure { body, .. }
            | ast::Expr::Group(body)
            | ast::Expr::Await(body)
            | ast::Expr::Discard(body) => {
                collect_from_expr(body, const_strings, out)
            }
            ast::Expr::Unary { expr, .. } => collect_from_expr(expr, const_strings, out),
            ast::Expr::TryCatch {
                try_expr,
                catch_expr,
            } => {
                collect_from_expr(try_expr, const_strings, out);
                collect_from_expr(catch_expr, const_strings, out);
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                collect_from_expr(condition, const_strings, out);
                collect_from_expr(then_expr, const_strings, out);
                collect_from_expr(else_expr, const_strings, out);
            }
            ast::Expr::Binary { left, right, .. } => {
                collect_from_expr(left, const_strings, out);
                collect_from_expr(right, const_strings, out);
            }
            ast::Expr::Range { start, end, .. } => {
                collect_from_expr(start, const_strings, out);
                collect_from_expr(end, const_strings, out);
            }
            ast::Expr::Index { base, index } => {
                collect_from_expr(base, const_strings, out);
                collect_from_expr(index, const_strings, out);
            }
            ast::Expr::Int(_)
            | ast::Expr::Float { .. }
            | ast::Expr::Char(_)
            | ast::Expr::Bool(_)
            | ast::Expr::Str(_)
            | ast::Expr::Ident(_) => {}
        _ => {}
        }
    }

    let mut out = HashSet::<String>::new();
    for function in &fir.typed_functions {
        collect_from_body(&function.body, &mut HashMap::new(), &mut out);
    }
    let mut out = out.into_iter().collect::<Vec<_>>();
    out.sort();
    out
}

fn collect_native_string_literals(fir: &fir::FirModule) -> Vec<String> {
    let mut merged = collect_string_literals(fir)
        .into_iter()
        .collect::<HashSet<_>>();
    for folded in collect_folded_temp_string_literals(fir) {
        merged.insert(folded);
    }
    let mut merged = merged.into_iter().collect::<Vec<_>>();
    merged.sort();
    merged
}

fn collect_string_literals_from_stmt(stmt: &ast::Stmt, literals: &mut HashSet<String>) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_string_literals_from_expr(value, literals),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_string_literals_from_expr(condition, literals);
            for nested in then_body {
                collect_string_literals_from_stmt(nested, literals);
            }
            for nested in else_body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_string_literals_from_expr(condition, literals);
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_string_literals_from_stmt(init, literals);
            }
            if let Some(condition) = condition {
                collect_string_literals_from_expr(condition, literals);
            }
            if let Some(step) = step {
                collect_string_literals_from_stmt(step, literals);
            }
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_string_literals_from_expr(iterable, literals);
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_string_literals_from_stmt(nested, literals);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_string_literals_from_expr(scrutinee, literals);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_string_literals_from_expr(guard, literals);
                }
                collect_string_literals_from_expr(&arm.value, literals);
            }
        }
    }
}

fn collect_string_literals_from_expr(expr: &ast::Expr, literals: &mut HashSet<String>) {
    match expr {
        ast::Expr::Str(value) => {
            literals.insert(value.clone());
        }
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_string_literals_from_expr(arg, literals);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => collect_string_literals_from_expr(base, literals),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_string_literals_from_expr(value, literals);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_string_literals_from_expr(body, literals);
        }
        ast::Expr::Group(inner) => collect_string_literals_from_expr(inner, literals),
        ast::Expr::Await(inner) => collect_string_literals_from_expr(inner, literals),
        ast::Expr::Discard(inner) => collect_string_literals_from_expr(inner, literals),
        ast::Expr::Unary { expr, .. } => collect_string_literals_from_expr(expr, literals),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_string_literals_from_expr(try_expr, literals);
            collect_string_literals_from_expr(catch_expr, literals);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_string_literals_from_expr(condition, literals);
            collect_string_literals_from_expr(then_expr, literals);
            collect_string_literals_from_expr(else_expr, literals);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_string_literals_from_expr(left, literals);
            collect_string_literals_from_expr(right, literals);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_string_literals_from_expr(start, literals);
            collect_string_literals_from_expr(end, literals);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_string_literals_from_expr(item, literals);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_string_literals_from_expr(base, literals);
            collect_string_literals_from_expr(index, literals);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn build_string_literal_ids(literals: &[String]) -> HashMap<String, i32> {
    literals
        .iter()
        .enumerate()
        .map(|(index, value)| (value.clone(), index as i32 + 1))
        .collect()
}

fn build_global_const_i32_map(fir: &fir::FirModule) -> HashMap<String, i32> {
    fir.typed_globals
        .iter()
        .filter_map(|item| {
            if item.is_static && item.mutable {
                None
            } else {
                item.const_i32.map(|value| (item.name.clone(), value))
            }
        })
        .collect()
}

fn build_mutable_static_i32_map(fir: &fir::FirModule) -> HashMap<String, i32> {
    fir.typed_globals
        .iter()
        .filter_map(|item| {
            if item.is_static && item.mutable {
                item.const_i32.map(|value| (item.name.clone(), value))
            } else {
                None
            }
        })
        .collect()
}

fn llvm_static_symbol_name(name: &str) -> String {
    format!("fz_static_{}", native_mangle_symbol(name))
}

fn collect_spawn_task_symbols(fir: &fir::FirModule) -> Vec<String> {
    fir.typed_functions
        .iter()
        .filter(|function| function.params.is_empty())
        .map(|function| function.name.clone())
        .collect()
}

fn build_variant_tag_map(fir: &fir::FirModule) -> HashMap<String, i32> {
    let mut keys = BTreeSet::<String>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_variant_keys_from_stmt(stmt, &mut keys);
        }
    }
    keys.into_iter()
        .enumerate()
        .map(|(idx, key)| (key, idx as i32 + 1))
        .collect()
}

fn collect_passthrough_function_map_from_typed(
    functions: &[hir::TypedFunction],
) -> HashMap<String, usize> {
    let mut passthrough = HashMap::<String, usize>::new();
    for function in functions {
        if function.params.is_empty() || function.body.len() != 1 {
            continue;
        }
        let ast::Stmt::Return(Some(ast::Expr::Ident(name))) = &function.body[0] else {
            continue;
        };
        if let Some((index, _)) = function
            .params
            .iter()
            .enumerate()
            .find(|(_, param)| &param.name == name)
        {
            passthrough.insert(function.name.clone(), index);
        }
    }
    passthrough
}

fn collect_passthrough_function_map_from_module(module: &ast::Module) -> HashMap<String, usize> {
    let mut passthrough = HashMap::<String, usize>::new();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        if function.params.is_empty() || function.body.len() != 1 {
            continue;
        }
        let ast::Stmt::Return(Some(ast::Expr::Ident(name))) = &function.body[0] else {
            continue;
        };
        if let Some((index, _)) = function
            .params
            .iter()
            .enumerate()
            .find(|(_, param)| &param.name == name)
        {
            passthrough.insert(function.name.clone(), index);
        }
    }
    passthrough
}

fn collect_variant_keys_from_stmt(stmt: &ast::Stmt, out: &mut BTreeSet<String>) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_variant_keys_from_expr(value, out),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_variant_keys_from_expr(value, out);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_variant_keys_from_expr(condition, out);
            for nested in then_body {
                collect_variant_keys_from_stmt(nested, out);
            }
            for nested in else_body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_variant_keys_from_expr(condition, out);
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_variant_keys_from_stmt(init, out);
            }
            if let Some(condition) = condition {
                collect_variant_keys_from_expr(condition, out);
            }
            if let Some(step) = step {
                collect_variant_keys_from_stmt(step, out);
            }
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_variant_keys_from_expr(iterable, out);
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_variant_keys_from_stmt(nested, out);
            }
        }
        ast::Stmt::Match { scrutinee, arms } => {
            collect_variant_keys_from_expr(scrutinee, out);
            for arm in arms {
                collect_variant_keys_from_pattern(&arm.pattern, out);
                if let Some(guard) = &arm.guard {
                    collect_variant_keys_from_expr(guard, out);
                }
                collect_variant_keys_from_expr(&arm.value, out);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
    }
}

fn collect_variant_keys_from_expr(expr: &ast::Expr, out: &mut BTreeSet<String>) {
    match expr {
        ast::Expr::EnumInit {
            enum_name, variant, ..
        } => {
            out.insert(format!("{enum_name}::{variant}"));
        }
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_variant_keys_from_expr(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => collect_variant_keys_from_expr(base, out),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_variant_keys_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_variant_keys_from_expr(body, out),
        ast::Expr::Group(inner) => collect_variant_keys_from_expr(inner, out),
        ast::Expr::Await(inner) => collect_variant_keys_from_expr(inner, out),
        ast::Expr::Discard(inner) => collect_variant_keys_from_expr(inner, out),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_variant_keys_from_expr(try_expr, out);
            collect_variant_keys_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_variant_keys_from_expr(condition, out);
            collect_variant_keys_from_expr(then_expr, out);
            collect_variant_keys_from_expr(else_expr, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_variant_keys_from_expr(start, out);
            collect_variant_keys_from_expr(end, out);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_variant_keys_from_expr(item, out);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_variant_keys_from_expr(base, out);
            collect_variant_keys_from_expr(index, out);
        }
        ast::Expr::Unary { expr, .. } => collect_variant_keys_from_expr(expr, out),
        ast::Expr::Binary { left, right, .. } => {
            collect_variant_keys_from_expr(left, out);
            collect_variant_keys_from_expr(right, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn collect_variant_keys_from_pattern(pattern: &ast::Pattern, out: &mut BTreeSet<String>) {
    match pattern {
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            out.insert(format!("{enum_name}::{variant}"));
        }
        ast::Pattern::Or(patterns) => {
            for nested in patterns {
                collect_variant_keys_from_pattern(nested, out);
            }
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_)
        | ast::Pattern::Struct { .. } => {}
    }
}

fn escape_c_string(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn expr_task_ref_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::FieldAccess { base, field } => {
            let mut name = expr_task_ref_name(base)?;
            name.push('.');
            name.push_str(field);
            Some(name)
        }
        ast::Expr::Group(inner) => expr_task_ref_name(inner),
        ast::Expr::Unary { expr, .. } => expr_task_ref_name(expr),
        _ => None,
    }
}

fn eval_const_string_expr(
    expr: &ast::Expr,
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match expr {
        ast::Expr::Str(value) => Some(value.clone()),
        ast::Expr::Ident(name) => const_strings.get(name).cloned(),
        ast::Expr::Group(inner) => eval_const_string_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_string_call(callee, args, const_strings),
        _ => None,
    }
}

fn eval_const_string_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<String> {
    match callee {
        "str.concat2" if args.len() == 2 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            Some(format!("{a}{b}"))
        }
        "str.concat3" if args.len() == 3 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            Some(format!("{a}{b}{c}"))
        }
        "str.concat4" if args.len() == 4 => {
            let a = eval_const_string_expr(&args[0], const_strings)?;
            let b = eval_const_string_expr(&args[1], const_strings)?;
            let c = eval_const_string_expr(&args[2], const_strings)?;
            let d = eval_const_string_expr(&args[3], const_strings)?;
            Some(format!("{a}{b}{c}{d}"))
        }
        "str.concat" if !args.is_empty() => {
            let mut out = String::new();
            for arg in args {
                out.push_str(&eval_const_string_expr(arg, const_strings)?);
            }
            Some(out)
        }
        "str.trim" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            Some(value.trim().to_string())
        }
        "str.replace" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let from = eval_const_string_expr(&args[1], const_strings)?;
            let to = eval_const_string_expr(&args[2], const_strings)?;
            Some(value.replace(&from, &to))
        }
        "str.slice" if args.len() == 3 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let start = eval_const_i32_expr(&args[1], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let span = eval_const_i32_expr(&args[2], const_strings)
                .unwrap_or(0)
                .max(0) as usize;
            let len = value.len();
            let s = start.min(len);
            let e = s.saturating_add(span).min(len);
            if value.is_char_boundary(s) && value.is_char_boundary(e) {
                Some(value[s..e].to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn eval_const_i32_expr(expr: &ast::Expr, const_strings: &HashMap<String, String>) -> Option<i32> {
    match expr {
        ast::Expr::Int(value) => i32::try_from(*value).ok(),
        ast::Expr::Bool(value) => Some(if *value { 1 } else { 0 }),
        ast::Expr::Group(inner) => eval_const_i32_expr(inner, const_strings),
        ast::Expr::Call { callee, args } => eval_const_i32_call(callee, args, const_strings),
        _ => None,
    }
}

fn eval_const_i32_call(
    callee: &str,
    args: &[ast::Expr],
    const_strings: &HashMap<String, String>,
) -> Option<i32> {
    match callee {
        "str.contains" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let needle = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.contains(&needle) { 1 } else { 0 })
        }
        "str.starts_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let prefix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.starts_with(&prefix) { 1 } else { 0 })
        }
        "str.ends_with" if args.len() == 2 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            let suffix = eval_const_string_expr(&args[1], const_strings)?;
            Some(if value.ends_with(&suffix) { 1 } else { 0 })
        }
        "str.len" if args.len() == 1 => {
            let value = eval_const_string_expr(&args[0], const_strings)?;
            i32::try_from(value.len()).ok()
        }
        _ => None,
    }
}

fn is_native_data_plane_string_call(callee: &str) -> bool {
    matches!(callee, "str.concat")
        || native_data_plane_import_for_callee(callee)
            .is_some_and(|import| import.callee.starts_with("str."))
}

fn canonicalize_array_index_window(expr: &ast::Expr) -> Option<(String, i32)> {
    match expr {
        ast::Expr::Ident(name) => Some((name.clone(), 0)),
        ast::Expr::Group(inner) => canonicalize_array_index_window(inner),
        ast::Expr::Binary { op, left, right } => match op {
            ast::BinaryOp::Add => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                (ast::Expr::Int(offset), ast::Expr::Ident(name)) => {
                    i32::try_from(*offset).ok().map(|off| (name.clone(), off))
                }
                _ => None,
            },
            ast::BinaryOp::Sub => match (left.as_ref(), right.as_ref()) {
                (ast::Expr::Ident(name), ast::Expr::Int(offset)) => i32::try_from(*offset)
                    .ok()
                    .and_then(|off| off.checked_neg())
                    .map(|off| (name.clone(), off)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn collect_used_runtime_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_runtime_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_runtime_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_runtime_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_runtime_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_runtime_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_runtime_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_runtime_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_runtime_imports_from_expr(guard, seen, used);
                }
                collect_used_runtime_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

fn collect_used_runtime_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            let empty_const_strings = HashMap::<String, String>::new();
            let folded_const = eval_const_string_call(callee, args, &empty_const_strings).is_some()
                || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
            if !folded_const {
                if let Some(import) = native_runtime_import_for_callee(callee) {
                    if seen.insert(import.symbol) {
                        used.push(import);
                    }
                }
            }
            for arg in args {
                collect_used_runtime_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_runtime_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_runtime_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_runtime_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_runtime_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_runtime_imports_from_expr(try_expr, seen, used);
            collect_used_runtime_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_runtime_imports_from_expr(condition, seen, used);
            collect_used_runtime_imports_from_expr(then_expr, seen, used);
            collect_used_runtime_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_runtime_imports_from_expr(left, seen, used);
            collect_used_runtime_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_runtime_imports_from_expr(start, seen, used);
            collect_used_runtime_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_runtime_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_runtime_imports_from_expr(base, seen, used);
            collect_used_runtime_imports_from_expr(index, seen, used);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn collect_used_data_plane_imports_from_stmt(
    stmt: &ast::Stmt,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_used_data_plane_imports_from_expr(value, seen, used),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in then_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
            for nested in else_body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_used_data_plane_imports_from_stmt(init, seen, used);
            }
            if let Some(condition) = condition {
                collect_used_data_plane_imports_from_expr(condition, seen, used);
            }
            if let Some(step) = step {
                collect_used_data_plane_imports_from_stmt(step, seen, used);
            }
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_used_data_plane_imports_from_expr(iterable, seen, used);
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_used_data_plane_imports_from_stmt(nested, seen, used);
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_used_data_plane_imports_from_expr(scrutinee, seen, used);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_used_data_plane_imports_from_expr(guard, seen, used);
                }
                collect_used_data_plane_imports_from_expr(&arm.value, seen, used);
            }
        }
    }
}

fn collect_used_data_plane_imports_from_expr(
    expr: &ast::Expr,
    seen: &mut HashSet<&'static str>,
    used: &mut Vec<&'static NativeRuntimeImport>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if let Some(import) = native_data_plane_import_for_callee(callee) {
                let empty_const_strings = HashMap::<String, String>::new();
                let folded_const =
                    eval_const_string_call(callee, args, &empty_const_strings).is_some()
                        || eval_const_i32_call(callee, args, &empty_const_strings).is_some();
                let can_skip = folded_const && callee.starts_with("str.");
                if !can_skip && seen.insert(import.symbol) {
                    used.push(import);
                }
            }
            for arg in args {
                collect_used_data_plane_imports_from_expr(arg, seen, used);
            }
        }
        ast::Expr::UnsafeBlock { .. } => {}
        ast::Expr::FieldAccess { base, .. } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_used_data_plane_imports_from_expr(value, seen, used);
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_used_data_plane_imports_from_expr(body, seen, used);
        }
        ast::Expr::Group(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_used_data_plane_imports_from_expr(inner, seen, used);
        }
        ast::Expr::Unary { expr, .. } => {
            collect_used_data_plane_imports_from_expr(expr, seen, used);
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_used_data_plane_imports_from_expr(try_expr, seen, used);
            collect_used_data_plane_imports_from_expr(catch_expr, seen, used);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_used_data_plane_imports_from_expr(condition, seen, used);
            collect_used_data_plane_imports_from_expr(then_expr, seen, used);
            collect_used_data_plane_imports_from_expr(else_expr, seen, used);
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_used_data_plane_imports_from_expr(left, seen, used);
            collect_used_data_plane_imports_from_expr(right, seen, used);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_used_data_plane_imports_from_expr(start, seen, used);
            collect_used_data_plane_imports_from_expr(end, seen, used);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_used_data_plane_imports_from_expr(item, seen, used);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_used_data_plane_imports_from_expr(base, seen, used);
            collect_used_data_plane_imports_from_expr(index, seen, used);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

struct ResolvedSource {
    source_path: PathBuf,
    project_root: PathBuf,
    manifest: Option<manifest::Manifest>,
    dependency_graph_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WorkspacePolicyFile {
    #[serde(default)]
    policy: WorkspacePolicySection,
    #[serde(default)]
    packages: HashMap<String, WorkspacePolicySection>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct WorkspacePolicySection {
    language_tier: Option<String>,
    allow_experimental: Option<bool>,
    unsafe_enforce_verify: Option<bool>,
    unsafe_enforce_release: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockfileMode {
    ValidateOrCreate,
    ForceRewrite,
}

fn resolve_source_path(input: &Path) -> Result<ResolvedSource> {
    resolve_source_path_with_target(input, false)
}

fn resolve_source_path_with_target(
    input: &Path,
    prefer_lib_target: bool,
) -> Result<ResolvedSource> {
    if input.is_file() {
        let root = input
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedSource {
            source_path: input.to_path_buf(),
            project_root: root,
            manifest: None,
            dependency_graph_hash: None,
        });
    }
    if !input.is_dir() {
        return Err(anyhow!(
            "path is neither a source file nor a project directory: {}",
            input.display()
        ));
    }

    let (manifest, manifest_path, dependency_graph_hash) =
        load_manifest(input, LockfileMode::ValidateOrCreate)?;

    let relative = if prefer_lib_target {
        manifest
            .target
            .lib
            .as_ref()
            .map(|lib| lib.path.as_str())
            .or_else(|| manifest.primary_bin_path())
            .ok_or_else(|| {
                anyhow!(
                    "no [target.lib] or [[target.bin]] entry in {}",
                    manifest_path.display()
                )
            })?
    } else {
        manifest
            .primary_bin_path()
            .ok_or_else(|| anyhow!("no [[target.bin]] entry in {}", manifest_path.display()))?
    };
    Ok(ResolvedSource {
        source_path: input.join(relative),
        project_root: input.to_path_buf(),
        manifest: Some(manifest),
        dependency_graph_hash: Some(dependency_graph_hash),
    })
}

fn load_manifest(
    dir: &Path,
    lock_mode: LockfileMode,
) -> Result<(manifest::Manifest, std::path::PathBuf, String)> {
    let primary = dir.join("fozzy.toml");
    let contents = std::fs::read_to_string(&primary)
        .with_context(|| format!("no valid compiler manifest found at {}", primary.display()))?;
    let mut parsed = manifest::load(&contents).context("failed parsing fozzy.toml")?;
    apply_workspace_policy(dir, &mut parsed)?;
    parsed
        .validate()
        .map_err(|err| anyhow!("invalid fozzy.toml: {err}"))?;
    validate_dependency_paths(dir, &parsed)?;
    let graph_hash = write_lockfile(dir, &parsed, &contents, lock_mode)?;
    Ok((parsed, primary, graph_hash))
}

fn apply_workspace_policy(dir: &Path, manifest: &mut manifest::Manifest) -> Result<()> {
    let Some((_, policy)) = load_workspace_policy(dir)? else {
        return Ok(());
    };
    let mut merged = policy.policy.clone();
    if let Some(package_override) = policy.packages.get(&manifest.package.name) {
        if package_override.language_tier.is_some() {
            merged.language_tier = package_override.language_tier.clone();
        }
        if package_override.allow_experimental.is_some() {
            merged.allow_experimental = package_override.allow_experimental;
        }
        if package_override.unsafe_enforce_verify.is_some() {
            merged.unsafe_enforce_verify = package_override.unsafe_enforce_verify;
        }
        if package_override.unsafe_enforce_release.is_some() {
            merged.unsafe_enforce_release = package_override.unsafe_enforce_release;
        }
    }

    if let Some(tier) = merged.language_tier {
        manifest.language.tier = tier;
    }
    if let Some(allow) = merged.allow_experimental {
        manifest.language.allow_experimental = allow;
    }
    if let Some(value) = merged.unsafe_enforce_verify {
        manifest.unsafe_policy.enforce_verify = Some(value);
    }
    if let Some(value) = merged.unsafe_enforce_release {
        manifest.unsafe_policy.enforce_release = Some(value);
    }
    Ok(())
}

fn load_workspace_policy(dir: &Path) -> Result<Option<(PathBuf, WorkspacePolicyFile)>> {
    let mut cursor = Some(dir.to_path_buf());
    while let Some(current) = cursor {
        let candidate = current.join("fozzy.workspace.toml");
        if candidate.exists() {
            let text = std::fs::read_to_string(&candidate)
                .with_context(|| format!("failed reading {}", candidate.display()))?;
            let parsed: WorkspacePolicyFile = toml::from_str(&text)
                .with_context(|| format!("failed parsing {}", candidate.display()))?;
            return Ok(Some((candidate, parsed)));
        }
        cursor = current.parent().map(Path::to_path_buf);
    }
    Ok(None)
}

fn validate_dependency_paths(dir: &Path, manifest: &manifest::Manifest) -> Result<()> {
    for (name, dependency) in &manifest.deps {
        if let manifest::Dependency::Path { path } = dependency {
            let resolved = dir.join(path);
            if !resolved.exists() {
                return Err(anyhow!(
                    "path dependency `{}` not found at {}",
                    name,
                    resolved.display()
                ));
            }
        }
    }
    Ok(())
}

pub fn refresh_lockfile(dir: &Path) -> Result<String> {
    let (_, _, graph_hash) = load_manifest(dir, LockfileMode::ForceRewrite)?;
    Ok(graph_hash)
}

fn write_lockfile(
    dir: &Path,
    manifest: &manifest::Manifest,
    root_manifest_contents: &str,
    mode: LockfileMode,
) -> Result<String> {
    let root_manifest_hash = sha256_hex(root_manifest_contents.as_bytes());
    let graph = build_dependency_graph(dir, manifest, &root_manifest_hash)?;
    let graph_bytes = serde_json::to_vec(&graph)?;
    let graph_hash = sha256_hex(&graph_bytes);
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.lock.v0",
        "dependencyGraphHash": graph_hash,
        "graph": graph,
    });
    let lock_path = dir.join("fozzy.lock");
    let should_write = match mode {
        LockfileMode::ForceRewrite => true,
        LockfileMode::ValidateOrCreate => {
            if !lock_path.exists() {
                true
            } else {
                let existing_text = std::fs::read_to_string(&lock_path)
                    .with_context(|| format!("failed reading lockfile: {}", lock_path.display()))?;
                let existing_json: serde_json::Value = serde_json::from_str(&existing_text)
                    .with_context(|| format!("failed parsing lockfile: {}", lock_path.display()))?;
                let existing_hash = existing_json
                    .get("dependencyGraphHash")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let existing_graph = existing_json.get("graph").cloned().unwrap_or_default();
                let existing_schema = existing_json
                    .get("schemaVersion")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                if existing_schema == "fozzylang.lock.v0"
                    && existing_hash == graph_hash
                    && existing_graph == graph
                {
                    false
                } else {
                    return Err(anyhow!(
                        "lockfile drift detected at {}: expected dependencyGraphHash={} (run `fz vendor {}` to refresh)",
                        lock_path.display(),
                        graph_hash,
                        dir.display()
                    ));
                }
            }
        }
    };
    if should_write {
        std::fs::write(&lock_path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("failed writing lockfile: {}", lock_path.display()))?;
    }
    Ok(graph_hash)
}

fn build_dependency_graph(
    dir: &Path,
    manifest: &manifest::Manifest,
    root_manifest_hash: &str,
) -> Result<serde_json::Value> {
    let mut dep_entries = Vec::new();
    for (name, dependency) in &manifest.deps {
        match dependency {
            manifest::Dependency::Path { path } => {
                let resolved = dir.join(path);
                let canonical = resolved.canonicalize().with_context(|| {
                    format!(
                        "failed canonicalizing path dependency `{}` at {}",
                        name,
                        resolved.display()
                    )
                })?;
                let dep_manifest_path = canonical.join("fozzy.toml");
                let dep_manifest_text =
                    std::fs::read_to_string(&dep_manifest_path).with_context(|| {
                        format!(
                            "path dependency `{}` missing manifest at {}",
                            name,
                            dep_manifest_path.display()
                        )
                    })?;
                let dep_manifest = manifest::load(&dep_manifest_text).with_context(|| {
                    format!(
                        "failed parsing dependency manifest for `{}` at {}",
                        name,
                        dep_manifest_path.display()
                    )
                })?;
                dep_manifest.validate().map_err(|err| {
                    anyhow!(
                        "invalid dependency manifest for `{}` at {}: {}",
                        name,
                        dep_manifest_path.display(),
                        err
                    )
                })?;
                let dep_source_hash = hash_directory_tree(&canonical)?;
                dep_entries.push(serde_json::json!({
                    "name": name,
                    "sourceType": "path",
                    "path": normalize_rel_path(path),
                    "canonicalPath": canonical.display().to_string(),
                    "package": {
                        "name": dep_manifest.package.name,
                        "version": dep_manifest.package.version,
                    },
                    "manifestHash": sha256_hex(dep_manifest_text.as_bytes()),
                    "sourceHash": dep_source_hash,
                }));
            }
            manifest::Dependency::Version { version, source } => {
                let source_locator = source
                    .clone()
                    .unwrap_or_else(|| "registry+https://crates.io".to_string());
                let source_hash =
                    sha256_hex(format!("version:{name}:{version}:{source_locator}").as_bytes());
                dep_entries.push(serde_json::json!({
                    "name": name,
                    "sourceType": "version",
                    "version": version,
                    "source": source_locator,
                    "sourceHash": source_hash,
                }));
            }
            manifest::Dependency::Git { git, rev } => {
                let source_hash = sha256_hex(format!("git:{name}:{git}:{rev}").as_bytes());
                dep_entries.push(serde_json::json!({
                    "name": name,
                    "sourceType": "git",
                    "git": git,
                    "rev": rev,
                    "sourceHash": source_hash,
                }));
            }
        }
    }
    Ok(serde_json::json!({
        "package": {
            "name": manifest.package.name,
            "version": manifest.package.version,
            "manifestHash": root_manifest_hash,
        },
        "deps": dep_entries,
    }))
}

fn normalize_rel_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn hash_directory_tree(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    let mut hasher = Sha256::new();
    for (rel, full) in files {
        hasher.update(rel.as_bytes());
        let bytes = std::fs::read(&full).with_context(|| {
            format!(
                "failed reading dependency file for hashing: {}",
                full.display()
            )
        })?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn collect_files_recursive(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(current)
        .with_context(|| format!("failed reading dependency directory: {}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed iterating dependency directory: {}",
                current.display()
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let full = entry.path();
        let rel = full
            .strip_prefix(root)
            .with_context(|| format!("failed deriving relative path for {}", full.display()))?;
        let rel_str = normalize_rel_path(&rel.display().to_string());
        if should_skip_hash_path(&rel_str) {
            continue;
        }
        if entry
            .file_type()
            .with_context(|| format!("failed reading file type for {}", full.display()))?
            .is_dir()
        {
            collect_files_recursive(root, &full, out)?;
        } else {
            out.push((rel_str, full));
        }
    }
    Ok(())
}

fn should_skip_hash_path(rel: &str) -> bool {
    rel.starts_with(".git/")
        || rel.starts_with(".fz/")
        || rel.starts_with("vendor/")
        || rel.starts_with("target/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn emit_native_artifact(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<PathBuf> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => emit_native_artifact_llvm(fir, project_root, profile, manifest),
        "cranelift" => emit_native_artifact_cranelift(fir, project_root, profile, manifest),
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn emit_native_libraries(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => emit_native_libraries_llvm(fir, project_root, profile, manifest),
        "cranelift" => emit_native_libraries_cranelift(fir, project_root, profile, manifest),
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn emit_native_libraries_llvm(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{}.ll", fir.name));
    let obj_path = build_dir.join(format!("{}.ffi.o", fir.name));
    let shim_obj_path = build_dir.join(format!("{}.ffi.runtime.o", fir.name));
    let static_path = build_dir.join(format!("lib{}.a", fir.name));
    let shared_path = build_dir.join(format!("lib{}.{}", fir.name, shared_lib_extension()));

    let string_literals = collect_native_string_literals(fir);
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(fir, enforce_contract_checks)?;
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut obj_compiled = false;
    let mut shim_compiled = false;
    let mut last_error = None;
    for tool in &candidates {
        let mut obj_cmd = Command::new(tool);
        obj_cmd
            .arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(&obj_path);
        apply_target_link_flags(&mut obj_cmd);
        apply_profile_optimization_flags(&mut obj_cmd, profile, manifest);
        apply_pgo_flags(&mut obj_cmd)?;
        match obj_cmd.output() {
            Ok(output) if output.status.success() => {
                obj_compiled = true;
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling llvm object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
                continue;
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
                continue;
            }
        }

        let mut shim_cmd = Command::new(tool);
        shim_cmd
            .arg("-x")
            .arg("c")
            .arg(&runtime_shim_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(&shim_obj_path);
        apply_target_link_flags(&mut shim_cmd);
        apply_profile_optimization_flags(&mut shim_cmd, profile, manifest);
        apply_pgo_flags(&mut shim_cmd)?;
        match shim_cmd.output() {
            Ok(output) if output.status.success() => {
                shim_compiled = true;
                break;
            }
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling runtime shim object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    if !obj_compiled || !shim_compiled {
        return Err(anyhow!(
            "failed compiling ffi library objects: {}",
            last_error.unwrap_or_else(|| "unknown compiler error".to_string())
        ));
    }

    create_static_archive(&static_path, &[obj_path.as_path(), shim_obj_path.as_path()])?;
    let allow_undefined = !collect_extern_c_imports(fir).is_empty();
    link_shared_library(
        &shared_path,
        &[obj_path.as_path(), shim_obj_path.as_path()],
        manifest,
        allow_undefined,
    )?;
    Ok((Some(static_path), Some(shared_path)))
}

fn emit_native_libraries_cranelift(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let object_path = build_dir.join(format!("{}.ffi.o", fir.name));
    let shim_obj_path = build_dir.join(format!("{}.ffi.runtime.o", fir.name));
    let static_path = build_dir.join(format!("lib{}.a", fir.name));
    let shared_path = build_dir.join(format!("lib{}.{}", fir.name, shared_lib_extension()));

    let string_literals = collect_native_string_literals(fir);
    let plan = build_native_canonical_plan(fir, true);
    let mut flags_builder = settings::builder();
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    let opt_level = match (profile, optimize_override) {
        (_, Some(true)) => "speed",
        (_, Some(false)) => "none",
        (BuildProfile::Dev, None) => "none",
        (BuildProfile::Release, None) => "speed",
        (BuildProfile::Verify, None) => "speed",
    };
    flags_builder
        .set("opt_level", opt_level)
        .map_err(|error| anyhow!("failed setting cranelift opt_level={opt_level}: {error}"))?;
    flags_builder
        .set("is_pic", "true")
        .map_err(|error| anyhow!("failed enabling cranelift PIC codegen: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;
    let object_builder = ObjectBuilder::new(isa, fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);

    let mut function_ids = HashMap::new();
    let mut function_signatures = HashMap::new();
    let mut mutable_global_data_ids = HashMap::<String, cranelift_module::DataId>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(&name);
        let data_id = module
            .declare_data(&symbol, Linkage::Local, true, false)
            .map_err(|error| anyhow!("failed declaring mutable static `{name}` data: {error}"))?;
        let mut data = DataDescription::new();
        data.define((value as i32).to_le_bytes().to_vec().into_boxed_slice());
        module
            .define_data(data_id, &data)
            .map_err(|error| anyhow!("failed defining mutable static `{name}` data: {error}"))?;
        mutable_global_data_ids.insert(name, data_id);
    }
    for function in &fir.typed_functions {
        let mut sig = module.make_signature();
        let mut param_tys = Vec::new();
        for param in &function.params {
            let ty = ast_signature_type_to_clif_type(&param.ty)
                .ok_or_else(|| anyhow!("unsupported native parameter type `{}`", param.ty))?;
            sig.params.push(AbiParam::new(ty));
            param_tys.push(ty);
        }
        let ret_ty = ast_signature_type_to_clif_type(&function.return_type);
        if let Some(ret_ty) = ret_ty {
            sig.returns.push(AbiParam::new(ret_ty));
        }
        let linkage = if is_extern_c_import_decl(function) {
            Linkage::Import
        } else {
            Linkage::Export
        };
        let symbol_name = if is_extern_c_import_decl(function) {
            function.name.clone()
        } else {
            native_mangle_symbol(&function.name)
        };
        let id = module
            .declare_function(symbol_name.as_str(), linkage, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring cranelift ffi symbol `{}`: {error}",
                    function.name
                )
            })?;
        function_ids.insert(function.name.clone(), id);
        function_signatures.insert(
            function.name.clone(),
            ClifFunctionSignature {
                params: param_tys,
                ret: ret_ty,
            },
        );
    }
    declare_native_runtime_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    declare_native_data_plane_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        let signature = function_signatures
            .get(&function.name)
            .ok_or_else(|| anyhow!("missing signature for `{}`", function.name))?;
        for param_ty in &signature.params {
            context.func.signature.params.push(AbiParam::new(*param_ty));
        }
        if let Some(ret_ty) = signature.ret {
            context.func.signature.returns.push(AbiParam::new(ret_ty));
        }

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);

        let mut locals = HashMap::<String, LocalBinding>::new();
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(index as u32);
            let param_ty =
                signature.params.get(index).copied().ok_or_else(|| {
                    anyhow!("missing param {} type for `{}`", index, function.name)
                })?;
            builder.declare_var(var, param_ty);
            let value = builder.block_params(entry)[index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), LocalBinding { var, ty: param_ty });
        }
        let mut next_var = function.params.len();
        let cfg = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => cfg,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        {
            let mut ctx = ClifLoweringCtx {
                module: &mut module,
                function_ids: &function_ids,
                function_signatures: &function_signatures,
                string_literal_ids: &plan.string_literal_ids,
                task_ref_ids: &plan.task_ref_ids,
                globals: &plan.global_const_i32,
                variant_tags: &plan.variant_tags,
                mutable_globals: &mutable_global_data_ids,
                closures: HashMap::new(),
                array_bindings: HashMap::new(),
                const_strings: HashMap::new(),
            };
            clif_emit_cfg(
                &mut builder,
                &mut ctx,
                &cfg,
                entry,
                &mut locals,
                signature.ret,
                &mut next_var,
                None,
            )?;
        }
        builder.finalize();
        module
            .define_function(function_id, &mut context)
            .map_err(|error| {
                anyhow!(
                    "failed defining cranelift ffi function `{}`: {error}",
                    function.name
                )
            })?;
        module.clear_context(&mut context);
    }
    let object_product = module.finish();
    let object_bytes = object_product
        .emit()
        .map_err(|error| anyhow!("failed emitting cranelift object bytes: {error}"))?;
    std::fs::write(&object_path, object_bytes).with_context(|| {
        format!(
            "failed writing cranelift ffi object: {}",
            object_path.display()
        )
    })?;

    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;
    compile_runtime_shim_object(&runtime_shim_path, &shim_obj_path, profile, manifest)?;
    create_static_archive(
        &static_path,
        &[object_path.as_path(), shim_obj_path.as_path()],
    )?;
    let allow_undefined = !collect_extern_c_imports(fir).is_empty();
    link_shared_library(
        &shared_path,
        &[object_path.as_path(), shim_obj_path.as_path()],
        manifest,
        allow_undefined,
    )?;
    Ok((Some(static_path), Some(shared_path)))
}

fn compile_runtime_shim_object(
    runtime_shim_path: &Path,
    out_object: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("c")
            .arg(runtime_shim_path)
            .arg("-c")
            .arg("-fPIC")
            .arg("-o")
            .arg(out_object);
        apply_target_link_flags(&mut cmd);
        apply_profile_optimization_flags(&mut cmd, profile, manifest);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed compiling runtime shim object: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed to compile runtime shim object: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

fn create_static_archive(output: &Path, objects: &[&Path]) -> Result<()> {
    let candidates = archiver_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("rcs").arg(output);
        for object in objects {
            cmd.arg(object);
        }
        match cmd.output() {
            Ok(output_result) if output_result.status.success() => return Ok(()),
            Ok(output_result) => {
                last_error = Some(format!(
                    "{} failed creating static archive: {}",
                    tool,
                    String::from_utf8_lossy(&output_result.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed to create static archive {}: {}",
        output.display(),
        last_error.unwrap_or_else(|| "unknown archiver error".to_string())
    ))
}

fn link_shared_library(
    output: &Path,
    objects: &[&Path],
    manifest: Option<&manifest::Manifest>,
    allow_undefined: bool,
) -> Result<()> {
    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        if cfg!(target_vendor = "apple") {
            cmd.arg("-dynamiclib");
            if allow_undefined {
                cmd.arg("-Wl,-undefined,dynamic_lookup");
            }
        } else {
            cmd.arg("-shared");
            if allow_undefined {
                cmd.arg("-Wl,--allow-shlib-undefined");
            }
        }
        for object in objects {
            cmd.arg(object);
        }
        cmd.arg("-o").arg(output);
        apply_target_link_flags(&mut cmd);
        apply_manifest_link_args(&mut cmd, manifest);
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;
        match cmd.output() {
            Ok(output_result) if output_result.status.success() => return Ok(()),
            Ok(output_result) => {
                last_error = Some(format!(
                    "{} failed linking shared library: {}",
                    tool,
                    String::from_utf8_lossy(&output_result.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }
    Err(anyhow!(
        "failed to link shared library {}: {}",
        output.display(),
        last_error.unwrap_or_else(|| "unknown linker error".to_string())
    ))
}

fn apply_profile_optimization_flags(
    cmd: &mut Command,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) {
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    match (profile, optimize_override) {
        (_, Some(true)) => {
            cmd.arg("-O2");
        }
        (_, Some(false)) => {
            cmd.arg("-O0");
        }
        (BuildProfile::Dev, None) => {
            cmd.arg("-O0");
        }
        (BuildProfile::Release, None) => {
            cmd.arg("-O2");
        }
        (BuildProfile::Verify, None) => {
            cmd.arg("-O1").arg("-g");
        }
    }
}

fn apply_pgo_flags(cmd: &mut Command) -> Result<()> {
    let pgo = configured_pgo();
    if let Some(dir) = pgo.generate_dir {
        std::fs::create_dir_all(&dir).with_context(|| {
            format!(
                "failed creating PGO profile generation directory: {}",
                dir.display()
            )
        })?;
        cmd.arg(format!("-fprofile-generate={}", dir.display()));
    }
    if let Some(profile) = pgo.use_profile {
        if !profile.exists() {
            bail!("PGO profile data not found: {}", profile.display());
        }
        cmd.arg(format!("-fprofile-use={}", profile.display()));
        cmd.arg("-fprofile-correction");
    }
    Ok(())
}

fn archiver_candidates() -> Vec<String> {
    if let Ok(explicit) = std::env::var("FZ_AR") {
        if !explicit.trim().is_empty() {
            return vec![explicit];
        }
    }
    vec!["ar".to_string()]
}

fn shared_lib_extension() -> &'static str {
    if cfg!(target_vendor = "apple") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
    }
}

fn resolve_native_backend(profile: BuildProfile, backend_override: Option<&str>) -> Result<String> {
    if let Some(explicit) = backend_override {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown backend `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    if let Ok(explicit) = std::env::var("FZ_NATIVE_BACKEND") {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    Ok(match profile {
        BuildProfile::Release => "llvm".to_string(),
        BuildProfile::Dev => "cranelift".to_string(),
        BuildProfile::Verify => "llvm".to_string(),
    })
}

fn emit_native_artifact_llvm(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{}.ll", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let string_literals = collect_native_string_literals(fir);
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(fir, enforce_contract_checks)?;
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-x")
            .arg("c")
            .arg(&runtime_shim_path)
            .arg("-o")
            .arg(&bin_path);
        apply_target_link_flags(&mut cmd);
        apply_manifest_link_args(&mut cmd, manifest);
        let optimize_override = manifest
            .and_then(|manifest| profile_config(manifest, profile))
            .and_then(|config| config.optimize);
        match (profile, optimize_override) {
            (_, Some(true)) => {
                cmd.arg("-O2");
            }
            (_, Some(false)) => {
                cmd.arg("-O0");
            }
            (BuildProfile::Dev, None) => {
                cmd.arg("-O0");
            }
            (BuildProfile::Release, None) => {
                cmd.arg("-O2");
            }
            (BuildProfile::Verify, None) => {
                cmd.arg("-O1").arg("-g");
            }
        }
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;

        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(bin_path),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }

    Err(anyhow!(
        "failed to compile llvm native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

fn emit_native_artifact_cranelift(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let object_path = build_dir.join(format!("{}.o", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let string_literals = collect_native_string_literals(fir);
    let mut flags_builder = settings::builder();
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    let opt_level = match (profile, optimize_override) {
        (_, Some(true)) => "speed",
        (_, Some(false)) => "none",
        (BuildProfile::Dev, None) => "none",
        (BuildProfile::Release, None) => "speed",
        (BuildProfile::Verify, None) => "speed",
    };
    flags_builder
        .set("opt_level", opt_level)
        .map_err(|error| anyhow!("failed setting cranelift opt_level={opt_level}: {error}"))?;
    flags_builder
        .set("is_pic", "true")
        .map_err(|error| anyhow!("failed enabling cranelift PIC codegen: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;

    let object_builder = ObjectBuilder::new(isa, fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);

    let mut function_ids = HashMap::new();
    let mut function_signatures = HashMap::new();
    let mut mutable_global_data_ids = HashMap::<String, cranelift_module::DataId>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(&name);
        let data_id = module
            .declare_data(&symbol, Linkage::Local, true, false)
            .map_err(|error| anyhow!("failed declaring mutable static `{name}` data: {error}"))?;
        let mut data = DataDescription::new();
        data.define((value as i32).to_le_bytes().to_vec().into_boxed_slice());
        module
            .define_data(data_id, &data)
            .map_err(|error| anyhow!("failed defining mutable static `{name}` data: {error}"))?;
        mutable_global_data_ids.insert(name, data_id);
    }
    for function in &fir.typed_functions {
        let mut sig = module.make_signature();
        let mut param_tys = Vec::new();
        for param in &function.params {
            let ty = ast_signature_type_to_clif_type(&param.ty)
                .ok_or_else(|| anyhow!("unsupported native parameter type `{}`", param.ty))?;
            sig.params.push(AbiParam::new(ty));
            param_tys.push(ty);
        }
        let ret_ty = ast_signature_type_to_clif_type(&function.return_type);
        if let Some(ret_ty) = ret_ty {
            sig.returns.push(AbiParam::new(ret_ty));
        }
        let linkage = if is_extern_c_import_decl(function) {
            Linkage::Import
        } else {
            Linkage::Export
        };
        let symbol_name = if is_extern_c_import_decl(function) {
            function.name.clone()
        } else {
            native_mangle_symbol(&function.name)
        };
        let id = module
            .declare_function(symbol_name.as_str(), linkage, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring cranelift symbol `{}`: {error}",
                    function.name
                )
            })?;
        function_ids.insert(function.name.clone(), id);
        function_signatures.insert(
            function.name.clone(),
            ClifFunctionSignature {
                params: param_tys,
                ret: ret_ty,
            },
        );
    }
    declare_native_runtime_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    declare_native_data_plane_imports(&mut module, &mut function_ids, &mut function_signatures)?;
    let spawn_task_symbols = collect_spawn_task_symbols(fir);
    let async_exports = collect_async_c_exports(fir);
    let runtime_shim_path = ensure_native_runtime_shim(
        &build_dir,
        &string_literals,
        &spawn_task_symbols,
        &async_exports,
    )?;

    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        let signature = function_signatures
            .get(&function.name)
            .ok_or_else(|| anyhow!("missing signature for `{}`", function.name))?;
        for param_ty in &signature.params {
            context.func.signature.params.push(AbiParam::new(*param_ty));
        }
        if let Some(ret_ty) = signature.ret {
            context.func.signature.returns.push(AbiParam::new(ret_ty));
        }

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);

        let mut locals = HashMap::<String, LocalBinding>::new();
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(index as u32);
            let param_ty =
                signature.params.get(index).copied().ok_or_else(|| {
                    anyhow!("missing param {} type for `{}`", index, function.name)
                })?;
            builder.declare_var(var, param_ty);
            let value = builder.block_params(entry)[index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), LocalBinding { var, ty: param_ty });
        }
        let mut next_var = function.params.len();
        let cfg = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => cfg,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        {
            let mut ctx = ClifLoweringCtx {
                module: &mut module,
                function_ids: &function_ids,
                function_signatures: &function_signatures,
                string_literal_ids: &plan.string_literal_ids,
                task_ref_ids: &plan.task_ref_ids,
                globals: &plan.global_const_i32,
                variant_tags: &plan.variant_tags,
                mutable_globals: &mutable_global_data_ids,
                closures: HashMap::new(),
                array_bindings: HashMap::new(),
                const_strings: HashMap::new(),
            };
            clif_emit_cfg(
                &mut builder,
                &mut ctx,
                &cfg,
                entry,
                &mut locals,
                signature.ret,
                &mut next_var,
                if function.name == "main" && signature.ret == Some(types::I32) {
                    Some(
                        plan.forced_main_return
                            .or(fir.entry_return_const_i32)
                            .unwrap_or(0),
                    )
                } else {
                    None
                },
            )?;
        }
        builder.finalize();

        module
            .define_function(function_id, &mut context)
            .map_err(|error| {
                anyhow!(
                    "failed defining cranelift function `{}`: {error}",
                    function.name
                )
            })?;
        module.clear_context(&mut context);
    }
    let object_product = module.finish();
    let object_bytes = object_product
        .emit()
        .map_err(|error| anyhow!("failed emitting cranelift object bytes: {error}"))?;
    std::fs::write(&object_path, object_bytes)
        .with_context(|| format!("failed writing cranelift object: {}", object_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg(&object_path)
            .arg(&runtime_shim_path)
            .arg("-o")
            .arg(&bin_path)
            .arg("-lpthread");
        apply_target_link_flags(&mut cmd);
        apply_manifest_link_args(&mut cmd, manifest);
        // Object code is already generated at selected Cranelift optimization level.
        apply_extra_linker_args(&mut cmd);
        apply_pgo_flags(&mut cmd)?;

        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(bin_path),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }

    Err(anyhow!(
        "failed to link cranelift native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

struct ClifLoweringCtx<'a> {
    module: &'a mut ObjectModule,
    function_ids: &'a HashMap<String, cranelift_module::FuncId>,
    function_signatures: &'a HashMap<String, ClifFunctionSignature>,
    string_literal_ids: &'a HashMap<String, i32>,
    task_ref_ids: &'a HashMap<String, i32>,
    globals: &'a HashMap<String, i32>,
    variant_tags: &'a HashMap<String, i32>,
    mutable_globals: &'a HashMap<String, cranelift_module::DataId>,
    closures: HashMap<String, ClifClosureBinding>,
    array_bindings: HashMap<String, ClifArrayBinding>,
    const_strings: HashMap<String, String>,
}

fn clif_emit_cfg(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    cfg: &ControlFlowCfg,
    entry_block: cranelift_codegen::ir::Block,
    locals: &mut HashMap<String, LocalBinding>,
    return_ty: Option<ClifType>,
    next_var: &mut usize,
    forced_return_i32: Option<i32>,
) -> Result<()> {
    let mut clif_blocks = Vec::with_capacity(cfg.blocks.len());
    for block_id in 0..cfg.blocks.len() {
        if block_id == cfg.entry {
            clif_blocks.push(entry_block);
        } else {
            clif_blocks.push(builder.create_block());
        }
    }

    let mut predecessor_count = vec![0usize; cfg.blocks.len()];
    for block in &cfg.blocks {
        match &block.terminator {
            ControlFlowTerminator::Return(_) | ControlFlowTerminator::Unreachable => {}
            ControlFlowTerminator::Jump { target, .. } => {
                predecessor_count[*target] += 1;
            }
            ControlFlowTerminator::Branch {
                then_target,
                else_target,
                ..
            } => {
                predecessor_count[*then_target] += 1;
                predecessor_count[*else_target] += 1;
            }
            ControlFlowTerminator::Switch {
                cases,
                default_target,
                ..
            } => {
                predecessor_count[*default_target] += 1;
                for (_, target) in cases {
                    predecessor_count[*target] += 1;
                }
            }
        }
    }

    let mut observed_predecessors = vec![0usize; cfg.blocks.len()];
    let mut sealed = vec![false; cfg.blocks.len()];
    if predecessor_count[cfg.entry] == 0 {
        builder.seal_block(clif_blocks[cfg.entry]);
        sealed[cfg.entry] = true;
    }

    let mut emitted = vec![false; cfg.blocks.len()];
    let mut queue = vec![cfg.entry];
    while let Some(block_id) = queue.pop() {
        if emitted[block_id] {
            continue;
        }
        emitted[block_id] = true;
        builder.switch_to_block(clif_blocks[block_id]);
        clif_emit_linear_stmts(builder, ctx, &cfg.blocks[block_id].stmts, locals, next_var)?;
        match &cfg.blocks[block_id].terminator {
            ControlFlowTerminator::Return(Some(expr)) => {
                if let Some(return_ty) = return_ty {
                    let value = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
                    let value = cast_clif_value(builder, value, return_ty)?;
                    builder.ins().return_(&[value.value]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
            ControlFlowTerminator::Return(None) => {
                if let Some(return_ty) = return_ty {
                    let ret = if return_ty == types::I32 {
                        builder
                            .ins()
                            .iconst(types::I32, forced_return_i32.unwrap_or(0) as i64)
                    } else {
                        zero_for_type(builder, return_ty)
                    };
                    builder.ins().return_(&[ret]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
            ControlFlowTerminator::Jump { target, .. } => {
                builder.ins().jump(clif_blocks[*target], &[]);
                observed_predecessors[*target] += 1;
                if !sealed[*target] && observed_predecessors[*target] >= predecessor_count[*target]
                {
                    builder.seal_block(clif_blocks[*target]);
                    sealed[*target] = true;
                }
                queue.push(*target);
            }
            ControlFlowTerminator::Branch {
                condition,
                then_target,
                else_target,
            } => {
                let cond_val = clif_emit_expr(builder, ctx, condition, locals, next_var)?;
                let zero = zero_for_type(builder, cond_val.ty);
                let cond = builder.ins().icmp(IntCC::NotEqual, cond_val.value, zero);
                builder.ins().brif(
                    cond,
                    clif_blocks[*then_target],
                    &[],
                    clif_blocks[*else_target],
                    &[],
                );
                observed_predecessors[*then_target] += 1;
                observed_predecessors[*else_target] += 1;
                if !sealed[*then_target]
                    && observed_predecessors[*then_target] >= predecessor_count[*then_target]
                {
                    builder.seal_block(clif_blocks[*then_target]);
                    sealed[*then_target] = true;
                }
                if !sealed[*else_target]
                    && observed_predecessors[*else_target] >= predecessor_count[*else_target]
                {
                    builder.seal_block(clif_blocks[*else_target]);
                    sealed[*else_target] = true;
                }
                queue.push(*else_target);
                queue.push(*then_target);
            }
            ControlFlowTerminator::Switch {
                scrutinee,
                cases,
                default_target,
            } => {
                let cond_val = clif_emit_expr(builder, ctx, scrutinee, locals, next_var)?;
                let cond_val = cast_clif_value(builder, cond_val, default_int_clif_type())?;
                let mut switch = Switch::new();
                for (value, target) in cases {
                    switch.set_entry(*value as u128, clif_blocks[*target]);
                }
                switch.emit(builder, cond_val.value, clif_blocks[*default_target]);
                for (_, target) in cases {
                    observed_predecessors[*target] += 1;
                    if !sealed[*target]
                        && observed_predecessors[*target] >= predecessor_count[*target]
                    {
                        builder.seal_block(clif_blocks[*target]);
                        sealed[*target] = true;
                    }
                    queue.push(*target);
                }
                observed_predecessors[*default_target] += 1;
                if !sealed[*default_target]
                    && observed_predecessors[*default_target] >= predecessor_count[*default_target]
                {
                    builder.seal_block(clif_blocks[*default_target]);
                    sealed[*default_target] = true;
                }
                queue.push(*default_target);
            }
            ControlFlowTerminator::Unreachable => {
                if let Some(return_ty) = return_ty {
                    let ret = zero_for_type(builder, return_ty);
                    builder.ins().return_(&[ret]);
                } else {
                    builder.ins().return_(&[]);
                }
            }
        }
    }

    if emitted.iter().any(|done| !*done) {
        bail!("cranelift cfg emission left one or more reachable blocks un-emitted");
    }
    for (index, block) in clif_blocks.iter().enumerate() {
        if !sealed[index] {
            builder.seal_block(*block);
            sealed[index] = true;
        }
    }
    Ok(())
}

fn clif_snapshot_closure_captures(
    builder: &mut FunctionBuilder,
    locals: &HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> HashMap<String, LocalBinding> {
    let mut captures = HashMap::new();
    for (name, binding) in locals {
        let captured_var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(captured_var, binding.ty);
        let current = builder.use_var(binding.var);
        builder.def_var(captured_var, current);
        captures.insert(
            name.clone(),
            LocalBinding {
                var: captured_var,
                ty: binding.ty,
            },
        );
    }
    captures
}

fn clif_restore_shadowed_locals(
    locals: &mut HashMap<String, LocalBinding>,
    saved: HashMap<String, Option<LocalBinding>>,
    inserted: HashSet<String>,
) {
    for (name, prior) in saved {
        if let Some(binding) = prior {
            locals.insert(name, binding);
        } else if inserted.contains(&name) {
            locals.remove(&name);
        }
    }
}

fn clif_emit_inlined_closure_call(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    binding: ClifClosureBinding,
    args: &[ast::Expr],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    let mut cast_args = Vec::with_capacity(binding.params.len());
    for (index, param) in binding.params.iter().enumerate() {
        let arg = args.get(index).cloned().unwrap_or(ast::Expr::Int(0));
        let mut lowered = clif_emit_expr(builder, ctx, &arg, locals, next_var)?;
        if let Some(target_ty) = ast_signature_type_to_clif_type(&param.ty) {
            lowered = cast_clif_value(builder, lowered, target_ty)?;
        }
        cast_args.push(lowered);
    }

    let mut saved = HashMap::<String, Option<LocalBinding>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), locals.get(name).copied());
        }
        locals.insert(name.clone(), *capture);
        inserted.insert(name.clone());
    }

    for (index, param) in binding.params.iter().enumerate() {
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), locals.get(&param.name).copied());
        }
        let target_ty = ast_signature_type_to_clif_type(&param.ty).unwrap_or(cast_args[index].ty);
        let var = Variable::from_u32(*next_var as u32);
        *next_var += 1;
        builder.declare_var(var, target_ty);
        let value = cast_clif_value(builder, cast_args[index], target_ty)?;
        builder.def_var(var, value.value);
        locals.insert(param.name.clone(), LocalBinding { var, ty: target_ty });
        inserted.insert(param.name.clone());
    }

    let mut result = clif_emit_expr(builder, ctx, &binding.body, locals, next_var)?;
    if let Some(return_ty) = &binding.return_type {
        if let Some(target_ty) = ast_signature_type_to_clif_type(return_ty) {
            result = cast_clif_value(builder, result, target_ty)?;
        }
    }
    clif_restore_shadowed_locals(locals, saved, inserted);
    Ok(result)
}

fn clif_emit_let_pattern(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    pattern: &ast::Pattern,
    value: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    let lowered = clif_emit_expr(builder, ctx, value, locals, next_var)?;
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let var = Variable::from_u32(*next_var as u32);
            *next_var += 1;
            builder.declare_var(var, lowered.ty);
            builder.def_var(var, lowered.value);
            locals.insert(
                name.clone(),
                LocalBinding {
                    var,
                    ty: lowered.ty,
                },
            );
        }
        ast::Pattern::Int(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, *expected as i64);
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Bool(expected) => {
            let expected_value = builder.ins().iconst(lowered.ty, i64::from(*expected));
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_value);
        }
        ast::Pattern::Struct { name, fields } => {
            let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = value
            else {
                bail!("native backend requires literal struct initializer for `let` struct destructuring");
            };
            if value_name != name {
                bail!(
                    "native backend requires exact literal struct type match for `let` struct destructuring"
                );
            }
            for (field_name, binding_name) in fields {
                if binding_name == "_" {
                    continue;
                }
                let Some((_, field_expr)) =
                    value_fields.iter().find(|(field, _)| field == field_name)
                else {
                    bail!("native backend requires struct literal fields to cover every bound pattern field");
                };
                let payload_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                let var = Variable::from_u32(*next_var as u32);
                *next_var += 1;
                builder.declare_var(var, payload_val.ty);
                builder.def_var(var, payload_val.value);
                locals.insert(
                    binding_name.clone(),
                    LocalBinding {
                        var,
                        ty: payload_val.ty,
                    },
                );
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
        } => {
            let key = format!("{enum_name}::{variant}");
            let expected_tag = builder.ins().iconst(
                lowered.ty,
                variant_tag_for_key(&key, ctx.variant_tags) as i64,
            );
            let _ = builder
                .ins()
                .icmp(IntCC::Equal, lowered.value, expected_tag);
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
            } = value
            {
                if value_enum == enum_name
                    && value_variant == variant
                    && payload.len() == bindings.len()
                {
                    for (binding_name, payload_expr) in bindings.iter().zip(payload.iter()) {
                        let payload_val =
                            clif_emit_expr(builder, ctx, payload_expr, locals, next_var)?;
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, payload_val.ty);
                        builder.def_var(var, payload_val.value);
                        locals.insert(
                            binding_name.clone(),
                            LocalBinding {
                                var,
                                ty: payload_val.ty,
                            },
                        );
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns
                .iter()
                .find(|pattern| pattern_matches_resolved_scrutinee(pattern, value, ctx.variant_tags))
            {
                return clif_emit_let_pattern(
                    builder,
                    ctx,
                    matched,
                    value,
                    locals,
                    next_var,
                );
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable initializer for payload or struct-field bindings in `let` or-patterns"
                );
            }
        }
    }
    Ok(())
}

fn clif_emit_linear_stmts(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    body: &[ast::Stmt],
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<()> {
    for stmt in body {
        match stmt {
            ast::Stmt::Let {
                name, value, ty, ..
            } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(name.clone(), const_value);
                    ctx.array_bindings.remove(name);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        name.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(name.clone(), source_bindings);
                        continue;
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        name.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    continue;
                }
                let mut val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                let target_ty = ty
                    .as_ref()
                    .and_then(ast_signature_type_to_clif_type)
                    .unwrap_or(val.ty);
                val = cast_clif_value(builder, val, target_ty)?;
                let binding = if let Some(existing) = locals.get(name).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, target_ty);
                    let binding = LocalBinding { var, ty: target_ty };
                    locals.insert(name.clone(), binding);
                    binding
                };
                let val = cast_clif_value(builder, val, binding.ty)?;
                builder.def_var(binding.var, val.value);
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_val = clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                    let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                    let inclusive_val = ClifValue {
                        value: builder.ins().iconst(default_int_clif_type(), i64::from(*inclusive)),
                        ty: default_int_clif_type(),
                    };
                    for (field, field_val) in [
                        ("start", start_val),
                        ("end", end_val),
                        ("inclusive", inclusive_val),
                    ] {
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, field_val.ty);
                        builder.def_var(field_var, field_val.value);
                        locals.insert(
                            format!("{name}.{field}"),
                            LocalBinding {
                                var: field_var,
                                ty: field_val.ty,
                            },
                        );
                    }
                }
                ctx.array_bindings.remove(name);
                ctx.const_strings.remove(name);
            }
            ast::Stmt::LetPattern { pattern, value, .. } => {
                clif_emit_let_pattern(builder, ctx, pattern, value, locals, next_var)?;
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(target.clone(), const_value);
                    ctx.array_bindings.remove(target);
                    continue;
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    ctx.closures.insert(
                        target.clone(),
                        ClifClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures: clif_snapshot_closure_captures(builder, locals, next_var),
                        },
                    );
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let mut lowered_items = Vec::with_capacity(items.len());
                    for item in items {
                        lowered_items.push(clif_emit_expr(builder, ctx, item, locals, next_var)?);
                    }
                    let (element_ty, element_bits, element_align, element_stride) =
                        clif_array_layout_from_values(&lowered_items);
                    let slot_size = (lowered_items.len() as u32) * u32::from(element_stride);
                    let align_shift = element_align.trailing_zeros() as u8;
                    let stack_slot =
                        builder.create_sized_stack_slot(cranelift_codegen::ir::StackSlotData::new(
                            cranelift_codegen::ir::StackSlotKind::ExplicitSlot,
                            slot_size,
                            align_shift,
                        ));
                    for (idx, mut item_val) in lowered_items.into_iter().enumerate() {
                        item_val = cast_clif_value(builder, item_val, element_ty)?;
                        let ptr = builder.ins().stack_addr(
                            pointer_sized_clif_type(),
                            stack_slot,
                            (idx as i32) * i32::from(element_stride),
                        );
                        builder.ins().store(MemFlags::new(), item_val.value, ptr, 0);
                    }
                    ctx.array_bindings.insert(
                        target.clone(),
                        ClifArrayBinding {
                            stack_slot,
                            len: items.len(),
                            element_ty,
                            element_bits,
                            element_align,
                            element_stride,
                        },
                    );
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_bindings) = ctx.array_bindings.get(source).cloned() {
                        ctx.array_bindings.insert(target.clone(), source_bindings);
                        continue;
                    }
                }
                let val = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                    if let ast::Expr::StructInit { fields, .. } = value {
                        for (field, field_expr) in fields {
                            let field_val =
                                clif_emit_expr(builder, ctx, field_expr, locals, next_var)?;
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                    if let ast::Expr::Range {
                        start,
                        end,
                        inclusive,
                    } = value
                    {
                        let start_val = clif_emit_expr(builder, ctx, start, locals, next_var)?;
                        let end_val = clif_emit_expr(builder, ctx, end, locals, next_var)?;
                        let inclusive_val = ClifValue {
                            value: builder
                                .ins()
                                .iconst(default_int_clif_type(), i64::from(*inclusive)),
                            ty: default_int_clif_type(),
                        };
                        for (field, field_val) in [
                            ("start", start_val),
                            ("end", end_val),
                            ("inclusive", inclusive_val),
                        ] {
                            let field_var = Variable::from_u32(*next_var as u32);
                            *next_var += 1;
                            builder.declare_var(field_var, field_val.ty);
                            builder.def_var(field_var, field_val.value);
                            locals.insert(
                                format!("{target}.{field}"),
                                LocalBinding {
                                    var: field_var,
                                    ty: field_val.ty,
                                },
                            );
                        }
                    }
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::CompoundAssign { target, op, value } => {
                let combined_expr = ast::Expr::Binary {
                    op: *op,
                    left: Box::new(ast::Expr::Ident(target.clone())),
                    right: Box::new(value.clone()),
                };
                let val = clif_emit_expr(builder, ctx, &combined_expr, locals, next_var)?;
                if let Some(data_id) = ctx.mutable_globals.get(target).copied() {
                    let val = cast_clif_value(builder, val, types::I32)?;
                    let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                    let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                    builder.ins().store(MemFlags::new(), val.value, ptr, 0);
                } else {
                    let binding = if let Some(existing) = locals.get(target).copied() {
                        existing
                    } else {
                        let var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(var, val.ty);
                        let binding = LocalBinding { var, ty: val.ty };
                        locals.insert(target.clone(), binding);
                        binding
                    };
                    let val = cast_clif_value(builder, val, binding.ty)?;
                    builder.def_var(binding.var, val.value);
                }
                ctx.array_bindings.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::Expr(expr)
            | ast::Stmt::Requires(expr)
            | ast::Stmt::Ensures(expr)
            | ast::Stmt::Defer(expr) => {
                let _ = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
            }
            ast::Stmt::Return(_)
            | ast::Stmt::If { .. }
            | ast::Stmt::While { .. }
            | ast::Stmt::For { .. }
            | ast::Stmt::ForIn { .. }
            | ast::Stmt::Loop { .. }
            | ast::Stmt::Break(_) | ast::Stmt::Continue
            | ast::Stmt::Match { .. } => {
                bail!("cranelift linear emission received non-linear control-flow statement");
            }
        }
    }
    Ok(())
}

fn variant_tag(variant: &str) -> i32 {
    (variant.bytes().fold(0u32, |acc, byte| {
        acc.wrapping_mul(33).wrapping_add(byte as u32)
    }) & 0x7fff_ffff) as i32
}

fn variant_tag_for_key(key: &str, variant_tags: &HashMap<String, i32>) -> i32 {
    variant_tags
        .get(key)
        .copied()
        .unwrap_or_else(|| variant_tag(key))
}

fn clif_emit_expr(
    builder: &mut FunctionBuilder,
    ctx: &mut ClifLoweringCtx<'_>,
    expr: &ast::Expr,
    locals: &mut HashMap<String, LocalBinding>,
    next_var: &mut usize,
) -> Result<ClifValue> {
    Ok(match expr {
        ast::Expr::Int(v) => {
            let ty = if i32::try_from(*v).is_ok() {
                types::I32
            } else {
                types::I64
            };
            ClifValue {
                value: builder.ins().iconst(ty, *v as i64),
                ty,
            }
        }
        ast::Expr::Float { value, bits } => {
            if bits.unwrap_or(64) == 32 {
                ClifValue {
                    value: builder.ins().f32const(*value as f32),
                    ty: types::F32,
                }
            } else {
                ClifValue {
                    value: builder.ins().f64const(*value),
                    ty: types::F64,
                }
            }
        }
        ast::Expr::Char(v) => ClifValue {
            value: builder.ins().iconst(types::I32, *v as i64),
            ty: types::I32,
        },
        ast::Expr::Bool(v) => ClifValue {
            value: builder.ins().iconst(types::I8, if *v { 1 } else { 0 }),
            ty: types::I8,
        },
        ast::Expr::Str(value) => ClifValue {
            value: builder.ins().iconst(
                pointer_sized_clif_type(),
                ctx.string_literal_ids.get(value).copied().unwrap_or(0) as i64,
            ),
            ty: pointer_sized_clif_type(),
        },
        ast::Expr::Ident(name) => {
            if let Some(binding) = locals.get(name).copied() {
                ClifValue {
                    value: builder.use_var(binding.var),
                    ty: binding.ty,
                }
            } else if let Some(data_id) = ctx.mutable_globals.get(name).copied() {
                let gv = ctx.module.declare_data_in_func(data_id, builder.func);
                let ptr = builder.ins().global_value(pointer_sized_clif_type(), gv);
                ClifValue {
                    value: builder.ins().load(types::I32, MemFlags::new(), ptr, 0),
                    ty: types::I32,
                }
            } else if let Some(value) = ctx.globals.get(name).copied() {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                }
            } else if let Some(task_ref) = ctx.task_ref_ids.get(name).copied() {
                ClifValue {
                    value: builder
                        .ins()
                        .iconst(default_int_clif_type(), task_ref as i64),
                    ty: default_int_clif_type(),
                }
            } else {
                ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), 0),
                    ty: default_int_clif_type(),
                }
            }
        }
        ast::Expr::Group(inner) => clif_emit_expr(builder, ctx, inner, locals, next_var)?,
        ast::Expr::Await(inner) => clif_emit_expr(builder, ctx, inner, locals, next_var)?,
        ast::Expr::Discard(inner) => {
            let _ = clif_emit_expr(builder, ctx, inner, locals, next_var)?;
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Closure {
            params,
            return_type,
            body,
        } => {
            let captures = clif_snapshot_closure_captures(builder, locals, next_var);
            let name = format!("__closure_{}", *next_var);
            ctx.closures.insert(
                name,
                ClifClosureBinding {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    body: (**body).clone(),
                    captures,
                },
            );
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Unary { op, expr } => {
            let value = clif_emit_expr(builder, ctx, expr, locals, next_var)?;
            match op {
                ast::UnaryOp::Plus => value,
                ast::UnaryOp::Neg => {
                    if value.ty == types::F32 || value.ty == types::F64 {
                        let zero = if value.ty == types::F32 {
                            builder.ins().f32const(0.0)
                        } else {
                            builder.ins().f64const(0.0)
                        };
                        ClifValue {
                            value: builder.ins().fsub(zero, value.value),
                            ty: value.ty,
                        }
                    } else {
                        let zero = builder.ins().iconst(value.ty, 0);
                        ClifValue {
                            value: builder.ins().isub(zero, value.value),
                            ty: value.ty,
                        }
                    }
                }
                ast::UnaryOp::Not => {
                    let zero = zero_for_type(builder, value.ty);
                    let pred = builder.ins().icmp(IntCC::Equal, value.value, zero);
                    bool_to_i8(builder, pred)
                }
                ast::UnaryOp::BitNot => {
                    if !value.ty.is_int() {
                        bail!("native backend bitwise not requires integer operand");
                    }
                    let all_ones = builder.ins().iconst(value.ty, -1);
                    ClifValue {
                        value: builder.ins().bxor(value.value, all_ones),
                        ty: value.ty,
                    }
                }
            }
        }
        ast::Expr::FieldAccess { base, field } => {
            if let Some(field_expr) = resolve_field_expr(base, field) {
                return clif_emit_expr(builder, ctx, &field_expr, locals, next_var);
            }
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = locals.get(&format!("{name}.{field}")).copied() {
                    ClifValue {
                        value: builder.use_var(binding.var),
                        ty: binding.ty,
                    }
                } else if let Some(task_ref_name) = expr_task_ref_name(expr) {
                    if let Some(task_ref) = ctx.task_ref_ids.get(&task_ref_name).copied() {
                        ClifValue {
                            value: builder
                                .ins()
                                .iconst(default_int_clif_type(), task_ref as i64),
                            ty: default_int_clif_type(),
                        }
                    } else {
                        clif_emit_expr(builder, ctx, base, locals, next_var)?
                    }
                } else {
                    clif_emit_expr(builder, ctx, base, locals, next_var)?
                }
            } else {
                clif_emit_expr(builder, ctx, base, locals, next_var)?
            }
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut first = None;
            for (_, value) in fields {
                let out = clif_emit_expr(builder, ctx, value, locals, next_var)?;
                if first.is_none() {
                    first = Some(out);
                }
            }
            first.unwrap_or_else(|| ClifValue {
                value: builder.ins().iconst(pointer_sized_clif_type(), 0),
                ty: pointer_sized_clif_type(),
            })
        }
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
        } => {
            for value in payload {
                let _ = clif_emit_expr(builder, ctx, value, locals, next_var)?;
            }
            let key = format!("{enum_name}::{variant}");
            ClifValue {
                value: builder.ins().iconst(
                    default_int_clif_type(),
                    variant_tag_for_key(&key, ctx.variant_tags) as i64,
                ),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr: _,
        } => clif_emit_expr(builder, ctx, try_expr, locals, next_var)?,
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            let cond = clif_emit_expr(builder, ctx, condition, locals, next_var)?;
            let cond_zero = zero_for_type(builder, cond.ty);
            let cond_pred = builder.ins().icmp(IntCC::NotEqual, cond.value, cond_zero);

            let then_block = builder.create_block();
            let else_block = builder.create_block();
            let merge_block = builder.create_block();
            builder
                .ins()
                .brif(cond_pred, then_block, &[], else_block, &[]);

            builder.switch_to_block(then_block);
            let then_value = clif_emit_expr(builder, ctx, then_expr, locals, next_var)?;
            builder.append_block_param(merge_block, then_value.ty);
            builder.ins().jump(merge_block, &[then_value.value]);

            builder.switch_to_block(else_block);
            let else_value = clif_emit_expr(builder, ctx, else_expr, locals, next_var)?;
            let else_value = cast_clif_value(builder, else_value, then_value.ty)?;
            builder.ins().jump(merge_block, &[else_value.value]);

            builder.seal_block(then_block);
            builder.seal_block(else_block);
            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            ClifValue {
                value: builder.block_params(merge_block)[0],
                ty: then_value.ty,
            }
        }
        ast::Expr::Range { start, .. } => clif_emit_expr(builder, ctx, start, locals, next_var)?,
        ast::Expr::ArrayLiteral(items) => {
            // Array literals are materialized by statement lowering into local bindings.
            for item in items {
                let _ = clif_emit_expr(builder, ctx, item, locals, next_var)?;
            }
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        ast::Expr::Index { base, index } => {
            let index_value =
                if let Some((base_name, offset)) = canonicalize_array_index_window(index) {
                    if let Some(binding) = locals.get(&base_name).copied() {
                        let base_raw = builder.use_var(binding.var);
                        let base = cast_clif_value(
                            builder,
                            ClifValue {
                                value: base_raw,
                                ty: binding.ty,
                            },
                            default_int_clif_type(),
                        )?
                        .value;
                        let value = if offset == 0 {
                            base
                        } else {
                            builder.ins().iadd_imm(base, i64::from(offset))
                        };
                        ClifValue {
                            value,
                            ty: default_int_clif_type(),
                        }
                    } else {
                        let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
                        cast_clif_value(builder, value, default_int_clif_type())?
                    }
                } else {
                    let value = clif_emit_expr(builder, ctx, index, locals, next_var)?;
                    cast_clif_value(builder, value, default_int_clif_type())?
                };
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = ctx.array_bindings.get(name) {
                    if binding.len == 0 {
                        return Ok(ClifValue {
                            value: builder.ins().iconst(binding.element_ty, 0),
                            ty: binding.element_ty,
                        });
                    }
                    if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
                        if const_idx >= 0 && (const_idx as usize) < binding.len {
                            let ptr = builder.ins().stack_addr(
                                pointer_sized_clif_type(),
                                binding.stack_slot,
                                const_idx * i32::from(binding.element_stride),
                            );
                            let loaded =
                                builder
                                    .ins()
                                    .load(binding.element_ty, MemFlags::new(), ptr, 0);
                            return Ok(ClifValue {
                                value: loaded,
                                ty: binding.element_ty,
                            });
                        }
                    }
                    let in_block = builder.create_block();
                    let out_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, binding.element_ty);

                    let zero = builder.ins().iconst(default_int_clif_type(), 0);
                    let len_const = builder
                        .ins()
                        .iconst(default_int_clif_type(), binding.len as i64);
                    let nonneg = builder.ins().icmp(
                        IntCC::SignedGreaterThanOrEqual,
                        index_value.value,
                        zero,
                    );
                    let below_len =
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThan, index_value.value, len_const);
                    let in_range = builder.ins().band(nonneg, below_len);
                    builder.ins().brif(in_range, in_block, &[], out_block, &[]);

                    builder.switch_to_block(in_block);
                    let base_ptr =
                        builder
                            .ins()
                            .stack_addr(pointer_sized_clif_type(), binding.stack_slot, 0);
                    let idx_ptr = if pointer_sized_clif_type() == default_int_clif_type() {
                        index_value.value
                    } else {
                        builder
                            .ins()
                            .uextend(pointer_sized_clif_type(), index_value.value)
                    };
                    let byte_offset = builder
                        .ins()
                        .imul_imm(idx_ptr, i64::from(binding.element_stride));
                    let addr = builder.ins().iadd(base_ptr, byte_offset);
                    let loaded = builder
                        .ins()
                        .load(binding.element_ty, MemFlags::new(), addr, 0);
                    builder.ins().jump(merge_block, &[loaded]);

                    builder.switch_to_block(out_block);
                    let zero_default = builder.ins().iconst(binding.element_ty, 0);
                    builder.ins().jump(merge_block, &[zero_default]);

                    builder.seal_block(in_block);
                    builder.seal_block(out_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    let selected = builder.block_params(merge_block)[0];
                    let _ = (
                        binding.element_bits,
                        binding.element_align,
                        binding.element_stride,
                    );
                    return Ok(ClifValue {
                        value: selected,
                        ty: binding.element_ty,
                    });
                }
            }
            clif_emit_expr(builder, ctx, base, locals, next_var)?
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = clif_emit_expr(builder, ctx, left, locals, next_var)?;
            match op {
                ast::BinaryOp::Add => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        ClifValue {
                            value: builder.ins().fadd(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    } else {
                        ClifValue {
                            value: builder.ins().iadd(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Sub => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        ClifValue {
                            value: builder.ins().fsub(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    } else {
                        ClifValue {
                            value: builder.ins().isub(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Mul => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        ClifValue {
                            value: builder.ins().fmul(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    } else {
                        ClifValue {
                            value: builder.ins().imul(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Div => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    if lhs.ty == types::F32 || lhs.ty == types::F64 {
                        ClifValue {
                            value: builder.ins().fdiv(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    } else {
                        ClifValue {
                            value: builder.ins().sdiv(lhs.value, rhs.value),
                            ty: lhs.ty,
                        }
                    }
                }
                ast::BinaryOp::Mod => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().srem(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitAnd => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().band(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitOr => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().bor(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::BitXor => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().bxor(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::Shl => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().ishl(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::Shr => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    ClifValue {
                        value: builder.ins().sshr(lhs.value, rhs.value),
                        ty: lhs.ty,
                    }
                }
                ast::BinaryOp::And => {
                    let lhs_zero = zero_for_type(builder, lhs.ty);
                    let lhs_pred = builder.ins().icmp(IntCC::NotEqual, lhs.value, lhs_zero);
                    let rhs_block = builder.create_block();
                    let short_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, types::I8);
                    builder
                        .ins()
                        .brif(lhs_pred, rhs_block, &[], short_block, &[]);

                    builder.switch_to_block(short_block);
                    let false_val = builder.ins().iconst(types::I8, 0);
                    builder.ins().jump(merge_block, &[false_val]);

                    builder.switch_to_block(rhs_block);
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs_zero = zero_for_type(builder, rhs.ty);
                    let rhs_pred = builder.ins().icmp(IntCC::NotEqual, rhs.value, rhs_zero);
                    let rhs_bool = bool_to_i8(builder, rhs_pred);
                    builder.ins().jump(merge_block, &[rhs_bool.value]);

                    builder.seal_block(short_block);
                    builder.seal_block(rhs_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    ClifValue {
                        value: builder.block_params(merge_block)[0],
                        ty: types::I8,
                    }
                }
                ast::BinaryOp::Or => {
                    let lhs_zero = zero_for_type(builder, lhs.ty);
                    let lhs_pred = builder.ins().icmp(IntCC::NotEqual, lhs.value, lhs_zero);
                    let rhs_block = builder.create_block();
                    let short_block = builder.create_block();
                    let merge_block = builder.create_block();
                    builder.append_block_param(merge_block, types::I8);
                    builder
                        .ins()
                        .brif(lhs_pred, short_block, &[], rhs_block, &[]);

                    builder.switch_to_block(short_block);
                    let true_val = builder.ins().iconst(types::I8, 1);
                    builder.ins().jump(merge_block, &[true_val]);

                    builder.switch_to_block(rhs_block);
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs_zero = zero_for_type(builder, rhs.ty);
                    let rhs_pred = builder.ins().icmp(IntCC::NotEqual, rhs.value, rhs_zero);
                    let rhs_bool = bool_to_i8(builder, rhs_pred);
                    builder.ins().jump(merge_block, &[rhs_bool.value]);

                    builder.seal_block(short_block);
                    builder.seal_block(rhs_block);
                    builder.switch_to_block(merge_block);
                    builder.seal_block(merge_block);
                    ClifValue {
                        value: builder.block_params(merge_block)[0],
                        ty: types::I8,
                    }
                }
                ast::BinaryOp::Eq => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = builder.ins().icmp(IntCC::Equal, lhs.value, rhs.value);
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Neq => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = builder.ins().icmp(IntCC::NotEqual, lhs.value, rhs.value);
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Lt => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = builder
                        .ins()
                        .icmp(IntCC::SignedLessThan, lhs.value, rhs.value);
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Lte => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred =
                        builder
                            .ins()
                            .icmp(IntCC::SignedLessThanOrEqual, lhs.value, rhs.value);
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Gt => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred = builder
                        .ins()
                        .icmp(IntCC::SignedGreaterThan, lhs.value, rhs.value);
                    bool_to_i8(builder, pred)
                }
                ast::BinaryOp::Gte => {
                    let rhs = clif_emit_expr(builder, ctx, right, locals, next_var)?;
                    let rhs = cast_clif_value(builder, rhs, lhs.ty)?;
                    let pred =
                        builder
                            .ins()
                            .icmp(IntCC::SignedGreaterThanOrEqual, lhs.value, rhs.value);
                    bool_to_i8(builder, pred)
                }
            }
        }
        ast::Expr::Call { callee, args } => {
            if let Some(value) = eval_const_i32_call(callee, args, &ctx.const_strings) {
                return Ok(ClifValue {
                    value: builder.ins().iconst(default_int_clif_type(), value as i64),
                    ty: default_int_clif_type(),
                });
            }
            if let Some(value) = eval_const_string_call(callee, args, &ctx.const_strings) {
                if let Some(id) = ctx.string_literal_ids.get(&value).copied() {
                    return Ok(ClifValue {
                        value: builder.ins().iconst(default_int_clif_type(), id as i64),
                        ty: default_int_clif_type(),
                    });
                }
            }
            if let Some(binding) = ctx.closures.get(callee).cloned() {
                return clif_emit_inlined_closure_call(
                    builder, ctx, binding, args, locals, next_var,
                );
            }
            let mut values = Vec::with_capacity(args.len());
            if let Some(function_id) = ctx.function_ids.get(callee).copied() {
                let signature = ctx.function_signatures.get(callee).ok_or_else(|| {
                    anyhow!("missing native function signature metadata for `{callee}`")
                })?;
                for (index, arg) in args.iter().enumerate() {
                    let mut lowered = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
                    if let Some(target) = signature.params.get(index).copied() {
                        lowered = cast_clif_value(builder, lowered, target)?;
                    }
                    values.push(lowered.value);
                }
                let func_ref = ctx.module.declare_func_in_func(function_id, builder.func);
                let call = builder.ins().call(func_ref, &values);
                if let Some(value) = builder.inst_results(call).first().copied() {
                    ClifValue {
                        value,
                        ty: signature.ret.unwrap_or(default_int_clif_type()),
                    }
                } else {
                    ClifValue {
                        value: builder.ins().iconst(default_int_clif_type(), 0),
                        ty: default_int_clif_type(),
                    }
                }
            } else {
                for arg in args {
                    let _ = clif_emit_expr(builder, ctx, arg, locals, next_var)?;
                }
                return Err(anyhow!(
                    "native backend cannot lower unresolved call target `{}`",
                    callee
                ));
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            clif_emit_linear_stmts(builder, ctx, body, locals, next_var)?;
            ClifValue {
                value: builder.ins().iconst(default_int_clif_type(), 0),
                ty: default_int_clif_type(),
            }
        }
        _ => ClifValue {
            value: builder.ins().iconst(default_int_clif_type(), 0),
            ty: default_int_clif_type(),
        },
    })
}

fn native_lowerability_diagnostics(module: &ast::Module) -> Vec<diagnostics::Diagnostic> {
    let mut diagnostics = Vec::new();
    let passthrough_functions = collect_passthrough_function_map_from_module(module);
    let mut variant_keys = BTreeSet::<String>::new();
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        for stmt in &function.body {
            collect_variant_keys_from_stmt(stmt, &mut variant_keys);
        }
    }
    let variant_tags = variant_keys
        .into_iter()
        .enumerate()
        .map(|(idx, key)| (key, idx as i32 + 1))
        .collect::<HashMap<_, _>>();
    diagnostics.extend(native_runtime_import_contract_errors().into_iter().map(|message| {
        diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            message,
            Some(
                "runtime shim imports are reserved for capability/host-effect boundaries; local data-plane paths must lower directly"
                    .to_string(),
            ),
        )
    }));
    for item in &module.items {
        let ast::Item::Function(function) = item else {
            continue;
        };
        for param in &function.params {
            if !native_backend_supports_signature_type(&param.ty) {
                diagnostics.push(diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    format!(
                        "native backend does not support parameter type `{}` in function `{}`",
                        param.ty, function.name
                    ),
                    Some(
                        "native backend signatures support scalar widths, pointer-sized integers, floats, and pointer-like/aggregate handles"
                            .to_string(),
                    ),
                ));
            }
        }
        if !native_backend_supports_signature_type(&function.return_type) {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "native backend does not support return type `{}` in function `{}`",
                    function.return_type, function.name
                ),
                Some(
                    "native backend signatures support scalar widths, pointer-sized integers, floats, and pointer-like/aggregate handles"
                        .to_string(),
                ),
            ));
        }
        if let Err(error) =
            build_control_flow_cfg(&function.body, &variant_tags, &passthrough_functions)
        {
            diagnostics.push(diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!(
                    "native backend cannot lower pattern/control-flow semantics in function `{}`: {}",
                    function.name, error
                ),
                Some(
                    "rewrite unsupported pattern guard shapes or non-lowerable control-flow forms to explicit statements"
                        .to_string(),
                ),
            ));
        }
    }

    let defined_functions = module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut unresolved = HashSet::<String>::new();
    for item in &module.items {
        if let ast::Item::Function(function) = item {
            let mut local_callables = HashSet::<String>::new();
            collect_local_callable_bindings(&function.body, &mut local_callables);
            for stmt in &function.body {
                collect_unresolved_calls_from_stmt(
                    stmt,
                    &defined_functions,
                    &local_callables,
                    &mut unresolved,
                );
            }
        }
    }
    let mut unresolved = unresolved.into_iter().collect::<Vec<_>>();
    unresolved.sort();
    diagnostics.extend(unresolved.into_iter().map(|callee| {
        diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            format!("native backend cannot execute unresolved call `{callee}`"),
            Some(
                "run via Fozzy scenario/host backends or provide a real native implementation for this symbol"
                    .to_string(),
            ),
        )
    }));

    diagnostics::assign_stable_codes(
        &mut diagnostics,
        diagnostics::DiagnosticDomain::NativeLowering,
    );
    diagnostics
}

fn experimental_feature_diagnostics(
    _module: &ast::Module,
    manifest: Option<&manifest::Manifest>,
) -> Vec<diagnostics::Diagnostic> {
    let tier = manifest
        .map(|value| value.language.tier.as_str())
        .unwrap_or("core_v1");
    let allow_experimental = manifest
        .map(|value| value.language.allow_experimental)
        .unwrap_or(false);
    if tier == "experimental" && allow_experimental {
        return Vec::new();
    }

    let mut diagnostics = Vec::new();
    diagnostics::assign_stable_codes(&mut diagnostics, diagnostics::DiagnosticDomain::Verifier);
    diagnostics
}

fn backend_capability_diagnostics(
    module: &ast::Module,
    backend: &str,
) -> Vec<diagnostics::Diagnostic> {
    let mut diagnostics = Vec::new();
    let backend = backend.trim().to_ascii_lowercase();
    if backend == "cranelift" {
        for item in &module.items {
            let ast::Item::Function(function) = item else {
                continue;
            };
            if function.is_pubext
                && function.is_async
                && function
                    .abi
                    .as_deref()
                    .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
            {
                diagnostics.push(
                    diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        format!(
                            "backend `cranelift` does not support async C export `{}`",
                            function.name
                        ),
                        Some(
                            "compile with `--backend llvm` or remove async C export surface"
                                .to_string(),
                        ),
                    )
                    .with_fix("switch backend: `fz build <path> --backend llvm`"),
                );
            }
            if function.is_async && function.is_unsafe {
                diagnostics.push(
                    diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        format!(
                            "backend `cranelift` rejects async+unsafe function `{}`",
                            function.name
                        ),
                        Some(
                            "use backend llvm for this code shape or refactor unsafe code outside async path"
                                .to_string(),
                        ),
                    )
                    .with_fix("switch backend: `fz build <path> --backend llvm`"),
                );
            }
        }
    }
    diagnostics
}

fn native_backend_supports_signature_type(ty: &ast::Type) -> bool {
    ast_signature_type_to_clif_type(ty).is_some() || matches!(ty, ast::Type::Void | ast::Type::Never)
}

fn ast_signature_type_to_clif_type(ty: &ast::Type) -> Option<ClifType> {
    match ty {
        ast::Type::Void | ast::Type::Never => None,
        ast::Type::Bool => Some(types::I8),
        ast::Type::ISize | ast::Type::USize => Some(pointer_sized_clif_type()),
        ast::Type::Int { bits, .. } => match bits {
            8 => Some(types::I8),
            16 => Some(types::I16),
            32 => Some(types::I32),
            64 => Some(types::I64),
            128 => Some(types::I128),
            _ => None,
        },
        ast::Type::Float { bits } => match bits {
            32 => Some(types::F32),
            64 => Some(types::F64),
            _ => None,
        },
        ast::Type::Char
        | ast::Type::Str
        | ast::Type::Ptr { .. }
        | ast::Type::Ref { .. }
        | ast::Type::Slice(_)
        | ast::Type::Array { .. }
        | ast::Type::Result { .. }
        | ast::Type::Option(_)
        | ast::Type::Vec(_)
        | ast::Type::Function { .. }
        | ast::Type::Named { .. }
        | ast::Type::TypeVar(_) => Some(pointer_sized_clif_type()),
    }
}

fn pointer_sized_clif_type() -> ClifType {
    if std::mem::size_of::<usize>() == 8 {
        types::I64
    } else {
        types::I32
    }
}

fn default_int_clif_type() -> ClifType {
    types::I32
}

fn clif_array_layout_from_values(values: &[ClifValue]) -> (ClifType, u16, u8, u8) {
    let element_ty = if values.iter().any(|value| value.ty == types::I64) {
        types::I64
    } else {
        types::I32
    };
    let element_bits = element_ty.bits() as u16;
    let element_stride = (element_bits / 8) as u8;
    let element_align = element_stride;
    (element_ty, element_bits, element_align, element_stride)
}

fn zero_for_type(builder: &mut FunctionBuilder, ty: ClifType) -> cranelift_codegen::ir::Value {
    if ty.is_int() {
        builder.ins().iconst(ty, 0)
    } else if ty == types::F32 {
        builder.ins().f32const(0.0)
    } else if ty == types::F64 {
        builder.ins().f64const(0.0)
    } else {
        builder.ins().iconst(default_int_clif_type(), 0)
    }
}

fn bool_to_i8(builder: &mut FunctionBuilder, pred: cranelift_codegen::ir::Value) -> ClifValue {
    let one = builder.ins().iconst(types::I8, 1);
    let zero = builder.ins().iconst(types::I8, 0);
    ClifValue {
        value: builder.ins().select(pred, one, zero),
        ty: types::I8,
    }
}

fn cast_clif_value(
    builder: &mut FunctionBuilder,
    value: ClifValue,
    target: ClifType,
) -> Result<ClifValue> {
    if value.ty == target {
        return Ok(value);
    }
    if value.ty.is_int() && target.is_int() {
        if value.ty.bits() < target.bits() {
            return Ok(ClifValue {
                value: builder.ins().sextend(target, value.value),
                ty: target,
            });
        }
        if value.ty.bits() > target.bits() {
            return Ok(ClifValue {
                value: builder.ins().ireduce(target, value.value),
                ty: target,
            });
        }
    }
    if value.ty.is_int() && (target == types::F32 || target == types::F64) {
        let out = if target == types::F32 {
            builder.ins().fcvt_from_sint(types::F32, value.value)
        } else {
            builder.ins().fcvt_from_sint(types::F64, value.value)
        };
        return Ok(ClifValue {
            value: out,
            ty: target,
        });
    }
    if (value.ty == types::F32 || value.ty == types::F64) && target.is_int() {
        return Ok(ClifValue {
            value: builder.ins().fcvt_to_sint(target, value.value),
            ty: target,
        });
    }
    if value.ty == types::F32 && target == types::F64 {
        return Ok(ClifValue {
            value: builder.ins().fpromote(types::F64, value.value),
            ty: types::F64,
        });
    }
    if value.ty == types::F64 && target == types::F32 {
        return Ok(ClifValue {
            value: builder.ins().fdemote(types::F32, value.value),
            ty: types::F32,
        });
    }
    bail!(
        "unsupported native cast from `{}` to `{}`",
        value.ty,
        target
    );
}

fn collect_unresolved_calls_from_stmt(
    stmt: &ast::Stmt,
    defined_functions: &HashSet<String>,
    local_callables: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match stmt {
        ast::Stmt::Let { value, .. }
        | ast::Stmt::LetPattern { value, .. }
        | ast::Stmt::Assign { value, .. }
        | ast::Stmt::CompoundAssign { value, .. }
        | ast::Stmt::Defer(value)
        | ast::Stmt::Requires(value)
        | ast::Stmt::Ensures(value)
        | ast::Stmt::Expr(value) => collect_unresolved_calls_from_expr(
            value,
            defined_functions,
            local_callables,
            unresolved,
        ),
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in then_body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            for nested in else_body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::While { condition, body } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                collect_unresolved_calls_from_stmt(
                    init,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            if let Some(condition) = condition {
                collect_unresolved_calls_from_expr(
                    condition,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            if let Some(step) = step {
                collect_unresolved_calls_from_stmt(
                    step,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::ForIn { iterable, body, .. } => {
            collect_unresolved_calls_from_expr(
                iterable,
                defined_functions,
                local_callables,
                unresolved,
            );
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::Loop { body } => {
            for nested in body {
                collect_unresolved_calls_from_stmt(
                    nested,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        ast::Stmt::Match { scrutinee, arms } => {
            collect_unresolved_calls_from_expr(
                scrutinee,
                defined_functions,
                local_callables,
                unresolved,
            );
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    collect_unresolved_calls_from_expr(
                        guard,
                        defined_functions,
                        local_callables,
                        unresolved,
                    );
                }
                collect_unresolved_calls_from_expr(
                    &arm.value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
    }
}

fn collect_unresolved_calls_from_expr(
    expr: &ast::Expr,
    defined_functions: &HashSet<String>,
    local_callables: &HashSet<String>,
    unresolved: &mut HashSet<String>,
) {
    match expr {
        ast::Expr::Call { callee, args } => {
            if !defined_functions.contains(callee)
                && !local_callables.contains(callee)
                && !native_backend_supports_call(callee)
            {
                unresolved.insert(callee.clone());
            }
            for arg in args {
                collect_unresolved_calls_from_expr(
                    arg,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            for stmt in body {
                collect_unresolved_calls_from_stmt(
                    stmt,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::FieldAccess { base, .. } => {
            collect_unresolved_calls_from_expr(
                base,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_unresolved_calls_from_expr(
                    value,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::Closure { body, .. } => {
            collect_unresolved_calls_from_expr(
                body,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Group(inner) => {
            collect_unresolved_calls_from_expr(
                inner,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_unresolved_calls_from_expr(
                inner,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Unary { expr, .. } => {
            collect_unresolved_calls_from_expr(
                expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_unresolved_calls_from_expr(
                try_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                catch_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_unresolved_calls_from_expr(
                condition,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                then_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                else_expr,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Binary { left, right, .. } => {
            collect_unresolved_calls_from_expr(
                left,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                right,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Range { start, end, .. } => {
            collect_unresolved_calls_from_expr(
                start,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(end, defined_functions, local_callables, unresolved);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_unresolved_calls_from_expr(
                    item,
                    defined_functions,
                    local_callables,
                    unresolved,
                );
            }
        }
        ast::Expr::Index { base, index } => {
            collect_unresolved_calls_from_expr(
                base,
                defined_functions,
                local_callables,
                unresolved,
            );
            collect_unresolved_calls_from_expr(
                index,
                defined_functions,
                local_callables,
                unresolved,
            );
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn collect_local_callable_bindings(body: &[ast::Stmt], out: &mut HashSet<String>) {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                if matches!(value, ast::Expr::Closure { .. }) {
                    out.insert(name.clone());
                }
                collect_local_callable_bindings_from_expr(value, out);
            }
            ast::Stmt::Assign { target, value } => {
                if matches!(value, ast::Expr::Closure { .. }) {
                    out.insert(target.clone());
                }
                collect_local_callable_bindings_from_expr(value, out);
            }
            ast::Stmt::LetPattern { value, .. }
            | ast::Stmt::CompoundAssign { value, .. }
            | ast::Stmt::Defer(value)
            | ast::Stmt::Requires(value)
            | ast::Stmt::Ensures(value)
            | ast::Stmt::Expr(value) => collect_local_callable_bindings_from_expr(value, out),
            ast::Stmt::Return(value) => {
                if let Some(value) = value {
                    collect_local_callable_bindings_from_expr(value, out);
                }
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_local_callable_bindings_from_expr(condition, out);
                collect_local_callable_bindings(then_body, out);
                collect_local_callable_bindings(else_body, out);
            }
            ast::Stmt::While { condition, body } => {
                collect_local_callable_bindings_from_expr(condition, out);
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::For {
                init,
                condition,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_local_callable_bindings(std::slice::from_ref(init.as_ref()), out);
                }
                if let Some(condition) = condition {
                    collect_local_callable_bindings_from_expr(condition, out);
                }
                if let Some(step) = step {
                    collect_local_callable_bindings(std::slice::from_ref(step.as_ref()), out);
                }
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::ForIn { iterable, body, .. } => {
                collect_local_callable_bindings_from_expr(iterable, out);
                collect_local_callable_bindings(body, out);
            }
            ast::Stmt::Loop { body } => collect_local_callable_bindings(body, out),
            ast::Stmt::Match { scrutinee, arms } => {
                collect_local_callable_bindings_from_expr(scrutinee, out);
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        collect_local_callable_bindings_from_expr(guard, out);
                    }
                    collect_local_callable_bindings_from_expr(&arm.value, out);
                }
            }
            ast::Stmt::Break(_) | ast::Stmt::Continue => {}
        }
    }
}

fn collect_local_callable_bindings_from_expr(expr: &ast::Expr, out: &mut HashSet<String>) {
    match expr {
        ast::Expr::Call { args, .. } => {
            for arg in args {
                collect_local_callable_bindings_from_expr(arg, out);
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            collect_local_callable_bindings(body, out);
        }
        ast::Expr::FieldAccess { base, .. } => collect_local_callable_bindings_from_expr(base, out),
        ast::Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                collect_local_callable_bindings_from_expr(value, out);
            }
        }
        ast::Expr::EnumInit { payload, .. } => {
            for value in payload {
                collect_local_callable_bindings_from_expr(value, out);
            }
        }
        ast::Expr::Closure { body, .. } => collect_local_callable_bindings_from_expr(body, out),
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            collect_local_callable_bindings_from_expr(inner, out)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            collect_local_callable_bindings_from_expr(try_expr, out);
            collect_local_callable_bindings_from_expr(catch_expr, out);
        }
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_local_callable_bindings_from_expr(condition, out);
            collect_local_callable_bindings_from_expr(then_expr, out);
            collect_local_callable_bindings_from_expr(else_expr, out);
        }
        ast::Expr::Unary { expr, .. } => collect_local_callable_bindings_from_expr(expr, out),
        ast::Expr::Binary { left, right, .. } => {
            collect_local_callable_bindings_from_expr(left, out);
            collect_local_callable_bindings_from_expr(right, out);
        }
        ast::Expr::Range { start, end, .. } => {
            collect_local_callable_bindings_from_expr(start, out);
            collect_local_callable_bindings_from_expr(end, out);
        }
        ast::Expr::ArrayLiteral(items) => {
            for item in items {
                collect_local_callable_bindings_from_expr(item, out);
            }
        }
        ast::Expr::Index { base, index } => {
            collect_local_callable_bindings_from_expr(base, out);
            collect_local_callable_bindings_from_expr(index, out);
        }
        ast::Expr::Int(_)
        | ast::Expr::Float { .. }
        | ast::Expr::Char(_)
        | ast::Expr::Bool(_)
        | ast::Expr::Str(_)
        | ast::Expr::Ident(_) => {}
        _ => {}
    }
}

fn native_backend_supports_call(callee: &str) -> bool {
    native_runtime_import_for_callee(callee).is_some()
        || native_data_plane_import_for_callee(callee).is_some()
}

fn declare_native_runtime_imports(
    module: &mut ObjectModule,
    function_ids: &mut HashMap<String, cranelift_module::FuncId>,
    function_signatures: &mut HashMap<String, ClifFunctionSignature>,
) -> Result<()> {
    for import in NATIVE_RUNTIME_IMPORTS {
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
                    "failed declaring native runtime import `{}` for `{}`: {error}",
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
            },
        );
    }
    Ok(())
}

fn declare_native_data_plane_imports(
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
            },
        );
    }
    Ok(())
}

fn ensure_native_runtime_shim(
    build_dir: &Path,
    string_literals: &[String],
    task_symbols: &[String],
    async_exports: &[NativeAsyncExport],
) -> Result<PathBuf> {
    let mut hasher = Sha256::new();
    for literal in string_literals {
        hasher.update(literal.as_bytes());
        hasher.update([0u8]);
    }
    for symbol in task_symbols {
        hasher.update(symbol.as_bytes());
        hasher.update([0u8]);
    }
    for export in async_exports {
        hasher.update(export.name.as_bytes());
        hasher.update([0u8]);
        hasher.update(export.mangled_symbol.as_bytes());
        hasher.update([0u8]);
        for (ty, name) in &export.params {
            hasher.update(ty.as_bytes());
            hasher.update([0u8]);
            hasher.update(name.as_bytes());
            hasher.update([0u8]);
        }
    }
    let digest = hasher.finalize();
    let tag = hex_encode(&digest[..8]);
    let runtime_shim_path = build_dir.join(format!("fz_native_runtime_{tag}.c"));
    std::fs::write(
        &runtime_shim_path,
        render_native_runtime_shim(string_literals, task_symbols, async_exports),
    )
    .with_context(|| {
        format!(
            "failed writing native runtime shim source: {}",
            runtime_shim_path.display()
        )
    })?;
    Ok(runtime_shim_path)
}

fn render_async_export_shim_code(async_exports: &[NativeAsyncExport]) -> String {
    if async_exports.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(
        r#"
#define FZ_MAX_ASYNC_EXPORT_STATES 4096

typedef struct {
  int in_use;
  int done;
  int32_t result_i32;
} fz_async_export_state;

static fz_async_export_state fz_async_export_states[FZ_MAX_ASYNC_EXPORT_STATES];
static pthread_mutex_t fz_async_export_lock = PTHREAD_MUTEX_INITIALIZER;

static int fz_async_export_slot_from_handle(uint64_t handle) {
  if (handle == 0) {
    return -1;
  }
  uint64_t slot = handle - 1;
  if (slot >= (uint64_t)FZ_MAX_ASYNC_EXPORT_STATES) {
    return -1;
  }
  return (int)slot;
}

"#,
    );

    for export in async_exports {
        let params = if export.params.is_empty() {
            "void".to_string()
        } else {
            export
                .params
                .iter()
                .map(|(ty, name)| format!("{ty} {name}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let invoke_args = export
            .params
            .iter()
            .map(|(_, name)| name.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let start_params = if export.params.is_empty() {
            "fz_async_handle_t* handle_out".to_string()
        } else {
            format!("{params}, fz_async_handle_t* handle_out")
        };
        let call_expr = if invoke_args.is_empty() {
            format!("{}()", export.mangled_symbol)
        } else {
            format!("{}({invoke_args})", export.mangled_symbol)
        };
        let _ = writeln!(
            &mut out,
            "extern int32_t {}({});",
            export.mangled_symbol, params
        );
        let _ = writeln!(
            &mut out,
            "int32_t {}_async_start({}) {{",
            export.name, start_params
        );
        out.push_str(
            "  if (handle_out == NULL) {\n    return -1;\n  }\n  int slot = -1;\n  pthread_mutex_lock(&fz_async_export_lock);\n  for (int i = 0; i < FZ_MAX_ASYNC_EXPORT_STATES; i++) {\n    if (!fz_async_export_states[i].in_use) {\n      fz_async_export_states[i].in_use = 1;\n      fz_async_export_states[i].done = 0;\n      fz_async_export_states[i].result_i32 = 0;\n      slot = i;\n      break;\n    }\n  }\n  pthread_mutex_unlock(&fz_async_export_lock);\n  if (slot < 0) {\n    return -3;\n  }\n",
        );
        let _ = writeln!(&mut out, "  int32_t result = {};", call_expr);
        out.push_str(
            "  pthread_mutex_lock(&fz_async_export_lock);\n  fz_async_export_states[slot].result_i32 = result;\n  fz_async_export_states[slot].done = 1;\n  pthread_mutex_unlock(&fz_async_export_lock);\n  *handle_out = (uint64_t)(slot + 1);\n  return 0;\n}\n",
        );
        let _ = writeln!(
            &mut out,
            "int32_t {}_async_poll(fz_async_handle_t handle, int32_t* done_out) {{",
            export.name
        );
        out.push_str(
            "  if (done_out == NULL) {\n    return -1;\n  }\n  int slot = fz_async_export_slot_from_handle(handle);\n  if (slot < 0) {\n    return -2;\n  }\n  pthread_mutex_lock(&fz_async_export_lock);\n  if (!fz_async_export_states[slot].in_use) {\n    pthread_mutex_unlock(&fz_async_export_lock);\n    return -2;\n  }\n  *done_out = fz_async_export_states[slot].done ? 1 : 0;\n  pthread_mutex_unlock(&fz_async_export_lock);\n  return 0;\n}\n",
        );
        let _ = writeln!(
            &mut out,
            "int32_t {}_async_await(fz_async_handle_t handle, int32_t* result_out) {{",
            export.name
        );
        out.push_str(
            "  if (result_out == NULL) {\n    return -1;\n  }\n  int slot = fz_async_export_slot_from_handle(handle);\n  if (slot < 0) {\n    return -2;\n  }\n  for (;;) {\n    pthread_mutex_lock(&fz_async_export_lock);\n    int in_use = fz_async_export_states[slot].in_use;\n    int done = fz_async_export_states[slot].done;\n    int32_t value = fz_async_export_states[slot].result_i32;\n    pthread_mutex_unlock(&fz_async_export_lock);\n    if (!in_use) {\n      return -2;\n    }\n    if (done) {\n      *result_out = value;\n      return 0;\n    }\n    sched_yield();\n  }\n}\n",
        );
        let _ = writeln!(
            &mut out,
            "int32_t {}_async_drop(fz_async_handle_t handle) {{",
            export.name
        );
        out.push_str(
            "  int slot = fz_async_export_slot_from_handle(handle);\n  if (slot < 0) {\n    return -2;\n  }\n  pthread_mutex_lock(&fz_async_export_lock);\n  if (!fz_async_export_states[slot].in_use) {\n    pthread_mutex_unlock(&fz_async_export_lock);\n    return -2;\n  }\n  fz_async_export_states[slot].in_use = 0;\n  fz_async_export_states[slot].done = 0;\n  fz_async_export_states[slot].result_i32 = 0;\n  pthread_mutex_unlock(&fz_async_export_lock);\n  return 0;\n}\n",
        );
    }
    out
}

fn render_native_runtime_shim(
    string_literals: &[String],
    task_symbols: &[String],
    async_exports: &[NativeAsyncExport],
) -> String {
    let mut literal_entries = String::new();
    for literal in string_literals {
        let _ = writeln!(&mut literal_entries, "  \"{}\",", escape_c_string(literal));
    }
    if literal_entries.is_empty() {
        literal_entries.push_str("  NULL,\n");
    }
    let mut task_declarations = String::new();
    let mut task_entries = String::new();
    for (index, symbol) in task_symbols.iter().enumerate() {
        let native_symbol = native_mangle_symbol(symbol);
        let linker_symbol = if cfg!(target_vendor = "apple") {
            format!("_{}", native_symbol)
        } else {
            native_symbol
        };
        let _ = writeln!(
            &mut task_declarations,
            "extern int32_t fz_task_entry_{}(void) __asm__(\"{}\");",
            index,
            escape_c_string(&linker_symbol)
        );
        let _ = writeln!(&mut task_entries, "  fz_task_entry_{},", index);
    }
    if task_entries.is_empty() {
        task_entries.push_str("  NULL,\n");
    }
    let async_export_shim = render_async_export_shim_code(async_exports);
    let count = string_literals.len();
    let task_count = task_symbols.len();
    let mut c = String::new();
    c.push_str(
        r#"#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

"#,
    );
    c.push_str("typedef int32_t (*fz_task_entry_fn)(void);\n");
    c.push_str("typedef int32_t (*fz_callback_i32_v0)(int32_t);\n");
    c.push_str("typedef uint64_t fz_async_handle_t;\n");
    c.push_str(&task_declarations);
    c.push_str("static fz_task_entry_fn fz_task_entries[] = {\n");
    c.push_str(&task_entries);
    c.push_str("};\n");
    c.push_str(&format!(
        "static const int fz_task_entry_count = {};\n\n",
        task_count
    ));
    c.push_str("static const char* fz_string_literals[] = {\n");
    c.push_str(&literal_entries);
    c.push_str("};\n");
    c.push_str(&format!(
        "static const int fz_string_literal_count = {};\n\n",
        count
    ));
    c.push_str(
        r#"#define FZ_MAX_DYNAMIC_STRINGS 16384
#define FZ_MAX_CONN_STATES 2048
#define FZ_MAX_HTTP_READ 262144
#define FZ_MAX_PROC_STATES 1024
#define FZ_MAX_HTTP_HEADERS 128
#define FZ_MAX_SPAWN_THREADS 4096
#define FZ_MAX_CONN_META 128
#define FZ_MAX_ROUTE_PARAMS 64
#define FZ_MAX_LISTS 2048
#define FZ_MAX_LIST_ITEMS 4096
#define FZ_MAX_MAPS 2048
#define FZ_MAX_MAP_ENTRIES 4096
#define FZ_MAX_INTERVALS 512
#define FZ_MAX_JSON_VALUES 16384

static char* fz_dynamic_strings[FZ_MAX_DYNAMIC_STRINGS];
static int fz_dynamic_string_count = 0;
static pthread_mutex_t fz_string_lock = PTHREAD_MUTEX_INITIALIZER;

static int fz_listener_fd = -1;
static pthread_mutex_t fz_listener_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  int in_use;
  int fd;
  int32_t method_id;
  int32_t path_id;
  int32_t body_id;
  int32_t request_id;
  int32_t remote_addr_id;
  int keep_alive;
  int header_count;
  int32_t header_key_ids[FZ_MAX_CONN_META];
  int32_t header_value_ids[FZ_MAX_CONN_META];
  int query_count;
  int32_t query_key_ids[FZ_MAX_CONN_META];
  int32_t query_value_ids[FZ_MAX_CONN_META];
  int param_count;
  int32_t param_key_ids[FZ_MAX_ROUTE_PARAMS];
  int32_t param_value_ids[FZ_MAX_ROUTE_PARAMS];
} fz_conn_state;

static fz_conn_state fz_conn_states[FZ_MAX_CONN_STATES];
static pthread_mutex_t fz_conn_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  char* data;
  size_t len;
  size_t cap;
} fz_bytes_buf;

typedef struct {
  int in_use;
  pid_t pid;
  int stdout_fd;
  int stderr_fd;
  int done;
  int exit_notified;
  int exit_code;
  size_t stdout_read_pos;
  size_t stderr_read_pos;
  int32_t stdout_id;
  int32_t stderr_id;
  fz_bytes_buf stdout_buf;
  fz_bytes_buf stderr_buf;
} fz_proc_state;

typedef struct {
  int in_use;
  int count;
  char* items[FZ_MAX_LIST_ITEMS];
} fz_list_state;

typedef struct {
  int in_use;
  int count;
  int32_t items[FZ_MAX_LIST_ITEMS];
} fz_array_state;

typedef struct {
  int in_use;
  int count;
  char* keys[FZ_MAX_MAP_ENTRIES];
  char* values[FZ_MAX_MAP_ENTRIES];
} fz_map_state;

typedef struct {
  int in_use;
  int32_t period_ms;
  int64_t next_ms;
} fz_interval_state;

typedef struct {
  int in_use;
  int32_t value_id;
} fz_json_value_state;

static fz_proc_state fz_proc_states[FZ_MAX_PROC_STATES];
static pthread_mutex_t fz_proc_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_proc_default_timeout_ms = 30000;
static int32_t fz_proc_last_error_id = 0;
static int32_t fz_last_exit_class = 0;
static fz_list_state fz_lists[FZ_MAX_LISTS];
static fz_array_state fz_arrays[FZ_MAX_LISTS];
static fz_map_state fz_maps[FZ_MAX_MAPS];
static fz_interval_state fz_intervals[FZ_MAX_INTERVALS];
static fz_json_value_state fz_json_values[FZ_MAX_JSON_VALUES];
static pthread_mutex_t fz_collections_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_time_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fz_json_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_conn_request_counter = 0;
static int32_t fz_last_error_code = 0;
static int32_t fz_last_error_class = 0;
static int32_t fz_last_error_message_id = 0;
static int fz_log_json = 0;

typedef struct {
  int32_t key_id;
  int32_t value_id;
} fz_http_header_pair;

static fz_http_header_pair fz_http_headers[FZ_MAX_HTTP_HEADERS];
static int fz_http_header_count = 0;
static pthread_mutex_t fz_http_lock = PTHREAD_MUTEX_INITIALIZER;
static int32_t fz_http_last_status = 0;
static int32_t fz_http_last_body_id = 0;
static int32_t fz_http_last_error_id = 0;
static int fz_fs_fd = -1;
static char fz_fs_base_path[512] = {0};
static char fz_fs_tmp_path[544] = {0};
static pthread_mutex_t fz_fs_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
  int in_use;
  int32_t handle;
  int32_t task_ref;
  int32_t context_id;
  int32_t group_id;
  pthread_t thread;
  int started;
  int finished;
  int detached;
  int joined;
  int cancelled;
  int32_t result;
} fz_spawn_state;

typedef struct {
  int in_use;
  int32_t id;
  int32_t active_count;
} fz_task_group_state;

static fz_spawn_state fz_spawn_states[FZ_MAX_SPAWN_THREADS];
static fz_task_group_state fz_task_groups[256];
static int32_t fz_next_spawn_handle = 1;
static int32_t fz_next_task_group_id = 1;
static int32_t fz_spawn_active_count = 0;
static int32_t fz_spawn_max_active = 1024;
static pthread_mutex_t fz_spawn_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_spawn_atexit_once = PTHREAD_ONCE_INIT;
static __thread int32_t fz_tls_task_context = 0;
static int64_t fz_async_deadline_ms = 0;
static int32_t fz_async_cancelled = 0;
static fz_callback_i32_v0 fz_host_callbacks[64];
static int fz_host_initialized = 0;
static pthread_mutex_t fz_host_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_env_bootstrap_once = PTHREAD_ONCE_INIT;

typedef struct {
  int32_t handle;
} fz_spawn_ctx;

static int fz_mark_cloexec(int fd);
static void fz_proc_set_last_error(const char* msg);
static void fz_dotenv_load(void);
static void fz_env_bootstrap(void);
static const char* fz_env_get_bootstrapped(const char* key);
static int fz_has_env_value(const char* key);
static void fz_log_bind_target(int listener_fd);
static int fz_json_parse_string(const char** cursor, char** out);
static int fz_parse_json_string_array(const char* raw, char*** out_items, int* out_count);
static int fz_parse_json_env_object(const char* raw, char*** out_items, int* out_count);
static void fz_free_string_list(char** items, int count);
static int fz_json_parse_value_slice(const char* raw, const char** out_start, const char** out_end);
int32_t fz_native_net_request_id(int32_t conn_fd);
int32_t fz_native_net_write(int32_t conn_fd, int32_t status_code, int32_t body_id);


static const char* fz_lookup_string(int32_t id) {
  if (id <= 0) {
    return "";
  }
  if (id <= fz_string_literal_count) {
    const char* literal = fz_string_literals[id - 1];
    return literal == NULL ? "" : literal;
  }
  int dynamic_index = id - fz_string_literal_count - 1;
  if (dynamic_index < 0 || dynamic_index >= fz_dynamic_string_count) {
    return "";
  }
  const char* value = fz_dynamic_strings[dynamic_index];
  return value == NULL ? "" : value;
}

static int32_t fz_intern_owned(char* owned) {
  if (owned == NULL) {
    return 0;
  }
  pthread_mutex_lock(&fz_string_lock);
  for (int i = 0; i < fz_string_literal_count; i++) {
    const char* literal = fz_string_literals[i];
    if (literal != NULL && strcmp(literal, owned) == 0) {
      pthread_mutex_unlock(&fz_string_lock);
      free(owned);
      return i + 1;
    }
  }
  for (int i = 0; i < fz_dynamic_string_count; i++) {
    const char* existing = fz_dynamic_strings[i];
    if (existing != NULL && strcmp(existing, owned) == 0) {
      pthread_mutex_unlock(&fz_string_lock);
      free(owned);
      return fz_string_literal_count + i + 1;
    }
  }
  if (fz_dynamic_string_count >= FZ_MAX_DYNAMIC_STRINGS) {
    pthread_mutex_unlock(&fz_string_lock);
    free(owned);
    return 0;
  }
  int index = fz_dynamic_string_count++;
  fz_dynamic_strings[index] = owned;
  pthread_mutex_unlock(&fz_string_lock);
  return fz_string_literal_count + index + 1;
}

static int32_t fz_intern_slice(const char* data, size_t len) {
  char* owned = (char*)malloc(len + 1);
  if (owned == NULL) {
    return 0;
  }
  if (len > 0) {
    memcpy(owned, data, len);
  }
  owned[len] = '\0';
  return fz_intern_owned(owned);
}

static void fz_set_last_error(int32_t code, int32_t class_id, const char* message) {
  if (message == NULL) {
    message = "";
  }
  fz_last_error_code = code;
  fz_last_error_class = class_id;
  fz_last_error_message_id = fz_intern_slice(message, strlen(message));
}

static int32_t fz_list_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_lists[i].in_use) {
      memset(&fz_lists[i], 0, sizeof(fz_lists[i]));
      fz_lists[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_list_state* fz_list_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_list_state* list = &fz_lists[handle - 1];
  return list->in_use ? list : NULL;
}

static int fz_list_push_cstr(fz_list_state* list, const char* value) {
  if (list == NULL || list->count >= FZ_MAX_LIST_ITEMS) {
    return -1;
  }
  if (value == NULL) {
    value = "";
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    return -1;
  }
  list->items[list->count++] = dup;
  return 0;
}

static int32_t fz_array_alloc(void) {
  for (int i = 0; i < FZ_MAX_LISTS; i++) {
    if (!fz_arrays[i].in_use) {
      memset(&fz_arrays[i], 0, sizeof(fz_arrays[i]));
      fz_arrays[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_array_state* fz_array_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_LISTS) {
    return NULL;
  }
  fz_array_state* array = &fz_arrays[handle - 1];
  return array->in_use ? array : NULL;
}

static int fz_array_push_i32(fz_array_state* array, int32_t value) {
  if (array == NULL || array->count >= FZ_MAX_LIST_ITEMS) {
    return -1;
  }
  array->items[array->count++] = value;
  return 0;
}

static int32_t fz_map_alloc(void) {
  for (int i = 0; i < FZ_MAX_MAPS; i++) {
    if (!fz_maps[i].in_use) {
      memset(&fz_maps[i], 0, sizeof(fz_maps[i]));
      fz_maps[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_map_state* fz_map_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_MAPS) {
    return NULL;
  }
  fz_map_state* map = &fz_maps[handle - 1];
  return map->in_use ? map : NULL;
}

static int fz_map_find_index(fz_map_state* map, const char* key) {
  if (map == NULL || key == NULL) {
    return -1;
  }
  for (int i = 0; i < map->count; i++) {
    if (map->keys[i] != NULL && strcmp(map->keys[i], key) == 0) {
      return i;
    }
  }
  return -1;
}

static char* fz_trim_ascii(char* text) {
  if (text == NULL) {
    return NULL;
  }
  while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
    text++;
  }
  size_t len = strlen(text);
  while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' || text[len - 1] == '\r' || text[len - 1] == '\n')) {
    text[--len] = '\0';
  }
  return text;
}

static void fz_unquote_env_value(char* value) {
  if (value == NULL) {
    return;
  }
  size_t len = strlen(value);
  if (len < 2) {
    return;
  }
  char quote = value[0];
  if ((quote != '\'' && quote != '\"') || value[len - 1] != quote) {
    return;
  }
  value[len - 1] = '\0';
  memmove(value, value + 1, len - 1);
  if (quote == '\"') {
    char* src = value;
    char* dst = value;
    while (*src != '\0') {
      if (*src == '\\' && src[1] != '\0') {
        src++;
        switch (*src) {
          case 'n': *dst++ = '\n'; break;
          case 'r': *dst++ = '\r'; break;
          case 't': *dst++ = '\t'; break;
          case '\\': *dst++ = '\\'; break;
          case '\"': *dst++ = '\"'; break;
          default: *dst++ = *src; break;
        }
        src++;
        continue;
      }
      *dst++ = *src++;
    }
    *dst = '\0';
  }
}

static void fz_dotenv_load(void) {
  const char* path = getenv("FZ_DOTENV_PATH");
  if (path == NULL || path[0] == '\0') {
    path = ".env";
  }
  FILE* file = fopen(path, "r");
  if (file == NULL) {
    return;
  }
  char line[4096];
  while (fgets(line, sizeof(line), file) != NULL) {
    char* entry = fz_trim_ascii(line);
    if (entry == NULL || entry[0] == '\0' || entry[0] == '#') {
      continue;
    }
    if (strncmp(entry, "export ", 7) == 0) {
      entry = fz_trim_ascii(entry + 7);
      if (entry == NULL || entry[0] == '\0') {
        continue;
      }
    }
    char* eq = strchr(entry, '=');
    if (eq == NULL) {
      continue;
    }
    *eq = '\0';
    char* key = fz_trim_ascii(entry);
    char* value = fz_trim_ascii(eq + 1);
    if (key == NULL || key[0] == '\0' || value == NULL) {
      continue;
    }
    fz_unquote_env_value(value);
    if (getenv(key) == NULL) {
      (void)setenv(key, value, 0);
    }
  }
  fclose(file);
}

static void fz_env_bootstrap(void) {
  fz_dotenv_load();
}

static const char* fz_env_get_bootstrapped(const char* key) {
  if (key == NULL || key[0] == '\0') {
    return NULL;
  }
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  return getenv(key);
}

static int fz_has_env_value(const char* key) {
  const char* value = fz_env_get_bootstrapped(key);
  return value != NULL && value[0] != '\0';
}

static int fz_parse_port_from_env(const char* key, int fallback) {
  const char* raw = fz_env_get_bootstrapped(key);
  if (raw == NULL || raw[0] == '\0') {
    return fallback;
  }
  char* end = NULL;
  long parsed = strtol(raw, &end, 10);
  if (end == raw || parsed <= 0 || parsed > 65535) {
    return fallback;
  }
  return (int)parsed;
}

static int fz_default_port(void) {
  int port = 8787;
  port = fz_parse_port_from_env("PORT", port);
  port = fz_parse_port_from_env("AGENT_PORT", port);
  port = fz_parse_port_from_env("FZ_PORT", port);
  return port;
}

static const char* fz_default_host_name(void) {
  const char* host = fz_env_get_bootstrapped("FZ_HOST");
  if (host == NULL || host[0] == '\0') {
    host = fz_env_get_bootstrapped("AGENT_HOST");
  }
  if (host == NULL || host[0] == '\0') {
    host = "127.0.0.1";
  }
  return host;
}

static uint32_t fz_default_addr(void) {
  const char* host = fz_default_host_name();
  struct in_addr addr;
  if (inet_pton(AF_INET, host, &addr) == 1) {
    return addr.s_addr;
  }
  if (strcmp(host, "localhost") == 0) {
    return htonl(INADDR_LOOPBACK);
  }
  return htonl(INADDR_LOOPBACK);
}

static void fz_log_bind_target(int listener_fd) {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  memset(&addr, 0, sizeof(addr));
  if (getsockname(listener_fd, (struct sockaddr*)&addr, &addr_len) != 0) {
    return;
  }
  char host[64];
  const char* rendered = inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host));
  if (rendered == NULL) {
    rendered = "127.0.0.1";
  }
  int port = (int)ntohs(addr.sin_port);
  const char* host_source = fz_has_env_value("FZ_HOST")
      ? "FZ_HOST"
      : (fz_has_env_value("AGENT_HOST") ? "AGENT_HOST" : "default");
  const char* port_source = fz_has_env_value("FZ_PORT")
      ? "FZ_PORT"
      : (fz_has_env_value("AGENT_PORT")
            ? "AGENT_PORT"
            : (fz_has_env_value("PORT") ? "PORT" : "default"));
  fprintf(
      stderr,
      "[fz-runtime] listen active addr=%s port=%d (host_source=%s port_source=%s)\n",
      rendered,
      port,
      host_source,
      port_source);
  fflush(stderr);
}

static int64_t fz_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

static int32_t fz_exit_class_from_status(int timed_out, int status, int spawn_error) {
  if (spawn_error) {
    return 3;
  }
  if (timed_out) {
    return 2;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status) == 0 ? 0 : 1;
  }
  if (WIFSIGNALED(status)) {
    return 1;
  }
  return 1;
}

static const char* fz_fs_path(void) {
  if (fz_fs_base_path[0] != '\0') {
    return fz_fs_base_path;
  }
  const char* from_env = getenv("FZ_FS_PATH");
  if (from_env == NULL || from_env[0] == '\0') {
    from_env = "/tmp/fozzy_native_store.dat";
  }
  snprintf(fz_fs_base_path, sizeof(fz_fs_base_path), "%s", from_env);
  snprintf(fz_fs_tmp_path, sizeof(fz_fs_tmp_path), "%s.tmp", from_env);
  return fz_fs_base_path;
}

static int fz_fs_ensure_open(void) {
  if (fz_fs_fd >= 0) {
    return fz_fs_fd;
  }
  const char* path = fz_fs_path();
  int fd = open(path, O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  fz_fs_fd = fd;
  return fd;
}

static void fz_http_headers_clear(void) {
  pthread_mutex_lock(&fz_http_lock);
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);
}

static char* fz_json_escape_owned(const char* input) {
  if (input == NULL) {
    input = "";
  }
  size_t in_len = strlen(input);
  size_t cap = (in_len * 6) + 1;
  char* out = (char*)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  size_t j = 0;
  for (size_t i = 0; i < in_len; i++) {
    unsigned char ch = (unsigned char)input[i];
    switch (ch) {
      case '\"': out[j++] = '\\'; out[j++] = '\"'; break;
      case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
      case '\b': out[j++] = '\\'; out[j++] = 'b'; break;
      case '\f': out[j++] = '\\'; out[j++] = 'f'; break;
      case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
      case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
      case '\t': out[j++] = '\\'; out[j++] = 't'; break;
      default:
        if (ch < 0x20) {
          static const char* hex = "0123456789abcdef";
          out[j++] = '\\';
          out[j++] = 'u';
          out[j++] = '0';
          out[j++] = '0';
          out[j++] = hex[(ch >> 4) & 0xF];
          out[j++] = hex[ch & 0xF];
        } else {
          out[j++] = (char)ch;
        }
        break;
    }
  }
  out[j] = '\0';
  return out;
}

static int32_t fz_json_value_alloc(int32_t value_id) {
  if (value_id <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_json_lock);
  for (int i = 0; i < FZ_MAX_JSON_VALUES; i++) {
    if (!fz_json_values[i].in_use) {
      fz_json_values[i].in_use = 1;
      fz_json_values[i].value_id = value_id;
      pthread_mutex_unlock(&fz_json_lock);
      return i + 1;
    }
  }
  pthread_mutex_unlock(&fz_json_lock);
  return -1;
}

static int32_t fz_json_value_get_id(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_JSON_VALUES) {
    return 0;
  }
  pthread_mutex_lock(&fz_json_lock);
  fz_json_value_state* slot = &fz_json_values[handle - 1];
  int32_t value_id = slot->in_use ? slot->value_id : 0;
  pthread_mutex_unlock(&fz_json_lock);
  return value_id;
}

static int32_t fz_json_value_alloc_from_slice(const char* start, const char* end) {
  if (start == NULL || end == NULL || end < start) {
    return -1;
  }
  int32_t value_id = fz_intern_slice(start, (size_t)(end - start));
  if (value_id <= 0) {
    return -1;
  }
  return fz_json_value_alloc(value_id);
}

static const char* fz_json_ws(const char* p) {
  while (p != NULL && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
    p++;
  }
  return p;
}

static int fz_json_match_lit(const char** cursor, const char* lit) {
  const char* p = fz_json_ws(*cursor);
  size_t n = strlen(lit);
  if (strncmp(p, lit, n) != 0) {
    return -1;
  }
  *cursor = p + n;
  return 0;
}

static int fz_json_skip_string_token(const char** cursor) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '\"') {
    return -1;
  }
  p++;
  while (*p != '\0') {
    if (*p == '\"') {
      *cursor = p + 1;
      return 0;
    }
    if (*p == '\\') {
      p++;
      if (*p == '\0') {
        return -1;
      }
      if (*p == 'u') {
        p++;
        for (int i = 0; i < 4; i++) {
          if (!isxdigit((unsigned char)p[i])) {
            return -1;
          }
        }
        p += 4;
        continue;
      }
      p++;
      continue;
    }
    p++;
  }
  return -1;
}

static int fz_json_skip_number_token(const char** cursor) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL) {
    return -1;
  }
  if (*p == '-') {
    p++;
  }
  if (*p == '0') {
    p++;
  } else if (isdigit((unsigned char)*p)) {
    while (isdigit((unsigned char)*p)) p++;
  } else {
    return -1;
  }
  if (*p == '.') {
    p++;
    if (!isdigit((unsigned char)*p)) {
      return -1;
    }
    while (isdigit((unsigned char)*p)) p++;
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') {
      p++;
    }
    if (!isdigit((unsigned char)*p)) {
      return -1;
    }
    while (isdigit((unsigned char)*p)) p++;
  }
  *cursor = p;
  return 0;
}

static int fz_json_skip_value_token(const char** cursor, int depth);

static int fz_json_skip_array_token(const char** cursor, int depth) {
  if (depth > 256) {
    return -1;
  }
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '[') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == ']') {
    *cursor = p + 1;
    return 0;
  }
  for (;;) {
    if (fz_json_skip_value_token(&p, depth + 1) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      *cursor = p + 1;
      return 0;
    }
    return -1;
  }
}

static int fz_json_skip_object_token(const char** cursor, int depth) {
  if (depth > 256) {
    return -1;
  }
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p != '{') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    *cursor = p + 1;
    return 0;
  }
  for (;;) {
    if (fz_json_skip_string_token(&p) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      return -1;
    }
    p = fz_json_ws(p + 1);
    if (fz_json_skip_value_token(&p, depth + 1) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      *cursor = p + 1;
      return 0;
    }
    return -1;
  }
}

static int fz_json_skip_value_token(const char** cursor, int depth) {
  const char* p = fz_json_ws(*cursor);
  if (p == NULL || *p == '\0') {
    return -1;
  }
  int rc = -1;
  switch (*p) {
    case '\"': rc = fz_json_skip_string_token(&p); break;
    case '{': rc = fz_json_skip_object_token(&p, depth); break;
    case '[': rc = fz_json_skip_array_token(&p, depth); break;
    case 't': rc = fz_json_match_lit(&p, "true"); break;
    case 'f': rc = fz_json_match_lit(&p, "false"); break;
    case 'n': rc = fz_json_match_lit(&p, "null"); break;
    default: rc = fz_json_skip_number_token(&p); break;
  }
  if (rc == 0) {
    *cursor = p;
  }
  return rc;
}

static int fz_json_parse_value_slice(const char* raw, const char** out_start, const char** out_end) {
  if (raw == NULL || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* start = fz_json_ws(raw);
  const char* p = start;
  if (fz_json_skip_value_token(&p, 0) != 0) {
    return -1;
  }
  p = fz_json_ws(p);
  if (*p != '\0') {
    return -1;
  }
  *out_start = start;
  *out_end = p;
  return 0;
}

static int fz_json_object_lookup(const char* raw, const char* key, const char** out_start, const char** out_end) {
  if (raw == NULL || key == NULL || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* p = fz_json_ws(raw);
  if (*p != '{') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return 0;
  }
  for (;;) {
    char* candidate = NULL;
    if (fz_json_parse_string(&p, &candidate) != 0) {
      return -1;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      free(candidate);
      return -1;
    }
    p = fz_json_ws(p + 1);
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      free(candidate);
      return -1;
    }
    const char* value_end = p;
    int matches = strcmp(candidate == NULL ? "" : candidate, key) == 0;
    free(candidate);
    if (matches) {
      *out_start = value_start;
      *out_end = value_end;
      return 1;
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return 0;
    }
    return -1;
  }
}

static int fz_json_array_lookup(const char* raw, int index, const char** out_start, const char** out_end) {
  if (raw == NULL || index < 0 || out_start == NULL || out_end == NULL) {
    return -1;
  }
  const char* p = fz_json_ws(raw);
  if (*p != '[') {
    return -1;
  }
  p = fz_json_ws(p + 1);
  if (*p == ']') {
    return 0;
  }
  int at = 0;
  for (;;) {
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      return -1;
    }
    const char* value_end = p;
    if (at == index) {
      *out_start = value_start;
      *out_end = value_end;
      return 1;
    }
    at++;
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      return 0;
    }
    return -1;
  }
}


static int fz_send_all(int fd, const char* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t wrote = send(fd, data + sent, len - sent, 0);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (wrote == 0) {
      return -1;
    }
    sent += (size_t)wrote;
  }
  return 0;
}

static const char* fz_http_reason(int status_code) {
  switch (status_code) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 422: return "Unprocessable Entity";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default: return "OK";
  }
}

static fz_conn_state* fz_conn_state_for(int fd, int create_if_missing) {
  fz_conn_state* free_slot = NULL;
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      return &fz_conn_states[i];
    }
    if (!fz_conn_states[i].in_use && free_slot == NULL) {
      free_slot = &fz_conn_states[i];
    }
  }
  if (!create_if_missing || free_slot == NULL) {
    return NULL;
  }
  memset(free_slot, 0, sizeof(*free_slot));
  free_slot->in_use = 1;
  free_slot->fd = fd;
  return free_slot;
}

static void fz_conn_state_drop(int fd) {
  pthread_mutex_lock(&fz_conn_lock);
  for (int i = 0; i < FZ_MAX_CONN_STATES; i++) {
    if (fz_conn_states[i].in_use && fz_conn_states[i].fd == fd) {
      memset(&fz_conn_states[i], 0, sizeof(fz_conn_states[i]));
      break;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
}

static int fz_find_header_end(const char* buf, int len) {
  for (int i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      return i + 4;
    }
  }
  return -1;
}

static int fz_contains_ci(const char* hay, size_t hay_len, const char* needle) {
  size_t needle_len = strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) {
    return 0;
  }
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    size_t j = 0;
    while (j < needle_len) {
      char a = (char)tolower((unsigned char)hay[i + j]);
      char b = (char)tolower((unsigned char)needle[j]);
      if (a != b) {
        break;
      }
      j++;
    }
    if (j == needle_len) {
      return 1;
    }
  }
  return 0;
}

static int64_t fz_parse_content_length(const char* headers, int header_len) {
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 15 && strncasecmp(cursor, "Content-Length:", 15) == 0) {
      const char* value = cursor + 15;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      char tmp[32];
      size_t max = (size_t)(line_end - value);
      if (max >= sizeof(tmp)) {
        max = sizeof(tmp) - 1;
      }
      memcpy(tmp, value, max);
      tmp[max] = '\0';
      char* parse_end = NULL;
      long long parsed = strtoll(tmp, &parse_end, 10);
      if (parse_end != tmp && parsed >= 0) {
        return parsed;
      }
    }
    cursor = line_end + 2;
  }
  return -1;
}

static int fz_parse_keep_alive(const char* headers, int header_len, const char* version, int version_len) {
  int keep_alive = (version_len >= 8 && strncasecmp(version, "HTTP/1.1", 8) == 0) ? 1 : 0;
  const char* cursor = headers;
  const char* end = headers + header_len;
  while (cursor < end) {
    const char* line_end = strstr(cursor, "\r\n");
    if (line_end == NULL || line_end > end) {
      break;
    }
    if (line_end == cursor) {
      break;
    }
    size_t line_len = (size_t)(line_end - cursor);
    if (line_len >= 11 && strncasecmp(cursor, "Connection:", 11) == 0) {
      const char* value = cursor + 11;
      while (value < line_end && (*value == ' ' || *value == '\t')) {
        value++;
      }
      size_t value_len = (size_t)(line_end - value);
      if (fz_contains_ci(value, value_len, "close")) {
        keep_alive = 0;
      } else if (fz_contains_ci(value, value_len, "keep-alive")) {
        keep_alive = 1;
      }
      break;
    }
    cursor = line_end + 2;
  }
  return keep_alive;
}

static int fz_send_http_response(int conn_fd, int status_code, const char* content_type, const char* body, int close_after) {
  if (conn_fd < 0) {
    return -1;
  }
  if (content_type == NULL || content_type[0] == '\0') {
    content_type = "text/plain; charset=utf-8";
  }
  if (body == NULL) {
    body = "";
  }
  int body_len = (int)strlen(body);
  const char* reason = fz_http_reason(status_code);
  char header[512];
  int header_len = snprintf(
      header,
      sizeof(header),
      "HTTP/1.1 %d %s\r\n"
      "Content-Type: %s\r\n"
      "Content-Length: %d\r\n"
      "Connection: %s\r\n"
      "\r\n",
      status_code,
      reason,
      content_type,
      body_len,
      close_after ? "close" : "keep-alive");
  if (header_len <= 0 || header_len >= (int)sizeof(header)) {
    return -1;
  }
  if (fz_send_all(conn_fd, header, (size_t)header_len) != 0) {
    return -1;
  }
  if (body_len > 0 && fz_send_all(conn_fd, body, (size_t)body_len) != 0) {
    return -1;
  }
  if (close_after) {
    shutdown(conn_fd, SHUT_RDWR);
    close(conn_fd);
    fz_conn_state_drop(conn_fd);
  }
  return 0;
}

static void fz_bytes_buf_init(fz_bytes_buf* buf) {
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static void fz_bytes_buf_free(fz_bytes_buf* buf) {
  if (buf->data != NULL) {
    free(buf->data);
  }
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }
  size_t needed = buf->len + len + 1;
  if (needed > buf->cap) {
    size_t next_cap = buf->cap == 0 ? 4096 : buf->cap;
    while (next_cap < needed) {
      next_cap *= 2;
    }
    char* next = (char*)realloc(buf->data, next_cap);
    if (next == NULL) {
      return -1;
    }
    buf->data = next;
    buf->cap = next_cap;
  }
  memcpy(buf->data + buf->len, data, len);
  buf->len += len;
  buf->data[buf->len] = '\0';
  return 0;
}

static int fz_drain_fd(int fd, fz_bytes_buf* buf) {
  if (fd < 0) {
    return 0;
  }
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(buf, tmp, (size_t)got) != 0) {
        return -1;
      }
      continue;
    }
    if (got == 0) {
      return 1;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
}

static int fz_set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int fz_mark_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static fz_proc_state* fz_proc_state_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_PROC_STATES) {
    return NULL;
  }
  fz_proc_state* state = &fz_proc_states[handle - 1];
  if (!state->in_use) {
    return NULL;
  }
  return state;
}

static void fz_proc_set_last_error(const char* msg) {
  if (msg == NULL) {
    msg = "proc error";
  }
  fz_proc_last_error_id = fz_intern_slice(msg, strlen(msg));
}

static int32_t fz_proc_state_alloc(pid_t pid, int stdout_fd, int stderr_fd) {
  for (int i = 0; i < FZ_MAX_PROC_STATES; i++) {
    if (!fz_proc_states[i].in_use) {
      fz_proc_states[i].in_use = 1;
      fz_proc_states[i].pid = pid;
      fz_proc_states[i].stdout_fd = stdout_fd;
      fz_proc_states[i].stderr_fd = stderr_fd;
      fz_proc_states[i].done = 0;
      fz_proc_states[i].exit_notified = 0;
      fz_proc_states[i].exit_code = -1;
      fz_proc_states[i].stdout_read_pos = 0;
      fz_proc_states[i].stderr_read_pos = 0;
      fz_proc_states[i].stdout_id = 0;
      fz_proc_states[i].stderr_id = 0;
      fz_bytes_buf_init(&fz_proc_states[i].stdout_buf);
      fz_bytes_buf_init(&fz_proc_states[i].stderr_buf);
      return i + 1;
    }
  }
  return -1;
}

static void fz_proc_finalize(fz_proc_state* state, int exit_code) {
  if (state->stdout_fd >= 0) {
    (void)fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    close(state->stdout_fd);
    state->stdout_fd = -1;
  }
  if (state->stderr_fd >= 0) {
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
    close(state->stderr_fd);
    state->stderr_fd = -1;
  }
  state->stdout_id = fz_intern_slice(
      state->stdout_buf.data == NULL ? "" : state->stdout_buf.data,
      state->stdout_buf.data == NULL ? 0 : state->stdout_buf.len);
  state->stderr_id = fz_intern_slice(
      state->stderr_buf.data == NULL ? "" : state->stderr_buf.data,
      state->stderr_buf.data == NULL ? 0 : state->stderr_buf.len);
  state->exit_code = exit_code;
  state->done = 1;
}

static void fz_spawn_join_all(void) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    pthread_t thread;
    int should_join = 0;
    pthread_mutex_lock(&fz_spawn_lock);
    fz_spawn_state* state = &fz_spawn_states[i];
    if (state->in_use && !state->detached && !state->joined) {
      state->joined = 1;
      thread = state->thread;
      should_join = 1;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    if (should_join) {
      (void)pthread_join(thread, NULL);
    }
  }
}

static void fz_spawn_register_atexit(void) {
  const char* max_active = fz_env_get_bootstrapped("FZ_SPAWN_MAX_ACTIVE");
  if (max_active != NULL && max_active[0] != '\0') {
    int parsed = atoi(max_active);
    if (parsed > 0 && parsed <= FZ_MAX_SPAWN_THREADS) {
      fz_spawn_max_active = parsed;
    }
  }
  (void)atexit(fz_spawn_join_all);
}

static fz_spawn_state* fz_spawn_state_by_handle_locked(int32_t handle) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    if (fz_spawn_states[i].in_use && fz_spawn_states[i].handle == handle) {
      return &fz_spawn_states[i];
    }
  }
  return NULL;
}

static fz_spawn_state* fz_spawn_state_alloc_locked(void) {
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    if (!fz_spawn_states[i].in_use) {
      return &fz_spawn_states[i];
    }
  }
  return NULL;
}

static fz_task_group_state* fz_task_group_by_id_locked(int32_t group_id) {
  for (int i = 0; i < 256; i++) {
    if (fz_task_groups[i].in_use && fz_task_groups[i].id == group_id) {
      return &fz_task_groups[i];
    }
  }
  return NULL;
}

static fz_task_group_state* fz_task_group_alloc_locked(void) {
  for (int i = 0; i < 256; i++) {
    if (!fz_task_groups[i].in_use) {
      return &fz_task_groups[i];
    }
  }
  return NULL;
}

static void* fz_spawn_thread_main(void* arg) {
  fz_spawn_ctx* ctx = (fz_spawn_ctx*)arg;
  if (ctx == NULL) {
    return NULL;
  }
  int32_t handle = ctx->handle;
  free(ctx);

  fz_task_entry_fn entry = NULL;
  int32_t context_id = 0;
  int32_t group_id = 0;
  int cancelled = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->started = 1;
    entry = fz_task_entries[state->task_ref - 1];
    context_id = state->context_id;
    group_id = state->group_id;
    cancelled = state->cancelled;
  }
  pthread_mutex_unlock(&fz_spawn_lock);

  int32_t result = -1;
  fz_tls_task_context = context_id;
  if (!cancelled && entry != NULL) {
    result = entry();
  } else if (cancelled) {
    result = -2;
  }

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->finished = 1;
    state->result = result;
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    if (group_id > 0) {
      fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
      if (group != NULL && group->active_count > 0) {
        group->active_count--;
      }
    }
    if (state->detached) {
      memset(state, 0, sizeof(*state));
    }
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return NULL;
}

static int32_t fz_native_spawn_impl(int32_t task_ref, int32_t context_id, int32_t group_id) {
  if (task_ref <= 0 || task_ref > fz_task_entry_count) {
    return -1;
  }
  if (fz_task_entries[task_ref - 1] == NULL) {
    return -1;
  }

  pthread_once(&fz_spawn_atexit_once, fz_spawn_register_atexit);
  pthread_mutex_lock(&fz_spawn_lock);
  if (fz_spawn_active_count >= fz_spawn_max_active) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  if (group_id > 0 && fz_task_group_by_id_locked(group_id) == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  fz_spawn_state* state = fz_spawn_state_alloc_locked();
  if (state == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  memset(state, 0, sizeof(*state));
  state->in_use = 1;
  state->handle = fz_next_spawn_handle++;
  state->task_ref = task_ref;
  state->context_id = context_id;
  state->group_id = group_id;
  if (group_id > 0) {
    fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
    if (group != NULL) {
      group->active_count++;
    }
  }
  fz_spawn_active_count++;
  int32_t handle = state->handle;
  pthread_mutex_unlock(&fz_spawn_lock);

  fz_spawn_ctx* ctx = (fz_spawn_ctx*)malloc(sizeof(fz_spawn_ctx));
  if (ctx == NULL) {
    pthread_mutex_lock(&fz_spawn_lock);
    state = fz_spawn_state_by_handle_locked(handle);
    if (state != NULL) {
      if (state->group_id > 0) {
        fz_task_group_state* group = fz_task_group_by_id_locked(state->group_id);
        if (group != NULL && group->active_count > 0) {
          group->active_count--;
        }
      }
      memset(state, 0, sizeof(*state));
    }
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  ctx->handle = handle;

  pthread_t thread;
  if (pthread_create(&thread, NULL, fz_spawn_thread_main, ctx) != 0) {
    free(ctx);
    pthread_mutex_lock(&fz_spawn_lock);
    state = fz_spawn_state_by_handle_locked(handle);
    if (state != NULL) {
      if (state->group_id > 0) {
        fz_task_group_state* group = fz_task_group_by_id_locked(state->group_id);
        if (group != NULL && group->active_count > 0) {
          group->active_count--;
        }
      }
      memset(state, 0, sizeof(*state));
    }
    if (fz_spawn_active_count > 0) {
      fz_spawn_active_count--;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state != NULL) {
    state->thread = thread;
  }
  pthread_mutex_unlock(&fz_spawn_lock);
  return handle;
}

int32_t fz_native_env_get(int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  if (key == NULL || key[0] == '\0') {
    return 0;
  }
  const char* value = fz_env_get_bootstrapped(key);
  if (value == NULL) {
    value = "";
  }
  return fz_intern_slice(value, strlen(value));
}

int32_t fz_native_time_now(void) {
  return (int32_t)fz_now_ms();
}

int32_t fz_native_http_header(int32_t key_id, int32_t value_id) {
  if (key_id <= 0 || value_id <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_http_lock);
  if (fz_http_header_count >= FZ_MAX_HTTP_HEADERS) {
    pthread_mutex_unlock(&fz_http_lock);
    return -1;
  }
  fz_http_headers[fz_http_header_count].key_id = key_id;
  fz_http_headers[fz_http_header_count].value_id = value_id;
  fz_http_header_count++;
  pthread_mutex_unlock(&fz_http_lock);
  return 0;
}

int32_t fz_native_json_escape(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  char* escaped = fz_json_escape_owned(input);
  if (escaped == NULL) {
    return 0;
  }
  return fz_intern_owned(escaped);
}

int32_t fz_native_json_str(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  char* escaped = fz_json_escape_owned(input);
  if (escaped == NULL) {
    return 0;
  }
  size_t len = strlen(escaped);
  char* wrapped = (char*)malloc(len + 3);
  if (wrapped == NULL) {
    free(escaped);
    return 0;
  }
  wrapped[0] = '\"';
  if (len > 0) {
    memcpy(wrapped + 1, escaped, len);
  }
  wrapped[len + 1] = '\"';
  wrapped[len + 2] = '\0';
  free(escaped);
  return fz_intern_owned(wrapped);
}

int32_t fz_native_json_raw(int32_t input_id) {
  const char* input = fz_lookup_string(input_id);
  if (input == NULL || input[0] == '\0') {
    return fz_intern_slice("null", 4);
  }
  return fz_intern_slice(input, strlen(input));
}

static int32_t fz_native_json_array_from_values(const int32_t* ids, int value_count) {
  if (ids == NULL || value_count <= 0) {
    return fz_intern_slice("[]", 2);
  }
  size_t total = 3;
  for (int i = 0; i < value_count; i++) {
    const char* value = fz_lookup_string(ids[i]);
    total += strlen(value == NULL || value[0] == '\0' ? "null" : value) + 1;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    return 0;
  }
  size_t used = 0;
  out[used++] = '[';
  for (int i = 0; i < value_count; i++) {
    if (i > 0) {
      out[used++] = ',';
    }
    const char* value = fz_lookup_string(ids[i]);
    if (value == NULL || value[0] == '\0') {
      value = "null";
    }
    size_t len = strlen(value);
    if (len > 0) {
      memcpy(out + used, value, len);
      used += len;
    }
  }
  out[used++] = ']';
  out[used] = '\0';
  return fz_intern_owned(out);
}

static int32_t fz_native_json_object_from_pairs(const int32_t* ids, int pair_count) {
  if (ids == NULL || pair_count <= 0) {
    return fz_intern_slice("{}", 2);
  }
  char** escaped_keys = (char**)calloc((size_t)pair_count, sizeof(char*));
  if (escaped_keys == NULL) {
    return 0;
  }
  size_t total = 3;
  for (int i = 0; i < pair_count; i++) {
    const char* key = fz_lookup_string(ids[i * 2]);
    const char* raw_value = fz_lookup_string(ids[(i * 2) + 1]);
    if (raw_value == NULL || raw_value[0] == '\0') {
      raw_value = "null";
    }
    escaped_keys[i] = fz_json_escape_owned(key);
    if (escaped_keys[i] == NULL) {
      for (int j = 0; j <= i; j++) {
        free(escaped_keys[j]);
      }
      free(escaped_keys);
      return 0;
    }
    total += strlen(escaped_keys[i]) + strlen(raw_value) + 5;
  }
  char* body = (char*)malloc(total);
  if (body == NULL) {
    for (int i = 0; i < pair_count; i++) {
      free(escaped_keys[i]);
    }
    free(escaped_keys);
    return 0;
  }
  size_t used = 0;
  body[used++] = '{';
  for (int i = 0; i < pair_count; i++) {
    if (i > 0) {
      body[used++] = ',';
    }
    body[used++] = '\"';
    size_t key_len = strlen(escaped_keys[i]);
    memcpy(body + used, escaped_keys[i], key_len);
    used += key_len;
    body[used++] = '\"';
    body[used++] = ':';
    const char* raw_value = fz_lookup_string(ids[(i * 2) + 1]);
    if (raw_value == NULL || raw_value[0] == '\0') {
      raw_value = "null";
    }
    size_t value_len = strlen(raw_value);
    memcpy(body + used, raw_value, value_len);
    used += value_len;
  }
  body[used++] = '}';
  body[used] = '\0';
  for (int i = 0; i < pair_count; i++) {
    free(escaped_keys[i]);
  }
  free(escaped_keys);
  return fz_intern_owned(body);
}

int32_t fz_native_json_array1(int32_t v1_id) {
  int32_t ids[] = {v1_id};
  return fz_native_json_array_from_values(ids, 1);
}

int32_t fz_native_json_array2(int32_t v1_id, int32_t v2_id) {
  int32_t ids[] = {v1_id, v2_id};
  return fz_native_json_array_from_values(ids, 2);
}

int32_t fz_native_json_array3(int32_t v1_id, int32_t v2_id, int32_t v3_id) {
  int32_t ids[] = {v1_id, v2_id, v3_id};
  return fz_native_json_array_from_values(ids, 3);
}

int32_t fz_native_json_array4(int32_t v1_id, int32_t v2_id, int32_t v3_id, int32_t v4_id) {
  int32_t ids[] = {v1_id, v2_id, v3_id, v4_id};
  return fz_native_json_array_from_values(ids, 4);
}

int32_t fz_native_json_object1(int32_t k1_id, int32_t v1_id) {
  int32_t ids[] = {k1_id, v1_id};
  return fz_native_json_object_from_pairs(ids, 1);
}

int32_t fz_native_json_object2(int32_t k1_id, int32_t v1_id, int32_t k2_id, int32_t v2_id) {
  int32_t ids[] = {k1_id, v1_id, k2_id, v2_id};
  return fz_native_json_object_from_pairs(ids, 2);
}

int32_t fz_native_json_object3(
    int32_t k1_id,
    int32_t v1_id,
    int32_t k2_id,
    int32_t v2_id,
    int32_t k3_id,
    int32_t v3_id) {
  int32_t ids[] = {k1_id, v1_id, k2_id, v2_id, k3_id, v3_id};
  return fz_native_json_object_from_pairs(ids, 3);
}

int32_t fz_native_json_object4(
    int32_t k1_id,
    int32_t v1_id,
    int32_t k2_id,
    int32_t v2_id,
    int32_t k3_id,
    int32_t v3_id,
    int32_t k4_id,
    int32_t v4_id) {
  int32_t ids[] = {k1_id, v1_id, k2_id, v2_id, k3_id, v3_id, k4_id, v4_id};
  return fz_native_json_object_from_pairs(ids, 4);
}

static int32_t fz_runtime_list_new(void) {
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_list_alloc();
  pthread_mutex_unlock(&fz_collections_lock);
  return handle;
}

static int32_t fz_runtime_list_push(int32_t handle, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  int ok = list != NULL && fz_list_push_cstr(list, value) == 0 ? 0 : -1;
  pthread_mutex_unlock(&fz_collections_lock);
  return ok;
}

static int32_t fz_runtime_list_pop(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || list->count <= 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  char* item = list->items[list->count - 1];
  list->items[list->count - 1] = NULL;
  list->count--;
  int32_t id = fz_intern_slice(item == NULL ? "" : item, item == NULL ? 0 : strlen(item));
  free(item);
  pthread_mutex_unlock(&fz_collections_lock);
  return id;
}

static int32_t fz_runtime_list_len(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  int32_t len = list == NULL ? -1 : list->count;
  pthread_mutex_unlock(&fz_collections_lock);
  return len;
}

static int32_t fz_runtime_list_get(int32_t handle, int32_t index) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  const char* item = list->items[index] == NULL ? "" : list->items[index];
  int32_t id = fz_intern_slice(item, strlen(item));
  pthread_mutex_unlock(&fz_collections_lock);
  return id;
}

static int32_t fz_runtime_list_set(int32_t handle, int32_t index, int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL || index < 0 || index >= list->count) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  char* dup = strdup(value);
  if (dup == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  free(list->items[index]);
  list->items[index] = dup;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

static int32_t fz_runtime_list_clear(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < list->count; i++) {
    free(list->items[i]);
    list->items[i] = NULL;
  }
  list->count = 0;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

static int32_t fz_runtime_list_join(int32_t handle, int32_t sep_id) {
  const char* sep = fz_lookup_string(sep_id);
  if (sep == NULL) sep = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  size_t sep_len = strlen(sep);
  size_t total = 1;
  for (int i = 0; i < list->count; i++) {
    total += strlen(list->items[i] == NULL ? "" : list->items[i]);
    if (i > 0) total += sep_len;
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  for (int i = 0; i < list->count; i++) {
    if (i > 0 && sep_len > 0) {
      memcpy(out + used, sep, sep_len);
      used += sep_len;
    }
    const char* item = list->items[i] == NULL ? "" : list->items[i];
    size_t len = strlen(item);
    if (len > 0) {
      memcpy(out + used, item, len);
      used += len;
    }
  }
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

static int32_t fz_runtime_map_new(void) {
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_map_alloc();
  pthread_mutex_unlock(&fz_collections_lock);
  return handle;
}

static int32_t fz_runtime_map_set(int32_t handle, int32_t key_id, int32_t value_id) {
  const char* key = fz_lookup_string(key_id);
  const char* value = fz_lookup_string(value_id);
  if (key == NULL || key[0] == '\0') {
    return -1;
  }
  if (value == NULL) value = "";
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx >= 0) {
    char* dup = strdup(value);
    if (dup == NULL) {
      pthread_mutex_unlock(&fz_collections_lock);
      return -1;
    }
    free(map->values[idx]);
    map->values[idx] = dup;
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  if (map->count >= FZ_MAX_MAP_ENTRIES) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  map->keys[map->count] = strdup(key);
  map->values[map->count] = strdup(value);
  if (map->keys[map->count] == NULL || map->values[map->count] == NULL) {
    free(map->keys[map->count]);
    free(map->values[map->count]);
    map->keys[map->count] = NULL;
    map->values[map->count] = NULL;
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  map->count++;
  pthread_mutex_unlock(&fz_collections_lock);
  return 0;
}

static int32_t fz_runtime_map_get(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  int idx = fz_map_find_index(map, key);
  const char* value = (idx >= 0 && map->values[idx] != NULL) ? map->values[idx] : "";
  int32_t out = fz_intern_slice(value, strlen(value));
  pthread_mutex_unlock(&fz_collections_lock);
  return out;
}

static int32_t fz_runtime_map_has(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  int ok = (map != NULL && key != NULL && fz_map_find_index(map, key) >= 0) ? 1 : 0;
  pthread_mutex_unlock(&fz_collections_lock);
  return ok;
}

static int32_t fz_runtime_map_delete(int32_t handle, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int idx = fz_map_find_index(map, key);
  if (idx < 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  free(map->keys[idx]);
  free(map->values[idx]);
  for (int i = idx; i + 1 < map->count; i++) {
    map->keys[i] = map->keys[i + 1];
    map->values[i] = map->values[i + 1];
  }
  map->count--;
  map->keys[map->count] = NULL;
  map->values[map->count] = NULL;
  pthread_mutex_unlock(&fz_collections_lock);
  return 1;
}

static int32_t fz_runtime_map_keys(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < map->count; i++) {
    (void)fz_list_push_cstr(list, map->keys[i] == NULL ? "" : map->keys[i]);
  }
  pthread_mutex_unlock(&fz_collections_lock);
  return list_handle;
}

static int32_t fz_runtime_map_len(int32_t handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(handle);
  int32_t len = map == NULL ? -1 : map->count;
  pthread_mutex_unlock(&fz_collections_lock);
  return len;
}

static int32_t fz_native_str_concat_parts(const char** parts, int count) {
  if (count <= 0) {
    return fz_intern_slice("", 0);
  }
  size_t total = 1;
  for (int i = 0; i < count; i++) {
    const char* part = parts[i] == NULL ? "" : parts[i];
    total += strlen(part);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    return 0;
  }
  size_t used = 0;
  for (int i = 0; i < count; i++) {
    const char* part = parts[i] == NULL ? "" : parts[i];
    size_t len = strlen(part);
    if (len > 0) {
      memcpy(out + used, part, len);
      used += len;
    }
  }
  out[used] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_concat2(int32_t a_id, int32_t b_id) {
  const char* parts[2] = {fz_lookup_string(a_id), fz_lookup_string(b_id)};
  return fz_native_str_concat_parts(parts, 2);
}

int32_t fz_native_str_concat3(int32_t a_id, int32_t b_id, int32_t c_id) {
  const char* parts[3] = {fz_lookup_string(a_id), fz_lookup_string(b_id), fz_lookup_string(c_id)};
  return fz_native_str_concat_parts(parts, 3);
}

int32_t fz_native_str_concat4(int32_t a_id, int32_t b_id, int32_t c_id, int32_t d_id) {
  const char* parts[4] = {
      fz_lookup_string(a_id), fz_lookup_string(b_id), fz_lookup_string(c_id), fz_lookup_string(d_id)};
  return fz_native_str_concat_parts(parts, 4);
}

int32_t fz_native_str_contains(int32_t value_id, int32_t needle_id) {
  const char* value = fz_lookup_string(value_id);
  const char* needle = fz_lookup_string(needle_id);
  if (value == NULL || needle == NULL) {
    return 0;
  }
  return strstr(value, needle) != NULL ? 1 : 0;
}

int32_t fz_native_str_starts_with(int32_t value_id, int32_t prefix_id) {
  const char* value = fz_lookup_string(value_id);
  const char* prefix = fz_lookup_string(prefix_id);
  if (value == NULL || prefix == NULL) {
    return 0;
  }
  size_t prefix_len = strlen(prefix);
  return strncmp(value, prefix, prefix_len) == 0 ? 1 : 0;
}

int32_t fz_native_str_ends_with(int32_t value_id, int32_t suffix_id) {
  const char* value = fz_lookup_string(value_id);
  const char* suffix = fz_lookup_string(suffix_id);
  if (value == NULL || suffix == NULL) {
    return 0;
  }
  size_t value_len = strlen(value);
  size_t suffix_len = strlen(suffix);
  if (suffix_len > value_len) {
    return 0;
  }
  return memcmp(value + (value_len - suffix_len), suffix, suffix_len) == 0 ? 1 : 0;
}

int32_t fz_native_str_trim(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL) {
    return fz_intern_slice("", 0);
  }
  const unsigned char* start = (const unsigned char*)value;
  while (*start != '\0' && isspace(*start)) {
    start++;
  }
  const unsigned char* end = start + strlen((const char*)start);
  while (end > start && isspace(*(end - 1))) {
    end--;
  }
  return fz_intern_slice((const char*)start, (size_t)(end - start));
}

int32_t fz_native_str_replace(int32_t value_id, int32_t from_id, int32_t to_id) {
  const char* value = fz_lookup_string(value_id);
  const char* from = fz_lookup_string(from_id);
  const char* to = fz_lookup_string(to_id);
  if (value == NULL) value = "";
  if (from == NULL) from = "";
  if (to == NULL) to = "";

  size_t value_len = strlen(value);
  size_t from_len = strlen(from);
  size_t to_len = strlen(to);
  if (from_len == 0) {
    return fz_intern_slice(value, value_len);
  }

  size_t occurrences = 0;
  const char* cursor = value;
  while ((cursor = strstr(cursor, from)) != NULL) {
    occurrences++;
    cursor += from_len;
  }
  if (occurrences == 0) {
    return fz_intern_slice(value, value_len);
  }
  size_t out_len = value_len;
  if (to_len >= from_len) {
    out_len += occurrences * (to_len - from_len);
  } else {
    out_len -= occurrences * (from_len - to_len);
  }
  char* out = (char*)malloc(out_len + 1);
  if (out == NULL) {
    return 0;
  }
  const char* src = value;
  char* dst = out;
  while (1) {
    const char* hit = strstr(src, from);
    if (hit == NULL) {
      size_t tail = strlen(src);
      memcpy(dst, src, tail);
      dst += tail;
      break;
    }
    size_t prefix = (size_t)(hit - src);
    memcpy(dst, src, prefix);
    dst += prefix;
    if (to_len > 0) {
      memcpy(dst, to, to_len);
      dst += to_len;
    }
    src = hit + from_len;
  }
  *dst = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_str_len(int32_t value_id) {
  const char* value = fz_lookup_string(value_id);
  return value == NULL ? 0 : (int32_t)strlen(value);
}

int32_t fz_native_str_slice(int32_t value_id, int32_t start, int32_t span) {
  const char* value = fz_lookup_string(value_id);
  if (value == NULL || span <= 0) {
    return fz_intern_slice("", 0);
  }
  int32_t value_len = (int32_t)strlen(value);
  int32_t begin = start < 0 ? 0 : start;
  if (begin > value_len) {
    begin = value_len;
  }
  int32_t max_span = value_len - begin;
  int32_t take = span > max_span ? max_span : span;
  return fz_intern_slice(value + begin, (size_t)take);
}

int32_t fz_native_str_split(int32_t value_id, int32_t sep_id) {
  const char* value = fz_lookup_string(value_id);
  const char* sep = fz_lookup_string(sep_id);
  if (value == NULL) value = "";
  if (sep == NULL) sep = "";
  int32_t list = fz_runtime_list_new();
  if (list < 0) {
    return -1;
  }
  size_t sep_len = strlen(sep);
  if (sep_len == 0) {
    (void)fz_runtime_list_push(list, fz_intern_slice(value, strlen(value)));
    return list;
  }
  const char* cursor = value;
  while (1) {
    const char* hit = strstr(cursor, sep);
    if (hit == NULL) {
      (void)fz_runtime_list_push(list, fz_intern_slice(cursor, strlen(cursor)));
      break;
    }
    (void)fz_runtime_list_push(list, fz_intern_slice(cursor, (size_t)(hit - cursor)));
    cursor = hit + sep_len;
  }
  return list;
}

int32_t fz_native_list_new(void) { return fz_runtime_list_new(); }
int32_t fz_native_list_push(int32_t handle, int32_t value_id) {
  return fz_runtime_list_push(handle, value_id);
}
int32_t fz_native_list_pop(int32_t handle) { return fz_runtime_list_pop(handle); }
int32_t fz_native_list_len(int32_t handle) { return fz_runtime_list_len(handle); }
int32_t fz_native_list_get(int32_t handle, int32_t index) {
  return fz_runtime_list_get(handle, index);
}
int32_t fz_native_list_set(int32_t handle, int32_t index, int32_t value_id) {
  return fz_runtime_list_set(handle, index, value_id);
}
int32_t fz_native_list_clear(int32_t handle) { return fz_runtime_list_clear(handle); }
int32_t fz_native_list_join(int32_t handle, int32_t sep_id) {
  return fz_runtime_list_join(handle, sep_id);
}

int32_t fz_native_map_new(void) { return fz_runtime_map_new(); }
int32_t fz_native_map_set(int32_t handle, int32_t key_id, int32_t value_id) {
  return fz_runtime_map_set(handle, key_id, value_id);
}
int32_t fz_native_map_get(int32_t handle, int32_t key_id) {
  return fz_runtime_map_get(handle, key_id);
}
int32_t fz_native_map_has(int32_t handle, int32_t key_id) {
  return fz_runtime_map_has(handle, key_id);
}
int32_t fz_native_map_delete(int32_t handle, int32_t key_id) {
  return fz_runtime_map_delete(handle, key_id);
}
int32_t fz_native_map_keys(int32_t handle) { return fz_runtime_map_keys(handle); }
int32_t fz_native_map_len(int32_t handle) { return fz_runtime_map_len(handle); }

int32_t fz_native_json_from_list(int32_t list_handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("[]", 2);
  }
  size_t total = 3;
  for (int i = 0; i < list->count; i++) {
    char* escaped = fz_json_escape_owned(list->items[i] == NULL ? "" : list->items[i]);
    if (escaped == NULL) continue;
    total += strlen(escaped) + 3;
    free(escaped);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '[';
  for (int i = 0; i < list->count; i++) {
    if (i > 0) out[used++] = ',';
    char* escaped = fz_json_escape_owned(list->items[i] == NULL ? "" : list->items[i]);
    if (escaped == NULL) {
      out[used++] = '\"';
      out[used++] = '\"';
      continue;
    }
    out[used++] = '\"';
    size_t n = strlen(escaped);
    memcpy(out + used, escaped, n);
    used += n;
    out[used++] = '\"';
    free(escaped);
  }
  out[used++] = ']';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_from_map(int32_t map_handle) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("{}", 2);
  }
  size_t total = 3;
  for (int i = 0; i < map->count; i++) {
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    char* v = fz_json_escape_owned(map->values[i] == NULL ? "" : map->values[i]);
    if (k != NULL && v != NULL) {
      total += strlen(k) + strlen(v) + 7;
    }
    free(k);
    free(v);
  }
  char* out = (char*)malloc(total);
  if (out == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  size_t used = 0;
  out[used++] = '{';
  for (int i = 0; i < map->count; i++) {
    if (i > 0) out[used++] = ',';
    char* k = fz_json_escape_owned(map->keys[i] == NULL ? "" : map->keys[i]);
    char* v = fz_json_escape_owned(map->values[i] == NULL ? "" : map->values[i]);
    if (k == NULL || v == NULL) {
      free(k);
      free(v);
      out[used++] = '\"';
      out[used++] = '\"';
      out[used++] = ':';
      out[used++] = '\"';
      out[used++] = '\"';
      continue;
    }
    out[used++] = '\"';
    size_t kn = strlen(k);
    memcpy(out + used, k, kn);
    used += kn;
    out[used++] = '\"';
    out[used++] = ':';
    out[used++] = '\"';
    size_t vn = strlen(v);
    memcpy(out + used, v, vn);
    used += vn;
    out[used++] = '\"';
    free(k);
    free(v);
  }
  out[used++] = '}';
  out[used] = '\0';
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_intern_owned(out);
}

int32_t fz_native_json_to_list(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  char** items = NULL;
  int count = 0;
  if (fz_parse_json_string_array(raw, &items, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(handle);
  if (list != NULL) {
    for (int i = 0; i < count; i++) {
      (void)fz_list_push_cstr(list, items[i] == NULL ? "" : items[i]);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  fz_free_string_list(items, count);
  return handle;
}

int32_t fz_native_json_to_map(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  char** pairs = NULL;
  int count = 0;
  if (fz_parse_json_env_object(raw, &pairs, &count) != 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_map_alloc();
  fz_map_state* map = fz_map_get(handle);
  if (map != NULL) {
    for (int i = 0; i < count && map->count < FZ_MAX_MAP_ENTRIES; i++) {
      char* eq = strchr(pairs[i], '=');
      if (eq == NULL) continue;
      *eq = '\0';
      map->keys[map->count] = strdup(pairs[i]);
      map->values[map->count] = strdup(eq + 1);
      if (map->keys[map->count] != NULL && map->values[map->count] != NULL) {
        map->count++;
      }
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  fz_free_string_list(pairs, count);
  return handle;
}

int32_t fz_native_json_parse(int32_t json_id) {
  const char* raw = fz_lookup_string(json_id);
  const char* start = NULL;
  const char* end = NULL;
  if (fz_json_parse_value_slice(raw, &start, &end) != 0) {
    return -1;
  }
  return fz_json_value_alloc_from_slice(start, end);
}

int32_t fz_native_json_get(int32_t json_value_handle, int32_t key_id) {
  int32_t value_id = fz_json_value_get_id(json_value_handle);
  const char* raw = fz_lookup_string(value_id);
  const char* key = fz_lookup_string(key_id);
  const char* start = NULL;
  const char* end = NULL;
  int rc = fz_json_object_lookup(raw, key == NULL ? "" : key, &start, &end);
  if (rc <= 0) {
    return -1;
  }
  return fz_json_value_alloc_from_slice(start, end);
}

int32_t fz_native_json_get_str(int32_t json_value_handle, int32_t key_id) {
  int32_t child = fz_native_json_get(json_value_handle, key_id);
  int32_t value_id = fz_json_value_get_id(child);
  const char* raw = fz_lookup_string(value_id);
  if (raw == NULL) {
    return fz_intern_slice("", 0);
  }
  const char* p = raw;
  char* out = NULL;
  if (fz_json_parse_string(&p, &out) != 0) {
    return fz_intern_slice("", 0);
  }
  p = fz_json_ws(p);
  if (*p != '\0' || out == NULL) {
    free(out);
    return fz_intern_slice("", 0);
  }
  return fz_intern_owned(out);
}

int32_t fz_native_json_has(int32_t json_value_handle, int32_t key_id) {
  int32_t value_id = fz_json_value_get_id(json_value_handle);
  const char* raw = fz_lookup_string(value_id);
  const char* key = fz_lookup_string(key_id);
  const char* start = NULL;
  const char* end = NULL;
  int rc = fz_json_object_lookup(raw, key == NULL ? "" : key, &start, &end);
  return rc > 0 ? 1 : 0;
}

int32_t fz_native_json_path(int32_t json_value_handle, int32_t path_id) {
  int32_t current = json_value_handle;
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return current;
  }
  const char* p = fz_json_ws(path);
  if (*p == '$') {
    p++;
  }
  if (*p == '.') {
    p++;
  }

  while (*p != '\0') {
    p = fz_json_ws(p);
    if (*p == '\0') {
      break;
    }
    if (*p == '.') {
      p++;
      continue;
    }
    if (*p == '[') {
      p++;
      int idx = 0;
      if (!isdigit((unsigned char)*p)) {
        return -1;
      }
      while (isdigit((unsigned char)*p)) {
        idx = (idx * 10) + (*p - '0');
        p++;
      }
      if (*p != ']') {
        return -1;
      }
      p++;
      int32_t value_id = fz_json_value_get_id(current);
      const char* raw = fz_lookup_string(value_id);
      const char* start = NULL;
      const char* end = NULL;
      int rc = fz_json_array_lookup(raw, idx, &start, &end);
      if (rc <= 0) {
        return -1;
      }
      current = fz_json_value_alloc_from_slice(start, end);
      if (current <= 0) {
        return -1;
      }
      continue;
    }
    const char* key_start = p;
    while (*p != '\0' && *p != '.' && *p != '[' && !isspace((unsigned char)*p)) {
      p++;
    }
    if (p == key_start) {
      return -1;
    }
    int32_t key_id = fz_intern_slice(key_start, (size_t)(p - key_start));
    current = fz_native_json_get(current, key_id);
    if (current <= 0) {
      return -1;
    }
  }

  return current;
}

static void fz_http_set_last_result(int status_code, const char* body, const char* err) {
  if (body == NULL) {
    body = "";
  }
  if (err == NULL) {
    err = "";
  }
  pthread_mutex_lock(&fz_http_lock);
  fz_http_last_status = status_code;
  fz_http_last_body_id = fz_intern_slice(body, strlen(body));
  fz_http_last_error_id = fz_intern_slice(err, strlen(err));
  pthread_mutex_unlock(&fz_http_lock);
}

static int fz_http_extract_status(char* payload, size_t payload_len, int* status_code, size_t* body_len) {
  if (status_code != NULL) {
    *status_code = 0;
  }
  if (body_len != NULL) {
    *body_len = payload_len;
  }
  if (payload == NULL || payload_len == 0) {
    return -1;
  }
  ssize_t i = (ssize_t)payload_len - 1;
  while (i >= 0 && (payload[i] == '\n' || payload[i] == '\r' || payload[i] == ' ' || payload[i] == '\t')) {
    i--;
  }
  if (i < 2) {
    return -1;
  }
  if (!isdigit((unsigned char)payload[i]) || !isdigit((unsigned char)payload[i - 1]) || !isdigit((unsigned char)payload[i - 2])) {
    return -1;
  }
  int parsed = (payload[i - 2] - '0') * 100 + (payload[i - 1] - '0') * 10 + (payload[i] - '0');
  ssize_t j = i - 3;
  while (j >= 0 && (payload[j] == '\n' || payload[j] == '\r')) {
    j--;
  }
  if (status_code != NULL) {
    *status_code = parsed;
  }
  if (body_len != NULL) {
    *body_len = (size_t)(j + 1);
  }
  return 0;
}

static int32_t fz_native_http_post_json_inner(int32_t endpoint_id, int32_t body_id, int return_body) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  const char* endpoint = fz_lookup_string(endpoint_id);
  const char* body = fz_lookup_string(body_id);
  if (endpoint == NULL || endpoint[0] == '\0') {
    fz_last_exit_class = 3;
    fz_set_last_error(EINVAL, 3, "http_post_json failed: endpoint is empty");
    fz_http_set_last_result(0, "", "http_post_json: empty endpoint");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  if (strstr(endpoint, "api.anthropic.com") != NULL) {
    const char* key = fz_env_get_bootstrapped("ANTHROPIC_API_KEY");
    if (key == NULL || key[0] == '\0') {
      const char* msg =
          "http_post_json failed: ANTHROPIC_API_KEY missing; export it or define it in .env";
      fz_last_exit_class = 3;
      fz_set_last_error(22, 3, msg);
      fz_http_set_last_result(0, "", msg);
      return return_body ? fz_intern_slice("", 0) : -1;
    }
  }
  if (body == NULL || body[0] == '\0') {
    body = "{}";
  }

  char* header_buf[FZ_MAX_HTTP_HEADERS];
  int header_count = 0;
  pthread_mutex_lock(&fz_http_lock);
  for (int i = 0; i < fz_http_header_count && i < FZ_MAX_HTTP_HEADERS; i++) {
    const char* key = fz_lookup_string(fz_http_headers[i].key_id);
    const char* value = fz_lookup_string(fz_http_headers[i].value_id);
    if (key == NULL || key[0] == '\0') {
      continue;
    }
    if (value == NULL) {
      value = "";
    }
    size_t n = strlen(key) + strlen(value) + 3;
    char* kv = (char*)malloc(n);
    if (kv == NULL) {
      continue;
    }
    snprintf(kv, n, "%s: %s", key, value);
    header_buf[header_count++] = kv;
  }
  fz_http_header_count = 0;
  pthread_mutex_unlock(&fz_http_lock);

  int max_args = 20 + (header_count * 2);
  char** argv = (char**)calloc((size_t)max_args, sizeof(char*));
  if (argv == NULL) {
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(ENOMEM, 3, "http_post_json failed: argv alloc failed");
    fz_http_set_last_result(0, "", "http_post_json: alloc failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  int ai = 0;
  argv[ai++] = "curl";
  argv[ai++] = "-sS";
  argv[ai++] = "-X";
  argv[ai++] = "POST";
  argv[ai++] = (char*)endpoint;
  for (int i = 0; i < header_count; i++) {
    argv[ai++] = "-H";
    argv[ai++] = header_buf[i];
  }
  argv[ai++] = "--data";
  argv[ai++] = (char*)body;
  argv[ai++] = "--connect-timeout";
  argv[ai++] = "10";
  argv[ai++] = "--max-time";
  argv[ai++] = "60";
  argv[ai++] = "-w";
  argv[ai++] = "\n%{http_code}";
  argv[ai++] = NULL;

  int out_pipe[2];
  int err_pipe[2];
  if (pipe(out_pipe) != 0) {
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_post_json failed: pipe failed");
    fz_http_set_last_result(0, "", "http_post_json: pipe failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_post_json failed: stderr pipe failed");
    fz_http_set_last_result(0, "", "http_post_json: stderr pipe failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    free(argv);
    for (int i = 0; i < header_count; i++) free(header_buf[i]);
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_post_json failed: fork failed");
    fz_http_set_last_result(0, "", "http_post_json: fork failed");
    return return_body ? fz_intern_slice("", 0) : -1;
  }

  if (pid == 0) {
    (void)dup2(out_pipe[1], STDOUT_FILENO);
    (void)dup2(err_pipe[1], STDERR_FILENO);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    execvp("curl", argv);
    argv[0] = "/usr/bin/curl";
    execv("/usr/bin/curl", argv);
    argv[0] = "/opt/homebrew/bin/curl";
    execv("/opt/homebrew/bin/curl", argv);
    dprintf(STDERR_FILENO, "http_post_json failed: unable to exec curl (%s)\n", strerror(errno));
    _exit(127);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  fz_bytes_buf out;
  fz_bytes_buf_init(&out);
  fz_bytes_buf err;
  fz_bytes_buf_init(&err);
  for (;;) {
    char tmp[4096];
    ssize_t got = read(out_pipe[0], tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&out, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    break;
  }
  close(out_pipe[0]);
  for (;;) {
    char tmp[4096];
    ssize_t got = read(err_pipe[0], tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&err, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    break;
  }
  close(err_pipe[0]);

  int status = 0;
  int waited = waitpid(pid, &status, 0);
  free(argv);
  for (int i = 0; i < header_count; i++) free(header_buf[i]);
  if (waited < 0) {
    fz_last_exit_class = 3;
    fz_set_last_error(errno, 3, "http_post_json failed: waitpid failed");
    fz_http_set_last_result(0, "", "http_post_json: waitpid failed");
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? fz_intern_slice("", 0) : -1;
  }
  fz_last_exit_class = fz_exit_class_from_status(0, status, 0);

  int status_code = 0;
  size_t body_len = out.len;
  int parsed_status = fz_http_extract_status(out.data, out.len, &status_code, &body_len);
  const char* body_text = out.data == NULL ? "" : out.data;
  const char* err_text = err.data == NULL ? "" : err.data;
  char saved = '\0';
  if (out.data != NULL && body_len < out.len) {
    saved = out.data[body_len];
    out.data[body_len] = '\0';
  }
  int32_t body_value_id = fz_intern_slice(body_text, strlen(body_text));
  if (out.data != NULL && body_len < out.len) {
    out.data[body_len] = saved;
  }
  int transport_status = status_code > 0 ? status_code : 599;
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && parsed_status == 0) {
    fz_http_set_last_result(status_code, body_text, err_text);
    fz_set_last_error(0, 0, "");
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? body_value_id : 0;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    const char* msg = "http_post_json failed: missing HTTP status trailer from transport";
    fz_http_set_last_result(transport_status, body_text, msg);
    fz_set_last_error(transport_status, 3, msg);
    int32_t fallback = strlen(body_text) > 0 ? body_value_id : fz_intern_slice(msg, strlen(msg));
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? fallback : transport_status;
  }
  if (WIFEXITED(status)) {
    char msg[256];
    snprintf(
        msg,
        sizeof(msg),
        "http_post_json failed: curl exit=%d endpoint=%s",
        WEXITSTATUS(status),
        endpoint);
    const char* err_msg = (err_text[0] != '\0') ? err_text : msg;
    const char* body_for_failure = (body_text[0] != '\0') ? body_text : err_msg;
    int32_t failure_body_id = fz_intern_slice(body_for_failure, strlen(body_for_failure));
    fz_http_set_last_result(transport_status, body_for_failure, err_msg);
    fz_set_last_error(WEXITSTATUS(status), 3, msg);
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? failure_body_id : WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    char msg[256];
    snprintf(
        msg,
        sizeof(msg),
        "http_post_json failed: curl terminated by signal=%d endpoint=%s",
        WTERMSIG(status),
        endpoint);
    const char* err_msg = (err_text[0] != '\0') ? err_text : msg;
    const char* body_for_failure = (body_text[0] != '\0') ? body_text : err_msg;
    int32_t failure_body_id = fz_intern_slice(body_for_failure, strlen(body_for_failure));
    fz_http_set_last_result(transport_status, body_for_failure, err_msg);
    fz_set_last_error(128 + WTERMSIG(status), 3, msg);
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? failure_body_id : (128 + WTERMSIG(status));
  }
  {
    const char* msg = "http_post_json failed: unknown child status";
    const char* err_msg = (err_text[0] != '\0') ? err_text : msg;
    const char* body_for_failure = (body_text[0] != '\0') ? body_text : err_msg;
    int32_t failure_body_id = fz_intern_slice(body_for_failure, strlen(body_for_failure));
    fz_http_set_last_result(transport_status, body_for_failure, err_msg);
    fz_set_last_error(-1, 3, msg);
    fz_bytes_buf_free(&out);
    fz_bytes_buf_free(&err);
    return return_body ? failure_body_id : -1;
  }
}

int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id) {
  return fz_native_http_post_json_inner(endpoint_id, body_id, 0);
}

int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id) {
  return fz_native_http_post_json_inner(endpoint_id, body_id, 1);
}

int32_t fz_native_http_last_status(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_status;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_body(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_body_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_http_last_error(void) {
  pthread_mutex_lock(&fz_http_lock);
  int32_t value = fz_http_last_error_id;
  pthread_mutex_unlock(&fz_http_lock);
  return value;
}

int32_t fz_native_error_code(void) {
  return fz_last_error_code;
}

int32_t fz_native_error_class(void) {
  return fz_last_error_class;
}

int32_t fz_native_error_message(void) {
  return fz_last_error_message_id;
}

int32_t fz_native_error_context(int32_t ctx_id) {
  const char* ctx = fz_lookup_string(ctx_id);
  const char* msg = fz_lookup_string(fz_last_error_message_id);
  if (ctx == NULL || ctx[0] == '\0') {
    return 0;
  }
  if (msg == NULL) {
    msg = "";
  }
  size_t n = strlen(msg) + strlen(ctx) + 4;
  char* out = (char*)malloc(n);
  if (out == NULL) {
    return -1;
  }
  snprintf(out, n, "%s: %s", msg, ctx);
  fz_last_error_message_id = fz_intern_owned(out);
  return 0;
}

static int32_t fz_log_emit(const char* level, const char* message, const char* fields) {
  if (level == NULL) level = "info";
  if (message == NULL) message = "";
  if (fields == NULL) fields = "{}";
  int64_t ts = fz_now_ms();
  if (fz_log_json) {
    fprintf(stdout, "{\"ts\":%lld,\"level\":\"%s\",\"msg\":\"", (long long)ts, level);
    for (const char* p = message; *p; p++) {
      if (*p == '"' || *p == '\\') fputc('\\', stdout);
      fputc(*p, stdout);
    }
    fprintf(stdout, "\",\"fields\":%s}\n", fields[0] == '\0' ? "{}" : fields);
  } else if (fields[0] != '\0' && strcmp(fields, "{}") != 0) {
    fprintf(stdout, "[%lld] %s %s | fields=%s\n", (long long)ts, level, message, fields);
  } else {
    fprintf(stdout, "[%lld] %s %s\n", (long long)ts, level, message);
  }
  fflush(stdout);
  return 0;
}

int32_t fz_native_log_info(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("info", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_warn(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("warn", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_error(int32_t message_id, int32_t fields_id) {
  return fz_log_emit("error", fz_lookup_string(message_id), fz_lookup_string(fields_id));
}

int32_t fz_native_log_fields1(int32_t k1_id, int32_t v1_id) {
  int32_t value = fz_native_json_str(v1_id);
  return fz_native_json_object1(k1_id, value);
}

int32_t fz_native_log_fields2(int32_t k1_id, int32_t v1_id, int32_t k2_id, int32_t v2_id) {
  int32_t value1 = fz_native_json_str(v1_id);
  int32_t value2 = fz_native_json_str(v2_id);
  return fz_native_json_object2(k1_id, value1, k2_id, value2);
}

int32_t fz_native_log_fields3(
    int32_t k1_id,
    int32_t v1_id,
    int32_t k2_id,
    int32_t v2_id,
    int32_t k3_id,
    int32_t v3_id) {
  int32_t value1 = fz_native_json_str(v1_id);
  int32_t value2 = fz_native_json_str(v2_id);
  int32_t value3 = fz_native_json_str(v3_id);
  return fz_native_json_object3(k1_id, value1, k2_id, value2, k3_id, value3);
}

int32_t fz_native_log_fields4(
    int32_t k1_id,
    int32_t v1_id,
    int32_t k2_id,
    int32_t v2_id,
    int32_t k3_id,
    int32_t v3_id,
    int32_t k4_id,
    int32_t v4_id) {
  int32_t value1 = fz_native_json_str(v1_id);
  int32_t value2 = fz_native_json_str(v2_id);
  int32_t value3 = fz_native_json_str(v3_id);
  int32_t value4 = fz_native_json_str(v4_id);
  return fz_native_json_object4(k1_id, value1, k2_id, value2, k3_id, value3, k4_id, value4);
}

int32_t fz_native_log_set_json(int32_t enabled) {
  fz_log_json = enabled != 0 ? 1 : 0;
  return 0;
}

int32_t fz_native_log_correlation_id(int32_t conn_fd) {
  return fz_native_net_request_id(conn_fd);
}

int32_t fz_native_time_sleep_ms(int32_t ms) {
  if (ms > 0) {
    usleep((useconds_t)ms * 1000);
  }
  return 0;
}

int32_t fz_native_time_elapsed_ms(int32_t start_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now - (int64_t)start_ms);
}

int32_t fz_native_time_deadline_after(int32_t delta_ms) {
  int64_t now = fz_now_ms();
  return (int32_t)(now + (int64_t)delta_ms);
}

int32_t fz_native_time_interval(int32_t period_ms) {
  if (period_ms <= 0) {
    return -1;
  }
  pthread_mutex_lock(&fz_time_lock);
  int32_t handle = -1;
  for (int i = 0; i < FZ_MAX_INTERVALS; i++) {
    if (!fz_intervals[i].in_use) {
      fz_intervals[i].in_use = 1;
      fz_intervals[i].period_ms = period_ms;
      fz_intervals[i].next_ms = fz_now_ms() + period_ms;
      handle = i + 1;
      break;
    }
  }
  pthread_mutex_unlock(&fz_time_lock);
  return handle;
}

int32_t fz_native_time_tick(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_INTERVALS) {
    return -1;
  }
  pthread_mutex_lock(&fz_time_lock);
  fz_interval_state* interval = &fz_intervals[handle - 1];
  if (!interval->in_use) {
    pthread_mutex_unlock(&fz_time_lock);
    return -1;
  }
  int64_t now = fz_now_ms();
  int64_t wait_ms = interval->next_ms - now;
  if (wait_ms > 0) {
    pthread_mutex_unlock(&fz_time_lock);
    usleep((useconds_t)wait_ms * 1000);
    pthread_mutex_lock(&fz_time_lock);
    interval = &fz_intervals[handle - 1];
  }
  now = fz_now_ms();
  interval->next_ms = now + interval->period_ms;
  pthread_mutex_unlock(&fz_time_lock);
  return 0;
}

int32_t fz_native_fs_open(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  pthread_mutex_unlock(&fz_fs_lock);
  return fd;
}

int32_t fz_native_fs_write(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  const char* payload = "fozzy\n";
  ssize_t wrote = write(fd, payload, strlen(payload));
  pthread_mutex_unlock(&fz_fs_lock);
  return wrote < 0 ? -1 : (int32_t)wrote;
}

int32_t fz_native_fs_read(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  lseek(fd, 0, SEEK_SET);
  char buf[4096];
  ssize_t got = read(fd, buf, sizeof(buf));
  pthread_mutex_unlock(&fz_fs_lock);
  return got < 0 ? -1 : (int32_t)got;
}

int32_t fz_native_fs_flush(void) {
  pthread_mutex_lock(&fz_fs_lock);
  int fd = fz_fs_ensure_open();
  int rc = (fd < 0) ? -1 : fsync(fd);
  pthread_mutex_unlock(&fz_fs_lock);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_fs_fsync(void) {
  return fz_native_fs_flush();
}

int32_t fz_native_fs_atomic_write(void) {
  pthread_mutex_lock(&fz_fs_lock);
  const char* path = fz_fs_path();
  (void)path;
  int fd = open(fz_fs_tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    pthread_mutex_unlock(&fz_fs_lock);
    return -1;
  }
  const char* payload = "{}\n";
  int ok = 0;
  if (write(fd, payload, strlen(payload)) < 0) {
    ok = -1;
  }
  if (fsync(fd) != 0) {
    ok = -1;
  }
  close(fd);
  pthread_mutex_unlock(&fz_fs_lock);
  return ok;
}

int32_t fz_native_fs_rename_atomic(void) {
  pthread_mutex_lock(&fz_fs_lock);
  const char* path = fz_fs_path();
  int rc = rename(fz_fs_tmp_path, path);
  pthread_mutex_unlock(&fz_fs_lock);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_fs_read_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return fz_intern_slice("", 0);
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.read_file failed");
    return fz_intern_slice("", 0);
  }
  fz_bytes_buf buf;
  fz_bytes_buf_init(&buf);
  char tmp[4096];
  for (;;) {
    ssize_t got = read(fd, tmp, sizeof(tmp));
    if (got > 0) {
      if (fz_bytes_buf_append(&buf, tmp, (size_t)got) != 0) {
        break;
      }
      continue;
    }
    if (got == 0) break;
    if (errno == EINTR) continue;
    break;
  }
  close(fd);
  int32_t out = fz_intern_slice(buf.data == NULL ? "" : buf.data, buf.len);
  fz_bytes_buf_free(&buf);
  return out;
}

int32_t fz_native_fs_write_file(int32_t path_id, int32_t content_id) {
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(content_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (content == NULL) content = "";
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    fz_set_last_error(errno, 3, "fs.write_file open failed");
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t wrote = write(fd, p, left);
    if (wrote < 0) {
      if (errno == EINTR) continue;
      close(fd);
      fz_set_last_error(errno, 3, "fs.write_file write failed");
      return -1;
    }
    if (wrote == 0) break;
    p += wrote;
    left -= (size_t)wrote;
  }
  close(fd);
  return 0;
}

int32_t fz_native_fs_mkdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
  return -1;
}

int32_t fz_native_fs_exists(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return 0;
  struct stat st;
  return stat(path, &st) == 0 ? 1 : 0;
}

int32_t fz_native_fs_stat_size(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return (int32_t)st.st_size;
}

int32_t fz_native_fs_listdir(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  DIR* dir = opendir(path);
  if (dir == NULL) return -1;
  pthread_mutex_lock(&fz_collections_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    struct dirent* ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
      (void)fz_list_push_cstr(list, ent->d_name);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  closedir(dir);
  return list_handle;
}

int32_t fz_native_fs_remove_file(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') return -1;
  return unlink(path) == 0 ? 0 : -1;
}

int32_t fz_native_fs_temp_file(int32_t prefix_id) {
  const char* prefix = fz_lookup_string(prefix_id);
  if (prefix == NULL || prefix[0] == '\0') prefix = "fz";
  char tmpl[512];
  snprintf(tmpl, sizeof(tmpl), "/tmp/%s-XXXXXX", prefix);
  int fd = mkstemp(tmpl);
  if (fd < 0) return fz_intern_slice("", 0);
  close(fd);
  return fz_intern_slice(tmpl, strlen(tmpl));
}

int32_t fz_native_path_join(int32_t left_id, int32_t right_id) {
  const char* left = fz_lookup_string(left_id);
  const char* right = fz_lookup_string(right_id);
  if (left == NULL) left = "";
  if (right == NULL) right = "";
  size_t left_len = strlen(left);
  size_t right_len = strlen(right);
  int need_sep = left_len > 0 && left[left_len - 1] != '/';
  char* out = (char*)malloc(left_len + right_len + (need_sep ? 2 : 1));
  if (out == NULL) return 0;
  strcpy(out, left);
  if (need_sep) strcat(out, "/");
  strcat(out, right);
  return fz_intern_owned(out);
}

int32_t fz_native_path_normalize(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL) path = "";
  char* out = strdup(path);
  if (out == NULL) return 0;
  size_t w = 0;
  for (size_t r = 0; out[r] != '\0'; r++) {
    if (out[r] == '/' && w > 0 && out[w - 1] == '/') continue;
    out[w++] = out[r];
  }
  if (w > 1 && out[w - 1] == '/') w--;
  out[w] = '\0';
  return fz_intern_owned(out);
}

int32_t fz_native_net_bind(void) {
  (void)pthread_once(&fz_env_bootstrap_once, fz_env_bootstrap);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "http.bind failed: socket() errno=%d (%s)", errno, strerror(errno));
    fz_set_last_error(errno, 3, msg);
    return -1;
  }
  (void)fz_mark_cloexec(fd);
  int yes = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = fz_default_addr();
  addr.sin_port = htons((uint16_t)fz_default_port());
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    char host[64];
    const char* rendered = inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host));
    if (rendered == NULL) {
      rendered = fz_default_host_name();
    }
    int bind_port = (int)ntohs(addr.sin_port);
    char msg[320];
    snprintf(
        msg,
        sizeof(msg),
        "http.bind failed on %s:%d errno=%d (%s); set FZ_HOST/FZ_PORT or AGENT_HOST/AGENT_PORT",
        rendered,
        bind_port,
        errno,
        strerror(errno));
    fz_set_last_error(errno, 3, msg);
    close(fd);
    return -1;
  }
  pthread_mutex_lock(&fz_listener_lock);
  fz_listener_fd = fd;
  pthread_mutex_unlock(&fz_listener_lock);
  fz_set_last_error(0, 0, "");
  return fd;
}

int32_t fz_native_net_listen(int32_t fd) {
  int listener = fd;
  if (listener < 0) {
    pthread_mutex_lock(&fz_listener_lock);
    listener = fz_listener_fd;
    pthread_mutex_unlock(&fz_listener_lock);
  }
  if (listener < 0) {
    fz_set_last_error(EINVAL, 3, "http.listen failed: no listener fd (call http.bind first)");
    return -1;
  }
  if (listen(listener, 128) != 0) {
    char msg[256];
    snprintf(
        msg,
        sizeof(msg),
        "http.listen failed fd=%d backlog=128 errno=%d (%s)",
        listener,
        errno,
        strerror(errno));
    fz_set_last_error(errno, 3, msg);
    return -1;
  }
  fz_log_bind_target(listener);
  fz_set_last_error(0, 0, "");
  return 0;
}

int32_t fz_native_net_accept(void) {
  int listener = -1;
  pthread_mutex_lock(&fz_listener_lock);
  listener = fz_listener_fd;
  pthread_mutex_unlock(&fz_listener_lock);
  if (listener < 0) {
    fz_set_last_error(EINVAL, 3, "http.accept failed: listener not initialized");
    return -1;
  }
  struct sockaddr_in peer;
  socklen_t peer_len = sizeof(peer);
  int conn_fd = accept(listener, (struct sockaddr*)&peer, &peer_len);
  if (conn_fd < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      char msg[256];
      snprintf(
          msg,
          sizeof(msg),
          "http.accept failed listener=%d errno=%d (%s)",
          listener,
          errno,
          strerror(errno));
      fz_set_last_error(errno, 3, msg);
    }
    return -1;
  }
  (void)fz_mark_cloexec(conn_fd);
  char peer_addr[64];
  const char* rendered = inet_ntop(AF_INET, &peer.sin_addr, peer_addr, sizeof(peer_addr));
  if (rendered == NULL) {
    rendered = "";
  }
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    state->remote_addr_id = fz_intern_slice(rendered, strlen(rendered));
    state->request_id = 0;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  fz_set_last_error(0, 0, "");
  return conn_fd;
}

int32_t fz_native_net_read(int32_t conn_fd) {
  if (conn_fd < 0) {
    return -1;
  }
  char* req = (char*)malloc(FZ_MAX_HTTP_READ + 1);
  if (req == NULL) {
    return -1;
  }
  int total = 0;
  int header_end = -1;
  int64_t content_length = -1;
  while (total < FZ_MAX_HTTP_READ) {
    ssize_t got = recv(conn_fd, req + total, (size_t)(FZ_MAX_HTTP_READ - total), 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      free(req);
      return -1;
    }
    if (got == 0) {
      break;
    }
    total += (int)got;
    req[total] = '\0';
    if (header_end < 0) {
      header_end = fz_find_header_end(req, total);
      if (header_end >= 0) {
        content_length = fz_parse_content_length(req, header_end);
      }
    }
    if (header_end >= 0) {
      if (content_length >= 0) {
        if (total >= header_end + content_length) {
          break;
        }
      } else {
        break;
      }
    }
  }
  if (total <= 0) {
    free(req);
    return total;
  }
  if (header_end < 0) {
    free(req);
    return -1;
  }

  const char* line_end = strstr(req, "\r\n");
  if (line_end == NULL) {
    free(req);
    return -1;
  }
  const char* sp1 = memchr(req, ' ', (size_t)(line_end - req));
  if (sp1 == NULL) {
    free(req);
    return -1;
  }
  const char* sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
  if (sp2 == NULL) {
    free(req);
    return -1;
  }

  size_t method_len = (size_t)(sp1 - req);
  size_t path_len = (size_t)(sp2 - (sp1 + 1));
  const char* version = sp2 + 1;
  int version_len = (int)(line_end - version);

  int body_len = total - header_end;
  if (content_length >= 0 && body_len > content_length) {
    body_len = (int)content_length;
  }
  if (body_len < 0) {
    body_len = 0;
  }

  const char* raw_path = sp1 + 1;
  const char* query_mark = memchr(raw_path, '?', path_len);
  size_t clean_path_len = query_mark == NULL ? path_len : (size_t)(query_mark - raw_path);

  int32_t method_id = fz_intern_slice(req, method_len);
  int32_t path_id = fz_intern_slice(raw_path, clean_path_len);
  int32_t body_id = fz_intern_slice(req + header_end, (size_t)body_len);
  int keep_alive = fz_parse_keep_alive(req, header_end, version, version_len);

  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 1);
  if (state != NULL) {
    state->method_id = method_id;
    state->path_id = path_id;
    state->body_id = body_id;
    state->keep_alive = keep_alive;
    state->header_count = 0;
    state->query_count = 0;
    state->param_count = 0;
    fz_conn_request_counter += 1;
    char rid[64];
    snprintf(rid, sizeof(rid), "req-%d", fz_conn_request_counter);
    state->request_id = fz_intern_slice(rid, strlen(rid));
    const char* cursor = line_end + 2;
    while (cursor < req + header_end && state->header_count < FZ_MAX_CONN_META) {
      const char* next = strstr(cursor, "\r\n");
      if (next == NULL || next <= cursor) break;
      const char* colon = memchr(cursor, ':', (size_t)(next - cursor));
      if (colon != NULL) {
        const char* v = colon + 1;
        while (v < next && (*v == ' ' || *v == '\t')) v++;
        state->header_key_ids[state->header_count] = fz_intern_slice(cursor, (size_t)(colon - cursor));
        state->header_value_ids[state->header_count] = fz_intern_slice(v, (size_t)(next - v));
        state->header_count++;
      }
      cursor = next + 2;
    }
    if (query_mark != NULL) {
      const char* q = query_mark + 1;
      const char* q_end = raw_path + path_len;
      while (q < q_end && state->query_count < FZ_MAX_CONN_META) {
        const char* amp = memchr(q, '&', (size_t)(q_end - q));
        const char* token_end = amp == NULL ? q_end : amp;
        const char* eq = memchr(q, '=', (size_t)(token_end - q));
        if (eq == NULL) {
          state->query_key_ids[state->query_count] = fz_intern_slice(q, (size_t)(token_end - q));
          state->query_value_ids[state->query_count] = fz_intern_slice("", 0);
          state->query_count++;
        } else {
          state->query_key_ids[state->query_count] = fz_intern_slice(q, (size_t)(eq - q));
          state->query_value_ids[state->query_count] = fz_intern_slice(eq + 1, (size_t)(token_end - (eq + 1)));
          state->query_count++;
        }
        if (amp == NULL) break;
        q = amp + 1;
      }
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);

  free(req);
  return total;
}

int32_t fz_native_net_method(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->method_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_path(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->path_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->body_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_body_json(int32_t conn_fd) {
  int32_t body_id = fz_native_net_body(conn_fd);
  return fz_native_json_parse(body_id);
}

int32_t fz_native_net_body_bind(int32_t conn_fd) {
  int32_t out_map = fz_runtime_map_new();
  if (out_map < 0) {
    return -1;
  }
  int32_t body = fz_native_net_body_json(conn_fd);
  if (body <= 0) {
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("invalid JSON body", 17));
    return out_map;
  }
  int32_t body_id = fz_json_value_get_id(body);
  const char* raw = fz_lookup_string(body_id);
  const char* p = fz_json_ws(raw);
  if (p == NULL || *p != '{') {
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("body must be JSON object", 24));
    return out_map;
  }
  p = fz_json_ws(p + 1);
  if (*p == '}') {
    return out_map;
  }
  for (;;) {
    char* key = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object key", 23));
      free(key);
      return out_map;
    }
    p = fz_json_ws(p);
    if (*p != ':') {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object syntax", 26));
      free(key);
      return out_map;
    }
    p = fz_json_ws(p + 1);
    const char* value_start = p;
    if (fz_json_skip_value_token(&p, 0) != 0) {
      (void)fz_runtime_map_set(
          out_map,
          fz_intern_slice("__error", 7),
          fz_intern_slice("invalid JSON object value", 25));
      free(key);
      return out_map;
    }
    const char* value_end = p;
    int32_t key_id = fz_intern_slice(key == NULL ? "" : key, strlen(key == NULL ? "" : key));
    free(key);

    const char* q = value_start;
    char* string_value = NULL;
    int decoded = fz_json_parse_string(&q, &string_value) == 0 && fz_json_ws(q) == value_end;
    if (decoded) {
      int32_t value_id = fz_intern_slice(string_value == NULL ? "" : string_value, strlen(string_value == NULL ? "" : string_value));
      free(string_value);
      (void)fz_runtime_map_set(out_map, key_id, value_id);
    } else {
      free(string_value);
      int32_t value_id = fz_intern_slice(value_start, (size_t)(value_end - value_start));
      (void)fz_runtime_map_set(out_map, key_id, value_id);
    }
    p = fz_json_ws(p);
    if (*p == ',') {
      p = fz_json_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      return out_map;
    }
    (void)fz_runtime_map_set(
        out_map,
        fz_intern_slice("__error", 7),
        fz_intern_slice("invalid JSON object terminator", 30));
    return out_map;
  }
}

int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->header_count; i++) {
    const char* k = fz_lookup_string(state->header_key_ids[i]);
    if (k != NULL && strcasecmp(k, key) == 0) {
      int32_t value = state->header_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_query(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->query_count; i++) {
    const char* k = fz_lookup_string(state->query_key_ids[i]);
    if (k != NULL && strcmp(k, key) == 0) {
      int32_t value = state->query_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_param(int32_t conn_fd, int32_t key_id) {
  const char* key = fz_lookup_string(key_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL || key == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return fz_intern_slice("", 0);
  }
  for (int i = 0; i < state->param_count; i++) {
    const char* k = fz_lookup_string(state->param_key_ids[i]);
    if (k != NULL && strcmp(k, key) == 0) {
      int32_t value = state->param_value_ids[i];
      pthread_mutex_unlock(&fz_conn_lock);
      return value;
    }
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_intern_slice("", 0);
}

int32_t fz_native_net_headers(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return -1;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t list_handle = fz_list_alloc();
  fz_list_state* list = fz_list_get(list_handle);
  if (list != NULL) {
    for (int i = 0; i < state->header_count; i++) {
      const char* k = fz_lookup_string(state->header_key_ids[i]);
      const char* v = fz_lookup_string(state->header_value_ids[i]);
      size_t n = strlen(k == NULL ? "" : k) + strlen(v == NULL ? "" : v) + 3;
      char* kv = (char*)malloc(n);
      if (kv == NULL) continue;
      snprintf(kv, n, "%s:%s", k == NULL ? "" : k, v == NULL ? "" : v);
      (void)fz_list_push_cstr(list, kv);
      free(kv);
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  pthread_mutex_unlock(&fz_conn_lock);
  return list_handle;
}

int32_t fz_native_net_request_id(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->request_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

int32_t fz_native_net_remote_addr(int32_t conn_fd) {
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  int32_t value = state == NULL ? 0 : state->remote_addr_id;
  pthread_mutex_unlock(&fz_conn_lock);
  return value;
}

static int fz_route_match_path_and_capture(fz_conn_state* state, const char* pattern) {
  if (state == NULL || pattern == NULL) {
    return 0;
  }
  const char* path = fz_lookup_string(state->path_id);
  if (path == NULL) path = "";
  state->param_count = 0;
  const char* p = path;
  const char* t = pattern;
  while (*p == '/') p++;
  while (*t == '/') t++;
  for (;;) {
    const char* p_end = strchr(p, '/');
    const char* t_end = strchr(t, '/');
    size_t p_len = p_end == NULL ? strlen(p) : (size_t)(p_end - p);
    size_t t_len = t_end == NULL ? strlen(t) : (size_t)(t_end - t);
    if (p_len == 0 && t_len == 0) return 1;
    if (p_len == 0 || t_len == 0) return 0;
    if (t[0] == ':') {
      if (state->param_count < FZ_MAX_ROUTE_PARAMS) {
        state->param_key_ids[state->param_count] = fz_intern_slice(t + 1, t_len - 1);
        state->param_value_ids[state->param_count] = fz_intern_slice(p, p_len);
        state->param_count++;
      }
    } else if (p_len != t_len || strncmp(p, t, p_len) != 0) {
      return 0;
    }
    if (p_end == NULL && t_end == NULL) return 1;
    if (p_end == NULL || t_end == NULL) return 0;
    p = p_end + 1;
    t = t_end + 1;
  }
}

int32_t fz_native_route_match(int32_t conn_fd, int32_t method_id, int32_t pattern_id) {
  const char* method = fz_lookup_string(method_id);
  const char* pattern = fz_lookup_string(pattern_id);
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_conn_lock);
    return 0;
  }
  if (method != NULL && method[0] != '\0') {
    const char* req_method = fz_lookup_string(state->method_id);
    if (req_method == NULL || strcmp(req_method, method) != 0) {
      pthread_mutex_unlock(&fz_conn_lock);
      return 0;
    }
  }
  int ok = fz_route_match_path_and_capture(state, pattern == NULL ? "" : pattern);
  pthread_mutex_unlock(&fz_conn_lock);
  return ok ? 1 : 0;
}

int32_t fz_native_route_write_404(int32_t conn_fd) {
  return fz_native_net_write(conn_fd, 404, fz_intern_slice("not found", 9));
}

int32_t fz_native_route_write_405(int32_t conn_fd) {
  return fz_native_net_write(conn_fd, 405, fz_intern_slice("method not allowed", 18));
}

int32_t fz_native_net_write_response(
    int32_t conn_fd,
    int32_t status_code,
    int32_t content_type_id,
    int32_t body_id,
    int32_t close_after) {
  const char* content_type = fz_lookup_string(content_type_id);
  const char* body = fz_lookup_string(body_id);
  return fz_send_http_response(conn_fd, status_code, content_type, body, close_after != 0);
}

int32_t fz_native_net_write(int32_t conn_fd, int32_t status_code, int32_t body_id) {
  int close_after = 1;
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    close_after = state->keep_alive ? 0 : 1;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_send_http_response(
      conn_fd,
      status_code,
      "text/plain; charset=utf-8",
      fz_lookup_string(body_id),
      close_after);
}

static char* fz_json_escape_string_bytes(const char* raw) {
  if (raw == NULL) {
    raw = "";
  }
  size_t len = strlen(raw);
  size_t cap = (len * 6) + 1;
  char* out = (char*)malloc(cap);
  if (out == NULL) {
    return NULL;
  }
  size_t used = 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char ch = (unsigned char)raw[i];
    if (ch == '\"' || ch == '\\') {
      out[used++] = '\\';
      out[used++] = (char)ch;
      continue;
    }
    switch (ch) {
      case '\b':
        out[used++] = '\\';
        out[used++] = 'b';
        break;
      case '\f':
        out[used++] = '\\';
        out[used++] = 'f';
        break;
      case '\n':
        out[used++] = '\\';
        out[used++] = 'n';
        break;
      case '\r':
        out[used++] = '\\';
        out[used++] = 'r';
        break;
      case '\t':
        out[used++] = '\\';
        out[used++] = 't';
        break;
      default:
        if (ch < 0x20) {
          (void)snprintf(out + used, cap - used, "\\u%04x", (unsigned int)ch);
          used += 6;
        } else {
          out[used++] = (char)ch;
        }
        break;
    }
  }
  out[used] = '\0';
  return out;
}

static int32_t fz_json_wrap_invalid_payload(const char* raw) {
  char* escaped = fz_json_escape_string_bytes(raw);
  if (escaped == NULL) {
    const char* fallback =
        "{\"error\":\"invalid_json_payload\",\"message\":\"http.write_json could not allocate sanitize buffer\"}";
    return fz_intern_slice(fallback, strlen(fallback));
  }
  const char* prefix =
      "{\"error\":\"invalid_json_payload\",\"message\":\"http.write_json sanitized non-JSON body\",\"raw\":\"";
  const char* suffix = "\"}";
  size_t total = strlen(prefix) + strlen(escaped) + strlen(suffix) + 1;
  char* wrapped = (char*)malloc(total);
  if (wrapped == NULL) {
    free(escaped);
    const char* fallback =
        "{\"error\":\"invalid_json_payload\",\"message\":\"http.write_json sanitize alloc failed\"}";
    return fz_intern_slice(fallback, strlen(fallback));
  }
  snprintf(wrapped, total, "%s%s%s", prefix, escaped, suffix);
  free(escaped);
  return fz_intern_owned(wrapped);
}

int32_t fz_native_net_write_json(int32_t conn_fd, int32_t status_code, int32_t body_id) {
  const char* body = fz_lookup_string(body_id);
  if (body == NULL || body[0] == '\0') {
    body = "null";
  }
  const char* send_body = body;
  int32_t replacement_id = 0;
  const char* start = NULL;
  const char* end = NULL;
  if (fz_json_parse_value_slice(body, &start, &end) != 0) {
    replacement_id = fz_json_wrap_invalid_payload(body);
    send_body = fz_lookup_string(replacement_id);
    fz_set_last_error(
        EINVAL,
        3,
        "http.write_json received invalid JSON body; response was sanitized");
  } else {
    fz_set_last_error(0, 0, "");
  }
  int close_after = 1;
  pthread_mutex_lock(&fz_conn_lock);
  fz_conn_state* state = fz_conn_state_for(conn_fd, 0);
  if (state != NULL) {
    close_after = state->keep_alive ? 0 : 1;
  }
  pthread_mutex_unlock(&fz_conn_lock);
  return fz_send_http_response(
      conn_fd,
      status_code,
      "application/json",
      send_body,
      close_after);
}

int32_t fz_native_close(int32_t fd) {
  if (fd >= 0) {
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }
  fz_conn_state_drop(fd);
  return 0;
}

static const char* fz_json_skip_ws(const char* p) {
  while (p != NULL && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
    p++;
  }
  return p;
}

static int fz_json_parse_string(const char** cursor, char** out) {
  if (cursor == NULL || *cursor == NULL || out == NULL) {
    return -1;
  }
  const char* p = fz_json_skip_ws(*cursor);
  if (p == NULL || *p != '\"') {
    return -1;
  }
  p++;
  size_t cap = 32;
  size_t len = 0;
  char* buf = (char*)malloc(cap);
  if (buf == NULL) {
    return -1;
  }
  while (*p != '\0') {
    char ch = *p++;
    if (ch == '\"') {
      buf[len] = '\0';
      *out = buf;
      *cursor = p;
      return 0;
    }
    if (ch == '\\') {
      char esc = *p++;
      if (esc == '\0') {
        free(buf);
        return -1;
      }
      switch (esc) {
        case '\"': ch = '\"'; break;
        case '\\': ch = '\\'; break;
        case '/': ch = '/'; break;
        case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        case 'n': ch = '\n'; break;
        case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break;
        case 'u':
          for (int i = 0; i < 4; i++) {
            if (!isxdigit((unsigned char)p[i])) {
              free(buf);
              return -1;
            }
          }
          p += 4;
          ch = '?';
          break;
        default:
          free(buf);
          return -1;
      }
    }
    if (len + 2 > cap) {
      cap *= 2;
      char* next = (char*)realloc(buf, cap);
      if (next == NULL) {
        free(buf);
        return -1;
      }
      buf = next;
    }
    buf[len++] = ch;
  }
  free(buf);
  return -1;
}

static int fz_parse_json_string_array(const char* raw, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (raw == NULL || raw[0] == '\0') {
    return 0;
  }
  const char* p = fz_json_skip_ws(raw);
  if (*p != '[') {
    return -1;
  }
  p = fz_json_skip_ws(p + 1);
  int cap = 4;
  int count = 0;
  char** items = (char**)calloc((size_t)cap, sizeof(char*));
  if (items == NULL) {
    return -1;
  }
  if (*p == ']') {
    *out_items = items;
    *out_count = 0;
    return 0;
  }
  for (;;) {
    char* item = NULL;
    if (fz_json_parse_string(&p, &item) != 0) {
      for (int i = 0; i < count; i++) free(items[i]);
      free(items);
      return -1;
    }
    if (count >= cap) {
      cap *= 2;
      char** next = (char**)realloc(items, (size_t)cap * sizeof(char*));
      if (next == NULL) {
        free(item);
        for (int i = 0; i < count; i++) free(items[i]);
        free(items);
        return -1;
      }
      items = next;
    }
    items[count++] = item;
    p = fz_json_skip_ws(p);
    if (*p == ',') {
      p = fz_json_skip_ws(p + 1);
      continue;
    }
    if (*p == ']') {
      break;
    }
    for (int i = 0; i < count; i++) free(items[i]);
    free(items);
    return -1;
  }
  *out_items = items;
  *out_count = count;
  return 0;
}

static int fz_parse_json_env_object(const char* raw, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (raw == NULL || raw[0] == '\0') {
    return 0;
  }
  const char* p = fz_json_skip_ws(raw);
  if (*p != '{') {
    return -1;
  }
  p = fz_json_skip_ws(p + 1);
  int cap = 4;
  int count = 0;
  char** entries = (char**)calloc((size_t)cap, sizeof(char*));
  if (entries == NULL) {
    return -1;
  }
  if (*p == '}') {
    *out_items = entries;
    *out_count = 0;
    return 0;
  }
  for (;;) {
    char* key = NULL;
    char* value = NULL;
    if (fz_json_parse_string(&p, &key) != 0) {
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    p = fz_json_skip_ws(p);
    if (*p != ':') {
      free(key);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    p = fz_json_skip_ws(p + 1);
    if (fz_json_parse_string(&p, &value) != 0) {
      free(key);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    size_t n = strlen(key) + strlen(value) + 2;
    char* joined = (char*)malloc(n);
    if (joined == NULL) {
      free(key);
      free(value);
      for (int i = 0; i < count; i++) free(entries[i]);
      free(entries);
      return -1;
    }
    snprintf(joined, n, "%s=%s", key, value);
    free(key);
    free(value);
    if (count >= cap) {
      cap *= 2;
      char** next = (char**)realloc(entries, (size_t)cap * sizeof(char*));
      if (next == NULL) {
        free(joined);
        for (int i = 0; i < count; i++) free(entries[i]);
        free(entries);
        return -1;
      }
      entries = next;
    }
    entries[count++] = joined;
    p = fz_json_skip_ws(p);
    if (*p == ',') {
      p = fz_json_skip_ws(p + 1);
      continue;
    }
    if (*p == '}') {
      break;
    }
    for (int i = 0; i < count; i++) free(entries[i]);
    free(entries);
    return -1;
  }
  *out_items = entries;
  *out_count = count;
  return 0;
}

static void fz_free_string_list(char** items, int count) {
  if (items == NULL) {
    return;
  }
  for (int i = 0; i < count; i++) {
    free(items[i]);
  }
  free(items);
}

static int fz_env_key_match(const char* entry, const char* key, size_t key_len) {
  if (entry == NULL || key == NULL) {
    return 0;
  }
  return strncmp(entry, key, key_len) == 0 && entry[key_len] == '=';
}

static char** fz_clone_env_with_overrides(char** overrides, int override_count) {
  int base_count = 0;
  while (environ != NULL && environ[base_count] != NULL) {
    base_count++;
  }
  int cap = base_count + override_count + 1;
  char** envp = (char**)calloc((size_t)cap, sizeof(char*));
  if (envp == NULL) {
    return NULL;
  }
  int count = 0;
  for (int i = 0; i < base_count; i++) {
    envp[count] = strdup(environ[i]);
    if (envp[count] == NULL) {
      for (int j = 0; j < count; j++) free(envp[j]);
      free(envp);
      return NULL;
    }
    count++;
  }
  for (int i = 0; i < override_count; i++) {
    const char* item = overrides[i];
    const char* eq = item == NULL ? NULL : strchr(item, '=');
    if (eq == NULL || eq == item) {
      continue;
    }
    size_t key_len = (size_t)(eq - item);
    int replaced = 0;
    for (int j = 0; j < count; j++) {
      if (fz_env_key_match(envp[j], item, key_len)) {
        char* dup = strdup(item);
        if (dup == NULL) {
          continue;
        }
        free(envp[j]);
        envp[j] = dup;
        replaced = 1;
        break;
      }
    }
    if (!replaced && count < cap - 1) {
      envp[count] = strdup(item);
      if (envp[count] != NULL) {
        count++;
      }
    }
  }
  envp[count] = NULL;
  return envp;
}

static void fz_free_env(char** envp) {
  if (envp == NULL) {
    return;
  }
  for (int i = 0; envp[i] != NULL; i++) {
    free(envp[i]);
  }
  free(envp);
}

static int32_t fz_native_proc_spawn_argv(
    const char* executable,
    char* const* argv,
    char* const* envp,
    const char* stdin_payload) {
  if (executable == NULL || executable[0] == '\0' || argv == NULL || argv[0] == NULL) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: invalid argv");
    return -1;
  }

  int out_pipe[2];
  int err_pipe[2];
  int in_pipe[2] = {-1, -1};
  if (pipe(out_pipe) != 0) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stdout pipe failed");
    return -1;
  }
  if (pipe(err_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stderr pipe failed");
    return -1;
  }
  if (stdin_payload != NULL && pipe(in_pipe) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: stdin pipe failed");
    return -1;
  }
  (void)fz_mark_cloexec(out_pipe[0]);
  (void)fz_mark_cloexec(err_pipe[0]);

  posix_spawn_file_actions_t file_actions;
  if (posix_spawn_file_actions_init(&file_actions) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: file actions init failed");
    return -1;
  }
  int file_actions_ok = 1;
  if (posix_spawn_file_actions_adddup2(&file_actions, out_pipe[1], STDOUT_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_adddup2(&file_actions, err_pipe[1], STDERR_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[0] >= 0
      && posix_spawn_file_actions_adddup2(&file_actions, in_pipe[0], STDIN_FILENO) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, out_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, out_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, err_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok
      && posix_spawn_file_actions_addclose(&file_actions, err_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[0] >= 0
      && posix_spawn_file_actions_addclose(&file_actions, in_pipe[0]) != 0) {
    file_actions_ok = 0;
  }
  if (file_actions_ok && in_pipe[1] >= 0
      && posix_spawn_file_actions_addclose(&file_actions, in_pipe[1]) != 0) {
    file_actions_ok = 0;
  }
  if (!file_actions_ok) {
    (void)posix_spawn_file_actions_destroy(&file_actions);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: file actions setup failed");
    return -1;
  }

  pid_t pid = 0;
  int spawn_rc = posix_spawnp(
      &pid,
      executable,
      &file_actions,
      NULL,
      argv,
      envp == NULL ? environ : envp);
  (void)posix_spawn_file_actions_destroy(&file_actions);
  if (spawn_rc != 0 || pid <= 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    if (in_pipe[0] >= 0) {
      close(in_pipe[0]);
      close(in_pipe[1]);
    }
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: posix_spawnp failed");
    return -1;
  }

  if (in_pipe[0] >= 0) {
    close(in_pipe[0]);
    size_t remaining = strlen(stdin_payload);
    const char* cursor = stdin_payload;
    while (remaining > 0) {
      ssize_t wrote = write(in_pipe[1], cursor, remaining);
      if (wrote < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      if (wrote == 0) {
        break;
      }
      cursor += wrote;
      remaining -= (size_t)wrote;
    }
    close(in_pipe[1]);
  }

  close(out_pipe[1]);
  close(err_pipe[1]);
  (void)fz_set_nonblocking(out_pipe[0]);
  (void)fz_set_nonblocking(err_pipe[0]);

  pthread_mutex_lock(&fz_proc_lock);
  int32_t handle = fz_proc_state_alloc(pid, out_pipe[0], err_pipe[0]);
  pthread_mutex_unlock(&fz_proc_lock);
  if (handle < 0) {
    kill(pid, SIGKILL);
    close(out_pipe[0]);
    close(err_pipe[0]);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: state allocation failed");
    return -1;
  }
  fz_proc_set_last_error("");
  return handle;
}

int32_t fz_native_proc_spawn(int32_t command_id) {
  const char* command = fz_lookup_string(command_id);
  if (command == NULL || command[0] == '\0') {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawn: empty command");
    return -1;
  }
  char* const argv[] = {"sh", "-lc", (char*)command, NULL};
  return fz_native_proc_spawn_argv("sh", argv, environ, NULL);
}

static int fz_clone_list_items(int32_t list_handle, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (list_handle <= 0) {
    return 0;
  }
  pthread_mutex_lock(&fz_collections_lock);
  fz_list_state* list = fz_list_get(list_handle);
  if (list == NULL || list->count <= 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  int count = list->count;
  char** items = (char**)calloc((size_t)count, sizeof(char*));
  if (items == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < count; i++) {
    const char* src = list->items[i] == NULL ? "" : list->items[i];
    items[i] = strdup(src);
    if (items[i] == NULL) {
      for (int j = 0; j < i; j++) {
        free(items[j]);
      }
      free(items);
      pthread_mutex_unlock(&fz_collections_lock);
      return -1;
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  *out_items = items;
  *out_count = count;
  return 0;
}

static int fz_clone_map_entries_as_env(int32_t map_handle, char*** out_items, int* out_count) {
  if (out_items == NULL || out_count == NULL) {
    return -1;
  }
  *out_items = NULL;
  *out_count = 0;
  if (map_handle <= 0) {
    return 0;
  }
  pthread_mutex_lock(&fz_collections_lock);
  fz_map_state* map = fz_map_get(map_handle);
  if (map == NULL || map->count <= 0) {
    pthread_mutex_unlock(&fz_collections_lock);
    return 0;
  }
  int count = map->count;
  char** entries = (char**)calloc((size_t)count, sizeof(char*));
  if (entries == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  for (int i = 0; i < count; i++) {
    const char* key = map->keys[i] == NULL ? "" : map->keys[i];
    const char* value = map->values[i] == NULL ? "" : map->values[i];
    size_t n = strlen(key) + strlen(value) + 2;
    entries[i] = (char*)malloc(n);
    if (entries[i] == NULL) {
      for (int j = 0; j < i; j++) {
        free(entries[j]);
      }
      free(entries);
      pthread_mutex_unlock(&fz_collections_lock);
      return -1;
    }
    snprintf(entries[i], n, "%s=%s", key, value);
  }
  pthread_mutex_unlock(&fz_collections_lock);
  *out_items = entries;
  *out_count = count;
  return 0;
}

int32_t fz_native_proc_spawnl(
    int32_t command_id,
    int32_t args_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  const char* command = fz_lookup_string(command_id);
  const char* stdin_payload = fz_lookup_string(stdin_id);
  if (command == NULL || command[0] == '\0') {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: empty command");
    return -1;
  }

  char** arg_items = NULL;
  int arg_count = 0;
  if (fz_clone_list_items(args_list_id, &arg_items, &arg_count) != 0) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: args_list clone failed");
    return -1;
  }

  char** env_items = NULL;
  int env_count = 0;
  if (fz_clone_map_entries_as_env(env_map_id, &env_items, &env_count) != 0) {
    fz_free_string_list(arg_items, arg_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: env_map clone failed");
    return -1;
  }

  int argv_count = arg_count + 2;
  char** argv = (char**)calloc((size_t)argv_count, sizeof(char*));
  if (argv == NULL) {
    fz_free_string_list(arg_items, arg_count);
    fz_free_string_list(env_items, env_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnl: argv alloc failed");
    return -1;
  }
  argv[0] = (char*)command;
  for (int i = 0; i < arg_count; i++) {
    argv[i + 1] = arg_items[i];
  }
  argv[argv_count - 1] = NULL;

  char** envp = fz_clone_env_with_overrides(env_items, env_count);
  int32_t handle = fz_native_proc_spawn_argv(
      command,
      argv,
      envp == NULL ? environ : envp,
      (stdin_payload == NULL || stdin_payload[0] == '\0') ? NULL : stdin_payload);

  fz_free_env(envp);
  free(argv);
  fz_free_string_list(arg_items, arg_count);
  fz_free_string_list(env_items, env_count);
  return handle;
}

int32_t fz_native_proc_spawnv(
    int32_t command_id,
    int32_t args_json_id,
    int32_t env_json_id,
    int32_t stdin_id) {
  const char* command = fz_lookup_string(command_id);
  const char* args_json = fz_lookup_string(args_json_id);
  const char* env_json = fz_lookup_string(env_json_id);
  const char* stdin_payload = fz_lookup_string(stdin_id);
  if (command == NULL || command[0] == '\0') {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: empty command");
    return -1;
  }

  char** arg_items = NULL;
  int arg_count = 0;
  if (fz_parse_json_string_array(args_json, &arg_items, &arg_count) != 0) {
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: args_json must be a JSON string array");
    return -1;
  }
  char** env_items = NULL;
  int env_count = 0;
  if (fz_parse_json_env_object(env_json, &env_items, &env_count) != 0) {
    fz_free_string_list(arg_items, arg_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: env_json must be a JSON object<string,string>");
    return -1;
  }

  int argv_count = arg_count + 2;
  char** argv = (char**)calloc((size_t)argv_count, sizeof(char*));
  if (argv == NULL) {
    fz_free_string_list(arg_items, arg_count);
    fz_free_string_list(env_items, env_count);
    fz_last_exit_class = 3;
    fz_proc_set_last_error("proc_spawnv: argv alloc failed");
    return -1;
  }
  argv[0] = (char*)command;
  for (int i = 0; i < arg_count; i++) {
    argv[i + 1] = arg_items[i];
  }
  argv[argv_count - 1] = NULL;

  char** envp = fz_clone_env_with_overrides(env_items, env_count);
  int32_t handle = fz_native_proc_spawn_argv(
      command,
      argv,
      envp == NULL ? environ : envp,
      (stdin_payload == NULL || stdin_payload[0] == '\0') ? NULL : stdin_payload);

  fz_free_env(envp);
  free(argv);
  fz_free_string_list(arg_items, arg_count);
  fz_free_string_list(env_items, env_count);
  return handle;
}

int32_t fz_native_proc_wait(int32_t handle, int32_t timeout_ms) {
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    fz_proc_set_last_error("proc_wait: invalid handle");
    return -1;
  }
  if (state->done) {
    pthread_mutex_unlock(&fz_proc_lock);
    return 0;
  }

  int64_t start = fz_now_ms();
  int status = 0;
  int timed_out = 0;
  for (;;) {
    if (fz_drain_fd(state->stdout_fd, &state->stdout_buf) < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: stdout drain failed");
      return -1;
    }
    if (fz_drain_fd(state->stderr_fd, &state->stderr_buf) < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: stderr drain failed");
      return -1;
    }

    pid_t waited = waitpid(state->pid, &status, WNOHANG);
    if (waited == state->pid) {
      break;
    }
    if (waited < 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      fz_proc_set_last_error("proc_wait: waitpid failed");
      return -1;
    }
    if (timeout_ms == 0) {
      pthread_mutex_unlock(&fz_proc_lock);
      return 1;
    }
    if (timeout_ms > 0 && (fz_now_ms() - start) >= timeout_ms) {
      kill(state->pid, SIGKILL);
      (void)waitpid(state->pid, &status, 0);
      timed_out = 1;
      break;
    }
    usleep(10 * 1000);
  }

  int exit_code = -1;
  if (timed_out) {
    exit_code = -124;
  } else if (WIFEXITED(status)) {
    exit_code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    exit_code = 128 + WTERMSIG(status);
  }
  fz_last_exit_class = fz_exit_class_from_status(timed_out, status, 0);
  fz_proc_finalize(state, exit_code);
  pthread_mutex_unlock(&fz_proc_lock);
  fz_proc_set_last_error("");
  return 0;
}

int32_t fz_native_proc_run(int32_t command_id) {
  int32_t handle = fz_native_proc_spawn(command_id);
  if (handle < 0) {
    return -1;
  }
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  return handle;
}

int32_t fz_native_proc_runv(
    int32_t command_id,
    int32_t args_json_id,
    int32_t env_json_id,
    int32_t stdin_id) {
  int32_t handle = fz_native_proc_spawnv(command_id, args_json_id, env_json_id, stdin_id);
  if (handle < 0) {
    return -1;
  }
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  return handle;
}

int32_t fz_native_proc_runl(
    int32_t command_id,
    int32_t args_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  int32_t handle = fz_native_proc_spawnl(command_id, args_list_id, env_map_id, stdin_id);
  if (handle < 0) {
    return -1;
  }
  int32_t waited = fz_native_proc_wait(handle, fz_proc_default_timeout_ms);
  if (waited < 0) {
    return -1;
  }
  return handle;
}

int32_t fz_native_proc_poll(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  return wait_result == 0 ? 1 : 0;
}

static int32_t fz_native_proc_read_stream_chunk(int32_t handle, int32_t max_bytes, int use_stdout) {
  if (max_bytes <= 0) {
    max_bytes = 4096;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    return fz_intern_slice("", 0);
  }
  if (!state->done) {
    (void)fz_drain_fd(state->stdout_fd, &state->stdout_buf);
    (void)fz_drain_fd(state->stderr_fd, &state->stderr_buf);
  }
  fz_bytes_buf* buf = use_stdout ? &state->stdout_buf : &state->stderr_buf;
  size_t* cursor = use_stdout ? &state->stdout_read_pos : &state->stderr_read_pos;
  size_t remaining = buf->len > *cursor ? (buf->len - *cursor) : 0;
  size_t take = remaining < (size_t)max_bytes ? remaining : (size_t)max_bytes;
  int32_t out = fz_intern_slice(buf->data == NULL ? "" : (buf->data + *cursor), take);
  *cursor += take;
  pthread_mutex_unlock(&fz_proc_lock);
  return out;
}

int32_t fz_native_proc_read_stdout(int32_t handle, int32_t max_bytes) {
  return fz_native_proc_read_stream_chunk(handle, max_bytes, 1);
}

int32_t fz_native_proc_read_stderr(int32_t handle, int32_t max_bytes) {
  return fz_native_proc_read_stream_chunk(handle, max_bytes, 0);
}

int32_t fz_native_proc_event(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  if (wait_result > 0) {
    return 0;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  if (state == NULL) {
    pthread_mutex_unlock(&fz_proc_lock);
    return -1;
  }
  int emit = state->exit_notified ? 0 : 1;
  state->exit_notified = 1;
  pthread_mutex_unlock(&fz_proc_lock);
  return emit;
}

int32_t fz_native_proc_stdout(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return fz_proc_last_error_id;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? 0 : state->stdout_id;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_stderr(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return fz_proc_last_error_id;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? 0 : state->stderr_id;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_exit_code(int32_t handle) {
  int wait_result = fz_native_proc_wait(handle, 0);
  if (wait_result < 0) {
    return -1;
  }
  if (wait_result > 0) {
    return -2;
  }
  pthread_mutex_lock(&fz_proc_lock);
  fz_proc_state* state = fz_proc_state_get(handle);
  int32_t value = (state == NULL) ? -1 : state->exit_code;
  pthread_mutex_unlock(&fz_proc_lock);
  return value;
}

int32_t fz_native_proc_exec_timeout(int32_t timeout_ms) {
  if (timeout_ms > 0) {
    fz_proc_default_timeout_ms = timeout_ms;
  }
  return 0;
}

int32_t fz_native_proc_exit_class(void) {
  return fz_last_exit_class;
}

int32_t fz_native_spawn(int32_t task_ref) {
  return fz_native_spawn_impl(task_ref, 0, 0);
}

int32_t fz_native_spawn_ctx(int32_t task_ref, int32_t context_id) {
  return fz_native_spawn_impl(task_ref, context_id, 0);
}

int32_t fz_native_join(int32_t handle) {
  pthread_t thread;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  if (state->detached) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -2;
  }
  if (state->joined && state->finished) {
    int32_t result = state->result;
    memset(state, 0, sizeof(*state));
    pthread_mutex_unlock(&fz_spawn_lock);
    return result;
  }
  state->joined = 1;
  thread = state->thread;
  pthread_mutex_unlock(&fz_spawn_lock);

  (void)pthread_join(thread, NULL);

  pthread_mutex_lock(&fz_spawn_lock);
  state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  int32_t result = state->result;
  memset(state, 0, sizeof(*state));
  pthread_mutex_unlock(&fz_spawn_lock);
  return result;
}

int32_t fz_native_detach(int32_t handle) {
  pthread_t thread;
  int should_detach = 0;
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  if (state->detached) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return 0;
  }
  state->detached = 1;
  if (state->finished) {
    memset(state, 0, sizeof(*state));
    pthread_mutex_unlock(&fz_spawn_lock);
    return 0;
  }
  thread = state->thread;
  should_detach = 1;
  pthread_mutex_unlock(&fz_spawn_lock);
  if (should_detach) {
    (void)pthread_detach(thread);
  }
  return 0;
}

int32_t fz_native_cancel_task(int32_t handle) {
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  state->cancelled = 1;
  pthread_mutex_unlock(&fz_spawn_lock);
  return 0;
}

int32_t fz_native_task_result(int32_t handle) {
  pthread_mutex_lock(&fz_spawn_lock);
  fz_spawn_state* state = fz_spawn_state_by_handle_locked(handle);
  if (state == NULL || !state->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  int32_t result = state->finished ? state->result : -2;
  pthread_mutex_unlock(&fz_spawn_lock);
  return result;
}

int32_t fz_native_task_context(void) {
  return fz_tls_task_context;
}

int32_t fz_native_task_group_begin(void) {
  pthread_mutex_lock(&fz_spawn_lock);
  fz_task_group_state* group = fz_task_group_alloc_locked();
  if (group == NULL) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  memset(group, 0, sizeof(*group));
  group->in_use = 1;
  group->id = fz_next_task_group_id++;
  int32_t group_id = group->id;
  pthread_mutex_unlock(&fz_spawn_lock);
  return group_id;
}

int32_t fz_native_task_group_spawn(int32_t group_id, int32_t task_ref) {
  return fz_native_spawn_impl(task_ref, 0, group_id);
}

int32_t fz_native_task_group_join(int32_t group_id) {
  for (;;) {
    int32_t next_handle = 0;
    pthread_mutex_lock(&fz_spawn_lock);
    fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
    if (group == NULL || !group->in_use) {
      pthread_mutex_unlock(&fz_spawn_lock);
      return -1;
    }
    for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
      fz_spawn_state* state = &fz_spawn_states[i];
      if (state->in_use && state->group_id == group_id && !state->detached) {
        next_handle = state->handle;
        break;
      }
    }
    if (next_handle == 0) {
      group->in_use = 0;
      pthread_mutex_unlock(&fz_spawn_lock);
      return 0;
    }
    pthread_mutex_unlock(&fz_spawn_lock);
    int32_t joined = fz_native_join(next_handle);
    if (joined < 0) {
      return joined;
    }
  }
}

int32_t fz_native_task_group_cancel(int32_t group_id) {
  pthread_mutex_lock(&fz_spawn_lock);
  fz_task_group_state* group = fz_task_group_by_id_locked(group_id);
  if (group == NULL || !group->in_use) {
    pthread_mutex_unlock(&fz_spawn_lock);
    return -1;
  }
  for (int i = 0; i < FZ_MAX_SPAWN_THREADS; i++) {
    fz_spawn_state* state = &fz_spawn_states[i];
    if (state->in_use && state->group_id == group_id) {
      state->cancelled = 1;
    }
  }
  group->in_use = 0;
  group->active_count = 0;
  pthread_mutex_unlock(&fz_spawn_lock);
  return 0;
}

int32_t fz_native_timeout(int32_t timeout_ms) {
  if (timeout_ms < 0) {
    return -1;
  }
  fz_async_deadline_ms = fz_now_ms() + (int64_t)timeout_ms;
  return 0;
}

int32_t fz_native_deadline(int32_t deadline_ms) {
  fz_async_deadline_ms = (int64_t)deadline_ms;
  return 0;
}

int32_t fz_native_cancel(void) {
  fz_async_cancelled = 1;
  return 0;
}

int32_t fz_native_recv(void) {
  if (fz_async_cancelled) {
    return -1;
  }
  if (fz_async_deadline_ms > 0 && fz_now_ms() > fz_async_deadline_ms) {
    return -1;
  }
  return 0;
}

int32_t fz_native_yield(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_checkpoint(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_pulse(void) {
  sched_yield();
  return 0;
}

int32_t fz_native_net_poll_next(void) {
  return -1;
}

int32_t fz_host_init(void) {
  pthread_mutex_lock(&fz_host_lock);
  fz_host_initialized = 1;
  for (int i = 0; i < 64; i++) {
    fz_host_callbacks[i] = NULL;
  }
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_shutdown(void) {
  pthread_mutex_lock(&fz_host_lock);
  fz_host_initialized = 0;
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_cleanup(void) {
  pthread_mutex_lock(&fz_host_lock);
  for (int i = 0; i < 64; i++) {
    fz_host_callbacks[i] = NULL;
  }
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb) {
  if (slot < 0 || slot >= 64 || cb == NULL) {
    return -1;
  }
  pthread_mutex_lock(&fz_host_lock);
  if (!fz_host_initialized) {
    pthread_mutex_unlock(&fz_host_lock);
    return -2;
  }
  fz_host_callbacks[slot] = cb;
  pthread_mutex_unlock(&fz_host_lock);
  return 0;
}

int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg) {
  if (slot < 0 || slot >= 64) {
    return -1;
  }
  pthread_mutex_lock(&fz_host_lock);
  fz_callback_i32_v0 cb = fz_host_callbacks[slot];
  pthread_mutex_unlock(&fz_host_lock);
  if (cb == NULL) {
    return -2;
  }
  return cb(arg);
}
"#,
    );
    c.push_str(&async_export_shim);
    c
}

fn linker_candidates() -> Vec<String> {
    if let Ok(explicit) = std::env::var("FZ_CC") {
        if !explicit.trim().is_empty() {
            return vec![explicit];
        }
    }
    let mut candidates = Vec::new();
    let target = std::env::var("TARGET")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if target.contains("apple-darwin") {
        candidates.push("clang".to_string());
        candidates.push("cc".to_string());
        candidates.push("gcc".to_string());
    } else if target.contains("linux") {
        candidates.push("cc".to_string());
        candidates.push("clang".to_string());
        candidates.push("gcc".to_string());
    } else {
        candidates.push("clang".to_string());
        candidates.push("cc".to_string());
        candidates.push("gcc".to_string());
    }
    candidates
}

fn apply_target_link_flags(cmd: &mut Command) {
    if let Ok(target) = std::env::var("TARGET") {
        let target = target.trim();
        if !target.is_empty() {
            cmd.arg("-target").arg(target);
        }
    }
}

fn apply_manifest_link_args(cmd: &mut Command, manifest: Option<&manifest::Manifest>) {
    let Some(manifest) = manifest else {
        return;
    };
    for search in &manifest.link.search {
        let trimmed = search.trim();
        if !trimmed.is_empty() {
            cmd.arg(format!("-L{trimmed}"));
        }
    }
    for lib in &manifest.link.libs {
        let trimmed = lib.trim();
        if !trimmed.is_empty() {
            cmd.arg(format!("-l{trimmed}"));
        }
    }
    if cfg!(target_vendor = "apple") {
        for framework in &manifest.link.frameworks {
            let trimmed = framework.trim();
            if !trimmed.is_empty() {
                cmd.arg("-framework").arg(trimmed);
            }
        }
    }
}

fn apply_extra_linker_args(cmd: &mut Command) {
    if let Ok(extra) = std::env::var("FZ_LINKER_ARGS") {
        for arg in extra.split_whitespace() {
            if !arg.trim().is_empty() {
                cmd.arg(arg);
            }
        }
    }
}

fn profile_config(
    manifest: &manifest::Manifest,
    profile: BuildProfile,
) -> Option<&manifest::Profile> {
    match profile {
        BuildProfile::Dev => manifest.profiles.dev.as_ref(),
        BuildProfile::Release => manifest.profiles.release.as_ref(),
        BuildProfile::Verify => manifest.profiles.verify.as_ref(),
    }
}

fn unsafe_contracts_enforced(manifest: Option<&manifest::Manifest>, profile: BuildProfile) -> bool {
    if let Some(manifest) = manifest {
        let unsafe_policy = &manifest.unsafe_policy;
        return match profile {
            BuildProfile::Dev => unsafe_policy.enforce_dev.unwrap_or(false),
            BuildProfile::Verify => unsafe_policy.enforce_verify.unwrap_or(true),
            BuildProfile::Release => unsafe_policy.enforce_release.unwrap_or(true),
        };
    }
    !matches!(profile, BuildProfile::Dev)
}

fn unsafe_scope_policy(manifest: Option<&manifest::Manifest>) -> (Vec<String>, Vec<String>) {
    let Some(manifest) = manifest else {
        return (Vec::new(), Vec::new());
    };
    (
        manifest.unsafe_policy.deny_unsafe_in.clone(),
        manifest.unsafe_policy.allow_unsafe_in.clone(),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        compile_file, compile_file_with_backend, compile_library_with_backend,
        derive_anchors_from_message, emit_ir, lower_backend_ir, lower_llvm_ir,
        native_runtime_import_contract_errors, native_runtime_import_for_callee, parse_program,
        refresh_lockfile, render_native_runtime_shim, verify_file, BackendKind, BuildProfile,
        NativeAsyncExport,
    };

    fn run_native_exit(exe: &Path) -> i32 {
        Command::new(exe)
            .status()
            .expect("native artifact should execute")
            .code()
            .expect("native artifact should exit with code")
    }

    #[test]
    fn compile_file_runs_pipeline() {
        let file_name = format!(
            "fozzylang-pipeline-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should compile");
        assert_eq!(artifact.module, path.file_stem().unwrap().to_string_lossy());
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn derive_anchors_from_message_extracts_primary_and_related_tokens() {
        let lines = vec![
            "fn main() -> i32 {".to_string(),
            "    let payload = build()".to_string(),
            "    return payload.missing".to_string(),
            "}".to_string(),
        ];
        let anchors =
            derive_anchors_from_message("field access on `payload` has no field `missing`", &lines)
                .expect("anchors should be extracted");
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].0, "payload");
        assert_eq!(anchors[1].0, "missing");
    }

    #[test]
    fn compile_project_directory_uses_manifest_target() {
        let project_name = format!(
            "fozzylang-project-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
        assert_eq!(artifact.module, "main");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_library_uses_lib_target_when_present() {
        let project_name = format!(
            "fozzylang-project-lib-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_library_with_backend(&root, BuildProfile::Dev, None)
            .expect("library project should compile");
        assert_eq!(artifact.module, "lib");
        assert!(artifact
            .static_lib
            .as_ref()
            .is_some_and(|path| path.exists()));
        assert!(artifact
            .shared_lib
            .as_ref()
            .is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn llvm_lowering_declares_extern_c_import_without_defining_stub() {
        let source = "ext c fn c_add(left: i32, right: i32) -> i32;\nfn main() -> i32 {\n    return c_add(1, 2)\n}\n";
        let module = parser::parse(source, "ffi_import").expect("source should parse");
        let typed = hir::lower(&module);
        let fir = fir::build_owned(typed);
        let ir = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
        assert!(ir.contains("declare i32 @c_add(i32, i32)"));
        assert!(!ir.contains("define i32 @c_add("));
    }

    #[test]
    fn enum_match_lowers_to_switch_for_eligible_arms() {
        let source = "enum ErrorCode { InvalidInput, NotFound, Conflict, Timeout, Io, Internal }\nfn classify(code: ErrorCode) -> i32 {\n    match code {\n        ErrorCode::Io => return 11,\n        ErrorCode::InvalidInput => return 17,\n        ErrorCode::Timeout => return 23,\n        ErrorCode::Conflict => return 31,\n        _ => return 43,\n    }\n}\nfn main() -> i32 {\n    return classify(ErrorCode::Io)\n}\n";
        let module = parser::parse(source, "match_switch").expect("source should parse");
        let typed = hir::lower(&module);
        let fir = fir::build_owned(typed);
        let llvm = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
        let clif = lower_backend_ir(&fir, BackendKind::Cranelift)
            .expect("cranelift lowering should succeed");
        assert!(llvm.contains("switch i32"));
        assert!(clif.contains("switch"));
    }

    #[test]
    fn compile_project_uses_capabilities_from_declared_modules() {
        let project_name = format!(
            "fozzylang-mod-cap-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod infra;\nfn main() -> i32 {\n    let listener = http.bind()\n    return listener\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/infra.fzy"), "use core.http;\n")
            .expect("module source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_project_resolves_use_alias_and_pub_use_reexport_calls() {
        let project_name = format!(
            "fozzylang-import-alias-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nfn main() -> i32 {\n    return services.invoke()\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "mod auth;\nmod store;\nuse auth::init as auth_init;\npub use store::init;\npub fn invoke() -> i32 {\n    return auth_init() + init()\n}\n",
        )
        .expect("services module should be written");
        std::fs::write(
            root.join("src/services/auth.fzy"),
            "pub fn init() -> i32 {\n    return 2\n}\n",
        )
        .expect("auth module should be written");
        std::fs::write(
            root.join("src/services/store.fzy"),
            "pub fn init() -> i32 {\n    return 3\n}\n",
        )
        .expect("store module should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_with_verify_errors_skips_native_output() {
        let file_name = format!(
            "fozzylang-error-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let c = http.connect()\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_project_fails_for_missing_path_dependency() {
        let project_name = format!(
            "fozzylang-deps-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = compile_file(&root, BuildProfile::Dev).expect_err("build should fail");
        assert!(error.to_string().contains("path dependency"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_project_fails_when_lockfile_drifts() {
        let project_name = format!(
            "fozzylang-lock-drift-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        std::fs::write(
            dep_dir.join("fozzy.toml"),
            "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"util\"\npath=\"src/main.fzy\"\n",
        )
        .expect("dep manifest should be written");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("dep source should be written");

        let first = compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
        assert_eq!(first.status, "ok");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 1\n}\n",
        )
        .expect("dep source should mutate");
        let error = compile_file(&root, BuildProfile::Dev).expect_err("drift should fail build");
        assert!(error.to_string().contains("lockfile drift detected"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn refresh_lockfile_unblocks_drifted_project_build() {
        let project_name = format!(
            "fozzylang-lock-refresh-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        std::fs::write(
            dep_dir.join("fozzy.toml"),
            "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"util\"\npath=\"src/main.fzy\"\n",
        )
        .expect("dep manifest should be written");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("dep source should be written");

        compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 2\n}\n",
        )
        .expect("dep source should mutate");
        refresh_lockfile(&root).expect("refresh lockfile should succeed");
        let artifact = compile_file(&root, BuildProfile::Dev).expect("build should recover");
        assert_eq!(artifact.status, "ok");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn profile_checks_can_be_disabled() {
        let project_name = format!(
            "fozzylang-profile-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[profiles.dev]\nchecks=false\noptimize=false\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.http;\nfn main() -> i32 {\n    let listener = http.bind()\n    return listener\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("build should run");
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_profile_rejects_unsafe_capabilities_even_if_declared() {
        let file_name = format!(
            "fozzylang-safe-profile-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use core.http;\nfn main() -> i32 {\n    let c = http.connect()\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Verify).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_rejects_false_contracts() {
        let file_name = format!(
            "fozzylang-contract-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    requires false\n    ensures false\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn release_profile_disables_runtime_contract_forcing() {
        let path = std::env::temp_dir().join(format!(
            "fozzylang-release-contract-force-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        ));
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    requires false\n    return 0\n}\n",
        )
        .expect("source should be written");
        let parsed = parse_program(&path).expect("source should parse");
        let (_typed, fir) = super::lower_fir_cached(&parsed);
        assert!(super::compute_forced_main_return(&fir, true).is_some());
        assert!(super::compute_forced_main_return(&fir, false).is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn emit_ir_includes_llvm_and_cranelift_forms() {
        let file_name = format!(
            "fozzylang-ir-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("temp source should be written");

        let output = emit_ir(&path).expect("emit ir should run");
        let ir = output.backend_ir.expect("backend ir should be available");
        assert!(ir.contains("backend=llvm"));
        assert!(ir.contains("backend=cranelift"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn backend_override_rejects_removed_c_shim() {
        let file_name = format!(
            "fozzylang-backend-removed-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("temp source should be written");

        let error = compile_file_with_backend(&path, BuildProfile::Dev, Some("c_shim"))
            .expect_err("removed backend must fail");
        assert!(error.to_string().contains("unknown backend"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_file_cranelift_rejects_async_c_exports_with_guidance() {
        let file_name = format!(
            "fozzylang-backend-risk-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "pubext async c fn serve(req: i32) -> i32 {\n    return req\n}\n\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file_with_backend(&path, BuildProfile::Dev, Some("cranelift"))
            .expect("build should return diagnostics");
        assert_eq!(artifact.status, "error");
        assert!(artifact
            .diagnostic_details
            .iter()
            .any(|d| d.message.contains("does not support async C export")));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn parse_program_cache_invalidates_on_source_change() {
        let file_name = format!(
            "fozzylang-parse-cache-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("temp source should be written");
        let first = parse_program(&path).expect("first parse should succeed");
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    return 17\n}\n\nfn extra() -> i32 {\n    return 1\n}\n",
        )
        .expect("temp source should mutate");
        let second = parse_program(&path).expect("second parse should succeed");
        assert_ne!(first.combined_source, second.combined_source);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn native_runtime_import_table_is_boundary_only_and_unique() {
        let errors = native_runtime_import_contract_errors();
        assert!(
            errors.is_empty(),
            "runtime import contract errors: {}",
            errors.join("; ")
        );

        let import = native_runtime_import_for_callee("http.header")
            .expect("http.header runtime import should exist");
        assert_eq!(import.symbol, "fz_native_net_header");
    }

    #[test]
    fn native_runtime_shim_exposes_request_response_and_process_result_apis() {
        let shim = render_native_runtime_shim(
            &[
                "GET".to_string(),
                "/healthz".to_string(),
                "{\"ok\":true}".to_string(),
            ],
            &["worker.run".to_string()],
            &[],
        );
        assert!(shim.contains("int32_t fz_native_net_method(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_path(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_body(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_body_json(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_body_bind(int32_t conn_fd)"));
        assert!(shim.contains("int32_t fz_native_net_write_response("));
        assert!(shim.contains("int32_t fz_native_proc_wait(int32_t handle, int32_t timeout_ms)"));
        assert!(shim.contains("int32_t fz_native_proc_stdout(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_proc_stderr(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_proc_exit_code(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_env_get(int32_t key_id)"));
        assert!(shim.contains("int32_t fz_native_str_concat2(int32_t a_id, int32_t b_id)"));
        assert!(shim.contains("int32_t fz_native_str_contains("));
        assert!(shim.contains("int32_t fz_native_http_header(int32_t key_id, int32_t value_id)"));
        assert!(
            shim.contains("int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id)")
        );
        assert!(shim.contains(
            "int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id)"
        ));
        assert!(shim.contains("int32_t fz_native_http_last_status(void)"));
        assert!(shim.contains("int32_t fz_native_http_last_error(void)"));
        assert!(shim.contains("int32_t fz_native_json_escape(int32_t input_id)"));
        assert!(shim.contains("int32_t fz_native_json_str(int32_t input_id)"));
        assert!(shim.contains("int32_t fz_native_json_raw(int32_t input_id)"));
        assert!(shim.contains("int32_t fz_native_json_array4("));
        assert!(shim.contains("int32_t fz_native_json_from_map(int32_t map_handle)"));
        assert!(shim.contains("int32_t fz_native_json_parse(int32_t json_id)"));
        assert!(
            shim.contains("int32_t fz_native_json_get(int32_t json_value_handle, int32_t key_id)")
        );
        assert!(shim
            .contains("int32_t fz_native_json_get_str(int32_t json_value_handle, int32_t key_id)"));
        assert!(
            shim.contains("int32_t fz_native_json_has(int32_t json_value_handle, int32_t key_id)")
        );
        assert!(shim
            .contains("int32_t fz_native_json_path(int32_t json_value_handle, int32_t path_id)"));
        assert!(shim.contains("int32_t fz_native_json_object1(int32_t k1_id, int32_t v1_id)"));
        assert!(shim.contains(
            "int32_t fz_native_json_object2(int32_t k1_id, int32_t v1_id, int32_t k2_id, int32_t v2_id)"
        ));
        assert!(shim.contains("int32_t fz_native_json_object3("));
        assert!(shim.contains("int32_t fz_native_json_object4("));
        assert!(shim.contains("posix_spawnp"));
        assert!(shim.contains("int32_t fz_native_proc_spawnv("));
        assert!(shim.contains("int32_t fz_native_proc_runv("));
        assert!(shim.contains("int32_t fz_native_proc_spawnl("));
        assert!(shim.contains("int32_t fz_native_proc_runl("));
        assert!(shim.contains("int32_t fz_native_proc_poll(int32_t handle)"));
        assert!(
            shim.contains("int32_t fz_native_proc_read_stdout(int32_t handle, int32_t max_bytes)")
        );
        assert!(shim.contains("int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id)"));
        assert!(shim.contains(
            "int32_t fz_native_route_match(int32_t conn_fd, int32_t method_id, int32_t pattern_id)"
        ));
        assert!(shim.contains("int32_t fz_native_fs_read_file(int32_t path_id)"));
        assert!(shim.contains("int32_t fz_native_time_tick(int32_t handle)"));
        assert!(shim.contains("int32_t fz_native_error_code(void)"));
        assert!(shim.contains("int32_t fz_native_log_info(int32_t message_id, int32_t fields_id)"));
        assert!(shim.contains("int32_t fz_native_log_fields2("));
        assert!(shim.contains("FD_CLOEXEC"));
        assert!(shim.contains("int32_t fz_native_proc_exit_class(void)"));
        assert!(shim.contains("int32_t fz_native_time_now(void)"));
        assert!(shim.contains("int32_t fz_native_fs_open(void)"));
        assert!(shim.contains("int32_t fz_native_pulse(void)"));
        assert!(shim.contains("static const int fz_task_entry_count = 1;"));
        assert!(shim.contains("fz_spawn_thread_main"));
    }

    #[test]
    fn native_runtime_shim_does_not_use_env_response_templates() {
        let shim = render_native_runtime_shim(&[], &[], &[]);
        assert!(!shim.contains("FZ_NET_WRITE_JSON_BODY"));
        assert!(!shim.contains("FZ_NET_WRITE_BODY"));
        assert!(!shim.contains("fz_env_or_default"));
    }

    #[test]
    fn native_runtime_shim_emits_async_export_handle_wrappers() {
        let shim = render_native_runtime_shim(
            &[],
            &[],
            &[NativeAsyncExport {
                name: "flush".to_string(),
                mangled_symbol: "flush".to_string(),
                params: vec![("int32_t".to_string(), "code".to_string())],
            }],
        );
        assert!(shim.contains("extern int32_t flush(int32_t code);"));
        assert!(
            shim.contains("int32_t flush_async_start(int32_t code, fz_async_handle_t* handle_out)")
        );
        assert!(
            shim.contains("int32_t flush_async_poll(fz_async_handle_t handle, int32_t* done_out)")
        );
        assert!(shim
            .contains("int32_t flush_async_await(fz_async_handle_t handle, int32_t* result_out)"));
        assert!(shim.contains("int32_t flush_async_drop(fz_async_handle_t handle)"));
    }

    #[test]
    fn native_runtime_shim_uses_documented_bind_defaults_and_visibility() {
        let shim = render_native_runtime_shim(&[], &[], &[]);
        assert!(shim.contains("int port = 8787;"));
        assert!(shim.contains("[fz-runtime] listen active addr=%s port=%d"));
        assert!(shim.contains("host_source=%s port_source=%s"));
    }

    #[test]
    fn native_runtime_shim_sanitizes_invalid_json_http_bodies() {
        let shim = render_native_runtime_shim(&[], &[], &[]);
        assert!(shim.contains("invalid_json_payload"));
        assert!(shim.contains("http.write_json sanitized non-JSON body"));
    }

    #[test]
    fn native_runtime_shim_bootstraps_dotenv_for_env_and_http() {
        let shim = render_native_runtime_shim(&[], &[], &[]);
        assert!(shim.contains("FZ_DOTENV_PATH"));
        assert!(shim.contains("ANTHROPIC_API_KEY missing"));
        assert!(shim.contains("--connect-timeout"));
        assert!(shim.contains("--max-time"));
        assert!(shim.contains("unable to exec curl"));
    }

    #[test]
    fn backend_defaults_dev_cranelift_release_llvm() {
        let project_name = format!(
            "fozzylang-backend-defaults-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let dev = compile_file_with_backend(&root, BuildProfile::Dev, None)
            .expect("dev build should succeed");
        assert_eq!(dev.status, "ok");
        assert!(root.join(".fz/build/main.o").exists());

        let release = compile_file_with_backend(&root, BuildProfile::Release, None)
            .expect("release build should succeed");
        assert_eq!(release.status, "ok");
        assert!(root.join(".fz/build/main.ll").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_accepts_runtime_and_dotted_native_calls() {
        let file_name = format!(
            "fozzylang-native-supported-runtime-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use core.http;\nfn main() -> i32 {\n    let listener = http.bind()\n    http.listen(listener)\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| diag
            .message
            .contains("native backend cannot execute unresolved call")));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cross_backend_non_i32_and_aggregate_signatures_execute_consistently() {
        let project_name = format!(
            "fozzylang-non-i32-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "#[repr(C)]\nstruct Pair { lo: i32, hi: i32 }\nfn id64(v: i64) -> i64 {\n    return v\n}\nfn gate(flag: bool) -> bool {\n    return flag\n}\nfn make_pair() -> Pair {\n    let p: Pair = Pair { lo: 1, hi: 2 }\n    return p\n}\nfn main() -> i64 {\n    let p: Pair = make_pair()\n    discard p\n    if gate(true) then return id64(3000000000)\n    return id64(3000000000)\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_primitive_control_flow_and_operator_fixture_execute_consistently() {
        let project_name = format!(
            "fozzylang-primitive-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        let fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/primitive_parity/main.fzy"),
        )
        .expect("primitive parity fixture should be readable");
        std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_native_completeness_fixture_execute_consistently() {
        let project_name = format!(
            "fozzylang-native-completeness-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        let fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/native_completeness/main.fzy"),
        )
        .expect("native completeness fixture should be readable");
        std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 25);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_const_static_globals_execute_consistently() {
        let project_name = format!(
            "fozzylang-const-static-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "const MAGIC: i32 = 7;\nstatic LIMIT: i32 = MAGIC + 3;\nfn main() -> i32 {\n    return MAGIC + LIMIT\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 17);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_static_mut_globals_execute_consistently() {
        let project_name = format!(
            "fozzylang-static-mut-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "static mut COUNTER: i32 = 2;\nfn bump() -> i32 {\n    COUNTER += 3;\n    return COUNTER\n}\nfn main() -> i32 {\n    let first = bump()\n    let second = bump()\n    return first + second\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 13);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn non_entry_infinite_loop_function_fixture_stays_non_regressing() {
        let project_name = format!(
            "fozzylang-spin-fixture-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        let fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/control_flow_spin/main.fzy"),
        )
        .expect("spin fixture should be readable");
        std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 7);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_reports_unsupported_native_signature_types() {
        let file_name = format!(
            "fozzylang-native-signature-unsupported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn helper(flag: bool) -> i32 {\n    if flag {\n        return 1\n    }\n    return 0\n}\nfn main() -> i32 {\n    return helper(true)\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("native backend does not support parameter type")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cross_backend_closure_capture_executes_consistently() {
        let project_name = format!(
            "fozzylang-closure-native-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let base: i32 = 9\n    let add = |x: i32| x + base;\n    return add(8)\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 17);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_let_pattern_destructuring_executes_consistently() {
        let project_name = format!(
            "fozzylang-let-pattern-native-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let Maybe::Some(v) = Maybe::Some(41);\n    return v + 1\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 42);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_struct_pattern_destructuring_executes_consistently() {
        let project_name = format!(
            "fozzylang-struct-pattern-native-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "struct Pair { left: i32, right: i32 }\nfn main() -> i32 {\n    let Pair { left, right: r } = Pair { left: 12, right: 30 };\n    match Pair { left: left, right: r } {\n        Pair { left: a, right: b } => return a + b,\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 42);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_accepts_native_let_pattern_lowering() {
        let file_name = format!(
            "fozzylang-native-let-pattern-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let Maybe::Some(v) = Maybe::Some(7);\n    return v\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("pattern destructuring in `let` statements")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_closure_lowering() {
        let file_name = format!(
            "fozzylang-native-closure-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let add1 = |x: i32| x + 1;\n    return add1(3)\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output
            .diagnostic_details
            .iter()
            .any(|diag| { diag.message.contains("closure/lambda expressions") }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_non_let_closure_usage_reports_unresolved_callable() {
        let file_name = format!(
            "fozzylang-native-closure-non-let-unsupported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn takes(cb: fn(i32) -> i32) -> i32 {\n    return cb(2)\n}\nfn main() -> i32 {\n    return takes(|x: i32| x + 1)\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("native backend cannot execute unresolved call `cb`")
        }));
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message.contains(
                "native backend only supports closures bound to local names via `let`/assignment",
            )
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_assigned_closure_usage() {
        let file_name = format!(
            "fozzylang-native-closure-assigned-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let mut cb = |x: i32| x + 1;\n    cb = |x: i32| x + 2;\n    return cb(3)\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message.contains(
                "native backend only supports closures bound to local names via `let`/assignment",
            )
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_let_pattern_variant_binding_source() {
        let file_name = format!(
            "fozzylang-native-let-pattern-source-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), None }\nfn id(v: Maybe) -> Maybe { return v }\nfn main() -> i32 {\n    let source = id(Maybe::Some(7))\n    let Maybe::Some(v) = source;\n    return v\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("supports `let` variant payload binding only when the initializer is the same literal enum variant")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_match_variant_payload_bindings() {
        let file_name = format!(
            "fozzylang-native-match-pattern-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Some(9)\n    match source {\n        Maybe::Some(v) => return v,\n        _ => return 0,\n    }\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("only supports match-arm variant payload bindings for literal enum scrutinees without guards")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_let_pattern_struct_binding_source() {
        let file_name = format!(
            "fozzylang-native-let-struct-pattern-source-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "struct Pair { left: i32, right: i32 }\nfn make(v: i32) -> Pair { return Pair { left: v, right: 1 } }\nfn main() -> i32 {\n    let source = make(7)\n    let Pair { left, right: r } = source;\n    return left + r\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message.contains(
                "supports `let` struct-field binding only when the initializer is the same literal struct value",
            )
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_match_struct_payload_bindings() {
        let file_name = format!(
            "fozzylang-native-match-struct-pattern-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "struct Pair { left: i32, right: i32 }\nfn make(v: i32) -> Pair { return Pair { left: v, right: 1 } }\nfn main() -> i32 {\n    let source = make(9)\n    match source {\n        Pair { left, right: r } => return left + r,\n    }\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("only supports match-arm struct-field bindings for literal struct scrutinees without guards")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_try_catch_expressions() {
        let file_name = format!(
            "fozzylang-native-try-catch-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let x = try fail() catch 7;\n    return x\n}\nfn fail() -> i32 {\n    return 1\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("native backend does not support `try/catch` expressions")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_range_expression_outside_for_in() {
        let file_name = format!(
            "fozzylang-native-range-expr-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let r = 1..4;\n    return r.end - r.start\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("detected parser-recognized expressions without full lowering parity")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_field_access_on_range_literal_expression() {
        let file_name = format!(
            "fozzylang-native-range-literal-field-access-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    return (1..4).end\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("detected parser-recognized expressions without full lowering parity")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_field_access_on_struct_literal_expression() {
        let file_name = format!(
            "fozzylang-native-struct-literal-field-access-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "struct Pair { left: i32, right: i32 }\nfn main() -> i32 {\n    return Pair { left: 3, right: 9 }.right\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("detected parser-recognized expressions without full lowering parity")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_nested_field_access_on_struct_literal_expression() {
        let file_name = format!(
            "fozzylang-native-nested-struct-literal-field-access-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "struct Inner { value: i32 }\nstruct Outer { inner: Inner }\nfn main() -> i32 {\n    return Outer { inner: Inner { value: 11 } }.inner.value\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("detected parser-recognized expressions without full lowering parity")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_nested_field_access_on_range_literal_expression() {
        let file_name = format!(
            "fozzylang-native-nested-range-field-access-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "struct Wrap { r: Range }\nfn main() -> i32 {\n    return Wrap { r: 2..8 }.r.end\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("detected parser-recognized expressions without full lowering parity")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_array_index_expression_shapes() {
        let file_name = format!(
            "fozzylang-native-array-index-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let values = [3, 5, 8];\n    let idx = 1;\n    return values[idx]\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("detected parser-recognized expressions without full lowering parity")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_match_variant_payload_bindings_for_literal_scrutinee() {
        let file_name = format!(
            "fozzylang-native-match-pattern-literal-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    match Maybe::Some(9) {\n        Maybe::Some(v) => return v,\n        _ => return 0,\n    }\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("only supports match-arm variant payload bindings for literal enum scrutinees without guards")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_match_guard_with_variant_payload_binding() {
        let file_name = format!(
            "fozzylang-native-match-guard-payload-binding-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Some(9)\n    match source {\n        Maybe::Some(v) if v > 7 => return v,\n        _ => return 0,\n    }\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("native backend does not support match guards that depend on payload or struct-field bindings")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_match_or_pattern_with_payload_bindings() {
        let file_name = format!(
            "fozzylang-native-match-or-payload-binding-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), Also(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Also(6)\n    match source {\n        Maybe::Some(v) | Maybe::Also(v) => return v,\n        _ => return 0,\n    }\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("payload or struct-field bindings within or-pattern match arms")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_native_let_or_pattern_with_payload_bindings() {
        let file_name = format!(
            "fozzylang-native-let-or-payload-binding-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), Also(i32), None }\nfn main() -> i32 {\n    let Maybe::Some(v) | Maybe::Also(v) = Maybe::Also(8);\n    return v\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("payload or struct-field bindings in `let` or-patterns")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_rejects_native_or_pattern_mismatched_binding_names() {
        let file_name = format!(
            "fozzylang-native-match-or-payload-binding-mismatch-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "enum Maybe { Some(i32), Also(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Some(9)\n    match source {\n        Maybe::Some(v) | Maybe::Also(w) => return 1,\n        _ => return 0,\n    }\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("or-pattern alternatives must bind identical names and types")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_dynamic_string_data_plane_calls_on_native_backend() {
        let file_name = format!(
            "fozzylang-native-dynamic-str-data-plane-unsupported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let s = env.get(\"K\")\n    if str.contains(s, \"a\") == 1 {\n        return 1\n    }\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("removed dynamic string data-plane runtime calls")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_accepts_foldable_string_data_plane_calls_on_native_backend() {
        let file_name = format!(
            "fozzylang-native-foldable-str-data-plane-supported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let s = \"  ab  \"\n    let t = str.trim(s)\n    if str.contains(str.replace(t, \"a\", \"x\"), \"x\") == 1 {\n        return str.len(str.replace(t, \"a\", \"x\"))\n    }\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(!output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("removed dynamic string data-plane runtime calls")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_rejects_list_map_data_plane_calls_on_native_backend() {
        let file_name = format!(
            "fozzylang-native-list-map-data-plane-unsupported-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let l = list.new()\n    list.push(l, \"x\")\n    return list.len(l)\n}\n",
        )
        .expect("temp source should be written");

        let output = verify_file(&path).expect("verify should run");
        assert!(output.diagnostic_details.iter().any(|diag| {
            diag.message
                .contains("native backend cannot execute unresolved call `list.new`")
        }));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn parse_program_fails_for_missing_declared_module() {
        let root_name = format!(
            "fozzylang-mod-missing-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(root_name);
        std::fs::create_dir_all(&root).expect("temp dir should be created");
        let path = root.join("main.fzy");
        std::fs::write(&path, "mod util;\nfn main() -> i32 {\n    return 0\n}\n")
            .expect("root source should be written");

        let error = parse_program(&path).expect_err("missing module should fail parsing");
        assert!(error.to_string().contains("resolving module `util`"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parse_program_detects_cycle() {
        let root_name = format!(
            "fozzylang-mod-cycle-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(root_name);
        std::fs::create_dir_all(&root).expect("temp dir should be created");
        let main = root.join("main.fzy");
        let a = root.join("a.fzy");
        let b = root.join("b.fzy");
        std::fs::write(&main, "mod a;\nfn main() -> i32 {\n return 0\n}\n")
            .expect("main source should be written");
        std::fs::write(&a, "mod b;\n").expect("module a should be written");
        std::fs::write(&b, "mod a;\n").expect("module b should be written");

        let error = parse_program(&main).expect_err("cycle should fail parsing");
        assert!(error.to_string().contains("cyclic module declaration"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn emit_ir_canonicalizes_sibling_module_calls() {
        let project_name = format!(
            "fozzylang-call-canonicalize-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nfn main() -> i32 {\n    services.http.start_server()\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod web;\nmod http;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/web.fzy"),
            "fn start_listener() -> i32 {\n    return 0\n}\n",
        )
        .expect("web source should be written");
        std::fs::write(
            root.join("src/services/http.fzy"),
            "fn start_server() -> i32 {\n    web.start_listener()\n    return 0\n}\n",
        )
        .expect("http source should be written");

        let output = emit_ir(&root).expect("emit ir should run");
        let ir = output.backend_ir.expect("backend ir should be available");
        assert!(ir.contains("@services.web.start_listener"));
        assert!(!ir.contains("@web.start_listener"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn direct_memory_backend_contract_array_index_lowers_without_data_plane_runtime_calls() {
        let source = "fn main() -> i32 {\n    let values = [3, 5, 8];\n    let idx = 2;\n    return values[idx]\n}\n";
        let module = parser::parse(source, "direct_memory_array").expect("source should parse");
        let typed = hir::lower(&module);
        let fir = fir::build_owned(typed);
        let llvm =
            lower_backend_ir(&fir, BackendKind::Llvm).expect("llvm lowering should succeed");
        let clif = lower_backend_ir(&fir, BackendKind::Cranelift)
            .expect("cranelift lowering should succeed");

        assert!(!llvm.contains("__native.array_"));
        assert!(!llvm.contains("fz_native_list_"));
        assert!(!llvm.contains("fz_native_map_"));
        assert!(!clif.contains("__native.array_"));
        assert!(!clif.contains("fz_native_list_"));
        assert!(!clif.contains("fz_native_map_"));
    }

    #[test]
    fn direct_memory_backend_contract_switch_and_constant_string_chain_lowering_is_parity_safe() {
        let source = "enum ErrorCode { InvalidInput, NotFound, Conflict, Timeout, Io, Internal }\nfn classify(code: ErrorCode) -> i32 {\n    match code {\n        ErrorCode::Io => return 11,\n        ErrorCode::InvalidInput => return 17,\n        ErrorCode::Timeout => return 23,\n        ErrorCode::Conflict => return 31,\n        _ => return 43,\n    }\n}\nfn main() -> i32 {\n    let values = [4, 6, 9]\n    let idx = 1\n    let score = values[idx]\n    if str.contains(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"), \"b\") == 1 {\n        return classify(ErrorCode::Io) + score + str.len(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"))\n    }\n    return 0\n}\n";
        let module = parser::parse(source, "direct_memory_contract").expect("source should parse");
        let typed = hir::lower(&module);
        let fir = fir::build_owned(typed);
        let llvm =
            lower_backend_ir(&fir, BackendKind::Llvm).expect("llvm lowering should succeed");
        let clif = lower_backend_ir(&fir, BackendKind::Cranelift)
            .expect("cranelift lowering should succeed");

        assert!(llvm.contains("switch i32"));
        assert!(clif.contains("switch"));
        assert!(!llvm.contains("declare i32 @fz_native_str_trim("));
        assert!(!llvm.contains("declare i32 @fz_native_str_replace("));
        assert!(!llvm.contains("declare i32 @fz_native_str_contains("));
        assert!(!llvm.contains("declare i32 @fz_native_str_len("));
    }

    #[test]
    fn cross_backend_direct_memory_contract_fixture_executes_consistently() {
        let project_name = format!(
            "fozzylang-direct-memory-contract-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let values = [4, 6, 9]\n    let idx = 1\n    let score = values[idx]\n    if str.contains(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"), \"b\") == 1 {\n        return score + str.len(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"))\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 9);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_direct_memory_folded_temp_string_literal_executes_consistently() {
        let project_name = format!(
            "fozzylang-direct-memory-folded-temp-str-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let base = \"  a  \"\n    let trimmed = str.trim(base)\n    let replaced = str.replace(trimmed, \"a\", \"xy\")\n    return str.len(replaced)\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_direct_memory_bounds_probe_executes_consistently() {
        let project_name = format!(
            "fozzylang-direct-memory-bounds-cross-backend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        let fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/direct_memory_safety/main.fzy"),
        )
        .expect("direct memory safety fixture should be readable");
        std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 68);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_direct_memory_i64_array_layout_executes_consistently() {
        let project_name = format!(
            "fozzylang-direct-memory-i64-array-layout-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let values = [3000000000, 4000000000]\n    let picked = values[0]\n    if picked > 2147483648 {\n        return 77\n    }\n    return 33\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 77);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_direct_memory_string_slice_executes_consistently() {
        let project_name = format!(
            "fozzylang-direct-memory-string-slice-layout-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    if str.starts_with(str.slice(\"abcdef\", 1, 3), \"bcd\") == 1 {\n        return str.len(str.slice(\"abcdef\", 1, 3)) + 16\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 19);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_direct_memory_rolling_window_index_executes_consistently() {
        let project_name = format!(
            "fozzylang-direct-memory-rolling-window-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let bytes = [10, 20, 30, 40, 50]\n    let i = 1\n    let a = bytes[i]\n    let b = bytes[i + 1]\n    let c = bytes[i + 2]\n    let d = bytes[i - 1]\n    return a + b + c + d\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift build should succeed");
        assert_eq!(cranelift.status, "ok");
        let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
            .expect("llvm build should succeed");
        assert_eq!(llvm.status, "ok");
        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_deref()
                .expect("cranelift artifact output should exist"),
        );
        let llvm_exit = run_native_exit(
            llvm.output
                .as_deref()
                .expect("llvm artifact output should exist"),
        );
        assert_eq!(cranelift_exit, llvm_exit);
        assert_eq!(cranelift_exit, 100);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cross_backend_unsafe_local_function_calls_execute_consistently() {
        let file_name = format!(
            "fozzylang-unsafe-local-backend-parity-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn lang_id(v: i32) -> i32 {\n    return v\n}\nunsafe fn lang_unsafe_id(v: i32) -> i32 {\n    return v\n}\nfn main() -> i32 {\n    let routed = lang_id(7)\n    discard lang_unsafe_id\n    unsafe {\n        discard lang_id(routed)\n    }\n    return routed\n}\n",
        )
        .expect("source should be written");

        let cranelift = compile_file_with_backend(&path, BuildProfile::Dev, Some("cranelift"))
            .expect("cranelift should compile unsafe local-call fixture");
        let llvm = compile_file_with_backend(&path, BuildProfile::Dev, Some("llvm"))
            .expect("llvm should compile unsafe local-call fixture");

        let cranelift_exit = run_native_exit(
            cranelift
                .output
                .as_ref()
                .expect("cranelift output should exist"),
        );
        let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
        assert_eq!(cranelift_exit, 7);
        assert_eq!(llvm_exit, 7);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn core_tier_no_longer_applies_legacy_shape_gate() {
        let project_name = format!(
            "fozzylang-core-tier-exp-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[language]\ntier=\"core_v1\"\nallow_experimental=false\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn risky() -> i32 { return 1 }\nfn main() -> i32 {\n    let v = try risky() catch 0\n    return v\n}\n",
        )
        .expect("source should be written");

        let output = verify_file(&root).expect("verify should run");
        assert!(!output
            .diagnostic_details
            .iter()
            .any(|d| d.message.contains("experimental language semantics")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn workspace_policy_can_override_package_language_tier() {
        let project_name = format!(
            "fozzylang-workspace-policy-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.workspace.toml"),
            "[policy]\nlanguage_tier=\"core_v1\"\nallow_experimental=false\n\n[packages.demo]\nlanguage_tier=\"experimental\"\nallow_experimental=true\n",
        )
        .expect("workspace policy should be written");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let v = try risky() catch 0\n    return v\n}\nfn risky() -> i32 { return 1 }\n",
        )
        .expect("source should be written");

        let output = verify_file(&root).expect("verify should run");
        assert!(!output
            .diagnostic_details
            .iter()
            .any(|d| d.message.contains("experimental language semantics")));
        let _ = std::fs::remove_dir_all(root);
    }
}
