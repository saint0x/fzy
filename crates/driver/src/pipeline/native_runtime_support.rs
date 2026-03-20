use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use super::*;

#[derive(Debug, Clone)]
pub(super) struct NativeAsyncExport {
    pub(super) name: String,
    pub(super) mangled_symbol: String,
    pub(super) params: Vec<(String, String)>,
}

pub(super) fn native_runtime_import_contract_errors() -> Vec<String> {
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
    for import in NATIVE_DATA_PLANE_IMPORTS {
        if !seen.insert(import.callee) {
            errors.push(format!(
                "duplicate native runtime import callee `{}` in data-plane import table",
                import.callee
            ));
        }
    }

    let declared_runtime = hir::runtime_intrinsic_names()
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let imported_runtime = NATIVE_RUNTIME_IMPORTS
        .iter()
        .chain(NATIVE_DATA_PLANE_IMPORTS.iter())
        .map(|import| import.callee)
        .collect::<HashSet<_>>();

    let critical = [
        "str.concat",
        "str.concat2",
        "str.concat3",
        "str.concat4",
        "proc.run",
        "proc.spawn",
        "proc.run_cmd",
        "proc.spawn_cmd",
        "proc.exec_timeout",
    ];
    for callee in critical
        .iter()
        .copied()
        .filter(|callee| !declared_runtime.contains(callee))
    {
        errors.push(format!(
            "intrinsic `{}` is required by parity gate but missing from HIR declarations",
            callee
        ));
    }
    for callee in critical
        .iter()
        .copied()
        .filter(|callee| !imported_runtime.contains(callee))
    {
        errors.push(format!(
            "intrinsic `{}` is declared in HIR but missing native import binding",
            callee
        ));
    }
    for callee in imported_runtime
        .iter()
        .filter(|callee| !declared_runtime.contains(**callee))
    {
        errors.push(format!(
            "native import `{}` is not declared as a runtime intrinsic in HIR",
            callee
        ));
    }
    errors
}

pub(super) fn is_extern_c_import_decl(function: &hir::TypedFunction) -> bool {
    function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        && function.body.is_empty()
}

pub(super) fn collect_extern_c_imports(fir: &fir::FirModule) -> Vec<&hir::TypedFunction> {
    fir.typed_functions
        .iter()
        .filter(|function| is_extern_c_import_decl(function))
        .collect()
}

pub(super) fn is_extern_c_abi_function(function: &hir::TypedFunction) -> bool {
    function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
}

pub(super) fn native_link_symbol_for_function(function: &hir::TypedFunction) -> String {
    let base = if is_extern_c_abi_function(function) {
        function
            .link_name
            .clone()
            .unwrap_or_else(|| function.name.clone())
    } else {
        function.name.clone()
    };
    native_mangle_symbol(&base)
}

pub(super) fn collect_async_c_exports(fir: &fir::FirModule) -> Vec<NativeAsyncExport> {
    fir.typed_functions
        .iter()
        .filter(|function| {
            function.is_async
                && is_extern_c_abi_function(function)
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
            name: native_link_symbol_for_function(function),
            mangled_symbol: native_link_symbol_for_function(function),
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

pub(super) fn ensure_native_runtime_shim(
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

pub(super) fn compile_runtime_shim_object(
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

pub(super) fn ffi_signature_type_to_c_type(ty: &ast::Type) -> String {
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

pub(super) fn collect_used_native_runtime_imports(
    fir: &fir::FirModule,
) -> Vec<&'static NativeRuntimeImport> {
    let mut seen = HashSet::<&'static str>::new();
    let mut used = Vec::<&'static NativeRuntimeImport>::new();
    for function in &fir.typed_functions {
        for stmt in &function.body {
            collect_used_runtime_imports_from_stmt(stmt, &mut seen, &mut used);
        }
    }
    used
}

pub(super) fn collect_used_native_data_plane_imports(
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

pub(super) fn render_native_runtime_shim(
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
#define FZ_MAX_STORAGE_KV 1024

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

typedef struct {
  int in_use;
  int32_t path_id;
  int32_t map_handle;
} fz_storage_kv_state;

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
static fz_storage_kv_state fz_storage_kv[FZ_MAX_STORAGE_KV];
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

static int32_t fz_storage_kv_alloc(void) {
  for (int i = 0; i < FZ_MAX_STORAGE_KV; i++) {
    if (!fz_storage_kv[i].in_use) {
      memset(&fz_storage_kv[i], 0, sizeof(fz_storage_kv[i]));
      fz_storage_kv[i].in_use = 1;
      return i + 1;
    }
  }
  return -1;
}

static fz_storage_kv_state* fz_storage_kv_get(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_STORAGE_KV) {
    return NULL;
  }
  fz_storage_kv_state* kv = &fz_storage_kv[handle - 1];
  return kv->in_use ? kv : NULL;
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

int32_t fz_native_log_fields_map(int32_t map_handle) {
  return fz_native_json_from_map(map_handle);
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

static int fz_storage_write_atomic_path(const char* path, const char* content) {
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (content == NULL) {
    content = "";
  }
  char tmp_path[2048];
  int written = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
  if (written <= 0 || (size_t)written >= sizeof(tmp_path)) {
    return -1;
  }
  int fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    return -1;
  }
  size_t left = strlen(content);
  const char* p = content;
  while (left > 0) {
    ssize_t n = write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return -1;
    }
    if (n == 0) {
      break;
    }
    p += n;
    left -= (size_t)n;
  }
  if (fsync(fd) != 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return rename(tmp_path, path) == 0 ? 0 : -1;
}

int32_t fz_native_storage_append(int32_t path_id, int32_t line_id) {
  const char* path = fz_lookup_string(path_id);
  const char* line = fz_lookup_string(line_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (line == NULL) {
    line = "";
  }
  int fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0644);
  if (fd < 0) {
    return -1;
  }
  size_t len = strlen(line);
  if (len > 0 && write(fd, line, len) < 0) {
    close(fd);
    return -1;
  }
  if (write(fd, "\n", 1) < 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

int32_t fz_native_storage_atomic_append(int32_t path_id, int32_t line_id) {
  const char* path = fz_lookup_string(path_id);
  const char* line = fz_lookup_string(line_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  if (line == NULL) {
    line = "";
  }
  int32_t existing_id = fz_native_fs_read_file(path_id);
  const char* existing = fz_lookup_string(existing_id);
  if (existing == NULL) {
    existing = "";
  }
  size_t existing_len = strlen(existing);
  size_t line_len = strlen(line);
  char* payload = (char*)malloc(existing_len + line_len + 3);
  if (payload == NULL) {
    return -1;
  }
  size_t used = 0;
  if (existing_len > 0) {
    memcpy(payload + used, existing, existing_len);
    used += existing_len;
    if (payload[used - 1] != '\n') {
      payload[used++] = '\n';
    }
  }
  if (line_len > 0) {
    memcpy(payload + used, line, line_len);
    used += line_len;
  }
  payload[used++] = '\n';
  payload[used] = '\0';
  int rc = fz_storage_write_atomic_path(path, payload);
  free(payload);
  return rc == 0 ? 0 : -1;
}

int32_t fz_native_storage_kv_open(int32_t path_id) {
  const char* path = fz_lookup_string(path_id);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }
  int32_t map_handle = fz_runtime_map_new();
  int32_t file_json_id = fz_native_fs_read_file(path_id);
  const char* raw = fz_lookup_string(file_json_id);
  if (raw != NULL && raw[0] != '\0') {
    int32_t parsed_handle = fz_native_json_to_map(file_json_id);
    if (parsed_handle > 0) {
      map_handle = parsed_handle;
    }
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t kv_handle = fz_storage_kv_alloc();
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv != NULL) {
    kv->path_id = path_id;
    kv->map_handle = map_handle;
  }
  pthread_mutex_unlock(&fz_collections_lock);
  return kv == NULL ? -1 : kv_handle;
}

int32_t fz_native_storage_kv_get(int32_t kv_handle, int32_t key_id) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return fz_intern_slice("", 0);
  }
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_collections_lock);
  return fz_runtime_map_get(map_handle, key_id);
}

int32_t fz_native_storage_kv_put(int32_t kv_handle, int32_t key_id, int32_t value_id) {
  pthread_mutex_lock(&fz_collections_lock);
  fz_storage_kv_state* kv = fz_storage_kv_get(kv_handle);
  if (kv == NULL) {
    pthread_mutex_unlock(&fz_collections_lock);
    return -1;
  }
  int32_t path_id = kv->path_id;
  int32_t map_handle = kv->map_handle;
  pthread_mutex_unlock(&fz_collections_lock);
  int rc = fz_runtime_map_set(map_handle, key_id, value_id);
  if (rc != 0) {
    return -1;
  }
  int32_t json_id = fz_native_json_from_map(map_handle);
  const char* path = fz_lookup_string(path_id);
  const char* content = fz_lookup_string(json_id);
  return fz_storage_write_atomic_path(path, content) == 0 ? 0 : -1;
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

int32_t fz_native_proc_argv_new(void) { return fz_runtime_list_new(); }
int32_t fz_native_proc_argv_push(int32_t argv_list_id, int32_t value_id) {
  return fz_runtime_list_push(argv_list_id, value_id);
}
int32_t fz_native_proc_env_new(void) { return fz_runtime_map_new(); }
int32_t fz_native_proc_env_set(int32_t env_map_id, int32_t key_id, int32_t value_id) {
  return fz_runtime_map_set(env_map_id, key_id, value_id);
}
int32_t fz_native_proc_spawn_cmd(
    int32_t command_id,
    int32_t argv_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  return fz_native_proc_spawnl(command_id, argv_list_id, env_map_id, stdin_id);
}
int32_t fz_native_proc_run_cmd(
    int32_t command_id,
    int32_t argv_list_id,
    int32_t env_map_id,
    int32_t stdin_id) {
  return fz_native_proc_runl(command_id, argv_list_id, env_map_id, stdin_id);
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

int32_t fz_native_task_group_spawn_n(int32_t group_id, int32_t task_ref, int32_t n) {
  if (n <= 0) {
    return 0;
  }
  for (int32_t i = 0; i < n; i++) {
    if (fz_native_task_group_spawn(group_id, task_ref) < 0) {
      return -1;
    }
  }
  return 0;
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

int32_t fz_native_task_group_join_all(int32_t group_id) {
  return fz_native_task_group_join(group_id);
}

int32_t fz_native_task_parallel_map(int32_t list_handle, int32_t task_ref) {
  int32_t count = fz_runtime_list_len(list_handle);
  if (count < 0) {
    return -1;
  }
  int32_t group_id = fz_native_task_group_begin();
  if (group_id < 0) {
    return -1;
  }
  if (fz_native_task_group_spawn_n(group_id, task_ref, count) < 0) {
    (void)fz_native_task_group_cancel(group_id);
    return -1;
  }
  return fz_native_task_group_join_all(group_id);
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

int32_t fz_native_assert_eq_i32(int32_t left, int32_t right) {
  if (left != right) {
    fprintf(stderr, "assert.eq_i32 failed: left=%d right=%d\n", left, right);
    return -1;
  }
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

