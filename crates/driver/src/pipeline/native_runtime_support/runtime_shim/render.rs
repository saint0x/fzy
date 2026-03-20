use super::super::super::*;
use super::super::ffi_exports::NativeAsyncExport;
use super::core::runtime_shim_section_core;
use super::http::runtime_shim_section_http;
use super::proc::runtime_shim_section_proc;
use super::services::runtime_shim_section_services;

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

pub(crate) fn render_native_runtime_shim(
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
    c.push_str(&format!("static const int fz_task_entry_count = {};\n\n", task_count));
    c.push_str("static const char* fz_string_literals[] = {\n");
    c.push_str(&literal_entries);
    c.push_str("};\n");
    c.push_str(&format!("static const int fz_string_literal_count = {};\n\n", count));
    c.push_str(runtime_shim_section_core());
    c.push_str(runtime_shim_section_http());
    c.push_str(runtime_shim_section_services());
    c.push_str(runtime_shim_section_proc());
    c.push_str(&async_export_shim);
    c
}
