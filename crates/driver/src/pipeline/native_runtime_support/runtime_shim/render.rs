use super::super::super::*;
use super::super::ffi_exports::{NativeAsyncExport, NativeSyncExport};
use super::core::runtime_shim_section_core;
use super::gpu::runtime_shim_section_gpu;
use super::http::runtime_shim_section_http;
use super::proc::runtime_shim_section_proc;
use super::services::runtime_shim_section_services;
use super::term::runtime_shim_section_term;

#[path = "render/async.rs"]
mod r#async;
#[path = "render/sync.rs"]
mod sync;

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

pub(crate) fn render_native_runtime_shim(
    string_literals: &[String],
    task_symbols: &[String],
    async_exports: &[NativeAsyncExport],
    sync_exports: &[NativeSyncExport],
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
    let async_export_shim = self::r#async::render_async_export_shim_code(async_exports);
    let sync_export_shim = self::sync::render_sync_export_shim_code(sync_exports);
    let count = string_literals.len();
    let task_count = task_symbols.len();
    let mut c = String::new();
    c.push_str(
        r#"#include <arpa/inet.h>
#include <ctype.h>
#ifdef __APPLE__
#include <crt_externs.h>
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include <sys/poll.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>
#endif
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
    c.push_str(&runtime_shim_section_core());
    c.push_str(&runtime_shim_section_gpu());
    c.push_str(&runtime_shim_section_http());
    c.push_str(&runtime_shim_section_services());
    c.push_str(&runtime_shim_section_proc());
    c.push_str(runtime_shim_section_term());
    c.push_str(&async_export_shim);
    c.push_str(&sync_export_shim);
    c
}
