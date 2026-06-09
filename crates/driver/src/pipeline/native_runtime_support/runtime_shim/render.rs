use super::super::super::*;
use super::super::ffi_exports::{
    collect_sync_repr_c_type_names, NativeAsyncExport, NativeExportParam, NativeExportReturn,
    NativeFfiType, NativeReprCEnum, NativeReprCStruct, NativeSyncExport,
};
use super::core::runtime_shim_section_core;
use super::gpu::runtime_shim_section_gpu;
use super::http::runtime_shim_section_http;
use super::proc::runtime_shim_section_proc;
use super::services::runtime_shim_section_services;
use super::term::runtime_shim_section_term;

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

fn render_repr_c_type_defs(sync_exports: &[NativeSyncExport]) -> String {
    let type_names = collect_sync_repr_c_type_names(sync_exports);
    if type_names.is_empty() {
        return String::new();
    }
    let mut rendered = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for export in sync_exports {
        for ty in export
            .params
            .iter()
            .map(|param| &param.ty)
            .chain(match &export.return_type {
                NativeExportReturn::Void => None.into_iter(),
                NativeExportReturn::Type(ty) => Some(ty).into_iter(),
            })
        {
            match ty {
                NativeFfiType::ReprCStruct(layout) if seen.insert(layout.name.clone()) => {
                    let _ = writeln!(&mut rendered, "typedef struct {} {{", layout.name);
                    for field in &layout.fields {
                        let _ = writeln!(&mut rendered, "  {} {};", field.c_type, field.name);
                    }
                    let _ = writeln!(&mut rendered, "}} {};\n", layout.name);
                }
                NativeFfiType::ReprCEnum(layout) if seen.insert(layout.name.clone()) => {
                    let _ = writeln!(&mut rendered, "typedef enum {} {{", layout.name);
                    for variant in &layout.variants {
                        let _ = writeln!(
                            &mut rendered,
                            "  {}_{} = {},",
                            layout.name, variant.name, variant.value
                        );
                    }
                    let _ = writeln!(&mut rendered, "}} {};\n", layout.name);
                }
                _ => {}
            }
        }
    }
    rendered
}

fn render_sync_export_helper_code(sync_exports: &[NativeSyncExport]) -> String {
    let mut out = String::new();
    let mut emitted_structs = std::collections::BTreeSet::new();
    let mut emitted_enums = std::collections::BTreeSet::new();
    for export in sync_exports {
        for ty in export
            .params
            .iter()
            .map(|param| &param.ty)
            .chain(match &export.return_type {
                NativeExportReturn::Void => None.into_iter(),
                NativeExportReturn::Type(ty) => Some(ty).into_iter(),
            })
        {
            match ty {
                NativeFfiType::ReprCStruct(layout)
                    if emitted_structs.insert(layout.name.clone()) =>
                {
                    render_struct_bridge_helpers(layout, &mut out);
                }
                NativeFfiType::ReprCEnum(layout) if emitted_enums.insert(layout.name.clone()) => {
                    render_enum_bridge_helpers(layout, &mut out);
                }
                _ => {}
            }
        }
    }
    out
}

fn render_struct_bridge_helpers(layout: &NativeReprCStruct, out: &mut String) {
    let _ = writeln!(
        out,
        "static uint64_t fz_encode_{}({} value) {{",
        layout.name, layout.name
    );
    let _ = writeln!(
        out,
        "  uint64_t handle = fz_native_agg_new(0, {});",
        layout.fields.len()
    );
    out.push_str("  if (handle == 0) {\n    return 0;\n  }\n");
    for (index, field) in layout.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "  (void)fz_native_agg_set_i64(handle, {}, (uint64_t)value.{});",
            index, field.name
        );
    }
    out.push_str("  return handle;\n}\n\n");

    let _ = writeln!(
        out,
        "static {} fz_decode_{}(uint64_t handle) {{",
        layout.name, layout.name
    );
    let _ = writeln!(out, "  {} value = {{0}};", layout.name);
    out.push_str("  if (handle == 0) {\n    return value;\n  }\n");
    for (index, field) in layout.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "  value.{} = ({})fz_native_agg_get_i64(handle, {});",
            field.name, field.c_type, index
        );
    }
    out.push_str("  return value;\n}\n\n");
}

fn render_enum_bridge_helpers(layout: &NativeReprCEnum, out: &mut String) {
    let _ = writeln!(
        out,
        "static uint64_t fz_encode_{}({} value) {{",
        layout.name, layout.name
    );
    out.push_str("  return fz_native_agg_new((int32_t)value, 0);\n}\n\n");
    let _ = writeln!(
        out,
        "static {} fz_decode_{}(uint64_t handle) {{",
        layout.name, layout.name
    );
    let _ = writeln!(
        out,
        "  return ({})fz_native_agg_tag(handle);\n}}\n",
        layout.name
    );
}

fn native_public_c_type(ty: &NativeFfiType) -> &str {
    match ty {
        NativeFfiType::Scalar { c_type } => c_type.as_str(),
        NativeFfiType::ReprCStruct(layout) => layout.name.as_str(),
        NativeFfiType::ReprCEnum(layout) => layout.name.as_str(),
    }
}

fn native_internal_c_type(ty: &NativeFfiType) -> &str {
    match ty {
        NativeFfiType::Scalar { c_type } => c_type.as_str(),
        NativeFfiType::ReprCStruct(_) | NativeFfiType::ReprCEnum(_) => "uint64_t",
    }
}

fn render_sync_export_signature_params(params: &[NativeExportParam]) -> String {
    if params.is_empty() {
        "void".to_string()
    } else {
        params
            .iter()
            .map(|param| format!("{} {}", native_public_c_type(&param.ty), param.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn render_sync_export_impl_params(params: &[NativeExportParam]) -> String {
    if params.is_empty() {
        "void".to_string()
    } else {
        params
            .iter()
            .map(|param| format!("{} {}", native_internal_c_type(&param.ty), param.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn render_sync_export_shim_code(sync_exports: &[NativeSyncExport]) -> String {
    if sync_exports.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&render_repr_c_type_defs(sync_exports));
    out.push_str(&render_sync_export_helper_code(sync_exports));

    for export in sync_exports {
        let public_return = match &export.return_type {
            NativeExportReturn::Void => "void".to_string(),
            NativeExportReturn::Type(ty) => native_public_c_type(ty).to_string(),
        };
        let impl_return = match &export.return_type {
            NativeExportReturn::Void => "void".to_string(),
            NativeExportReturn::Type(ty) => native_internal_c_type(ty).to_string(),
        };
        let public_params = render_sync_export_signature_params(&export.params);
        let impl_params = render_sync_export_impl_params(&export.params);
        let _ = writeln!(
            &mut out,
            "extern {} {}({});",
            impl_return, export.impl_symbol, impl_params
        );
        let _ = writeln!(
            &mut out,
            "{} {}({}) {{",
            public_return, export.public_symbol, public_params
        );

        let mut call_args = Vec::with_capacity(export.params.len());
        let mut repr_c_param_names = Vec::new();
        for param in &export.params {
            match &param.ty {
                NativeFfiType::Scalar { .. } => {
                    call_args.push(param.name.clone());
                }
                NativeFfiType::ReprCStruct(layout) => {
                    let handle_name = format!("{}_handle", param.name);
                    let _ = writeln!(
                        &mut out,
                        "  uint64_t {} = fz_encode_{}({});",
                        handle_name, layout.name, param.name
                    );
                    call_args.push(handle_name.clone());
                    repr_c_param_names.push(handle_name);
                }
                NativeFfiType::ReprCEnum(layout) => {
                    let handle_name = format!("{}_handle", param.name);
                    let _ = writeln!(
                        &mut out,
                        "  uint64_t {} = fz_encode_{}({});",
                        handle_name, layout.name, param.name
                    );
                    call_args.push(handle_name.clone());
                    repr_c_param_names.push(handle_name);
                }
            }
        }

        let call_expr = if call_args.is_empty() {
            format!("{}()", export.impl_symbol)
        } else {
            format!("{}({})", export.impl_symbol, call_args.join(", "))
        };
        match &export.return_type {
            NativeExportReturn::Void => {
                let _ = writeln!(&mut out, "  {};", call_expr);
                for handle_name in repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name
                    );
                }
                out.push_str("}\n\n");
            }
            NativeExportReturn::Type(NativeFfiType::Scalar { .. }) => {
                let _ = writeln!(&mut out, "  {} result = {};", public_return, call_expr);
                for handle_name in repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name
                    );
                }
                out.push_str("  return result;\n}\n\n");
            }
            NativeExportReturn::Type(NativeFfiType::ReprCStruct(layout)) => {
                out.push_str("  uint64_t result_handle = ");
                out.push_str(&call_expr);
                out.push_str(";\n");
                for handle_name in &repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0 && {} != result_handle) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name, handle_name
                    );
                }
                let _ = writeln!(
                    &mut out,
                    "  {} result = fz_decode_{}(result_handle);",
                    layout.name, layout.name
                );
                out.push_str(
                    "  if (result_handle != 0) { fz_native_agg_drop(result_handle); }\n  return result;\n}\n\n",
                );
            }
            NativeExportReturn::Type(NativeFfiType::ReprCEnum(layout)) => {
                out.push_str("  uint64_t result_handle = ");
                out.push_str(&call_expr);
                out.push_str(";\n");
                for handle_name in &repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0 && {} != result_handle) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name, handle_name
                    );
                }
                let _ = writeln!(
                    &mut out,
                    "  {} result = fz_decode_{}(result_handle);",
                    layout.name, layout.name
                );
                out.push_str(
                    "  if (result_handle != 0) { fz_native_agg_drop(result_handle); }\n  return result;\n}\n\n",
                );
            }
        }
    }

    out
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
    let async_export_shim = render_async_export_shim_code(async_exports);
    let sync_export_shim = render_sync_export_shim_code(sync_exports);
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
    c.push_str(runtime_shim_section_core());
    c.push_str(runtime_shim_section_gpu());
    c.push_str(runtime_shim_section_http());
    c.push_str(runtime_shim_section_services());
    c.push_str(runtime_shim_section_proc());
    c.push_str(runtime_shim_section_term());
    c.push_str(&async_export_shim);
    c.push_str(&sync_export_shim);
    c
}
