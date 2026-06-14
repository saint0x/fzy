use super::*;

pub(super) fn render_async_export_shim_code(async_exports: &[NativeAsyncExport]) -> String {
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
