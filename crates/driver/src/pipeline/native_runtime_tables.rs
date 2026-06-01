#[derive(Debug, Clone, Copy)]
pub(super) struct NativeRuntimeImport {
    pub(super) callee: &'static str,
    pub(super) symbol: &'static str,
    pub(super) arity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NativeRuntimeImportContract {
    pub(super) callee: &'static str,
    pub(super) symbol: &'static str,
    pub(super) arity: usize,
    pub(super) arg_ownership: &'static str,
    pub(super) return_ownership: &'static str,
    pub(super) required_capability: &'static str,
    pub(super) linearity: &'static str,
    pub(super) error_behavior: &'static str,
    pub(super) trace_behavior: &'static str,
    pub(super) blocking_behavior: &'static str,
}

pub(super) const NATIVE_RUNTIME_IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "alloc",
        symbol: "fz_native_alloc",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "free",
        symbol: "fz_native_free",
        arity: 1,
    },
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
        callee: "http.read_headers",
        symbol: "fz_native_net_read_headers",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "env.get",
        symbol: "fz_native_env_get",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.argv_count",
        symbol: "fz_native_proc_argv_count",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.argv_get",
        symbol: "fz_native_proc_argv_get",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "term.read_line",
        symbol: "fz_native_term_read_line",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "term.stdin_eof",
        symbol: "fz_native_term_stdin_eof",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "term.write",
        symbol: "fz_native_term_write",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "term.write_err",
        symbol: "fz_native_term_write_err",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "term.stdin_is_tty",
        symbol: "fz_native_term_stdin_is_tty",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "term.stdout_is_tty",
        symbol: "fz_native_term_stdout_is_tty",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "time.now",
        symbol: "fz_native_time_now",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "gpu.device_count",
        symbol: "fz_native_gpu_device_count",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "gpu.default_device",
        symbol: "fz_native_gpu_default_device",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "gpu.device_name",
        symbol: "fz_native_gpu_device_name",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.device_memory_bytes",
        symbol: "fz_native_gpu_device_memory_bytes",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.alloc_f32",
        symbol: "fz_native_gpu_alloc_f32",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "gpu.alloc_i32",
        symbol: "fz_native_gpu_alloc_i32",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "gpu.alloc_u32",
        symbol: "fz_native_gpu_alloc_u32",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "gpu.upload_f32",
        symbol: "fz_native_gpu_upload_f32",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.upload_i32",
        symbol: "fz_native_gpu_upload_i32",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.upload_u32",
        symbol: "fz_native_gpu_upload_u32",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.download_f32",
        symbol: "fz_native_gpu_download_f32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.download_i32",
        symbol: "fz_native_gpu_download_i32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.download_u32",
        symbol: "fz_native_gpu_download_u32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.free",
        symbol: "fz_native_gpu_buffer_free",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.slice",
        symbol: "fz_native_gpu_slice",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.launch0",
        symbol: "fz_native_gpu_launch0",
        arity: 5,
    },
    NativeRuntimeImport {
        callee: "gpu.launch1",
        symbol: "fz_native_gpu_launch1",
        arity: 6,
    },
    NativeRuntimeImport {
        callee: "gpu.launch2",
        symbol: "fz_native_gpu_launch2",
        arity: 7,
    },
    NativeRuntimeImport {
        callee: "gpu.launch3",
        symbol: "fz_native_gpu_launch3",
        arity: 8,
    },
    NativeRuntimeImport {
        callee: "gpu.launch4",
        symbol: "fz_native_gpu_launch4",
        arity: 9,
    },
    NativeRuntimeImport {
        callee: "gpu.wait",
        symbol: "fz_native_gpu_wait",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.wait_async",
        symbol: "fz_native_gpu_wait_async",
        arity: 1,
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
        callee: "http.post_json_stream",
        symbol: "fz_native_http_post_json_stream",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.request_stream",
        symbol: "fz_native_http_request_stream",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.stream_read",
        symbol: "fz_native_http_stream_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.stream_read_line",
        symbol: "fz_native_http_stream_read_line",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_eof",
        symbol: "fz_native_http_stream_eof",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_status",
        symbol: "fz_native_http_stream_status",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_error",
        symbol: "fz_native_http_stream_error",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.stream_close",
        symbol: "fz_native_http_stream_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.header_set",
        symbol: "fz_native_http_header",
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
        callee: "crypto.random_hex",
        symbol: "fz_native_crypto_random_hex",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.random_base64",
        symbol: "fz_native_crypto_random_base64",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.sha256",
        symbol: "fz_native_crypto_sha256",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.hmac_sha256",
        symbol: "fz_native_crypto_hmac_sha256",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "crypto.constant_time_eq",
        symbol: "fz_native_crypto_constant_time_eq",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "crypto.base64_encode",
        symbol: "fz_native_crypto_base64_encode",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.base64_decode",
        symbol: "fz_native_crypto_base64_decode",
        arity: 1,
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
        callee: "json.from_list",
        symbol: "fz_native_json_from_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.array",
        symbol: "fz_native_json_from_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.from_map",
        symbol: "fz_native_json_from_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.object",
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
        callee: "json.keys",
        symbol: "fz_native_json_keys",
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
        callee: "http.body_read",
        symbol: "fz_native_net_body_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.body_eof",
        symbol: "fz_native_net_body_eof",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.body_discard",
        symbol: "fz_native_net_body_discard",
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
        callee: "http.response_header_set",
        symbol: "fz_native_net_response_header_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.response_header_add",
        symbol: "fz_native_net_response_header_add",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "http.response_header_clear",
        symbol: "fz_native_net_response_header_clear",
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
        callee: "http.websocket_accept",
        symbol: "fz_native_net_websocket_accept",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_read",
        symbol: "fz_native_net_websocket_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_kind",
        symbol: "fz_native_net_websocket_kind",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_close_code",
        symbol: "fz_native_net_websocket_close_code",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_error",
        symbol: "fz_native_net_websocket_error",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "http.websocket_write_text",
        symbol: "fz_native_net_websocket_write_text",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_write_binary",
        symbol: "fz_native_net_websocket_write_binary",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_ping",
        symbol: "fz_native_net_websocket_ping",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_pong",
        symbol: "fz_native_net_websocket_pong",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "http.websocket_close",
        symbol: "fz_native_net_websocket_close",
        arity: 3,
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
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.close",
        symbol: "fz_native_fs_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.write",
        symbol: "fz_native_fs_write",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.read",
        symbol: "fz_native_fs_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.flush",
        symbol: "fz_native_fs_flush",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.fsync",
        symbol: "fz_native_fs_fsync",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.lock",
        symbol: "fz_native_fs_lock",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.atomic_write",
        symbol: "fz_native_fs_atomic_write",
        arity: 2,
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
        callee: "fs.is_file",
        symbol: "fz_native_fs_is_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.is_dir",
        symbol: "fz_native_fs_is_dir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.is_symlink",
        symbol: "fz_native_fs_is_symlink",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.stat_size",
        symbol: "fz_native_fs_stat_size",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.stat_mtime",
        symbol: "fz_native_fs_stat_mtime",
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
        callee: "fs.remove",
        symbol: "fz_native_fs_remove",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.temp_file",
        symbol: "fz_native_fs_temp_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.copy_file",
        symbol: "fz_native_fs_copy_file",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.copy_tree",
        symbol: "fz_native_fs_copy_tree",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "path.join",
        symbol: "fz_native_path_join",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "path.basename",
        symbol: "fz_native_path_basename",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.dirname",
        symbol: "fz_native_path_dirname",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.stem",
        symbol: "fz_native_path_stem",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.extension",
        symbol: "fz_native_path_extension",
        arity: 1,
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
        callee: "log.fields",
        symbol: "fz_native_log_fields_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_json",
        symbol: "fz_native_log_set_json",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_enabled",
        symbol: "fz_native_log_set_enabled",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_level",
        symbol: "fz_native_log_set_level",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_sink",
        symbol: "fz_native_log_set_sink",
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
        callee: "thread.spawn_ctx",
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
        callee: "task.context_id",
        symbol: "fz_native_task_context_id",
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
        callee: "task.group_spawn_n",
        symbol: "fz_native_task_group_spawn_n",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "task.group_join",
        symbol: "fz_native_task_group_join",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.group_join_all",
        symbol: "fz_native_task_group_join_all",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.group_cancel",
        symbol: "fz_native_task_group_cancel",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.parallel_map",
        symbol: "fz_native_task_parallel_map",
        arity: 2,
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
        callee: "assert.eq_i32",
        symbol: "fz_native_assert_eq_i32",
        arity: 2,
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
        callee: "http.poll_register",
        symbol: "fz_native_net_poll_register",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.run",
        symbol: "fz_native_proc_run",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.runl",
        symbol: "fz_native_proc_runl",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.argv_new",
        symbol: "fz_native_proc_argv_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.argv_push",
        symbol: "fz_native_proc_argv_push",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.env_new",
        symbol: "fz_native_proc_env_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.env_set",
        symbol: "fz_native_proc_env_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "proc.spawn_cmd",
        symbol: "fz_native_proc_spawn_cmd",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.run_cmd",
        symbol: "fz_native_proc_run_cmd",
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
        callee: "proc.close",
        symbol: "fz_native_proc_close",
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
    NativeRuntimeImport {
        callee: "list.new",
        symbol: "fz_native_list_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "list.push",
        symbol: "fz_native_list_push",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "list.pop",
        symbol: "fz_native_list_pop",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.len",
        symbol: "fz_native_list_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.get",
        symbol: "fz_native_list_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "list.set",
        symbol: "fz_native_list_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "list.clear",
        symbol: "fz_native_list_clear",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.join",
        symbol: "fz_native_list_join",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.new",
        symbol: "fz_native_map_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "map.set",
        symbol: "fz_native_map_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "map.get",
        symbol: "fz_native_map_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.has",
        symbol: "fz_native_map_has",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.delete",
        symbol: "fz_native_map_delete",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.keys",
        symbol: "fz_native_map_keys",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "map.len",
        symbol: "fz_native_map_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "storage.append",
        symbol: "fz_native_storage_append",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "storage.atomic_append",
        symbol: "fz_native_storage_atomic_append",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "storage.kv_open",
        symbol: "fz_native_storage_kv_open",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "storage.kv_close",
        symbol: "fz_native_storage_kv_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "storage.kv_get",
        symbol: "fz_native_storage_kv_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "storage.kv_put",
        symbol: "fz_native_storage_kv_put",
        arity: 3,
    },
];

pub(super) const NATIVE_DATA_PLANE_IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "str.concat",
        symbol: "fz_native_str_concat2",
        arity: 2,
    },
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
        callee: "str.from_i32",
        symbol: "fz_native_str_from_i32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.from_bool",
        symbol: "fz_native_str_from_bool",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.repeat",
        symbol: "fz_native_str_repeat",
        arity: 2,
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
        callee: "str.visible_len_ansi",
        symbol: "fz_native_str_visible_len_ansi",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.slice",
        symbol: "fz_native_str_slice",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.upper_ascii",
        symbol: "fz_native_str_upper_ascii",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.lower_ascii",
        symbol: "fz_native_str_lower_ascii",
        arity: 1,
    },
];

pub(super) fn native_runtime_import_for_callee(
    callee: &str,
) -> Option<&'static NativeRuntimeImport> {
    NATIVE_RUNTIME_IMPORTS
        .iter()
        .find(|import| import.callee == callee)
}

pub(super) fn native_data_plane_import_for_callee(
    callee: &str,
) -> Option<&'static NativeRuntimeImport> {
    NATIVE_DATA_PLANE_IMPORTS
        .iter()
        .find(|import| import.callee == callee)
}

fn required_capability_for_callee(callee: &str) -> &'static str {
    if callee == "alloc" || callee == "free" {
        "mem"
    } else if callee.starts_with("http.") || callee.starts_with("route.") {
        "http"
    } else if callee.starts_with("proc.") {
        "proc"
    } else if callee.starts_with("fs.") {
        "fs"
    } else if callee.starts_with("storage.") {
        "storage"
    } else if callee.starts_with("crypto.") {
        "rng"
    } else if callee.starts_with("time.") {
        "time"
    } else if callee.starts_with("gpu.") {
        "gpu"
    } else if callee.starts_with("term.") {
        "log"
    } else if callee.starts_with("thread.")
        || callee.starts_with("task.")
        || matches!(
            callee,
            "spawn"
                | "spawn_ctx"
                | "thread.spawn_ctx"
                | "detach"
                | "cancel_task"
                | "yield"
                | "recv"
        )
    {
        "thread"
    } else {
        "none"
    }
}

fn default_error_behavior(callee: &str) -> &'static str {
    if callee.starts_with("json.") || callee.starts_with("str.") {
        "value_or_empty"
    } else if callee.starts_with("http.")
        || callee.starts_with("route.")
        || callee.starts_with("proc.")
        || callee.starts_with("fs.")
        || callee.starts_with("storage.")
        || callee.starts_with("crypto.")
        || callee.starts_with("gpu.")
    {
        "runtime_status_with_last_error"
    } else {
        "none"
    }
}

fn default_trace_behavior(callee: &str) -> &'static str {
    if callee.starts_with("http.")
        || callee.starts_with("proc.")
        || callee.starts_with("task.")
        || callee.starts_with("thread.")
        || callee.starts_with("fs.")
        || callee.starts_with("storage.")
        || callee.starts_with("gpu.")
    {
        "emit_runtime_event"
    } else {
        "none"
    }
}

fn default_blocking_behavior(callee: &str) -> &'static str {
    if matches!(
        callee,
        "join"
            | "cancel_task"
            | "task.group_join"
            | "task.group_join_all"
            | "task.group_cancel"
            | "proc.wait"
            | "fs.open"
            | "fs.read"
            | "fs.write"
            | "fs.flush"
            | "fs.fsync"
            | "fs.lock"
            | "http.read"
            | "http.read_headers"
            | "http.stream_read"
            | "http.stream_read_line"
            | "http.request_stream"
            | "http.poll_next"
            | "http.websocket_read"
            | "term.read_line"
            | "fs.read_file"
            | "fs.write_file"
            | "fs.atomic_write"
            | "storage.atomic_append"
            | "gpu.device_name"
            | "gpu.device_memory_bytes"
            | "gpu.alloc_f32"
            | "gpu.alloc_i32"
            | "gpu.alloc_u32"
            | "gpu.upload_f32"
            | "gpu.upload_i32"
            | "gpu.upload_u32"
            | "gpu.download_f32"
            | "gpu.download_i32"
            | "gpu.download_u32"
            | "gpu.slice"
            | "gpu.launch0"
            | "gpu.launch1"
            | "gpu.launch2"
            | "gpu.launch3"
            | "gpu.launch4"
            | "gpu.wait"
            | "gpu.wait_async"
    ) {
        "may_block"
    } else {
        "nonblocking"
    }
}

fn default_linearity(callee: &str) -> &'static str {
    if matches!(
        callee,
        "alloc"
            | "http.bind"
            | "http.accept"
            | "http.connect"
            | "http.poll_next"
            | "http.request_stream"
            | "http.post_json_stream"
            | "http.websocket_accept"
            | "spawn"
            | "thread.spawn"
            | "spawn_ctx"
            | "thread.spawn_ctx"
            | "proc.spawn"
            | "proc.spawnl"
            | "proc.spawn_cmd"
            | "proc.run_cmd"
            | "proc.argv_new"
            | "proc.env_new"
            | "task.group_begin"
            | "task.group_spawn"
            | "storage.kv_open"
            | "fs.open"
            | "gpu.default_device"
            | "gpu.alloc_f32"
            | "gpu.alloc_i32"
            | "gpu.alloc_u32"
            | "gpu.upload_f32"
            | "gpu.upload_i32"
            | "gpu.upload_u32"
            | "gpu.launch0"
            | "gpu.launch1"
            | "gpu.launch2"
            | "gpu.launch3"
            | "gpu.launch4"
    ) {
        "produces_linear_handle"
    } else if matches!(
        callee,
        "list.new"
            | "map.new"
            | "json.parse"
            | "json.to_list"
            | "json.to_map"
            | "json.keys"
            | "fs.listdir"
            | "gpu.download_f32"
            | "gpu.download_i32"
            | "gpu.download_u32"
            | "gpu.slice"
    ) {
        "produces_handle"
    } else if matches!(
        callee,
        "join"
            | "detach"
            | "cancel_task"
            | "task.group_join"
            | "task.group_join_all"
            | "task.group_cancel"
            | "http.write"
            | "http.write_json"
            | "http.write_response"
            | "http.close"
            | "close"
            | "route.write_404"
            | "route.write_405"
            | "proc.close"
            | "storage.kv_close"
            | "fs.close"
    ) {
        "consumes_linear_handle"
    } else if matches!(
        callee,
        "task_result"
            | "proc.wait"
            | "proc.poll"
            | "http.listen"
            | "http.read"
            | "http.read_headers"
            | "http.method"
            | "http.path"
            | "http.body"
            | "http.body_read"
            | "http.body_eof"
            | "http.body_discard"
            | "http.body_json"
            | "http.body_bind"
            | "http.header"
            | "http.query"
            | "http.param"
            | "http.headers"
            | "http.request_id"
            | "http.remote_addr"
            | "http.response_header_set"
            | "http.response_header_add"
            | "http.response_header_clear"
            | "http.stream_read"
            | "http.stream_read_line"
            | "http.stream_eof"
            | "http.stream_status"
            | "http.stream_error"
            | "http.websocket_read"
            | "http.websocket_kind"
            | "http.websocket_error"
            | "http.websocket_close_code"
            | "http.websocket_write_text"
            | "http.websocket_write_binary"
            | "http.websocket_ping"
            | "http.websocket_pong"
            | "proc.exec_timeout"
            | "proc.event"
            | "proc.read_stdout"
            | "proc.read_stderr"
            | "proc.stdout"
            | "proc.stderr"
            | "proc.exit_code"
            | "fs.write"
            | "fs.read"
            | "fs.flush"
            | "fs.fsync"
            | "fs.lock"
            | "channel.send"
            | "channel.recv"
            | "storage.kv_get"
            | "storage.kv_put"
    ) {
        "observes_linear_handle"
    } else if matches!(
        callee,
        "list.push"
            | "list.pop"
            | "list.len"
            | "list.get"
            | "list.set"
            | "list.clear"
            | "list.join"
            | "map.set"
            | "map.get"
            | "map.has"
            | "map.delete"
            | "map.keys"
            | "map.len"
            | "json.get"
            | "json.get_str"
            | "json.has"
            | "json.path"
    ) {
        "observes_handle"
    } else if matches!(
        callee,
        "free" | "http.stream_close" | "http.websocket_close" | "gpu.free"
    ) {
        "consumes_linear_handle"
    } else {
        "nonlinear"
    }
}

pub(super) fn native_runtime_contract_for_callee(
    callee: &str,
) -> Option<NativeRuntimeImportContract> {
    let import = native_runtime_import_for_callee(callee)
        .or_else(|| native_data_plane_import_for_callee(callee))?;
    let mut contract = NativeRuntimeImportContract {
        callee: import.callee,
        symbol: import.symbol,
        arity: import.arity,
        arg_ownership: "borrow_args",
        return_ownership: "value",
        required_capability: required_capability_for_callee(import.callee),
        linearity: default_linearity(import.callee),
        error_behavior: default_error_behavior(import.callee),
        trace_behavior: default_trace_behavior(import.callee),
        blocking_behavior: default_blocking_behavior(import.callee),
    };
    match import.callee {
        "alloc" => {
            contract.arg_ownership = "borrow_size";
            contract.return_ownership = "owned_allocation";
        }
        "gpu.device_count" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "value";
        }
        "gpu.default_device" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "owned_gpu_device";
        }
        "gpu.device_name" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "value";
        }
        "gpu.device_memory_bytes" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "value";
        }
        "gpu.alloc_f32" | "gpu.alloc_i32" | "gpu.alloc_u32" => {
            contract.arg_ownership = "borrow_handle_len";
            contract.return_ownership = "owned_gpu_buffer";
        }
        "gpu.upload_f32" | "gpu.upload_i32" | "gpu.upload_u32" => {
            contract.arg_ownership = "borrow_handle_host_array";
            contract.return_ownership = "owned_gpu_buffer";
        }
        "gpu.download_f32" | "gpu.download_i32" | "gpu.download_u32" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "owned_numeric_vec";
        }
        "gpu.slice" => {
            contract.arg_ownership = "borrow_handle_range";
            contract.return_ownership = "gpu_buffer_view";
        }
        "gpu.launch0" | "gpu.launch1" | "gpu.launch2" | "gpu.launch3" | "gpu.launch4" => {
            contract.arg_ownership = "borrow_kernel_launch_packet";
            contract.return_ownership = "owned_gpu_event";
        }
        "gpu.wait" | "gpu.wait_async" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "gpu.free" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "free" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "join" | "detach" | "cancel_task" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "spawn" | "thread.spawn" | "spawn_ctx" | "thread.spawn_ctx" => {
            contract.arg_ownership = "borrow_spawn_fn";
            contract.return_ownership = "owned_task_handle";
        }
        "task_result" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "http.bind" | "http.accept" | "http.connect" | "http.poll_next" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "owned_http_handle";
        }
        "http.listen"
        | "http.read"
        | "http.read_headers"
        | "http.body_eof"
        | "http.body_discard"
        | "http.request_id"
        | "http.remote_addr"
        | "http.response_header_clear" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "http.method" | "http.path" | "http.body" | "http.header" | "http.query" | "http.param" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "value";
        }
        "http.body_read" => {
            contract.arg_ownership = "borrow_handle_limit";
            contract.return_ownership = "value";
        }
        "http.body_json" | "http.body_bind" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "owned_json_handle";
        }
        "http.headers" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "owned_map_handle";
        }
        "http.response_header_set" | "http.response_header_add" => {
            contract.arg_ownership = "borrow_handle_key_value";
            contract.return_ownership = "status";
        }
        "http.request_stream" => {
            contract.arg_ownership = "borrow_endpoint_payload_headers";
            contract.return_ownership = "owned_http_stream";
        }
        "http.post_json_stream" => {
            contract.arg_ownership = "borrow_endpoint_payload";
            contract.return_ownership = "owned_http_stream";
        }
        "http.stream_close" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "http.stream_read" => {
            contract.arg_ownership = "borrow_handle_limit";
            contract.return_ownership = "value";
        }
        "http.stream_read_line" | "http.stream_error" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "value";
        }
        "http.stream_eof" | "http.stream_status" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "http.write" | "http.write_json" => {
            contract.arg_ownership = "consume_arg0_borrow_status_payload";
            contract.return_ownership = "status";
        }
        "http.write_response" => {
            contract.arg_ownership = "consume_arg0_borrow_response_parts";
            contract.return_ownership = "status";
        }
        "http.websocket_accept" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "owned_websocket_handle";
        }
        "http.websocket_read"
        | "http.websocket_kind"
        | "http.websocket_error"
        | "http.websocket_close_code" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "value";
        }
        "http.websocket_write_text"
        | "http.websocket_write_binary"
        | "http.websocket_ping"
        | "http.websocket_pong" => {
            contract.arg_ownership = "borrow_handle_payload";
            contract.return_ownership = "status";
        }
        "http.websocket_close" => {
            contract.arg_ownership = "consume_arg0_borrow_close_payload";
            contract.return_ownership = "status";
        }
        "close" | "http.close" | "route.write_404" | "route.write_405" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "proc.spawn" | "proc.spawnl" | "proc.spawn_cmd" => {
            contract.arg_ownership = "borrow_spawn_spec";
            contract.return_ownership = "owned_proc_handle";
        }
        "proc.run_cmd" => {
            contract.arg_ownership = "borrow_spawn_spec";
            contract.return_ownership = "owned_proc_handle";
        }
        "proc.argv_new" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "owned_proc_argv";
        }
        "proc.env_new" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "owned_proc_env";
        }
        "proc.argv_push" => {
            contract.arg_ownership = "borrow_handle_value";
            contract.return_ownership = "status";
        }
        "proc.env_set" => {
            contract.arg_ownership = "borrow_handle_key_value";
            contract.return_ownership = "status";
        }
        "proc.close" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "proc.wait" => {
            contract.arg_ownership = "borrow_handle_timeout";
            contract.return_ownership = "status";
        }
        "proc.poll" | "proc.exec_timeout" | "proc.event" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "proc.read_stdout" | "proc.read_stderr" => {
            contract.arg_ownership = "borrow_handle_limit";
            contract.return_ownership = "value";
        }
        "proc.stdout" | "proc.stderr" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "value";
        }
        "proc.exit_code" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "task.group_begin" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "owned_task_group";
        }
        "task.group_spawn" => {
            contract.arg_ownership = "borrow_group_spawn_fn";
            contract.return_ownership = "owned_task_handle";
        }
        "task.group_join" | "task.group_join_all" | "task.group_cancel" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "list.new" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "owned_list_handle";
        }
        "list.push" | "list.set" => {
            contract.arg_ownership = "borrow_handle_value";
            contract.return_ownership = "status";
        }
        "list.pop" | "list.get" => {
            contract.arg_ownership = "borrow_handle_index";
            contract.return_ownership = "value";
        }
        "list.len" | "list.clear" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "list.join" => {
            contract.arg_ownership = "borrow_handle_separator";
            contract.return_ownership = "value";
        }
        "map.new" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "owned_map_handle";
        }
        "map.set" => {
            contract.arg_ownership = "borrow_handle_key_value";
            contract.return_ownership = "status";
        }
        "map.get" => {
            contract.arg_ownership = "borrow_handle_key";
            contract.return_ownership = "value";
        }
        "map.has" | "map.delete" => {
            contract.arg_ownership = "borrow_handle_key";
            contract.return_ownership = "status";
        }
        "map.keys" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "owned_list_handle";
        }
        "map.len" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "json.parse" => {
            contract.arg_ownership = "borrow_text";
            contract.return_ownership = "owned_json_handle";
        }
        "json.to_list" | "json.keys" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "owned_list_handle";
        }
        "json.to_map" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "owned_map_handle";
        }
        "json.get" | "json.path" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "owned_json_handle";
        }
        "json.get_str" => {
            contract.arg_ownership = "borrow_handle_key";
            contract.return_ownership = "value";
        }
        "json.has" => {
            contract.arg_ownership = "borrow_handle_key";
            contract.return_ownership = "status";
        }
        "fs.open" => {
            contract.arg_ownership = "borrow_path";
            contract.return_ownership = "owned_file_handle";
        }
        "fs.close" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "fs.write" => {
            contract.arg_ownership = "borrow_handle_bytes";
            contract.return_ownership = "status";
        }
        "fs.read" => {
            contract.arg_ownership = "borrow_handle_limit";
            contract.return_ownership = "value";
        }
        "fs.flush" | "fs.fsync" | "fs.lock" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "status";
        }
        "fs.listdir" => {
            contract.arg_ownership = "borrow_path";
            contract.return_ownership = "owned_list_handle";
        }
        "channel.send" => {
            contract.arg_ownership = "borrow_handle_payload";
            contract.return_ownership = "status";
        }
        "channel.recv" => {
            contract.arg_ownership = "borrow_handle";
            contract.return_ownership = "value";
        }
        "storage.kv_open" => {
            contract.arg_ownership = "borrow_path";
            contract.return_ownership = "owned_kv_store";
        }
        "storage.kv_close" => {
            contract.arg_ownership = "consume_arg0";
            contract.return_ownership = "status";
        }
        "storage.kv_get" => {
            contract.arg_ownership = "borrow_handle_key";
            contract.return_ownership = "value";
        }
        "storage.kv_put" => {
            contract.arg_ownership = "borrow_handle_key_value";
            contract.return_ownership = "status";
        }
        "fs.atomic_write" => {
            contract.arg_ownership = "borrow_path_bytes";
            contract.return_ownership = "status";
        }
        "storage.atomic_append" => {
            contract.arg_ownership = "borrow_target_bytes";
            contract.return_ownership = "status";
        }
        _ => {}
    }
    Some(contract)
}

pub(super) fn native_runtime_contracts() -> Vec<NativeRuntimeImportContract> {
    NATIVE_RUNTIME_IMPORTS
        .iter()
        .chain(NATIVE_DATA_PLANE_IMPORTS.iter())
        .filter_map(|import| native_runtime_contract_for_callee(import.callee))
        .collect()
}
