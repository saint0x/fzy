#[derive(Debug, Clone, Copy)]
pub(super) struct NativeRuntimeImport {
    pub(super) callee: &'static str,
    pub(super) symbol: &'static str,
    pub(super) arity: usize,
}

pub(super) const NATIVE_RUNTIME_IMPORTS: &[NativeRuntimeImport] = &[
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
