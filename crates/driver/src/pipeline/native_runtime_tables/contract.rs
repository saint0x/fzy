use super::*;

pub(crate) fn required_capability_for_callee(callee: &str) -> &'static str {
    if matches!(callee, "alloc" | "free" | "mem.freeze" | "mem.unfreeze") {
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

pub(crate) fn default_error_behavior(callee: &str) -> &'static str {
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

pub(crate) fn default_trace_behavior(callee: &str) -> &'static str {
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

pub(crate) fn default_blocking_behavior(callee: &str) -> &'static str {
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

pub(crate) fn default_linearity(callee: &str) -> &'static str {
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

pub(crate) fn native_runtime_contract_for_callee(
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
        "mem.freeze" | "mem.unfreeze" => {
            contract.arg_ownership = "none";
            contract.return_ownership = "status";
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

pub(crate) fn native_runtime_contracts() -> Vec<NativeRuntimeImportContract> {
    native_runtime_imports()
        .chain(NATIVE_DATA_PLANE_IMPORTS.iter())
        .filter_map(|import| native_runtime_contract_for_callee(import.callee))
        .collect()
}
