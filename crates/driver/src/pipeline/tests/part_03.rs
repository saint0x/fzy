use super::*;

#[test]
fn compile_file_emits_async_runtime_wait_policy_evidence() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-runtime-wait-artifacts-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_runtime_wait_artifacts\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_runtime_wait_artifacts\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.proc;\nuse core.thread;\n\nasync fn bounded_http() -> i32 {\n    timeout(25)\n    let conn = http.accept()\n    defer close(conn)\n    discard http.read(conn)\n    return 0\n}\n\nasync fn unbounded_http() -> i32 {\n    let conn = http.accept()\n    defer close(conn)\n    discard http.read(conn)\n    return 0\n}\n\nfn main() -> i32 {\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    let handle = proc.spawn_cmd(\"echo\", argv, env_map, \"\")\n    discard proc.wait(handle, 100)\n    discard proc.close(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("compile should run");
    assert_eq!(artifact.status, "ok");

    let async_report = std::fs::read_to_string(root.join(".fz/async-safety.json"))
        .expect("async safety report should exist");
    assert!(async_report.contains("\"boundedRuntimeWaits\": true"));
    assert!(async_report.contains("\"cancelTaskCleanup\": \"join_and_cleanup\""));
    assert!(async_report.contains("\"callee\": \"http.read\""));
    assert!(async_report.contains("\"bounding\": \"task_local_timeout_or_deadline\""));
    assert!(async_report.contains("\"bounding\": \"missing_timeout_or_deadline\""));
    assert!(async_report.contains("\"callee\": \"proc.wait\""));
    assert!(async_report.contains("\"bounding\": \"explicit_timeout_arg\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_emits_gpu_event_async_policy_evidence() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-gpu-event-async-policy-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_event_async_policy\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_event_async_policy\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.thread;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nasync host fn flush(event: GpuEvent) -> void {\n    await gpu.wait_async(event)\n}\nasync host fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 8)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 8)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 8), gpu.slice(output, 0, 8), 8)\n    timeout(25)\n    await flush(event)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("compile should run");
    assert_eq!(artifact.status, "ok");

    let async_report = std::fs::read_to_string(root.join(".fz/async-safety.json"))
        .expect("async safety report should exist");
    assert!(async_report.contains("\"gpuEventTerminalPolicy\": true"));
    assert!(async_report.contains("\"gpuEventCancellation\": \"deadline_bound_wait_then_cleanup\""));
    assert!(async_report.contains("\"callee\": \"gpu.wait_async\""));
    assert!(async_report.contains("\"surface\": \"gpu_event\""));
    assert!(async_report.contains("\"waitPolicy\": \"task_local_timeout_or_deadline\""));
    assert!(async_report.contains("\"currentState\": \"waited\""));
    assert!(async_report.contains("\"cancellationPolicy\": \"deadline_bound_wait_then_cleanup\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_surfaces_async_unbounded_runtime_wait_diagnostic() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-runtime-wait-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_runtime_wait_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_runtime_wait_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.thread;\nasync fn worker() -> i32 {\n    let conn = http.accept()\n    defer close(conn)\n    discard http.read(conn)\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("function `worker` performs blocking http wait `http.read` without a timeout/deadline bound")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_async_unbounded_runtime_wait_diagnostic_is_snapshot_stable() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-runtime-wait-snapshot-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_runtime_wait_snapshot\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_runtime_wait_snapshot\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.thread;\nasync fn worker() -> i32 {\n    let conn = http.accept()\n    defer close(conn)\n    discard http.read(conn)\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| diagnostic
            .message
            == "function `worker` performs blocking http wait `http.read` without a timeout/deadline bound")
        .expect("strict runtime-wait diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "Add `timeout(...)` or `deadline(...)` before the blocking call, or switch to an intrinsically bounded wait such as `proc.wait(..., timeout_ms)` or `http.poll_next()`. GPU event waits should be deadline-bound so cancelled async work cannot strand pending launches."
        )
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("strict runtime-wait diagnostic should carry stable code");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_rejects_unbounded_gpu_event_waits() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-gpu-event-unbounded-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_event_unbounded_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_event_unbounded_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.thread;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nasync host fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 8)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 8)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 8), gpu.slice(output, 0, 8), 8)\n    await gpu.wait_async(event)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("function `main` performs blocking gpu_event wait `gpu.wait_async` without a timeout/deadline bound")));
    assert!(artifact.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("gpu event `event` in `main` reaches `gpu.wait`/`gpu.wait_async` without a task-local timeout/deadline bound")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_allows_bounded_async_runtime_waits() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-runtime-wait-bounded-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_runtime_wait_bounded\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_runtime_wait_bounded\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.thread;\nasync fn worker() -> i32 {\n    timeout(25)\n    let conn = http.accept()\n    defer close(conn)\n    discard http.read(conn)\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "ok");
    assert!(!artifact
        .diagnostic_details
        .iter()
        .any(|diagnostic| diagnostic
            .message
            .contains("without a timeout/deadline bound")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_allows_bounded_gpu_event_waits() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-gpu-event-bounded-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_event_bounded_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_event_bounded_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.thread;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nasync host fn flush(event: GpuEvent) -> void {\n    deadline(25)\n    await gpu.wait_async(event)\n}\nasync host fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 8)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 8)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 8), gpu.slice(output, 0, 8), 8)\n    deadline(25)\n    await flush(event)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "ok");
    assert!(!artifact
        .diagnostic_details
        .iter()
        .any(|diagnostic| diagnostic.message.contains("gpu.wait_async")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_rejects_rpc_calls_without_deadlines() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-rpc-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"rpc_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "rpc Ping(req: i32) -> i32;\nfn main() -> i32 {\n    Ping(1)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact
        .diagnostic_details
        .iter()
        .any(|diagnostic| diagnostic
            .message
            .contains("RPC method `Ping` is called without an explicit timeout/deadline")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_rejects_rpc_calls_without_cleanup_policy() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-rpc-strict-cleanup-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"rpc_strict_cleanup\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_strict_cleanup\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "rpc Ping(req: i32) -> i32;\nfn main() -> i32 {\n    timeout(25)\n    Ping(1)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact
        .diagnostic_details
        .iter()
        .any(|diagnostic| diagnostic.message.contains(
            "RPC method `Ping` is called without an explicit recv()/cancel() cleanup policy"
        )));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_rpc_deadline_diagnostic_is_snapshot_stable() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-rpc-strict-snapshot-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"rpc_strict_snapshot\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_strict_snapshot\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "rpc Ping(req: i32) -> i32;\nfn main() -> i32 {\n    Ping(1)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
            .message
            == "RPC method `Ping` is called without an explicit timeout/deadline on every call path"
        })
        .expect("strict rpc deadline diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "Add `timeout(...)` or `deadline(...)` before the RPC call or immediately after it so strict mode can prove the request is bounded."
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-DRV-DAD1DDDC"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_surfaces_task_group_missing_terminal_diagnostic() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-group-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_group_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_group_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("task group `group` is created by `task.group_begin()` and exits `main` without `task.group_join`, `task.group_join_all`, or `task.group_cancel`")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_task_group_terminal_diagnostic_is_snapshot_stable() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-group-snapshot-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_group_snapshot\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_group_snapshot\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| diagnostic
            .message
            == "task group `group` is created by `task.group_begin()` and exits `main` without `task.group_join`, `task.group_join_all`, or `task.group_cancel`")
        .expect("strict task group diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "Terminate every task group explicitly with `task.group_join`, `task.group_join_all`, or `task.group_cancel` before the function exits."
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-DRV-181DE01A"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_surfaces_task_handle_misuse_diagnostic() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-handle-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_handle_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_handle_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    detach(handle)\n    discard task_result(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("task handle `handle` is already terminated by `detach(handle)` and later observed by `task_result(handle)`")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_surfaces_task_handle_missing_terminal_diagnostic() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-handle-missing-terminal-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_handle_missing_terminal_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_handle_missing_terminal_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("task handle `handle` is created by `spawn` and exits `main` without `join`, `detach`, or `cancel_task`")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_task_handle_missing_terminal_diagnostic_is_snapshot_stable() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-handle-missing-terminal-snapshot-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_handle_missing_terminal_snapshot\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_handle_missing_terminal_snapshot\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| diagnostic
            .message
            == "task handle `handle` is created by `spawn` and exits `main` without `join`, `detach`, or `cancel_task`")
        .expect("strict task handle missing-terminal diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "Terminate every task handle exactly once with `join`, `detach`, or `cancel_task` before the function exits."
        )
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("strict task handle missing-terminal diagnostic should carry stable code");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_task_handle_result_after_terminal_diagnostic_is_snapshot_stable() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-handle-snapshot-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_handle_snapshot\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_handle_snapshot\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    detach(handle)\n    discard task_result(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| diagnostic
            .message
            == "task handle `handle` is already terminated by `detach(handle)` and later observed by `task_result(handle)`")
        .expect("strict task handle diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "Read `task_result(...)` before the terminal operation, or remove the later result observation."
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-DRV-3B80C0B0"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_conditional_move_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-conditional-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    if true {\n        let q = p\n        discard q\n    }\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` uses conditionally consumed value `p` after path-sensitive ownership merge"
        })
        .expect("conditional-move memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("make ownership outcomes consistent on every branch and loop path before reusing or freeing the value")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-DFF13221"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn strict_rpc_cleanup_diagnostic_is_snapshot_stable() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-rpc-strict-cleanup-snapshot-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"rpc_strict_cleanup_snapshot\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_strict_cleanup_snapshot\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "rpc Ping(req: i32) -> i32;\nfn main() -> i32 {\n    timeout(25)\n    Ping(1)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                == "RPC method `Ping` is called without an explicit recv()/cancel() cleanup policy on every call path"
        })
        .expect("strict rpc cleanup diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "Handle every RPC call with `recv()` or `cancel()` so strict mode can prove the request is cleaned up on success, deadline, and cancellation paths."
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-DRV-56917592"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_rpc_borrowed_payload_diagnostic_is_snapshot_stable() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-rpc-borrowed-payload-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"rpc_borrowed_payload\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_borrowed_payload\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "rpc Ping(req: &str) -> i32;\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Verify).expect("verify should run");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "RPC method `Ping` parameter `req` uses unsupported payload type `&str`"
        })
        .expect("borrowed rpc payload diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "RPC payloads must cross the boundary as owned/value data; replace borrowed, pointer-like, async, or function payloads with `str`, bytes, JSON, or a typed owned struct/enum"
        )
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_if_expression_conditional_move_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-if-expr-conditional-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    let q = if true { p } else { alloc(64) }\n    free(p)\n    free(q)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` uses conditionally consumed value `p` after path-sensitive ownership merge"
        })
        .expect("if-expression conditional-move diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("make ownership outcomes consistent on every branch and loop path before reusing or freeing the value")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("if-expression conditional-move diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_match_expression_conditional_move_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-match-expr-conditional-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    let q = match true {\n        true => p,\n        _ => alloc(64),\n    }\n    free(p)\n    free(q)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` uses conditionally consumed value `p` after path-sensitive ownership merge"
        })
        .expect("match-expression conditional-move diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("make ownership outcomes consistent on every branch and loop path before reusing or freeing the value")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("match-expression conditional-move diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}
