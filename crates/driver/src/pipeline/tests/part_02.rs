use super::*;

#[test]
fn strict_compile_rejects_allocation_after_mem_freeze() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-freeze-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_freeze_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_freeze_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.mem;\nfn main() -> i32 {\n    mem.freeze()\n    let p = alloc(8)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("allocation `alloc` after `mem.freeze()`")
        })
        .expect("strict memory-freeze diagnostic should be present");
    assert_eq!(diagnostic.code.as_deref(), Some("E-DRV-MEM-FREEZE-PHASE"));

    let memory_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/memory-report.json")).expect("memory report should exist"),
    )
    .expect("memory report should be valid json");
    let main_phase = memory_report["freeze_phases"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["function"] == "main"))
        .expect("main freeze phase should be recorded");
    assert_eq!(
        main_phase["entryUnfrozen"]["allocWhileFrozen"].as_bool(),
        Some(true)
    );
    assert!(memory_report["violations"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| {
            item["kind"] == "freeze_phase"
                && item["detail"].as_str().is_some_and(|detail| {
                    detail.contains("allocation `alloc` after `mem.freeze()`")
                })
        })));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn strict_compile_rejects_helper_call_from_frozen_memory_phase() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-freeze-helper-strict-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_freeze_helper_strict\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_freeze_helper_strict\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.mem;\nfn allocate_more() -> i32 {\n    let p = alloc(8)\n    free(p)\n    return 0\n}\nfn main() -> i32 {\n    mem.freeze()\n    return allocate_more()\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("strict compile should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact
        .diagnostic_details
        .iter()
        .any(|diagnostic| diagnostic
            .message
            .contains("calls `allocate_more` from a frozen memory phase")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn documented_handle_contract_matrix_matches_compiler_metadata() {
    let docs = std::fs::read_to_string("/Users/deepsaint/Desktop/fozzylang/docs/stdlib-v1.md")
        .expect("stdlib contract doc should exist");
    assert!(docs.contains("### Handle Contract Matrix"));
    assert!(docs
        .contains("Compiler-shipped handle contracts are emitted in `.fz/handle-contracts.json`."));

    for contract in hir::runtime_handle_contracts() {
        let expected_line = format!(
            "- `{}`: copy={}, owned={}, linear={}, closable={}, send-safe={}, async-stable={}",
            contract.name,
            if contract.copy { "yes" } else { "no" },
            if contract.owned { "yes" } else { "no" },
            if contract.linear { "yes" } else { "no" },
            if contract.closable { "yes" } else { "no" },
            if contract.send_safe { "yes" } else { "no" },
            if contract.async_stable { "yes" } else { "no" },
        );
        assert!(
            docs.contains(&expected_line),
            "stdlib doc is missing handle contract row: {expected_line}"
        );
    }
}

#[test]
fn compile_file_memory_report_tracks_process_builder_handles() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-report-process-builders-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_report_process_builders\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_report_process_builders\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.proc;\nfn main() -> i32 {\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"hi\")\n    let env = proc.env_new()\n    discard proc.env_set(env, \"K\", \"V\")\n    let handle = proc.spawn_cmd(\"echo\", argv, env, \"\")\n    discard proc.close(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let memory_report = std::fs::read_to_string(root.join(".fz/memory-report.json"))
        .expect("memory report should exist");
    assert!(
        memory_report.contains("\"name\":\"argv\"") || memory_report.contains("\"name\": \"argv\"")
    );
    assert!(
        memory_report.contains("\"type\":\"ProcessArgv\"")
            || memory_report.contains("\"type\": \"ProcessArgv\"")
    );
    assert!(
        memory_report.contains("\"name\":\"env\"") || memory_report.contains("\"name\": \"env\"")
    );
    assert!(
        memory_report.contains("\"type\":\"ProcessEnv\"")
            || memory_report.contains("\"type\": \"ProcessEnv\"")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_memory_report_tracks_kv_store_handles() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-report-kv-store-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_report_kv_store\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_report_kv_store\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.storage;\nfn main() -> i32 {\n    let store = storage.kv_open(\"session.kv\")\n    discard storage.kv_put(store, \"session:key\", \"value\")\n    discard storage.kv_close(store)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let memory_report = std::fs::read_to_string(root.join(".fz/memory-report.json"))
        .expect("memory report should exist");
    assert!(
        memory_report.contains("\"name\":\"store\"")
            || memory_report.contains("\"name\": \"store\"")
    );
    assert!(
        memory_report.contains("\"type\":\"KvStoreHandle\"")
            || memory_report.contains("\"type\": \"KvStoreHandle\"")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_memory_report_tracks_file_handles() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-report-file-handle-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_report_file_handle\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_report_file_handle\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.fs;\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fzy-memory-report-file-handle.txt\")\n    discard fs.write(file, \"hello\")\n    discard fs.flush(file)\n    discard fs.close(file)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let memory_report = std::fs::read_to_string(root.join(".fz/memory-report.json"))
        .expect("memory report should exist");
    assert!(
        memory_report.contains("\"name\":\"file\"") || memory_report.contains("\"name\": \"file\"")
    );
    assert!(
        memory_report.contains("\"type\":\"FileHandle\"")
            || memory_report.contains("\"type\": \"FileHandle\"")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_memory_report_tracks_runtime_handle_families() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-report-runtime-handles-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_report_runtime_handles\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_report_runtime_handles\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn close_ws(ws: WebSocketHandle) -> i32 {\n    return http.websocket_close(ws, 1000, \"ok\")\n}\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    let conn = http.accept()\n    let ws = http.websocket_accept(conn)\n    discard close_ws(ws)\n    let handle = spawn(worker)\n    discard join(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let memory_report = std::fs::read_to_string(root.join(".fz/memory-report.json"))
        .expect("memory report should exist");
    assert!(
        memory_report.contains("\"name\":\"listener\"")
            || memory_report.contains("\"name\": \"listener\"")
    );
    assert!(
        memory_report.contains("\"type\":\"HttpHandle\"")
            || memory_report.contains("\"type\": \"HttpHandle\"")
    );
    assert!(
        memory_report.contains("\"name\":\"ws\"") || memory_report.contains("\"name\": \"ws\"")
    );
    assert!(
        memory_report.contains("\"type\":\"WebSocketHandle\"")
            || memory_report.contains("\"type\": \"WebSocketHandle\"")
    );
    assert!(
        memory_report.contains("\"name\":\"handle\"")
            || memory_report.contains("\"name\": \"handle\"")
    );
    assert!(
        memory_report.contains("\"type\":\"TaskHandle\"")
            || memory_report.contains("\"type\": \"TaskHandle\"")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_runtime_contracts_cover_runtime_handle_consumers() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-runtime-contracts-runtime-handles-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"runtime_contracts_runtime_handles\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"runtime_contracts_runtime_handles\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.proc;\nuse core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    let conn = http.accept()\n    let ws = http.websocket_accept(conn)\n    discard http.websocket_close(ws, 1000, \"ok\")\n    let argv = proc.argv_new()\n    let env = proc.env_new()\n    let proc_handle = proc.spawn_cmd(\"echo\", argv, env, \"\")\n    discard proc.close(proc_handle)\n    let handle = spawn(worker)\n    discard join(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let runtime_contracts = std::fs::read_to_string(root.join(".fz/native-runtime-contracts.json"))
        .expect("native runtime contracts should exist");
    assert!(runtime_contracts.contains("\"callee\": \"http.websocket_close\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"consume_arg0_borrow_close_payload\""));
    assert!(runtime_contracts.contains("\"returnOwnership\": \"status\""));
    assert!(runtime_contracts.contains("\"callee\": \"proc.close\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"consume_arg0\""));
    assert!(runtime_contracts.contains("\"callee\": \"join\""));
    assert!(runtime_contracts.contains("\"linearity\": \"consumes_linear_handle\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_runtime_contracts_cover_file_handle_consumers() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-runtime-contracts-file-handle-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"runtime_contracts_file_handle\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"runtime_contracts_file_handle\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.fs;\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fzy-runtime-contract-file-handle.txt\")\n    discard fs.write(file, \"hello\")\n    discard fs.flush(file)\n    discard fs.fsync(file)\n    discard fs.lock(file)\n    discard fs.close(file)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let runtime_contracts = std::fs::read_to_string(root.join(".fz/native-runtime-contracts.json"))
        .expect("native runtime contracts should exist");
    assert!(runtime_contracts.contains("\"callee\": \"fs.open\""));
    assert!(runtime_contracts.contains("\"returnOwnership\": \"owned_file_handle\""));
    assert!(runtime_contracts.contains("\"callee\": \"fs.close\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"consume_arg0\""));
    assert!(runtime_contracts.contains("\"callee\": \"fs.write\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"borrow_handle_bytes\""));
    assert!(runtime_contracts.contains("\"callee\": \"fs.read\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"borrow_handle_limit\""));
    assert!(runtime_contracts.contains("\"linearity\": \"observes_linear_handle\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_memory_report_tracks_stream_and_task_group_handles() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-report-stream-task-group-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_report_stream_task_group\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_report_stream_task_group\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn finish(group: TaskGroupHandle) -> i32 {\n    return task.group_join_all(group)\n}\nfn close_stream(stream: HttpStreamHandle) -> i32 {\n    return http.stream_close(stream)\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    discard finish(group)\n    let stream = http.post_json_stream(\"https://example.com\", \"{}\")\n    discard close_stream(stream)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let memory_report = std::fs::read_to_string(root.join(".fz/memory-report.json"))
        .expect("memory report should exist");
    assert!(
        memory_report.contains("\"name\":\"group\"")
            || memory_report.contains("\"name\": \"group\"")
    );
    assert!(
        memory_report.contains("\"type\":\"TaskGroupHandle\"")
            || memory_report.contains("\"type\": \"TaskGroupHandle\"")
    );
    assert!(
        memory_report.contains("\"name\":\"stream\"")
            || memory_report.contains("\"name\": \"stream\"")
    );
    assert!(
        memory_report.contains("\"type\":\"HttpStreamHandle\"")
            || memory_report.contains("\"type\": \"HttpStreamHandle\"")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_memory_report_tracks_collection_handles() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-memory-report-collection-handles-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"memory_report_collection_handles\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"memory_report_collection_handles\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let payload = json.parse(\"{\\\"items\\\":{\\\"a\\\":\\\"1\\\",\\\"b\\\":\\\"2\\\"}}\")\n    let items = json.keys(payload)\n    let table = json.to_map(json.path(payload, \"items\"))\n    discard list.len(items)\n    discard map.len(table)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let memory_report = std::fs::read_to_string(root.join(".fz/memory-report.json"))
        .expect("memory report should exist");
    assert!(
        memory_report.contains("\"type\":\"JsonHandle\"")
            || memory_report.contains("\"type\": \"JsonHandle\"")
    );
    assert!(
        memory_report.contains("\"type\":\"ListHandle\"")
            || memory_report.contains("\"type\": \"ListHandle\"")
    );
    assert!(
        memory_report.contains("\"type\":\"MapHandle\"")
            || memory_report.contains("\"type\": \"MapHandle\"")
    );
}

#[test]
fn compile_file_runtime_contracts_cover_collection_handle_observers() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-runtime-contracts-collection-handles-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"runtime_contracts_collection_handles\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"runtime_contracts_collection_handles\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let payload = json.parse(\"{\\\"items\\\":{\\\"a\\\":\\\"1\\\",\\\"b\\\":\\\"2\\\"}}\")\n    let items = json.keys(payload)\n    let table = json.to_map(json.path(payload, \"items\"))\n    discard list.len(items)\n    discard map.len(table)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let runtime_contracts = std::fs::read_to_string(root.join(".fz/native-runtime-contracts.json"))
        .expect("native runtime contracts should exist");
    assert!(runtime_contracts.contains("\"callee\": \"json.parse\""));
    assert!(runtime_contracts.contains("\"callee\": \"json.path\""));
    assert!(runtime_contracts.contains("\"callee\": \"json.to_map\""));
    assert!(runtime_contracts.contains("\"callee\": \"json.keys\""));
    assert!(runtime_contracts.contains("\"callee\": \"list.len\""));
    assert!(runtime_contracts.contains("\"callee\": \"map.len\""));
    assert!(runtime_contracts.contains("\"linearity\": \"produces_handle\""));
    assert!(runtime_contracts.contains("\"linearity\": \"observes_handle\""));
}

#[test]
fn compile_file_runtime_contracts_cover_stream_and_task_group_consumers() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-runtime-contracts-stream-task-group-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"runtime_contracts_stream_task_group\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"runtime_contracts_stream_task_group\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    discard task.group_join_all(group)\n    let stream = http.post_json_stream(\"https://example.com\", \"{}\")\n    discard http.stream_close(stream)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let runtime_contracts = std::fs::read_to_string(root.join(".fz/native-runtime-contracts.json"))
        .expect("native runtime contracts should exist");
    assert!(runtime_contracts.contains("\"callee\": \"http.stream_close\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"consume_arg0\""));
    assert!(runtime_contracts.contains("\"returnOwnership\": \"status\""));
    assert!(runtime_contracts.contains("\"callee\": \"task.group_join_all\""));
    assert!(runtime_contracts.contains("\"linearity\": \"consumes_linear_handle\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_emits_rpc_policy_evidence() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-rpc-safety-artifacts-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"rpc_safety_artifacts\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_safety_artifacts\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nuse core.http;\nrpc Ping(req: i32) -> i32;\nrpc Pong(req: i32) -> i32;\nfn main() -> i32 {\n    timeout(50)\n    Ping(1)\n    Pong(2)\n    cancel()\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let rpc_report =
        std::fs::read_to_string(root.join(".fz/rpc-safety.json")).expect("rpc report should exist");
    assert!(rpc_report.contains("\"deadlinePerCall\": true"));
    assert!(rpc_report.contains("\"requestOwnershipExplicit\": true"));
    assert!(rpc_report.contains("\"responseOwnershipExplicit\": true"));
    assert!(rpc_report.contains("\"payloadTypesSupported\": true"));
    assert!(rpc_report.contains("\"method\": \"Ping\""));
    assert!(rpc_report.contains("\"policy\": \"cancel\""));
    assert!(rpc_report.contains("\"cleanupPolicy\": \"explicit\""));
    assert!(rpc_report.contains("\"method\": \"Pong\""));
    assert!(rpc_report.contains("\"policy\": \"missing\""));
    assert!(rpc_report.contains("\"handlerCleanupStatus\": \"explicit\""));
    assert!(rpc_report.contains("\"errorNormalization\": \"status_code\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_runtime_contracts_cover_kv_store_consumers() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-runtime-contracts-kv-store-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"runtime_contracts_kv_store\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"runtime_contracts_kv_store\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.storage;\nfn main() -> i32 {\n    let store = storage.kv_open(\"session.kv\")\n    discard storage.kv_put(store, \"session:key\", \"value\")\n    discard storage.kv_close(store)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let runtime_contracts = std::fs::read_to_string(root.join(".fz/native-runtime-contracts.json"))
        .expect("native runtime contracts should exist");
    assert!(runtime_contracts.contains("\"callee\": \"storage.kv_open\""));
    assert!(runtime_contracts.contains("\"returnOwnership\": \"owned_kv_store\""));
    assert!(runtime_contracts.contains("\"callee\": \"storage.kv_close\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"consume_arg0\""));
    assert!(runtime_contracts.contains("\"linearity\": \"consumes_linear_handle\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_emits_async_task_handle_policy_evidence() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-handle-artifacts-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_handle_artifacts\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_handle_artifacts\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    let status = task_result(handle)\n    if status < 0 {\n        return join(handle)\n    }\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let async_report = std::fs::read_to_string(root.join(".fz/async-safety.json"))
        .expect("async safety report should exist");
    assert!(async_report.contains("\"taskHandleTerminalPolicy\": true"));
    assert!(async_report.contains("\"handle\": \"handle\""));
    assert!(async_report.contains("\"origin\": \"spawn\""));
    assert!(async_report.contains("\"policy\": \"join\""));
    assert!(async_report.contains("\"currentState\": \"joined\""));
    assert!(async_report.contains("\"resultReadsBeforeTerminal\": 1"));
    assert!(async_report.contains("\"resultReadsAfterTerminal\": 0"));
    assert!(async_report.contains("\"resultReads\": 1"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_emits_async_task_handle_missing_terminal_finding() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-handle-missing-terminal-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_handle_missing_terminal\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_handle_missing_terminal\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    discard 0\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("compile should run");
    assert_eq!(artifact.status, "error");

    let async_report = std::fs::read_to_string(root.join(".fz/async-safety.json"))
        .expect("async safety report should exist");
    assert!(async_report.contains("\"kind\": \"task_handle_missing_terminal\""));
    assert!(async_report.contains("\"currentState\": \"missing_terminal\""));
    assert!(async_report.contains("without `join`, `detach`, or `cancel_task`"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_emits_async_task_handle_misuse_findings() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-handle-misuse-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_handle_misuse\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_handle_misuse\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    detach(handle)\n    discard task_result(handle)\n    cancel_task(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("compile should run");
    assert_eq!(artifact.status, "error");

    let async_report = std::fs::read_to_string(root.join(".fz/async-safety.json"))
        .expect("async safety report should exist");
    assert!(async_report.contains("\"kind\": \"task_result_after_terminal\""));
    assert!(async_report.contains("\"kind\": \"task_handle_double_terminal\""));
    assert!(async_report.contains("\"currentState\": \"invalid_result_after_terminal\""));
    assert!(async_report.contains("\"resultReadsAfterTerminal\": 1"));
    assert!(async_report.contains("already terminated by `detach(handle)`"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_emits_async_task_group_misuse_findings() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-group-misuse-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_group_misuse\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_group_misuse\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("compile should run");
    assert_eq!(artifact.status, "error");

    let async_report = std::fs::read_to_string(root.join(".fz/async-safety.json"))
        .expect("async safety report should exist");
    assert!(async_report.contains("\"kind\": \"task_group_missing_terminal\""));
    assert!(async_report.contains("\"group\": \"group\""));
    assert!(async_report.contains("\"currentState\": \"missing_terminal\""));
    assert!(async_report
        .contains("without `task.group_join`, `task.group_join_all`, or `task.group_cancel`"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_emits_async_task_wrapper_terminal_state() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-async-task-wrapper-terminal-state-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"async_task_wrapper_terminal_state\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"async_task_wrapper_terminal_state\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn finish(handle: TaskHandle) -> i32 {\n    return join(handle)\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    return finish(handle)\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("compile should run");
    assert_eq!(artifact.status, "ok");

    let async_report = std::fs::read_to_string(root.join(".fz/async-safety.json"))
        .expect("async safety report should exist");
    assert!(async_report.contains("\"policy\": \"join via finish\""));
    assert!(async_report.contains("\"currentState\": \"joined\""));
    assert!(!async_report.contains("\"kind\": \"task_handle_missing_terminal\""));

    let _ = std::fs::remove_dir_all(root);
}
