use super::*;

#[test]
fn verify_kv_close_wrapper_consumes_handle() {
    let file_name = format!(
        "fozzylang-memory-kv-close-wrapper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.storage;\nfn close_store(store: KvStoreHandle) -> i32 {\n    return storage.kv_close(store)\n}\nfn main() -> i32 {\n    let store = storage.kv_open(\"session.kv\")\n    discard storage.kv_put(store, \"session:key\", \"value\")\n    discard close_store(store)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` leaks allocation")
            || diagnostic
                .message
                .contains("linear value `store` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_file_close_wrapper_consumes_handle() {
    let file_name = format!(
        "fozzylang-memory-file-close-wrapper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.fs;\nfn close_file(file: FileHandle) -> i32 {\n    return fs.close(file)\n}\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fzy-file-close-wrapper.txt\")\n    discard fs.write(file, \"hello\")\n    discard close_file(file)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` linear value `file` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_non_consuming_stream_param_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-non-consuming-stream-param-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn inspect(stream: HttpStreamHandle) -> i32 {\n    if http.stream_eof(stream) == 1 {\n        return 1\n    }\n    discard http.stream_status(stream)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `inspect` linear value `stream` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_json_handle_helper_return_and_observer_chain_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-json-helper-return-observer-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn load() -> JsonHandle {\n    return json.parse(\"{\\\"items\\\":{\\\"a\\\":\\\"1\\\",\\\"b\\\":\\\"2\\\"}}\")\n}\nfn item_keys(payload: JsonHandle) -> ListHandle {\n    return json.keys(payload)\n}\nfn main() -> i32 {\n    let payload = load()\n    let keys = item_keys(payload)\n    return list.len(keys)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("resource escape")
            || diagnostic.message.contains("was not consumed/freed")
            || diagnostic.message.contains("uses moved value")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_list_handle_helper_observers_preserve_ownership() {
    let file_name = format!(
        "fozzylang-memory-list-helper-observers-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn size(items: ListHandle) -> i32 {\n    return list.len(items)\n}\nfn main() -> i32 {\n    let items = list.new()\n    discard list.push(items, \"alpha\")\n    discard list.push(items, \"beta\")\n    return size(items) + list.len(items)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("resource escape")
            || diagnostic.message.contains("was not consumed/freed")
            || diagnostic.message.contains("uses moved value")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_map_handle_helper_return_and_observers_stay_clean() {
    let file_name = format!(
        "fozzylang-memory-map-helper-return-observers-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn build_map() -> MapHandle {\n    let payload = map.new()\n    discard map.set(payload, \"a\", \"1\")\n    discard map.set(payload, \"b\", \"2\")\n    return payload\n}\nfn count(payload: MapHandle) -> i32 {\n    return map.len(payload)\n}\nfn main() -> i32 {\n    let payload = build_map()\n    discard map.set(payload, \"c\", \"3\")\n    return count(payload) + map.len(payload)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("resource escape")
            || diagnostic.message.contains("was not consumed/freed")
            || diagnostic.message.contains("uses moved value")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_stream_close_wrapper_consumes_handle() {
    let file_name = format!(
        "fozzylang-memory-stream-close-wrapper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn close_stream(stream: HttpStreamHandle) -> i32 {\n    return http.stream_close(stream)\n}\nfn main() -> i32 {\n    let stream = http.post_json_stream(\"https://example.com\", \"{}\")\n    discard close_stream(stream)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` linear value `stream` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_group_join_all_wrapper_consumes_group() {
    let file_name = format!(
        "fozzylang-memory-task-group-join-wrapper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn finish(group: TaskGroupHandle) -> i32 {\n    return task.group_join_all(group)\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    discard finish(group)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` linear value `group` was not consumed/freed")
            || diagnostic.message.contains("task group `group`")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_group_cancel_wrapper_consumes_group() {
    let file_name = format!(
        "fozzylang-memory-task-group-cancel-wrapper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn finish(group: TaskGroupHandle) -> i32 {\n    return task.group_cancel(group)\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    discard finish(group)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` linear value `group` was not consumed/freed")
            || diagnostic.message.contains("task group `group`")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_http_write_json_consumes_connection_param() {
    let file_name = format!(
        "fozzylang-memory-http-write-json-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn respond(conn: HttpHandle) -> i32 {\n    return http.write_json(conn, 200, \"{\\\"ok\\\":true}\")\n}\nfn main() -> i32 {\n    let conn = http.accept()\n    discard respond(conn)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` leaks allocation")
            || diagnostic
                .message
                .contains("function `respond` linear value `conn` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_loop_local_consumed_http_handle_does_not_escape_merge() {
    let file_name = format!(
        "fozzylang-memory-loop-consumed-http-handle-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn main() -> i32 {\n    let mut served = 0\n    while served < 2 {\n        let conn = http.accept()\n        discard http.write_json(conn, 200, \"{\\\"ok\\\":true}\")\n        served = served + 1\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("divergent ownership state for `conn`")
            || diagnostic
                .message
                .contains("uses moved value `conn` after move/consume")
            || diagnostic
                .message
                .contains("function `main` leaks allocation")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_memory_lifecycle_imbalance_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-lifecycle-imbalance-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let left = alloc(32)\n    let right = alloc(64)\n    free(left)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "memory lifecycle imbalance: alloc sites=2 free sites=1 returned-owned sites=0"
        })
        .expect("memory lifecycle imbalance diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("pair allocations with explicit `free(...)` or defer-based cleanup, or return the owned value explicitly on every allocating path")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("memory lifecycle imbalance diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_free_after_defer_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-free-after-defer-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    defer free(p)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` consumes value `p` after scheduling deferred cleanup for the same owner"
        })
        .expect("free-after-defer memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-6A188E7B"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_defer_after_free_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-defer-after-free-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    free(p)\n    defer free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` schedules deferred cleanup for non-owned or already-consumed value `p`"
        })
        .expect("defer-after-free memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-51C35EBD"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_branch_leak_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-branch-leak-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    if true {\n        return 0\n    }\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` leaks allocation id=1 owned by `p`"
        })
        .expect("branch-leak memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-52019802"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_early_return_leak_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-early-return-leak-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` leaks allocation id=1 owned by `p`"
        })
        .expect("early-return leak memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("early-return leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_loop_leak_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-loop-leak-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    loop {\n        break\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` leaks allocation id=1 owned by `p`"
        })
        .expect("loop leak memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("loop leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_grouped_owned_return_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-grouped-owned-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce() -> *mut u8 {\n    let p = alloc(32)\n    return (p)\n}\nfn main() -> i32 {\n    let p = produce()\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `produce` leaks allocation")
            || diagnostic
                .message
                .contains("crosses function with potential resource escape")
            || diagnostic
                .message
                .contains("linear value `p` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_helper_owned_param_transfer_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-helper-owned-param-transfer-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn consume(p: *mut u8) -> i32 {\n    free(p)\n    return 0\n}\nfn main() -> i32 {\n    let p = alloc(32)\n    discard consume(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` leaks allocation")
            || diagnostic
                .message
                .contains("consumes non-owned or already-consumed value `p`")
            || diagnostic
                .message
                .contains("linear value `p` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_non_consuming_helper_preserves_caller_ownership() {
    let file_name = format!(
        "fozzylang-memory-non-consuming-helper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn inspect(p: *mut u8) -> i32 {\n    discard p\n    return 0\n}\nfn main() -> i32 {\n    let p = alloc(32)\n    discard inspect(p)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("function `main` leaks allocation")
            || diagnostic
                .message
                .contains("consumes non-owned or already-consumed value `p`")
            || diagnostic.message.contains("double-frees provenance root")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_match_arm_cleanup_updates_ownership_state() {
    let file_name = format!(
        "fozzylang-memory-match-arm-cleanup-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    match true {\n        true => free(p),\n        _ => 0,\n    }\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("divergent ownership state for `p`")
                || diagnostic.message.contains(
                    "uses conditionally consumed value `p` after path-sensitive ownership merge",
                )
                || diagnostic
                    .message
                    .contains("consumes non-owned or already-consumed value `p`")
        })
        .expect("match-arm cleanup ownership diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("make ownership outcomes consistent on every branch and loop path before reusing or freeing the value")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("match-arm cleanup diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_grouped_owned_ffi_argument_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-grouped-owned-ffi-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "ext unsafe c fn take_owned(p_owned: *u8) -> i32;\nunsafe fn main() -> i32 {\n    let p = alloc(32)\n    discard take_owned((p))\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| diagnostic.message.contains("double-frees provenance root"))
        .expect("grouped owned ffi reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("grouped owned ffi reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_projected_owned_ffi_argument_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-projected-owned-ffi-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Holder { ptr: *mut u8 }\next unsafe c fn take_owned(p_owned: *u8) -> i32;\nunsafe fn main() -> i32 {\n    let holder: Holder = Holder { ptr: alloc(32) }\n    discard take_owned(holder.ptr)\n    free(holder.ptr)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("consumes non-owned or already-consumed value `holder`")
                || diagnostic
                    .message
                    .contains("divergent ownership state for `holder`")
                || diagnostic.message.contains("double-frees provenance root")
        })
        .expect("projected owned ffi reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("projected owned ffi reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}
