#[test]
fn verify_tuple_partial_move_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-tuple-partial-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let pair: (*mut u8, *mut u8) = (alloc(32), alloc(32))\n    let (left, _) = pair\n    close(left)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` performs partial move from owned aggregate; partial moves are forbidden in v0"
        })
        .expect("tuple partial-move memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "move or destructure the full owned aggregate, or borrow fields instead of extracting only one owned subvalue"
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-16CC6B10"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_nested_struct_field_partial_move_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-nested-struct-field-partial-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Inner { ptr: *mut u8 }\nstruct Outer { inner: Inner, tag: i32 }\nfn main() -> i32 {\n    let outer: Outer = Outer { inner: Inner { ptr: alloc(32) }, tag: 7 }\n    let ptr = outer.inner.ptr\n    close(ptr)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` performs partial move from owned aggregate; partial moves are forbidden in v0"
        })
        .expect("nested struct-field partial-move memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "move or destructure the full owned aggregate, or borrow fields instead of extracting only one owned subvalue"
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-16CC6B10"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_partial_move_assignment_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-partial-move-assignment-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Inner { ptr: *mut u8 }\nstruct Outer { inner: Inner, tag: i32 }\nfn main() -> i32 {\n    let mut ptr = alloc(8)\n    let outer: Outer = Outer { inner: Inner { ptr: alloc(32) }, tag: 7 }\n    ptr = outer.inner.ptr\n    close(ptr)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` performs partial move assignment from owned aggregate; partial moves are forbidden in v0"
        })
        .expect("partial-move assignment memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "move or destructure the full owned aggregate, or borrow fields instead of extracting only one owned subvalue"
        )
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("partial-move assignment memory diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_enum_partial_move_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-enum-partial-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Pairish { Both(*mut u8, *mut u8), Empty }\nfn main() -> i32 {\n    let pair = Pairish::Both(alloc(32), alloc(32))\n    match pair {\n        Pairish::Both(left, _) => close(left),\n        _ => return 0,\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` performs partial move from owned aggregate; partial moves are forbidden in v0"
        })
        .expect("enum partial-move memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "move or destructure the full owned aggregate, or borrow fields instead of extracting only one owned subvalue"
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-16CC6B10"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_continue_after_free_loop_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-continue-after-free-loop-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let i: i32 = 0\n    let p = alloc(32)\n    while i < 2 {\n        if i == 0 {\n            free(p)\n            i = i + 1\n            continue\n        }\n        close(p)\n        i = i + 1\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message.contains(
                "uses conditionally consumed value `p` after path-sensitive ownership merge",
            ) || diagnostic
                .message
                .contains("divergent ownership state for `p` across loop iterations")
        })
        .expect("continue-after-free loop reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("make ownership outcomes consistent on every branch and loop path before reusing or freeing the value")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("continue-after-free loop reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_break_after_free_loop_exit_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-break-after-free-loop-exit-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    while true {\n        free(p)\n        break\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("leaks allocation")
            || diagnostic
                .message
                .contains("divergent ownership state for `p`")
            || diagnostic
                .message
                .contains("uses conditionally consumed value `p`")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_branch_divergent_ownership_diagnostic_prefers_control_flow_guidance() {
    let file_name = format!(
        "fozzylang-memory-branch-divergent-ownership-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    if true {\n        free(p)\n    } else {\n    }\n    close(p)\n    return 0\n}\n",
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
        })
        .expect("branch divergent ownership diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("make ownership outcomes consistent on every branch and loop path before reusing or freeing the value")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("branch divergent ownership diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_double_free_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-double-free-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    free(p)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` double-frees provenance root 1 via `p`"
        })
        .expect("double-free memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-6C81B006"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_plain_owned_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-owned-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce() -> *mut u8 {\n    let p = alloc(32)\n    return p\n}\nfn main() -> i32 {\n    let p = produce()\n    free(p)\n    return 0\n}\n",
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
            .contains("crosses function with potential resource escape")
            || diagnostic
                .message
                .contains("linear value `p` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_http_handle_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-http-handle-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn open_listener() -> HttpHandle {\n    return http.bind()\n}\nfn main() -> i32 {\n    let listener = open_listener()\n    close(listener)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("potential resource escape")
            || diagnostic
                .message
                .contains("linear value `listener` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_process_handle_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-process-handle-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nfn start() -> ProcessHandle {\n    let argv = proc.argv_new()\n    let env = proc.env_new()\n    return proc.spawn_cmd(\"echo\", argv, env, \"\")\n}\nfn main() -> i32 {\n    let handle = start()\n    discard proc.close(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("potential resource escape")
            || diagnostic
                .message
                .contains("linear value `handle` was not consumed/freed")
            || diagnostic
                .message
                .contains("linear value `argv` was not consumed/freed")
            || diagnostic
                .message
                .contains("linear value `env` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_file_handle_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-file-handle-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.fs;\nfn open_file() -> FileHandle {\n    return fs.open(\"/tmp/fzy-file-return.txt\")\n}\nfn main() -> i32 {\n    let file = open_file()\n    discard fs.write(file, \"hello\")\n    discard fs.close(file)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("potential resource escape")
            || diagnostic
                .message
                .contains("linear value `file` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_kv_store_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-kv-store-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.storage;\nfn open_store() -> KvStoreHandle {\n    return storage.kv_open(\"session.kv\")\n}\nfn main() -> i32 {\n    let store = open_store()\n    discard storage.kv_put(store, \"session:key\", \"value\")\n    discard storage.kv_close(store)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("potential resource escape")
            || diagnostic
                .message
                .contains("linear value `store` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_http_stream_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-http-stream-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn open_stream() -> HttpStreamHandle {\n    return http.post_json_stream(\"https://example.com\", \"{}\")\n}\nfn main() -> i32 {\n    let stream = open_stream()\n    discard http.stream_close(stream)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("potential resource escape")
            || diagnostic
                .message
                .contains("linear value `stream` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_group_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-task-group-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn start_group() -> TaskGroupHandle {\n    return task.group_begin()\n}\nfn main() -> i32 {\n    let group = start_group()\n    discard task.group_cancel(group)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("potential resource escape")
            || diagnostic
                .message
                .contains("linear value `group` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_websocket_return_does_not_report_resource_escape() {
    let file_name = format!(
        "fozzylang-memory-websocket-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn accept_ws(conn: HttpHandle) -> WebSocketHandle {\n    return http.websocket_accept(conn)\n}\nfn main() -> i32 {\n    let conn = http.accept()\n    let ws = accept_ws(conn)\n    discard http.websocket_close(ws, 1000, \"ok\")\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("potential resource escape")
            || diagnostic
                .message
                .contains("linear value `ws` was not consumed/freed")
            || diagnostic
                .message
                .contains("linear value `conn` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_branch_relayed_owned_return_does_not_report_memory_lifecycle_imbalance() {
    let file_name = format!(
        "fozzylang-memory-branch-relay-owned-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce() -> *mut u8 {\n    let p = alloc(32)\n    return p\n}\nfn relay(flag: i32) -> *mut u8 {\n    if flag == 0 {\n        return produce()\n    }\n    return produce()\n}\nfn main() -> i32 {\n    let p = relay(0)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("memory lifecycle imbalance")
            || diagnostic
                .message
                .contains("crosses function with potential resource escape")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_if_expression_relayed_owned_return_does_not_report_memory_lifecycle_imbalance() {
    let file_name = format!(
        "fozzylang-memory-if-expr-owned-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce() -> *mut u8 {\n    let p = alloc(32)\n    return p\n}\nfn relay(flag: i32) -> *mut u8 {\n    return if flag == 0 { produce() } else { produce() }\n}\nfn main() -> i32 {\n    let p = relay(0)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("memory lifecycle imbalance")
            || diagnostic
                .message
                .contains("crosses function with potential resource escape")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_handle_wrapper_return_does_not_report_memory_lifecycle_imbalance() {
    let file_name = format!(
        "fozzylang-memory-task-handle-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn worker() -> i32 {\n    return 7\n}\nfn start() -> TaskHandle {\n    return spawn(worker)\n}\nfn main() -> i32 {\n    let handle = start()\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("memory lifecycle imbalance")
            || diagnostic
                .message
                .contains("crosses function with potential resource escape")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_binary_expression_joins_consume_task_handles() {
    let file_name = format!(
        "fozzylang-memory-binary-join-task-handles-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn main() -> i32 {\n    let left = spawn(worker)\n    let right = spawn(worker)\n    return join(left) + join(right)\n}\n",
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
                .contains("linear value `left` was not consumed/freed")
            || diagnostic
                .message
                .contains("linear value `right` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_websocket_close_wrapper_consumes_handle() {
    let file_name = format!(
        "fozzylang-memory-websocket-close-wrapper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn close_ws(ws: WebSocketHandle) -> i32 {\n    return http.websocket_close(ws, 1000, \"ok\")\n}\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    let conn = http.accept()\n    let ws = http.websocket_accept(conn)\n    discard close_ws(ws)\n    return 0\n}\n",
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
                .contains("linear value `ws` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_process_close_wrapper_consumes_handle() {
    let file_name = format!(
        "fozzylang-memory-process-close-wrapper-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nfn close_wrapper(handle: ProcessHandle) -> i32 {\n    return proc.close(handle)\n}\nfn main() -> i32 {\n    let argv = proc.argv_new()\n    let env = proc.env_new()\n    let handle = proc.spawn_cmd(\"echo\", argv, env, \"\")\n    discard close_wrapper(handle)\n    return 0\n}\n",
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
                .contains("linear value `handle` was not consumed/freed")
            || diagnostic
                .message
                .contains("linear value `argv` was not consumed/freed")
            || diagnostic
                .message
                .contains("linear value `env` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

