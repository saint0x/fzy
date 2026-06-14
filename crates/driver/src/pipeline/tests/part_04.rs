use super::*;

#[test]
fn verify_grouped_binding_move_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-grouped-binding-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    let q = (p)\n    free(p)\n    free(q)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `p` after move/consume"
        })
        .expect("grouped-binding move diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("grouped-binding move diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_helper_owned_param_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-helper-owned-param-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn consume(p: *mut u8) -> i32 {\n    free(p)\n    return 0\n}\nfn main() -> i32 {\n    let p = alloc(32)\n    discard consume(p)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `p` after move/consume"
        })
        .expect("helper-owned-param reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("helper-owned-param reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_alias_use_after_free_provenance_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-alias-use-after-free-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    let q = p\n    free(p)\n    close(q)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses value `q` after provenance root 1 was freed"
        })
        .expect("alias use-after-free provenance diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "stop using aliases after freeing the owning value; move the free later, or return/assign a fresh owned value before reuse"
        )
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("alias use-after-free provenance diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_helper_returned_first_arg_provenance_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-helper-returned-first-arg-provenance-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn first(a: *mut u8, b: *mut u8) -> *mut u8 {\n    return a\n}\nfn second(a: *mut u8, b: *mut u8) -> *mut u8 {\n    return b\n}\nfn main() -> i32 {\n    let a = alloc(32)\n    let b = alloc(32)\n    let from_first = first(a, b)\n    let from_second = second(a, b)\n    free(a)\n    close(from_first)\n    close(from_second)\n    free(b)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let from_first = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` uses value `from_first` after provenance root 1 was freed"
        })
        .expect("helper-returned first-arg provenance diagnostic should be present");
    assert_eq!(
        from_first.help.as_deref(),
        Some(
            "stop using aliases after freeing the owning value; move the free later, or return/assign a fresh owned value before reuse"
        )
    );
    assert!(
        !output.diagnostic_details.iter().any(|diagnostic| diagnostic
            .message
            .contains("uses value `from_second` after provenance root")),
        "second parameter provenance should stay distinct"
    );
    let _ = from_first
        .code
        .as_deref()
        .expect("helper-returned first-arg provenance diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_tuple_pattern_provenance_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-tuple-pattern-provenance-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let a = alloc(32)\n    let b = alloc(32)\n    let (left, right) = (a, b)\n    free(a)\n    close(left)\n    close(right)\n    free(b)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let left = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` uses value `left` after provenance root 1 was freed"
        })
        .expect("tuple-pattern provenance diagnostic should be present");
    assert_eq!(
        left.help.as_deref(),
        Some(
            "stop using aliases after freeing the owning value; move the free later, or return/assign a fresh owned value before reuse"
        )
    );
    assert!(
        !output.diagnostic_details.iter().any(|diagnostic| diagnostic
            .message
            .contains("uses value `right` after provenance root")),
        "tuple right element should preserve distinct provenance"
    );
    let _ = left
        .code
        .as_deref()
        .expect("tuple-pattern provenance diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_struct_pattern_provenance_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-struct-pattern-provenance-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Pair { left: *mut u8, right: *mut u8 }\nfn main() -> i32 {\n    let a = alloc(32)\n    let b = alloc(32)\n    let Pair { left, right } = Pair { left: a, right: b }\n    free(a)\n    close(left)\n    close(right)\n    free(b)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let left = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` uses value `left` after provenance root 1 was freed"
        })
        .expect("struct-pattern provenance diagnostic should be present");
    assert_eq!(
        left.help.as_deref(),
        Some(
            "stop using aliases after freeing the owning value; move the free later, or return/assign a fresh owned value before reuse"
        )
    );
    assert!(
        !output.diagnostic_details.iter().any(|diagnostic| diagnostic
            .message
            .contains("uses value `right` after provenance root")),
        "struct right field should preserve distinct provenance"
    );
    let _ = left
        .code
        .as_deref()
        .expect("struct-pattern provenance diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_reassignment_clears_stale_provenance_root() {
    let file_name = format!(
        "fozzylang-memory-reassignment-clears-stale-provenance-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "ext unsafe c fn acquire_owned() -> *u8\nunsafe fn main() -> i32 {\n    let p = alloc(32)\n    let q = p\n    q = acquire_owned()\n    free(p)\n    close(q)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(
        !output.diagnostic_details.iter().any(|diagnostic| diagnostic
            .message
            .contains("uses value `q` after provenance root")),
        "reassignment should clear stale provenance on q"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_returned_second_pointer_arg_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-returned-second-pointer-arg-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn passthrough(a: *mut u8, b: *mut u8) -> *mut u8 {\n    return b\n}\nfn main() -> i32 {\n    let a = alloc(32)\n    let b = alloc(32)\n    let ret = passthrough(a, b)\n    free(a)\n    close(ret)\n    free(b)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(
        !output.diagnostic_details.iter().any(|diagnostic| diagnostic
            .message
            .contains("uses value `ret` after provenance root")),
        "returned second parameter should not collapse to first argument provenance root"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_nested_use_after_free_control_flow_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-nested-use-after-free-control-flow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let p = alloc(32)\n    let q = p\n    if true {\n        free(p)\n    } else {\n        return 0\n    }\n    close(q)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses value `q` after provenance root 1 was freed"
        })
        .expect("nested use-after-free control-flow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "stop using aliases after freeing the owning value; move the free later, or return/assign a fresh owned value before reuse"
        )
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("nested use-after-free control-flow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_handle_wrapper_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-task-handle-wrapper-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn finish(handle: TaskHandle) -> i32 {\n    return join(handle)\n}\nfn main() -> i32 {\n    let handle = spawn(worker)\n    discard finish(handle)\n    discard join(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `handle` after move/consume"
        })
        .expect("task-handle wrapper reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("task-handle wrapper reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_http_wrapper_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-http-wrapper-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn respond(conn: HttpHandle) -> i32 {\n    return http.write_json(conn, 200, \"{}\")\n}\nfn main() -> i32 {\n    let conn = http.accept()\n    discard respond(conn)\n    discard http.write_json(conn, 200, \"{}\")\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `conn` after move/consume"
        })
        .expect("http wrapper reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("http wrapper reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_process_wrapper_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-process-wrapper-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nfn close_handle(handle: ProcessHandle) -> i32 {\n    return proc.close(handle)\n}\nfn main() -> i32 {\n    let argv = proc.argv_new()\n    let env = proc.env_new()\n    let handle = proc.spawn_cmd(\"echo\", argv, env, \"\")\n    discard close_handle(handle)\n    discard proc.close(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `handle` after move/consume"
        })
        .expect("process wrapper reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("process wrapper reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_file_handle_wrapper_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-file-handle-wrapper-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.fs;\nfn close_file(file: FileHandle) -> i32 {\n    return fs.close(file)\n}\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fzy-file-wrapper-reuse.txt\")\n    discard fs.write(file, \"hello\")\n    discard close_file(file)\n    discard fs.close(file)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `file` after move/consume"
        })
        .expect("file-handle wrapper reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("file-handle wrapper reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_kv_store_wrapper_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-kv-store-wrapper-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.storage;\nfn close_store(store: KvStoreHandle) -> i32 {\n    return storage.kv_close(store)\n}\nfn main() -> i32 {\n    let store = storage.kv_open(\"session.kv\")\n    discard storage.kv_put(store, \"session:key\", \"value\")\n    discard close_store(store)\n    discard storage.kv_close(store)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `store` after move/consume"
        })
        .expect("kv-store wrapper reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("kv-store wrapper reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_stream_wrapper_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-stream-wrapper-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn close_stream(stream: HttpStreamHandle) -> i32 {\n    return http.stream_close(stream)\n}\nfn main() -> i32 {\n    let stream = http.post_json_stream(\"https://example.com\", \"{}\")\n    discard close_stream(stream)\n    discard http.stream_close(stream)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `stream` after move/consume"
        })
        .expect("stream wrapper reuse diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("stream wrapper reuse diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_group_wrapper_reuse_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-task-group-wrapper-reuse-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn finish(group: TaskGroupHandle) -> i32 {\n    return task.group_join_all(group)\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    discard finish(group)\n    discard task.group_cancel(group)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let moved = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` uses moved value `group` after move/consume"
        })
        .expect("task-group wrapper reuse moved diagnostic should be present");
    assert_eq!(
        moved.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = moved
        .code
        .as_deref()
        .expect("task-group wrapper reuse moved diagnostic should carry stable code");

    let double_terminal = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "task group `group` is terminated multiple times (task.group_join_all via finish, task.group_cancel)"
        })
        .expect("task-group wrapper reuse double-terminal diagnostic should be present");
    assert_eq!(
        double_terminal.help.as_deref(),
        Some(
            "Choose exactly one terminal group operation for each task group and remove the later terminal calls."
        )
    );
    let _ = double_terminal
        .code
        .as_deref()
        .expect("task-group wrapper reuse double-terminal diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_return_if_expression_partial_terminal_transfer_reports_leak() {
    let file_name = format!(
        "fozzylang-memory-return-if-expr-transfer-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce(flag: i32) -> *mut u8 {\n    let p = alloc(32)\n    return if flag == 0 { p } else { alloc(64) }\n}\nfn main() -> i32 {\n    let p = produce(0)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `produce` leaks allocation id=1 owned by `p`"
        })
        .expect("return-if terminal leak diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("return-if terminal leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_return_match_expression_partial_terminal_transfer_reports_leak() {
    let file_name = format!(
        "fozzylang-memory-return-match-expr-transfer-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce(flag: i32) -> *mut u8 {\n    let p = alloc(32)\n    return match flag {\n        0 => p,\n        _ => alloc(64),\n    }\n}\nfn main() -> i32 {\n    let p = produce(0)\n    free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `produce` leaks allocation id=1 owned by `p`"
        })
        .expect("return-match terminal leak diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("return-match terminal leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_return_if_expression_owned_transfer_on_all_paths_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-return-if-expr-transfer-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce(flag: i32) -> *mut u8 {\n    let p = alloc(32)\n    return if flag == 0 { p } else { (p) }\n}\nfn main() -> i32 {\n    let p = produce(0)\n    free(p)\n    return 0\n}\n",
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
            .contains("divergent ownership state for `p`")
            || diagnostic
                .message
                .contains("crosses function with potential resource escape")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_return_match_expression_owned_transfer_on_all_paths_stays_clean() {
    let file_name = format!(
        "fozzylang-memory-return-match-expr-transfer-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn produce(flag: i32) -> *mut u8 {\n    let p = alloc(32)\n    return match flag {\n        0 => p,\n        _ => (p),\n    }\n}\nfn main() -> i32 {\n    let p = produce(0)\n    free(p)\n    return 0\n}\n",
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
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_partial_move_memory_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-memory-partial-move-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Pair { left: *mut u8, right: *mut u8 }\nfn main() -> i32 {\n    let pair: Pair = Pair { left: alloc(32), right: alloc(32) }\n    let Pair { left, right: _ } = pair\n    free(left)\n    return 0\n}\n",
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
        .expect("partial-move memory diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some(
            "move or destructure the full owned aggregate, or borrow fields instead of extracting only one owned subvalue"
        )
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-16CC6B10"));

    let _ = std::fs::remove_file(path);
}
