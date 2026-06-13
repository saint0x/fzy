#[test]
fn verify_thread_boundary_shared_param_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-thread-boundary-shared-param-snapshot-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nasync fn worker(v: &'a i32) -> i32 {\n    discard v\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `worker` parameter `v` requires Send/Sync-safe wrapper before thread crossing"
        })
        .expect("thread-boundary shared-param diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("wrap borrowed references/pointers in a Send/Sync-safe owned boundary type before crossing threads")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-635AA029"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_process_builder_argv_leak_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-process-builder-argv-leak-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nfn main() -> i32 {\n    let argv = proc.argv_new()\n    proc.argv_push(argv, \"hi\")\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` linear value `argv` was not consumed/freed"
        })
        .expect("process-builder argv leak diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("linear resources must be consumed exactly once")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("process-builder argv leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_process_builder_env_leak_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-process-builder-env-leak-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nfn main() -> i32 {\n    let env = proc.env_new()\n    proc.env_set(env, \"K\", \"V\")\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` linear value `env` was not consumed/freed"
        })
        .expect("process-builder env leak diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("linear resources must be consumed exactly once")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("process-builder env leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_file_handle_leak_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-file-handle-leak-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.fs;\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fzy-file-handle-leak.txt\")\n    discard fs.write(file, \"hello\")\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` linear value `file` was not consumed/freed"
        })
        .expect("file-handle leak diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("linear resources must be consumed exactly once")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("file-handle leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_kv_store_handle_leak_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-kv-store-leak-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.storage;\nfn main() -> i32 {\n    let store = storage.kv_open(\"session.kv\")\n    discard storage.kv_put(store, \"session:key\", \"value\")\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message == "function `main` linear value `store` was not consumed/freed"
        })
        .expect("kv-store leak diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("linear resources must be consumed exactly once")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("kv-store leak diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_process_builders_consumed_by_spawn_cmd_do_not_report_linear_leaks() {
    let file_name = format!(
        "fozzylang-process-builder-spawn-pass-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nfn main() -> i32 {\n    let argv = proc.argv_new()\n    proc.argv_push(argv, \"hi\")\n    let env = proc.env_new()\n    proc.env_set(env, \"K\", \"V\")\n    let handle = proc.spawn_cmd(\"echo\", argv, env, \"\")\n    discard proc.close(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("linear value `argv` was not consumed/freed")
            || diagnostic
                .message
                .contains("linear value `env` was not consumed/freed")
            || (diagnostic.message.contains("leaks allocation")
                && (diagnostic.message.contains("`argv`") || diagnostic.message.contains("`env`")))
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_explicit_borrowed_local_via_call_stays_clean() {
    let file_name = format!(
        "fozzylang-borrowed-local-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'a *mut u8) -> &'a *mut u8 {\n    return v\n}\nfn main() -> i32 {\n    let p = alloc(32)\n    let alias: &'a *mut u8 = borrow(p)\n    discard alias\n    free(p)\n    return 0\n}\n",
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
            .contains("call signature mismatch for `borrow`")
            || diagnostic.message.contains("argument 0 type mismatch")
            || diagnostic
                .message
                .contains("linear value `alias` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_borrow_then_free_prefers_borrow_region_diagnostic() {
    let file_name = format!(
        "fozzylang-borrow-then-free-snapshot-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'a *mut u8) -> &'a *mut u8 {\n    return v\n}\nfn main() -> i32 {\n    let p = alloc(32)\n    let alias: &'a *mut u8 = borrow(p)\n    free(p)\n    discard alias\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` consumes owner `p` via `free(p)` while borrowed reference `alias` is still live"
        })
        .expect("borrow-then-free diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("borrow-then-free diagnostic should carry stable code");
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("call signature mismatch for `borrow`")
            || diagnostic
                .message
                .contains("linear value `alias` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_borrow_then_move_prefers_borrow_region_diagnostic() {
    let file_name = format!(
        "fozzylang-borrow-then-move-snapshot-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'a *mut u8) -> &'a *mut u8 {\n    return v\n}\nfn main() -> i32 {\n    let p = alloc(32)\n    let alias: &'a *mut u8 = borrow(p)\n    let y = p\n    discard alias\n    free(y)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` consumes owner `p` via `let y = p` while borrowed reference `alias` is still live"
        })
        .expect("borrow-then-move diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("borrow-then-move diagnostic should carry stable code");
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("call signature mismatch for `borrow`")
            || diagnostic
                .message
                .contains("linear value `alias` was not consumed/freed")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_mutable_borrow_then_shared_local_reborrow_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-mut-borrow-shared-reborrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let x: i32 = 1\n    let unique: &'a mut i32 = x\n    let shared: &'a i32 = x\n    discard unique\n    discard shared\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` creates shared borrow `shared` from owner `x` while mutable borrowed reference `unique` is still live"
        })
        .expect("mutable/shared local reborrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("mutable/shared local reborrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_shared_borrow_then_mutable_local_reborrow_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-shared-borrow-mut-reborrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let x: i32 = 1\n    let shared: &'a i32 = x\n    let unique: &'a mut i32 = x\n    discard shared\n    discard unique\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` creates mutable borrow `unique` from owner `x` while shared borrowed reference `shared` is still live"
        })
        .expect("shared/mutable local reborrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("shared/mutable local reborrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_mutable_borrow_then_shared_call_reborrow_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-mut-borrow-shared-call-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn inspect(v: &'a i32) -> i32 {\n    discard v\n    return 0\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    let unique: &'a mut i32 = x\n    discard inspect(x)\n    discard unique\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` creates shared borrow of owner `x` via `inspect(x)` while mutable borrowed reference `unique` is still live"
        })
        .expect("mutable/shared call reborrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("mutable/shared call reborrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_mutable_borrow_across_await_call_edge_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-mut-borrow-await-edge-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn touch(value: &'a mut i32) -> i32 {\n    discard value\n    return 0\n}\nasync fn worker(v: &'a mut i32) -> i32 {\n    await recv()\n    return touch(v)\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "call edge `worker -> touch` can hold mutable borrows across await boundary"
        })
        .expect("mutable borrow across await call-edge diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move the `await` before borrowing, or switch the async call edge to owned/Send-safe data")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("mutable borrow across await call-edge diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_borrowed_return_across_async_suspension_call_edge_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-borrowed-return-await-edge-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'a i32) -> &'a i32 {\n    return v\n}\nasync fn worker(v: &'a i32) -> i32 {\n    await recv()\n    let alias = borrow(v)\n    discard alias\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "call edge `worker -> borrow` can propagate borrowed references across async suspension boundary"
        })
        .expect("borrowed return across await call-edge diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("resolve borrowed data before the suspension point or return an owned value instead")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("borrowed return across await call-edge diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_generic_borrow_across_await_call_edge_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-generic-borrow-await-edge-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn project<T: Show>(value: &'a T) -> &'a T {\n    return value\n}\nasync fn worker(v: &'a i32) -> i32 {\n    await recv()\n    discard project<i32>(v)\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "call edge `worker -> project` is generic/trait-heavy with borrowed parameters across await; inter-procedural lifetime summary rejected"
        })
        .expect("generic borrowed await-edge diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("specialize the borrowed call edge away from the async suspension path, or hand off owned values instead")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("generic borrowed await-edge diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_mutable_borrow_then_direct_owner_access_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-mut-borrow-direct-owner-access-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let x: i32 = 1\n    let unique: &'a mut i32 = x\n    discard x\n    discard unique\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` accesses owner `x` via `x` while mutable borrowed reference `unique` is still live"
        })
        .expect("mutable borrow direct owner access diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("use the mutable-borrowed alias directly, or move the owner access after the borrow's last use")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("mutable borrow direct owner access diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_mutable_borrow_then_plain_owner_call_access_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-mut-borrow-owner-call-access-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn inspect_value(v: i32) -> i32 {\n    return v\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    let unique: &'a mut i32 = x\n    discard inspect_value(x)\n    discard unique\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` accesses owner `x` via `inspect_value(x)` while mutable borrowed reference `unique` is still live"
        })
        .expect("mutable borrow owner call access diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("use the mutable-borrowed alias directly, or move the owner access after the borrow's last use")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("mutable borrow owner call access diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_reference_lifetime_relay_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-reference-lifetime-relay-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'b i32) -> &'b i32 {\n    return v\n}\nfn relay(a: &'a i32, b: &'b i32) -> &'a i32 {\n    return borrow(b)\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("returns reference expression with mismatched lifetime")
        })
        .expect("returned-reference lifetime relay diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("return the reference tied to the declared output lifetime on every path, or return an owned value instead")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("returned-reference lifetime relay diagnostic should carry stable code");
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("call signature mismatch for `borrow`")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_assignment_shaped_reference_lifetime_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-reference-lifetime-assignment-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow_a(v: &'a i32) -> &'a i32 {\n    return v\n}\nfn borrow_b(v: &'b i32) -> &'b i32 {\n    return v\n}\nfn relay(a: &'a i32, b: &'b i32) -> &'a i32 {\n    let mut out = borrow_a(a)\n    if true {\n        out = borrow_b(b)\n    }\n    return out\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message.contains(
                "returns reference expression without a statically traced lifetime source",
            ) || diagnostic
                .message
                .contains("returns reference expression with mismatched lifetime")
        })
        .expect("assignment-shaped returned-reference lifetime diagnostic should be present");
    let expected_help = if diagnostic
        .message
        .contains("without a statically traced lifetime source")
    {
        "bind the returned reference to one explicit input lifetime before returning, or switch the API to an owned return"
    } else {
        "return the reference tied to the declared output lifetime on every path, or return an owned value instead"
    };
    assert_eq!(diagnostic.help.as_deref(), Some(expected_help));
    let _ = diagnostic.code.as_deref().expect(
        "assignment-shaped returned-reference lifetime diagnostic should carry stable code",
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_if_expression_reference_lifetime_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-reference-lifetime-if-expr-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn relay(flag: i32, a: &'a i32, b: &'b i32) -> &'a i32 {\n    return if flag == 0 { a } else { b }\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("returns reference expression with mismatched lifetime")
                || diagnostic.message.contains(
                    "returns reference expression without a statically traced lifetime source",
                )
        })
        .expect("if-expression returned-reference lifetime diagnostic should be present");
    let expected_help = if diagnostic
        .message
        .contains("without a statically traced lifetime source")
    {
        "bind the returned reference to one explicit input lifetime before returning, or switch the API to an owned return"
    } else {
        "return the reference tied to the declared output lifetime on every path, or return an owned value instead"
    };
    assert_eq!(diagnostic.help.as_deref(), Some(expected_help));
    let _ = diagnostic
        .code
        .as_deref()
        .expect("if-expression returned-reference lifetime diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

