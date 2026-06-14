use super::*;

#[test]
fn verify_spawn_closure_shared_borrow_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-spawn-closure-shared-borrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn observe(v: &'a i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    let shared: &'a i32 = x\n    let worker = | | observe(shared)\n    let handle = spawn(worker)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` spawn captures shared borrowed reference `shared` across thread boundary"
        })
        .expect("spawn closure shared-borrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("spawn closure shared-borrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_spawn_closure_mutable_borrow_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-spawn-closure-mutable-borrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn touch(v: &'a mut i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    let unique: &'a mut i32 = x\n    let worker = | | touch(unique)\n    let handle = spawn(worker)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` spawn captures mutable borrowed reference `unique` across thread boundary"
        })
        .expect("spawn closure mutable-borrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("spawn closure mutable-borrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_group_spawn_closure_shared_borrow_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-task-group-spawn-shared-borrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn observe(v: &'a i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    let x: i32 = 1\n    let shared: &'a i32 = x\n    let worker = | | observe(shared)\n    discard task.group_spawn(group, worker)\n    discard task.group_join_all(group)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` task.group_spawn captures shared borrowed reference `shared` across thread boundary"
        })
        .expect("task.group_spawn closure shared-borrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("task.group_spawn closure shared-borrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_spawn_ctx_closure_shared_borrow_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-spawn-ctx-shared-borrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn observe(v: &'a i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    let shared: &'a i32 = x\n    let worker = | | observe(shared)\n    let handle = spawn_ctx(worker, 7)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` spawn_ctx captures shared borrowed reference `shared` across thread boundary"
        })
        .expect("spawn_ctx closure shared-borrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("spawn_ctx closure shared-borrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_thread_spawn_ctx_closure_shared_borrow_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-thread-spawn-ctx-shared-borrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn observe(v: &'a i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    let shared: &'a i32 = x\n    let worker = | | observe(shared)\n    let handle = thread.spawn_ctx(worker, 7)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` thread.spawn_ctx captures shared borrowed reference `shared` across thread boundary"
        })
        .expect("thread.spawn_ctx closure shared-borrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("thread.spawn_ctx closure shared-borrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_parallel_map_closure_shared_borrow_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-parallel-map-shared-borrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn observe(v: &'a i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    let x: i32 = 1\n    let shared: &'a i32 = x\n    let worker = | | observe(shared)\n    let code = task.parallel_map(group, worker)\n    discard code\n    discard task.group_join_all(group)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` task.parallel_map captures shared borrowed reference `shared` across thread boundary"
        })
        .expect("task.parallel_map closure shared-borrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("task.parallel_map closure shared-borrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_task_group_spawn_n_closure_shared_borrow_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-task-group-spawn-n-shared-borrow-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn observe(v: &'a i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let group = task.group_begin()\n    let x: i32 = 1\n    let shared: &'a i32 = x\n    let worker = | | observe(shared)\n    discard task.group_spawn_n(group, worker, 1)\n    discard task.group_join_all(group)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` task.group_spawn_n captures shared borrowed reference `shared` across thread boundary"
        })
        .expect("task.group_spawn_n closure shared-borrow diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move owned data into the spawned task, or wrap borrowed references/pointers in a Send/Sync-safe owned boundary type")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("task.group_spawn_n closure shared-borrow diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_spawn_closure_non_send_safe_http_handle_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-spawn-closure-http-handle-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nuse core.thread;\nfn main() -> i32 {\n    let conn = http.accept()\n    let worker = | | http.path(conn)\n    let handle = spawn(worker)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` spawn captures non-Send-safe handle `conn` (HttpHandle) across thread boundary"
        })
        .expect("spawn closure non-send-safe http-handle diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move only Send-safe handles into spawned tasks, or finish/close the non-Send-safe handle before crossing the thread boundary")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("spawn closure non-send-safe http-handle diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_spawn_closure_non_send_safe_file_handle_reports_thread_boundary_help() {
    let file_name = format!(
        "fozzylang-spawn-closure-file-handle-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.fs;\nuse core.thread;\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fzy-spawn-file-handle.txt\")\n    let worker = | | fs.flush(file)\n    let handle = spawn(worker)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                == "function `main` spawn captures non-Send-safe handle `file` (FileHandle) across thread boundary"
        })
        .expect("spawn closure non-send-safe file-handle diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move only Send-safe handles into spawned tasks, or finish/close the non-Send-safe handle before crossing the thread boundary")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("spawn closure non-send-safe file-handle diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_spawn_closure_owned_capture_stays_clean() {
    let file_name = format!(
        "fozzylang-spawn-closure-owned-capture-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn main() -> i32 {\n    let x: i32 = 1\n    let worker = | | x\n    let handle = spawn(worker)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diag| matches!(diag.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains("captures shared borrowed reference")
            || diag.message.contains("captures mutable borrowed reference")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_spawn_closure_send_safe_list_handle_stays_clean() {
    let file_name = format!(
        "fozzylang-spawn-closure-send-safe-list-handle-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.thread;\nfn main() -> i32 {\n    let payload = json.parse(\"[1,2,3]\")\n    let items = json.to_list(payload)\n    let worker = | | list.len(items)\n    let handle = spawn(worker)\n    return join(handle)\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diag| matches!(diag.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains("captures non-Send-safe handle")
            || diag.message.contains("captures shared borrowed reference")
            || diag.message.contains("captures mutable borrowed reference")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_non_thread_borrowed_reference_does_not_report_thread_boundary_diagnostic() {
    let file_name = format!(
        "fozzylang-borrowed-reference-pass-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'a i32) -> &'a i32 {\n    return v\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diag| matches!(diag.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains("thread-capable boundary")
            || diag
                .help
                .as_deref()
                .unwrap_or_default()
                .contains("Send/Sync-safe handle")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_mutable_and_shared_alias_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-mutable-shared-alias-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn touch(a: &'a mut i32, b: &'a i32) -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    touch(x, x)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message
                == "function `main` call `touch` aliases mutable and shared borrows for `x`"
        })
        .expect("mutable/shared alias diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-E4FA711B"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn core_tier_no_longer_applies_legacy_shape_gate() {
    let project_name = format!(
        "fozzylang-core-tier-exp-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[language]\ntier=\"core_v1\"\nallow_experimental=false\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn risky() -> i32 { return 1 }\nfn main() -> i32 {\n    let v = try risky() catch 0\n    return v\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&root).expect("verify should run");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|d| d.message.contains("experimental language semantics")));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn workspace_policy_can_override_package_language_tier() {
    let project_name = format!(
        "fozzylang-workspace-policy-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.workspace.toml"),
        "[policy]\nlanguage_tier=\"core_v1\"\nallow_experimental=false\n\n[packages.demo]\nlanguage_tier=\"experimental\"\nallow_experimental=true\n",
    )
    .expect("workspace policy should be written");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let v = try risky() catch 0\n    return v\n}\nfn risky() -> i32 { return 1 }\n",
    )
    .expect("source should be written");

    let output = verify_file(&root).expect("verify should run");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|d| d.message.contains("experimental language semantics")));
    let _ = std::fs::remove_dir_all(root);
}
