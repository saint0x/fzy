use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use diagnostics::Severity;

use super::native_runtime_support::{render_native_runtime_shim, NativeAsyncExport};
use super::{
    collect_async_c_exports, compile_file, compile_file_with_backend, compile_library_with_backend,
    derive_anchors_from_message, emit_ir, lower_backend_ir, lower_llvm_ir, native_mangle_symbol,
    native_runtime_import_contract_errors, native_runtime_import_for_callee, parse_program,
    refresh_lockfile, verify_file, verify_file_with_root_source, BackendKind, BuildProfile,
};

fn run_native_exit(exe: &Path) -> i32 {
    Command::new(exe)
        .status()
        .expect("native artifact should execute")
        .code()
        .expect("native artifact should exit with code")
}

fn run_native_status(exe: &Path) -> std::process::ExitStatus {
    Command::new(exe)
        .status()
        .expect("native artifact should execute")
}

fn run_native_output(exe: &Path) -> std::process::Output {
    Command::new(exe)
        .output()
        .expect("native artifact should execute")
}

fn nm_symbols(path: &Path) -> Vec<String> {
    let nm = Command::new("nm")
        .arg(path)
        .output()
        .expect("nm should be available");
    assert!(
        nm.status.success(),
        "nm should succeed for {}",
        path.display()
    );
    String::from_utf8_lossy(&nm.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[test]
fn compile_file_runs_pipeline() {
    let file_name = format!(
        "fozzylang-pipeline-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should compile");
    assert_eq!(artifact.module, path.file_stem().unwrap().to_string_lossy());
    assert_eq!(artifact.status, "ok");
    assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

    let _ = std::fs::remove_file(path);
}

#[test]
fn compile_file_emits_memory_async_rpc_and_unsafe_reports() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-safety-artifacts-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"safety_artifacts\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"safety_artifacts\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let p = alloc(16)\n    defer free(p)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");
    for name in [
        "memory-report.json",
        "memory-report.md",
        "unsafe-report.json",
        "async-safety.json",
        "rpc-safety.json",
        "ffi-report.json",
        "ffi-report.md",
        "native-runtime-contracts.json",
    ] {
        assert!(
            root.join(".fz").join(name).exists(),
            "expected safety artifact {name}"
        );
    }

    let memory_report = std::fs::read_to_string(root.join(".fz/memory-report.json"))
        .expect("memory report should exist");
    assert!(memory_report.contains("\"owners\""));
    assert!(memory_report.contains("\"violations\""));
    assert!(memory_report.contains("\"versions\""));

    let runtime_contracts = std::fs::read_to_string(root.join(".fz/native-runtime-contracts.json"))
        .expect("native runtime contracts should exist");
    assert!(runtime_contracts.contains("\"requiredCapability\""));
    assert!(runtime_contracts.contains("\"blockingBehavior\""));
    assert!(runtime_contracts.contains("\"callee\": \"join\""));
    assert!(runtime_contracts.contains("\"callee\": \"task_result\""));
    assert!(runtime_contracts.contains("\"linearity\": \"consumes_linear_handle\""));
    assert!(runtime_contracts.contains("\"linearity\": \"observes_linear_handle\""));
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
    assert!(rpc_report.contains("\"method\": \"Ping\""));
    assert!(rpc_report.contains("\"policy\": \"explicit\""));
    assert!(rpc_report.contains("\"method\": \"Pong\""));
    assert!(rpc_report.contains("\"policy\": \"missing\""));
    assert!(rpc_report.contains("\"handlerCleanupStatus\": \"requires_explicit_cleanup_contract\""));

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
    assert!(async_report.contains("\"resultReads\": 1"));

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
    assert!(async_report
        .contains("without `task.group_join`, `task.group_join_all`, or `task.group_cancel`"));

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
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-05B8968C"));

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
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-47DDFF6D"));

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
        Some("enforce ownership transfer semantics and ensure every allocation is released")
    );
    assert_eq!(diagnostic.code.as_deref(), Some("E-VER-47DDFF6D"));

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
fn derive_anchors_from_message_extracts_primary_and_related_tokens() {
    let lines = vec![
        "fn main() -> i32 {".to_string(),
        "    let payload = build()".to_string(),
        "    return payload.missing".to_string(),
        "}".to_string(),
    ];
    let anchors =
        derive_anchors_from_message("field access on `payload` has no field `missing`", &lines)
            .expect("anchors should be extracted");
    assert_eq!(anchors.len(), 2);
    assert_eq!(anchors[0].0, "payload");
    assert_eq!(anchors[1].0, "missing");
}

#[test]
fn derive_anchors_from_message_requires_exact_identifier_matches() {
    let lines = vec![
        "fn feature_surface_demo(seed: i32) -> i32 {".to_string(),
        "    let surface: bool = feature_surface_demo(1)".to_string(),
        "}".to_string(),
    ];
    let anchors = derive_anchors_from_message(
        "let binding `surface` type mismatch: expected `bool`, got `i32`",
        &lines,
    )
    .expect("anchors should be extracted");
    assert_eq!(anchors[0].0, "surface");
    assert_eq!(anchors[0].1.start_line, 2);
}

#[test]
fn verify_file_with_root_source_uses_project_graph_for_unsaved_buffers() {
    let project_name = format!(
        "fozzylang-root-override-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/model")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod model;\nfn main() -> i32 {\n    model.preflight();\n    return 0\n}\n",
    )
    .expect("main should be written");
    std::fs::write(
        root.join("src/model/mod.fzy"),
        "fn preflight() -> i32 {\n    return 0\n}\n",
    )
    .expect("model module should be written");

    let override_source =
        "mod model;\nfn main() -> i32 {\n    let surface: bool = 1;\n    model.preflight();\n    return 0\n}\n";
    let output = verify_file_with_root_source(&root, Some(override_source))
        .expect("verify with source override should run");
    assert!(output
        .diagnostic_details
        .iter()
        .any(|diagnostic| diagnostic.message.contains("type-check failed")));
    assert!(
        !output.diagnostic_details.iter().any(|diagnostic| diagnostic
            .message
            .contains("unresolved call target `model.preflight`"))
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_file_rejects_non_fzy_source_files() {
    let path = std::env::temp_dir().join(format!(
        "fozzylang-non-fzy-{}.rs",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::write(&path, "fn main() {}\n").expect("foreign source should be written");

    let error = verify_file(&path).expect_err("non-fzy file should be rejected");
    assert!(
        error
            .to_string()
            .contains("expected a `.fzy` source file or a project directory"),
        "unexpected error: {error}"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_file_resolves_same_module_helpers_inside_nested_object_literals() {
    let project_name = format!(
        "fozzylang-helper-object-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod services;\nfn main() -> i32 {\n    services.security.check();\n    return 0\n}\n",
    )
    .expect("main should be written");
    std::fs::write(root.join("src/services/mod.fzy"), "mod security;\n")
        .expect("services mod should be written");
    std::fs::write(
        root.join("src/services/security.fzy"),
        "fn helper() -> str {\n    return \"ok\"\n}\n\nfn nested() -> str {\n    let payload = json.object(#{\n        \"mode\": json.str(helper()),\n        \"tuple\": json.str(if helper() == \"ok\" { helper() } else { \"no\" }),\n    })\n    return payload\n}\n\npub fn check() -> i32 {\n    if str.len(nested()) > 0 {\n        return 0\n    }\n    return 1\n}\n",
    )
    .expect("security module should be written");

    let output = verify_file(&root).expect("verify should return diagnostics payload");
    assert!(
        !output.diagnostic_details.iter().any(|diagnostic| diagnostic
            .message
            .contains("unresolved call target `helper`")),
        "same-module helper calls inside object literals should be qualified"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_file_accepts_log_import_without_stdlib_leak_diagnostics() {
    let file_name = format!(
        "fozzylang-log-import-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(&path, "use core.log;\nfn main() -> i32 { return 0 }\n")
        .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(
        !output
            .diagnostic_details
            .iter()
            .any(|diagnostic| diagnostic.message.contains("log.request_log")),
        "stdlib log helper should not poison import-only programs"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn compile_project_accepts_cross_module_qualified_enum_values_in_calls() {
    let project_name = format!(
        "fozzylang-cross-module-enum-values-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/model")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod model;\nfn main() -> i32 {\n    let ok_status = model.types.control_status_label(model.types.ControlStatus::ControlOk)\n    let boot_phase = model.types.queue_phase_label(model.types.QueuePhase::QueueBoot)\n    if ok_status == \"ok\" && boot_phase == \"boot\" {\n        return 0\n    }\n    return 17\n}\n",
    )
    .expect("main should be written");
    std::fs::write(root.join("src/model/mod.fzy"), "mod types;\n")
        .expect("model mod should be written");
    std::fs::write(
        root.join("src/model/types.fzy"),
        "pub enum ControlStatus { ControlOk, ControlFail }\npub enum QueuePhase { QueueBoot, QueueDrain }\n\npub fn control_status_label(value: ControlStatus) -> str {\n    match value {\n        ControlStatus::ControlOk => return \"ok\",\n        ControlStatus::ControlFail => return \"fail\",\n        _ => return \"unknown\",\n    }\n}\n\npub fn queue_phase_label(value: QueuePhase) -> str {\n    match value {\n        QueuePhase::QueueBoot => return \"boot\",\n        QueuePhase::QueueDrain => return \"drain\",\n        _ => return \"unknown\",\n    }\n}\n",
    )
    .expect("types module should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    let output = artifact.output.expect("native artifact should exist");
    assert_eq!(run_native_exit(&output), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_preserves_trait_impl_methods_and_generic_bounds() {
    let project_name = format!(
        "fozzylang-trait-generic-qualified-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "trait LangScore { fn score(v: i32) -> i32; }\ntrait LangCode { fn code(v: i32) -> i32; }\nstruct LangProbe { value: i32 }\nimpl LangScore for LangProbe { fn score(v: i32) -> i32 { return v + 1; } }\nimpl LangCode for LangProbe { fn code(v: i32) -> i32 { return v + 2; } }\nfn lang_keep<T: LangScore + LangCode>(v: T) -> T { return v; }\nfn main() -> i32 {\n    let probe = LangProbe { value: 7 };\n    let kept = lang_keep<LangProbe>(probe);\n    discard kept;\n    if LangProbe.score(7) == 8 && LangProbe.code(7) == 9 {\n        return 0;\n    }\n    return 17;\n}\n",
    )
    .expect("main should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    let output = artifact.output.expect("native artifact should exist");
    assert_eq!(run_native_exit(&output), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_preserves_trait_impl_methods_in_nested_modules() {
    let project_name = format!(
        "fozzylang-trait-generic-nested-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/tests")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod tests;\nfn main() -> i32 { return tests.smoke.run(); }\n",
    )
    .expect("main should be written");
    std::fs::write(root.join("src/tests/mod.fzy"), "mod smoke;\n")
        .expect("tests mod should be written");
    std::fs::write(
        root.join("src/tests/smoke.fzy"),
        "trait LangScore { fn score(v: i32) -> i32; }\ntrait LangCode { fn code(v: i32) -> i32; }\nstruct LangProbe { value: i32 }\nimpl LangScore for LangProbe { fn score(v: i32) -> i32 { return v + 1; } }\nimpl LangCode for LangProbe { fn code(v: i32) -> i32 { return v + 2; } }\npub fn lang_keep<T: LangScore + LangCode>(v: T) -> T { return v; }\npub fn run() -> i32 {\n    let probe = LangProbe { value: 7 };\n    let kept = lang_keep<LangProbe>(probe);\n    discard kept;\n    if LangProbe.score(7) == 8 && LangProbe.code(7) == 9 {\n        return 0;\n    }\n    return 17;\n}\n",
    )
    .expect("smoke module should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    let output = artifact.output.expect("native artifact should exist");
    assert_eq!(run_native_exit(&output), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_accepts_core_http_helper_surface() {
    let project_name = format!(
        "fozzylang-core-http-helpers-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nfn main() -> i32 {\n    let payload = http.json_payload_new()\n    discard http.json_payload_set_str(payload, \"message\", \"hi\")\n    discard http.json_payload_set_raw(payload, \"ok\", \"true\")\n    let body = http.json_payload_encode(payload)\n    let event = http.sse_event(\"message_start\", body, 0)\n    if str.len(event.event_type) > 0 && str.len(event.data) > 0 && event.done == 0 {\n        return 0\n    }\n    return 17\n}\n",
    )
    .expect("main should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    let output = artifact.output.expect("native artifact should exist");
    assert_eq!(run_native_exit(&output), 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn parse_diagnostic_context_is_reported_as_notes_not_help() {
    let project_name = format!(
        "fozzylang-parse-note-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/model")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod model;\nfn main() -> i32 { return 0 }\n",
    )
    .expect("main should be written");
    std::fs::write(
        root.join("src/model/mod.fzy"),
        "fn broken( -> i32 {\n    return 0\n}\n",
    )
    .expect("broken module should be written");

    let output = verify_file(&root).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| diagnostic.message.contains("expected parameter name"))
        .expect("parse diagnostic should be present");
    assert!(diagnostic
        .help
        .as_deref()
        .is_some_and(|help| !help.contains("source:") && !help.contains("import chain:")));
    assert!(diagnostic.notes.iter().any(|note| note.contains("source:")));
    assert!(diagnostic
        .notes
        .iter()
        .any(|note| note.contains("import chain:")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn backend_capability_diagnostics_keep_native_domain_codes() {
    let project_name = format!(
        "fozzylang-native-domain-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n[build]\nbackend=\"cranelift\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "pubext async c fn risky() -> i32 { return 0 }\nfn main() -> i32 { return 0 }\n",
    )
    .expect("main should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Verify, Some("cranelift"))
        .expect("compile should succeed with diagnostics");
    let diagnostic = artifact
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("backend `cranelift` does not support async C export")
        })
        .expect("backend diagnostic should be present");
    assert!(diagnostic
        .code
        .as_deref()
        .is_some_and(|code| code.starts_with("E-NAT-")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_surface_executes_on_llvm_backend() {
    let project_name = format!(
        "fozzylang-simd-llvm-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.simd;\n\nfn main() -> i32 {\n    let ints = simd.i32x4_add(simd.i32x4_load([1, 2, 3, 4]), simd.i32x4_splat(2))\n    let uint_source = simd.u32x4_store(simd.u32x4_new(1, 2, 3, 4))\n    let float_source = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let shifted = simd.i32x4_shl(ints, 1)\n    let bounded = simd.i32x4_max(shifted, simd.i32x4_new(7, 1, 11, 1))\n    let lane = 5\n    let shuffled = simd.i32x4_shuffle(ints, shifted, 0, lane, 2, 7)\n    let zip_lo = simd.i32x4_zip_lo(ints, shifted)\n    let zip_hi = simd.i32x4_zip_hi(ints, shifted)\n    let unzipped_left = simd.i32x4_unzip_left(zip_lo, zip_hi)\n    let unzipped_right = simd.i32x4_unzip_right(zip_lo, zip_hi)\n    let mask = simd.i32x4_gt(ints, simd.i32x4_splat(4))\n    let stored_ints = simd.i32x4_store(ints)\n    let picked = simd.i32x4_select(mask, ints, simd.i32x4_splat(0))\n    let sum = simd.i32x4_reduce_add(picked)\n    let signed_sat = simd.i32x4_saturating_add(simd.i32x4_new(2147483640, -2147483640, 100, -100), simd.i32x4_new(20, -20, -250, 250))\n    let signed_sat_back = simd.i32x4_saturating_sub(signed_sat, simd.i32x4_new(100, -100, -100, 100))\n    let bitmask = simd.mask32x4_bitmask(mask)\n    let signed_bits = simd.f32x4_bitcast_i32x4(simd.f32x4_new(1.0, -2.0, 0.0, 4.0))\n    let signed_roundtrip = simd.i32x4_bitcast_f32x4(signed_bits)\n    let alias_roundtrip = simd.i32x4_as_u32x4(simd.u32x4_as_i32x4(simd.u32x4_new(9, 11, 13, 15)))\n    let unsigned_sat = simd.u32x4_saturating_add(simd.i32x4_as_u32x4(simd.i32x4_new(-1, -5, 10, 0)), simd.i32x4_as_u32x4(simd.i32x4_new(1, 10, 20, -1)))\n    let unsigned_sat_back = simd.u32x4_saturating_sub(unsigned_sat, simd.u32x4_new(1, 5, 100, 0))\n    let uints_ok = simd.mask32x4_all(simd.u32x4_eq(simd.u32x4_max(simd.u32x4_shr(simd.u32x4_shl(simd.u32x4_load(uint_source), 2), 1), simd.u32x4_new(0, 4, 0, 8)), simd.u32x4_new(2, 4, 6, 8)))\n    let stored_uints = simd.u32x4_store(alias_roundtrip)\n    let floats = simd.f32x4_min(simd.f32x4_mul(simd.f32x4_splat(1.5), simd.f32x4_load(float_source)), simd.f32x4_max(simd.f32x4_new(1.0, 3.0, 4.0, 5.0), simd.f32x4_new(1.5, 2.5, 4.5, 6.0)))\n    let stored_floats = simd.f32x4_store(floats)\n    let stored_mask = simd.mask32x4_store(mask)\n    let floats_ok = simd.mask32x4_all(simd.f32x4_eq(floats, simd.f32x4_new(1.5, 3.0, 4.5, 6.0)))\n    if simd.mask32x4_any(mask) == false {\n        return 11\n    }\n    if simd.mask32x4_none(mask) == true {\n        return 13\n    }\n    if uints_ok == false {\n        return 17\n    }\n    if floats_ok == false {\n        return 19\n    }\n    if simd.i32x4_lane0(bounded) != 7 {\n        return 21\n    }\n    if simd.i32x4_lane2(ints) != 5 {\n        return 23\n    }\n    if simd.i32x4_lane1(shuffled) != 8 {\n        return 25\n    }\n    if bitmask != 12 {\n        return 27\n    }\n    if sum != 11 {\n        return 29\n    }\n    if simd.i32x4_reduce_min(signed_sat) != simd.i32x4_lane1(signed_sat) {\n        return 30\n    }\n    if simd.i32x4_reduce_max(signed_sat) != simd.i32x4_lane0(signed_sat) {\n        return 31\n    }\n    if simd.i32x4_lane3(zip_hi) != 12 {\n        return 33\n    }\n    if stored_ints[3] != 6 {\n        return 34\n    }\n    if simd.mask32x4_all(simd.i32x4_eq(unzipped_left, ints)) == false {\n        return 35\n    }\n    if simd.mask32x4_all(simd.i32x4_eq(unzipped_right, shifted)) == false {\n        return 37\n    }\n    if stored_mask[0] != false || stored_mask[2] != true {\n        return 38\n    }\n    if simd.mask32x4_all(simd.f32x4_eq(signed_roundtrip, simd.f32x4_new(1.0, -2.0, 0.0, 4.0))) == false {\n        return 39\n    }\n    if simd.mask32x4_all(simd.f32x4_eq(simd.f32x4_load(stored_floats), floats)) == false {\n        return 41\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(alias_roundtrip, simd.u32x4_new(9, 11, 13, 15))) == false {\n        return 43\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(simd.u32x4_load(stored_uints), alias_roundtrip)) == false {\n        return 45\n    }\n    if simd.i32x4_lane2(signed_sat) != -150 || simd.i32x4_lane3(signed_sat) != 150 {\n        return 47\n    }\n    if simd.i32x4_lane0(signed_sat_back) != 2147483547 || simd.i32x4_lane1(signed_sat_back) != -2147483548 {\n        return 49\n    }\n    if simd.i32x4_lane2(signed_sat_back) != -50 || simd.i32x4_lane3(signed_sat_back) != 50 {\n        return 50\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(unsigned_sat, simd.i32x4_as_u32x4(simd.i32x4_new(-1, -1, 30, -1)))) == false {\n        return 51\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(unsigned_sat_back, simd.i32x4_as_u32x4(simd.i32x4_new(-2, -6, 0, -1)))) == false {\n        return 53\n    }\n    if simd.u32x4_reduce_min(alias_roundtrip) != simd.u32x4_lane0(alias_roundtrip) || simd.u32x4_reduce_max(alias_roundtrip) != simd.u32x4_lane3(alias_roundtrip) {\n        return 55\n    }\n    if simd.f32x4_reduce_min(floats) != simd.f32x4_lane0(floats) || simd.f32x4_reduce_max(floats) != simd.f32x4_lane3(floats) {\n        return 57\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(llvm_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_text_block_workloads_execute_on_llvm_backend() {
    let project_name = format!(
        "fozzylang-simd-text-block-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.simd;\n\nfn alpha_mask(block: [u32; 4]) -> mask32x4 {\n    let value = simd.u32x4_load(block)\n    let lower = simd.mask32x4_and(simd.u32x4_ge(value, simd.u32x4_new(97, 97, 97, 97)), simd.u32x4_le(value, simd.u32x4_new(122, 122, 122, 122)))\n    let upper = simd.mask32x4_and(simd.u32x4_ge(value, simd.u32x4_new(65, 65, 65, 65)), simd.u32x4_le(value, simd.u32x4_new(90, 90, 90, 90)))\n    return simd.mask32x4_or(lower, upper)\n}\n\nfn delimiter_bitmask(block: [u32; 4]) -> i32 {\n    let value = simd.u32x4_load(block)\n    let is_space = simd.u32x4_eq(value, simd.u32x4_new(32, 32, 32, 32))\n    let is_comma = simd.u32x4_eq(value, simd.u32x4_new(44, 44, 44, 44))\n    let is_colon = simd.u32x4_eq(value, simd.u32x4_new(58, 58, 58, 58))\n    let is_tab = simd.u32x4_eq(value, simd.u32x4_new(9, 9, 9, 9))\n    let delimiter_mask = simd.mask32x4_or(simd.mask32x4_or(is_space, is_comma), simd.mask32x4_or(is_colon, is_tab))\n    return simd.mask32x4_bitmask(delimiter_mask)\n}\n\nfn equality_bitmask(left: [u32; 4], right: [u32; 4]) -> i32 {\n    return simd.mask32x4_bitmask(simd.u32x4_eq(simd.u32x4_load(left), simd.u32x4_load(right)))\n}\n\nfn main() -> i32 {\n    let block = simd.u32x4_store(simd.u32x4_new(65, 122, 44, 57))\n    let alpha = alpha_mask(block)\n    if simd.mask32x4_bitmask(alpha) != 3 { return 11 }\n    if delimiter_bitmask(block) != 4 { return 13 }\n    let left = simd.u32x4_store(simd.u32x4_new(58, 44, 120, 32))\n    let right = simd.u32x4_store(simd.u32x4_new(58, 10, 120, 95))\n    if equality_bitmask(left, right) != 5 { return 15 }\n    let merged = simd.u32x4_max(simd.u32x4_load(left), simd.u32x4_load(right))\n    if simd.u32x4_reduce_max(merged) != simd.u32x4_lane2(merged) { return 17 }\n    if simd.u32x4_reduce_min(merged) != simd.u32x4_lane1(merged) { return 19 }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(llvm_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn llvm_array_literal_return_values_round_trip_through_named_locals() {
    let project_name = format!(
        "fozzylang-array-return-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn make() -> [i32; 4] {\n    return [1, 2, 3, 4]\n}\n\nfn main() -> i32 {\n    let out = make()\n    return out[2] - 3\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(llvm_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_array_return_values_survive_following_calls() {
    let project_name = format!(
        "fozzylang-array-return-ownership-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn seed() -> [i32; 4] {\n    return [9, 8, 7, 6]\n}\n\nfn id(v: i32) -> i32 {\n    return v\n}\n\nfn main() -> i32 {\n    let values = seed()\n    discard id(41)\n    if values[0] != 9 || values[1] != 8 || values[2] != 7 || values[3] != 6 {\n        return 77\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(cranelift.status, "ok");
    assert_eq!(llvm.status, "ok");

    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_ref()
            .expect("cranelift output should exist"),
    );
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(cranelift_exit, 0);
    assert_eq!(llvm_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_surface_executes_on_cranelift_backend() {
    let project_name = format!(
        "fozzylang-simd-cranelift-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n[build]\nbackend=\"cranelift\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.simd;\nfn main() -> i32 {\n    let ints = simd.i32x4_add(simd.i32x4_new(1, 2, 3, 4), simd.i32x4_splat(1))\n    return simd.i32x4_lane0(ints)\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift SIMD build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("cranelift SIMD artifact output should exist"),
    );
    assert_eq!(exit, 2);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_raw_pointer_memory_executes_on_native_backends() {
    let project_name = format!(
        "fozzylang-simd-ptr-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.simd;\n\nfn plus1(ptr: *mut u8) -> *mut u8 {\n    unsafe {\n        return ptr + 1\n    }\n}\n\nfn aligned_lane0(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_aligned(ptr)\n        return simd.i32x4_lane0(value)\n    }\n}\n\nfn aligned_lane3(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_aligned(ptr)\n        return simd.i32x4_lane3(value)\n    }\n}\n\nfn unaligned_lane0(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_unaligned(ptr)\n        return simd.i32x4_lane0(value)\n    }\n}\n\nfn unaligned_lane3(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_unaligned(ptr)\n        return simd.i32x4_lane3(value)\n    }\n}\n\nfn aligned_mask_bits(ptr: *mut u8) -> i32 {\n    unsafe {\n        return simd.mask32x4_bitmask(simd.mask32x4_load_ptr_aligned(ptr))\n    }\n}\n\nfn unaligned_mask_bits(ptr: *mut u8) -> i32 {\n    unsafe {\n        return simd.mask32x4_bitmask(simd.mask32x4_load_ptr_unaligned(ptr))\n    }\n}\n\nfn main() -> i32 {\n    let p = alloc(32)\n    defer free(p)\n    let r = alloc(32)\n    defer free(r)\n    let m = alloc(16)\n    defer free(m)\n    let n = alloc(16)\n    defer free(n)\n    unsafe {\n        simd.i32x4_store_ptr_aligned(p, simd.i32x4_new(10, 20, 30, 40))\n        simd.i32x4_store_ptr_unaligned(plus1(r), simd.i32x4_new(90, 80, 70, 60))\n        simd.mask32x4_store_ptr_aligned(m, simd.mask32x4_load([true, false, true, false]))\n        simd.mask32x4_store_ptr_unaligned(plus1(n), simd.mask32x4_load([false, true, true, false]))\n    }\n    if aligned_lane0(p) != 10 || aligned_lane3(p) != 40 { return 11 }\n    if unaligned_lane0(plus1(r)) != 90 || unaligned_lane3(plus1(r)) != 60 { return 13 }\n    if aligned_mask_bits(m) != 5 { return 15 }\n    if unaligned_mask_bits(plus1(n)) != 6 { return 17 }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(llvm.status, "ok");
    assert_eq!(cranelift.status, "ok");
    assert_eq!(
        run_native_exit(llvm.output.as_ref().expect("llvm output should exist")),
        0
    );
    assert_eq!(
        run_native_exit(
            cranelift
                .output
                .as_ref()
                .expect("cranelift output should exist")
        ),
        0
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_types_are_rejected_across_abi_boundaries() {
    let file_name = format!(
        "fozzylang-simd-abi-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "pubext c fn expose(v: i32x4) -> i32x4 { return v }\nfn main() -> i32 { return 0 }\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(output.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("SIMD type appears across ABI boundary")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn portable_simd_shuffle_traps_on_out_of_range_lane() {
    let project_name = format!(
        "fozzylang-simd-shuffle-trap-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.simd;\nfn main() -> i32 {\n    let bad = 9\n    let value = simd.i32x4_shuffle(simd.i32x4_new(1, 2, 3, 4), simd.i32x4_splat(0), 0, bad, 2, 3)\n    return simd.i32x4_lane0(value)\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    let llvm_status = run_native_status(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert!(!llvm_status.success());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_directory_uses_manifest_target() {
    let project_name = format!(
        "fozzylang-project-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.module, "main");
    assert_eq!(
        artifact
            .output
            .as_deref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str()),
        Some("demo")
    );
    assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_library_uses_lib_target_when_present() {
    let project_name = format!(
        "fozzylang-project-lib-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_library_with_backend(&root, BuildProfile::Dev, None)
        .expect("library project should compile");
    assert_eq!(artifact.module, "lib");
    assert!(artifact
        .static_lib
        .as_ref()
        .is_some_and(|path| path.exists()));
    assert!(artifact
        .shared_lib
        .as_ref()
        .is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_library_allows_explicit_llvm_backend_override() {
    let project_name = format!(
        "fozzylang-project-lib-llvm-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_library_with_backend(&root, BuildProfile::Release, Some("llvm"))
        .expect("llvm backend override should compile for --lib");
    assert_eq!(artifact.status, "ok");
    assert!(artifact
        .static_lib
        .as_ref()
        .is_some_and(|path| path.exists()));
    assert!(artifact
        .shared_lib
        .as_ref()
        .is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_library_allows_async_c_exports_with_default_release_backend() {
    let project_name = format!(
        "fozzylang-project-lib-async-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "use core.thread;\n#[ffi_panic(abort)]\npubext async c fn flush(code: i32) -> i32 {\n    checkpoint();\n    return code\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_library_with_backend(&root, BuildProfile::Release, None)
        .expect("library project should compile");
    assert_eq!(artifact.status, "ok");
    assert!(artifact
        .static_lib
        .as_ref()
        .is_some_and(|path| path.exists()));
    assert!(artifact
        .shared_lib
        .as_ref()
        .is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn llvm_lowering_declares_extern_c_import_without_defining_stub() {
    let source = "ext c fn c_add(left: i32, right: i32) -> i32;\nfn main() -> i32 {\n    return c_add(1, 2)\n}\n";
    let module = parser::parse(source, "ffi_import").expect("source should parse");
    let typed = hir::lower(&module);
    let fir = fir::build_owned(typed);
    let ir = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
    assert!(ir.contains("declare i32 @c_add(i32, i32)"));
    assert!(!ir.contains("define i32 @c_add("));
}

#[test]
fn llvm_lowering_uses_native_aggregate_handles_for_aggregate_literals() {
    let source = "struct Pair { left: i32, right: i32 }\nenum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let pair = Pair { left: 3, right: 4 }\n    let tagged = Maybe::Some(9)\n    let tupled = (1, 2)\n    discard pair\n    discard tagged\n    discard tupled\n    return 0\n}\n";
    let module = parser::parse(source, "agg_handles").expect("source should parse");
    let typed = hir::lower(&module);
    let fir = fir::build_owned(typed);
    let ir = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
    assert!(ir.contains("declare i64 @fz_native_agg_new(i32, i32)"));
    assert!(ir.contains("call i64 @fz_native_agg_new("));
    assert!(ir.contains("call i32 @fz_native_agg_set_i64("));
}

#[test]
fn llvm_backend_executes_handle_backed_local_destructuring() {
    let project_name = format!(
        "fozzylang-llvm-handle-local-destructure-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn main() -> i32 {\n    let pair = Pair { left: 10, right: 20 }\n    let Pair { left, right } = pair;\n    let tagged = Maybe::Some { value: 5, extra: 7 }\n    match tagged {\n        Maybe::Some { value, extra } => return left + right + value + extra,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(llvm_exit, 42);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cranelift_backend_executes_handle_backed_local_destructuring() {
    let project_name = format!(
        "fozzylang-cranelift-handle-local-destructure-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn main() -> i32 {\n    let pair = Pair { left: 10, right: 20 }\n    let Pair { left, right } = pair;\n    let tagged = Maybe::Some { value: 5, extra: 7 }\n    match tagged {\n        Maybe::Some { value, extra } => return left + right + value + extra,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    assert_eq!(cranelift_exit, 42);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn module_qualified_extern_c_import_uses_link_symbol() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("fozzylang-ext-qual-{suffix}"));
    std::fs::create_dir_all(root.join("services")).expect("project dir should be created");
    let main = root.join("main.fzy");
    std::fs::write(
        &main,
        "mod services;\nfn main() -> i32 {\n    unsafe {\n        return services.kernels.hk_mix32(1, 2)\n    }\n}\n",
    )
    .expect("main should be written");
    std::fs::write(root.join("services/mod.fzy"), "mod kernels;\n").expect("mod should be written");
    std::fs::write(
        root.join("services/kernels.fzy"),
        "ext unsafe c fn hk_mix32(a: i32, b: i32) -> i32;\n",
    )
    .expect("kernels should be written");

    let parsed = parse_program(&main).expect("project should parse");
    let import = parsed
        .module
        .items
        .iter()
        .find_map(|item| match item {
            ast::Item::Function(function)
                if function.name == "services.kernels.hk_mix32" && function.is_extern =>
            {
                Some(function)
            }
            _ => None,
        })
        .expect("qualified extern import should exist");
    assert_eq!(import.link_name.as_deref(), Some("hk_mix32"));

    let typed = hir::lower(&parsed.module);
    let fir = fir::build_owned(typed);
    let ir = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
    assert!(ir.contains("declare i32 @hk_mix32(i32, i32)"));
    assert!(!ir.contains("declare i32 @services.kernels.hk_mix32"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn enum_match_lowers_to_switch_for_eligible_arms() {
    let source = "enum ErrorCode { InvalidInput, NotFound, Conflict, Timeout, Io, Internal }\nfn classify(code: ErrorCode) -> i32 {\n    match code {\n        ErrorCode::Io => return 11,\n        ErrorCode::InvalidInput => return 17,\n        ErrorCode::Timeout => return 23,\n        ErrorCode::Conflict => return 31,\n        _ => return 43,\n    }\n}\nfn main() -> i32 {\n    return classify(ErrorCode::Io)\n}\n";
    let module = parser::parse(source, "match_switch").expect("source should parse");
    let typed = hir::lower(&module);
    let fir = fir::build_owned(typed);
    let llvm = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
    let clif =
        lower_backend_ir(&fir, BackendKind::Cranelift).expect("cranelift lowering should succeed");
    assert!(llvm.contains("switch i32"));
    assert!(clif.contains("switch"));
}

#[test]
fn compile_project_uses_capabilities_from_declared_modules() {
    let project_name = format!(
        "fozzylang-mod-cap-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod infra;\nfn main() -> i32 {\n    let listener = http.bind()\n    defer close(listener)\n    http.listen(listener)\n    return 0\n}\n",
    )
    .expect("main source should be written");
    std::fs::write(root.join("src/infra.fzy"), "use core.http;\n")
        .expect("module source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");
    assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_resolves_use_alias_and_pub_use_reexport_calls() {
    let project_name = format!(
        "fozzylang-import-alias-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod services;\nfn main() -> i32 {\n    return services.invoke()\n}\n",
    )
    .expect("main source should be written");
    std::fs::write(
        root.join("src/services/mod.fzy"),
        "mod auth;\nmod store;\nuse auth::init as auth_init;\npub use store::init;\npub fn invoke() -> i32 {\n    return auth_init() + init()\n}\n",
    )
    .expect("services module should be written");
    std::fs::write(
        root.join("src/services/auth.fzy"),
        "pub fn init() -> i32 {\n    return 2\n}\n",
    )
    .expect("auth module should be written");
    std::fs::write(
        root.join("src/services/store.fzy"),
        "pub fn init() -> i32 {\n    return 3\n}\n",
    )
    .expect("store module should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");
    assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_resolves_pub_use_reexport_calls_across_module_boundary() {
    let project_name = format!(
        "fozzylang-pub-use-cross-module-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/cli")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod cli;\nfn main() -> i32 {\n    return cli.run_chat()\n}\n",
    )
    .expect("main source should be written");
    std::fs::write(
        root.join("src/cli/mod.fzy"),
        "mod commands;\npub use commands::run_chat;\npub fn boot() -> i32 {\n    return 0\n}\n",
    )
    .expect("cli module should be written");
    std::fs::write(
        root.join("src/cli/commands.fzy"),
        "pub fn run_chat() -> i32 {\n    return 11\n}\n",
    )
    .expect("commands module should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");
    assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("artifact output should exist"),
    );
    assert_eq!(exit, 11);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_resolves_cross_module_const_value_paths() {
    let project_name = format!(
        "fozzylang-cross-module-const-values-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/model")).expect("model dir should be created");
    std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod model;\nmod services;\nfn main() -> i32 {\n    return services.run()\n}\n",
    )
    .expect("main source should be written");
    std::fs::write(root.join("src/model/mod.fzy"), "mod types;\n")
        .expect("model mod should be written");
    std::fs::write(
        root.join("src/model/types.fzy"),
        "pub const ANSWER: i32 = 7\npub fn label(v: i32) -> str {\n    if v == ANSWER {\n        return \"ok\"\n    }\n    return \"bad\"\n}\n",
    )
    .expect("model types should be written");
    std::fs::write(
        root.join("src/services/mod.fzy"),
        "pub fn run() -> i32 {\n    let v = model.types.ANSWER\n    if model.types.label(v) == \"ok\" {\n        return 0\n    }\n    return 1\n}\n",
    )
    .expect("services mod should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");
    assert_eq!(
        run_native_exit(
            artifact
                .output
                .as_ref()
                .expect("native artifact should be produced")
        ),
        0
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_file_runs_typed_core_io_metadata_and_tree_ops() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("fozzylang-core-io-fs-{suffix}"));
    let src_dir = root.join("src");
    let nested_dir = src_dir.join("nested");
    std::fs::create_dir_all(&nested_dir).expect("nested directory should be created");
    std::fs::write(src_dir.join("a.txt"), "hello").expect("source file should be written");
    std::fs::write(nested_dir.join("b.txt"), "world").expect("nested file should be written");
    let source = std::env::temp_dir().join(format!("fozzylang-core-io-fs-{suffix}.fzy"));
    let quoted_root = root.to_string_lossy().replace('\"', "\\\"");
    std::fs::write(
        &source,
        format!(
            "use core.io;\nuse core.path;\n\nfn main() -> i32 {{\n    let root = \"{quoted_root}\"\n    let src = path.join(root, \"src\")\n    let copied = path.join(root, \"copied.txt\")\n    let staged = path.join(root, \"staged\")\n    let dist = path.join(root, \"dist\")\n    let file_meta = io.metadata(path.join(src, \"a.txt\"))\n    if file_meta.exists != 1 {{ return 10 }}\n    if file_meta.is_file != 1 {{ return 11 }}\n    if file_meta.size != 5 {{ return 12 }}\n    let entries = io.list_dir_entries(src)\n    if io.dir_len(entries) != 2 {{ return 13 }}\n    if io.dir_name(entries, 0) != \"a.txt\" {{ return 14 }}\n    let nested = io.dir_entry(entries, 1)\n    if nested.name != \"nested\" {{ return 15 }}\n    if nested.is_dir != 1 {{ return 16 }}\n    if io.copy_file(path.join(src, \"a.txt\"), copied) != 0 {{ return 17 }}\n    if io.copy_tree(src, dist) != 0 {{ return 18 }}\n    if io.stage_tree(src, staged) != 0 {{ return 19 }}\n    let dist_nested = io.metadata(path.join(dist, \"nested\"))\n    let staged_nested = io.metadata(path.join(staged, \"nested\"))\n    if dist_nested.is_dir != 1 {{ return 20 }}\n    if staged_nested.is_dir != 1 {{ return 21 }}\n    if io.remove(dist) != 0 {{ return 22 }}\n    if io.exists(dist) != 0 {{ return 23 }}\n    if io.remove(staged) != 0 {{ return 24 }}\n    if io.exists(staged) != 0 {{ return 25 }}\n    return 0\n}}\n"
        ),
    )
    .expect("source should be written");

    let artifact = compile_file(&source, BuildProfile::Dev).expect("pipeline should compile");
    assert_eq!(artifact.status, "ok");
    assert_eq!(
        run_native_exit(
            artifact
                .output
                .as_ref()
                .expect("native artifact should be produced")
        ),
        0
    );

    let _ = std::fs::remove_file(source);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_with_verify_errors_skips_native_output() {
    let file_name = format!(
        "fozzylang-error-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let c = http.connect()\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.output.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn compile_project_fails_for_missing_path_dependency() {
    let project_name = format!(
        "fozzylang-deps-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let error = compile_file(&root, BuildProfile::Dev).expect_err("build should fail");
    assert!(error.to_string().contains("path dependency"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_fails_when_lockfile_drifts() {
    let project_name = format!(
        "fozzylang-lock-drift-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    let dep_dir = root.join("deps/util");
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");
    std::fs::write(
        dep_dir.join("fozzy.toml"),
        "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"util\"\npath=\"src/main.fzy\"\n",
    )
    .expect("dep manifest should be written");
    std::fs::write(
        dep_dir.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("dep source should be written");

    let first = compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
    assert_eq!(first.status, "ok");
    std::fs::write(
        dep_dir.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 1\n}\n",
    )
    .expect("dep source should mutate");
    let artifact = compile_file(&root, BuildProfile::Dev).expect("drift should auto-refresh");
    assert_eq!(artifact.status, "ok");
    let lock_text =
        std::fs::read_to_string(root.join("fozzy.lock")).expect("lockfile should be readable");
    assert!(lock_text.contains("dependencyGraphHash"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn refresh_lockfile_unblocks_drifted_project_build() {
    let project_name = format!(
        "fozzylang-lock-refresh-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    let dep_dir = root.join("deps/util");
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");
    std::fs::write(
        dep_dir.join("fozzy.toml"),
        "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"util\"\npath=\"src/main.fzy\"\n",
    )
    .expect("dep manifest should be written");
    std::fs::write(
        dep_dir.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("dep source should be written");

    compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
    std::fs::write(
        dep_dir.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 2\n}\n",
    )
    .expect("dep source should mutate");
    refresh_lockfile(&root).expect("refresh lockfile should succeed");
    let artifact = compile_file(&root, BuildProfile::Dev).expect("build should recover");
    assert_eq!(artifact.status, "ok");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_library_from_main_source_does_not_export_main_symbol() {
    let source = std::env::temp_dir().join(format!(
        "fozzylang-lib-main-symbol-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::write(
        &source,
        "#[ffi_panic(abort)]\npubext c fn exported() -> i32 {\n    return 7\n}\n\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_library_with_backend(&source, BuildProfile::Dev, None)
        .expect("library build from main source should succeed");
    assert_eq!(artifact.status, "ok");
    let object_path = source
        .parent()
        .expect("temp source should have parent")
        .join(".fz/build")
        .join(format!(
            "{}.ffi.o",
            source
                .file_stem()
                .and_then(|value| value.to_str())
                .expect("source file stem should be valid")
        ));
    assert!(object_path.exists(), "ffi object should exist");
    let nm = Command::new("nm")
        .arg(&object_path)
        .output()
        .expect("nm should be available");
    assert!(nm.status.success(), "nm should succeed");
    let symbols = String::from_utf8_lossy(&nm.stdout);
    assert!(
        !symbols
            .lines()
            .any(|line| line.ends_with(" T _main") || line.ends_with(" T main")),
        "library object should not export main as a global symbol: {symbols}"
    );
    assert!(
        symbols
            .lines()
            .any(|line| line.ends_with(" _exported") || line.ends_with(" exported")),
        "library object should export the pubext symbol: {symbols}"
    );

    let _ = std::fs::remove_file(source);
}

#[test]
fn profile_checks_can_be_disabled() {
    let project_name = format!(
        "fozzylang-profile-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[profiles.dev]\nchecks=false\noptimize=false\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nfn main() -> i32 {\n    let listener = http.bind()\n    return listener\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("build should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.output.is_none());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn profile_checks_false_does_not_suppress_verifier_errors() {
    let project_name = format!(
        "fozzylang-profile-verifier-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[profiles.dev]\nchecks=false\noptimize=false\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "ext c fn c_read(buf_owned: *u8) -> i32;\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("build should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.diagnostic_details.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("must be declared `ext unsafe c fn`")
    }));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_profile_rejects_unsafe_capabilities_even_if_declared() {
    let file_name = format!(
        "fozzylang-safe-profile-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn main() -> i32 {\n    let c = http.connect()\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let artifact = compile_file(&path, BuildProfile::Verify).expect("pipeline should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.output.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn compile_rejects_false_contracts() {
    let file_name = format!(
        "fozzylang-contract-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    requires false\n    ensures false\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
    assert_eq!(artifact.status, "error");
    assert!(artifact.output.is_none());

    let _ = std::fs::remove_file(path);
}

#[test]
fn release_profile_disables_runtime_contract_forcing() {
    let path = std::env::temp_dir().join(format!(
        "fozzylang-release-contract-force-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    requires false\n    return 0\n}\n",
    )
    .expect("source should be written");
    let parsed = parse_program(&path).expect("source should parse");
    let (_typed, fir) = super::lower_fir_cached(&parsed);
    assert!(super::compute_forced_main_return(&fir, true).is_some());
    assert!(super::compute_forced_main_return(&fir, false).is_none());
    let _ = std::fs::remove_file(path);
}

#[test]
fn emit_ir_includes_llvm_and_cranelift_forms() {
    let file_name = format!(
        "fozzylang-ir-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
        .expect("temp source should be written");

    let output = emit_ir(&path).expect("emit ir should run");
    let ir = output.backend_ir.expect("backend ir should be available");
    assert!(ir.contains("backend=llvm"));
    assert!(ir.contains("backend=cranelift"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn namespaced_module_consts_resolve_consistently_across_native_backends() {
    let project_name = format!(
        "fozzylang-namespaced-consts-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/model")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(root.join("src/model/mod.fzy"), "mod types;\n")
        .expect("model mod should be written");
    std::fs::write(
        root.join("src/model/types.fzy"),
        "const PROJECT_KIND_UNKNOWN: i32 = 0\nconst PROJECT_KIND_JUCE: i32 = 1\nconst PROJECT_KIND_CMAKE: i32 = 2\n\nfn project_kind_label(kind: i32) -> str {\n    if kind == PROJECT_KIND_JUCE {\n        return \"juce\"\n    }\n    if kind == PROJECT_KIND_CMAKE {\n        return \"cmake\"\n    }\n    return \"unknown\"\n}\n",
    )
    .expect("types module should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod model;\n\nfn main() -> i32 {\n    let label0 = model.types.project_kind_label(model.types.PROJECT_KIND_UNKNOWN)\n    let label1 = model.types.project_kind_label(model.types.PROJECT_KIND_JUCE)\n    let label2 = model.types.project_kind_label(model.types.PROJECT_KIND_CMAKE)\n    if label0 == \"unknown\" && label1 == \"juce\" && label2 == \"cmake\" {\n        return 0\n    }\n    return 41\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, 0);
    assert_eq!(llvm_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn backend_override_rejects_removed_c_shim() {
    let file_name = format!(
        "fozzylang-backend-removed-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
        .expect("temp source should be written");

    let error = compile_file_with_backend(&path, BuildProfile::Dev, Some("c_shim"))
        .expect_err("removed backend must fail");
    assert!(error.to_string().contains("unknown backend"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn compile_file_cranelift_rejects_async_c_exports_with_guidance() {
    let file_name = format!(
        "fozzylang-backend-risk-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "pubext async c fn serve(req: i32) -> i32 {\n    return req\n}\n\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let artifact = compile_file_with_backend(&path, BuildProfile::Dev, Some("cranelift"))
        .expect("build should return diagnostics");
    assert_eq!(artifact.status, "error");
    assert!(artifact
        .diagnostic_details
        .iter()
        .any(|d| d.message.contains("does not support async C export")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn parse_program_cache_invalidates_on_source_change() {
    let file_name = format!(
        "fozzylang-parse-cache-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
        .expect("temp source should be written");
    let first = parse_program(&path).expect("first parse should succeed");
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    return 17\n}\n\nfn extra() -> i32 {\n    return 1\n}\n",
    )
    .expect("temp source should mutate");
    let second = parse_program(&path).expect("second parse should succeed");
    assert_ne!(first.combined_source, second.combined_source);

    let _ = std::fs::remove_file(path);
}

#[test]
fn native_runtime_import_table_is_boundary_only_and_unique() {
    let errors = native_runtime_import_contract_errors();
    assert!(
        errors.is_empty(),
        "runtime import contract errors: {}",
        errors.join("; ")
    );

    let import = native_runtime_import_for_callee("http.header")
        .expect("http.header runtime import should exist");
    assert_eq!(import.symbol, "fz_native_net_header");
    let outbound = native_runtime_import_for_callee("http.header_set")
        .expect("http.header_set runtime import should exist");
    assert_eq!(outbound.symbol, "fz_native_http_header");
    let stream = native_runtime_import_for_callee("http.request_stream")
        .expect("http.request_stream runtime import should exist");
    assert_eq!(stream.symbol, "fz_native_http_request_stream");
}

#[test]
fn embedded_core_security_module_merges_qualified_helpers() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("fozzylang-core-security-{suffix}.fzy"));
    std::fs::write(
        &path,
        "use core.security;\nfn main() -> i32 {\n    if security.verify_value(\"k\", \"v\", security.sign_value(\"k\", \"v\")) == 1 {\n        return 0\n    }\n    return 13\n}\n",
    )
    .expect("source should be written");

    let parsed = parse_program(&path).expect("security facade should parse");
    let function_names = parsed
        .module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) => Some(function.name.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(function_names
        .iter()
        .any(|name| name == "security.verify_value"));
    assert!(function_names
        .iter()
        .any(|name| name == "security.sign_value"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn embedded_core_security_module_typechecks_urlsafe_and_signing_helpers() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("fozzylang-core-security-typecheck-{suffix}.fzy"));
    std::fs::write(
        &path,
        "use core.security;\nfn main() -> i32 {\n    let url = security.base64_url_encode(\"ok\")\n    let roundtrip = security.base64_url_decode(url)\n    if roundtrip == \"ok\" && security.verify_value(\"k\", \"v\", security.sign_value(\"k\", \"v\")) == 1 {\n        return 0\n    }\n    return 13\n}\n",
    )
    .expect("source should be written");

    let parsed = parse_program(&path).expect("security facade should parse");
    let typed = hir::lower(&parsed.module);
    assert_eq!(
        typed.type_errors, 0,
        "unexpected type errors: {:?}",
        typed.type_error_details
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn native_lowerability_accepts_embedded_core_security_helpers() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("fozzylang-core-security-native-{suffix}.fzy"));
    std::fs::write(
        &path,
        "use core.security;\nfn main() -> i32 {\n    let url = security.base64_url_encode(\"ok\")\n    let roundtrip = security.base64_url_decode(url)\n    if roundtrip == \"ok\" && security.verify_value(\"k\", \"v\", security.sign_value(\"k\", \"v\")) == 1 {\n        return 0\n    }\n    return 13\n}\n",
    )
    .expect("source should be written");

    let parsed = parse_program(&path).expect("security facade should parse");
    let diagnostics = super::native_lowerability_diagnostics(&parsed.module);
    assert!(
        diagnostics.is_empty(),
        "unexpected native diagnostics: {:?}",
        diagnostics
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn native_runtime_shim_exposes_request_response_and_process_result_apis() {
    let shim = render_native_runtime_shim(
        &[
            "GET".to_string(),
            "/healthz".to_string(),
            "{\"ok\":true}".to_string(),
        ],
        &["worker.run".to_string()],
        &[],
    );
    assert!(shim.contains("int32_t fz_native_net_method(int32_t conn_fd)"));
    assert!(shim.contains("int32_t fz_native_net_path(int32_t conn_fd)"));
    assert!(shim.contains("int32_t fz_native_net_body(int32_t conn_fd)"));
    assert!(shim.contains("int32_t fz_native_net_body_json(int32_t conn_fd)"));
    assert!(shim.contains("int32_t fz_native_net_body_bind(int32_t conn_fd)"));
    assert!(shim.contains("int32_t fz_native_net_write_response("));
    assert!(shim.contains("int32_t fz_native_proc_wait(int32_t handle, int32_t timeout_ms)"));
    assert!(shim.contains("int32_t fz_native_proc_stdout(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_proc_stderr(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_proc_exit_code(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_env_get(int32_t key_id)"));
    assert!(shim.contains("int32_t fz_native_str_concat2(int32_t a_id, int32_t b_id)"));
    assert!(shim.contains("int32_t fz_native_str_repeat(int32_t value_id, int32_t count)"));
    assert!(shim.contains("int32_t fz_native_str_contains("));
    assert!(shim.contains("int32_t fz_native_str_visible_len_ansi(int32_t value_id)"));
    assert!(shim.contains("int32_t fz_native_http_header(int32_t key_id, int32_t value_id)"));
    assert!(shim.contains("int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id)"));
    assert!(shim.contains(
        "int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id)"
    ));
    assert!(shim
        .contains("int32_t fz_native_http_post_json_stream(int32_t endpoint_id, int32_t body_id)"));
    assert!(shim.contains(
        "int32_t fz_native_http_request_stream(int32_t method_id, int32_t endpoint_id, int32_t body_id)"
    ));
    assert!(shim.contains("int32_t fz_native_http_stream_read(int32_t handle, int32_t max_bytes)"));
    assert!(shim.contains("int32_t fz_native_http_stream_read_line(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_http_stream_eof(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_http_stream_status(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_http_stream_error(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_http_stream_close(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_http_last_status(void)"));
    assert!(shim.contains("int32_t fz_native_http_last_error(void)"));
    assert!(shim.contains("int32_t fz_native_crypto_random_hex(int32_t len_bytes)"));
    assert!(shim.contains("int32_t fz_native_crypto_random_base64(int32_t len_bytes)"));
    assert!(shim.contains("int32_t fz_native_crypto_sha256(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_crypto_hmac_sha256(int32_t key_id, int32_t data_id)"));
    assert!(shim
        .contains("int32_t fz_native_crypto_constant_time_eq(int32_t left_id, int32_t right_id)"));
    assert!(shim.contains("int32_t fz_native_crypto_base64_encode(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_crypto_base64_decode(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_json_escape(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_json_str(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_json_raw(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_json_from_map(int32_t map_handle)"));
    assert!(shim.contains("int32_t fz_native_json_parse(int32_t json_id)"));
    assert!(shim.contains("int32_t fz_native_json_get(int32_t json_value_handle, int32_t key_id)"));
    assert!(
        shim.contains("int32_t fz_native_json_get_str(int32_t json_value_handle, int32_t key_id)")
    );
    assert!(shim.contains("int32_t fz_native_json_has(int32_t json_value_handle, int32_t key_id)"));
    assert!(
        shim.contains("int32_t fz_native_json_path(int32_t json_value_handle, int32_t path_id)")
    );
    assert!(shim.contains("posix_spawnp"));
    assert!(shim.contains("int32_t fz_native_proc_spawnl("));
    assert!(shim.contains("int32_t fz_native_proc_runl("));
    assert!(shim.contains("int32_t fz_native_proc_poll(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_proc_read_stdout(int32_t handle, int32_t max_bytes)"));
    assert!(shim.contains("int32_t fz_native_proc_argv_count(void)"));
    assert!(shim.contains("int32_t fz_native_proc_argv_get(int32_t index)"));
    assert!(shim.contains("int32_t fz_native_term_read_line(void)"));
    assert!(shim.contains("int32_t fz_native_term_stdin_eof(void)"));
    assert!(shim.contains("int32_t fz_native_term_write(int32_t text_id)"));
    assert!(shim.contains("int32_t fz_native_term_write_err(int32_t text_id)"));
    assert!(shim.contains("int32_t fz_native_term_stdin_is_tty(void)"));
    assert!(shim.contains("int32_t fz_native_term_stdout_is_tty(void)"));
    assert!(shim.contains("int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id)"));
    assert!(shim.contains(
        "int32_t fz_native_route_match(int32_t conn_fd, int32_t method_id, int32_t pattern_id)"
    ));
    assert!(shim.contains("int32_t fz_native_fs_read_file(int32_t path_id)"));
    assert!(shim.contains("int32_t fz_native_fs_is_file(int32_t path_id)"));
    assert!(shim.contains("int32_t fz_native_fs_is_dir(int32_t path_id)"));
    assert!(shim.contains("int32_t fz_native_fs_is_symlink(int32_t path_id)"));
    assert!(shim.contains("int32_t fz_native_fs_stat_mtime(int32_t path_id)"));
    assert!(shim.contains("int32_t fz_native_fs_copy_file(int32_t src_id, int32_t dst_id)"));
    assert!(shim.contains("int32_t fz_native_fs_copy_tree(int32_t src_id, int32_t dst_id)"));
    assert!(shim.contains("int32_t fz_native_fs_remove(int32_t path_id)"));
    assert!(shim.contains("qsort(list->items"));
    assert!(shim.contains("int32_t fz_native_time_tick(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_error_code(void)"));
    assert!(shim.contains("int32_t fz_native_log_info(int32_t message_id, int32_t fields_id)"));
    assert!(shim.contains("int32_t fz_native_log_fields_map(int32_t map_handle)"));
    assert!(shim.contains("int32_t fz_native_log_set_enabled(int32_t enabled)"));
    assert!(shim.contains("int32_t fz_native_log_set_level(int32_t level_id)"));
    assert!(shim.contains("int32_t fz_native_log_set_sink(int32_t sink_id)"));
    assert!(shim.contains("FD_CLOEXEC"));
    assert!(shim.contains("int32_t fz_native_proc_exit_class(void)"));
    assert!(shim.contains("int32_t fz_native_time_now(void)"));
    assert!(shim.contains("int32_t fz_native_fs_open(void)"));
    assert!(shim.contains("int32_t fz_native_pulse(void)"));
    assert!(shim.contains("static const int fz_task_entry_count = 1;"));
    assert!(shim.contains("fz_spawn_thread_main"));
}

#[test]
fn cross_backend_crypto_runtime_and_security_facade_execute_consistently() {
    let project_name = format!(
        "fozzylang-crypto-security-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.crypto;\nuse core.security;\n\nfn main() -> i32 {\n    let digest = crypto.sha256(\"abc\")\n    let mac = crypto.hmac_sha256(\"key\", \"The quick brown fox jumps over the lazy dog\")\n    let encoded = crypto.base64_encode(\"fozzy\")\n    let decoded = crypto.base64_decode(encoded)\n    let url = security.base64_url_encode(\"ok\")\n    let roundtrip = security.base64_url_decode(url)\n    let hex_token = crypto.random_hex(16)\n    let b64_token = crypto.random_base64(16)\n    if digest != \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\" { return 11 }\n    if mac != \"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8\" { return 13 }\n    if encoded != \"Zm96enk=\" || decoded != \"fozzy\" { return 17 }\n    if url != \"b2s\" || roundtrip != \"ok\" { return 19 }\n    if str.len(hex_token) != 32 || str.len(b64_token) != 24 { return 23 }\n    if crypto.constant_time_eq(digest, digest) != 1 { return 29 }\n    if crypto.constant_time_eq(digest, mac) != 0 { return 31 }\n    if security.verify_value(\"key\", \"The quick brown fox jumps over the lazy dog\", mac) != 1 { return 37 }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn native_runtime_shim_does_not_use_env_response_templates() {
    let shim = render_native_runtime_shim(&[], &[], &[]);
    assert!(!shim.contains("FZ_NET_WRITE_JSON_BODY"));
    assert!(!shim.contains("FZ_NET_WRITE_BODY"));
    assert!(!shim.contains("fz_env_or_default"));
}

#[test]
fn native_runtime_shim_emits_async_export_handle_wrappers() {
    let shim = render_native_runtime_shim(
        &[],
        &[],
        &[NativeAsyncExport {
            name: "flush".to_string(),
            mangled_symbol: "flush".to_string(),
            params: vec![("int32_t".to_string(), "code".to_string())],
        }],
    );
    assert!(shim.contains("extern int32_t flush(int32_t code);"));
    assert!(shim.contains("int32_t flush_async_start(int32_t code, fz_async_handle_t* handle_out)"));
    assert!(shim.contains("int32_t flush_async_poll(fz_async_handle_t handle, int32_t* done_out)"));
    assert!(
        shim.contains("int32_t flush_async_await(fz_async_handle_t handle, int32_t* result_out)")
    );
    assert!(shim.contains("int32_t flush_async_drop(fz_async_handle_t handle)"));
}

#[test]
fn native_mangle_symbol_rewrites_dots_for_c_identifiers() {
    assert_eq!(
        native_mangle_symbol("api.ffi.fz_bench_async"),
        "api_ffi_fz_bench_async"
    );
}

#[test]
fn async_c_exports_use_sanitized_link_symbols_not_qualified_module_paths() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("fozzylang-async-export-{suffix}"));
    std::fs::create_dir_all(root.join("api")).expect("project dir should be created");
    let main = root.join("main.fzy");
    std::fs::write(&main, "mod api;\nfn main() -> i32 {\n    return 0\n}\n")
        .expect("main should be written");
    std::fs::write(root.join("api/mod.fzy"), "mod ffi;\n").expect("mod should be written");
    std::fs::write(
        root.join("api/ffi.fzy"),
        "pubext async c fn fz_bench_async(seed: i32) -> i32 {\n    return seed\n}\n",
    )
    .expect("ffi should be written");

    let parsed = parse_program(&main).expect("project should parse");
    let typed = hir::lower(&parsed.module);
    let fir = fir::build_owned(typed);
    let exports = collect_async_c_exports(&fir);
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].name, "fz_bench_async");
    assert_eq!(exports[0].mangled_symbol, "fz_bench_async");

    let shim = render_native_runtime_shim(&[], &[], &exports);
    assert!(shim.contains("extern int32_t fz_bench_async(int32_t seed);"));
    assert!(!shim.contains("extern int32_t api.ffi.fz_bench_async"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn native_runtime_shim_uses_documented_bind_defaults_and_visibility() {
    let shim = render_native_runtime_shim(&[], &[], &[]);
    assert!(shim.contains("int port = 8787;"));
    assert!(shim.contains("[fz-runtime] listen active addr=%s port=%d"));
    assert!(shim.contains("host_source=%s port_source=%s"));
}

#[test]
fn native_runtime_shim_sanitizes_invalid_json_http_bodies() {
    let shim = render_native_runtime_shim(&[], &[], &[]);
    assert!(shim.contains("invalid_json_payload"));
    assert!(shim.contains("http.write_json sanitized non-JSON body"));
}

#[test]
fn native_runtime_shim_bootstraps_dotenv_for_env_and_http() {
    let shim = render_native_runtime_shim(&[], &[], &[]);
    assert!(shim.contains("FZ_DOTENV_PATH"));
    assert!(shim.contains("fz_http_header_upsert"));
    assert!(shim.contains("content-type"));
    assert!(shim.contains("--connect-timeout"));
    assert!(shim.contains("--max-time"));
    assert!(shim.contains("unable to exec curl"));
}

#[test]
fn native_runtime_shim_declares_shared_helpers_before_first_use() {
    let shim = render_native_runtime_shim(&[], &[], &[]);

    let bytes_init_decl = shim
        .find("static void fz_bytes_buf_init(fz_bytes_buf* buf);")
        .expect("bytes init prototype should be emitted");
    let bytes_free_decl = shim
        .find("static void fz_bytes_buf_free(fz_bytes_buf* buf);")
        .expect("bytes free prototype should be emitted");
    let bytes_append_decl = shim
        .find("static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len);")
        .expect("bytes append prototype should be emitted");
    let wait_decl = shim
        .find("static int fz_wait_for_fd_event(int fd, short events, int timeout_ms);")
        .expect("wait helper prototype should be emitted");
    let bytes_init_def = shim
        .find("static void fz_bytes_buf_init(fz_bytes_buf* buf) {")
        .expect("bytes init definition should be emitted");
    let bytes_free_def = shim
        .find("static void fz_bytes_buf_free(fz_bytes_buf* buf) {")
        .expect("bytes free definition should be emitted");
    let bytes_append_def = shim
        .find("static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len) {")
        .expect("bytes append definition should be emitted");
    let wait_def = shim
        .find("static int fz_wait_for_fd_event(int fd, short events, int timeout_ms) {")
        .expect("wait helper definition should be emitted");

    assert!(bytes_init_decl < bytes_init_def);
    assert!(bytes_free_decl < bytes_free_def);
    assert!(bytes_append_decl < bytes_append_def);
    assert!(wait_decl < wait_def);
}

#[test]
fn backend_defaults_dev_cranelift_release_llvm() {
    let project_name = format!(
        "fozzylang-backend-defaults-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let dev = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("dev build should succeed");
    assert_eq!(dev.status, "ok");
    assert!(root.join(".fz/build/demo.o").exists());
    assert_eq!(
        dev.output
            .as_deref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str()),
        Some("demo")
    );

    let release = compile_file_with_backend(&root, BuildProfile::Release, None)
        .expect("release build should succeed");
    assert_eq!(release.status, "ok");
    assert!(root.join(".fz/build/demo.ll").exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_accepts_runtime_and_dotted_native_calls() {
    let file_name = format!(
        "fozzylang-native-supported-runtime-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn main() -> i32 {\n    let listener = http.bind()\n    http.listen(listener)\n    http.poll_register(listener)\n    discard http.poll_next()\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| diag
        .message
        .contains("native backend cannot execute unresolved call")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn cross_backend_non_i32_and_aggregate_signatures_execute_consistently() {
    let project_name = format!(
        "fozzylang-non-i32-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "#[repr(C)]\nstruct Pair { lo: i32, hi: i32 }\nfn id64(v: i64) -> i64 {\n    return v\n}\nfn gate(flag: bool) -> bool {\n    return flag\n}\nfn make_pair() -> Pair {\n    let p: Pair = Pair { lo: 1, hi: 2 }\n    return p\n}\nfn main() -> i64 {\n    let p: Pair = make_pair()\n    discard p\n    if gate(true) then return id64(3000000000)\n    return id64(3000000000)\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_primitive_control_flow_and_operator_fixture_execute_consistently() {
    let project_name = format!(
        "fozzylang-primitive-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    let fixture = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/primitive_parity/main.fzy"),
    )
    .expect("primitive parity fixture should be readable");
    std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_native_completeness_fixture_execute_consistently() {
    let project_name = format!(
        "fozzylang-native-completeness-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    let fixture = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/native_completeness/main.fzy"),
    )
    .expect("native completeness fixture should be readable");
    std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 25);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_const_static_globals_execute_consistently() {
    let project_name = format!(
        "fozzylang-const-static-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "const MAGIC: i32 = 7;\nstatic LIMIT: i32 = MAGIC + 3;\nfn main() -> i32 {\n    return MAGIC + LIMIT\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 17);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_static_mut_globals_execute_consistently() {
    let project_name = format!(
        "fozzylang-static-mut-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "static mut COUNTER: i32 = 2;\nfn bump() -> i32 {\n    COUNTER += 3;\n    return COUNTER\n}\nfn main() -> i32 {\n    let first = bump()\n    let second = bump()\n    return first + second\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 13);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_float_execution_is_consistent() {
    let project_name = format!(
        "fozzylang-float-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn score(base: f64, bonus: f64) -> f64 {\n    return (base + bonus) / 2.0\n}\nfn main() -> i32 {\n    let blended: f64 = score(5.0, 1.0)\n    if blended >= 3.0 && blended < 4.0 {\n        return 17\n    }\n    return 9\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 17);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_non_finite_float_results_trap() {
    let project_name = format!(
        "fozzylang-float-nonfinite-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let boom: f64 = 1.0 / 0.0\n    return if boom > 0.0 { 1 } else { 0 }\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");

    let cranelift_status = run_native_status(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_status = run_native_status(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );

    assert!(!cranelift_status.success());
    assert!(!llvm_status.success());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn non_entry_infinite_loop_function_fixture_stays_non_regressing() {
    let project_name = format!(
        "fozzylang-spin-fixture-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    let fixture = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/control_flow_spin/main.fzy"),
    )
    .expect("spin fixture should be readable");
    std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 7);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn live_server_main_check_path_terminates_without_const_eval_hang() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frameworklib/fzweb/src");
    let source = root.join("live_server_main.fzy");
    let parsed = parse_program(&source).expect("live_server_main should parse");
    let typed = hir::lower(&parsed.module);
    assert_eq!(
        typed.entry_return_const_i32, None,
        "long-lived live server entrypoint should not be eagerly const-evaluated"
    );
    let fir = fir::build_owned(typed);
    assert!(fir.nodes > 0, "live_server_main should lower to FIR");
    let report = verify_file(&source).expect("live_server_main verify should return");
    assert_eq!(
        report.diagnostics, 0,
        "expected clean diagnostics for live_server_main"
    );
}

#[test]
fn verify_reports_unsupported_native_signature_types() {
    let file_name = format!(
        "fozzylang-native-signature-unsupported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn helper(flag: bool) -> i32 {\n    if flag {\n        return 1\n    }\n    return 0\n}\nfn main() -> i32 {\n    return helper(true)\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("native backend does not support parameter type")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn cross_backend_closure_capture_executes_consistently() {
    let project_name = format!(
        "fozzylang-closure-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let base: i32 = 9\n    let add = |x: i32| x + base;\n    return add(8)\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 17);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_let_pattern_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-let-pattern-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let Maybe::Some(v) = Maybe::Some(41);\n    return v + 1\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 42);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_struct_pattern_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-struct-pattern-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nfn main() -> i32 {\n    let Pair { left, right: r } = Pair { left: 12, right: 30 };\n    match Pair { left: left, right: r } {\n        Pair { left: a, right: b } => return a + b,\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 42);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_tuple_pattern_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-tuple-pattern-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let source = (7, (9, 11));\n    let (left, (right, _)) = source;\n    return left + right\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 16);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_helper_returned_pattern_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-helper-pattern-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn make_pair(seed: i32) -> Pair {\n    return Pair { left: seed + 2, right: seed + 3 }\n}\nfn make_tuple(seed: i32) -> (i32, i32) {\n    return (seed, seed + 5)\n}\nfn make_variant(seed: i32) -> Maybe {\n    return Maybe::Some { value: seed + 7, extra: seed + 11 }\n}\nfn main() -> i32 {\n    let Pair { left, right } = make_pair(10);\n    let (tuple_left, tuple_right) = make_tuple(4);\n    match make_variant(1) {\n        Maybe::Some { value, extra } => return left + right + tuple_left + tuple_right + value + extra,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 58);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_control_flow_returned_pattern_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-control-flow-pattern-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn choose_pair(flag: bool) -> Pair {\n    return if flag { Pair { left: 5, right: 7 } } else { Pair { left: 1, right: 2 } }\n}\nfn choose_tuple(flag: bool) -> (i32, i32) {\n    return match flag {\n        true => (11, 13),\n        _ => (0, 0),\n    }\n}\nfn choose_variant(flag: bool) -> Maybe {\n    return if flag { Maybe::Some { value: 17, extra: 19 } } else { Maybe::None }\n}\nfn main() -> i32 {\n    let Pair { left, right } = choose_pair(true);\n    let (tuple_left, tuple_right) = choose_tuple(true);\n    match choose_variant(true) {\n        Maybe::Some { value, extra } => return left + right + tuple_left + tuple_right + value + extra,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 72);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_multistmt_helper_pattern_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-multistmt-helper-pattern-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn build_pair(seed: i32) -> Pair {\n    let left = seed + 2\n    let right = left + 3\n    return Pair { left: left, right: right }\n}\nfn build_tuple(seed: i32) -> (i32, i32) {\n    let base = seed + 4\n    let tail = base + 5\n    return (base, tail)\n}\nfn build_variant(seed: i32) -> Maybe {\n    let value = seed + 6\n    let extra = value + 7\n    return Maybe::Some { value: value, extra: extra }\n}\nfn main() -> i32 {\n    let Pair { left, right } = build_pair(1);\n    let (tuple_left, tuple_right) = build_tuple(2);\n    match build_variant(3) {\n        Maybe::Some { value, extra } => return left + right + tuple_left + tuple_right + value + extra,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 51);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_call_returned_aggregate_binding_executes_consistently() {
    let project_name = format!(
        "fozzylang-call-returned-aggregate-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some(i32), None }\nfn pair_id(v: Pair) -> Pair { return v }\nfn tuple_id(v: (i32, i32)) -> (i32, i32) { return v }\nfn maybe_id(v: Maybe) -> Maybe { return v }\nfn main() -> i32 {\n    let pair_source = pair_id(Pair { left: 7, right: 8 })\n    let Pair { left, right } = pair_source;\n    let tuple_source = tuple_id((3, 4))\n    let (a, b) = tuple_source;\n    let maybe_source = maybe_id(Maybe::Some(9))\n    let Maybe::Some(v) = maybe_source;\n    return left + right + a + b + v\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 31);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_parameter_aggregate_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-parameter-aggregate-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn sum_pair(pair: Pair) -> i32 {\n    let Pair { left, right } = pair;\n    return left + right\n}\nfn sum_tuple(pair: (i32, i32)) -> i32 {\n    let (left, right) = pair;\n    return left + right\n}\nfn sum_maybe(maybe: Maybe) -> i32 {\n    match maybe {\n        Maybe::Some { value, extra } => return value + extra,\n        _ => return 0,\n    }\n}\nfn main() -> i32 {\n    return sum_pair(Pair { left: 7, right: 8 }) + sum_tuple((3, 4)) + sum_maybe(Maybe::Some { value: 5, extra: 9 })\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 36);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_named_variant_pattern_destructuring_executes_consistently() {
    let project_name = format!(
        "fozzylang-variant-named-pattern-native-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "enum Token { Number { whole: i32, frac: i32 }, End }\nfn main() -> i32 {\n    let source = Token::Number { whole: 12, frac: 30 };\n    let Token::Number { whole, frac } = source;\n    match source {\n        Token::Number { whole: a, frac: b } => return a + b,\n        _ => return whole + frac,\n    }\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 42);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_accepts_native_let_pattern_lowering() {
    let file_name = format!(
        "fozzylang-native-let-pattern-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let Maybe::Some(v) = Maybe::Some(7);\n    return v\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("pattern destructuring in `let` statements")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_closure_lowering() {
    let file_name = format!(
        "fozzylang-native-closure-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let add1 = |x: i32| x + 1;\n    return add1(3)\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diag| { diag.message.contains("closure/lambda expressions") }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_non_let_closure_usage_reports_unresolved_callable() {
    let file_name = format!(
        "fozzylang-native-closure-non-let-unsupported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn takes(cb: fn(i32) -> i32) -> i32 {\n    return cb(2)\n}\nfn main() -> i32 {\n    return takes(|x: i32| x + 1)\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("native backend cannot execute unresolved call `cb`")
    }));
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains(
            "native backend only supports closures bound to local names via `let`/assignment",
        )
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_assigned_closure_usage() {
    let file_name = format!(
        "fozzylang-native-closure-assigned-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let mut cb = |x: i32| x + 1;\n    cb = |x: i32| x + 2;\n    return cb(3)\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains(
            "native backend only supports closures bound to local names via `let`/assignment",
        )
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_let_pattern_variant_binding_source() {
    let file_name = format!(
        "fozzylang-native-let-pattern-source-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), None }\nfn id(v: Maybe) -> Maybe { return v }\nfn main() -> i32 {\n    let source = id(Maybe::Some(7))\n    let Maybe::Some(v) = source;\n    return v\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("supports `let` variant payload binding only when the initializer is the same literal enum variant")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_match_variant_payload_bindings() {
    let file_name = format!(
        "fozzylang-native-match-pattern-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Some(9)\n    match source {\n        Maybe::Some(v) => return v,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("only supports match-arm variant payload bindings for literal enum scrutinees without guards")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_let_pattern_struct_binding_source() {
    let file_name = format!(
        "fozzylang-native-let-struct-pattern-source-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Pair { left: i32, right: i32 }\nfn make(v: i32) -> Pair { return Pair { left: v, right: 1 } }\nfn main() -> i32 {\n    let source = make(7)\n    let Pair { left, right: r } = source;\n    return left + r\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains(
            "supports `let` struct-field binding only when the initializer is the same literal struct value",
        )
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_let_pattern_tuple_binding_source() {
    let file_name = format!(
        "fozzylang-native-let-tuple-pattern-source-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn make(v: i32) -> (i32, i32) { return (v, v + 1) }\nfn main() -> i32 {\n    let source = make(7)\n    let (left, right) = source;\n    return left + right\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains(
            "requires tuple initializer or tuple-bound local for `let` tuple destructuring",
        )
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_control_flow_pattern_binding_sources() {
    let file_name = format!(
        "fozzylang-native-control-flow-pattern-source-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn pair(flag: bool) -> Pair {\n    return if flag { Pair { left: 3, right: 4 } } else { Pair { left: 0, right: 0 } }\n}\nfn tuple(flag: bool) -> (i32, i32) {\n    return match flag {\n        true => (5, 6),\n        _ => (0, 0),\n    }\n}\nfn tagged(flag: bool) -> Maybe {\n    return if flag { Maybe::Some { value: 7, extra: 8 } } else { Maybe::None }\n}\nfn main() -> i32 {\n    let Pair { left, right } = pair(true);\n    let (a, b) = tuple(true);\n    match tagged(true) {\n        Maybe::Some { value, extra } => return left + right + a + b + value + extra,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains("literal enum scrutinee")
            || diag.message.contains("literal struct scrutinee")
            || diag.message.contains("literal tuple scrutinee")
            || diag
                .message
                .contains("tuple initializer or tuple-bound local")
            || diag
                .message
                .contains("struct initializer or struct-bound local")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_multistmt_helper_pattern_binding_sources() {
    let file_name = format!(
        "fozzylang-native-multistmt-helper-pattern-source-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Pair { left: i32, right: i32 }\nenum Maybe { Some { value: i32, extra: i32 }, None }\nfn pair(seed: i32) -> Pair {\n    let left = seed + 1\n    let right = left + 2\n    return Pair { left: left, right: right }\n}\nfn tuple(seed: i32) -> (i32, i32) {\n    let a = seed + 3\n    let b = a + 4\n    return (a, b)\n}\nfn tagged(seed: i32) -> Maybe {\n    let value = seed + 5\n    let extra = value + 6\n    return Maybe::Some { value: value, extra: extra }\n}\nfn main() -> i32 {\n    let Pair { left, right } = pair(1);\n    let (a, b) = tuple(2);\n    match tagged(3) {\n        Maybe::Some { value, extra } => return left + right + a + b + value + extra,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message.contains("literal enum scrutinee")
            || diag.message.contains("literal struct scrutinee")
            || diag
                .message
                .contains("tuple initializer or tuple-bound local")
            || diag
                .message
                .contains("struct initializer or struct-bound local")
            || diag.message.contains("enum-bound local payloads")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_match_struct_payload_bindings() {
    let file_name = format!(
        "fozzylang-native-match-struct-pattern-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Pair { left: i32, right: i32 }\nfn make(v: i32) -> Pair { return Pair { left: v, right: 1 } }\nfn main() -> i32 {\n    let source = make(9)\n    match source {\n        Pair { left, right: r } => return left + r,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("only supports match-arm struct-field bindings for literal struct scrutinees without guards")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_try_catch_expressions() {
    let file_name = format!(
        "fozzylang-native-try-catch-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let x = try fail() catch 7;\n    return x\n}\nfn fail() -> i32 {\n    return 1\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("native backend does not support `try/catch` expressions")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_range_expression_outside_for_in() {
    let file_name = format!(
        "fozzylang-native-range-expr-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let r = 1..4;\n    return r.end - r.start\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("detected parser-recognized expressions without full lowering parity")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_field_access_on_range_literal_expression() {
    let file_name = format!(
        "fozzylang-native-range-literal-field-access-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(&path, "fn main() -> i32 {\n    return (1..4).end\n}\n")
        .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("detected parser-recognized expressions without full lowering parity")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_field_access_on_struct_literal_expression() {
    let file_name = format!(
        "fozzylang-native-struct-literal-field-access-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Pair { left: i32, right: i32 }\nfn main() -> i32 {\n    return Pair { left: 3, right: 9 }.right\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("detected parser-recognized expressions without full lowering parity")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_nested_field_access_on_struct_literal_expression() {
    let file_name = format!(
        "fozzylang-native-nested-struct-literal-field-access-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Inner { value: i32 }\nstruct Outer { inner: Inner }\nfn main() -> i32 {\n    return Outer { inner: Inner { value: 11 } }.inner.value\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("detected parser-recognized expressions without full lowering parity")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_nested_field_access_on_range_literal_expression() {
    let file_name = format!(
        "fozzylang-native-nested-range-field-access-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "struct Wrap { r: Range }\nfn main() -> i32 {\n    return Wrap { r: 2..8 }.r.end\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("detected parser-recognized expressions without full lowering parity")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_array_index_expression_shapes() {
    let file_name = format!(
        "fozzylang-native-array-index-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let values = [3, 5, 8];\n    let idx = 1;\n    return values[idx]\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("detected parser-recognized expressions without full lowering parity")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_match_variant_payload_bindings_for_literal_scrutinee() {
    let file_name = format!(
        "fozzylang-native-match-pattern-literal-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    match Maybe::Some(9) {\n        Maybe::Some(v) => return v,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("only supports match-arm variant payload bindings for literal enum scrutinees without guards")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_match_guard_with_variant_payload_binding() {
    let file_name = format!(
        "fozzylang-native-match-guard-payload-binding-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Some(9)\n    match source {\n        Maybe::Some(v) if v > 7 => return v,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("native backend does not support match guards that depend on payload or struct-field bindings")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_match_or_pattern_with_payload_bindings() {
    let file_name = format!(
        "fozzylang-native-match-or-payload-binding-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), Also(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Also(6)\n    match source {\n        Maybe::Some(v) | Maybe::Also(v) => return v,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("payload or struct-field bindings within or-pattern match arms")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_native_let_or_pattern_with_payload_bindings() {
    let file_name = format!(
        "fozzylang-native-let-or-payload-binding-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), Also(i32), None }\nfn main() -> i32 {\n    let Maybe::Some(v) | Maybe::Also(v) = Maybe::Also(8);\n    return v\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("payload or struct-field bindings in `let` or-patterns")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_rejects_native_or_pattern_mismatched_binding_names() {
    let file_name = format!(
        "fozzylang-native-match-or-payload-binding-mismatch-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum Maybe { Some(i32), Also(i32), None }\nfn main() -> i32 {\n    let source = Maybe::Some(9)\n    match source {\n        Maybe::Some(v) | Maybe::Also(w) => return 1,\n        _ => return 0,\n    }\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("or-pattern alternatives must bind identical names and types")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_dynamic_string_data_plane_calls_on_native_backend() {
    let file_name = format!(
        "fozzylang-native-dynamic-str-data-plane-unsupported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let s = env.get(\"K\")\n    if str.contains(s, \"a\") == 1 {\n        return 1\n    }\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("removed dynamic string data-plane runtime calls")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_foldable_string_data_plane_calls_on_native_backend() {
    let file_name = format!(
        "fozzylang-native-foldable-str-data-plane-supported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let s = \"  ab  \"\n    let t = str.trim(s)\n    if str.contains(str.replace(t, \"a\", \"x\"), \"x\") == 1 {\n        return str.len(str.replace(t, \"a\", \"x\"))\n    }\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("removed dynamic string data-plane runtime calls")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_accepts_list_map_data_plane_calls_on_native_backend() {
    let file_name = format!(
        "fozzylang-native-list-map-data-plane-unsupported-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() -> i32 {\n    let l = list.new()\n    list.push(l, \"x\")\n    return list.len(l)\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| {
        diag.message
            .contains("native backend cannot execute unresolved call")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn parse_program_fails_for_missing_declared_module() {
    let root_name = format!(
        "fozzylang-mod-missing-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(root_name);
    std::fs::create_dir_all(&root).expect("temp dir should be created");
    let path = root.join("main.fzy");
    std::fs::write(&path, "mod util;\nfn main() -> i32 {\n    return 0\n}\n")
        .expect("root source should be written");

    let error = parse_program(&path).expect_err("missing module should fail parsing");
    assert!(error.to_string().contains("resolving module `util`"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn parse_program_detects_cycle() {
    let root_name = format!(
        "fozzylang-mod-cycle-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(root_name);
    std::fs::create_dir_all(&root).expect("temp dir should be created");
    let main = root.join("main.fzy");
    let a = root.join("a.fzy");
    let b = root.join("b.fzy");
    std::fs::write(&main, "mod a;\nfn main() -> i32 {\n return 0\n}\n")
        .expect("main source should be written");
    std::fs::write(&a, "mod b;\n").expect("module a should be written");
    std::fs::write(&b, "mod a;\n").expect("module b should be written");

    let error = parse_program(&main).expect_err("cycle should fail parsing");
    assert!(error.to_string().contains("cyclic module declaration"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn emit_ir_canonicalizes_sibling_module_calls() {
    let project_name = format!(
        "fozzylang-call-canonicalize-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "mod services;\nfn main() -> i32 {\n    services.http.start_server()\n    return 0\n}\n",
    )
    .expect("main source should be written");
    std::fs::write(root.join("src/services/mod.fzy"), "mod web;\nmod http;\n")
        .expect("services mod should be written");
    std::fs::write(
        root.join("src/services/web.fzy"),
        "fn start_listener() -> i32 {\n    return 0\n}\n",
    )
    .expect("web source should be written");
    std::fs::write(
        root.join("src/services/http.fzy"),
        "fn start_server() -> i32 {\n    web.start_listener()\n    return 0\n}\n",
    )
    .expect("http source should be written");

    let output = emit_ir(&root).expect("emit ir should run");
    let ir = output.backend_ir.expect("backend ir should be available");
    assert!(ir.contains("@services_web_start_listener"));
    assert!(!ir.contains("@web_start_listener"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn direct_memory_backend_contract_array_index_lowers_without_data_plane_runtime_calls() {
    let source = "fn main() -> i32 {\n    let values = [3, 5, 8];\n    let idx = 2;\n    return values[idx]\n}\n";
    let module = parser::parse(source, "direct_memory_array").expect("source should parse");
    let typed = hir::lower(&module);
    let fir = fir::build_owned(typed);
    let llvm = lower_backend_ir(&fir, BackendKind::Llvm).expect("llvm lowering should succeed");
    let clif =
        lower_backend_ir(&fir, BackendKind::Cranelift).expect("cranelift lowering should succeed");

    assert!(!llvm.contains("__native.array_"));
    assert!(!llvm.contains("fz_native_list_"));
    assert!(!llvm.contains("fz_native_map_"));
    assert!(!clif.contains("__native.array_"));
    assert!(!clif.contains("fz_native_list_"));
    assert!(!clif.contains("fz_native_map_"));
}

#[test]
fn direct_memory_backend_contract_switch_and_constant_string_chain_lowering_is_parity_safe() {
    let source = "enum ErrorCode { InvalidInput, NotFound, Conflict, Timeout, Io, Internal }\nfn classify(code: ErrorCode) -> i32 {\n    match code {\n        ErrorCode::Io => return 11,\n        ErrorCode::InvalidInput => return 17,\n        ErrorCode::Timeout => return 23,\n        ErrorCode::Conflict => return 31,\n        _ => return 43,\n    }\n}\nfn main() -> i32 {\n    let values = [4, 6, 9]\n    let idx = 1\n    let score = values[idx]\n    if str.contains(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"), \"b\") == 1 {\n        return classify(ErrorCode::Io) + score + str.len(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"))\n    }\n    return 0\n}\n";
    let module = parser::parse(source, "direct_memory_contract").expect("source should parse");
    let typed = hir::lower(&module);
    let fir = fir::build_owned(typed);
    let llvm = lower_backend_ir(&fir, BackendKind::Llvm).expect("llvm lowering should succeed");
    let clif =
        lower_backend_ir(&fir, BackendKind::Cranelift).expect("cranelift lowering should succeed");

    assert!(llvm.contains("switch i32"));
    assert!(clif.contains("switch"));
    assert!(!llvm.contains("declare i32 @fz_native_str_trim("));
    assert!(!llvm.contains("declare i32 @fz_native_str_replace("));
    assert!(!llvm.contains("declare i32 @fz_native_str_contains("));
    assert!(!llvm.contains("declare i32 @fz_native_str_len("));
}

#[test]
fn cross_backend_direct_memory_contract_fixture_executes_consistently() {
    let project_name = format!(
        "fozzylang-direct-memory-contract-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let values = [4, 6, 9]\n    let idx = 1\n    let score = values[idx]\n    if str.contains(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"), \"b\") == 1 {\n        return score + str.len(str.replace(str.trim(\"  xax  \"), \"a\", \"b\"))\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 9);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_direct_memory_folded_temp_string_literal_executes_consistently() {
    let project_name = format!(
        "fozzylang-direct-memory-folded-temp-str-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let base = \"  a  \"\n    let trimmed = str.trim(base)\n    let replaced = str.replace(trimmed, \"a\", \"xy\")\n    return str.len(replaced)\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 2);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_direct_memory_bounds_probe_executes_consistently() {
    let project_name = format!(
        "fozzylang-direct-memory-bounds-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    let fixture = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/direct_memory_safety/main.fzy"),
    )
    .expect("direct memory safety fixture should be readable");
    std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 68);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_direct_memory_i64_array_layout_executes_consistently() {
    let project_name = format!(
        "fozzylang-direct-memory-i64-array-layout-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let values = [3000000000, 4000000000]\n    let picked = values[0]\n    if picked > 2147483648 {\n        return 77\n    }\n    return 33\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 77);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_direct_memory_string_slice_executes_consistently() {
    let project_name = format!(
        "fozzylang-direct-memory-string-slice-layout-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    if str.starts_with(str.slice(\"abcdef\", 1, 4), \"bcd\") == 1 {\n        return str.len(str.slice(\"abcdef\", 1, 4)) + 16\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 19);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_direct_memory_rolling_window_index_executes_consistently() {
    let project_name = format!(
        "fozzylang-direct-memory-rolling-window-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let bytes = [10, 20, 30, 40, 50]\n    let i = 1\n    let a = bytes[i]\n    let b = bytes[i + 1]\n    let c = bytes[i + 2]\n    let d = bytes[i - 1]\n    return a + b + c + d\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 100);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_unsafe_local_function_calls_execute_consistently() {
    let file_name = format!(
        "fozzylang-unsafe-local-backend-parity-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn lang_id(v: i32) -> i32 {\n    return v\n}\nunsafe fn lang_unsafe_id(v: i32) -> i32 {\n    return v\n}\nfn main() -> i32 {\n    let routed = lang_id(7)\n    discard lang_unsafe_id\n    unsafe {\n        discard lang_id(routed)\n    }\n    return routed\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&path, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift should compile unsafe local-call fixture");
    let llvm = compile_file_with_backend(&path, BuildProfile::Dev, Some("llvm"))
        .expect("llvm should compile unsafe local-call fixture");

    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_ref()
            .expect("cranelift output should exist"),
    );
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(cranelift_exit, 7);
    assert_eq!(llvm_exit, 7);

    let _ = std::fs::remove_file(path);
}

#[test]
fn cross_backend_async_term_and_file_artifacts_remain_identical() {
    let project_name = format!(
        "fozzylang-async-term-file-parity-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    let out_path = root.join("parity-output.json");
    let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"backend_parity\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"backend_parity\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        format!(
            "use core.fs;\nuse core.term;\nuse core.thread;\n\nfn worker() -> i32 {{\n    return 5\n}}\n\nfn main() -> i32 {{\n    let handle = spawn(worker)\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    let direct = join(handle)\n    let grouped = task.group_join_all(group)\n    let payload = map.new()\n    discard map.set(payload, \"direct\", json.str(str.from_i32(direct)))\n    discard map.set(payload, \"grouped\", json.str(str.from_i32(grouped)))\n    discard map.set(payload, \"mode\", json.str(\"parity\"))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    discard term.write(\"stdout-parity\\n\")\n    discard term.write_err(\"stderr-parity\\n\")\n    return direct + grouped\n}}\n"
        ),
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");

    let _ = std::fs::remove_file(&out_path);
    let cranelift_output = run_native_output(
        cranelift
            .output
            .as_deref()
            .expect("cranelift output should exist"),
    );
    let cranelift_exit = cranelift_output
        .status
        .code()
        .expect("cranelift output should include exit code");
    let cranelift_stdout =
        String::from_utf8(cranelift_output.stdout).expect("cranelift stdout should be utf-8");
    let cranelift_stderr =
        String::from_utf8(cranelift_output.stderr).expect("cranelift stderr should be utf-8");
    let cranelift_artifact =
        std::fs::read_to_string(&out_path).expect("cranelift artifact should exist");

    let _ = std::fs::remove_file(&out_path);
    let llvm_output = run_native_output(llvm.output.as_deref().expect("llvm output should exist"));
    let llvm_exit = llvm_output
        .status
        .code()
        .expect("llvm output should include exit code");
    let llvm_stdout = String::from_utf8(llvm_output.stdout).expect("llvm stdout should be utf-8");
    let llvm_stderr = String::from_utf8(llvm_output.stderr).expect("llvm stderr should be utf-8");
    let llvm_artifact = std::fs::read_to_string(&out_path).expect("llvm artifact should exist");

    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 10);
    assert_eq!(cranelift_stdout, llvm_stdout);
    assert_eq!(cranelift_stdout, "stdout-parity\n");
    assert_eq!(cranelift_stderr, llvm_stderr);
    assert_eq!(cranelift_stderr, "stderr-parity\n");
    assert_eq!(cranelift_artifact, llvm_artifact);
    assert!(cranelift_artifact.contains("\"direct\":\"5\""));
    assert!(cranelift_artifact.contains("\"grouped\":\"5\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_proc_payload_artifacts_remain_identical() {
    let project_name = format!(
        "fozzylang-proc-payload-parity-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    let out_path = root.join("proc-output.json");
    let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"backend_proc_parity\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"backend_proc_parity\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        format!(
            "use core.fs;\nuse core.proc;\n\nfn main() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"printf left; printf right >&2\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    let wait_status = proc.wait(handle, 1000)\n    let stdout = proc.stdout(handle)\n    let stderr = proc.stderr(handle)\n    discard proc.close(handle)\n    let payload = map.new()\n    discard map.set(payload, \"wait\", json.str(str.from_i32(wait_status)))\n    discard map.set(payload, \"stdout\", json.str(stdout))\n    discard map.set(payload, \"stderr\", json.str(stderr))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    return wait_status\n}}\n"
        ),
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");

    let _ = std::fs::remove_file(&out_path);
    let cranelift_output = run_native_output(
        cranelift
            .output
            .as_deref()
            .expect("cranelift output should exist"),
    );
    let cranelift_exit = cranelift_output
        .status
        .code()
        .expect("cranelift output should include exit code");
    let cranelift_stdout =
        String::from_utf8(cranelift_output.stdout).expect("cranelift stdout should be utf-8");
    let cranelift_stderr =
        String::from_utf8(cranelift_output.stderr).expect("cranelift stderr should be utf-8");
    let cranelift_artifact =
        std::fs::read_to_string(&out_path).expect("cranelift artifact should exist");

    let _ = std::fs::remove_file(&out_path);
    let llvm_output = run_native_output(llvm.output.as_deref().expect("llvm output should exist"));
    let llvm_exit = llvm_output
        .status
        .code()
        .expect("llvm output should include exit code");
    let llvm_stdout = String::from_utf8(llvm_output.stdout).expect("llvm stdout should be utf-8");
    let llvm_stderr = String::from_utf8(llvm_output.stderr).expect("llvm stderr should be utf-8");
    let llvm_artifact = std::fs::read_to_string(&out_path).expect("llvm artifact should exist");

    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 0);
    assert_eq!(cranelift_stdout, llvm_stdout);
    assert!(cranelift_stdout.is_empty());
    assert_eq!(cranelift_stderr, llvm_stderr);
    assert!(cranelift_stderr.is_empty());
    assert_eq!(cranelift_artifact, llvm_artifact);
    assert!(cranelift_artifact.contains("\"wait\":\"0\""));
    assert!(cranelift_artifact.contains("\"stdout\":\"left\""));
    assert!(cranelift_artifact.contains("\"stderr\":\"right\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_library_exports_remain_identical() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root = std::env::temp_dir().join(format!("fozzylang-lib-parity-llvm-{suffix}"));
    let clif_root = std::env::temp_dir().join(format!("fozzylang-lib-parity-clif-{suffix}"));

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"backend_lib_parity\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"backend_lib_parity\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n\n#[ffi_panic(abort)]\npubext c fn mul(left: i32, right: i32) -> i32 {\n    return left * right\n}\n",
        )
        .expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm library build should succeed");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift library build should succeed");

    let llvm_static_symbols = nm_symbols(
        llvm.static_lib
            .as_deref()
            .expect("llvm static lib should exist"),
    );
    let clif_static_symbols = nm_symbols(
        cranelift
            .static_lib
            .as_deref()
            .expect("cranelift static lib should exist"),
    );
    let llvm_shared_symbols = nm_symbols(
        llvm.shared_lib
            .as_deref()
            .expect("llvm shared lib should exist"),
    );
    let clif_shared_symbols = nm_symbols(
        cranelift
            .shared_lib
            .as_deref()
            .expect("cranelift shared lib should exist"),
    );

    for expected in ["add", "mul"] {
        assert!(
            llvm_static_symbols
                .iter()
                .any(|line| line.contains(expected)),
            "llvm static exports should include {expected}"
        );
        assert!(
            clif_static_symbols
                .iter()
                .any(|line| line.contains(expected)),
            "cranelift static exports should include {expected}"
        );
        assert!(
            llvm_shared_symbols
                .iter()
                .any(|line| line.contains(expected)),
            "llvm shared exports should include {expected}"
        );
        assert!(
            clif_shared_symbols
                .iter()
                .any(|line| line.contains(expected)),
            "cranelift shared exports should include {expected}"
        );
    }

    let llvm_public = llvm_shared_symbols
        .iter()
        .filter(|line| {
            line.contains(" add")
                || line.ends_with(" add")
                || line.contains(" mul")
                || line.ends_with(" mul")
        })
        .cloned()
        .collect::<Vec<_>>();
    let clif_public = clif_shared_symbols
        .iter()
        .filter(|line| {
            line.contains(" add")
                || line.ends_with(" add")
                || line.contains(" mul")
                || line.ends_with(" mul")
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(llvm_public.len(), clif_public.len());

    let _ = std::fs::remove_dir_all(llvm_root);
    let _ = std::fs::remove_dir_all(clif_root);
}

#[test]
fn cross_backend_defer_executes_on_safe_scope_return_in_lifo_order() {
    let file_name = format!(
        "fozzylang-defer-safe-scope-lifo-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "static mut TRACE: i32 = 0;\nfn mark(v: i32) -> i32 {\n    TRACE = (TRACE * 10) + v;\n    return 0\n}\nfn scoped() -> i32 {\n    defer mark(1)\n    if true {\n        defer mark(2)\n        return 5\n    }\n    return 0\n}\nfn main() -> i32 {\n    return scoped() + TRACE\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&path, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift should compile safe-scope defer fixture");
    let llvm = compile_file_with_backend(&path, BuildProfile::Dev, Some("llvm"))
        .expect("llvm should compile safe-scope defer fixture");

    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_ref()
            .expect("cranelift output should exist"),
    );
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(cranelift_exit, 26);
    assert_eq!(llvm_exit, 26);

    let _ = std::fs::remove_file(path);
}

#[test]
fn cross_backend_defer_executes_inside_unsafe_block_before_return() {
    let file_name = format!(
        "fozzylang-defer-unsafe-block-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "static mut TRACE: i32 = 0;\nfn mark(v: i32) -> i32 {\n    TRACE = (TRACE * 10) + v;\n    return 0\n}\nfn main() -> i32 {\n    unsafe {\n        defer mark(1)\n        defer mark(2)\n    }\n    return 5 + TRACE\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&path, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift should compile unsafe-block defer fixture");
    let llvm = compile_file_with_backend(&path, BuildProfile::Dev, Some("llvm"))
        .expect("llvm should compile unsafe-block defer fixture");

    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_ref()
            .expect("cranelift output should exist"),
    );
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(cranelift_exit, 26);
    assert_eq!(llvm_exit, 26);

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_non_exhaustive_match_anchors_to_match_site() {
    let file_name = format!(
        "fozzylang-non-exhaustive-match-anchor-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "enum State { Ready, Waiting, Done }\n\nfn main(flag: bool) -> i32 {\n    let current = if flag { State::Ready } else { State::Waiting };\n    match current {\n        State::Ready => return 1,\n        _ if flag => return 2,\n    }\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                .contains("non-exhaustive match for enum `State`")
        })
        .expect("non-exhaustive diagnostic should be present");
    let span = diagnostic
        .span
        .as_ref()
        .expect("non-exhaustive diagnostic should be anchored");
    assert_eq!(span.start_line, 5);
    assert_eq!(diagnostic.snippet.as_deref(), Some("    match current {"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_process_namespace_migration_matches_verifier_guidance() {
    let file_name = format!(
        "fozzylang-process-namespace-guidance-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn main() {\n    discard process.run(\"echo hi\");\n    return;\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                .contains("native backend cannot execute unresolved call `process.run`")
        })
        .expect("native unresolved-call diagnostic should be present");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("migrate to `proc.run`"));
    assert!(!help.contains("proc.stdout"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_thread_boundary_borrowed_return_reports_thread_specific_help() {
    let file_name = format!(
        "fozzylang-thread-boundary-borrowed-return-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "async fn worker(v: &'a i32) -> &'a i32 {\n    return v\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                .contains("returns borrowed reference across thread-capable boundary")
        })
        .expect("thread-boundary borrowed-return diagnostic should be present");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("return owned values or a Send/Sync-safe handle"));
    assert!(!help.contains("capability token parameters"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_thread_boundary_mutable_param_reports_send_sync_wrapper_guidance() {
    let file_name = format!(
        "fozzylang-thread-boundary-mutable-param-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "async fn worker(v: &'a mut i32) -> i32 {\n    discard v\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diag| {
            diag.message
                .contains("requires Send/Sync-safe wrapper before thread crossing")
        })
        .expect("thread-boundary mutable-param diagnostic should be present");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("wrap borrowed references/pointers"));
    assert!(!help.contains("capability token parameters"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_thread_boundary_shared_param_reports_send_sync_wrapper_guidance() {
    let file_name = format!(
        "fozzylang-thread-boundary-shared-param-{}.fzy",
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
        .find(|diag| {
            diag.message
                .contains("parameter `v` requires Send/Sync-safe wrapper before thread crossing")
        })
        .expect("thread-boundary shared-param diagnostic should be present");
    let help = diagnostic.help.as_deref().unwrap_or_default();
    assert!(help.contains("wrap borrowed references/pointers"));
    assert!(!help.contains("capability token parameters"));

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
