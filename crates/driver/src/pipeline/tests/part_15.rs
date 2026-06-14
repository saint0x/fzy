use super::*;

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
fn cross_backend_repr_c_struct_exports_roundtrip_through_real_c_abi() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root = std::env::temp_dir().join(format!("fozzylang-abi-struct-llvm-{suffix}"));
    let clif_root = std::env::temp_dir().join(format!("fozzylang-abi-struct-clif-{suffix}"));

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"abi_struct_roundtrip\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"abi_struct_roundtrip\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[repr(C)]\nstruct Packet {\n    left: i32,\n    right: i32,\n}\n\n#[ffi_panic(abort)]\npubext c fn echo(packet: Packet) -> Packet {\n    return packet\n}\n\n#[repr(C)]\nstruct Totals {\n    input_count: i32,\n    js_doubled: i32,\n    callback_total: i32,\n}\n\n#[ffi_panic(abort)]\npubext c fn bridge_click(count: i32) -> Totals {\n    return Totals {\n        input_count: count,\n        js_doubled: count * 2,\n        callback_total: count + 11,\n    }\n}\n",
        )
        .expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm library build should succeed");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift library build should succeed");
    let host_source = r#"
#include <stdint.h>

typedef struct Packet {
  int32_t left;
  int32_t right;
} Packet;

typedef struct Totals {
  int32_t input_count;
  int32_t js_doubled;
  int32_t callback_total;
} Totals;

Packet echo(Packet packet);
Totals bridge_click(int32_t count);

int main(void) {
  Packet packet = {7, 9};
  Packet echoed = echo(packet);
  if (echoed.left != 7 || echoed.right != 9) return 11;
  Totals totals = bridge_click(5);
  if (totals.input_count != 5) return 13;
  if (totals.js_doubled != 10) return 17;
  if (totals.callback_total != 16) return 19;
  return 0;
}
"#;

    compile_and_run_c_host(
        host_source,
        llvm.static_lib
            .as_deref()
            .expect("llvm static lib should exist"),
        &llvm_root,
    );
    compile_and_run_c_host(
        host_source,
        cranelift
            .static_lib
            .as_deref()
            .expect("cranelift static lib should exist"),
        &clif_root,
    );

    let _ = std::fs::remove_dir_all(llvm_root);
    let _ = std::fs::remove_dir_all(clif_root);
}

#[test]
fn cross_backend_handle_matrix_runtime_executes_consistently() {
    let project_name = format!(
        "fozzylang-handle-matrix-parity-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    let out_path = root.join("handle-matrix-output.json");
    let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"backend_handle_matrix\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"backend_handle_matrix\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        format!(
            "use core.fs;\nuse core.term;\n\nfn main() -> i32 {{\n    let array_payload = json.parse(\"[1,2,3]\")\n    let items = json.to_list(array_payload)\n    let object_payload = json.parse(\"{{\\\"left\\\":\\\"1\\\",\\\"right\\\":\\\"2\\\"}}\")\n    let table = json.to_map(object_payload)\n    let total = list.len(items) + map.len(table)\n    let summary = map.new()\n    discard map.set(summary, \"total\", json.str(str.from_i32(total)))\n    let encoded = json.object(summary)\n    fs.write_file(\"{quoted_out}\", encoded)\n    discard term.write(\"handle-matrix-parity\\n\")\n    return total\n}}\n"
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
    assert!(cranelift_exit >= 0);
    assert_eq!(cranelift_stdout, llvm_stdout);
    assert_eq!(cranelift_stdout, "handle-matrix-parity\n");
    assert_eq!(cranelift_stderr, llvm_stderr);
    assert!(cranelift_stderr.is_empty());
    assert_eq!(cranelift_artifact, llvm_artifact);
    assert!(cranelift_artifact.contains("\"total\":"));

    let _ = std::fs::remove_dir_all(root);
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
    let _ = diagnostic
        .code
        .as_deref()
        .expect("thread-boundary borrowed-return diagnostic should carry stable code");

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
    let _ = diagnostic
        .code
        .as_deref()
        .expect("thread-boundary mutable-param diagnostic should carry stable code");

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
