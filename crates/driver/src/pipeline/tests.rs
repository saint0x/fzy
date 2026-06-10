use std::path::Path;
use std::process::Command;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use diagnostics::Severity;

use super::native_runtime_support::{render_native_runtime_shim, NativeAsyncExport};
use super::native_runtime_tables::native_runtime_contract_for_callee;
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

fn compile_and_run_c_host(source: &str, static_lib: &Path, work_dir: &Path) {
    let host_c = work_dir.join("host.c");
    let host_bin = work_dir.join("host");
    std::fs::write(&host_c, source).expect("host source should be written");
    let status = Command::new("cc")
        .arg(&host_c)
        .arg(static_lib)
        .arg("-lpthread")
        .arg("-o")
        .arg(&host_bin)
        .status()
        .expect("cc should be available");
    assert!(status.success(), "c host build should succeed");
    let run = Command::new(&host_bin)
        .status()
        .expect("c host should execute");
    assert!(
        run.success(),
        "c host should exit successfully with {}",
        run.code().unwrap_or(-1)
    );
}

#[cfg(target_vendor = "apple")]
fn compile_and_run_c_host_with_metal(source: &str, static_lib: &Path, work_dir: &Path) {
    let host_c = work_dir.join("host.c");
    let host_bin = work_dir.join("host");
    std::fs::write(&host_c, source).expect("host source should be written");
    let status = Command::new("cc")
        .arg(&host_c)
        .arg(static_lib)
        .arg("-lpthread")
        .arg("-framework")
        .arg("Foundation")
        .arg("-framework")
        .arg("Metal")
        .arg("-o")
        .arg(&host_bin)
        .status()
        .expect("cc should be available");
    assert!(status.success(), "gpu c host build should succeed");
    let run = Command::new(&host_bin)
        .status()
        .expect("gpu c host should execute");
    assert!(
        run.success(),
        "gpu c host should exit successfully with {}",
        run.code().unwrap_or(-1)
    );
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
fn verify_file_reports_kernel_ir_lowering_failures() {
    let file_name = format!(
        "fozzylang-kernel-ir-verify-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "device fn classify(flag: bool) -> i32 {\n    match flag {\n        true => return 1,\n        _ => return 0,\n    }\n}\nkernel fn main(output: GpuSlice<i32>) -> void {\n    output[0] = classify(true)\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(output.diagnostics > 0);
    assert!(output.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("kernel lowering for `classify` failed: Kernel IR does not yet support `match` statements in GPU functions")));

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
        "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
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
        "native-runtime-contracts.md",
        "handle-contracts.json",
        "gpu-kernel-package.json",
        "gpu-kernel-package.md",
        "language-policy.json",
        "language-policy.md",
        "release-policy.json",
        "release-policy.md",
        "stdlib-capability-policy.json",
        "stdlib-capability-policy.md",
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
    let runtime_contracts_md =
        std::fs::read_to_string(root.join(".fz/native-runtime-contracts.md"))
            .expect("native runtime contracts markdown should exist");
    assert!(runtime_contracts_md.contains("| Callee | Symbol | Arity |"));
    assert!(runtime_contracts_md.contains("`join`"));
    assert!(runtime_contracts_md.contains("`task_result`"));

    let handle_contracts = std::fs::read_to_string(root.join(".fz/handle-contracts.json"))
        .expect("handle contracts should exist");
    assert!(handle_contracts.contains("\"name\": \"HttpHandle\""));
    let gpu_kernel_package = std::fs::read_to_string(root.join(".fz/gpu-kernel-package.json"))
        .expect("gpu kernel package should exist");
    assert!(gpu_kernel_package.contains("\"schemaVersion\": \"fozzylang.gpu_kernel_package.v1\""));
    assert!(gpu_kernel_package.contains("\"backendAdapters\""));
    assert!(gpu_kernel_package.contains("\"spirv\""));
    assert!(gpu_kernel_package.contains("\"nvptx\""));
    assert!(gpu_kernel_package
        .contains("\"descriptorStatus\": \"shared_contract_bound_not_executable\""));
    assert!(gpu_kernel_package.contains("\"abiVersion\": \"fozzylang.gpu_launch_abi.v1\""));
    assert!(gpu_kernel_package.contains("\"argumentLayoutClasses\""));
    assert!(gpu_kernel_package.contains("\"backendLimitProfiles\""));
    assert!(gpu_kernel_package.contains("\"moduleFormat\": \"spirv.binary_module\""));
    assert!(gpu_kernel_package.contains("\"executionModel\": \"GLCompute\""));
    assert!(gpu_kernel_package.contains("\"moduleFormat\": \"ptx.assembly_text\""));
    assert!(gpu_kernel_package.contains("\"entryDirective\": \".entry\""));
    assert!(gpu_kernel_package.contains("\"parameterStateSpace\": \".param\""));
    let gpu_kernel_package_md = std::fs::read_to_string(root.join(".fz/gpu-kernel-package.md"))
        .expect("gpu kernel package markdown should exist");
    assert!(gpu_kernel_package_md.contains("# GPU Kernel Package"));
    assert!(gpu_kernel_package_md.contains("## Layout Classes"));
    assert!(gpu_kernel_package_md.contains("| Function | Space | Params | Capabilities | Return |"));

    let language_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/language-policy.json"))
            .expect("language policy should exist"),
    )
    .expect("language policy should be valid json");
    assert_eq!(
        language_policy["language"]["changePolicy"].as_str(),
        Some("additive_only")
    );
    assert!(language_policy["syntaxFreeze"]["surface"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["name"] == "fn")));
    let language_policy_md = std::fs::read_to_string(root.join(".fz/language-policy.md"))
        .expect("language policy markdown should exist");
    assert!(language_policy_md.contains("## Syntax Freeze"));
    assert!(language_policy_md.contains("| Profile | Checks | Unsafe | Backend |"));
    let release_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/release-policy.json")).expect("release policy should exist"),
    )
    .expect("release policy should be valid json");
    assert_eq!(
        release_policy["schemaVersion"].as_str(),
        Some("fozzylang.release_policy.v1")
    );
    assert_eq!(
        release_policy["versions"]["traceSchemaVersion"].as_str(),
        Some("fozzy-trace.v4")
    );
    let release_policy_md = std::fs::read_to_string(root.join(".fz/release-policy.md"))
        .expect("release policy markdown should exist");
    assert!(release_policy_md.contains("## Compatibility"));
    assert!(release_policy_md.contains("## Benchmark Lanes"));
    let stdlib_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/stdlib-capability-policy.json"))
            .expect("stdlib capability policy should exist"),
    )
    .expect("stdlib capability policy should be valid json");
    assert_eq!(
        stdlib_policy["schemaVersion"].as_str(),
        Some("fozzylang.stdlib_capability_policy.v1")
    );
    assert!(stdlib_policy["modules"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["module"] == "core.http")));
    let stdlib_policy_md = std::fs::read_to_string(root.join(".fz/stdlib-capability-policy.md"))
        .expect("stdlib capability policy markdown should exist");
    assert!(stdlib_policy_md.contains("## Module Contracts"));
    assert!(stdlib_policy_md.contains("## Strict Hazards"));
    assert!(handle_contracts.contains("\"name\": \"JsonHandle\""));
    assert!(handle_contracts.contains("\"linear\": true"));
    assert!(handle_contracts.contains("\"linear\": false"));
}

#[test]
fn compile_file_skips_rewriting_unchanged_safety_artifacts() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-safety-artifact-cache-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"artifact_cache\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"artifact_cache\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let first = compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
    assert_eq!(first.status, "ok");
    let report_path = root.join(".fz/release-policy.json");
    let initial_mtime = std::fs::metadata(&report_path)
        .expect("release policy artifact should exist")
        .modified()
        .expect("release policy mtime should exist");

    std::thread::sleep(Duration::from_millis(20));
    let second = compile_file(&root, BuildProfile::Dev).expect("second build should succeed");
    assert_eq!(second.status, "ok");
    let refreshed_mtime = std::fs::metadata(&report_path)
        .expect("release policy artifact should still exist")
        .modified()
        .expect("release policy mtime should still exist");
    assert_eq!(initial_mtime, refreshed_mtime);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn language_policy_artifact_reports_syntax_freeze_and_profile_defaults() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-language-policy-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"language_policy\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"language_policy\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("build should succeed");
    assert_eq!(artifact.status, "ok");
    let payload: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/language-policy.json"))
            .expect("language policy artifact should be readable"),
    )
    .expect("language policy should be valid json");
    assert_eq!(
        payload["schemaVersion"].as_str(),
        Some("fozzylang.language_policy.v1")
    );
    assert_eq!(
        payload["language"]["changePolicy"].as_str(),
        Some("additive_only")
    );
    let syntax_names = payload["syntaxFreeze"]["surface"]
        .as_array()
        .expect("syntax freeze should be an array")
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "fn",
        "let",
        "let mut",
        "struct",
        "enum",
        "match",
        "trait",
        "impl",
        "async",
        "await",
        "rpc",
        "unsafe metadata",
        "defer",
        "use core.*",
        "extern",
        "pubext",
    ] {
        assert!(
            syntax_names.contains(&expected),
            "syntax freeze missing `{expected}`"
        );
    }
    let dev = &payload["profiles"]["dev"];
    assert_eq!(dev["backend"].as_str(), Some("cranelift"));
    assert_eq!(dev["checksEnabled"].as_bool(), Some(true));
    assert_eq!(dev["unsafeContractsEnforced"].as_bool(), Some(false));
    assert_eq!(dev["optimize"].as_bool(), Some(false));
    assert_eq!(dev["optimizationLevel"].as_str(), Some("O0"));
    assert_eq!(dev["diagnosticStrictness"].as_str(), Some("standard"));
    assert_eq!(dev["emitSafetyArtifacts"].as_bool(), Some(true));
    let strict = &payload["profiles"]["strict"];
    assert_eq!(strict["backend"].as_str(), Some("llvm"));
    assert_eq!(strict["checksEnabled"].as_bool(), Some(true));
    assert_eq!(strict["unsafeContractsEnforced"].as_bool(), Some(true));
    assert_eq!(strict["optimize"].as_bool(), Some(true));
    assert_eq!(strict["optimizationLevel"].as_str(), Some("O2+g"));
    assert_eq!(strict["diagnosticStrictness"].as_str(), Some("strict"));
    assert_eq!(
        strict["runtimeImportsAllowed"].as_str(),
        Some("declared_native_runtime_contracts_only")
    );
    assert_eq!(
        strict["capabilityPolicy"].as_str(),
        Some("explicit_compiler_checked")
    );

    let markdown = std::fs::read_to_string(root.join(".fz/language-policy.md"))
        .expect("language policy markdown should be readable");
    assert!(markdown.contains("- `fn`: function declarations"));
    assert!(markdown.contains("| `strict` | `true` | `true` | `llvm` |"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn language_policy_artifact_respects_manifest_profile_overrides() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-language-policy-overrides-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"language_policy_overrides\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"language_policy_overrides\"\npath=\"src/main.fzy\"\n\n[language]\ntier=\"experimental\"\nallow_experimental=true\n\n[profiles.strict]\nbackend=\"cranelift\"\nchecks=false\noptimize=false\ndiagnostic_strictness=\"standard\"\nemit_safety_artifacts=false\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn risky() -> i32 { return 1 }\nfn main() -> i32 {\n    let v = try risky() catch 0\n    return v\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Strict).expect("build should run");
    let payload: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/language-policy.json"))
            .expect("language policy artifact should be readable"),
    )
    .expect("language policy should be valid json");
    assert_eq!(artifact.status, "ok");
    assert_eq!(
        payload["language"]["defaultTier"].as_str(),
        Some("experimental")
    );
    assert_eq!(
        payload["language"]["allowExperimental"].as_bool(),
        Some(true)
    );
    let strict = &payload["profiles"]["strict"];
    assert_eq!(strict["backend"].as_str(), Some("cranelift"));
    assert_eq!(strict["checksEnabled"].as_bool(), Some(false));
    assert_eq!(strict["optimize"].as_bool(), Some(false));
    assert_eq!(strict["diagnosticStrictness"].as_str(), Some("standard"));
    assert_eq!(strict["emitSafetyArtifacts"].as_bool(), Some(false));
    assert_eq!(strict["experimentalFeaturesAllowed"].as_bool(), Some(true));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn release_policy_artifact_reports_error_perf_and_compat_contracts() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-release-policy-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"release_policy\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"release_policy\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("build should succeed");
    assert_eq!(artifact.status, "ok");

    let payload: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/release-policy.json"))
            .expect("release policy artifact should be readable"),
    )
    .expect("release policy should be valid json");
    assert_eq!(
        payload["schemaVersion"].as_str(),
        Some("fozzylang.release_policy.v1")
    );
    assert_eq!(
        payload["versions"]["languageVersion"].as_str(),
        Some("fozzylang.language.v1")
    );
    assert_eq!(
        payload["versions"]["traceSchemaVersion"].as_str(),
        Some("fozzy-trace.v4")
    );
    assert_eq!(
        payload["versions"]["manifestSchemaVersion"].as_str(),
        Some("fozzy.run_manifest.v1")
    );
    assert_eq!(
        payload["versions"]["runtimeAbiVersion"].as_str(),
        Some("fozzylang.runtime.v0")
    );
    assert_eq!(
        payload["versions"]["nativeImportTableVersion"].as_str(),
        Some("fozzylang.native_runtime_contracts.v1")
    );
    assert_eq!(
        payload["errorModel"]["serviceFunctionsReturn"].as_str(),
        Some("Result<T, Error>")
    );
    assert_eq!(payload["errorModel"]["cliMainReturn"].as_str(), Some("i32"));
    assert!(payload["errorModel"]["errorClasses"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["name"] == "timeout")));
    assert_eq!(
        payload["performance"]["benchmarkArtifact"].as_str(),
        Some("artifacts/bench_core_rust_vs_fzy.json")
    );
    assert!(payload["performance"]["workloads"]
        .as_array()
        .is_some_and(|items| items
            .iter()
            .any(|item| item["name"] == "compiler_parse_lower_build")));
    assert!(payload["documentation"]["surfaces"]
        .as_array()
        .is_some_and(|items| items
            .iter()
            .any(|item| item["name"] == "diagnostic-catalog")));
    assert_eq!(
        payload["releaseGating"]["compatibilitySetRequired"].as_bool(),
        Some(true)
    );

    let markdown = std::fs::read_to_string(root.join(".fz/release-policy.md"))
        .expect("release policy markdown should be readable");
    assert!(markdown.contains("## Error Model"));
    assert!(markdown.contains("`transport`: boundary and IO failures at runtime or service edges"));
    assert!(markdown.contains("## Implementation-Backed Docs"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stdlib_capability_policy_artifact_reports_module_contracts_and_hazards() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-stdlib-policy-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"stdlib_policy\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"stdlib_policy\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.http;\nuse core.thread;\nfn worker() -> i32 { return 1 }\nfn main() -> i32 {\n    let handle = spawn(worker)\n    discard join(handle)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("build should succeed");
    assert_eq!(artifact.status, "ok");

    let payload: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join(".fz/stdlib-capability-policy.json"))
            .expect("stdlib capability policy artifact should be readable"),
    )
    .expect("stdlib capability policy should be valid json");
    assert_eq!(
        payload["schemaVersion"].as_str(),
        Some("fozzylang.stdlib_capability_policy.v1")
    );
    assert_eq!(
        payload["capabilityPolicy"]["propagation"].as_str(),
        Some("explicit_compiler_checked")
    );
    assert_eq!(
        payload["jsonBoundaryRule"]["inside"].as_str(),
        Some("typed_structs_and_enums")
    );
    for expected in [
        "core.mem",
        "core.http",
        "core.proc",
        "core.fs",
        "core.thread",
        "core.time",
        "core.crypto",
        "core.json",
        "core.log",
    ] {
        assert!(payload["modules"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["module"] == expected)));
    }
    for expected in [
        "json_raw_composite_or_dynamic_injection",
        "path_traversal_literal",
        "shell_process_builder",
        "tempfile_non_atomic_write",
        "http_header_non_normalized",
        "crypto_secret_eq",
    ] {
        assert!(payload["strictHazards"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["kind"] == expected)));
    }

    let markdown = std::fs::read_to_string(root.join(".fz/stdlib-capability-policy.md"))
        .expect("stdlib capability policy markdown should be readable");
    assert!(markdown.contains("| `core.http` | `http` |"));
    assert!(markdown.contains("`crypto_secret_eq` (`warning`)"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_strict_stdlib_policy_surfaces_json_raw_and_shell_hazards() {
    let path = std::env::temp_dir().join(format!(
        "fozzylang-stdlib-hazards-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::write(
        &path,
        "use core.proc;\nuse core.http;\nfn main() -> i32 {\n    let payload = map.new()\n    discard map.set(payload, \"body\", json.raw(\"{\\\"unsafe\\\":true}\"))\n    discard proc.argv_push(proc.argv_new(), \"-c\")\n    discard proc.spawn_cmd(\"/bin/sh\", proc.argv_new(), proc.env_new(), \"\")\n    discard http.header_set(\"X-Demo\", \"ok\")\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    let messages = output
        .diagnostic_details
        .iter()
        .map(|item| item.message.clone())
        .collect::<Vec<_>>();
    assert!(messages
        .iter()
        .any(|item| item.contains("`json.raw(...)` embeds a composite or quoted JSON literal")));
    assert!(messages
        .iter()
        .any(|item| item.contains("process argv uses shell command-string flag")));
    assert!(messages
        .iter()
        .any(|item| item.contains("shells out through `/bin/sh`")));
    assert!(messages
        .iter()
        .any(|item| item.contains("HTTP header `X-Demo` is not normalized")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_strict_stdlib_policy_surfaces_path_temp_and_crypto_hazards() {
    let path = std::env::temp_dir().join(format!(
        "fozzylang-stdlib-path-hazards-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::write(
        &path,
        "use core.fs;\nuse core.security;\nfn main() -> i32 {\n    discard fs.write_file(\"../secrets.txt\", \"oops\")\n    discard fs.write_file(\"/tmp/out.txt\", \"temp\")\n    if security.sign_value(\"k\", \"v\") == security.sign_value(\"k\", \"v\") {\n        return 0\n    }\n    return 1\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    let messages = output
        .diagnostic_details
        .iter()
        .map(|item| item.message.clone())
        .collect::<Vec<_>>();
    assert!(messages
        .iter()
        .any(|item| item.contains("traversal-prone literal path `../secrets.txt`")));
    assert!(messages
        .iter()
        .any(|item| item.contains("writes directly to temp path `/tmp/out.txt`")));
    assert!(messages
        .iter()
        .any(|item| item.contains("secret-bearing values are compared with `==`/`!=`")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn compile_file_handle_contracts_align_with_runtime_contracts() {
    let root = std::env::temp_dir().join(format!(
        "fozzylang-handle-contracts-alignment-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"handle_contracts_alignment\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"handle_contracts_alignment\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.fs;\nuse core.http;\nuse core.proc;\nuse core.storage;\nuse core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn main() -> i32 {\n    let conn = http.accept()\n    discard http.write_json(conn, 200, \"{}\")\n    let stream = http.post_json_stream(\"https://example.com\", \"{}\")\n    discard http.stream_close(stream)\n    let argv = proc.argv_new()\n    let env = proc.env_new()\n    let handle = proc.spawn_cmd(\"echo\", argv, env, \"\")\n    discard proc.close(handle)\n    let task = spawn(worker)\n    discard join(task)\n    let ctx_task = thread.spawn_ctx(worker, 7)\n    discard join(ctx_task)\n    let store = storage.kv_open(\"session.kv\")\n    discard storage.kv_close(store)\n    let file = fs.open(\"/tmp/fzy-handle-contract-file.txt\")\n    discard fs.write(file, \"hello\")\n    discard fs.close(file)\n    let payload = json.parse(\"{}\")\n    let items = json.to_list(payload)\n    let table = map.new()\n    discard list.len(items)\n    discard map.len(table)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.status, "ok");

    let handle_contracts = std::fs::read_to_string(root.join(".fz/handle-contracts.json"))
        .expect("handle contracts should exist");
    assert!(handle_contracts.contains("\"name\": \"HttpHandle\""));
    assert!(handle_contracts.contains("\"consumerIntrinsics\""));
    assert!(handle_contracts.contains("\"name\": \"JsonHandle\""));
    assert!(handle_contracts.contains("\"producerIntrinsics\""));
    assert!(handle_contracts.contains("\"name\": \"KvStoreHandle\""));
    assert!(handle_contracts.contains("\"name\": \"FileHandle\""));

    let runtime_contracts = std::fs::read_to_string(root.join(".fz/native-runtime-contracts.json"))
        .expect("native runtime contracts should exist");
    assert!(runtime_contracts.contains("\"callee\": \"http.write_json\""));
    assert!(runtime_contracts.contains("\"argOwnership\": \"consume_arg0_borrow_status_payload\""));
    assert!(runtime_contracts.contains("\"callee\": \"http.post_json_stream\""));
    assert!(runtime_contracts.contains("\"linearity\": \"produces_linear_handle\""));
    assert!(runtime_contracts.contains("\"callee\": \"json.parse\""));
    assert!(runtime_contracts.contains("\"linearity\": \"produces_handle\""));
    assert!(runtime_contracts.contains("\"callee\": \"list.len\""));
    assert!(runtime_contracts.contains("\"linearity\": \"observes_handle\""));
    assert!(runtime_contracts.contains("\"callee\": \"fs.close\""));
    assert!(runtime_contracts.contains("\"callee\": \"fs.read\""));
    assert!(runtime_contracts.contains("\"callee\": \"thread.spawn_ctx\""));
    assert!(runtime_contracts.contains("\"returnOwnership\": \"owned_task_handle\""));
}

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
    assert!(rpc_report.contains("\"policy\": \"explicit\""));
    assert!(rpc_report.contains("\"cleanupPolicy\": \"missing\""));
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

#[test]
fn verify_same_lifetime_reference_relay_stays_clean() {
    let file_name = format!(
        "fozzylang-reference-lifetime-clean-relay-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'a i32) -> &'a i32 {\n    return v\n}\nfn relay(a: &'a i32) -> &'a i32 {\n    return borrow(a)\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("mismatched lifetime")
            || diagnostic
                .message
                .contains("without a statically traced lifetime source")
            || diagnostic.message.contains("potential resource escape")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_inferred_local_reference_across_await_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-inferred-local-await-reference-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn borrow(v: &'a i32) -> &'a i32 {\n    return v\n}\nasync fn worker(v: &'a i32) -> i32 {\n    let alias = borrow(v)\n    await recv()\n    discard alias\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message.contains(
                "cannot use borrowed local reference `alias` across await suspension points",
            )
        })
        .expect("inferred-local across-await diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("resolve the borrowed local before `await`, or keep only owned data alive across the suspension point")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("inferred-local across-await diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_if_body_borrowed_reference_across_await_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-if-body-await-reference-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "async fn worker(v: &'a i32) -> i32 {\n    if true {\n        await recv()\n        discard v\n    }\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("cannot use borrowed reference `v` across await suspension points")
        })
        .expect("if-body across-await diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move the `await` before the borrowed use, or replace the borrowed path with an owned value across suspension")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("if-body across-await diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_match_arm_borrowed_reference_across_await_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-match-arm-await-reference-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "async fn worker(v: &'a i32) -> i32 {\n    match await recv() {\n        0 => v,\n        _ => 0,\n    }\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("cannot use borrowed reference `v` across await suspension points")
        })
        .expect("match-arm across-await diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move the `await` before the borrowed use, or replace the borrowed path with an owned value across suspension")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("match-arm across-await diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_loop_body_borrowed_reference_across_await_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-loop-body-await-reference-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "async fn worker(v: &'a i32) -> i32 {\n    while false {\n        await recv()\n        discard v\n    }\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("cannot use borrowed reference `v` across await suspension points")
        })
        .expect("loop-body across-await diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("move the `await` before the borrowed use, or replace the borrowed path with an owned value across suspension")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("loop-body across-await diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_non_async_stable_process_argv_across_await_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-process-argv-await-handle-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nasync fn worker() -> i32 {\n    let argv = proc.argv_new()\n    await recv()\n    discard argv\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message.contains(
                "cannot use non-async-stable handle `argv` (ProcessArgv) across await suspension points",
            )
        })
        .expect("process argv across-await diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("finish, consume, or replace the non-async-stable handle before `await`, or move the suspension point earlier")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("process argv across-await diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_non_async_stable_process_env_across_await_diagnostic_is_snapshot_stable() {
    let file_name = format!(
        "fozzylang-process-env-await-handle-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.proc;\nasync fn worker() -> i32 {\n    let env = proc.env_new()\n    await recv()\n    discard env\n    return 0\n}\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    let diagnostic = output
        .diagnostic_details
        .iter()
        .find(|diagnostic| {
            diagnostic.message.contains(
                "cannot use non-async-stable handle `env` (ProcessEnv) across await suspension points",
            )
        })
        .expect("process env across-await diagnostic should be present");
    assert_eq!(
        diagnostic.help.as_deref(),
        Some("finish, consume, or replace the non-async-stable handle before `await`, or move the suspension point earlier")
    );
    let _ = diagnostic
        .code
        .as_deref()
        .expect("process env across-await diagnostic should carry stable code");

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_owner_access_after_mutable_borrow_last_use_stays_clean() {
    let file_name = format!(
        "fozzylang-mut-borrow-last-use-clean-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "fn inspect_value(v: i32) -> i32 {\n    return v\n}\nfn main() -> i32 {\n    let x: i32 = 1\n    let unique: &'a mut i32 = x\n    discard unique\n    discard inspect_value(x)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let output = verify_file(&path).expect("verify should succeed with diagnostics");
    assert!(!output
        .diagnostic_details
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, Severity::Error)));
    assert!(!output.diagnostic_details.iter().any(|diagnostic| {
        diagnostic.message.contains("accesses owner `x`")
            && diagnostic
                .message
                .contains("mutable borrowed reference `unique`")
    }));

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
fn compile_project_accepts_core_log_import_surface() {
    let project_name = format!(
        "fozzylang-core-log-import-{}",
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
        "use core.log;\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("main should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("project should compile");
    assert_eq!(artifact.status, "ok");
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
        "use core.simd;\n\nfn main() -> i32 {\n    let ints = simd.i32x4_add(simd.i32x4_load([1, 2, 3, 4]), simd.i32x4_splat(2))\n    let uint_source = simd.u32x4_store(simd.u32x4_new(1, 2, 3, 4))\n    let float_source = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let shifted = simd.i32x4_shl(ints, 1)\n    let bounded = simd.i32x4_max(shifted, simd.i32x4_new(7, 1, 11, 1))\n    let lane = 5\n    let shuffled = simd.i32x4_shuffle(ints, shifted, 0, lane, 2, 7)\n    let zip_lo = simd.i32x4_zip_lo(ints, shifted)\n    let zip_hi = simd.i32x4_zip_hi(ints, shifted)\n    let unzipped_left = simd.i32x4_unzip_left(zip_lo, zip_hi)\n    let unzipped_right = simd.i32x4_unzip_right(zip_lo, zip_hi)\n    let mask = simd.i32x4_gt(ints, simd.i32x4_splat(4))\n    let stored_ints = simd.i32x4_store(ints)\n    let picked = simd.i32x4_select(mask, ints, simd.i32x4_splat(0))\n    let sum = simd.i32x4_reduce_add(picked)\n    let signed_sat = simd.i32x4_saturating_add(simd.i32x4_new(2147483640, -2147483640, 100, -100), simd.i32x4_new(20, -20, -250, 250))\n    let signed_sat_back = simd.i32x4_saturating_sub(signed_sat, simd.i32x4_new(100, -100, -100, 100))\n    let bitmask = simd.mask32x4_bitmask(mask)\n    let signed_bits = simd.f32x4_bitcast_i32x4(simd.f32x4_new(1.0, -2.0, 0.0, 4.0))\n    let signed_roundtrip = simd.i32x4_bitcast_f32x4(signed_bits)\n    let alias_roundtrip = simd.i32x4_as_u32x4(simd.u32x4_as_i32x4(simd.u32x4_new(9, 11, 13, 15)))\n    let unsigned_sat = simd.u32x4_saturating_add(simd.i32x4_as_u32x4(simd.i32x4_new(-1, -5, 10, 0)), simd.i32x4_as_u32x4(simd.i32x4_new(1, 10, 20, -1)))\n    let unsigned_sat_back = simd.u32x4_saturating_sub(unsigned_sat, simd.u32x4_new(1, 5, 100, 0))\n    let uints_ok = simd.mask32x4_all(simd.u32x4_eq(simd.u32x4_max(simd.u32x4_shr(simd.u32x4_shl(simd.u32x4_load(uint_source), 2), 1), simd.u32x4_new(0, 4, 0, 8)), simd.u32x4_new(2, 4, 6, 8)))\n    let stored_uints = simd.u32x4_store(alias_roundtrip)\n    let floats = simd.f32x4_min(simd.f32x4_mul(simd.f32x4_splat(1.5f32), simd.f32x4_load(float_source)), simd.f32x4_max(simd.f32x4_new(1.0, 3.0, 4.0, 5.0), simd.f32x4_new(1.5, 2.5, 4.5, 6.0)))\n    let stored_floats = simd.f32x4_store(floats)\n    let stored_mask = simd.mask32x4_store(mask)\n    let floats_ok = simd.mask32x4_all(simd.f32x4_eq(floats, simd.f32x4_new(1.5, 3.0, 4.5, 6.0)))\n    if simd.mask32x4_any(mask) == false {\n        return 11\n    }\n    if simd.mask32x4_none(mask) == true {\n        return 13\n    }\n    if uints_ok == false {\n        return 17\n    }\n    if floats_ok == false {\n        return 19\n    }\n    if simd.i32x4_lane0(bounded) != 7 {\n        return 21\n    }\n    if simd.i32x4_lane2(ints) != 5 {\n        return 23\n    }\n    if simd.i32x4_lane1(shuffled) != 8 {\n        return 25\n    }\n    if bitmask != 12 {\n        return 27\n    }\n    if sum != 11 {\n        return 29\n    }\n    if simd.i32x4_reduce_min(signed_sat) != simd.i32x4_lane1(signed_sat) {\n        return 30\n    }\n    if simd.i32x4_reduce_max(signed_sat) != simd.i32x4_lane0(signed_sat) {\n        return 31\n    }\n    if simd.i32x4_lane3(zip_hi) != 12 {\n        return 33\n    }\n    if stored_ints[3] != 6 {\n        return 34\n    }\n    if simd.mask32x4_all(simd.i32x4_eq(unzipped_left, ints)) == false {\n        return 35\n    }\n    if simd.mask32x4_all(simd.i32x4_eq(unzipped_right, shifted)) == false {\n        return 37\n    }\n    if stored_mask[0] != false || stored_mask[2] != true {\n        return 38\n    }\n    if simd.mask32x4_all(simd.f32x4_eq(signed_roundtrip, simd.f32x4_new(1.0, -2.0, 0.0, 4.0))) == false {\n        return 39\n    }\n    if simd.mask32x4_all(simd.f32x4_eq(simd.f32x4_load(stored_floats), floats)) == false {\n        return 41\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(alias_roundtrip, simd.u32x4_new(9, 11, 13, 15))) == false {\n        return 43\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(simd.u32x4_load(stored_uints), alias_roundtrip)) == false {\n        return 45\n    }\n    if simd.i32x4_lane2(signed_sat) != -150 || simd.i32x4_lane3(signed_sat) != 150 {\n        return 47\n    }\n    if simd.i32x4_lane0(signed_sat_back) != 2147483547 || simd.i32x4_lane1(signed_sat_back) != -2147483548 {\n        return 49\n    }\n    if simd.i32x4_lane2(signed_sat_back) != -50 || simd.i32x4_lane3(signed_sat_back) != 50 {\n        return 50\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(unsigned_sat, simd.i32x4_as_u32x4(simd.i32x4_new(-1, -1, 30, -1)))) == false {\n        return 51\n    }\n    if simd.mask32x4_all(simd.u32x4_eq(unsigned_sat_back, simd.i32x4_as_u32x4(simd.i32x4_new(-2, -6, 0, -1)))) == false {\n        return 53\n    }\n    if simd.u32x4_reduce_min(alias_roundtrip) != simd.u32x4_lane0(alias_roundtrip) || simd.u32x4_reduce_max(alias_roundtrip) != simd.u32x4_lane3(alias_roundtrip) {\n        return 55\n    }\n    if simd.f32x4_reduce_min(floats) != simd.f32x4_lane0(floats) || simd.f32x4_reduce_max(floats) != simd.f32x4_lane3(floats) {\n        return 57\n    }\n    return 0\n}\n",
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
fn compile_library_supports_raw_pointer_indexing_and_usize_consts() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root = std::env::temp_dir().join(format!("fozzylang-lib-ptr-llvm-{suffix}"));
    let clif_root = std::env::temp_dir().join(format!("fozzylang-lib-ptr-clif-{suffix}"));
    let manifest =
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n";
    let source = "const WEIGHT_COUNT_LEN: usize = 4\n#[ffi_panic(abort)]\npubext c fn head_pair_sum(weights_borrowed: *f32, weights_len: usize) -> f32 {\n    discard weights_len\n    discard WEIGHT_COUNT_LEN\n    return weights_borrowed[0] + weights_borrowed[1]\n}\n";

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(root.join("fozzy.toml"), manifest).expect("manifest should be written");
        std::fs::write(root.join("src/lib.fzy"), source).expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm raw pointer indexing library build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift raw pointer indexing library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let _ = std::fs::remove_dir_all(llvm_root);
    let _ = std::fs::remove_dir_all(clif_root);
}

#[test]
fn compile_library_supports_raw_pointer_indexed_writes() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("fozzylang-lib-ptr-write-{suffix}"));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "#[ffi_panic(abort)]\npubext c fn poke(out_values_out: *f32, out_values_len: usize) -> i32 {\n    discard out_values_len\n    out_values_out[0] = 1.0f32\n    return 0\n}\n",
    )
    .expect("source should be written");

    let parsed = parse_program(&root.join("src/lib.fzy")).expect("parse should succeed");
    let ((_typed, fir), _) = super::lower_fir_cached_with_metadata(&parsed);
    assert_eq!(fir.type_errors, 0, "{:?}", fir.type_error_details);

    let artifact = compile_library_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("raw pointer indexed write library build should succeed");
    assert_eq!(
        artifact.status,
        "ok",
        "{:?}",
        artifact
            .diagnostic_details
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn compile_library_supports_gpu_pointer_upload_helpers_and_kernel_simd_arrays() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root = std::env::temp_dir().join(format!("fozzylang-lib-gpu-neural-llvm-{suffix}"));
    let clif_root = std::env::temp_dir().join(format!("fozzylang-lib-gpu-neural-clif-{suffix}"));
    let manifest =
        "[package]\nname=\"gpu_demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"gpu_demo_lib\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;
use core.simd;

fn bias(value: f32) -> f32 {
    return value + 1.0f32
}

kernel fn forward(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
    let i = gpu.global_id_x()
    if i < n {
        let lanes = simd.f32x4_store(simd.f32x4_add(
            simd.f32x4_splat(bias(input[i])),
            simd.f32x4_load([1.0f32, 2.0f32, 3.0f32, 4.0f32]),
        ))
        let mut scratch = [0.0f32, 0.0f32, 0.0f32, 0.0f32]
        scratch[0] = lanes[0]
        output[i] = scratch[0]
    }
}

#[ffi_panic(abort)]
pubext c fn render(weights_borrowed: *f32, weights_len: usize, out_values_out: *f32, out_values_len: usize) -> i32 {
    discard weights_len
    if out_values_len < 4 { return 11 }
    let dev = gpu.default_device()
    let input: GpuBuffer<f32> = gpu.upload_f32(dev, weights_borrowed)
    defer gpu.free(input)
    let output: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)
    defer gpu.free(output)
    let event = gpu.launch3(forward, 4, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)
    gpu.wait(event)
    let values: Vec<f32> = gpu.download_f32(output)
    let mut idx = 0
    while idx < 4 {
        out_values_out[idx] = values[idx]
        idx = idx + 1
    }
    return 0
}
"#;

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(root.join("fozzy.toml"), manifest).expect("manifest should be written");
        std::fs::write(root.join("src/lib.fzy"), source).expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm gpu helper library build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift gpu helper library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let _ = std::fs::remove_dir_all(llvm_root);
    let _ = std::fs::remove_dir_all(clif_root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn borrowed_gpu_upload_from_ffi_raw_pointer_uses_element_counts_at_runtime() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-upload-runtime-llvm-{suffix}"));
    let clif_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-upload-runtime-clif-{suffix}"));
    let manifest = "[package]\nname=\"gpu_upload_runtime\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"gpu_upload_runtime\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;

#[ffi_panic(abort)]
pubext c fn echo_gpu_upload(weights_borrowed: *f32, weights_len: usize, out_values_out: *f32, out_values_len: usize) -> i32 {
    discard weights_len
    discard out_values_len
    let dev = gpu.default_device()
    let input: GpuBuffer<f32> = gpu.upload_f32(dev, weights_borrowed)
    defer gpu.free(input)
    let values: Vec<f32> = gpu.download_f32(input)
    out_values_out[0] = values[0]
    out_values_out[1] = values[1]
    out_values_out[2] = values[2]
    out_values_out[3] = values[3]
    return 0
}
"#;

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(root.join("fozzy.toml"), manifest).expect("manifest should be written");
        std::fs::write(root.join("src/lib.fzy"), source).expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm gpu upload runtime library build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift gpu upload runtime library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let host_source = r#"
#include <stdint.h>

int32_t echo_gpu_upload(float* weights_borrowed, uintptr_t weights_len, float* out_values_out, uintptr_t out_values_len);

int main(void) {
  float values[4] = {1.0f, 2.0f, 3.0f, 4.0f};
  float out[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  int32_t status = echo_gpu_upload(values, sizeof(values), out, sizeof(out));
  if (status != 0) return 11;
  if (out[0] != 1.0f) return 12;
  if (out[1] != 2.0f) return 13;
  if (out[2] != 3.0f) return 14;
  if (out[3] != 4.0f) return 15;
  return 0;
}
"#;

    compile_and_run_c_host_with_metal(
        host_source,
        llvm.static_lib
            .as_deref()
            .expect("llvm static lib should exist"),
        &llvm_root,
    );
    compile_and_run_c_host_with_metal(
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

#[cfg(target_vendor = "apple")]
#[test]
fn metal_kernel_stmt_discard_of_gpu_slice_lowers_to_noop_without_breaking_launch() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let clif_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-discard-slice-runtime-{suffix}"));
    let manifest = "[package]\nname=\"gpu_discard_slice_runtime\"\nversion=\"0.1.0\"\n\n[ffi]\npanic_boundary=\"abort\"\n\n[target.lib]\nname=\"gpu_discard_slice_runtime\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;

kernel fn paint(input: GpuSlice<f32>, output: GpuSlice<i32>) -> void {
    let i = gpu.global_id_x()
    let total = gpu.slice_len(output)
    if i < total {
        discard input
        output[i] = 7
    }
}

#[ffi_panic(abort)]
pubext c fn render(values_borrowed: *f32, values_len: usize, out_words_out: *i32, out_words_len: usize) -> i32 {
    discard values_len
    discard out_words_len
    let dev = gpu.default_device()
    let input: GpuBuffer<f32> = gpu.upload_f32(dev, values_borrowed)
    defer gpu.free(input)
    let output: GpuBuffer<i32> = gpu.alloc_i32(dev, 8)
    defer gpu.free(output)
    let event = gpu.launch2(paint, 1, 64, gpu.slice(input, 0, 8), gpu.slice(output, 0, 8))
    gpu.wait(event)
    let words: Vec<i32> = gpu.download_i32(output)
    out_words_out[0] = words[0]
    out_words_out[1] = words[1]
    out_words_out[2] = words[2]
    out_words_out[3] = words[3]
    return 0
}
"#;

    std::fs::create_dir_all(clif_root.join("src")).expect("project dir should be created");
    std::fs::write(clif_root.join("fozzy.toml"), manifest).expect("manifest should be written");
    std::fs::write(clif_root.join("src/lib.fzy"), source).expect("source should be written");

    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift discard-slice runtime library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let host_source = r#"
#include <stdint.h>

int32_t render(float* values_borrowed, uintptr_t values_len, int32_t* out_words_out, uintptr_t out_words_len);

int main(void) {
  float values[8] = {0.0f, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f};
  int32_t out[4] = {0, 0, 0, 0};
  int32_t status = render(values, sizeof(values), out, sizeof(out));
  if (status != 0) return 11;
  if (out[0] != 7) return 12;
  if (out[1] != 7) return 13;
  if (out[2] != 7) return 14;
  if (out[3] != 7) return 15;
  return 0;
}
"#;

    compile_and_run_c_host_with_metal(
        host_source,
        cranelift
            .static_lib
            .as_deref()
            .expect("cranelift static lib should exist"),
        &clif_root,
    );

    let _ = std::fs::remove_dir_all(clif_root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn gpu_download_u32_large_readback_survives_multi_threadgroup_launch() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let clif_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-large-u32-readback-{suffix}"));
    let manifest = "[package]\nname=\"gpu_large_u32_readback\"\nversion=\"0.1.0\"\n\n[ffi]\npanic_boundary=\"abort\"\n\n[target.lib]\nname=\"gpu_large_u32_readback\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;

kernel fn paint(output: GpuSlice<u32>, n: i32) -> void {
    let i = gpu.global_id_x()
    if i < n {
        output[i] = 255 + ((i + 1) << 8)
    }
}

#[ffi_panic(abort)]
pubext c fn run(out_rgba_out: *u32, out_rgba_len: usize, out_count: i32) -> i32 {
    discard out_rgba_len
    let dev = gpu.default_device()
    let output: GpuBuffer<u32> = gpu.alloc_u32(dev, out_count)
    defer gpu.free(output)
    let event = gpu.launch2(paint, ((out_count + 63) / 64), 64, gpu.slice(output, 0, out_count), out_count)
    gpu.wait(event)
    let words: Vec<u32> = gpu.download_u32(output)
    let mut idx = 0
    while idx < out_count {
        out_rgba_out[idx] = words[idx]
        idx = idx + 1
    }
    return 0
}
"#;

    std::fs::create_dir_all(clif_root.join("src")).expect("project dir should be created");
    std::fs::write(clif_root.join("fozzy.toml"), manifest).expect("manifest should be written");
    std::fs::write(clif_root.join("src/lib.fzy"), source).expect("source should be written");

    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift large u32 readback library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let host_source = r#"
#include <stdint.h>

int32_t run(uint32_t* out_rgba_out, uintptr_t out_rgba_len, int32_t out_count);

int main(void) {
  static uint32_t out[12544];
  int32_t status = run(out, sizeof(out), 12544);
  if (status != 0) return 11;
  if (out[0] != 511u) return 12;
  if (out[1] != 767u) return 13;
  if (out[4095] != (uint32_t)(255 + ((4095 + 1) << 8))) return 14;
  if (out[12543] != (uint32_t)(255 + ((12543 + 1) << 8))) return 15;
  return 0;
}
"#;

    compile_and_run_c_host_with_metal(
        host_source,
        cranelift
            .static_lib
            .as_deref()
            .expect("cranelift static lib should exist"),
        &clif_root,
    );

    let _ = std::fs::remove_dir_all(clif_root);
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
            "use core.io;\nuse core.path;\n\nfn main() -> i32 {{\n    let root = \"{quoted_root}\"\n    let src = path.join(root, \"src\")\n    let copied = path.join(root, \"copied.txt\")\n    let staged = path.join(root, \"staged\")\n    let dist = path.join(root, \"dist\")\n    let file_meta = io.metadata(path.join(src, \"a.txt\"))\n    if file_meta.exists != 1 {{ return 10 }}\n    if file_meta.is_file != 1 {{ return 11 }}\n    if file_meta.size != 5 {{ return 12 }}\n    let entries = io.list_dir_entries(src)\n    if io.dir_len(entries) != 2 {{ return 13 }}\n    if io.dir_name(entries, 0) != \"a.txt\" {{ return 14 }}\n    let nested = io.dir_entry(entries, 1)\n    if nested.name != \"nested\" {{ return 15 }}\n    if nested.is_dir != 1 {{ return 16 }}\n    let copied_plan = io.copy_plan(path.join(src, \"a.txt\"), copied, 0)\n    if io.execute_copy(copied_plan) != 0 {{ return 17 }}\n    let dist_plan = io.copy_plan(src, dist, 1)\n    if io.execute_copy(dist_plan) != 0 {{ return 18 }}\n    if io.stage_tree(src, staged) != 0 {{ return 19 }}\n    let dist_nested = io.metadata(path.join(dist, \"nested\"))\n    let staged_nested = io.metadata(path.join(staged, \"nested\"))\n    if dist_nested.is_dir != 1 {{ return 20 }}\n    if staged_nested.is_dir != 1 {{ return 21 }}\n    if io.remove_target(io.remove_plan(dist, 1)) != 0 {{ return 22 }}\n    if io.exists(dist) != 0 {{ return 23 }}\n    if io.remove_target(io.remove_plan(staged, 1)) != 0 {{ return 24 }}\n    if io.exists(staged) != 0 {{ return 25 }}\n    return 0\n}}\n"
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
fn parse_program_imports_symbols_from_path_dependency_library_targets() {
    let project_name = format!(
        "fozzylang-dep-lib-import-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    let dep_dir = root.join("deps/util");
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::create_dir_all(dep_dir.join("src/metrics")).expect("dep src dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use util;\nfn main() -> i32 {\n    return util.score()\n}\n",
    )
    .expect("source should be written");
    std::fs::write(
        dep_dir.join("fozzy.toml"),
        "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"util\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("dep manifest should be written");
    std::fs::write(
        dep_dir.join("src/lib.fzy"),
        "mod metrics;\npub fn score() -> i32 {\n    return metrics.score()\n}\n",
    )
    .expect("dep lib should be written");
    std::fs::write(
        dep_dir.join("src/metrics/mod.fzy"),
        "pub fn score() -> i32 {\n    return 7\n}\n",
    )
    .expect("dep module should be written");

    let parsed = parse_program(&root.join("src/main.fzy")).expect("project should parse");
    let qualified = parsed
        .module
        .items
        .iter()
        .find_map(|item| match item {
            ast::Item::Function(function) if function.name == "util.score" => Some(function),
            _ => None,
        })
        .expect("dependency library function should be qualified into the merged program");
    assert!(qualified.is_pub);

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

    let output = emit_ir(&path, None).expect("emit ir should run");
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
    assert_ne!(first.combined_source(), second.combined_source());

    let _ = std::fs::remove_file(path);
}

#[test]
fn parse_program_cache_invalidates_on_imported_module_change() {
    let project_name = format!(
        "fozzylang-import-cache-{}",
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
        "mod services;\nfn main() -> i32 {\n    return services.boot()\n}\n",
    )
    .expect("main source should be written");
    std::fs::write(
        root.join("src/services/mod.fzy"),
        "pub fn boot() -> i32 {\n    return 5\n}\n",
    )
    .expect("imported module should be written");

    let first = parse_program(&root.join("src/main.fzy")).expect("first parse should succeed");
    std::fs::write(
        root.join("src/services/mod.fzy"),
        "pub fn boot() -> i32 {\n    return 8\n}\n\npub fn extra() -> i32 {\n    return 1\n}\n",
    )
    .expect("imported module should mutate");
    let second = parse_program(&root.join("src/main.fzy")).expect("second parse should succeed");
    assert_ne!(first.combined_source(), second.combined_source());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn native_lowerability_malformed_program_reports_diagnostics_without_panicking() {
    let source = "fn main() -> i32 {\n    return missing_call()\n}\n";
    let module = parser::parse(source, "phase_guard").expect("parse should succeed");
    let diagnostics = std::panic::catch_unwind(|| super::native_lowerability_diagnostics(&module));
    assert!(
        diagnostics.is_ok(),
        "native lowerability should not panic on unresolved calls"
    );
    let diagnostics = diagnostics.expect("native lowerability should return diagnostics");
    assert!(
        diagnostics.iter().any(|diag| diag
            .message
            .contains("native backend cannot execute unresolved call")),
        "expected unresolved-call diagnostic, got {:?}",
        diagnostics
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn compiler_phase_lockin_fixture_parses_lowers_and_links_across_backends() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/compiler_phase_lockin");
    let parsed = parse_program(&root.join("src/main.fzy")).expect("fixture project should parse");
    assert!(
        parsed.module.items.iter().any(
            |item| matches!(item, ast::Item::Function(function) if function.name == "services.boot")
        ),
        "flattened module should include services.boot"
    );
    assert!(
        parsed
            .module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Function(function) if function.name == "model.types.flavor_score")),
        "flattened module should include model.types.flavor_score"
    );

    let (_typed, fir) = super::lower_fir_cached(&parsed);
    let llvm = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
    let cranelift =
        lower_backend_ir(&fir, BackendKind::Cranelift).expect("cranelift lowering should succeed");
    assert!(llvm.contains("@services_boot()"));
    assert!(llvm.contains("@model_types_flavor_score()"));
    assert!(cranelift.contains("services_boot"));
    assert!(cranelift.contains("model_types_flavor_score"));

    let artifact = compile_file(&root, BuildProfile::Dev).expect("fixture build should succeed");
    assert_eq!(artifact.status, "ok");
    assert_eq!(
        artifact.dependency_graph_hash.as_deref(),
        refresh_lockfile(&root).ok().as_deref()
    );
}

#[test]
fn compiler_phase_lockin_fixture_supports_user_module_wildcard_imports() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/compiler_phase_lockin");
    let parsed = parse_program(&root.join("src/main.fzy")).expect("fixture project should parse");
    let (_typed, fir) = super::lower_fir_cached(&parsed);
    assert_eq!(
        fir.type_errors, 0,
        "wildcard phase fixture should stay type-clean: {:?}",
        fir.type_error_details
    );
    assert!(
        parsed
            .module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Function(function) if function.name == "services.auth.login")),
        "flattened module should include wildcard-imported nested module function source"
    );
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
fn native_runtime_documented_contract_surface_matches_shim_symbols() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
    for (callee, expected_arg_ownership, expected_linearity, expected_snippet) in [
        (
            "http.stream_close",
            "consume_arg0",
            "consumes_linear_handle",
            "int32_t fz_native_http_stream_close(int32_t handle)",
        ),
        (
            "http.websocket_close",
            "consume_arg0_borrow_close_payload",
            "consumes_linear_handle",
            "int32_t fz_native_net_websocket_close(int32_t ws_handle, int32_t code, int32_t reason_id)",
        ),
        (
            "proc.close",
            "consume_arg0",
            "consumes_linear_handle",
            "int32_t fz_native_proc_close(int32_t handle)",
        ),
        (
            "proc.wait",
            "borrow_handle_timeout",
            "observes_linear_handle",
            "int32_t fz_native_proc_wait(int32_t handle, int32_t timeout_ms)",
        ),
        (
            "proc.poll",
            "borrow_handle",
            "observes_linear_handle",
            "int32_t fz_native_proc_poll(int32_t handle)",
        ),
        (
            "task.group_join_all",
            "consume_arg0",
            "consumes_linear_handle",
            "int32_t fz_native_task_group_join_all(int32_t group_id)",
        ),
        (
            "task.group_cancel",
            "consume_arg0",
            "consumes_linear_handle",
            "int32_t fz_native_task_group_cancel(int32_t group_id)",
        ),
        (
            "fs.atomic_write",
            "borrow_path_bytes",
            "nonlinear",
            "int32_t fz_native_fs_atomic_write(int32_t path_id, int32_t body_id)",
        ),
        (
            "storage.atomic_append",
            "borrow_target_bytes",
            "nonlinear",
            "int32_t fz_native_storage_atomic_append(int32_t path_id, int32_t line_id)",
        ),
    ] {
        let import = native_runtime_import_for_callee(callee)
            .unwrap_or_else(|| panic!("expected native runtime import for `{callee}`"));
        let contract = native_runtime_contract_for_callee(callee)
            .unwrap_or_else(|| panic!("expected native runtime contract for `{callee}`"));
        assert_eq!(contract.symbol, import.symbol, "symbol drift for {callee}");
        assert_eq!(
            contract.arg_ownership, expected_arg_ownership,
            "arg ownership drift for {callee}"
        );
        assert_eq!(
            contract.linearity, expected_linearity,
            "linearity drift for {callee}"
        );
        assert!(
            shim.contains(expected_snippet),
            "runtime shim is missing `{expected_snippet}` for {callee}"
        );
    }
}

#[test]
fn documented_native_runtime_contract_surface_has_expected_metadata() {
    for (callee, arity, arg_ownership, blocking, linearity, capability, error, trace) in [
        (
            "http.stream_close",
            1,
            "consume_arg0",
            "nonblocking",
            "consumes_linear_handle",
            "http",
            "runtime_status_with_last_error",
            "emit_runtime_event",
        ),
        (
            "http.websocket_close",
            3,
            "consume_arg0_borrow_close_payload",
            "nonblocking",
            "consumes_linear_handle",
            "http",
            "runtime_status_with_last_error",
            "emit_runtime_event",
        ),
        (
            "proc.close",
            1,
            "consume_arg0",
            "nonblocking",
            "consumes_linear_handle",
            "proc",
            "runtime_status_with_last_error",
            "emit_runtime_event",
        ),
        (
            "proc.wait",
            2,
            "borrow_handle_timeout",
            "may_block",
            "observes_linear_handle",
            "proc",
            "runtime_status_with_last_error",
            "emit_runtime_event",
        ),
        (
            "proc.poll",
            1,
            "borrow_handle",
            "nonblocking",
            "observes_linear_handle",
            "proc",
            "runtime_status_with_last_error",
            "emit_runtime_event",
        ),
        (
            "task.group_join_all",
            1,
            "consume_arg0",
            "may_block",
            "consumes_linear_handle",
            "thread",
            "none",
            "emit_runtime_event",
        ),
        (
            "task.group_cancel",
            1,
            "consume_arg0",
            "may_block",
            "consumes_linear_handle",
            "thread",
            "none",
            "emit_runtime_event",
        ),
        (
            "fs.atomic_write",
            2,
            "borrow_path_bytes",
            "may_block",
            "nonlinear",
            "fs",
            "runtime_status_with_last_error",
            "emit_runtime_event",
        ),
        (
            "storage.atomic_append",
            2,
            "borrow_target_bytes",
            "may_block",
            "nonlinear",
            "storage",
            "runtime_status_with_last_error",
            "emit_runtime_event",
        ),
    ] {
        let contract = native_runtime_contract_for_callee(callee)
            .unwrap_or_else(|| panic!("expected runtime contract for `{callee}`"));
        assert_eq!(contract.arity, arity, "arity drift for {callee}");
        assert_eq!(
            contract.arg_ownership, arg_ownership,
            "arg ownership drift for {callee}"
        );
        assert_eq!(
            contract.blocking_behavior, blocking,
            "blocking behavior drift for {callee}"
        );
        assert_eq!(
            contract.linearity, linearity,
            "linearity drift for {callee}"
        );
        assert_eq!(
            contract.required_capability, capability,
            "required capability drift for {callee}"
        );
        assert_eq!(
            contract.error_behavior, error,
            "error behavior drift for {callee}"
        );
        assert_eq!(
            contract.trace_behavior, trace,
            "trace behavior drift for {callee}"
        );
    }
}

#[test]
fn native_runtime_contract_markdown_surface_matches_expected_metadata() {
    let value = super::build_native_runtime_contracts_json();
    let markdown = super::render_native_runtime_contracts_markdown(&value);
    assert!(markdown.contains("# Native Runtime Contracts"));
    for snippet in [
        "| `http.stream_close` | `fz_native_http_stream_close` | 1 | `consume_arg0` | `status` | `http` | `consumes_linear_handle` | `runtime_status_with_last_error` | `emit_runtime_event` | `nonblocking` |",
        "| `proc.wait` | `fz_native_proc_wait` | 2 | `borrow_handle_timeout` | `status` | `proc` | `observes_linear_handle` | `runtime_status_with_last_error` | `emit_runtime_event` | `may_block` |",
        "| `fs.atomic_write` | `fz_native_fs_atomic_write` | 2 | `borrow_path_bytes` | `status` | `fs` | `nonlinear` | `runtime_status_with_last_error` | `emit_runtime_event` | `may_block` |",
        "| `storage.atomic_append` | `fz_native_storage_atomic_append` | 2 | `borrow_target_bytes` | `status` | `storage` | `nonlinear` | `runtime_status_with_last_error` | `emit_runtime_event` | `may_block` |",
    ] {
        assert!(
            markdown.contains(snippet),
            "native runtime contract markdown missing `{snippet}`"
        );
    }
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
    assert!(shim.contains("int32_t fz_native_crypto_base64_url_encode(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_crypto_base64_url_decode(int32_t input_id)"));
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
    assert!(shim.contains("int32_t fz_native_fs_open(int32_t path_id)"));
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
        "use core.crypto;\nuse core.error;\nuse core.security;\n\nfn main() -> i32 {\n    let digest = crypto.sha256(\"abc\")\n    let mac = crypto.hmac_sha256(\"key\", \"The quick brown fox jumps over the lazy dog\")\n    let encoded = crypto.base64_encode(\"fozzy\")\n    let decoded = crypto.base64_decode(encoded)\n    let crypto_url = crypto.base64_url_encode(\"ok\")\n    let crypto_roundtrip = crypto.base64_url_decode(crypto_url)\n    let url = security.base64_url_encode(\"ok\")\n    let roundtrip = security.base64_url_decode(url)\n    let hex_token = crypto.random_hex(16)\n    let b64_token = crypto.random_base64(16)\n    if digest != \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\" { return 11 }\n    if mac != \"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8\" { return 13 }\n    if encoded != \"Zm96enk=\" || decoded != \"fozzy\" { return 17 }\n    if crypto_url != \"b2s\" || crypto_roundtrip != \"ok\" { return 18 }\n    if url != \"b2s\" || roundtrip != \"ok\" { return 19 }\n    if str.len(hex_token) != 32 || str.len(b64_token) != 24 { return 23 }\n    if crypto.constant_time_eq(digest, digest) != 1 { return 29 }\n    if crypto.constant_time_eq(digest, mac) != 0 { return 31 }\n    if security.verify_value(\"key\", \"The quick brown fox jumps over the lazy dog\", mac) != 1 { return 37 }\n    if crypto.base64_decode(\"A===\") != \"\" { return 41 }\n    if error.code() == 0 || error.message() == \"\" { return 43 }\n    if security.base64_url_decode(\"A\") != \"\" { return 47 }\n    if error.code() == 0 || error.message() == \"\" { return 49 }\n    if crypto.base64_decode(encoded) != \"fozzy\" { return 53 }\n    if error.code() != 0 || error.message() != \"\" { return 59 }\n    return 0\n}\n",
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
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
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
        &[],
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

    let shim = render_native_runtime_shim(&[], &[], &exports, &[]);
    assert!(shim.contains("extern int32_t fz_bench_async(int32_t seed);"));
    assert!(!shim.contains("extern int32_t api.ffi.fz_bench_async"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn native_runtime_shim_uses_documented_bind_defaults_and_visibility() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
    assert!(shim.contains("int port = 8787;"));
    assert!(shim.contains("[fz-runtime] listen active addr=%s port=%d"));
    assert!(shim.contains("host_source=%s port_source=%s"));
}

#[test]
fn native_runtime_shim_sanitizes_invalid_json_http_bodies() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
    assert!(shim.contains("invalid_json_payload"));
    assert!(shim.contains("http.write_json sanitized non-JSON body"));
}

#[test]
fn native_runtime_shim_bootstraps_dotenv_for_env_and_http() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
    assert!(shim.contains("FZ_DOTENV_PATH"));
    assert!(shim.contains("fz_http_header_upsert"));
    assert!(shim.contains("content-type"));
    assert!(shim.contains("--connect-timeout"));
    assert!(shim.contains("--max-time"));
    assert!(shim.contains("unable to exec curl"));
}

#[test]
fn native_runtime_shim_declares_shared_helpers_before_first_use() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);

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
fn verify_gpu_surface_stays_backend_neutral_before_live_adapter_lands() {
    let file_name = format!(
        "fozzylang-gpu-verify-neutral-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.gpu;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 4)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    gpu.wait(event)\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(
        !output
            .diagnostic_details
            .iter()
            .any(|diag| diag.message.contains(
                "gpu backend `metal` is declared in the architecture but not yet executable"
            )),
        "verify should stay backend-neutral, got {:?}",
        output
            .diagnostic_details
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        !output.diagnostic_details.iter().any(|diag| diag
            .message
            .contains("native backend cannot execute unresolved call `gpu.")),
        "verify should not regress to unresolved GPU call diagnostics, got {:?}",
        output
            .diagnostic_details
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn native_build_routes_gpu_launch_through_truthful_backend_path() {
    let project_name = format!(
        "fozzylang-gpu-build-declared-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_build_declared\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_build_declared\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 4)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    gpu.wait(event)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("gpu build should return artifact diagnostics");
    if cfg!(target_vendor = "apple") {
        assert_eq!(artifact.status, "ok");
        let output = artifact
            .output
            .as_deref()
            .expect("gpu build output should exist on Apple");
        assert_eq!(run_native_exit(output), 0);
    } else {
        assert_eq!(artifact.status, "error");
        assert!(
            artifact
                .diagnostic_details
                .iter()
                .any(|diag| diag.message.contains(
                    "gpu backend `metal` is declared in the architecture but not yet executable"
                )),
            "expected declared-but-not-executable diagnostic, got {:?}",
            artifact
                .diagnostic_details
                .iter()
                .map(|diag| diag.message.clone())
                .collect::<Vec<_>>()
        );
    }
    assert!(
        !artifact.diagnostic_details.iter().any(|diag| diag
            .message
            .contains("native backend cannot execute unresolved call `gpu.")),
        "GPU build should not regress to unresolved GPU call diagnostics, got {:?}",
        artifact
            .diagnostic_details
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_host_gpu_lifecycle_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-host-lifecycle-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_host_lifecycle\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_host_lifecycle\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nhost fn main() -> i32 {\n    let count = gpu.device_count()\n    if count < 1 {\n        return 11\n    }\n    let dev = gpu.default_device()\n    let name = gpu.device_name(dev)\n    let bytes = gpu.device_memory_bytes(dev)\n    let zero: i64 = 0\n    if str.len(name) <= 0 {\n        return 12\n    }\n    if bytes <= zero {\n        return 13\n    }\n    let buf = gpu.alloc_f32(dev, 16)\n    let window = gpu.slice(buf, 4, 8)\n    discard window\n    gpu.free(buf)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal host lifecycle build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal host lifecycle output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_host_gpu_upload_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-host-upload-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_host_upload\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_host_upload\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let buf: GpuBuffer<f32> = gpu.upload_f32(dev, values)\n    let window: GpuSlice<f32> = gpu.slice(buf, 1, 2)\n    discard window\n    gpu.free(buf)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal host upload build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal host upload output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_host_gpu_download_roundtrip_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-host-download-roundtrip-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_host_download_roundtrip\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_host_download_roundtrip\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let buf: GpuBuffer<f32> = gpu.upload_f32(dev, values)\n    let downloaded: Vec<f32> = gpu.download_f32(buf)\n    gpu.free(buf)\n    if downloaded[0] != values[0] {\n        return 11\n    }\n    if downloaded[1] != values[1] {\n        return 12\n    }\n    if downloaded[2] != values[2] {\n        return 13\n    }\n    if downloaded[3] != values[3] {\n        return 14\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal host download roundtrip build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal host download roundtrip output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_gpu_kernel_suite_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-kernel-suite-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_kernel_suite\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_kernel_suite\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nkernel fn vector_add(left: GpuSlice<f32>, right: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = left[i] + right[i]\n    }\n}\nkernel fn saxpy(x: GpuSlice<f32>, y: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = x[i] * 2.0f32 + y[i]\n    }\n}\nkernel fn relu(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        let value = input[i]\n        if value > 0.0f32 {\n            output[i] = value\n        } else {\n            output[i] = 0.0f32\n        }\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n\n    let left: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let right: [f32; 4] = simd.f32x4_store(simd.f32x4_new(10.0, 20.0, 30.0, 40.0))\n    let left_buf: GpuBuffer<f32> = gpu.upload_f32(dev, left)\n    let right_buf: GpuBuffer<f32> = gpu.upload_f32(dev, right)\n    let add_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let add_event = gpu.launch4(vector_add, 1, 64, gpu.slice(left_buf, 0, 4), gpu.slice(right_buf, 0, 4), gpu.slice(add_buf, 0, 4), 4)\n    gpu.wait(add_event)\n    let add_out: Vec<f32> = gpu.download_f32(add_buf)\n    gpu.free(left_buf)\n    gpu.free(right_buf)\n    gpu.free(add_buf)\n    if add_out[0] != 11.0f32 || add_out[1] != 22.0f32 || add_out[2] != 33.0f32 || add_out[3] != 44.0f32 {\n        return 11\n    }\n\n    let saxpy_x: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let saxpy_y: [f32; 4] = simd.f32x4_store(simd.f32x4_new(5.0, 6.0, 7.0, 8.0))\n    let saxpy_x_buf: GpuBuffer<f32> = gpu.upload_f32(dev, saxpy_x)\n    let saxpy_y_buf: GpuBuffer<f32> = gpu.upload_f32(dev, saxpy_y)\n    let saxpy_out_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let saxpy_event = gpu.launch4(saxpy, 1, 64, gpu.slice(saxpy_x_buf, 0, 4), gpu.slice(saxpy_y_buf, 0, 4), gpu.slice(saxpy_out_buf, 0, 4), 4)\n    gpu.wait(saxpy_event)\n    let saxpy_out: Vec<f32> = gpu.download_f32(saxpy_out_buf)\n    gpu.free(saxpy_x_buf)\n    gpu.free(saxpy_y_buf)\n    gpu.free(saxpy_out_buf)\n    if saxpy_out[0] != 7.0f32 || saxpy_out[1] != 10.0f32 || saxpy_out[2] != 13.0f32 || saxpy_out[3] != 16.0f32 {\n        return 12\n    }\n\n    let relu_values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(-1.0, -2.0, 3.0, 4.0))\n    let relu_in_buf: GpuBuffer<f32> = gpu.upload_f32(dev, relu_values)\n    let relu_out_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let relu_event = gpu.launch3(relu, 1, 64, gpu.slice(relu_in_buf, 0, 4), gpu.slice(relu_out_buf, 0, 4), 4)\n    gpu.wait(relu_event)\n    let relu_out: Vec<f32> = gpu.download_f32(relu_out_buf)\n    gpu.free(relu_in_buf)\n    gpu.free(relu_out_buf)\n    if relu_out[0] != 0.0f32 || relu_out[1] != 0.0f32 || relu_out[2] != 3.0f32 || relu_out[3] != 4.0f32 {\n        return 13\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal kernel suite build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal kernel suite output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_gpu_image_brightness_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-image-brightness-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_image_brightness\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_image_brightness\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nkernel fn brighten(input: GpuSlice<f32>, delta: f32, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        let value = input[i] + delta\n        if value > 1.0f32 {\n            output[i] = 1.0f32\n        } else {\n            output[i] = value\n        }\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let pixels: [f32; 4] = simd.f32x4_store(simd.f32x4_new(0.0, 0.25, 0.75, 0.5))\n    let input_buf: GpuBuffer<f32> = gpu.upload_f32(dev, pixels)\n    let output_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let event = gpu.launch4(brighten, 1, 64, gpu.slice(input_buf, 0, 4), 0.25f32, gpu.slice(output_buf, 0, 4), 4)\n    gpu.wait(event)\n    let output: Vec<f32> = gpu.download_f32(output_buf)\n    gpu.free(input_buf)\n    gpu.free(output_buf)\n    if output[0] != 0.25f32 || output[1] != 0.5f32 || output[2] != 1.0f32 || output[3] != 0.75f32 {\n        return 41\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal image brightness build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal image brightness output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_gpu_runtime_failure_reports_stable_diagnostics() {
    let project_name = format!(
        "fozzylang-gpu-runtime-failure-diagnostics-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_runtime_failure_diagnostics\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_runtime_failure_diagnostics\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    let output = gpu.alloc_f32(dev, 4)\n    let event = gpu.launch3(copy, 1, 1000000, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    gpu.wait(event)\n    gpu.free(input)\n    gpu.free(output)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal runtime failure diagnostics build should succeed");
    assert_eq!(artifact.status, "ok");
    let output = Command::new(
        artifact
            .output
            .as_deref()
            .expect("metal runtime failure diagnostics output should exist"),
    )
    .env("FZ_NATIVE_DEBUG_ERRORS", "1")
    .output()
    .expect("native artifact should execute");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr
        .contains("gpu.launch failed: block 1000000 exceeds Metal max threads-per-threadgroup"));
    assert!(stderr.contains("gpu.wait failed: invalid GPU event handle"));

    let _ = std::fs::remove_dir_all(root);
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

    let output = emit_ir(&root, None).expect("emit ir should run");
    let ir = output.backend_ir.expect("backend ir should be available");
    assert!(ir.contains("@services_web_start_listener"));
    assert!(!ir.contains("@web_start_listener"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn emit_ir_can_target_a_single_backend_without_breaking_default_dual_output() {
    let file_name = format!(
        "fozzylang-ir-single-backend-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
        .expect("temp source should be written");

    let llvm_output = emit_ir(&path, Some("llvm")).expect("llvm emit ir should run");
    let llvm_ir = llvm_output
        .backend_ir
        .expect("llvm backend ir should be available");
    assert!(llvm_ir.contains("backend=llvm"));
    assert!(!llvm_ir.contains("backend=cranelift"));

    let cranelift_output = emit_ir(&path, Some("cranelift")).expect("cranelift emit ir should run");
    let cranelift_ir = cranelift_output
        .backend_ir
        .expect("cranelift backend ir should be available");
    assert!(cranelift_ir.contains("backend=cranelift"));
    assert!(!cranelift_ir.contains("backend=llvm"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn benchmark_result_fixture_stays_buildable_under_release_llvm_gate() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root should resolve");
    let benchmark = repo_root.join("examples/benchmarks/result_scratch_bench.fzy");

    let artifact = compile_file_with_backend(&benchmark, BuildProfile::Release, Some("llvm"))
        .expect("benchmark fixture should compile");
    assert_eq!(artifact.status, "ok");
    assert!(artifact.output.is_some());
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
