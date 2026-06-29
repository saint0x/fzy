use super::{compile_file, verify_file, BuildProfile};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn run_native_exit(exe: &Path) -> i32 {
    Command::new(exe)
        .status()
        .expect("native artifact should execute")
        .code()
        .expect("native artifact should exit with code")
}

pub(super) fn run_native_status(exe: &Path) -> std::process::ExitStatus {
    Command::new(exe)
        .status()
        .expect("native artifact should execute")
}

pub(super) fn run_native_output(exe: &Path) -> std::process::Output {
    Command::new(exe)
        .output()
        .expect("native artifact should execute")
}

pub(super) fn nm_symbols(path: &Path) -> Vec<String> {
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

pub(super) fn compile_and_run_c_host(source: &str, static_lib: &Path, work_dir: &Path) {
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
pub(super) fn compile_and_run_c_host_with_metal(source: &str, static_lib: &Path, work_dir: &Path) {
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
        "use core.fs;\nuse core.security;\nfn main() -> i32 {\n    discard fs.write_file(\"../secrets.txt\", \"oops\")\n    discard fs.write_file(\"/tmp/out.txt\", \"temp\")\n    let signer = security.default_signer()\n    if security.sign(signer, \"k\", \"v\") == security.sign(signer, \"k\", \"v\") {\n        return 0\n    }\n    return 1\n}\n",
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
        "use core.fs;\nuse core.http;\nuse core.io;\nuse core.proc;\nuse core.storage;\nuse core.thread;\nfn worker() -> i32 {\n    return 1\n}\nfn main() -> i32 {\n    let conn = http.accept()\n    discard http.write_json(conn, 200, \"{}\")\n    let stream = http.post_json_stream(\"https://example.com\", \"{}\")\n    discard http.stream_close(stream)\n    let argv = proc.argv_new()\n    let env = proc.env_new()\n    let handle = proc.spawn_cmd(\"echo\", argv, env, \"\")\n    discard proc.close(handle)\n    let task = spawn(worker)\n    discard join(task)\n    let ctx_task = thread.spawn_ctx(worker, 7)\n    discard join(ctx_task)\n    let store = storage.kv_open(\"session.kv\")\n    discard storage.kv_close(store)\n    let file = fs.open(\"/tmp/fzy-handle-contract-file.txt\")\n    discard fs.write(file, \"hello\")\n    discard fs.close(file)\n    let payload = json.parse(\"{}\")\n    let items = json.to_list(payload)\n    let table = map.new()\n    let raw = io.read_bytes(\"/tmp/fzy-handle-contract-file.txt\")\n    discard io.write_bytes(\"/tmp/fzy-handle-contract-file-copy.txt\", raw)\n    discard list.len(items)\n    discard map.len(table)\n    return 0\n}\n",
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
    assert!(handle_contracts.contains("\"name\": \"BytesHandle\""));
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
    assert!(runtime_contracts.contains("\"callee\": \"fs.read_bytes\""));
    assert!(runtime_contracts.contains("\"returnOwnership\": \"owned_bytes_handle\""));
    assert!(runtime_contracts.contains("\"callee\": \"bytes.len\""));
    assert!(runtime_contracts.contains("\"callee\": \"list.len\""));
    assert!(runtime_contracts.contains("\"linearity\": \"observes_handle\""));
    assert!(runtime_contracts.contains("\"callee\": \"fs.close\""));
    assert!(runtime_contracts.contains("\"callee\": \"fs.read\""));
    assert!(runtime_contracts.contains("\"callee\": \"thread.spawn_ctx\""));
    assert!(runtime_contracts.contains("\"returnOwnership\": \"owned_task_handle\""));
}
