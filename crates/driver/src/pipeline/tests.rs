use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    collect_async_c_exports, compile_file, compile_file_with_backend,
    compile_library_with_backend, derive_anchors_from_message, emit_ir, lower_backend_ir,
    lower_llvm_ir, native_mangle_symbol, native_runtime_import_contract_errors,
    native_runtime_import_for_callee, parse_program, refresh_lockfile, verify_file,
    BackendKind, BuildProfile,
};
use super::native_runtime_support::{render_native_runtime_shim, NativeAsyncExport};

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
fn compile_library_rejects_explicit_llvm_backend_override() {
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

    let error = compile_library_with_backend(&root, BuildProfile::Release, Some("llvm"))
        .expect_err("llvm backend override should be rejected for --lib");
    assert!(error
        .to_string()
        .contains("not supported for `fz build --lib`"));

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
    std::fs::write(root.join("services/mod.fzy"), "mod kernels;\n")
        .expect("mod should be written");
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
    let clif = lower_backend_ir(&fir, BackendKind::Cranelift)
        .expect("cranelift lowering should succeed");
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
        "mod infra;\nfn main() -> i32 {\n    let listener = http.bind()\n    http.listen(listener)\n    return 0\n}\n",
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
    let error = compile_file(&root, BuildProfile::Dev).expect_err("drift should fail build");
    assert!(error.to_string().contains("lockfile drift detected"));

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
    assert_eq!(artifact.status, "ok");
    assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

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
    assert!(shim.contains("int32_t fz_native_str_contains("));
    assert!(shim.contains("int32_t fz_native_http_header(int32_t key_id, int32_t value_id)"));
    assert!(
        shim.contains("int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id)")
    );
    assert!(shim.contains(
        "int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id)"
    ));
    assert!(shim.contains("int32_t fz_native_http_last_status(void)"));
    assert!(shim.contains("int32_t fz_native_http_last_error(void)"));
    assert!(shim.contains("int32_t fz_native_json_escape(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_json_str(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_json_raw(int32_t input_id)"));
    assert!(shim.contains("int32_t fz_native_json_from_map(int32_t map_handle)"));
    assert!(shim.contains("int32_t fz_native_json_parse(int32_t json_id)"));
    assert!(
        shim.contains("int32_t fz_native_json_get(int32_t json_value_handle, int32_t key_id)")
    );
    assert!(shim
        .contains("int32_t fz_native_json_get_str(int32_t json_value_handle, int32_t key_id)"));
    assert!(
        shim.contains("int32_t fz_native_json_has(int32_t json_value_handle, int32_t key_id)")
    );
    assert!(shim
        .contains("int32_t fz_native_json_path(int32_t json_value_handle, int32_t path_id)"));
    assert!(shim.contains("posix_spawnp"));
    assert!(shim.contains("int32_t fz_native_proc_spawnl("));
    assert!(shim.contains("int32_t fz_native_proc_runl("));
    assert!(shim.contains("int32_t fz_native_proc_poll(int32_t handle)"));
    assert!(
        shim.contains("int32_t fz_native_proc_read_stdout(int32_t handle, int32_t max_bytes)")
    );
    assert!(shim.contains("int32_t fz_native_net_header(int32_t conn_fd, int32_t key_id)"));
    assert!(shim.contains(
        "int32_t fz_native_route_match(int32_t conn_fd, int32_t method_id, int32_t pattern_id)"
    ));
    assert!(shim.contains("int32_t fz_native_fs_read_file(int32_t path_id)"));
    assert!(shim.contains("int32_t fz_native_time_tick(int32_t handle)"));
    assert!(shim.contains("int32_t fz_native_error_code(void)"));
    assert!(shim.contains("int32_t fz_native_log_info(int32_t message_id, int32_t fields_id)"));
    assert!(shim.contains("int32_t fz_native_log_fields_map(int32_t map_handle)"));
    assert!(shim.contains("FD_CLOEXEC"));
    assert!(shim.contains("int32_t fz_native_proc_exit_class(void)"));
    assert!(shim.contains("int32_t fz_native_time_now(void)"));
    assert!(shim.contains("int32_t fz_native_fs_open(void)"));
    assert!(shim.contains("int32_t fz_native_pulse(void)"));
    assert!(shim.contains("static const int fz_task_entry_count = 1;"));
    assert!(shim.contains("fz_spawn_thread_main"));
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
    assert!(
        shim.contains("int32_t flush_async_start(int32_t code, fz_async_handle_t* handle_out)")
    );
    assert!(
        shim.contains("int32_t flush_async_poll(fz_async_handle_t handle, int32_t* done_out)")
    );
    assert!(shim
        .contains("int32_t flush_async_await(fz_async_handle_t handle, int32_t* result_out)"));
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
    assert!(shim.contains("ANTHROPIC_API_KEY missing"));
    assert!(shim.contains("--connect-timeout"));
    assert!(shim.contains("--max-time"));
    assert!(shim.contains("unable to exec curl"));
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
    assert!(root.join(".fz/build/main.o").exists());

    let release = compile_file_with_backend(&root, BuildProfile::Release, None)
        .expect("release build should succeed");
    assert_eq!(release.status, "ok");
    assert!(root.join(".fz/build/main.ll").exists());

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
        "use core.http;\nfn main() -> i32 {\n    let listener = http.bind()\n    http.listen(listener)\n    return 0\n}\n",
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
    let clif = lower_backend_ir(&fir, BackendKind::Cranelift)
        .expect("cranelift lowering should succeed");

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
    let clif = lower_backend_ir(&fir, BackendKind::Cranelift)
        .expect("cranelift lowering should succeed");

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
        "fn main() -> i32 {\n    if str.starts_with(str.slice(\"abcdef\", 1, 3), \"bcd\") == 1 {\n        return str.len(str.slice(\"abcdef\", 1, 3)) + 16\n    }\n    return 0\n}\n",
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
