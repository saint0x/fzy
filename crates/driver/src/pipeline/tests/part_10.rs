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

