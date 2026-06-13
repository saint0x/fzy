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

