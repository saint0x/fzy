use super::*;

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
