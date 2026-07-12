use super::super::llvm::lower_llvm_ir;
use super::*;

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
    assert!(
        artifact
            .diagnostic_details
            .iter()
            .any(|d| d.message.contains("does not support async C export"))
    );

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
fn compile_file_reuses_successful_build_cache_for_warm_noop() {
    let project_name = format!(
        "fozzylang-build-cache-{}",
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
        "fn main() -> i32 {\n    return 1\n}\n",
    )
    .expect("source should be written");

    let first = compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
    assert_eq!(first.status, "ok");
    let output = first.output.expect("first build should produce output");
    std::fs::remove_file(&output).expect("output should be removable");

    let second = compile_file(&root, BuildProfile::Dev).expect("second build should recover");
    assert_eq!(second.status, "ok");
    assert!(
        second.output.as_ref().is_some_and(|path| path.exists()),
        "second build should recreate an executable when outputs are missing"
    );

    let cache_path = root.join(".fz/build/demo.bin.cranelift.buildcache.json");
    let cache_text = std::fs::read_to_string(&cache_path).expect("build cache should exist");
    let cache_json: serde_json::Value =
        serde_json::from_str(&cache_text).expect("build cache should be valid json");
    let source_stamps = cache_json
        .get("source_stamps")
        .and_then(|value| value.as_array())
        .expect("build cache should record source stamps");
    assert!(
        !source_stamps.is_empty(),
        "build cache should track source inputs for warm validation"
    );

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
    let report = super::build_native_runtime_contracts_report();
    let markdown = super::render_native_runtime_contracts_markdown(&report);
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
        "use core.security;\nfn main() -> i32 {\n    let signer = security.default_signer()\n    if security.verify(signer, \"k\", \"v\", security.sign(signer, \"k\", \"v\")) == 1 {\n        return 0\n    }\n    return 13\n}\n",
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
    assert!(
        function_names
            .iter()
            .any(|name| name == "security.default_signer")
    );
    assert!(function_names.iter().any(|name| name == "security.sign"));
    assert!(function_names.iter().any(|name| name == "security.verify"));

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
        "use core.security;\nfn main() -> i32 {\n    let signer = security.default_signer()\n    let token = security.opaque_token(16)\n    if str.contains(token, \"=\") == 0 && security.verify(signer, \"k\", \"v\", security.sign(signer, \"k\", \"v\")) == 1 {\n        return 0\n    }\n    return 13\n}\n",
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
        "use core.security;\nfn main() -> i32 {\n    let signer = security.default_signer()\n    let token = security.opaque_token(16)\n    if str.contains(token, \"=\") == 0 && security.verify(signer, \"k\", \"v\", security.sign(signer, \"k\", \"v\")) == 1 {\n        return 0\n    }\n    return 13\n}\n",
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
    assert!(
        shim.contains("int32_t fz_native_http_post_json(int32_t endpoint_id, int32_t body_id)")
    );
    assert!(shim.contains(
        "int32_t fz_native_http_post_json_capture(int32_t endpoint_id, int32_t body_id)"
    ));
    assert!(
        shim.contains(
            "int32_t fz_native_http_post_json_stream(int32_t endpoint_id, int32_t body_id)"
        )
    );
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
    assert!(
        shim.contains(
            "int32_t fz_native_crypto_constant_time_eq(int32_t left_id, int32_t right_id)"
        )
    );
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
        "use core.crypto;\nuse core.error;\nuse core.security;\n\nfn main() -> i32 {\n    let digest = crypto.sha256(\"abc\")\n    let mac = crypto.hmac_sha256(\"key\", \"The quick brown fox jumps over the lazy dog\")\n    let encoded = crypto.base64_encode(\"fozzy\")\n    let decoded = crypto.base64_decode(encoded)\n    let crypto_url = crypto.base64_url_encode(\"ok\")\n    let crypto_roundtrip = crypto.base64_url_decode(crypto_url)\n    let hex_token = crypto.random_hex(16)\n    let b64_token = crypto.random_base64(16)\n    let signer = security.default_signer()\n    let signed = security.sign(signer, \"key\", \"The quick brown fox jumps over the lazy dog\")\n    let opaque = security.opaque_token(16)\n    if digest != \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\" { return 11 }\n    if mac != \"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8\" { return 13 }\n    if encoded != \"Zm96enk=\" || decoded != \"fozzy\" { return 17 }\n    if crypto_url != \"b2s\" || crypto_roundtrip != \"ok\" { return 18 }\n    if str.len(hex_token) != 32 || str.len(b64_token) != 24 { return 23 }\n    if str.len(opaque) != 22 || str.contains(opaque, \"=\") == 1 || str.contains(opaque, \"+\") == 1 || str.contains(opaque, \"/\") == 1 { return 24 }\n    if crypto.constant_time_eq(digest, digest) != 1 { return 29 }\n    if crypto.constant_time_eq(digest, mac) != 0 { return 31 }\n    if security.verify(signer, \"key\", \"The quick brown fox jumps over the lazy dog\", signed) != 1 { return 37 }\n    if str.starts_with(signed, \"v1:\") != 1 { return 38 }\n    if crypto.base64_decode(\"A===\") != \"\" { return 41 }\n    if error.code() == 0 || error.message() == \"\" { return 43 }\n    if security.verify(signer, \"key\", \"The quick brown fox jumps over the lazy dog\", mac) != 0 { return 47 }\n    if crypto.base64_decode(encoded) != \"fozzy\" { return 53 }\n    if error.code() != 0 || error.message() != \"\" { return 59 }\n    return 0\n}\n",
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
    assert!(
        shim.contains("int32_t flush_async_start(int32_t code, fz_async_handle_t* handle_out)")
    );
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
fn native_runtime_shim_uses_explicit_bind_addr_and_numeric_listener_logging() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
    assert!(shim.contains("invalid addr `%s` (expected host:port or [ipv6]:port)"));
    assert!(shim.contains("getaddrinfo(host, service, &hints, &results)"));
    assert!(shim.contains("[fz-runtime] listen active addr=%s port=%s"));
}

#[test]
fn native_runtime_shim_sanitizes_invalid_json_http_bodies() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
    assert!(shim.contains("invalid_json_payload"));
    assert!(shim.contains("http.write_json sanitized non-JSON body"));
}
