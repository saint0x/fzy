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

