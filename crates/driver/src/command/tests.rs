#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    use super::super::*;
    use crate::pipeline::IncrementalBuildReport;

    fn run_check_text(source: &str, suffix: &str) -> String {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-diag-{suffix}-{unique}.fzy"));
        std::fs::write(&path, source).expect("source should be written");
        let output = run(Command::Check { path: path.clone() }, Format::Text)
            .expect("check command should run");
        let _ = std::fs::remove_file(path);
        output
    }

    #[test]
    fn version_command_reports_identity_and_compatibility() {
        let output = run(Command::Version, Format::Text).expect("version command should run");
        assert!(output.contains("version:"));
        assert!(output.contains("trace_schema_version:"));
    }

    #[test]
    fn version_command_json_includes_compatibility() {
        let output = run(Command::Version, Format::Json).expect("version command should run");
        let value: serde_json::Value = serde_json::from_str(&output).expect("json should parse");
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            value["compatibility"]["traceSchemaVersion"],
            "fozzy-trace.v4"
        );
    }

    #[test]
    fn inspect_stdlib_process_reports_embedded_source() {
        let output = run(
            Command::InspectStdlib {
                module: "process".to_string(),
            },
            Format::Json,
        )
        .expect("inspect stdlib should run");
        let value: serde_json::Value = serde_json::from_str(&output).expect("json should parse");
        assert_eq!(value["module"], "process");
        assert_eq!(value["parse"], "ok");
        assert!(value["source"]
            .as_str()
            .is_some_and(|source| source.contains("fn argv_or")));
    }

    #[test]
    fn inspect_stdlib_log_and_gpu_exclude_removed_convenience_helpers() {
        let log_output = run(
            Command::InspectStdlib {
                module: "log".to_string(),
            },
            Format::Json,
        )
        .expect("inspect stdlib log should run");
        let log_value: serde_json::Value =
            serde_json::from_str(&log_output).expect("log json should parse");
        let log_source = log_value["source"]
            .as_str()
            .expect("log source should be present");
        assert!(!log_source.contains("request_log("));
        assert!(!log_source.contains("request_log_sampled("));
        assert!(!log_source.contains("request_event("));
        let gpu_source = include_str!("../../../../core/src/gpu.fzy");
        assert!(!gpu_source.contains("slice_bounds_score("));
    }

    #[test]
    fn inspect_stdlib_rejects_internal_util_module() {
        let err = run(
            Command::InspectStdlib {
                module: "util".to_string(),
            },
            Format::Json,
        )
        .expect_err("internal util module should not be inspectable");
        assert!(err
            .to_string()
            .contains("unknown embedded core stdlib module `util`"));
    }

    #[test]
    fn detects_scenario_paths() {
        assert!(is_fozzy_scenario(Path::new("tests/example.fozzy.json")));
        assert!(!is_fozzy_scenario(Path::new("examples/main.fzy")));
    }

    #[test]
    fn parity_covers_primitive_control_flow_fixture() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/primitive_parity/main.fzy");
        let parity = parity_command(&source, 4242, Format::Json).expect("parity should run");
        let parity_json: serde_json::Value =
            serde_json::from_str(&parity).expect("parity json should parse");
        assert_eq!(parity_json["ok"], true);
        assert_eq!(parity_json["kind"], "executable");
        assert_eq!(parity_json["checks"]["sameExitCode"], true);
        assert_eq!(parity_json["checks"]["sameStdout"], true);
        assert_eq!(parity_json["checks"]["sameStderr"], true);
        assert_eq!(parity_json["checks"]["sameVerifierResult"], true);
        assert!(parity_json["backendResults"]["llvm"]["exitCode"].is_number());
        assert!(parity_json["backendResults"]["cranelift"]["exitCode"].is_number());
        assert_eq!(
            parity_json["backendCapabilities"]["cranelift"]["unsupported"][0]["feature"],
            "async_c_export_surface"
        );
    }

    #[test]
    fn parity_command_covers_library_exports_across_backends() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-parity-lib-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"parity_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"parity_lib\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n\n#[ffi_panic(abort)]\npubext c fn mul(left: i32, right: i32) -> i32 {\n    return left * right\n}\n",
        )
        .expect("source should be written");

        let parity = parity_command(&root, 7, Format::Json).expect("library parity should run");
        let parity_json: serde_json::Value =
            serde_json::from_str(&parity).expect("parity json should parse");
        assert_eq!(parity_json["ok"], true);
        assert_eq!(parity_json["kind"], "library");
        assert_eq!(parity_json["checks"]["sameStaticExports"], true);
        assert_eq!(parity_json["checks"]["sameSharedExports"], true);
        assert!(parity_json["backendResults"]["llvm"]["staticExports"].is_array());
        assert!(parity_json["backendResults"]["cranelift"]["sharedExports"].is_array());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn check_and_verify_accept_lib_only_project_roots() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-check-lib-only-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"check_lib_only\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"check_lib_only\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "pub fn helper(value: i32) -> i32 {\n    return value + 1\n}\n",
        )
        .expect("source should be written");

        let check = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("check should succeed for lib-only project");
        let check_json: serde_json::Value =
            serde_json::from_str(&check).expect("check output should parse");
        assert_eq!(check_json["errors"].as_u64(), Some(0));
        assert_eq!(check_json["module"].as_str(), Some("lib"));

        let verify = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should succeed for lib-only project");
        let verify_json: serde_json::Value =
            serde_json::from_str(&verify).expect("verify output should parse");
        assert_eq!(verify_json["errors"].as_u64(), Some(0));
        assert_eq!(verify_json["module"].as_str(), Some("lib"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parity_canary_builds_fzweb_project_with_both_backends() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frameworklib/fzweb");
        let parity = parity_command(&project, 11, Format::Json).expect("fzweb parity should run");
        let parity_json: serde_json::Value =
            serde_json::from_str(&parity).expect("parity json should parse");
        assert_eq!(parity_json["ok"], true);
        assert_eq!(parity_json["kind"], "executable");
        assert_eq!(parity_json["checks"]["sameBuildStatus"], true);
        assert_eq!(parity_json["checks"]["sameVerifierResult"], true);
        assert_eq!(parity_json["checks"]["sameRuntimeBehavior"], true);
    }

    #[test]
    fn formatter_rewrites_trailing_whitespace() {
        let file_name = format!(
            "fozzylang-fmt-{}.fzy",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() {   \n\n\n  return 0   \n}   ")
            .expect("temp source should be written");

        let changed = format_source_file(&path).expect("formatter should run");
        assert!(changed);
        let content = std::fs::read_to_string(&path).expect("formatted file should be readable");
        assert!(!content.contains("   \n"));
        assert!(content.ends_with('\n'));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn formatter_accepts_directory_targets() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-fmt-dir-{suffix}"));
        std::fs::create_dir_all(root.join("nested")).expect("directory should be created");
        let first = root.join("main.fzy");
        let second = root.join("nested/lib.fzy");
        std::fs::write(&first, "fn main() -> i32 {   \n    return 0\n}\n")
            .expect("first source should be written");
        std::fs::write(&second, "fn helper() -> i32 {   \n    return 0\n}\n")
            .expect("second source should be written");

        let changed = format_source_target(&root, false).expect("directory format should succeed");
        assert_eq!(changed.len(), 2);
        let first_content = std::fs::read_to_string(&first).expect("first source should be read");
        let second_content =
            std::fs::read_to_string(&second).expect("second source should be read");
        assert!(!first_content.contains("   \n"));
        assert!(!second_content.contains("   \n"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn formatter_preserves_newline_delimited_control_flow() {
        let file_name = format!(
            "fozzylang-fmt-control-flow-{}.fzy",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "test \"det_surface_score\" {\n    let score = runtime.surface_score()\n    if score > 0 {\n        checkpoint()\n    }\n}\n",
        )
        .expect("temp source should be written");

        let _ = format_source_file(&path).expect("formatter should run");
        let content = std::fs::read_to_string(&path).expect("formatted file should be readable");
        assert!(content.contains("let score = runtime.surface_score()\n    if score > 0"));
        parser::parse(&content, "main").expect("formatted file should parse");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn formatter_preserves_logical_and_operator() {
        let file_name = format!(
            "fozzylang-fmt-logical-and-{}.fzy",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "test \"det_reference_contract\" {\n    if model.service_name() == \"fzweb\" && model.route_count() == 12 {\n        checkpoint()\n    }\n}\n",
        )
        .expect("temp source should be written");

        let _ = format_source_file(&path).expect("formatter should run");
        let content = std::fs::read_to_string(&path).expect("formatted file should be readable");
        assert!(content.contains("&&"));
        assert!(!content.contains("& &"));
        parser::parse(&content, "main").expect("formatted file should parse");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn formatter_round_trips_trait_generic_fixture() {
        let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/trait_generic/main.fzy");
        let source = std::fs::read_to_string(&source_path).expect("fixture source should be read");
        let formatted = format_source(&source);
        parser::parse(&formatted, "main").expect("formatted fixture should parse");
        assert!(formatted.contains("fn id<T: Show>(v: T) -> T"));
    }

    #[test]
    fn audit_unsafe_uses_semantic_calls_not_lexical_substrings() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-audit-semantic-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let note: str = \"unsafe(\\\"fake\\\")\"\n    // unsafe(\"comment\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::AuditUnsafe {
                path: source.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect("audit should succeed");
        assert!(output.contains("\"entries\":[]"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn audit_unsafe_generates_contract_for_unsafe_block() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-audit-missing-reason-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    unsafe {\n        return 0\n    }\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::AuditUnsafe {
                path: source.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect("audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("unsafe audit should emit json");
        assert_eq!(payload["missingContractCount"].as_u64(), Some(0));
        assert_eq!(payload["invalidOwnerIdCount"].as_u64(), Some(0));
        assert_eq!(payload["strictUnsafeAudit"].as_bool(), Some(true));
        let entries = payload["entries"]
            .as_array()
            .expect("entries should be an array");
        assert!(!entries.is_empty());
        let block = entries
            .iter()
            .find(|entry| entry["kind"] == "unsafe_block")
            .expect("unsafe block entry should exist");
        assert_eq!(block["line"].as_u64(), Some(2));
        assert_eq!(block["owner_id"].as_str(), Some("owner::main::scope_root"));
        let docs_markdown = payload["docsMarkdown"]
            .as_str()
            .expect("markdown artifact should be reported");
        let docs = std::fs::read_to_string(docs_markdown).expect("markdown artifact should exist");
        assert!(docs.contains("Owner ID"));
        assert!(docs.contains("unsafe_block"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn audit_unsafe_collects_generated_contract_from_semantic_call() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-audit-reasoned-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn lang_id(v: i32) -> i32 {\n    return v\n}\nunsafe fn lang_unsafe_id(v: i32) -> i32 {\n    return v\n}\nfn main() -> i32 {\n    let routed = lang_id(7)\n    discard lang_unsafe_id\n    unsafe {\n        discard lang_id(routed)\n    }\n    return routed\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::AuditUnsafe {
                path: source.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect("audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("unsafe audit should emit json");
        assert_eq!(payload["missingContractCount"].as_u64(), Some(0));
        assert_eq!(payload["invalidOwnerIdCount"].as_u64(), Some(0));
        assert_eq!(payload["strictUnsafeAudit"].as_bool(), Some(true));
        let entries = payload["entries"]
            .as_array()
            .expect("entries should be an array");
        assert!(entries
            .iter()
            .all(|entry| entry["line"].as_u64().unwrap_or(0) > 0));
        assert!(entries.iter().any(|entry| {
            entry["kind"] == "unsafe_fn"
                && entry["owner_id"].as_str() == Some("owner::lang_unsafe_id::v")
        }));
        assert!(entries.iter().any(|entry| {
            entry["kind"] == "unsafe_block"
                && entry["owner_id"].as_str() == Some("owner::main::scope_root")
        }));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn audit_unsafe_fails_for_callsite_outside_unsafe_under_strict_policy() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-unsafe-violation-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_unsafe_violation\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_unsafe_violation\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "unsafe fn risky(v: i32) -> i32 {\n    return v\n}\n\nfn main() -> i32 {\n    return risky(7)\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::AuditUnsafe {
                path: root.clone(),
                workspace: false,
            },
            Format::Json,
        )
        .expect_err("strict unsafe audit should fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("strict unsafe audit failed"));
        assert!(rendered.contains("context_violations=1"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_memory_emits_strict_artifact_paths() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-memory-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_memory\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_memory\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let p = alloc(16)\n    defer free(p)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::AuditMemory { path: root.clone() }, Format::Json)
            .expect("memory audit should succeed");
        assert!(output.contains("\"mode\":\"memory-audit\""));
        assert!(output.contains("\"profile\":\"strict\""));
        assert!(output.contains("\"owners\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_memory_includes_path_dependency_library_functions() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-memory-dep-{suffix}"));
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_memory_dep\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_memory_dep\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use util;\nfn main() -> i32 {\n    let score = util.score()\n    if score == 7 {\n        return 0\n    }\n    return 91\n}\n",
        )
        .expect("source should be written");
        std::fs::write(
            dep_dir.join("fozzy.toml"),
            "[package]\nname=\"util\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"util\"\npath=\"src/lib.fzy\"\n",
        )
        .expect("dep manifest should be written");
        std::fs::write(
            dep_dir.join("src/lib.fzy"),
            "pub fn score() -> i32 {\n    return 7\n}\n",
        )
        .expect("dep lib source should be written");

        let output = run(Command::AuditMemory { path: root.clone() }, Format::Json)
            .expect("memory audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("memory audit should emit json");
        let function_names = payload["report"]["functions"]
            .as_array()
            .expect("report functions should be present")
            .iter()
            .filter_map(|value| value["name"].as_str())
            .collect::<Vec<_>>();
        assert!(function_names.contains(&"util.score"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_ffi_emits_import_and_export_inventory() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-ffi-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_ffi\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_ffi\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "#[repr(C)]\nstruct Packet {\n    value: i32,\n}\n\next unsafe c fn host_apply(cb_ctx: *mut u8, cb: fn(i32) -> i32, buf_borrowed: *u8, buf_len: usize) -> *u8;\n#[ffi_panic(abort)]\npubext c fn dispatch(packet: Packet, out_owned: *u8, out_len: usize) -> Packet {\n    discard host_apply\n    discard out_owned\n    discard out_len\n    return packet\n}\n\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::AuditFfi { path: root.clone() }, Format::Json)
            .expect("ffi audit should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("ffi audit should emit json");
        assert_eq!(payload["mode"].as_str(), Some("ffi-audit"));
        assert_eq!(payload["imports"].as_u64(), Some(1));
        assert_eq!(payload["exports"].as_u64(), Some(1));
        assert_eq!(payload["pointerContractViolationCount"].as_u64(), Some(0));
        assert_eq!(
            payload["callbackContextAnchorViolationCount"].as_u64(),
            Some(0)
        );
        assert_eq!(payload["asyncImportViolationCount"].as_u64(), Some(0));
        assert_eq!(payload["missingPanicBoundaryCount"].as_u64(), Some(0));
        let report = &payload["report"];
        assert_eq!(
            report["schemaVersion"].as_str(),
            Some("fozzylang.ffi_report.v2")
        );
        let import = report["imports"]
            .as_array()
            .and_then(|items| items.first())
            .expect("one import should be present");
        assert_eq!(import["name"].as_str(), Some("host_apply"));
        assert_eq!(import["pointerContractOk"].as_bool(), Some(true));
        assert_eq!(import["callbackContextAnchorOk"].as_bool(), Some(true));
        assert_eq!(import["ffiStableOk"].as_bool(), Some(true));
        let export = report["exports"]
            .as_array()
            .and_then(|items| items.first())
            .expect("one export should be present");
        assert_eq!(export["name"].as_str(), Some("dispatch"));
        assert_eq!(export["panicBoundaryDeclared"].as_bool(), Some(true));
        assert_eq!(export["ffiStableOk"].as_bool(), Some(true));
        let markdown_path = payload["markdown"]
            .as_str()
            .expect("markdown path should be reported");
        let markdown =
            std::fs::read_to_string(markdown_path).expect("ffi markdown artifact should exist");
        assert!(markdown.contains("pointer_contract_ok=true"));
        assert!(markdown.contains("panic_boundary_declared=true"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_ffi_fails_for_missing_pointer_contract_metadata() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-ffi-invalid-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"audit_ffi_invalid\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"audit_ffi_invalid\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "ext unsafe c fn host_touch(buf: *u8, len: usize) -> i32;\nfn main() -> i32 {\n    discard host_touch\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = run(Command::AuditFfi { path: root.clone() }, Format::Json)
            .expect_err("ffi audit should fail when pointer contracts are invalid");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("strict safety artifact generation failed")
                || rendered.contains("pointer parameters require ownership suffix")
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn audit_unsafe_non_project_root_reports_target_guidance() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-audit-root-guidance-{suffix}"));
        let nested = root.join("app");
        let nested_src = nested.join("src");
        std::fs::create_dir_all(&nested_src).expect("nested project tree should be created");
        std::fs::write(
            nested.join("fozzy.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"app\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            nested_src.join("main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let err = run(
            Command::AuditUnsafe {
                path: root.clone(),
                workspace: false,
            },
            Format::Text,
        )
        .expect_err("audit should fail for non-project root path");
        let msg = err.to_string();
        assert!(msg.contains("not a Fozzy project root"));
        assert!(msg.contains("detected nested project(s)"));
        assert!(msg.contains(&nested.display().to_string()));
        assert!(msg.contains("fz audit unsafe <project-path>"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn headers_command_generates_c_header_for_exports() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-{suffix}.h"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32;\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        assert!(output.contains("mode: headers"));
        assert!(output.contains("abi_manifest:"));
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("int32_t add(int32_t left, int32_t right);"));
        assert!(header_text.contains("int32_t fz_host_init(void);"));
        assert!(header_text.contains("int32_t fz_host_last_error_code(void);"));
        assert!(header_text.contains("const char* fz_host_last_error_message(void);"));
        assert!(header_text.contains("fz_host_register_callback_i32"));
        let abi_path = header.with_extension("abi.json");
        assert!(abi_path.exists());

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn headers_command_generates_async_export_handle_api() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-async-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-async-{suffix}.h"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext async c fn flush(code: i32) -> i32 {\n    return code\n}\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("typedef uint64_t fz_async_handle_t;"));
        assert!(header_text
            .contains("int32_t flush_async_start(int32_t code, fz_async_handle_t* handle_out);"));
        assert!(header_text
            .contains("int32_t flush_async_poll(fz_async_handle_t handle, int32_t* done_out);"));
        assert!(header_text
            .contains("int32_t flush_async_await(fz_async_handle_t handle, int32_t* result_out);"));
        assert!(header_text.contains("int32_t flush_async_drop(fz_async_handle_t handle);"));
        assert!(!header_text.contains("int32_t flush(int32_t code);"));

        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        assert!(abi_text.contains("\"async\": true"));
        assert!(abi_text.contains("\"execution\": \"async-handle-sync-start-v1\""));
        assert!(abi_text.contains("\"startSymbol\": \"flush_async_start\""));
        assert!(abi_text.contains("\"startMode\": \"synchronous-execute-then-store\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn headers_command_rejects_async_export_without_i32_return() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-async-ret-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext async c fn flush(code: i32) -> i64 {\n    return code\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::Headers {
                path: source.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers command should reject non-i32 async return");
        assert!(error.to_string().contains("must return `i32`"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn headers_command_maps_pointer_sized_ints_to_size_t_semantics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-psize-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-psize-{suffix}.h"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn span(len: usize, delta: isize) -> usize;\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("size_t span(size_t len, ssize_t delta);"));

        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        assert!(abi_text.contains("\"fzy\": \"usize\""));
        assert!(abi_text.contains("\"fzy\": \"isize\""));
        assert!(abi_text.contains("\"c\": \"size_t\""));
        assert!(abi_text.contains("\"c\": \"ssize_t\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn headers_command_rejects_pointer_without_length_contract() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-nolen-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn write(buf_borrowed: *u8) -> i32;\n",
        )
        .expect("source should be written");
        let error = run(
            Command::Headers {
                path: source.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers command should reject pointer without len");
        assert!(error.to_string().contains("paired length parameter"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn headers_command_emits_typed_callback_typedefs_and_import_contracts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-callback-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-callback-{suffix}.h"));
        std::fs::write(
            &source,
            "ext unsafe c fn host_apply(cb: fn(i32) -> i32, cb_ctx: *mut u8, buf_borrowed: *u8, buf_len: usize) -> i32;\n#[ffi_panic(abort)]\npubext c fn run(cb: fn(i32) -> i32, cb_ctx: *mut u8, value: i32) -> i32;\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("typedef int32_t (*fz_callback_sig0_v0)(int32_t arg0);"));
        assert!(header_text.contains("int32_t run(fz_callback_sig0_v0 cb,"));
        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        assert!(abi_text.contains("\"imports\""));
        assert!(abi_text.contains("\"callbackAbi\": \"signature-typed-v1\""));
        assert!(abi_text.contains("\"signature\": \"fn(i32) -> i32\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn check_rejects_pointer_like_extern_c_import_without_pointer_contract_suffix() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-extern-c-contract-missing-{suffix}.fzy"));
        std::fs::write(
            &source,
            "ext unsafe c fn c_read(buf: *u8, len: usize) -> i32;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Check {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("check command should return diagnostics");
        assert!(output.contains("must declare ownership suffix and paired length/context contract"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn headers_command_reports_repr_c_alignment_sensitive_layouts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-headers-layout-{suffix}.fzy"));
        let header = std::env::temp_dir().join(format!("fozzylang-headers-layout-{suffix}.h"));
        std::fs::write(
            &source,
            "#[repr(C)]\nstruct PackedLike { a: u8, b: u64, c: u16 }\n#[repr(C)]\nenum Mode { Ready, Busy }\n#[ffi_panic(abort)]\npubext c fn touch(v: u64) -> u64;\n",
        )
        .expect("source should be written");

        run(
            Command::Headers {
                path: source.clone(),
                output: Some(header.clone()),
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        let abi_path = header.with_extension("abi.json");
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be created");
        let abi: serde_json::Value =
            serde_json::from_str(&abi_text).expect("abi manifest should be valid json");
        let layouts = abi["reprCLayouts"]
            .as_array()
            .expect("reprCLayouts should be an array");
        let packed = layouts
            .iter()
            .find(|layout| layout["name"] == "PackedLike")
            .expect("PackedLike layout should exist");
        assert_eq!(packed["size"].as_u64(), Some(24));
        assert_eq!(packed["align"].as_u64(), Some(8));
        let fields = packed["fields"]
            .as_array()
            .expect("PackedLike fields should be emitted");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0]["name"].as_str(), Some("a"));
        assert_eq!(fields[0]["c"].as_str(), Some("uint8_t"));
        assert_eq!(fields[0]["offset"].as_u64(), Some(0));
        assert_eq!(fields[1]["name"].as_str(), Some("b"));
        assert_eq!(fields[1]["c"].as_str(), Some("uint64_t"));
        assert_eq!(fields[1]["offset"].as_u64(), Some(8));
        assert_eq!(fields[2]["name"].as_str(), Some("c"));
        assert_eq!(fields[2]["c"].as_str(), Some("uint16_t"));
        assert_eq!(fields[2]["offset"].as_u64(), Some(16));
        let mode = layouts
            .iter()
            .find(|layout| layout["name"] == "Mode")
            .expect("Mode layout should exist");
        assert_eq!(mode["size"].as_u64(), Some(4));
        assert_eq!(mode["align"].as_u64(), Some(4));
        assert_eq!(mode["storage"].as_str(), Some("int32_t"));
        let variants = mode["variants"]
            .as_array()
            .expect("Mode variants should be emitted");
        assert_eq!(variants.len(), 2);
        assert_eq!(variants[0]["name"].as_str(), Some("Ready"));
        assert_eq!(variants[0]["value"].as_u64(), Some(0));
        assert_eq!(variants[1]["name"].as_str(), Some("Busy"));
        assert_eq!(variants[1]["value"].as_u64(), Some(1));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(header);
        let _ = std::fs::remove_file(abi_path);
    }

    #[test]
    fn build_lib_abi_manifest_includes_repr_c_return_field_metadata() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-lib-layout-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[repr(C)]\nstruct BridgeClickResult {\n    input_count: i32,\n    js_doubled: i32,\n    callback_total: i32,\n    handshake_score: i32,\n}\n\n#[ffi_panic(abort)]\npubext c fn bridge_click(count: i32) -> BridgeClickResult {\n    return BridgeClickResult {\n        input_count: count,\n        js_doubled: count,\n        callback_total: count,\n        handshake_score: count,\n    }\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: true,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build --lib should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let abi_path = std::path::PathBuf::from(
            payload["abiManifest"]
                .as_str()
                .expect("abi manifest path should be present"),
        );
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be readable");
        let abi: serde_json::Value =
            serde_json::from_str(&abi_text).expect("abi manifest should be valid json");
        let layout = abi["reprCLayouts"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|layout| layout["name"] == "BridgeClickResult")
            })
            .expect("BridgeClickResult layout should exist");
        let fields = layout["fields"]
            .as_array()
            .expect("BridgeClickResult fields should be emitted");
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["name"].as_str(), Some("input_count"));
        assert_eq!(fields[0]["c"].as_str(), Some("int32_t"));
        assert_eq!(fields[1]["name"].as_str(), Some("js_doubled"));
        assert_eq!(fields[2]["name"].as_str(), Some("callback_total"));
        assert_eq!(fields[3]["name"].as_str(), Some("handshake_score"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn build_lib_project_root_abi_manifest_includes_repr_c_return_field_metadata() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-build-lib-root-layout-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"reprc_root_layout\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"reprc_root_layout\"\npath=\"src/lib.fzy\"\n\n[ffi]\npanic_boundary=\"abort\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[repr(C)]\nstruct BridgeClickResult {\n    input_count: i32,\n    js_doubled: i32,\n    callback_total: i32,\n    handshake_score: i32,\n}\n\n#[ffi_panic(abort)]\npubext c fn bridge_click(count: i32) -> BridgeClickResult {\n    return BridgeClickResult {\n        input_count: count,\n        js_doubled: count,\n        callback_total: count,\n        handshake_score: count,\n    }\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: true,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build --lib should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let abi_path = std::path::PathBuf::from(
            payload["abiManifest"]
                .as_str()
                .expect("abi manifest path should be present"),
        );
        let abi_text = std::fs::read_to_string(&abi_path).expect("abi manifest should be readable");
        let abi: serde_json::Value =
            serde_json::from_str(&abi_text).expect("abi manifest should be valid json");
        let layout = abi["reprCLayouts"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|layout| layout["name"] == "BridgeClickResult")
            })
            .expect("BridgeClickResult layout should exist");
        let fields = layout["fields"]
            .as_array()
            .expect("BridgeClickResult fields should be emitted");
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["name"].as_str(), Some("input_count"));
        assert_eq!(fields[1]["name"].as_str(), Some("js_doubled"));
        assert_eq!(fields[2]["name"].as_str(), Some("callback_total"));
        assert_eq!(fields[3]["name"].as_str(), Some("handshake_score"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn headers_command_collects_exports_from_declared_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-headers-project-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"headers_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"headers_project\"\npath=\"src/main.fzy\"\n\n[ffi]\npanic_boundary=\"abort\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod ffi;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/ffi.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32;\n",
        )
        .expect("ffi source should be written");

        let output = run(
            Command::Headers {
                path: root.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect("headers command should succeed");
        assert!(output.contains("exports: 1"));
        let header = root.join("include/headers_project.h");
        let header_text = std::fs::read_to_string(&header).expect("header should be created");
        assert!(header_text.contains("int32_t add(int32_t left, int32_t right);"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn vendor_command_refreshes_lock_and_writes_vendor_manifest() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-vendor-{suffix}"));
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"vendor_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"vendor_project\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
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
        std::fs::write(
            root.join("fozzy.lock"),
            "{\"schemaVersion\":\"fozzylang.lock.v0\",\"dependencyGraphHash\":\"stale\",\"graph\":{\"deps\":[]}}",
        )
        .expect("stale lock should be written");

        let output = run(Command::Vendor { path: root.clone() }, Format::Json)
            .expect("vendor command should succeed");
        assert!(output.contains("\"ok\":true"));
        assert!(output.contains("\"lockHash\""));
        let vendor_manifest = root.join("vendor/fozzy-vendor.json");
        assert!(vendor_manifest.exists());
        let vendor_manifest_text =
            std::fs::read_to_string(&vendor_manifest).expect("vendor manifest should be readable");
        assert!(vendor_manifest_text.contains("\"schemaVersion\": \"fozzylang.vendor.v0\""));
        assert!(vendor_manifest_text.contains("\"sourceHash\""));
        assert!(root.join("vendor/util/src/main.fzy").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn vendor_command_records_remote_deps_without_path_copy() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-vendor-remote-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"vendor_remote\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"vendor_remote\"\npath=\"src/main.fzy\"\n\n[deps]\nserde={version=\"1.0.0\",source=\"registry+https://registry.example.test\"}\nparser={git=\"https://github.com/example/parser.git\",rev=\"abc123\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");

        let output = run(Command::Vendor { path: root.clone() }, Format::Json)
            .expect("vendor command should succeed");
        assert!(output.contains("\"ok\":true"));
        let vendor_manifest = root.join("vendor/fozzy-vendor.json");
        let vendor_manifest_text =
            std::fs::read_to_string(&vendor_manifest).expect("vendor manifest should be readable");
        assert!(vendor_manifest_text.contains("\"sourceType\": \"version\""));
        assert!(vendor_manifest_text.contains("\"sourceType\": \"git\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn vendor_command_copies_framework_dependencies() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-vendor-framework-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"vendor_framework\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"vendor_framework\"\npath=\"src/main.fzy\"\n\n[deps]\nfzbounds={}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use fzbounds;\nfn main() -> i32 {\n    return fzbounds.touch()\n}\n",
        )
        .expect("main source should be written");

        let output = run(Command::Vendor { path: root.clone() }, Format::Json)
            .expect("vendor command should succeed");
        assert!(output.contains("\"ok\":true"));
        let vendor_manifest = root.join("vendor/fozzy-vendor.json");
        let vendor_manifest_text =
            std::fs::read_to_string(&vendor_manifest).expect("vendor manifest should be readable");
        assert!(vendor_manifest_text.contains("\"sourceType\": \"framework\""));
        assert!(root.join("vendor/fzbounds/src/lib.fzy").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rpc_gen_command_emits_schema_and_stubs() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-rpc-{suffix}.fzy"));
        let out_dir = std::env::temp_dir().join(format!("fozzylang-rpc-out-{suffix}"));
        std::fs::write(
            &source,
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Stream(stream<PingReq>) -> stream<PingRes>;\n",
        )
        .expect("source should be written");

        let output = run(
            Command::RpcGen {
                path: source.clone(),
                out_dir: Some(out_dir.clone()),
            },
            Format::Json,
        )
        .expect("rpc gen should succeed");
        assert!(output.contains("\"methods\":2"));
        assert!(output.contains("\"schema\":\""));
        assert!(out_dir.join("rpc.schema.json").exists());
        assert!(out_dir.join("rpc.client.fzy").exists());
        assert!(out_dir.join("rpc.server.fzy").exists());
        let schema = std::fs::read_to_string(out_dir.join("rpc.schema.json"))
            .expect("rpc schema should be readable");
        let client = std::fs::read_to_string(out_dir.join("rpc.client.fzy"))
            .expect("rpc client should be readable");
        let server = std::fs::read_to_string(out_dir.join("rpc.server.fzy"))
            .expect("rpc server should be readable");
        assert!(!client.contains("TODO"));
        assert!(!server.contains("TODO"));
        assert!(schema.contains("\"schemaVersion\": \"fozzylang.rpc.v1\""));
        assert!(schema.contains("\"mode\": \"unary\""));
        assert!(schema.contains("\"mode\": \"bidirectional_streaming\""));
        assert!(schema.contains("\"clientStreaming\": true"));
        assert!(client.contains("deadline("));
        assert!(client.contains("cancel()"));
        assert!(client.contains("return Ping(req)"));
        assert!(client.contains("return Stream(arg0)"));
        assert!(!client.contains("transport_send"));
        assert!(server.contains("deadline("));
        assert!(server.contains("prepare_ping_handler"));
        assert!(server.contains("prepare_stream_handler"));
        assert!(!server.contains("transport_recv"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn abi_check_allows_added_exports_with_stable_existing_signatures() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline = std::env::temp_dir().join(format!("fozzylang-abi-baseline-{suffix}.json"));
        let current = std::env::temp_dir().join(format!("fozzylang-abi-current-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    },
                    {
                        "name":"sub",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("current abi should be written");

        let output = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Json,
        )
        .expect("abi-check should pass for additive exports");
        assert!(output.contains("\"ok\":true"));
        assert!(output.contains("sub:sync(int32_t,int32_t)->int32_t"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn abi_check_rejects_changed_signature_for_existing_export() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline =
            std::env::temp_dir().join(format!("fozzylang-abi-baseline-sig-{suffix}.json"));
        let current = std::env::temp_dir().join(format!("fozzylang-abi-current-sig-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":1,
                        "params":[{"name":"left","fzy":"i32","c":"int32_t"},{"name":"right","fzy":"i32","c":"int32_t"}],
                        "return":{"fzy":"i32","c":"int32_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [
                    {
                        "name":"add",
                        "symbolVersion":2,
                        "params":[{"name":"left","fzy":"i64","c":"int64_t"},{"name":"right","fzy":"i64","c":"int64_t"}],
                        "return":{"fzy":"i64","c":"int64_t"}
                    }
                ]
            })
            .to_string(),
        )
        .expect("current abi should be written");

        let error = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Text,
        )
        .expect_err("abi-check should fail for signature changes");
        assert!(error
            .to_string()
            .contains("signature changed for export `add`"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn abi_check_rejects_contract_weakening() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline =
            std::env::temp_dir().join(format!("fozzylang-abi-baseline-contract-{suffix}.json"));
        let current =
            std::env::temp_dir().join(format!("fozzylang-abi-current-contract-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"consume",
                    "symbolVersion":1,
                    "params":[{"name":"buf_borrowed","fzy":"*u8","c":"uint8_t*","contract":{"ownership":"borrowed","nullability":"non_null","mutability":"mut","lifetimeAnchor":"loan:buf","view":{"kind":"ptr_len","lengthParam":"buf_len"}}},{"name":"buf_len","fzy":"usize","c":"size_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const","lifetimeAnchor":null,"view":null}}],
                    "return":{"fzy":"i32","c":"int32_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const"}},
                    "contract":{"callbackBindings":[]}
                }]
            }).to_string(),
        ).expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"consume",
                    "symbolVersion":1,
                    "params":[{"name":"buf_borrowed","fzy":"*u8","c":"uint8_t*","contract":{"ownership":"borrowed","nullability":"nullable","mutability":"mut","lifetimeAnchor":"loan:buf","view":{"kind":"ptr_len","lengthParam":"buf_len"}}},{"name":"buf_len","fzy":"usize","c":"size_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const","lifetimeAnchor":null,"view":null}}],
                    "return":{"fzy":"i32","c":"int32_t","contract":{"ownership":"value","nullability":"n/a","mutability":"const"}},
                    "contract":{"callbackBindings":[]}
                }]
            }).to_string(),
        ).expect("current abi should be written");
        let error = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Text,
        )
        .expect_err("abi-check should fail for weakened contracts");
        assert!(error
            .to_string()
            .contains("contract weakened/changed for export `consume`"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn abi_check_rejects_sync_to_async_mode_change() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let baseline =
            std::env::temp_dir().join(format!("fozzylang-abi-baseline-async-mode-{suffix}.json"));
        let current =
            std::env::temp_dir().join(format!("fozzylang-abi-current-async-mode-{suffix}.json"));
        std::fs::write(
            &baseline,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.1.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"flush",
                    "async": false,
                    "symbolVersion":1,
                    "params":[{"name":"code","fzy":"i32","c":"int32_t"}],
                    "return":{"fzy":"i32","c":"int32_t"},
                    "contract":{"execution":"sync","callbackBindings":[]}
                }]
            })
            .to_string(),
        )
        .expect("baseline abi should be written");
        std::fs::write(
            &current,
            serde_json::json!({
                "schemaVersion": "fozzylang.ffi_abi.v1",
                "package": {"name":"demo","version":"0.2.0"},
                "panicBoundary": "abort",
                "exports": [{
                    "name":"flush",
                    "async": true,
                    "symbolVersion":1,
                    "params":[{"name":"code","fzy":"i32","c":"int32_t"}],
                    "return":{"fzy":"i32","c":"int32_t"},
                    "contract":{"execution":"async-handle-v1","callbackBindings":[]}
                }]
            })
            .to_string(),
        )
        .expect("current abi should be written");

        let error = run(
            Command::AbiCheck {
                current: current.clone(),
                baseline: baseline.clone(),
            },
            Format::Text,
        )
        .expect_err("abi-check should fail for async mode changes");
        assert!(error
            .to_string()
            .contains("signature changed for export `flush`"));

        let _ = std::fs::remove_file(baseline);
        let _ = std::fs::remove_file(current);
    }

    #[test]
    fn rpc_gen_command_reads_declarations_from_declared_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-rpc-project-{suffix}"));
        let out_dir = std::env::temp_dir().join(format!("fozzylang-rpc-project-out-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"rpc_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"rpc_project\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod rpc_api;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/rpc_api.fzy"),
            "rpc Ping(req: PingReq) -> PingRes;\nrpc Stream(stream<PingReq>) -> stream<PingRes>;\n",
        )
        .expect("rpc source should be written");

        let output = run(
            Command::RpcGen {
                path: root.clone(),
                out_dir: Some(out_dir.clone()),
            },
            Format::Json,
        )
        .expect("rpc gen should succeed");
        assert!(output.contains("\"methods\":2"));
        assert!(out_dir.join("rpc.schema.json").exists());
        let server = std::fs::read_to_string(out_dir.join("rpc.server.fzy"))
            .expect("rpc server should be readable");
        assert!(server.contains("apply_rpc_handler_contract"));
        assert!(server.contains("prepare_ping_handler"));

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn doc_gen_includes_rpc_and_ffi_surfaces_from_semantic_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-doc-project-{suffix}"));
        std::fs::create_dir_all(root.join("src/api")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"doc_project\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"doc_project\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod api;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/api/mod.fzy"), "mod ffi;\nmod rpc;\n")
            .expect("api module should be written");
        std::fs::write(
            root.join("src/api/ffi.fzy"),
            "/// Hash bytes for the host boundary.\npubext c fn hash32(ptr_borrowed: *u8, len: usize) -> u32;\n",
        )
        .expect("ffi source should be written");
        std::fs::write(
            root.join("src/api/rpc.fzy"),
            "/// Ping the service edge.\nrpc Ping(req: PingReq) -> PingRes;\n",
        )
        .expect("rpc source should be written");

        let output = run(
            Command::DocGen {
                path: root.clone(),
                format: "json".to_string(),
                out: None,
                reference: None,
            },
            Format::Json,
        )
        .expect("doc gen should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("doc gen json should parse");
        let rendered = payload["rendered"]
            .as_str()
            .expect("rendered docs should be present");
        let rendered_json: serde_json::Value =
            serde_json::from_str(rendered).expect("rendered docs payload should parse");
        assert_eq!(rendered_json["schemaVersion"], "fozzylang.doc.v1");
        let items = rendered_json["items"]
            .as_array()
            .expect("doc items should be an array");
        assert!(items.iter().any(|item| {
            item["kind"] == "ffi-export"
                && item["signature"]
                    .as_str()
                    .is_some_and(|value| value.contains("pubext c fn hash32"))
                && item["docs"]
                    .as_str()
                    .is_some_and(|value| value.contains("Hash bytes for the host boundary."))
        }));
        assert!(items.iter().any(|item| {
            item["kind"] == "rpc"
                && item["signature"]
                    .as_str()
                    .is_some_and(|value| value.contains("rpc Ping(req: PingReq) -> PingRes;"))
                && item["docs"]
                    .as_str()
                    .is_some_and(|value| value.contains("Ping the service edge."))
        }));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_threads_persists_runtime_config() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-threads-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: false,
                threads: Some(3),
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed");
        assert!(output.contains("\"threads\":3"));
        let runtime_config = source
            .parent()
            .expect("temp source should have parent")
            .join(".fz/runtime.json");
        assert!(runtime_config.exists());
        let runtime_text =
            std::fs::read_to_string(&runtime_config).expect("runtime config should be readable");
        assert!(runtime_text.contains("\"threads\": 3"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(runtime_config);
    }

    #[test]
    fn build_command_emits_runnable_binary_named_after_target() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-build-binary-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project src should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo_binary\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo_binary\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 7\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: false,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let artifact = std::path::PathBuf::from(
            payload["output"]
                .as_str()
                .expect("build output should include artifact path"),
        );
        assert_eq!(
            artifact.file_name().and_then(|name| name.to_str()),
            Some("demo_binary")
        );
        assert!(artifact.exists());
        let status = std::process::Command::new(&artifact)
            .status()
            .expect("native artifact should execute");
        assert_eq!(status.code(), Some(7));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_lib_emits_static_shared_and_headers() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-lib-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: true,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build --lib should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        assert_eq!(payload["buildMode"].as_str(), Some("lib"));
        assert!(payload
            .get("staticLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(payload
            .get("sharedLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(payload
            .get("header")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(payload
            .get("abiManifest")
            .and_then(|value| value.as_str())
            .is_some());
        let artifact_manifest = std::path::PathBuf::from(
            payload["artifactManifest"]
                .as_str()
                .expect("artifact manifest should be present"),
        );
        let artifact_payload: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&artifact_manifest).expect("artifact manifest should be readable"),
        )
        .expect("artifact manifest should be valid json");
        for key in [
            "source",
            "projectRoot",
            "staticLib",
            "sharedLib",
            "header",
            "abiManifest",
            "artifactManifest",
        ] {
            let value = artifact_payload[key]
                .as_str()
                .unwrap_or_else(|| panic!("artifact manifest field `{key}` should be a string"));
            assert!(
                !std::path::Path::new(value).is_absolute(),
                "artifact manifest field `{key}` should be relative: {value}"
            );
        }

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn build_binary_with_c_exports_also_reports_interop_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-build-interop-{suffix}.fzy"));
        std::fs::write(
            &source,
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n\nfn main() -> i32 {\n    return add(2, 5)\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Build {
                path: source.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: false,
                threads: None,
                backend: None,
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("build output should be valid json");
        let interop = payload
            .get("interop")
            .expect("interop metadata should be present for c exports");
        assert_eq!(
            interop.get("buildMode").and_then(|value| value.as_str()),
            Some("lib")
        );
        assert!(interop
            .get("staticLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(interop
            .get("sharedLib")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(interop
            .get("header")
            .and_then(|value| value.as_str())
            .is_some());
        assert!(interop
            .get("abiManifest")
            .and_then(|value| value.as_str())
            .is_some());
        assert_eq!(
            interop
                .get("hostLifecycle")
                .and_then(|value| value.get("lastErrorMessage"))
                .and_then(|value| value.as_str()),
            Some("fz_host_last_error_message")
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn generate_c_headers_reuses_cached_outputs_when_inputs_are_unchanged() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-header-cache-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"header_cache\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"header_cache\"\npath=\"src/lib.fzy\"\n\n[ffi]\npanic_boundary=\"abort\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/lib.fzy"),
            "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
        )
        .expect("source should be written");

        let first = generate_c_headers(&root, None).expect("header generation should succeed");
        let cache_path = first.path.with_extension("header.cache.json");
        assert!(cache_path.exists(), "cache stamp should be written");
        let header_mtime = std::fs::metadata(&first.path)
            .and_then(|meta| meta.modified())
            .expect("header mtime");
        let abi_mtime = std::fs::metadata(&first.abi_manifest)
            .and_then(|meta| meta.modified())
            .expect("abi mtime");
        let cache_mtime = std::fs::metadata(&cache_path)
            .and_then(|meta| meta.modified())
            .expect("cache mtime");

        std::thread::sleep(std::time::Duration::from_millis(20));
        let second =
            generate_c_headers(&root, None).expect("cached header generation should succeed");
        assert_eq!(second.exports, 1);
        assert_eq!(
            std::fs::metadata(&second.path)
                .and_then(|meta| meta.modified())
                .expect("header mtime"),
            header_mtime
        );
        assert_eq!(
            std::fs::metadata(&second.abi_manifest)
                .and_then(|meta| meta.modified())
                .expect("abi mtime"),
            abi_mtime
        );
        assert_eq!(
            std::fs::metadata(&cache_path)
                .and_then(|meta| meta.modified())
                .expect("cache mtime"),
            cache_mtime
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unsafe_docs_cache_hit_tracks_input_fingerprint() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-unsafe-docs-cache-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"unsafe_docs\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"unsafe_docs\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "unsafe fn risky() -> i32 {\n    return 7\n}\n\nfn main() -> i32 {\n    unsafe {\n        return risky()\n    }\n}\n",
        )
        .expect("source should be written");

        let docs = root.join(".fz/unsafe-docs.md");
        std::fs::create_dir_all(docs.parent().expect("docs parent")).expect("docs dir");
        std::fs::write(&docs, "# unsafe docs\n").expect("write docs");
        std::fs::write(docs.with_extension("json"), b"{}").expect("write docs json");
        std::fs::write(docs.with_extension("html"), b"<p>unsafe docs</p>")
            .expect("write docs html");
        write_unsafe_docs_cache_stamp(&root, &docs).expect("write cache stamp");
        let stamp = unsafe_docs_cache_path(&docs);
        assert!(stamp.exists(), "unsafe docs stamp should be written");
        assert!(
            unsafe_docs_cache_hit(&root, &docs).expect("cache hit should evaluate"),
            "fresh cache stamp should match inputs"
        );
        let docs_mtime = std::fs::metadata(&docs)
            .and_then(|meta| meta.modified())
            .expect("docs mtime");
        let stamp_mtime = std::fs::metadata(&stamp)
            .and_then(|meta| meta.modified())
            .expect("stamp mtime");

        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(
            std::fs::metadata(&docs)
                .and_then(|meta| meta.modified())
                .expect("docs mtime"),
            docs_mtime
        );
        assert_eq!(
            std::fs::metadata(&stamp)
                .and_then(|meta| meta.modified())
                .expect("stamp mtime"),
            stamp_mtime
        );
        std::fs::write(
            root.join("src/main.fzy"),
            "unsafe fn risky() -> i32 {\n    return 9\n}\n\nfn main() -> i32 {\n    unsafe {\n        return risky()\n    }\n}\n",
        )
        .expect("rewrite source");
        assert!(
            !unsafe_docs_cache_hit(&root, &docs).expect("cache hit should re-evaluate"),
            "cache stamp should miss after source changes"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn non_scenario_test_uses_scheduler_for_deterministic_execution() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-sched-{suffix}.fzy"));
        std::fs::write(
            &source,
            "test \"a\" {}\ntest \"b\" {}\ntest \"c\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(9),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: Some("coverage_guided".to_string()),
                rich_artifacts: false,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"scheduler\":\"coverage_guided\""));
        assert!(output.contains("\"executedTasks\":3"));
        assert!(output.contains("\"executionOrder\":[0,1,2]"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_command_executes_native_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-run-native-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 7\n}\n")
            .expect("source should be written");

        let error = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect_err("run command should fail with child exit code");
        let command_error = error
            .downcast_ref::<CommandFailure>()
            .expect("expected command failure payload");
        assert_eq!(command_error.exit_code, 7);
        assert!(command_error.output.contains("\"exitCode\":7"));
        assert!(command_error.output.contains("\"binary\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_spawn_executes_worker_side_effect() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-spawn-native-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-spawn-native-{suffix}.txt"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    proc.run(\"/bin/sh -lc 'echo spawned > {quoted_out}'\")\n    return 0\n}}\n\nfn main() -> i32 {{\n    spawn(worker)\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run command should succeed for spawn worker side effect");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            out_path.exists(),
            "spawned worker side effect output should exist at {}",
            out_path.display()
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn run_task_group_spawn_n_executes_all_worker_side_effects() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-group-native-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-group-native-{suffix}.txt"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo grouped >> {quoted_out}'\")\n}}\n\nfn main() -> i32 {{\n    let group = task.group_begin()\n    discard task.group_spawn_n(group, worker, 3)\n    return task.group_join_all(group)\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run command should succeed for grouped worker side effects");
        assert!(output.contains("\"exitCode\":0"));
        let content =
            std::fs::read_to_string(&out_path).expect("group worker output should be readable");
        assert_eq!(
            content.lines().count(),
            3,
            "expected three worker side effects"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn run_task_group_join_all_propagates_worker_failure() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-group-failure-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\nuse core.thread;\n\nfn worker() -> i32 {\n    return proc.run(\"/bin/sh -lc 'exit 7'\")\n}\n\nfn main() -> i32 {\n    let group = task.group_begin()\n    discard task.group_spawn(group, worker)\n    return task.group_join_all(group)\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect_err("group worker failure should surface as command failure");
        let command_error = error
            .downcast_ref::<CommandFailure>()
            .expect("expected command failure payload");
        assert_eq!(command_error.exit_code, 7);
        assert!(command_error.output.contains("\"exitCode\":7"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn run_spawned_worker_preserves_json_object_payloads() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-spawn-json-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-spawn-json-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.thread;\n\nfn worker() -> i32 {{\n    let payload = map.new()\n    discard map.set(payload, \"status\", json.str(\"ok\"))\n    discard map.set(payload, \"probe\", json.raw(\"7\"))\n    let doc = json.object(payload)\n    fs.write_file(\"{quoted_out}\", doc)\n    return 0\n}}\n\nfn main() -> i32 {{\n    let handle = spawn(worker)\n    return join(handle)\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("spawned json worker should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let content =
            std::fs::read_to_string(&out_path).expect("spawned json output should be readable");
        assert_ne!(
            content.trim(),
            "{}",
            "spawned json payload should not collapse to empty object"
        );
        assert!(
            content.contains("\"status\":\"ok\""),
            "spawned json payload should preserve string field"
        );
        assert!(
            content.contains("\"probe\":7"),
            "spawned json payload should preserve raw numeric field"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn run_spawned_worker_preserves_proc_result_json_payloads() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-spawn-proc-json-{suffix}.fzy"));
        let out_path =
            std::env::temp_dir().join(format!("fozzylang-spawn-proc-json-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"printf ok\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    discard proc.wait(handle, 1000)\n    let stdout = proc.stdout(handle)\n    let stderr = proc.stderr(handle)\n    discard proc.close(handle)\n    let payload = map.new()\n    discard map.set(payload, \"exit\", json.str(\"0\"))\n    discard map.set(payload, \"stdout\", json.str(stdout))\n    discard map.set(payload, \"stderr\", json.str(stderr))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    return 0\n}}\n\nfn main() -> i32 {{\n    let handle = spawn(worker)\n    return join(handle)\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("spawned proc json worker should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let content = std::fs::read_to_string(&out_path)
            .expect("spawned proc json output should be readable");
        assert_ne!(
            content.trim(),
            "{}",
            "spawned proc json payload should not collapse to empty object"
        );
        assert!(content.contains("\"exit\":\"0\""));
        assert!(content.contains("\"stdout\":\"ok\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn proc_wait_drains_large_child_output_without_stalling() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-proc-wait-backpressure-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\n\nfn main() -> i32 {\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"/usr/bin/python3 -c 'import sys; sys.stdout.write(\\\"o\\\" * 300000); sys.stdout.flush(); sys.stderr.write(\\\"e\\\" * 300000); sys.stderr.flush()'\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    let waited = proc.wait(handle, 10000)\n    let stdout = proc.stdout(handle)\n    let stderr = proc.stderr(handle)\n    let exit_code = proc.exit_code(handle)\n    discard proc.close(handle)\n    if waited == 0 && exit_code == 0 && str.len(stdout) == 300000 && str.len(stderr) == 300000 {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("large-output proc wait should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn deferred_proc_close_does_not_clobber_returned_exit_code() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-proc-defer-return-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\n\nfn status_of() -> i32 {\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"exit 0\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    discard proc.wait(handle, 1000)\n    return proc.exit_code(handle)\n}\n\nfn main() -> i32 {\n    if status_of() == 0 {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("deferred proc close should preserve exit code");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn proc_poll_reports_running_then_completion_without_consuming_handle() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-proc-poll-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.proc;\n\nfn main() -> i32 {\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 0.2; printf ready\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    let first = proc.poll(handle)\n    let waited = proc.wait(handle, 1000)\n    let second = proc.poll(handle)\n    let exit_code = proc.exit_code(handle)\n    let stdout = proc.stdout(handle)\n    discard proc.close(handle)\n    if first == 0 && waited == 0 && second == 1 && exit_code == 0 && stdout == \"ready\" {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("proc poll should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn host_backed_atomic_write_and_storage_atomic_append_persist_expected_bytes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-atomic-runtime-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        let atomic_path = root.join("state.txt");
        let append_path = root.join("audit.log");
        let atomic_quoted = atomic_path.to_string_lossy().replace('\"', "\\\"");
        let append_quoted = append_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"atomic_runtime\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"atomic_runtime\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            format!(
                "use core.fs;\nuse core.storage;\n\nfn main() -> i32 {{\n    discard fs.atomic_write(\"{atomic_quoted}\", \"alpha\")\n    discard storage.atomic_append(\"{append_quoted}\", \"first\")\n    discard storage.atomic_append(\"{append_quoted}\", \"second\")\n    let state = fs.read_file(\"{atomic_quoted}\")\n    let audit = fs.read_file(\"{append_quoted}\")\n    if state == \"alpha\" && audit == \"first\\nsecond\\n\" {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backed atomic write and append should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        assert_eq!(
            std::fs::read_to_string(&atomic_path).expect("atomic file should exist"),
            "alpha"
        );
        assert_eq!(
            std::fs::read_to_string(&append_path).expect("append log should exist"),
            "first\nsecond\n"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn host_backed_bytes_runtime_reads_slices_decodes_and_rewrites_binary_payloads() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-bytes-runtime-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        let fixture = root.join("fixture.bin");
        let copy = root.join("copy.bin");
        let mut payload = Vec::<u8>::new();
        payload.extend_from_slice(&12_u64.to_le_bytes());
        payload.extend_from_slice(br#"{"ok":"yes"}"#);
        payload.extend_from_slice(&1.0f32.to_le_bytes());
        payload.extend_from_slice(&0x3c00_u16.to_le_bytes());
        std::fs::write(&fixture, payload).expect("fixture should be written");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"bytes_runtime\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"bytes_runtime\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            format!(
                "use core.bytes;\nuse core.io;\n\nfn main() -> i32 {{\n    let raw = io.read_bytes(\"{}\")\n    let header_len: i64 = bytes.read_u64_le(raw, 0)\n    if header_len != 12 {{\n        return 11\n    }}\n    if bytes.len(raw) != 26 {{\n        return 12\n    }}\n    if bytes.at(raw, 23) != 63 {{\n        return 13\n    }}\n    if bytes.read_u16_le(raw, 24) != 15360 {{\n        return 14\n    }}\n    if bytes.read_u32_le(raw, 20) != 1065353216 {{\n        return 15\n    }}\n    let value32 = bytes.read_f32_le(raw, 20)\n    if value32 < 0.99f32 || value32 > 1.01f32 {{\n        return 16\n    }}\n    let value16 = bytes.read_f16_le(raw, 24)\n    if value16 < 0.99f32 || value16 > 1.01f32 {{\n        return 17\n    }}\n    let header = bytes.as_str(bytes.slice(raw, 8, 20))\n    if header != \"{{\\\"ok\\\":\\\"yes\\\"}}\" {{\n        return 18\n    }}\n    let tensor = bytes.slice(raw, 20, 26)\n    if io.write_bytes(\"{}\", tensor) != 0 {{\n        return 19\n    }}\n    let copied = io.read_bytes(\"{}\")\n    if bytes.len(copied) != 6 {{\n        return 21\n    }}\n    let copied32 = bytes.read_f32_le(copied, 0)\n    if copied32 < 0.99f32 || copied32 > 1.01f32 {{\n        return 22\n    }}\n    let copied16 = bytes.read_f16_le(copied, 4)\n    if copied16 < 0.99f32 || copied16 > 1.01f32 {{\n        return 23\n    }}\n    return 0\n}}\n",
                fixture.display(),
                copy.display(),
                copy.display()
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backed bytes runtime should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        assert_eq!(
            std::fs::read(&copy).expect("copy should exist"),
            [&1.0f32.to_le_bytes()[..], &0x3c00_u16.to_le_bytes()[..]].concat()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn crypto_runtime_surface_supports_hash_hmac_base64_and_secure_compare() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-crypto-runtime-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.crypto;\nuse core.error;\nuse core.security;\n\nfn main() -> i32 {\n    let digest = crypto.sha256(\"abc\")\n    let mac = crypto.hmac_sha256(\"key\", \"The quick brown fox jumps over the lazy dog\")\n    let encoded = crypto.base64_encode(\"fozzy\")\n    let decoded = crypto.base64_decode(encoded)\n    let crypto_url = crypto.base64_url_encode(\"ok\")\n    let crypto_roundtrip = crypto.base64_url_decode(crypto_url)\n    let hex_token = crypto.random_hex(16)\n    let b64_token = crypto.random_base64(16)\n    let signer = security.default_signer()\n    let signed = security.sign(signer, \"key\", \"The quick brown fox jumps over the lazy dog\")\n    let opaque = security.opaque_token(16)\n    if digest != \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\" {\n        return 11\n    }\n    if mac != \"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8\" {\n        return 13\n    }\n    if encoded != \"Zm96enk=\" || decoded != \"fozzy\" {\n        return 17\n    }\n    if crypto_url != \"b2s\" || crypto_roundtrip != \"ok\" {\n        return 18\n    }\n    if str.len(hex_token) != 32 || str.len(b64_token) != 24 {\n        return 23\n    }\n    if str.len(opaque) != 22 || str.contains(opaque, \"=\") == 1 || str.contains(opaque, \"+\") == 1 || str.contains(opaque, \"/\") == 1 {\n        return 24\n    }\n    if crypto.constant_time_eq(digest, digest) != 1 {\n        return 29\n    }\n    if crypto.constant_time_eq(digest, mac) != 0 {\n        return 31\n    }\n    if security.verify(signer, \"key\", \"The quick brown fox jumps over the lazy dog\", signed) != 1 {\n        return 37\n    }\n    if str.starts_with(signed, \"v1:\") != 1 {\n        return 38\n    }\n    if crypto.base64_decode(\"A===\") != \"\" {\n        return 41\n    }\n    if error.code() == 0 || error.message() == \"\" {\n        return 43\n    }\n    if security.verify(signer, \"key\", \"The quick brown fox jumps over the lazy dog\", mac) != 0 {\n        return 47\n    }\n    if crypto.base64_decode(encoded) != \"fozzy\" {\n        return 53\n    }\n    if error.code() != 0 || error.message() != \"\" {\n        return 59\n    }\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .unwrap_or_else(|err| {
            if let Some(command_failure) = err.downcast_ref::<CommandFailure>() {
                panic!(
                    "crypto runtime should succeed: {}\noutput:\n{}",
                    command_failure, command_failure.output
                );
            }
            panic!("crypto runtime should succeed: {err}");
        });
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn build_lib_host_callback_can_read_borrowed_string_payload_bytes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-borrowed-payload-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        let input_path = root.join("control.input.json");
        let echoed_path = root.join("control.echo.json");
        std::fs::write(&input_path, "{\"status\":\"ok\",\"control_plane\":\"fzy\"}")
            .expect("input payload should be written");
        std::fs::write(
            root.join("fozzy.toml"),
            format!(
                "[package]\nname=\"ffi_borrowed_payload\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_borrowed_payload\"\npath=\"src/main.fzy\"\n\n[ffi]\npanic_boundary=\"error\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n"
            ),
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            format!(
                "use core.fs;\n\next unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;\n\n#[ffi_panic(error)]\npubext c fn dispatch() -> i32 {{\n    let raw = fs.read_file(\"{}\")\n    unsafe {{\n        return host_touch(raw, str.len(raw))\n    }}\n}}\n",
                input_path.display()
            ),
        )
        .expect("source should be written");

        for backend in ["llvm", "cranelift"] {
            let output = run(
                Command::Build {
                    path: root.clone(),
                    release: false,
                    strict: false,
                    incremental: false,
                    lib: true,
                    threads: None,
                    backend: Some(backend.to_string()),
                    pgo_generate: false,
                    pgo_use: None,
                    link_libs: Vec::new(),
                    link_search: Vec::new(),
                    frameworks: Vec::new(),
                },
                Format::Json,
            )
            .expect("build --lib should succeed");
            let payload_json: serde_json::Value =
                serde_json::from_str(&output).expect("build output should be valid json");
            let shared_lib = PathBuf::from(
                payload_json["sharedLib"]
                    .as_str()
                    .expect("sharedLib should be present"),
            );
            let header_path = PathBuf::from(
                payload_json["header"]
                    .as_str()
                    .expect("header should be present"),
            );
            let include_dir = header_path
                .parent()
                .expect("header should have parent directory");
            let probe_source = root.join(format!("probe-{backend}.c"));
            let probe_binary = root.join(format!("probe-{backend}"));
            std::fs::write(
                &probe_source,
                format!(
                    "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include \"ffi_borrowed_payload.h\"\n\nstatic uint8_t captured[256];\nstatic size_t captured_len = 0;\n\nint32_t host_touch(const uint8_t* ptr, size_t len) {{\n  if (ptr == NULL) return 91;\n  if (len > sizeof(captured)) return 92;\n  memcpy(captured, ptr, len);\n  captured_len = len;\n  FILE* f = fopen(\"{}\", \"wb\");\n  if (f == NULL) return 93;\n  if (len > 0) fwrite(ptr, 1, len, f);\n  fclose(f);\n  return 0;\n}}\n\nint main(void) {{\n  if (fz_host_init() != 0) return 101;\n  char expected[256];\n  for (int i = 0; i < 512; i++) {{\n    FILE* input = fopen(\"{}\", \"wb\");\n    if (input == NULL) return 106;\n    int written = snprintf(expected, sizeof(expected), \"{{\\\"status\\\":\\\"ok\\\",\\\"control_plane\\\":\\\"fzy\\\",\\\"seq\\\":%d}}\", i);\n    if (written < 0 || (size_t)written >= sizeof(expected)) {{\n      fclose(input);\n      return 107;\n    }}\n    fwrite(expected, 1, (size_t)written, input);\n    fclose(input);\n    int32_t rc = dispatch();\n    if (rc != 0) return rc;\n    if (captured_len != (size_t)written) return 104;\n    if (memcmp(captured, expected, (size_t)written) != 0) return 105;\n  }}\n  int32_t shutdown_rc = fz_host_shutdown();\n  int32_t cleanup_rc = fz_host_cleanup();\n  if (shutdown_rc != 0) return 102;\n  if (cleanup_rc != 0) return 103;\n  return 0;\n}}\n",
                    echoed_path.display(),
                    input_path.display()
                ),
            )
            .expect("probe source should be written");
            let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
            let rpath_flag = format!(
                "-Wl,-rpath,{}",
                shared_lib
                    .parent()
                    .expect("shared lib should have parent")
                    .display()
            );
            let status = ProcessCommand::new(&cc)
                .arg(&probe_source)
                .arg(&shared_lib)
                .arg("-I")
                .arg(include_dir)
                .arg(&rpath_flag)
                .arg("-o")
                .arg(&probe_binary)
                .status()
                .expect("C probe should compile");
            assert!(
                status.success(),
                "C probe compile should succeed for backend {backend}"
            );
            let status = ProcessCommand::new(&probe_binary)
                .status()
                .expect("C probe should execute");
            assert_eq!(
                status.code(),
                Some(0),
                "C probe should observe borrowed payload bytes for backend {backend}"
            );
            let echoed =
                std::fs::read_to_string(&echoed_path).expect("echoed payload should exist");
            assert!(
                echoed.contains("\"seq\":511"),
                "final echoed payload should match the last borrowed callback payload"
            );
            let _ = std::fs::remove_file(&probe_source);
            let _ = std::fs::remove_file(&probe_binary);
            let _ = std::fs::remove_file(&echoed_path);
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn portable_simd_surface_runs_via_fz_run_with_llvm_backend() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-simd-runtime-{suffix}"));
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

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("llvm".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .unwrap_or_else(|err| {
            if let Some(command_failure) = err.downcast_ref::<CommandFailure>() {
                panic!(
                    "SIMD runtime should succeed: {}\noutput:\n{}",
                    command_failure, command_failure.output
                );
            }
            panic!("SIMD runtime should succeed: {err}");
        });
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn portable_simd_surface_runs_via_fz_run_with_cranelift_backend() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-simd-runtime-cranelift-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        let fixture = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/simd_portable/main.fzy"),
        )
        .expect("portable simd fixture should be readable");
        std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .unwrap_or_else(|err| {
            if let Some(command_failure) = err.downcast_ref::<CommandFailure>() {
                panic!(
                    "SIMD runtime should succeed on cranelift: {}\noutput:\n{}",
                    command_failure, command_failure.output
                );
            }
            panic!("SIMD runtime should succeed on cranelift: {err}");
        });
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_http_post_json_applies_headers_and_preserves_raw_json_values() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should resolve");
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = Arc::clone(&captured);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept connection");
            let mut buf = Vec::<u8>::new();
            let mut header_end = None;
            let mut content_length = 0usize;
            loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).expect("server read should succeed");
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if header_end.is_none() {
                    if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                        let end_index = end + 4;
                        header_end = Some(end_index);
                        let header_text = String::from_utf8_lossy(&buf[..end_index]).to_string();
                        for line in header_text.lines() {
                            let lower = line.to_ascii_lowercase();
                            if let Some(value) = lower.strip_prefix("content-length:") {
                                content_length = value.trim().parse::<usize>().unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(end_index) = header_end {
                    if buf.len() >= end_index + content_length {
                        break;
                    }
                }
            }
            *captured_clone.lock().expect("capture lock should succeed") =
                String::from_utf8_lossy(&buf).to_string();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                )
                .expect("server response should write");
        });

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-http-json-{suffix}.fzy"));
        std::fs::write(
            &source,
            format!(
                "use core.http;\n\nfn main() -> i32 {{\n    discard http.header_set(\"x-demo\", \"sentinel\")\n    let inner = map.new()\n    discard map.set(inner, \"status\", json.raw(\"true\"))\n    discard map.set(inner, \"msg\", json.str(\"ok\"))\n    let items = list.new()\n    discard list.push(items, json.raw(\"1\"))\n    discard list.push(items, json.object(inner))\n    let payload = map.new()\n    discard map.set(payload, \"outer\", json.object(inner))\n    discard map.set(payload, \"items\", json.array(items))\n    discard http.post_json_capture(\"http://127.0.0.1:{}/echo\", json.object(payload))\n    let status = http.last_status()\n    if status != 200 {{\n        return status\n    }}\n    return 0\n}}\n",
                addr.port()
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("http json runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"));

        server.join().expect("server thread should finish");
        let request = captured
            .lock()
            .expect("capture lock should succeed")
            .clone();
        assert!(
            request.to_ascii_lowercase().contains("x-demo: sentinel"),
            "expected outbound custom header in request: {request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "expected JSON content-type header in request: {request}"
        );
        assert!(
            request.contains("\"outer\":{\"status\":true,\"msg\":\"ok\"}"),
            "expected raw nested JSON object in request body: {request}"
        );
        assert!(
            request.contains("\"items\":[1,{\"status\":true,\"msg\":\"ok\"}]"),
            "expected raw JSON array values in request body: {request}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_http_request_stream_reads_sse_events_incrementally() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should resolve");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept connection");
            let mut buf = Vec::<u8>::new();
            let mut header_end = None;
            let mut content_length = 0usize;
            loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).expect("server read should succeed");
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if header_end.is_none() {
                    if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                        let end_index = end + 4;
                        header_end = Some(end_index);
                        let header_text = String::from_utf8_lossy(&buf[..end_index]).to_string();
                        for line in header_text.lines() {
                            let lower = line.to_ascii_lowercase();
                            if let Some(value) = lower.strip_prefix("content-length:") {
                                content_length = value.trim().parse::<usize>().unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(end_index) = header_end {
                    if buf.len() >= end_index + content_length {
                        break;
                    }
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .expect("server headers should write");
            stream
                .write_all(b"event: message_start\n\n")
                .expect("message_start should write");
            stream.flush().expect("message_start flush should succeed");
            std::thread::sleep(std::time::Duration::from_millis(10));
            stream
                .write_all(b"event: content_block_delta\ndata: {\"type\":\"text_delta\",\"text\":\"hi\"}\n\n")
                .expect("content block should write");
            stream.flush().expect("content block flush should succeed");
            std::thread::sleep(std::time::Duration::from_millis(10));
            stream
                .write_all(b"event: message_stop\n\n")
                .expect("message_stop should write");
            stream.flush().expect("message_stop flush should succeed");
        });

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-http-stream-{suffix}.fzy"));
        std::fs::write(
            &source,
            format!(
                "use core.http;\n\nfn read_event_type(stream: HttpStreamHandle) -> str {{\n    loop {{\n        let line = http.stream_read_line(stream)\n        if line == \"\" {{\n            if http.stream_eof(stream) == 1 {{\n                return \"\"\n            }}\n            continue\n        }}\n        if str.starts_with(line, \"event:\") == 1 {{\n            let value = str.slice(line, 6, str.len(line))\n            if str.starts_with(value, \" \") == 1 {{\n                return str.slice(value, 1, str.len(value))\n            }}\n            return value\n        }}\n    }}\n}}\n\nfn read_event_data(stream: HttpStreamHandle) -> str {{\n    loop {{\n        let line = http.stream_read_line(stream)\n        if line == \"\" {{\n            if http.stream_eof(stream) == 1 {{\n                return \"\"\n            }}\n            continue\n        }}\n        if str.starts_with(line, \"data:\") == 1 {{\n            let value = str.slice(line, 5, str.len(line))\n            if str.starts_with(value, \" \") == 1 {{\n                return str.slice(value, 1, str.len(value))\n            }}\n            return value\n        }}\n    }}\n}}\n\nfn main() -> i32 {{\n    discard http.header_set(\"accept\", \"text/event-stream\")\n    let stream = http.post_json_stream(\"http://127.0.0.1:{}/sse\", \"{{\\\"stream\\\":true}}\")\n    let status = http.stream_status(stream)\n    if status != 200 {{\n        discard http.stream_close(stream)\n        return status\n    }}\n    let first = read_event_type(stream)\n    let second = read_event_type(stream)\n    let second_data = read_event_data(stream)\n    let third = read_event_type(stream)\n    discard http.stream_close(stream)\n    if first == \"message_start\" && second == \"content_block_delta\" && second_data == \"{{\\\"type\\\":\\\"text_delta\\\",\\\"text\\\":\\\"hi\\\"}}\" && third == \"message_stop\" {{\n        return 0\n    }}\n    return 17\n}}\n",
                addr.port()
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("http streaming runtime program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        server.join().expect("server thread should finish");
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn cancel_task_runs_worker_cleanup_and_closes_proc_handle() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-cancel-task-cleanup-{suffix}.fzy"));
        let started_path =
            std::env::temp_dir().join(format!("fozzylang-cancel-task-started-{suffix}.txt"));
        let cleanup_path =
            std::env::temp_dir().join(format!("fozzylang-cancel-task-cleanup-{suffix}.txt"));
        let quoted_started = started_path.to_string_lossy().replace('\"', "\\\"");
        let quoted_cleanup = cleanup_path.to_string_lossy().replace('\"', "\\\"");
        let _ = std::fs::remove_file(&started_path);
        let _ = std::fs::remove_file(&cleanup_path);
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 5\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    fs.write_file(\"{quoted_started}\", \"started\")\n    loop {{\n        if recv() != 0 {{\n            fs.write_file(\"{quoted_cleanup}\", \"cancelled\")\n            return 0\n        }}\n        checkpoint()\n    }}\n}}\n\nfn main() -> i32 {{\n    let task = spawn(worker)\n    while fs.exists(\"{quoted_started}\") == 0 {{\n        checkpoint()\n    }}\n    discard cancel_task(task)\n    if fs.read_file(\"{quoted_cleanup}\") == \"cancelled\" {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("cancel_task runtime program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        assert_eq!(
            std::fs::read_to_string(&cleanup_path).expect("cleanup file should exist"),
            "cancelled"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(started_path);
        let _ = std::fs::remove_file(cleanup_path);
    }

    #[test]
    fn task_group_cancel_runs_worker_cleanup_and_closes_proc_handles() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-cleanup-{suffix}.fzy"));
        let left_started =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-left-started-{suffix}.txt"));
        let right_started =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-right-started-{suffix}.txt"));
        let left_cleanup =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-left-cleanup-{suffix}.txt"));
        let right_cleanup =
            std::env::temp_dir().join(format!("fozzylang-group-cancel-right-cleanup-{suffix}.txt"));
        let quoted_left_started = left_started.to_string_lossy().replace('\"', "\\\"");
        let quoted_right_started = right_started.to_string_lossy().replace('\"', "\\\"");
        let quoted_left_cleanup = left_cleanup.to_string_lossy().replace('\"', "\\\"");
        let quoted_right_cleanup = right_cleanup.to_string_lossy().replace('\"', "\\\"");
        let _ = std::fs::remove_file(&left_started);
        let _ = std::fs::remove_file(&right_started);
        let _ = std::fs::remove_file(&left_cleanup);
        let _ = std::fs::remove_file(&right_cleanup);
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn left_worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 5\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    fs.write_file(\"{quoted_left_started}\", \"started\")\n    loop {{\n        if recv() != 0 {{\n            fs.write_file(\"{quoted_left_cleanup}\", \"cancelled\")\n            return 0\n        }}\n        checkpoint()\n    }}\n}}\n\nfn right_worker() -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, \"sleep 5\")\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    defer proc.close(handle)\n    fs.write_file(\"{quoted_right_started}\", \"started\")\n    loop {{\n        if recv() != 0 {{\n            fs.write_file(\"{quoted_right_cleanup}\", \"cancelled\")\n            return 0\n        }}\n        checkpoint()\n    }}\n}}\n\nfn main() -> i32 {{\n    let group = task.group_begin()\n    discard task.group_spawn(group, left_worker)\n    discard task.group_spawn(group, right_worker)\n    while fs.exists(\"{quoted_left_started}\") == 0 || fs.exists(\"{quoted_right_started}\") == 0 {{\n        checkpoint()\n    }}\n    discard task.group_cancel(group)\n    if fs.read_file(\"{quoted_left_cleanup}\") == \"cancelled\" && fs.read_file(\"{quoted_right_cleanup}\") == \"cancelled\" {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("task.group_cancel runtime program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        assert_eq!(
            std::fs::read_to_string(&left_cleanup).expect("left cleanup file should exist"),
            "cancelled"
        );
        assert_eq!(
            std::fs::read_to_string(&right_cleanup).expect("right cleanup file should exist"),
            "cancelled"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(left_started);
        let _ = std::fs::remove_file(right_started);
        let _ = std::fs::remove_file(left_cleanup);
        let _ = std::fs::remove_file(right_cleanup);
    }

    #[test]
    fn http_stream_read_line_respects_task_local_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr should resolve");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept connection");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).expect("server read should succeed");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                )
                .expect("server headers should write");
            stream.flush().expect("headers flush should succeed");
            std::thread::sleep(std::time::Duration::from_millis(150));
            stream
                .write_all(b"event: message_start\n\n")
                .expect("event write should succeed");
            stream.flush().expect("event flush should succeed");
        });

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-http-stream-timeout-{suffix}.fzy"));
        std::fs::write(
            &source,
            format!(
                "use core.http;\nuse core.thread;\n\nfn main() -> i32 {{\n    discard http.header_set(\"accept\", \"text/event-stream\")\n    timeout(25)\n    let stream = http.post_json_stream(\"http://127.0.0.1:{}/sse\", \"{{\\\"stream\\\":true}}\")\n    defer http.stream_close(stream)\n    if http.stream_status(stream) != 200 {{\n        return http.stream_status(stream)\n    }}\n    let line = http.stream_read_line(stream)\n    let err = http.stream_error(stream)\n    if line == \"\" && (http.stream_eof(stream) == 1 || str.len(err) > 0) {{\n        return 0\n    }}\n    return 17\n}}\n",
                addr.port()
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("http stream timeout program should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );

        server.join().expect("server thread should finish");
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn request_handler_spawns_preserve_join_results_and_json_response() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-spawn-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_spawn\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_spawn\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.http;\nuse core.proc;\nuse core.thread;\n\nfn probe_worker() -> i32 {{\n    return 7\n}}\n\nfn left_worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'exit 0'\")\n}}\n\nfn right_worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'exit 0'\")\n}}\n\nfn write_response(conn: HttpHandle) -> i32 {{\n    let probe = spawn(probe_worker)\n    let left = spawn(left_worker)\n    let right = spawn(right_worker)\n    let probe_result = join(probe)\n    let left_result = join(left)\n    let right_result = join(right)\n    if probe_result == 7 && left_result == 0 && right_result == 0 {{\n        let payload = map.new()\n        discard map.set(payload, \"probe_result\", json.str(\"7\"))\n        discard map.set(payload, \"left_result\", json.str(\"0\"))\n        discard map.set(payload, \"right_result\", json.str(\"0\"))\n        http.write_json(conn, 200, json.object(payload))\n        return 0\n    }}\n    let err = map.new()\n    discard map.set(err, \"probe_result\", json.str(\"bad\"))\n    discard map.set(err, \"left_result\", json.str(\"bad\"))\n    discard map.set(err, \"right_result\", json.str(\"bad\"))\n    http.write_json(conn, 500, json.object(err))\n    return 13\n}}\n\nfn main() -> i32 {{\n    let listener = http.bind(\"127.0.0.1:{port}\")\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let conn = http.accept()\n    http.read(conn)\n    let method = http.method(conn)\n    let path = http.path(conn)\n    if method == \"POST\" && path == \"/tools/parallel_bash/run\" {{\n        return write_response(conn)\n    }}\n    http.write_json(conn, 404, \"{{}}\")\n    return 0\n}}\n",
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(
            artifact.status,
            "ok",
            "request-path spawn repro should compile cleanly: diagnostics={:#?}, root={}",
            artifact.diagnostic_details,
            root.display()
        );
        let binary = artifact.output.unwrap_or_else(|| {
            panic!(
                "build artifact should include output path: root={}",
                root.display()
            )
        });

        let mut child = std::process::Command::new(&binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        use std::io::{Read as _, Write as _};
        stream
            .write_all(
                b"POST /tools/parallel_bash/run HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.contains("\"probe_result\":\"7\""),
            "response should preserve probe result json: {response}"
        );
        assert!(
            response.contains("\"left_result\":\"0\""),
            "response should preserve left result json: {response}"
        );
        assert!(
            response.contains("\"right_result\":\"0\""),
            "response should preserve right result json: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn host_backed_http_read_succeeds_after_poll_registration() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-read-poll-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_read_poll\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_read_poll\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            &format!(
                "use core.http;\n\nfn main() -> i32 {{\n    let listener = http.bind(\"127.0.0.1:{port}\")\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let conn = http.accept()\n    if http.poll_register(conn) != 0 {{\n        discard http.close(conn)\n        return 23\n    }}\n    discard http.poll_next()\n    let read_status = http.read(conn)\n    if read_status != 0 {{\n        http.write(conn, 503, \"{{\\\"error\\\":\\\"read_failed\\\"}}\")\n        return 25\n    }}\n    http.write(conn, 200, \"ok\")\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.ends_with("ok"),
            "response body should be ok: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn request_handler_body_json_stays_stable_under_repeated_json_churn() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-body-json-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_body_json\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_body_json\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            &format!(
                "use core.http;\n\nfn write_echo(conn: HttpHandle, body: JsonHandle) -> i32 {{\n    let message = json.get_str(body, \"message\")\n    let tag = json.get_str(body, \"tag\")\n    let meta = map.new()\n    discard map.set(meta, \"message\", json.str(message))\n    discard map.set(meta, \"tag\", json.str(tag))\n    discard map.set(meta, \"kind\", json.str(\"body_json\"))\n    let items = list.new()\n    discard list.push(items, json.str(message))\n    discard list.push(items, json.str(tag))\n    discard list.push(items, json.object(meta))\n    let payload = map.new()\n    discard map.set(payload, \"ok\", json.raw(\"true\"))\n    discard map.set(payload, \"message\", json.str(message))\n    discard map.set(payload, \"tag\", json.str(tag))\n    discard map.set(payload, \"echo\", json.object(meta))\n    discard map.set(payload, \"items\", json.array(items))\n    return http.write_json(conn, 200, json.object(payload))\n}}\n\nfn main() -> i32 {{\n    let listener = http.bind(\"127.0.0.1:{port}\")\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let mut served = 0\n    while served < 12 {{\n        let conn = http.accept()\n        http.read(conn)\n        let method = http.method(conn)\n        let path = http.path(conn)\n        if method == \"POST\" && path == \"/echo\" {{\n            let body = http.body_json(conn)\n            discard write_echo(conn, body)\n        }} else {{\n            http.write_json(conn, 404, \"{{}}\")\n        }}\n        served = served + 1\n    }}\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        for idx in 0..12 {
            let start = std::time::Instant::now();
            let mut stream = loop {
                match std::net::TcpStream::connect(("127.0.0.1", port)) {
                    Ok(stream) => break stream,
                    Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(error) => {
                        let _ = child.kill();
                        panic!("request should connect: {error}");
                    }
                }
            };
            let body = format!(
                "{{\"message\":\"msg-{idx}\",\"tag\":\"tag-{idx}\",\"meta\":{{\"slot\":\"{idx}\"}}}}"
            );
            let request = format!(
                "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(request.as_bytes())
                .expect("request should write");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("response should read");
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "response was: {response}"
            );
            assert!(
                response.contains(&format!("\"message\":\"msg-{idx}\"")),
                "response should preserve message field: {response}"
            );
            assert!(
                response.contains(&format!("\"tag\":\"tag-{idx}\"")),
                "response should preserve tag field: {response}"
            );
            assert!(
                response.contains("\"ok\":true"),
                "response should preserve raw boolean field: {response}"
            );
            assert!(
                response.contains("\"kind\":\"body_json\""),
                "response should preserve nested echo metadata: {response}"
            );
            assert!(
                !response.trim_end().ends_with("{}"),
                "response should not collapse to an empty json object: {response}"
            );
        }

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn host_backed_http_read_preserves_prefetched_content_length_body() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-prefetched-body-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_prefetched_body\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_prefetched_body\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            &format!(
                "use core.http;\n\nfn main() -> i32 {{\n    let listener = http.bind(\"127.0.0.1:{port}\")\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let conn = http.accept()\n    if http.read(conn) != 0 {{\n        discard http.close(conn)\n        return 23\n    }}\n    let body = http.body(conn)\n    discard http.write_response(conn, 200, \"application/json; charset=utf-8\", body, 1)\n    if body == \"{{\\\"ok\\\":true}}\" {{\n        return 0\n    }}\n    return 25\n}}\n"
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        let body = "{\"ok\":true}";
        let request = format!(
            "POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.contains("{\"ok\":true}"),
            "prefetched request body should survive http.read buffering: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn storage_kv_roundtrips_and_closes_handles_cleanly() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-storage-roundtrip-{suffix}"));
        let source = root.join("src/main.fzy");
        let out_path = root.join("out.txt");
        let store_path = root.join("store.kv");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"storage_roundtrip\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"storage_roundtrip\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.storage;\n\nfn main() -> i32 {{\n    let left = storage.kv_open(\"{}\")\n    discard storage.kv_put(left, \"session:key\", \"value\")\n    let right = storage.kv_open(\"{}\")\n    discard fs.write_file(\"{}\", storage.kv_get(right, \"session:key\"))\n    discard storage.kv_close(left)\n    discard storage.kv_close(right)\n    return 0\n}}\n",
                store_path.display(),
                store_path.display(),
                out_path.display(),
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("storage roundtrip should succeed");
        assert!(
            output.contains("\"exitCode\":0"),
            "unexpected output: {output}"
        );
        let persisted = std::fs::read_to_string(&out_path).expect("roundtrip output should exist");
        assert_eq!(persisted, "value");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fz_run_matches_direct_binary_for_child_process_build_orchestration() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-run-parity-{suffix}"));
        let source = root.join("src/main.fzy");
        let fixture_root = root.join("fixture-project");
        let report_path = fixture_root.join("configure.report.json");
        let config_path = fixture_root.join("demo.toml");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::create_dir_all(&fixture_root).expect("fixture root should be created");
        std::fs::write(&config_path, "name = \"demo\"\n").expect("config should be written");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"run_parity\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"run_parity\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            r#"use core.fs;
use core.proc;
use core.process;

fn find_flag(args: ListHandle, name: str) -> str {
    let mut idx = 0
    while idx < list.len(args) {
        if list.get(args, idx) == name {
            if idx + 1 < list.len(args) {
                return list.get(args, idx + 1)
            }
            return ""
        }
        idx += 1
    }
    return ""
}

fn argv_list() -> ListHandle {
    let out = list.new()
    let mut idx = 0
    while idx < process.argv_count() {
        discard list.push(out, process.argv_or(idx, ""))
        idx += 1
    }
    return out
}

fn run_build(project_root: str) -> i32 {
    let env_map = proc.env_new()
    let argv = proc.argv_new()
    let report = str.concat(project_root, "/configure.report.json")
    let command = str.concat("printf '{\"status\":\"0\",\"stdout\":\"configured\",\"stderr\":\"\"}' > ", report)
    discard proc.argv_push(argv, "-lc")
    discard proc.argv_push(argv, command)
    let handle = proc.spawn_cmd("/bin/sh", argv, env_map, "")
    discard proc.wait(handle, 5000)
    let exit_code = proc.exit_code(handle)
    discard proc.stdout(handle)
    discard proc.stderr(handle)
    discard proc.close(handle)
    let payload = fs.read_file(report)
    if exit_code == 0 && str.contains(payload, "\"status\":\"0\"") == 1 {
        return 0
    }
    return 1
}

fn main() -> i32 {
    let args = argv_list()
    let command = process.argv_or(1, "")
    let project_root = find_flag(args, "--project")
    discard find_flag(args, "--config")
    if command == "build" && project_root != "" {
        return run_build(project_root)
    }
    return 64
}
"#,
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .clone()
            .expect("build artifact should include output path");

        let direct = std::process::Command::new(&binary)
            .args([
                "build",
                "--project",
                fixture_root.to_string_lossy().as_ref(),
                "--config",
                config_path.to_string_lossy().as_ref(),
            ])
            .output()
            .expect("direct binary should run");
        assert_eq!(direct.status.code(), Some(0));
        assert!(std::fs::read_to_string(&report_path)
            .expect("report should exist after direct run")
            .contains("\"status\":\"0\""));

        let _ = std::fs::remove_file(&report_path);
        let wrapped = run(
            Command::Run {
                path: root.clone(),
                args: vec![
                    "build".to_string(),
                    "--project".to_string(),
                    fixture_root.display().to_string(),
                    "--config".to_string(),
                    config_path.display().to_string(),
                ],
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("wrapped run should succeed");
        assert!(
            wrapped.contains("\"exitCode\":0"),
            "unexpected wrapped output: {wrapped}"
        );
        assert!(std::fs::read_to_string(&report_path)
            .expect("report should exist after wrapped run")
            .contains("\"status\":\"0\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn response_headers_support_custom_and_repeated_set_cookie_values() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-response-headers-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_response_headers\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_response_headers\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            &format!(
                "use core.http;\n\nfn main() -> i32 {{\n    let listener = http.bind(\"127.0.0.1:{port}\")\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let conn = http.accept()\n    if http.read(conn) != 0 {{\n        discard http.close(conn)\n        return 23\n    }}\n    discard http.response_header_set(conn, \"X-Test\", \"present\")\n    discard http.response_header_add(conn, \"Set-Cookie\", \"sid=abc; Path=/; HttpOnly\")\n    discard http.response_header_add(conn, \"Set-Cookie\", \"pref=dark; Path=/; Secure\")\n    discard http.write_response(conn, 200, \"text/plain; charset=utf-8\", \"ok\", 1)\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("server did not become reachable: {error}");
                }
            }
        };
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .expect("request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.contains("X-Test: present"),
            "custom header missing from response: {response}"
        );
        assert!(
            response.contains("Set-Cookie: sid=abc; Path=/; HttpOnly"),
            "first set-cookie missing from response: {response}"
        );
        assert!(
            response.contains("Set-Cookie: pref=dark; Path=/; Secure"),
            "second set-cookie missing from response: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn request_body_streaming_reads_chunked_uploads_incrementally() {
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-http-body-stream-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"http_body_stream\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"http_body_stream\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            &format!(
                "use core.http;\n\nfn main() -> i32 {{\n    let listener = http.bind(\"127.0.0.1:{port}\")\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let conn = http.accept()\n    if http.read_headers(conn) != 0 {{\n        discard http.close(conn)\n        return 23\n    }}\n    let mut body = \"\"\n    while http.body_eof(conn) == 0 {{\n        body = str.concat(body, http.body_read(conn, 4))\n    }}\n    discard http.write_response(conn, 200, \"text/plain; charset=utf-8\", body, 1)\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::{Read as _, Write as _};
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("request should connect: {error}");
                }
            }
        };
        stream
            .write_all(
                b"POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nstre\r\n4\r\namin\r\n2\r\ng!\r\n0\r\n\r\n",
            )
            .expect("chunked request should write");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("response should read");

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "response was: {response}"
        );
        assert!(
            response.ends_with("streaming!"),
            "streamed body should round-trip through response: {response}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn websocket_upgrade_supports_text_frame_round_trip() {
        fn read_http_headers(stream: &mut std::net::TcpStream) -> String {
            use std::io::Read as _;
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 256];
                let read = stream.read(&mut chunk).expect("header read should succeed");
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            String::from_utf8_lossy(&buf).to_string()
        }

        fn write_masked_text_frame(stream: &mut std::net::TcpStream, text: &str) {
            use std::io::Write as _;
            let payload = text.as_bytes();
            let mask = [0x11u8, 0x22, 0x33, 0x44];
            let mut frame = Vec::new();
            frame.push(0x81u8);
            frame.push(0x80u8 | payload.len() as u8);
            frame.extend_from_slice(&mask);
            for (idx, byte) in payload.iter().enumerate() {
                frame.push(byte ^ mask[idx % 4]);
            }
            stream.write_all(&frame).expect("frame should write");
        }

        fn read_ws_frame(stream: &mut std::net::TcpStream) -> (u8, Vec<u8>) {
            use std::io::Read as _;
            let mut hdr = [0u8; 2];
            stream
                .read_exact(&mut hdr)
                .expect("frame header should read");
            let opcode = hdr[0] & 0x0f;
            let mut len = (hdr[1] & 0x7f) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                stream
                    .read_exact(&mut ext)
                    .expect("extended len should read");
                len = u16::from_be_bytes(ext) as usize;
            }
            let mut payload = vec![0u8; len];
            if len > 0 {
                stream
                    .read_exact(&mut payload)
                    .expect("payload should read");
            }
            (opcode, payload)
        }

        let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
        let port = probe
            .local_addr()
            .expect("probe addr should resolve")
            .port();
        drop(probe);

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-websocket-upgrade-{suffix}"));
        let source = root.join("src/main.fzy");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"websocket_upgrade\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"websocket_upgrade\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            &format!(
                "use core.http;\n\nfn main() -> i32 {{\n    let listener = http.bind(\"127.0.0.1:{port}\")\n    defer close(listener)\n    if http.listen(listener) != 0 {{\n        return 21\n    }}\n    let conn = http.accept()\n    defer close(conn)\n    if http.read_headers(conn) != 0 {{\n        return 23\n    }}\n    let ws = http.websocket_accept(conn)\n    let message = http.websocket_read(ws, 256)\n    let kind = http.websocket_kind(ws)\n    if kind != \"text\" || message != \"hello\" {{\n        discard http.websocket_close(ws, 1002, \"protocol\")\n        return 25\n    }}\n    discard http.websocket_write_text(ws, \"world\")\n    discard http.websocket_close(ws, 1000, \"bye\")\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("server child should spawn");

        use std::io::Write as _;
        let start = std::time::Instant::now();
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(_) if start.elapsed() <= std::time::Duration::from_secs(5) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => {
                    let _ = child.kill();
                    panic!("request should connect: {error}");
                }
            }
        };
        stream
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .expect("websocket upgrade should write");
        let response = read_http_headers(&mut stream);
        assert!(
            response.starts_with("HTTP/1.1 101"),
            "upgrade response was: {response}"
        );
        assert!(
            response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "accept hash missing from response: {response}"
        );

        write_masked_text_frame(&mut stream, "hello");
        let (opcode, payload) = read_ws_frame(&mut stream);
        assert_eq!(opcode, 0x1, "expected text frame opcode");
        assert_eq!(String::from_utf8_lossy(&payload), "world");
        let (close_opcode, close_payload) = read_ws_frame(&mut stream);
        assert_eq!(close_opcode, 0x8, "expected close frame opcode");
        assert!(close_payload.len() >= 2, "close payload missing code");
        assert_eq!(
            u16::from_be_bytes([close_payload[0], close_payload[1]]),
            1000
        );

        let status = child.wait().expect("server child should exit");
        assert_eq!(status.code(), Some(0));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn run_supports_same_function_name_in_sibling_modules() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-module-collision-{suffix}"));
        std::fs::create_dir_all(&root).expect("root should be created");
        let main = root.join("main.fzy");
        std::fs::write(
            &main,
            "mod a;\nmod b;\nfn main() -> i32 {\n    let sum: i32 = a.ping() + b.ping()\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("a.fzy"), "fn ping() -> i32 {\n    return 1\n}\n")
            .expect("a module should be written");
        std::fs::write(root.join("b.fzy"), "fn ping() -> i32 {\n    return 2\n}\n")
            .expect("b module should be written");

        let check = run(Command::Check { path: main.clone() }, Format::Json)
            .expect("check should succeed for sibling name collisions");
        assert!(check.contains("\"errors\":0"));
        let run_output = run(
            Command::Run {
                path: main.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run should succeed for sibling name collisions");
        assert!(run_output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compiler_phase_fixture_check_verify_build_and_parity_stay_aligned() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/compiler_phase_lockin");

        let check = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("check should succeed for compiler phase fixture");
        let check_payload: serde_json::Value =
            serde_json::from_str(&check).expect("check output should be valid json");
        assert_eq!(check_payload["errors"].as_u64(), Some(0));
        assert_eq!(check_payload["module"].as_str(), Some("main"));

        let verify = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should succeed for compiler phase fixture");
        let verify_payload: serde_json::Value =
            serde_json::from_str(&verify).expect("verify output should be valid json");
        assert_eq!(verify_payload["errors"].as_u64(), Some(0));
        assert_eq!(verify_payload["warnings"].as_u64(), Some(0));

        let build = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("build should succeed for compiler phase fixture");
        let build_payload: serde_json::Value =
            serde_json::from_str(&build).expect("build output should be valid json");
        assert_eq!(build_payload["status"].as_str(), Some("ok"));
        assert!(build_payload["dependencyGraphHash"].is_string());
        assert_eq!(
            build_payload["policy"]["lockfileState"].as_str(),
            Some("present")
        );

        let parity = run(
            Command::Parity {
                path: root.clone(),
                seed: Some(4242),
            },
            Format::Json,
        )
        .expect("parity should succeed for compiler phase fixture");
        let parity_payload: serde_json::Value =
            serde_json::from_str(&parity).expect("parity output should be valid json");
        assert_eq!(parity_payload["ok"].as_bool(), Some(true));
        assert_eq!(
            parity_payload["checks"]["sameVerifierResult"].as_bool(),
            Some(true)
        );
        assert_eq!(
            parity_payload["checks"]["sameExitCode"].as_bool(),
            Some(true)
        );
        assert_eq!(parity_payload["checks"]["sameStdout"].as_bool(), Some(true));
        assert_eq!(
            parity_payload["checks"]["sameRuntimeBehavior"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn compiler_phase_commands_invalidate_import_cache_and_recover_after_fix() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-command-cache-{suffix}"));
        std::fs::create_dir_all(root.join("src/services")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"compiler_cache\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"compiler_cache\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.term;\nmod services;\nfn main() -> i32 {\n    discard term.write(\"cache-check\\n\")\n    return services.boot()\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("service source should be written");

        let first = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("first check should succeed");
        let first_payload: serde_json::Value =
            serde_json::from_str(&first).expect("first check should be valid json");
        assert_eq!(first_payload["errors"].as_u64(), Some(0));

        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn renamed() -> i32 {\n    return 0\n}\n",
        )
        .expect("service source should mutate");

        let broken_check = run(Command::Check { path: root.clone() }, Format::Json)
            .expect("broken check should return diagnostics");
        let broken_check_payload: serde_json::Value =
            serde_json::from_str(&broken_check).expect("broken check should be valid json");
        assert!(broken_check_payload["errors"].as_u64().unwrap_or(0) > 0);
        let broken_messages = broken_check_payload["items"]
            .as_array()
            .expect("diagnostic items should be an array")
            .iter()
            .filter_map(|item| item["message"].as_str())
            .collect::<Vec<_>>();
        assert!(broken_messages
            .iter()
            .any(|message| message.contains("unresolved call target `services.boot`")));

        let broken_verify = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("broken verify should return diagnostics");
        let broken_verify_payload: serde_json::Value =
            serde_json::from_str(&broken_verify).expect("broken verify should be valid json");
        assert!(broken_verify_payload["errors"].as_u64().unwrap_or(0) > 0);

        let broken_build = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("broken build should return diagnostics");
        let broken_build_payload: serde_json::Value =
            serde_json::from_str(&broken_build).expect("broken build should be valid json");
        assert_eq!(broken_build_payload["status"].as_str(), Some("error"));

        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("service source should be restored");

        let repaired_build = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect("repaired build should succeed");
        let repaired_build_payload: serde_json::Value =
            serde_json::from_str(&repaired_build).expect("repaired build should be valid json");
        assert_eq!(repaired_build_payload["status"].as_str(), Some("ok"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compiler_phase_fixture_host_backed_run_stays_warning_free() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/compiler_phase_lockin");

        let output = run(
            Command::Run {
                path: root,
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backed run should succeed for compiler phase fixture");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("run output should be valid json");
        assert_eq!(payload["status"].as_str(), Some("ok"));
        assert_eq!(payload["diagnostics"].as_u64(), Some(0));
        assert_eq!(payload["exitCode"].as_i64(), Some(0));
    }

    #[test]
    fn compiler_phase_invalid_programs_emit_diagnostics_not_panics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-command-invalid-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"compiler_invalid\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"compiler_invalid\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main( -> i32 {\n    return 0\n}\n",
        )
        .expect("invalid source should be written");

        for output in [
            run(Command::Check { path: root.clone() }, Format::Json)
                .expect("check should return diagnostics"),
            run(Command::Verify { path: root.clone() }, Format::Json)
                .expect("verify should return diagnostics"),
        ] {
            assert!(
                !output.contains("panicked at"),
                "compiler command should emit diagnostics instead of panicking: {output}"
            );
            let payload: serde_json::Value =
                serde_json::from_str(&output).expect("command output should be valid json");
            let errors = payload["errors"]
                .as_u64()
                .unwrap_or_else(|| payload["diagnostics"].as_u64().unwrap_or(0));
            assert!(
                errors > 0,
                "invalid source should produce errors: {payload}"
            );
        }

        let build_error = run(
            Command::Build {
                path: root.clone(),
                release: false,
                strict: false,
                incremental: false,
                lib: false,
                threads: None,
                backend: Some("llvm".to_string()),
                pgo_generate: false,
                pgo_use: None,
                link_libs: Vec::new(),
                link_search: Vec::new(),
                frameworks: Vec::new(),
            },
            Format::Json,
        )
        .expect_err("build should fail cleanly for invalid source");
        assert!(
            !build_error.to_string().contains("panicked at"),
            "build should fail with diagnostics, not panic: {build_error}"
        );
        assert!(
            build_error.to_string().contains("parse failed"),
            "build failure should preserve parser diagnostics: {build_error}"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_run_host_backends_preserves_live_run_semantics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-backend-flag-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native host backend run should stay on the live run path");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        assert!(!output.contains("\"bridge\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_preserves_cli_args_and_terminal_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-term-args-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.process;\nuse core.term;\n\nfn main() -> i32 {\n    let current = process.current()\n    let tty = term.status()\n    let style = term.transcript_style(4)\n    discard term.transcript_write(style, \"argc\", str.from_i32(current.argc))\n    discard term.transcript_write(style, \"cmd\", current.command)\n    discard term.transcript_write(style, \"mode\", process.argv_or(1, \"\"))\n    discard term.transcript_write(style, \"stdin\", str.from_i32(tty.stdin_is_tty))\n    discard term.transcript_write(style, \"stdout\", str.from_i32(tty.stdout_is_tty))\n    discard term.eprint_line(str.concat(\"flag=\", process.argv_or(2, \"\")))\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: vec!["serve".to_string(), "--json".to_string()],
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native run with cli args should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("argc 3"), "output was: {output}");
        assert!(output.contains("mode serve"), "output was: {output}");
        assert!(output.contains("stdin"), "output was: {output}");
        assert!(output.contains("stdout"), "output was: {output}");
        assert!(output.contains("flag=--json"), "output was: {output}");
        assert!(output.contains("\"stdout\":\""), "output was: {output}");
        assert!(output.contains("\"stderr\":\""), "output was: {output}");

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_host_backends_preserves_cli_args_and_terminal_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-term-host-args-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.process;\nuse core.term;\n\nfn main() -> i32 {\n    let current = process.current()\n    discard term.transcript_write(term.transcript_style(4), \"argc\", str.from_i32(current.argc))\n    discard term.transcript_write(term.transcript_style(4), \"mode\", process.argv_or(1, \"\"))\n    discard term.eprint_line(str.concat(\"flag=\", process.argv_or(2, \"\")))\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: vec!["serve".to_string(), "--json".to_string()],
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: Some(10),
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native host backend run with cli args should succeed");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("argc 3"), "output was: {output}");
        assert!(output.contains("mode serve"), "output was: {output}");
        assert!(output.contains("flag=--json"), "output was: {output}");

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_core_log_policy_routes_and_filters_output() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-log-policy-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.log;\n\nfn main() -> i32 {\n    let hidden = map.new()\n    let shown = map.new()\n    discard map.set(hidden, \"phase\", \"hidden\")\n    discard map.set(shown, \"phase\", \"shown\")\n    discard log.set_enabled(1)\n    discard log.set_sink_name(\"stderr\")\n    discard log.set_level_name(\"warn\")\n    discard log.info(\"hidden-info\", log.fields(hidden))\n    discard log.warn(\"shown-warn\", log.fields(shown))\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native log policy run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("shown-warn"), "output was: {output}");
        assert!(!output.contains("hidden-info"), "output was: {output}");
        assert!(output.contains("\"stderr\":\""), "output was: {output}");

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_core_text_and_transcript_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-core-text-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-core-text-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.term;\nuse core.text;\n\nfn main() -> i32 {{\n    let payload = map.new()\n    discard map.set(payload, \"left\", json.str(text.pad_left(\"7\", 3)))\n    discard map.set(payload, \"right\", json.str(text.pad_right(\"ok\", 4)))\n    discard map.set(payload, \"indented\", json.str(text.indent(\"a\\nb\", \"> \")))\n    discard map.set(payload, \"ansi_width\", json.str(str.from_i32(text.visible_len_ansi(\"\\x1b[31mred\\x1b[0m\"))))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    discard term.transcript_kv(\"mode\", \"chat\", 8)\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("core text helpers run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(output.contains("mode     chat"), "output was: {output}");
        let content =
            std::fs::read_to_string(&out_path).expect("core text helper output should exist");
        assert!(
            content.contains("\"left\":\"  7\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"right\":\"ok  \""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"ansi_width\":\"3\""),
            "content was: {content}"
        );
        assert!(content.contains("> a\\n> b"), "content was: {content}");

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_string_slice_and_ascii_case_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-str-slice-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-str-slice-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.text;\n\nfn main() -> i32 {{\n    let payload = map.new()\n    discard map.set(payload, \"0\", json.str(str.slice(\"name\", 0, 1)))\n    discard map.set(payload, \"1\", json.str(str.slice(\"name\", 1, 2)))\n    discard map.set(payload, \"2\", json.str(str.slice(\"name\", 2, 3)))\n    discard map.set(payload, \"3\", json.str(str.slice(\"name\", 3, 4)))\n    discard map.set(payload, \"upper\", json.str(text.upper_ascii(\"tool_arg_name\")))\n    discard map.set(payload, \"lower\", json.str(text.lower_ascii(\"TOOL_ARG_NAME\")))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("string slice/case runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");
        let content =
            std::fs::read_to_string(&out_path).expect("string slice/case output should exist");
        assert!(content.contains("\"0\":\"n\""), "content was: {content}");
        assert!(content.contains("\"1\":\"a\""), "content was: {content}");
        assert!(content.contains("\"2\":\"m\""), "content was: {content}");
        assert!(content.contains("\"3\":\"e\""), "content was: {content}");
        assert!(
            content.contains("\"upper\":\"TOOL_ARG_NAME\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"lower\":\"tool_arg_name\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_mutable_string_accumulation_persists_concat_results() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-str-accumulate-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-str-accumulate-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn upper_char(ch: str) -> str {{\n    if ch == \"a\" {{ return \"A\" }}\n    if ch == \"n\" {{ return \"N\" }}\n    if ch == \"m\" {{ return \"M\" }}\n    if ch == \"e\" {{ return \"E\" }}\n    return ch\n}}\n\nfn main() -> i32 {{\n    let payload = map.new()\n    let mut serial = \"\"\n    serial = str.concat(serial, \"N\")\n    serial = str.concat(serial, \"A\")\n    serial = str.concat(serial, \"M\")\n    serial = str.concat(serial, \"E\")\n    let mut from_slice = \"\"\n    let value = \"name\"\n    let mut idx: i32 = 0\n    while idx < str.len(value) {{\n        from_slice = str.concat(from_slice, upper_char(str.slice(value, idx, idx + 1)))\n        idx += 1\n    }}\n    discard map.set(payload, \"direct\", json.str(str.concat(\"A\", \"B\")))\n    discard map.set(payload, \"serial\", json.str(serial))\n    discard map.set(payload, \"slice_loop\", json.str(from_slice))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("mutable string accumulation runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");
        let content = std::fs::read_to_string(&out_path)
            .expect("mutable string accumulation output should exist");
        assert!(
            content.contains("\"direct\":\"AB\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"serial\":\"NAME\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"slice_loop\":\"NAME\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_core_io_and_path_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-core-io-{suffix}"));
        let nested = root.join("custom_tools");
        std::fs::create_dir_all(&nested).expect("nested directory should be created");
        std::fs::write(nested.join("tool.json"), "{\"name\":\"demo\"}")
            .expect("probe file should be created");
        let source = std::env::temp_dir().join(format!("fozzylang-core-io-{suffix}.fzy"));
        let quoted_root = root.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.io;\nuse core.path;\n\nfn main() -> i32 {{\n    let dir = path.join(\"{quoted_root}\", \"custom_tools\")\n    let entries = io.list_dir(dir)\n    if list.len(entries) != 1 {{\n        return 11\n    }}\n    if list.get(entries, 0) != \"tool.json\" {{\n        return 12\n    }}\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("core io/path helpers run should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_binary_reads_piped_stdin_and_reports_non_tty_mode() {
        use std::io::Write as _;

        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-term-stdin-{suffix}"));
        let source = root.join("src/main.fzy");
        let out_path = std::env::temp_dir().join(format!("fozzylang-term-stdin-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"term_stdin\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"term_stdin\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\nuse core.term;\n\nfn main() -> i32 {{\n    let line = term.read_line()\n    let eof_before = term.stdin_eof()\n    let second = term.read_line()\n    let eof_after = term.stdin_eof()\n    let payload = map.new()\n    discard map.set(payload, \"line\", json.str(line))\n    discard map.set(payload, \"second\", json.str(second))\n    discard map.set(payload, \"eof_before\", json.str(str.from_i32(eof_before)))\n    discard map.set(payload, \"eof_after\", json.str(str.from_i32(eof_after)))\n    discard map.set(payload, \"stdin_tty\", json.str(str.from_i32(term.stdin_is_tty())))\n    discard map.set(payload, \"stdout_tty\", json.str(str.from_i32(term.stdout_is_tty())))\n    fs.write_file(\"{quoted_out}\", json.object(payload))\n    discard term.print(\"prompt> \")\n    discard term.eprint_line(\"warn\")\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let artifact = compile_file_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            Some("cranelift"),
        )
        .expect("build should succeed");
        assert_eq!(artifact.status, "ok");
        let binary = artifact
            .output
            .expect("build artifact should include output path");

        let mut child = std::process::Command::new(&binary)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("binary should spawn");
        child
            .stdin
            .take()
            .expect("stdin pipe should exist")
            .write_all(b"hello world\n")
            .expect("stdin should write");
        let output = child.wait_with_output().expect("child should exit");
        assert_eq!(output.status.code(), Some(0));

        let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
        let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
        assert!(stdout.contains("prompt> "), "stdout was: {stdout}");
        assert!(stderr.contains("warn"), "stderr was: {stderr}");

        let content =
            std::fs::read_to_string(&out_path).expect("stdin runtime output should exist");
        assert!(
            content.contains("\"line\":\"hello world\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"second\":\"\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"eof_before\":\"0\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"eof_after\":\"1\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"stdin_tty\":\"0\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"stdout_tty\":\"0\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_json_array_traversal_and_raw_extraction_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-json-array-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-json-array-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn main() -> i32 {{\n    let parsed = json.parse(\"{{\\\"content\\\":[{{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"hi\\\"}},{{\\\"type\\\":\\\"tool_use\\\",\\\"name\\\":\\\"bash\\\",\\\"input\\\":{{\\\"command\\\":\\\"printf ok\\\"}}}}]}}\")\n    let content = json.get(parsed, \"content\")\n    let block0 = json.get(content, \"0\")\n    let block1 = json.get(content, \"1\")\n    let input = json.get(block1, \"input\")\n    let out = map.new()\n    discard map.set(out, \"content_raw\", json.str(json.get_str(content, \"raw\")))\n    discard map.set(out, \"block0_type\", json.str(json.get_str(block0, \"type\")))\n    discard map.set(out, \"block0_text\", json.str(json.get_str(block0, \"text\")))\n    discard map.set(out, \"block1_type\", json.str(json.get_str(block1, \"type\")))\n    discard map.set(out, \"block1_name\", json.str(json.get_str(block1, \"name\")))\n    discard map.set(out, \"input_raw\", json.str(json.get_str(input, \"raw\")))\n    fs.write_file(\"{quoted_out}\", json.object(out))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("json array traversal runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let content =
            std::fs::read_to_string(&out_path).expect("json array traversal output should exist");
        assert!(
            content.contains("\"block0_type\":\"text\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"block0_text\":\"hi\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"block1_type\":\"tool_use\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"block1_name\":\"bash\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\\\"command\\\":\\\"printf ok\\\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\\\"type\\\":\\\"text\\\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_json_object_key_iteration_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-json-keys-{suffix}.fzy"));
        let out_path = std::env::temp_dir().join(format!("fozzylang-json-keys-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn main() -> i32 {{\n    let parsed = json.parse(\"{{\\\"message\\\":\\\"hi\\\",\\\"count\\\":\\\"2\\\"}}\")\n    let keys = json.keys(parsed)\n    let child = json.get(parsed, list.get(keys, 0))\n    let as_map = json.to_map(parsed)\n    let out = map.new()\n    discard map.set(out, \"keys_len\", json.str(str.from_i32(list.len(keys))))\n    discard map.set(out, \"first_key\", json.str(list.get(keys, 0)))\n    discard map.set(out, \"first_raw\", json.str(json.get_str(child, \"raw\")))\n    discard map.set(out, \"map_keys_len\", json.str(str.from_i32(list.len(map.keys(as_map)))))\n    fs.write_file(\"{quoted_out}\", json.object(out))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("json object key iteration runtime program should succeed");
        assert!(output.contains("\"exitCode\":0"), "output was: {output}");
        let content =
            std::fs::read_to_string(&out_path).expect("json key iteration output should exist");
        assert!(
            content.contains("\"keys_len\":\"2\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"map_keys_len\":\"2\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"first_key\":\"message\"")
                || content.contains("\"first_key\":\"count\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\"first_raw\":\"\\\"hi\\\"\"")
                || content.contains("\"first_raw\":\"\\\"2\\\"\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_host_backends_preserves_fs_side_effects_for_json_array_traversal() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-json-array-host-{suffix}"));
        let source = root.join("src/main.fzy");
        let out_path =
            std::env::temp_dir().join(format!("fozzylang-json-array-host-{suffix}.json"));
        let quoted_out = out_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"json_array_host\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"json_array_host\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            &source,
            format!(
                "use core.fs;\n\nfn main() -> i32 {{\n    let parsed = json.parse(\"{{\\\"content\\\":[{{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"hi\\\"}},{{\\\"type\\\":\\\"tool_use\\\",\\\"name\\\":\\\"bash\\\",\\\"input\\\":{{\\\"command\\\":\\\"printf ok\\\"}}}}]}}\")\n    let content = json.get(parsed, \"content\")\n    let block1 = json.get(content, \"1\")\n    let input = json.get(block1, \"input\")\n    let out = map.new()\n    discard map.set(out, \"mode\", json.str(json.get_str(block1, \"type\")))\n    discard map.set(out, \"input_raw\", json.str(json.get_str(input, \"raw\")))\n    fs.write_file(\"{quoted_out}\", json.object(out))\n    return 0\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&out_path);

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: Some(10),
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("host-backend json array traversal program should succeed");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        let content = std::fs::read_to_string(&out_path)
            .expect("host-backed runtime should preserve absolute fs side effect output");
        assert!(
            content.contains("\"mode\":\"tool_use\""),
            "content was: {content}"
        );
        assert!(
            content.contains("\\\"command\\\":\\\"printf ok\\\""),
            "content was: {content}"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(out_path);
    }

    #[test]
    fn native_run_variadic_str_concat_executes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-str-concat-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let value = str.concat(\"svc/\", \"tenant/\", \"sessions/\", \"abc\", \"/latest\")\n    if str.len(value) == 30 && str.starts_with(value, \"svc/\") == 1 && str.ends_with(value, \"/latest\") == 1 {\n        return 0\n    }\n    return 13\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("variadic str.concat run should succeed");
        assert!(output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_string_conversion_and_path_helpers_execute() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-path-format-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let rendered = str.concat(\"port=\", str.from_i32(8080), \", enabled=\", str.from_bool(true))\n    let joined = path.join(\"/srv/app\", \"config/runtime.json\")\n    if rendered != \"port=8080, enabled=true\" then return 11\n    if path.dirname(joined) != \"/srv/app/config\" then return 12\n    if path.basename(joined) != \"runtime.json\" then return 13\n    if path.stem(joined) != \"runtime\" then return 14\n    if path.extension(joined) != \"json\" then return 15\n    if path.normalize(\"/srv//app/config/\") != \"/srv/app/config\" then return 16\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("path/conversion run should succeed");
        assert!(output.contains("\"exitCode\":0"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_terminal_hex_and_unicode_escapes_preserve_ansi_bytes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-ansi-escape-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    discard term.write(\"\\x1b[31mred\\u001b[0m\\033\\n\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("ansi escape run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            output.contains("\\u001b[31mred\\u001b[0m\\u001b\\n")
                || output.contains("\u{001b}[31mred\u{001b}[0m\u{001b}\n"),
            "output was: {output}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_project_root_host_backends_preserves_live_run_semantics() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-host-project-run-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"host_project_run\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"host_project_run\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("project-root host backend run should stay on the live run path");
        assert!(output.contains("\"routing\":{\"mode\":\"native-host-runtime\""));
        assert!(output.contains("\"exitCode\":0"));
        assert!(!output.contains("\"bridge\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_run_host_backends_rejects_deterministic_live_mode() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-det-reject-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");

        let error = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: None,
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect_err("native host-backed deterministic run should be rejected");
        assert!(error
            .to_string()
            .contains("deterministic execution is unavailable"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_run_project_root_host_backends_rejects_deterministic_live_mode() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-host-project-det-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"host_project_det\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"host_project_det\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("main source should be written");

        let error = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: None,
                host_backends: true,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect_err("project-root host-backed deterministic run should be rejected");
        assert!(error
            .to_string()
            .contains("deterministic execution is unavailable"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn native_test_host_backends_is_rejected_for_native_sources() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-record-{suffix}.fzy"));
        let record =
            std::env::temp_dir().join(format!("fozzylang-host-record-{suffix}.trace.fozzy"));
        std::fs::write(
            &source,
            "test \"probe\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&record);

        let error = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: true,
                safe_profile: false,
                seed: Some(4242),
                record: Some(record.clone()),
                host_backends: true,
                backend: None,
                scheduler: None,
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect_err("host-backed native test path should be rejected");
        assert!(error
            .to_string()
            .contains("host-backed execution is unavailable for native `fz test`"));
        assert!(
            !record.exists(),
            "requested record path should not be materialized"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(record);
    }

    #[test]
    fn host_backed_run_rejects_recording_for_live_native_execution() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-host-run-{suffix}.fzy"));
        let record = std::env::temp_dir().join(format!("fozzylang-host-run-{suffix}.trace.fozzy"));
        std::fs::write(
            &source,
            "test \"probe\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&record);

        let error = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: true,
                safe_profile: false,
                seed: Some(4242),
                record: Some(record.clone()),
                host_backends: true,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect_err("host-backed native run recording should be rejected");
        assert!(
            error
                .to_string()
                .contains("deterministic execution is unavailable"),
            "unexpected error: {error}"
        );
        assert!(
            !record.exists(),
            "live host-backed native run should not materialize a trace record"
        );

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(record);
    }

    #[test]
    fn run_cranelift_module_qualified_spawn_executes_nested_worker() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-module-spawn-{suffix}"));
        let output_path = std::env::temp_dir().join(format!("fozzylang-module-spawn-{suffix}.txt"));
        let quoted_out = output_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"module_spawn\"\nversion = \"0.1.0\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\n\nfn main() -> i32 {\n    return services.tools.run_probe()\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod tools;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/tools.fzy"),
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo nested > {quoted_out}'\")\n}}\n\nfn run_probe() -> i32 {{\n    let handle = spawn(worker)\n    let result = join(handle)\n    if result == 0 && fs.exists(\"{quoted_out}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("tools source should be written");
        let _ = std::fs::remove_file(&output_path);

        let output = run(
            Command::Run {
                path: root.join("src/main.fzy"),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("cranelift module-qualified spawn should succeed");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            output_path.exists(),
            "nested worker should create output file"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn run_cranelift_nested_module_spawns_complete_from_spawned_coordinator() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-nested-module-spawn-{suffix}"));
        let left_path =
            std::env::temp_dir().join(format!("fozzylang-nested-module-spawn-left-{suffix}.txt"));
        let right_path =
            std::env::temp_dir().join(format!("fozzylang-nested-module-spawn-right-{suffix}.txt"));
        let quoted_left = left_path.to_string_lossy().replace('\"', "\\\"");
        let quoted_right = right_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"nested_module_spawn\"\nversion = \"0.1.0\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nuse core.thread;\n\nfn main() -> i32 {\n    let handle = spawn(services.tools.run_probe)\n    return join(handle)\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod tools;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/tools.fzy"),
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn worker_left() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo left > {quoted_left}'\")\n}}\n\nfn worker_right() -> i32 {{\n    return proc.run(\"/bin/sh -lc 'echo right > {quoted_right}'\")\n}}\n\nfn run_probe() -> i32 {{\n    let left = spawn(worker_left)\n    let right = spawn(worker_right)\n    let left_result = join(left)\n    let right_result = join(right)\n    if left_result == 0 && right_result == 0 && fs.exists(\"{quoted_left}\") == 1 && fs.exists(\"{quoted_right}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("tools source should be written");
        let _ = std::fs::remove_file(&left_path);
        let _ = std::fs::remove_file(&right_path);

        let output = run(
            Command::Run {
                path: root.join("src/main.fzy"),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("nested module-qualified spawns should succeed from spawned coordinator");
        assert!(output.contains("\"exitCode\":0"));
        assert!(
            left_path.exists(),
            "left nested worker should create output file"
        );
        assert!(
            right_path.exists(),
            "right nested worker should create output file"
        );

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
    }

    #[test]
    fn run_cranelift_live_shape_spawns_preserve_proc_json_payloads() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-live-shape-spawn-{suffix}"));
        let left_path =
            std::env::temp_dir().join(format!("fozzylang-live-shape-left-{suffix}.json"));
        let right_path =
            std::env::temp_dir().join(format!("fozzylang-live-shape-right-{suffix}.json"));
        let quoted_left = left_path.to_string_lossy().replace('\"', "\\\"");
        let quoted_right = right_path.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"live_shape_spawn\"\nversion = \"0.1.0\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\n\nfn main() -> i32 {\n    return services.tools.run_probe()\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/services/mod.fzy"), "mod tools;\n")
            .expect("services mod should be written");
        std::fs::write(
            root.join("src/services/tools.fzy"),
            format!(
                "use core.fs;\nuse core.proc;\nuse core.thread;\n\nfn shell_payload(command: str, out_path: str) -> i32 {{\n    let env_map = proc.env_new()\n    let argv = proc.argv_new()\n    discard proc.argv_push(argv, \"-lc\")\n    discard proc.argv_push(argv, command)\n    let handle = proc.spawn_cmd(\"/bin/sh\", argv, env_map, \"\")\n    discard proc.wait(handle, 1000)\n    let stdout = proc.stdout(handle)\n    let stderr = proc.stderr(handle)\n    discard proc.close(handle)\n    let payload = map.new()\n    discard map.set(payload, \"status\", json.str(\"ok\"))\n    discard map.set(payload, \"stdout\", json.str(stdout))\n    discard map.set(payload, \"stderr\", json.str(stderr))\n    fs.write_file(out_path, json.object(payload))\n    return 0\n}}\n\nfn worker_left() -> i32 {{\n    return shell_payload(\"printf left\", \"{quoted_left}\")\n}}\n\nfn worker_right() -> i32 {{\n    return shell_payload(\"printf right\", \"{quoted_right}\")\n}}\n\nfn probe_worker() -> i32 {{\n    return 7\n}}\n\nfn run_probe() -> i32 {{\n    let probe = spawn(probe_worker)\n    let probe_result = join(probe)\n    let left = spawn(worker_left)\n    let right = spawn(worker_right)\n    let left_result = join(left)\n    let right_result = join(right)\n    if probe_result == 7 && left_result == 0 && right_result == 0 && fs.exists(\"{quoted_left}\") == 1 && fs.exists(\"{quoted_right}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("tools source should be written");
        let _ = std::fs::remove_file(&left_path);
        let _ = std::fs::remove_file(&right_path);

        let output = run(
            Command::Run {
                path: root.join("src/main.fzy"),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("live-shape nested spawns should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let left_content =
            std::fs::read_to_string(&left_path).expect("left payload should be readable");
        let right_content =
            std::fs::read_to_string(&right_path).expect("right payload should be readable");
        assert_ne!(left_content.trim(), "{}");
        assert_ne!(right_content.trim(), "{}");
        assert!(left_content.contains("\"stdout\":\"left\""));
        assert!(right_content.contains("\"stdout\":\"right\""));

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(left_path);
        let _ = std::fs::remove_file(right_path);
    }

    #[test]
    fn run_spawn_ctx_workers_preserve_string_payloads_under_concurrency() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-string-race-{suffix}"));
        let one = std::env::temp_dir().join(format!("fozzylang-string-race-one-{suffix}.json"));
        let two = std::env::temp_dir().join(format!("fozzylang-string-race-two-{suffix}.json"));
        let three = std::env::temp_dir().join(format!("fozzylang-string-race-three-{suffix}.json"));
        let four = std::env::temp_dir().join(format!("fozzylang-string-race-four-{suffix}.json"));
        let quoted_one = one.to_string_lossy().replace('\"', "\\\"");
        let quoted_two = two.to_string_lossy().replace('\"', "\\\"");
        let quoted_three = three.to_string_lossy().replace('\"', "\\\"");
        let quoted_four = four.to_string_lossy().replace('\"', "\\\"");
        std::fs::create_dir_all(root.join("src")).expect("project src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname = \"string_race\"\nversion = \"0.1.0\"\n\n[[target.bin]]\nname = \"string_race\"\npath = \"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            format!(
                "use core.fs;\nuse core.thread;\n\nfn json_obj4(k1: str, v1: str, k2: str, v2: str, k3: str, v3: str, k4: str, v4: str) -> str {{\n    let obj = map.new()\n    discard map.set(obj, k1, v1)\n    discard map.set(obj, k2, v2)\n    discard map.set(obj, k3, v3)\n    discard map.set(obj, k4, v4)\n    return json.object(obj)\n}}\n\nfn worker_one() -> i32 {{\n    fs.write_file(\"{quoted_one}\", json_obj4(\"slot\", json.str(\"one\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn worker_two() -> i32 {{\n    fs.write_file(\"{quoted_two}\", json_obj4(\"slot\", json.str(\"two\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn worker_three() -> i32 {{\n    fs.write_file(\"{quoted_three}\", json_obj4(\"slot\", json.str(\"three\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn worker_four() -> i32 {{\n    fs.write_file(\"{quoted_four}\", json_obj4(\"slot\", json.str(\"four\"), \"status\", json.str(\"ok\"), \"kind\", json.str(\"spawn_ctx\"), \"ctx\", json.str(str.from_i32(thread.context_id()))))\n    return 0\n}}\n\nfn main() -> i32 {{\n    let one = spawn_ctx(worker_one, 1)\n    let two = spawn_ctx(worker_two, 2)\n    let three = spawn_ctx(worker_three, 3)\n    let four = spawn_ctx(worker_four, 4)\n    let r1 = join(one)\n    let r2 = join(two)\n    let r3 = join(three)\n    let r4 = join(four)\n    if r1 == 0 && r2 == 0 && r3 == 0 && r4 == 0 && fs.exists(\"{quoted_one}\") == 1 && fs.exists(\"{quoted_two}\") == 1 && fs.exists(\"{quoted_three}\") == 1 && fs.exists(\"{quoted_four}\") == 1 {{\n        return 0\n    }}\n    return 13\n}}\n"
            ),
        )
        .expect("source should be written");
        let _ = std::fs::remove_file(&one);
        let _ = std::fs::remove_file(&two);
        let _ = std::fs::remove_file(&three);
        let _ = std::fs::remove_file(&four);

        let output = run(
            Command::Run {
                path: root.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: Some("cranelift".to_string()),
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("concurrent spawn_ctx writers should preserve payload strings");
        assert!(output.contains("\"exitCode\":0"));
        for (path, slot, ctx_id) in [
            (&one, "one", "1"),
            (&two, "two", "2"),
            (&three, "three", "3"),
            (&four, "four", "4"),
        ] {
            let content = std::fs::read_to_string(path).expect("worker payload should be readable");
            assert_ne!(content.trim(), "", "worker payload should not be empty");
            assert!(content.contains(&format!("\"slot\":\"{slot}\"")));
            assert!(content.contains("\"status\":\"ok\""));
            assert!(content.contains(&format!("\"ctx\":\"{ctx_id}\"")));
        }

        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(one);
        let _ = std::fs::remove_file(two);
        let _ = std::fs::remove_file(three);
        let _ = std::fs::remove_file(four);
    }

    #[test]
    fn scenario_routing_keeps_det_for_host_backends() {
        let routing = scenario_run_routing(true, true);
        assert!(routing.deterministic_applied);
        assert_eq!(routing.mode, "host-backed-deterministic-scenario");
        assert!(routing.reason.contains("deterministic"));
    }

    #[test]
    fn anthropic_probe_steps_include_concrete_proc_events() {
        let steps = build_live_http_probe_steps("call anthropic provider", false);
        assert!(!steps.is_empty());
        let rendered = serde_json::to_string(&steps).expect("steps should serialize");
        assert!(rendered.contains("\"type\":\"proc_when\""));
        assert!(rendered.contains("\"type\":\"proc_spawn\""));
        assert!(rendered.contains("http.request.anthropic.start"));
    }

    #[test]
    fn host_backed_anthropic_probe_skips_proc_stubs() {
        let steps = build_live_http_probe_steps("anthropic", true);
        let rendered = serde_json::to_string(&steps).expect("steps should serialize");
        assert!(rendered.contains("\"type\":\"proc_spawn\""));
        assert!(!rendered.contains("\"type\":\"proc_when\""));
    }

    #[test]
    fn run_command_routes_det_through_language_async_model() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-run-det-route-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.fs;\nfn main() -> i32 {\n    let file = fs.open(\"/tmp/fozzylang-run-det-route.txt\")\n    defer fs.close(file)\n    discard fs.write(file, \"route=det\\n\")\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(5),
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("deterministic run should succeed");
        assert!(output.contains("\"deterministic-language-async-model\""));
        assert!(output.contains("\"asyncCheckpointCount\""));
        assert!(output.contains("\"routing\""));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_async_intrinsics_timeout_deadline_cancel_recv_compile_and_run() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-native-async-intrinsics-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.thread;\nfn main() -> i32 {\n    timeout(10)\n    let _d: i32 = deadline(1000)\n    let _c: i32 = cancel()\n    let _r: i32 = recv()\n    return 0\n}\n",
        )
        .expect("source should be written");
        let output = run(
            Command::Run {
                path: source.clone(),
                args: Vec::new(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: None,
                record: None,
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("native run should succeed");
        assert!(output.contains("\"exitCode\":0"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn non_scenario_test_record_writes_thread_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "test \"a\" {}\ntest \"b\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("random".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("test command should emit json");
        let artifacts = payload["artifacts"]
            .as_object()
            .expect("native test run should publish artifact paths");

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace = base.join(format!("{stem}.native.trace.json"));
        assert_eq!(
            artifacts.get("trace").and_then(|value| value.as_str()),
            Some(native_trace.to_string_lossy().as_ref())
        );
        let native_trace_text =
            std::fs::read_to_string(&native_trace).expect("native trace should be written");
        let native_trace_payload: serde_json::Value =
            serde_json::from_str(&native_trace_text).expect("native trace should be valid json");
        assert_eq!(
            native_trace_payload["schemaVersion"].as_str(),
            Some("fozzylang.test_trace.v1")
        );
        assert_eq!(native_trace_payload["discoveredTests"].as_u64(), Some(2));
        assert_eq!(native_trace_payload["executedTests"].as_u64(), Some(2));
        assert_eq!(native_trace_payload["scheduler"].as_str(), Some("random"));
        assert!(
            !trace.exists(),
            "legacy goal trace path should not be materialized"
        );
        assert_eq!(
            artifacts.get("timeline").and_then(|value| value.as_str()),
            Some(
                base.join(format!("{stem}.timeline.json"))
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert_eq!(
            artifacts.get("report").and_then(|value| value.as_str()),
            Some(
                base.join(format!("{stem}.report.json"))
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert_eq!(
            artifacts.get("manifest").and_then(|value| value.as_str()),
            Some(
                base.join(format!("{stem}.manifest.json"))
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert!(base.join(format!("{stem}.timeline.json")).exists());
        assert!(base.join(format!("{stem}.report.json")).exists());
        assert!(base.join(format!("{stem}.manifest.json")).exists());
        assert!(!base.join(format!("{stem}.explore.json")).exists());
        assert!(!base.join(format!("{stem}.shrink.json")).exists());
        assert!(!base.join(format!("{stem}.scenarios.json")).exists());

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.explore.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.shrink.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.scenarios.json")));
    }

    #[test]
    fn counts_async_hooks_from_semantic_ast() {
        let source = r#"
            async fn worker() -> i32 { return 0 }
            async fn io_next() -> i32 { return 1 }
            fn main() -> i32 {
                let x = await io_next()
                yield()
                checkpoint()
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("source should parse");
        assert_eq!(count_async_hooks_in_module(&module), 5);
    }

    #[test]
    fn native_test_record_writes_test_artifacts_from_real_test_bodies() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.fzy"));
        let trace = std::env::temp_dir().join(format!("fozzylang-test-record-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "use core.thread;\nfn worker() -> i32 {\n    checkpoint()\n    return 7\n}\ntest \"flow\" {\n    let handle = spawn(worker)\n    let result = join(handle)\n    timeout(10)\n    cancel()\n    assert.eq_i32(result, 7)\n}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(5),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        let output_json: serde_json::Value =
            serde_json::from_str(&output).expect("output should be valid json");
        assert_eq!(output_json["passedTests"].as_u64(), Some(1));
        assert!(
            output_json["asyncCheckpointCount"]
                .as_u64()
                .expect("checkpoint count should be numeric")
                >= 2
        );

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let native_trace_path = base.join(format!("{stem}.native.trace.json"));
        let native_trace_text =
            std::fs::read_to_string(&native_trace_path).expect("native trace should be readable");
        let native_trace: serde_json::Value =
            serde_json::from_str(&native_trace_text).expect("native trace should parse");
        assert_eq!(
            native_trace["schemaVersion"].as_str(),
            Some("fozzylang.test_trace.v1")
        );
        assert_eq!(
            native_trace["asyncSchedule"].as_array().map(Vec::len),
            Some(1)
        );
        let tests = native_trace["tests"]
            .as_array()
            .expect("tests array should be present");
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0]["status"].as_str(), Some("passed"));
        let event_details = tests[0]["events"]
            .as_array()
            .expect("events should be present")
            .iter()
            .filter_map(|event| event["detail"].as_str())
            .collect::<Vec<_>>();
        assert!(event_details.contains(&"checkpoint"));
        assert!(event_details.contains(&"timeout(10)"));
        assert!(event_details.contains(&"cancel"));
        assert!(event_details
            .iter()
            .any(|detail| detail.contains("worker -> handle:")));
        assert!(event_details
            .iter()
            .any(|detail| detail.contains("handle:1")));

        let report = std::fs::read_to_string(base.join(format!("{stem}.report.json")))
            .expect("report should be readable");
        assert!(report.contains("\"schemaVersion\": \"fozzylang.test_report.v1\""));
        assert!(report.contains("\"runtimeEventCount\""));
        let timeline = std::fs::read_to_string(base.join(format!("{stem}.timeline.json")))
            .expect("timeline should be readable");
        assert!(timeline.contains("\"schemaVersion\": \"fozzylang.test_timeline.v1\""));
        assert!(timeline.contains("\"test\": \"flow\""));
        let manifest = std::fs::read_to_string(base.join(format!("{stem}.manifest.json")))
            .expect("manifest should be readable");
        assert!(manifest.contains("\"schemaVersion\": \"fozzylang.test_manifest.v1\""));
        assert!(manifest.contains("\"source\""));
        assert!(manifest.contains("\"scheduler\": \"fifo\""));
        assert!(manifest.contains("\"strictVerify\": false"));
        assert!(manifest.contains("\"safeProfile\": false"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(native_trace_path);
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
    }

    #[test]
    fn native_test_record_report_includes_real_thread_findings() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-finding-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-test-finding-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "unsafe fn lang_unsafe_id(v: i32) -> i32 {\n    return v\n}\ntest \"ok\" {\n    assert.eq_i32(1, 1)\n}\nfn main() -> i32 {\n    discard lang_unsafe_id\n    return 0\n}\n",
        )
        .expect("source should be written");

        run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(9),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("trace should have a stem")
            .to_string();
        let base = trace
            .parent()
            .expect("trace should have parent")
            .to_path_buf();
        let report = std::fs::read_to_string(base.join(format!("{stem}.report.json")))
            .expect("report should be readable");
        assert!(report.contains("\"threadFindings\""));
        assert!(report.contains("\"kind\": \"unsafe_site_accounting\""));
        assert!(report.contains("\"contractHash\""));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(trace);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
    }

    #[test]
    fn headers_command_rejects_ffi_when_panic_contract_missing() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-ffi-panic-{suffix}.fzy"));
        std::fs::write(
            &source,
            "pubext c fn add(left: i32, right: i32) -> i32;\nfn main() -> i32 {\n    panic(err)\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::Headers {
                path: source.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers command should fail");
        assert!(error.to_string().contains("ffi panic contract missing"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn non_scenario_test_filter_selects_named_tests() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-filter-{suffix}.fzy"));
        std::fs::write(
            &source,
            "test \"alpha\" {}\ntest \"beta\" {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(1),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: false,
                filter: Some("alpha".to_string()),
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"selectedTests\":1"));
        assert!(output.contains("\"selectedTestNames\":[\"alpha\"]"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn native_test_executes_body_and_reports_assertion_failure() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-failure-{suffix}.fzy"));
        std::fs::write(
            &source,
            "test \"boom\" {\n    assert.eq_i32(2, 5)\n}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(1),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: false,
                filter: None,
            },
            Format::Json,
        )
        .expect_err("test command should fail when assertion fails");
        let rendered = error.to_string();
        assert!(rendered.contains("exit code 1"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn nondet_tests_execute_on_non_deterministic_runs() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-test-nondet-{suffix}.fzy"));
        std::fs::write(
            &source,
            "test \"chaos\" nondet {\n    assert.eq_i32(1, 1)\n}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: false,
                strict_verify: false,
                safe_profile: false,
                seed: Some(1),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: None,
                rich_artifacts: false,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        assert!(output.contains("\"selectedTests\":1"));
        assert!(output.contains("\"nondeterministicTestNames\":[\"chaos\"]"));
        assert!(output.contains("\"passedTests\":1"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn replay_command_routes_native_trace_through_goal_bridge() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-replay-{suffix}.trace.json"));
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "fifo",
                "seed": 7,
                "executionOrder": [0, 1],
                "asyncSchedule": [1],
                "rpcFrames": [
                    {"event":"rpc_send","method":"Ping","taskId":0},
                    {"event":"rpc_recv","method":"Ping","taskId":1}
                ],
                "events": [{"event":"completed","taskId":0}],
            })
            .to_string(),
        )
        .expect("trace should be written");

        let error = run(
            Command::Replay {
                trace: trace.clone(),
            },
            Format::Text,
        )
        .expect_err("replay should require a goal-trace bridge for native traces");
        assert!(error.to_string().contains(".manifest.json"));

        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn explore_command_uses_native_engine_for_native_manifest() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("fozzylang-native-explore-{suffix}"));
        std::fs::create_dir_all(&base).expect("base should be created");
        let trace = base.join("demo.trace.json");
        let manifest = base.join("demo.trace.manifest.json");
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "random",
                "seed": 9,
                "executionOrder": [0, 2, 1],
                "asyncSchedule": [2, 0],
                "rpcFrames": [],
                "events": [],
            })
            .to_string(),
        )
        .expect("trace should be written");
        std::fs::write(
            &manifest,
            serde_json::json!({
                "schemaVersion": "fozzylang.artifacts.v0",
                "trace": trace.display().to_string(),
            })
            .to_string(),
        )
        .expect("manifest should be written");

        let output = run(
            Command::Explore {
                target: manifest.clone(),
            },
            Format::Json,
        )
        .expect("explore should succeed");
        assert!(output.contains("\"schemaVersion\":\"fozzylang.native_explore.v0\""));
        assert!(output.contains("\"engine\":\"fozzylang-native\""));
        assert!(output.contains("\"schedules\""));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn explore_command_accepts_steps_scenarios() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let scenario =
            std::env::temp_dir().join(format!("fozzylang-steps-explore-{suffix}.fozzy.json"));
        std::fs::write(
            &scenario,
            serde_json::json!({
                "version": 1,
                "name": "steps-explore",
                "steps": [
                    {"type": "trace_event", "name": "boot"},
                    {"type": "assert_eq_int", "a": 1, "b": 1}
                ]
            })
            .to_string(),
        )
        .expect("scenario should be written");

        let output = run(
            Command::Explore {
                target: scenario.clone(),
            },
            Format::Json,
        )
        .expect("explore should succeed for steps scenarios");
        assert!(output.contains("\"mode\":\"explore\""));
        assert!(output.contains("\"status\":\"pass\""));

        let _ = std::fs::remove_file(scenario);
    }

    #[test]
    fn ci_command_routes_native_trace_through_goal_bridge() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-ci-fail-{suffix}.trace.json"));
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "fifo",
                "seed": 3,
                "executionOrder": [0],
                "asyncSchedule": [],
                "rpcFrames": [
                    {"event":"rpc_recv","method":"Ping","taskId":0}
                ],
                "events": [],
            })
            .to_string(),
        )
        .expect("trace should be written");

        let error = run(
            Command::Ci {
                trace: trace.clone(),
                strict: false,
            },
            Format::Text,
        )
        .expect_err("ci should require a goal-trace bridge for native traces");
        assert!(error.to_string().contains(".manifest.json"));

        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn shrink_command_routes_native_trace_through_goal_bridge() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-shrink-{suffix}.trace.json"));
        std::fs::write(
            &trace,
            serde_json::json!({
                "schemaVersion": "fozzylang.thread_trace.v0",
                "capability": "thread",
                "scheduler": "fifo",
                "seed": 11,
                "executionOrder": [0, 1],
                "asyncSchedule": [1],
                "rpcFrames": [
                    {"event":"rpc_send","method":"Ping","taskId":0},
                    {"event":"rpc_deadline","method":"Ping","taskId":1}
                ],
                "events": [],
            })
            .to_string(),
        )
        .expect("trace should be written");

        let error = run(
            Command::Shrink {
                trace: trace.clone(),
            },
            Format::Text,
        )
        .expect_err("shrink should require a goal-trace bridge for native traces");
        assert!(error.to_string().contains(".manifest.json"));

        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn async_workload_uses_structured_task_model() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-async-workload-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.thread;\nasync fn worker() -> i32 {\n    checkpoint()\n    return 0\n}\ntest \"flow\" {\n    let handle = spawn(worker)\n    let result = join(handle)\n    assert.eq_i32(result, 0)\n}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(3),
                record: None,
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: false,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        let output_json: serde_json::Value =
            serde_json::from_str(&output).expect("output should be valid json");
        assert_eq!(output_json["executedTasks"].as_u64(), Some(1));
        assert!(
            output_json["asyncCheckpointCount"]
                .as_u64()
                .expect("checkpoint count should be numeric")
                >= 1
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn resolve_replay_target_prefers_manifest_goal_trace() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("fozzylang-replay-resolve-{suffix}"));
        std::fs::create_dir_all(&base).expect("base dir should be created");
        let goal_trace = base.join("goal.fozzy");
        let manifest = base.join("trace.manifest.json");
        std::fs::write(&goal_trace, "{\"version\":3}").expect("goal trace should be written");
        std::fs::write(
            &manifest,
            serde_json::json!({
                "schemaVersion": "fozzylang.artifacts.v0",
                "goalTrace": goal_trace.display().to_string()
            })
            .to_string(),
        )
        .expect("manifest should be written");

        let resolved = resolve_replay_target(&manifest).expect("target should resolve");
        assert_eq!(resolved, goal_trace);

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn trace_verify_accepts_native_test_manifest() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-native-test-verify-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-test-verify-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "test \"ok\" {\n    assert.eq_i32(1, 1)\n}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(5),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        let manifest = trace
            .parent()
            .expect("trace should have parent")
            .join(format!(
                "{}.manifest.json",
                trace
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .expect("stem")
            ));
        let output = run(
            Command::TraceVerify {
                trace: manifest.clone(),
                strict: true,
            },
            Format::Json,
        )
        .expect("trace verify should accept native test manifest");
        assert!(output.contains("\"schemaVersion\":\"fozzylang.native_test_trace_verify.v1\""));
        assert!(output.contains("\"ok\":true"));

        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("stem");
        let base = trace.parent().expect("parent");
        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
    }

    #[test]
    fn replay_and_ci_accept_native_test_manifest() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source =
            std::env::temp_dir().join(format!("fozzylang-native-test-replay-{suffix}.fzy"));
        let trace =
            std::env::temp_dir().join(format!("fozzylang-native-test-replay-{suffix}.trace.json"));
        std::fs::write(
            &source,
            "use core.thread;\nfn worker() -> i32 {\n    checkpoint()\n    return 3\n}\ntest \"ok\" {\n    let handle = spawn(worker)\n    let result = join(handle)\n    assert.eq_i32(result, 3)\n}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        run(
            Command::Test {
                path: source.clone(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(9),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                scheduler: Some("fifo".to_string()),
                rich_artifacts: true,
                filter: None,
            },
            Format::Json,
        )
        .expect("test command should succeed");
        let stem = trace
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("stem");
        let base = trace.parent().expect("parent");
        let manifest = base.join(format!("{stem}.manifest.json"));

        let replay = run(
            Command::Replay {
                trace: manifest.clone(),
            },
            Format::Json,
        )
        .expect("replay should accept native test manifest");
        assert!(replay.contains("\"schemaVersion\":\"fozzylang.native_test_replay.v1\""));
        assert!(replay.contains("\"ok\":true"));

        let ci = run(
            Command::Ci {
                trace: manifest.clone(),
                strict: true,
            },
            Format::Json,
        )
        .expect("ci should accept native test manifest");
        assert!(ci.contains("\"schemaVersion\":\"fozzylang.native_test_ci.v1\""));
        assert!(ci.contains("\"ok\":true"));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(base.join(format!("{stem}.native.trace.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.timeline.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.report.json")));
        let _ = std::fs::remove_file(base.join(format!("{stem}.manifest.json")));
    }

    #[test]
    fn trace_native_command_converts_fozzy_trace_to_native_schema() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("fozzylang-trace-native-{suffix}"));
        std::fs::create_dir_all(&base).expect("base dir should be created");
        let goal_trace = base.join("goal.fozzy");
        std::fs::write(
            &goal_trace,
            serde_json::json!({
                "format": FOZZY_TRACE_FORMAT,
                "version": FOZZY_TRACE_VERSION,
                "decisions": [
                    {"kind":"scheduler_pick","task_id":1,"label":"rpc_send"},
                    {"kind":"rpc_send","task_id":1,"method":"Ping"}
                ],
                "events": [{"name":"ping","time_ms":0,"fields":{}}],
                "summary": {"identity":{"seed":99}}
            })
            .to_string(),
        )
        .expect("goal trace should be written");

        let output = run(
            Command::TraceNative {
                trace: goal_trace.clone(),
                output: None,
            },
            Format::Json,
        )
        .expect("trace-native should succeed");
        assert!(output.contains("\"seed\":99"));
        assert!(output.contains("\"rpcFrames\":1"));

        let native_trace = base.join("goal.trace.json");
        let native_manifest = base.join("goal.trace.manifest.json");
        let trace_text =
            std::fs::read_to_string(&native_trace).expect("native trace should be written");
        assert!(trace_text.contains("\"schemaVersion\": \"fozzylang.thread_trace.v0\""));
        assert!(trace_text.contains("\"compatibility\""));
        assert!(trace_text.contains("\"checkpointCount\": 0"));
        assert!(trace_text.contains("\"event\": \"rpc_send\""));
        let manifest_text =
            std::fs::read_to_string(&native_manifest).expect("native manifest should be written");
        assert!(manifest_text.contains("\"compatibility\""));
        assert!(manifest_text.contains("\"goalTrace\""));
        assert!(manifest_text.contains("goal.fozzy"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn trace_verify_reports_compatibility_and_replay_contract_checks() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let scenario =
            std::env::temp_dir().join(format!("fozzylang-trace-verify-compat-{suffix}.fozzy.json"));
        let trace = std::env::temp_dir().join(format!(
            "fozzylang-trace-verify-compat-{suffix}.trace.fozzy"
        ));
        std::fs::write(
            &scenario,
            serde_json::json!({
                "version": 1,
                "name": "trace-verify-compat",
                "steps": [
                    {"type": "trace_event", "name": "boot"},
                    {"type": "memory_checkpoint", "name": "after_boot"},
                    {"type": "assert_eq_int", "a": 1, "b": 1}
                ]
            })
            .to_string(),
        )
        .expect("scenario should be written");

        let run_output = run(
            Command::Run {
                path: scenario.clone(),
                args: Vec::new(),
                deterministic: true,
                strict_verify: false,
                safe_profile: false,
                seed: Some(7),
                record: Some(trace.clone()),
                host_backends: false,
                backend: None,
                max_seconds: None,
                exit_on_healthcheck: None,
                smoke_http: None,
            },
            Format::Json,
        )
        .expect("run should record trace");
        assert!(run_output.contains("\"status\":\"pass\""));

        let verify_output = run(
            Command::TraceVerify {
                trace: trace.clone(),
                strict: true,
            },
            Format::Json,
        )
        .expect("trace verify should succeed");
        assert!(verify_output.contains("\"compatibility\""));
        assert!(verify_output.contains("\"traceSchemaVersion\":\"fozzy-trace.v4\""));
        assert!(verify_output.contains("\"name\":\"compatibility_set\""));
        assert!(verify_output.contains("\"name\":\"checkpoint_count_match\""));

        let _ = std::fs::remove_file(scenario);
        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn debug_check_command_reports_readiness() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-debug-check-{suffix}.fzy"));
        std::fs::write(
            &source,
            "use core.thread;\nasync fn worker() -> i32 {}\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
        let output = run(
            Command::DebugCheck {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("debug-check should succeed");
        assert!(output.contains("\"debugSymbols\""));
        assert!(output.contains("\"asyncBacktraceReady\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn plan_claim_accuracy_gate_detects_missing_evidence() {
        let plan = "- [✅] Added `lsp_rename`\n- [✅] Updated docs\n";
        let corpus = vec![(
            "crates/driver/src/lsp.rs".to_string(),
            "fn lsp_rename() {}".to_string(),
        )];
        let gate = analyze_plan_claim_accuracy(plan, &corpus);
        assert_eq!(gate.completed, 2);
        assert_eq!(gate.checked, 1);
        assert_eq!(gate.missing_evidence.len(), 1);
        assert!(gate.missing_evidence[0].contains("`lsp_rename`"));
    }

    #[test]
    fn lsp_commands_smoke_for_workspace_file() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-smoke-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn helper() -> i32 {\n    return 0\n}\nfn main() -> i32 {\n    return helper()\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("\"ok\":true"));
        let definition = run(
            Command::LspDefinition {
                path: source.clone(),
                symbol: "helper".to_string(),
            },
            Format::Json,
        )
        .expect("lsp definition should succeed");
        assert!(definition.contains("\"kind\":\"function\""));
        let hover = run(
            Command::LspHover {
                path: source.clone(),
                symbol: "main".to_string(),
            },
            Format::Json,
        )
        .expect("lsp hover should succeed");
        assert!(hover.contains("\"signature\""));
        let rename = run(
            Command::LspRename {
                path: source.clone(),
                from: "helper".to_string(),
                to: "helper2".to_string(),
            },
            Format::Json,
        )
        .expect("lsp rename should succeed");
        assert!(rename.contains("\"replacements\""));
        let smoke = run(
            Command::LspSmoke {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("lsp smoke should succeed");
        assert!(smoke.contains("\"features\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_diagnostics_json_includes_snippet_and_labels() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-diagnostics-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let payload: str = \"unterminated\n    return 0\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("\"snippet\""));
        assert!(diagnostics.contains("\"labels\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_diagnostics_text_includes_full_diagnostic_body() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-diag-text-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    missing_call()\n    return 0\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("mode: lsp-diagnostics"));
        assert!(diagnostics.contains("error["));
        assert!(diagnostics.contains("help:"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_diagnostics_text_uses_human_grouped_type_notes() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-grouped-notes-{suffix}.fzy"));
        std::fs::write(
            &source,
            "fn main() -> i32 {\n    let value: i32 = \"oops\"\n    missing_symbol(1)\n    return value\n}\n",
        )
        .expect("source should be written");
        let diagnostics = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("lsp diagnostics should succeed");
        assert!(diagnostics.contains("additional grouped root cause: unresolved call target"));
        assert!(!diagnostics.contains("type_error_count="));
        assert!(diagnostics.contains("explain: fz explain verifier.grouped_type_error"));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn lsp_commands_reject_non_fzy_files() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lsp-foreign-{suffix}.rs"));
        std::fs::write(&source, "fn main() {}\n").expect("source should be written");

        let error = run(
            Command::LspDiagnostics {
                path: source.clone(),
            },
            Format::Json,
        )
        .expect_err("non-fzy diagnostics input should be rejected");
        assert!(
            error
                .to_string()
                .contains("expected a `.fzy` source file or a project directory"),
            "unexpected error: {error}"
        );

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn diagnostics_regression_unresolved_call_and_field_variant_resolution() {
        let unresolved = run_check_text(
            "fn main() -> i32 {\n    return missing_symbol()\n}\n",
            "unresolved-call",
        );
        assert!(unresolved.contains("unresolved call target"));

        let field = run_check_text(
            "struct User { id: i32 }\nfn main() -> i32 {\n    let user = User { id: 1 }\n    return user.missing\n}\n",
            "field-resolution",
        );
        assert!(field.contains("has no field `missing`"));

        let variant = run_check_text(
            "enum Status { Ok }\nfn main() -> i32 {\n    discard Status::Err\n    return 0\n}\n",
            "variant-resolution",
        );
        assert!(variant.contains("has no variant `Err`"));

        let unqualified_pattern = run_check_text(
            "enum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let m = Maybe::Some(1)\n    match m {\n        Some(v) => v,\n        _ => 0,\n    }\n}\n",
            "variant-pattern-qualification",
        );
        assert!(unqualified_pattern.contains("unqualified enum variant pattern"));
    }

    #[test]
    fn diagnostics_regression_match_capability_and_ffi_boundary() {
        let match_unreachable = run_check_text(
            "fn main() -> i32 {\n    match 1 {\n        _ => 0,\n        1 => 1,\n    }\n}\n",
            "match-unreachable",
        );
        assert!(match_unreachable.contains("unreachable"));

        let capability = run_check_text(
            "fn main() -> i32 {\n    let listener = http.bind(\"127.0.0.1:8787\")\n    return listener\n}\n",
            "capability-violation",
        );
        assert!(capability.contains("missing required capability"));

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-diag-ffi-boundary-{unique}.fzy"));
        std::fs::write(&path, "pubext c fn exported() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");
        let ffi = run(
            Command::Headers {
                path: path.clone(),
                output: None,
            },
            Format::Text,
        )
        .expect_err("headers should fail without ffi_panic attribute")
        .to_string();
        assert!(ffi.contains("ffi panic contract missing"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn dx_check_accepts_convention_project() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-dx-ok-{suffix}"));
        std::fs::create_dir_all(root.join("src/api")).expect("api dir should be created");
        std::fs::create_dir_all(root.join("src/model")).expect("model dir should be created");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::create_dir_all(root.join("src/runtime")).expect("runtime dir should be created");
        std::fs::create_dir_all(root.join("src/cli")).expect("cli dir should be created");
        std::fs::create_dir_all(root.join("src/tests")).expect("tests dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"dx_ok\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"dx_ok\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod api;\nmod model;\nmod services;\nmod runtime;\nmod cli;\nmod tests;\n\nfn main() -> i32 {\n    model.preflight()\n    cli.boot()\n    services.boot_all()\n    runtime.start()\n    api.touch()\n    return 0\n}\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/api/mod.fzy"),
            "fn touch() -> i32 {\n    return 0\n}\n",
        )
        .expect("api mod should be written");
        std::fs::write(
            root.join("src/model/mod.fzy"),
            "fn preflight() -> i32 {\n    return 0\n}\n",
        )
        .expect("model mod should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "fn boot_all() -> i32 {\n    return 0\n}\n",
        )
        .expect("services mod should be written");
        std::fs::write(
            root.join("src/runtime/mod.fzy"),
            "fn start() -> i32 {\n    return 0\n}\n",
        )
        .expect("runtime mod should be written");
        std::fs::write(
            root.join("src/cli/mod.fzy"),
            "fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("cli mod should be written");
        std::fs::write(root.join("src/tests/mod.fzy"), "mod smoke;\n")
            .expect("tests mod should be written");
        std::fs::write(root.join("src/tests/smoke.fzy"), "test \"det\" {}\n")
            .expect("smoke test should be written");

        let output = run(
            Command::DxCheck {
                path: root.clone(),
                strict: true,
            },
            Format::Json,
        )
        .expect("dx-check should pass");
        assert!(output.contains("\"ok\":true"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dx_check_rejects_tests_declared_in_main() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-dx-bad-{suffix}"));
        std::fs::create_dir_all(root.join("src/api")).expect("api dir should be created");
        std::fs::create_dir_all(root.join("src/model")).expect("model dir should be created");
        std::fs::create_dir_all(root.join("src/services")).expect("services dir should be created");
        std::fs::create_dir_all(root.join("src/runtime")).expect("runtime dir should be created");
        std::fs::create_dir_all(root.join("src/cli")).expect("cli dir should be created");
        std::fs::create_dir_all(root.join("src/tests")).expect("tests dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"dx_bad\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"dx_bad\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod api;\nmod model;\nmod services;\nmod runtime;\nmod cli;\nmod tests;\ntest \"bad\" {}\nfn main() -> i32 { return 0 }\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/api/mod.fzy"),
            "fn touch() -> i32 {\n    return 0\n}\n",
        )
        .expect("api mod should be written");
        std::fs::write(
            root.join("src/model/mod.fzy"),
            "fn preflight() -> i32 {\n    return 0\n}\n",
        )
        .expect("model mod should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "fn boot_all() -> i32 {\n    return 0\n}\n",
        )
        .expect("services mod should be written");
        std::fs::write(
            root.join("src/runtime/mod.fzy"),
            "fn start() -> i32 {\n    return 0\n}\n",
        )
        .expect("runtime mod should be written");
        std::fs::write(
            root.join("src/cli/mod.fzy"),
            "fn boot() -> i32 {\n    return 0\n}\n",
        )
        .expect("cli mod should be written");
        std::fs::write(root.join("src/tests/mod.fzy"), "mod smoke;\n")
            .expect("tests mod should be written");
        std::fs::write(root.join("src/tests/smoke.fzy"), "test \"det\" {}\n")
            .expect("smoke test should be written");

        let error = run(
            Command::DxCheck {
                path: root.clone(),
                strict: true,
            },
            Format::Text,
        )
        .expect_err("dx-check should fail");
        assert!(!error.to_string().trim().is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn proof_ref_valid_accepts_existing_trace_artifact() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-proof-ref-{suffix}.fozzy"));
        std::fs::write(&path, "{}").expect("trace file should be written");
        let proof_ref = format!("trace://{}#site=usite_demo", path.display());
        assert!(proof_ref_valid(&proof_ref));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proof_ref_valid_rejects_missing_trace_artifact() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fozzylang-proof-ref-missing-{suffix}.fozzy"));
        let proof_ref = format!("trace://{}#site=usite_demo", path.display());
        assert!(!proof_ref_valid(&proof_ref));
    }

    #[test]
    fn check_rejects_pointer_like_safe_extern_c_import() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-safe-extern-c-{suffix}.fzy"));
        std::fs::write(
            &source,
            "ext c fn c_read(buf_owned: *u8) -> i32;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let output = run(
            Command::Check {
                path: source.clone(),
            },
            Format::Text,
        )
        .expect("check command should return diagnostics");
        assert!(output.contains("must be declared `ext unsafe c fn`"));

        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn verify_accepts_documented_safe_wrapper_over_unsafe_import() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-wrapper-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"ffi_wrapper\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_wrapper\"\npath=\"src/main.fzy\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "ext unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;\n\nfn abi_touch(s: str) -> i32 {\n    unsafe {\n        return host_touch(s, str.len(s))\n    }\n}\n\nfn safe_touch(s: str) -> i32 {\n    return abi_touch(s)\n}\n\nfn main() -> i32 {\n    return safe_touch(\"ok\")\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should return diagnostics");
        assert!(output.contains("\"errors\":0"));
        assert!(!output.contains("call edge `abi_touch -> host_touch` reaches unsafe code"));
        assert!(!output.contains("call edge `safe_touch -> abi_touch` reaches unsafe code"));
        assert!(output.contains("structural unsafe contract metadata is present"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_accepts_unsafe_import_wrapper_bound_through_let() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-wrapper-let-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"ffi_wrapper_let\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_wrapper_let\"\npath=\"src/main.fzy\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "ext unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;\n\nfn abi_touch(s: str) -> i32 {\n    let code = unsafe {\n        host_touch(s, str.len(s))\n    }\n    return code\n}\n\nfn safe_touch(s: str) -> i32 {\n    return abi_touch(s)\n}\n\nfn main() -> i32 {\n    return safe_touch(\"ok\")\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should return diagnostics");
        assert!(output.contains("\"errors\":0"));
        assert!(!output.contains("return type mismatch: expected `i32`, got `void`"));
        assert!(output.contains("structural unsafe contract metadata is present"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_accepts_zero_arg_file_backed_unsafe_import_wrapper() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-ffi-zero-arg-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"ffi_zero_arg\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"ffi_zero_arg\"\npath=\"src/main.fzy\"\n\n[unsafe]\ncontracts=\"compiler\"\nenforce_verify=true\nenforce_release=true\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "use core.fs;\n\next unsafe c fn host_dispatch() -> i32;\n\nfn abi_dispatch(raw: str) -> i32 {\n    discard fs.write_file(\"/tmp/in.json\", raw)\n    return safe_dispatch()\n}\n\nfn safe_dispatch() -> i32 {\n    return raw_dispatch()\n}\n\nfn raw_dispatch() -> i32 {\n    unsafe {\n        return host_dispatch()\n    }\n}\n\nfn main() -> i32 {\n    return abi_dispatch(\"{}\")\n}\n",
        )
        .expect("source should be written");

        let output = run(Command::Verify { path: root.clone() }, Format::Json)
            .expect("verify should return diagnostics");
        assert!(
            output.contains("\"errors\":0"),
            "unexpected output: {output}"
        );
        assert!(!output.contains("call edge `safe_dispatch -> raw_dispatch` reaches unsafe code"));
        assert!(!output.contains("call edge `raw_dispatch -> host_dispatch` reaches unsafe code"));
        assert!(output.contains("structural unsafe contract metadata is present"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explain_catalog_returns_entries() {
        let output = run(
            Command::Explain {
                diag_code: "catalog".to_string(),
            },
            Format::Json,
        )
        .expect("catalog explain should succeed");
        assert!(output.contains("\"schemaVersion\":\"fozzylang.diagnostic_catalog.v1\""));
        assert!(output.contains("\"code_prefix\":\"E-HIR-\""));
    }

    #[test]
    fn explain_json_schema_for_grouped_type_error_is_snapshot_stable() {
        let output = run(
            Command::Explain {
                diag_code: "verifier.grouped_type_error".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("explain json should parse");
        assert_eq!(payload["schemaVersion"], DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION);
        assert_eq!(payload["catalogKey"], "verifier.grouped_type_error");
        assert_eq!(payload["family"], "verifier");
        assert_eq!(payload["nextCommand"], "fz verify <path> --json");
        assert_eq!(
            payload["explainCommand"],
            "fz explain verifier.grouped_type_error"
        );
        assert_eq!(
            payload["catalog"]["production_risk"],
            "High: grouped type errors indicate the program is not semantically stable enough for trusted lowering."
        );
    }

    #[test]
    fn explain_json_schema_for_native_backend_capability_is_snapshot_stable() {
        let output = run(
            Command::Explain {
                diag_code: "native.cranelift_async_unsafe_unsupported".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("explain json should parse");
        assert_eq!(payload["schemaVersion"], DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION);
        assert_eq!(
            payload["catalogKey"],
            "native.cranelift_async_unsafe_unsupported"
        );
        assert_eq!(payload["family"], "native-lowering");
        assert_eq!(
            payload["likelyFix"],
            "Switch to LLVM or refactor unsafe operations outside the async function boundary."
        );
        assert_eq!(
            payload["nextCommand"],
            "fz build <path> --backend llvm --json"
        );
    }

    #[test]
    fn explain_json_schema_for_ffi_contract_diagnostic_is_snapshot_stable() {
        let output = run(
            Command::Explain {
                diag_code: "verifier.extern_c_pointer_requires_contract".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("explain json should parse");
        assert_eq!(payload["schemaVersion"], DIAGNOSTIC_EXPLAIN_SCHEMA_VERSION);
        assert_eq!(
            payload["catalogKey"],
            "verifier.extern_c_pointer_requires_contract"
        );
        assert_eq!(payload["family"], "verifier");
        assert_eq!(
            payload["explainCommand"],
            "fz explain verifier.extern_c_pointer_requires_contract"
        );
        assert!(payload["rootCause"]
            .as_str()
            .is_some_and(|value| value.contains("ownership contract")));
    }

    #[test]
    fn explain_text_includes_production_action_fields() {
        let output = run(
            Command::Explain {
                diag_code: "E-VER-DEADBEEF".to_string(),
            },
            Format::Text,
        )
        .expect("explain should succeed");
        assert!(output.contains("common_triggers"));
        assert!(output.contains("production_action"));
        assert!(output.contains("production_risk"));
        assert!(output.contains("explain_command"));
    }

    #[test]
    fn explain_accepts_exact_catalog_key() {
        let output = run(
            Command::Explain {
                diag_code: "verifier.grouped_type_error".to_string(),
            },
            Format::Json,
        )
        .expect("explain should succeed");
        assert!(output.contains("\"catalogKey\":\"verifier.grouped_type_error\""));
        assert!(output.contains("collapsed multiple related type-check failures"));
    }

    #[test]
    fn explain_accepts_rendered_catalog_keys() {
        for key in [
            "verifier.missing_explicit_capabilities",
            "parser.syntax_error",
            "verifier.function_missing_required_capability",
            "native.cranelift_async_unsafe_unsupported",
        ] {
            let output = run(
                Command::Explain {
                    diag_code: key.to_string(),
                },
                Format::Json,
            )
            .expect("explain should succeed");
            assert!(output.contains(&format!("\"catalogKey\":\"{key}\"")));
            assert!(!output.contains("\"family\":\"unknown\""));
        }
    }

    #[test]
    fn lint_command_supports_tiers() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let source = std::env::temp_dir().join(format!("fozzylang-lint-tier-{suffix}.fzy"));
        std::fs::write(&source, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("source should be written");
        let output = run(
            Command::Lint {
                path: source.clone(),
                tier: "production".to_string(),
            },
            Format::Json,
        )
        .expect("lint should succeed");
        assert!(output.contains("\"mode\":\"lint\""));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn perf_command_reports_real_workload_summary() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let artifact = std::env::temp_dir().join(format!("fozzylang-perf-{suffix}.json"));
        std::fs::write(
            &artifact,
            serde_json::json!({
                "benches": [
                    {"bench": "cli_startup", "ratio_fzy_over_rust": 1.25},
                    {"bench": "http_throughput", "ratio_fzy_over_rust": 0.95},
                    {"bench": "compiler_parse_lower_build", "ratio_fzy_over_rust": 1.75}
                ]
            })
            .to_string(),
        )
        .expect("benchmark artifact should be written");

        let output = run(
            Command::Perf {
                artifact: Some(artifact.clone()),
            },
            Format::Json,
        )
        .expect("perf command should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("perf output should be valid json");
        assert_eq!(payload["mode"], "perf");
        assert_eq!(payload["benchCount"], 3);
        assert_eq!(payload["worstKernel"], "compiler_parse_lower_build");
        assert_eq!(payload["worstRatioFzyOverRust"], 1.75);
        let avg = payload["averageRatioFzyOverRust"]
            .as_f64()
            .expect("average ratio should be numeric");
        assert!((avg - 1.3166666666666667).abs() < 1e-12, "{avg}");

        let _ = std::fs::remove_file(artifact);
    }

    #[test]
    fn stability_dashboard_reports_compatibility_and_perf_sources() {
        let output = run(Command::StabilityDashboard, Format::Json)
            .expect("stability dashboard should succeed");
        let payload: serde_json::Value =
            serde_json::from_str(&output).expect("stability dashboard should emit json");
        assert_eq!(payload["mode"], "stability-dashboard");
        assert_eq!(
            payload["dashboard"]["schemaVersion"],
            "fozzylang.stability_dashboard.v1"
        );
        assert_eq!(
            payload["dashboard"]["compatibility"]["traceSchemaVersion"],
            "fozzy-trace.v4"
        );
        assert_eq!(
            payload["dashboard"]["performance"]["artifact"],
            "artifacts/bench_core_rust_vs_fzy.json"
        );
        assert!(payload["dashboard"]["performance"]["workloads"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["name"] == "cli_startup")));
    }

    #[test]
    fn init_command_scaffolds_buildable_project_with_runtime_artifacts() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-init-e2e-{suffix}"));
        let output = run(
            Command::Init {
                path: root.clone(),
                package_name: Some("demo_init".to_string()),
                template: Some("rust".to_string()),
                with: vec!["run".to_string(), "memory".to_string(), "host".to_string()],
                force: false,
            },
            Format::Json,
        )
        .expect("init should succeed");
        assert!(output.contains("\"initialized project\""));
        assert!(root.join("fozzy.toml").exists());
        assert!(root.join("src/main.fzy").exists());
        assert!(root.join("tests/run.pass.fozzy.json").exists());
        assert!(root.join("tests/memory.pass.fozzy.json").exists());
        assert!(root.join("tests/host.pass.fozzy.json").exists());
        assert!(root.join("tests/INIT_GUIDE.md").exists());
        assert!(root.join(".fozzy/runs").exists());
        assert!(root.join(".fozzy/corpora").exists());

        let artifact = compile_file_with_backend_with_root_guidance(&root, BuildProfile::Dev, None)
            .expect("scaffolded project should compile");
        assert_eq!(artifact.status, "ok");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn init_command_supports_current_directory_bootstrap() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-init-cwd-{suffix}"));
        std::fs::create_dir_all(&root).expect("root should be created");
        let prev = std::env::current_dir().expect("cwd should resolve");
        std::env::set_current_dir(&root).expect("cwd should switch");
        let result = run(
            Command::Init {
                path: root.clone(),
                package_name: None,
                template: Some("minimal".to_string()),
                with: vec!["all".to_string()],
                force: false,
            },
            Format::Text,
        );
        std::env::set_current_dir(prev).expect("cwd should restore");
        result.expect("init in current directory should succeed");
        assert!(root.join("fozzy.toml").exists());
        assert!(root.join("src/main.fzy").exists());
        assert!(root.join("tests/example.fozzy.json").exists());
        assert!(root.join(".fozzy/corpora").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn incremental_build_reuses_module_objects_on_second_build() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-incr-reuse-{suffix}"));
        std::fs::create_dir_all(root.join("src/services")).expect("project dirs should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"incr_reuse\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"incr_reuse\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nfn main() -> i32 {\n    return services.boot()\n}\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 7\n}\n",
        )
        .expect("service should be written");

        let first = compile_file_incremental_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            None,
        )
        .expect("first incremental build should succeed");
        assert_eq!(first.status, "ok");
        assert!(first
            .incremental
            .as_ref()
            .is_some_and(|report| report.rebuilt_modules > 0));

        let second = compile_file_incremental_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            None,
        )
        .expect("second incremental build should succeed");
        let report = second
            .incremental
            .expect("incremental report should be attached");
        assert_eq!(report.rebuilt_modules, 0);
        assert_eq!(report.reused_modules, report.module_count);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn incremental_build_targets_touched_module_without_rebuilding_everything() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-incr-touch-{suffix}"));
        std::fs::create_dir_all(root.join("src/services")).expect("project dirs should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"incr_touch\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"incr_touch\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nfn main() -> i32 {\n    return services.boot()\n}\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 7\n}\n\npub fn health() -> i32 {\n    return 1\n}\n",
        )
        .expect("service should be written");

        compile_file_incremental_with_backend_with_root_guidance(&root, BuildProfile::Dev, None)
            .expect("seed incremental build should succeed");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 8\n}\n\npub fn health() -> i32 {\n    return 1\n}\n",
        )
        .expect("service should mutate");

        let rebuilt = compile_file_incremental_with_backend_with_root_guidance(
            &root,
            BuildProfile::Dev,
            None,
        )
        .expect("incremental rebuild should succeed");
        let report = rebuilt
            .incremental
            .expect("incremental report should be attached");
        assert!(report.rebuilt_modules >= 1);
        assert!(report.rebuilt_modules < report.module_count);
        assert!(report
            .module_details
            .iter()
            .any(|module| { module.path.ends_with("src/services/mod.fzy") && module.rebuilt }));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn incremental_build_serializes_same_project_parallel_calls() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-incr-parallel-{suffix}"));
        std::fs::create_dir_all(root.join("src/services")).expect("project dirs should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"incr_parallel\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"incr_parallel\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nfn main() -> i32 {\n    return services.boot()\n}\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 7\n}\n",
        )
        .expect("service should be written");

        let worker_count = 4usize;
        let barrier = Arc::new(Barrier::new(worker_count));
        let mut handles = Vec::new();
        for _ in 0..worker_count {
            let root = root.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                compile_file_incremental_with_backend_with_root_guidance(
                    &root,
                    BuildProfile::Dev,
                    None,
                )
            }));
        }

        let results: Vec<BuildArtifact> = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .expect("parallel incremental build thread should not panic")
                    .expect("parallel incremental build should succeed")
            })
            .collect();
        assert!(results.iter().all(|artifact| artifact.status == "ok"));
        assert!(results
            .iter()
            .all(|artifact| artifact.output.as_ref().is_some_and(|path| path.exists())));

        let reports: Vec<&IncrementalBuildReport> = results
            .iter()
            .map(|artifact| {
                artifact
                    .incremental
                    .as_ref()
                    .expect("incremental report should be attached")
            })
            .collect();
        assert!(reports.iter().any(|report| report.rebuilt_modules > 0));
        assert!(reports.iter().all(|report| {
            report.rebuilt_modules + report.reused_modules == report.module_count
        }));
        assert!(reports
            .iter()
            .all(|report| report.module_count == reports[0].module_count));

        let status = std::process::Command::new(
            results[0]
                .output
                .as_ref()
                .expect("artifact output should be present"),
        )
        .status()
        .expect("built binary should execute");
        assert_eq!(status.code(), Some(7));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn incremental_build_compiles_distinct_snapshots_in_parallel() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-incr-snapshots-{suffix}"));
        std::fs::create_dir_all(root.join("src/services")).expect("project dirs should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"incr_snapshots\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"incr_snapshots\"\npath=\"src/main.fzy\"\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "mod services;\nfn main() -> i32 {\n    return services.boot() + 1\n}\n",
        )
        .expect("main should be written");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 7\n}\n",
        )
        .expect("service should be written");

        let snapshot_a = crate::pipeline::prepare_build_snapshot(&root)
            .expect("first snapshot capture should succeed");
        std::fs::write(
            root.join("src/services/mod.fzy"),
            "pub fn boot() -> i32 {\n    return 8\n}\n",
        )
        .expect("service should mutate");
        let snapshot_b = crate::pipeline::prepare_build_snapshot(&root)
            .expect("second snapshot capture should succeed");
        assert_ne!(
            snapshot_a.snapshot_project_root,
            snapshot_b.snapshot_project_root
        );

        let barrier = Arc::new(Barrier::new(2));
        let root_a = snapshot_a.snapshot_project_root.clone();
        let root_b = snapshot_b.snapshot_project_root.clone();
        let handle_a = {
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                compile_file_incremental_with_backend_with_root_guidance(
                    &root_a,
                    BuildProfile::Dev,
                    None,
                )
            })
        };
        let handle_b = {
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                compile_file_incremental_with_backend_with_root_guidance(
                    &root_b,
                    BuildProfile::Dev,
                    None,
                )
            })
        };

        let artifact_a = handle_a
            .join()
            .expect("snapshot A build thread should not panic")
            .expect("snapshot A build should succeed");
        let artifact_b = handle_b
            .join()
            .expect("snapshot B build thread should not panic")
            .expect("snapshot B build should succeed");
        assert_eq!(artifact_a.status, "ok");
        assert_eq!(artifact_b.status, "ok");

        let output_a = artifact_a
            .output
            .as_ref()
            .expect("snapshot A output should be present");
        let output_b = artifact_b
            .output
            .as_ref()
            .expect("snapshot B output should be present");
        assert_ne!(output_a, output_b);
        assert!(output_a.to_string_lossy().contains("/.fz/snapshots/"));
        assert!(output_b.to_string_lossy().contains("/.fz/snapshots/"));

        let status_a = std::process::Command::new(output_a)
            .status()
            .expect("snapshot A binary should execute");
        let status_b = std::process::Command::new(output_b)
            .status()
            .expect("snapshot B binary should execute");
        assert_eq!(status_a.code(), Some(8));
        assert_eq!(status_b.code(), Some(9));

        let report_a = artifact_a
            .incremental
            .expect("snapshot A incremental report should be present");
        let report_b = artifact_b
            .incremental
            .expect("snapshot B incremental report should be present");
        let main_object_a = report_a
            .module_details
            .iter()
            .find(|module| module.path.ends_with("src/main.fzy"))
            .and_then(|module| module.object.clone())
            .expect("snapshot A main object should exist");
        let main_object_b = report_b
            .module_details
            .iter()
            .find(|module| module.path.ends_with("src/main.fzy"))
            .and_then(|module| module.object.clone())
            .expect("snapshot B main object should exist");
        let service_object_a = report_a
            .module_details
            .iter()
            .find(|module| module.path.ends_with("src/services/mod.fzy"))
            .and_then(|module| module.object.clone())
            .expect("snapshot A service object should exist");
        let service_object_b = report_b
            .module_details
            .iter()
            .find(|module| module.path.ends_with("src/services/mod.fzy"))
            .and_then(|module| module.object.clone())
            .expect("snapshot B service object should exist");
        assert_eq!(main_object_a, main_object_b);
        assert_ne!(service_object_a, service_object_b);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn init_command_requires_force_when_scaffold_paths_exist() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fozzylang-init-collision-{suffix}"));
        std::fs::create_dir_all(root.join("src")).expect("src should be created");
        std::fs::write(root.join("src/main.fzy"), "fn main() -> i32 { return 7 }\n")
            .expect("main should be written");

        let err = run(
            Command::Init {
                path: root.clone(),
                package_name: Some("collision".to_string()),
                template: None,
                with: Vec::new(),
                force: false,
            },
            Format::Text,
        )
        .expect_err("init should reject existing scaffold paths");
        assert!(err.to_string().contains("scaffold-managed paths"));

        let _ = std::fs::remove_dir_all(root);
    }
}
