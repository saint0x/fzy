#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{lower, split_generic_callee};

    #[test]
    fn lowers_trait_bounds_and_generic_specializations() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            struct Boxed { value: i32 }
            impl Show for Boxed { fn show(v: i32) -> i32 { return v; } }
            fn id<T: Show>(v: T) -> T { return v; }
            fn main() -> i32 {
                let b = Boxed { value: 9 };
                let b2 = id<Boxed>(b);
                return b2.value;
            }
        "#;
        let module = parser::parse(&source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.trait_violations.is_empty());
        assert!(typed
            .generic_specializations
            .iter()
            .any(|entry| entry.starts_with("id<")));
    }

    #[test]
    fn flags_missing_trait_impl_for_specialization() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            fn id<T: Show>(v: T) -> T { return v; }
            fn main() -> i32 {
                let v: i32 = 4;
                discard id<i32>(v);
                return 0;
            }
        "#;
        let module = parser::parse(&source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(!typed.trait_violations.is_empty());
    }

    #[test]
    fn parses_nested_generic_specializations() {
        let (base, explicit) = split_generic_callee("id<Option<Result<i32, i32>>>");
        assert_eq!(base, "id");
        let explicit = explicit.expect("explicit generic args");
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit[0].to_string(), "Option<Result<i32, i32>>");
    }

    #[test]
    fn lowers_impl_methods_as_callable_symbols() {
        let source = r#"
            trait Render { fn render(v: i32) -> i32; }
            struct Point { x: i32 }
            impl Render for Point {
                fn render(v: i32) -> i32 { return v + 1; }
            }
            fn main() -> i32 {
                return Point.render(4);
            }
        "#;
        let module = parser::parse(&source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed
            .typed_functions
            .iter()
            .any(|function| function.name == "Point.render"));
    }

    #[test]
    fn flags_trait_impl_parameter_type_mismatch() {
        let source = r#"
            trait Render { fn render(v: i32) -> i32; }
            struct Point { x: i32 }
            impl Render for Point {
                fn render(v: i64) -> i32 { return 1; }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .trait_violations
            .iter()
            .any(|detail| detail.contains("parameter 0 type mismatch")));
    }

    #[test]
    fn validates_trait_associated_items_in_impls() {
        let source = r#"
            trait Cache {
                type Key;
                const VERSION: i32;
                fn get(k: i32) -> i32;
            }
            struct Store {}
            impl Cache for Store {
                type Key = i32;
                const VERSION: i32 = 1;
                fn get(k: i32) -> i32 { return k; }
            }
            impl Cache for i32 {
                fn get(k: i32) -> i32 { return k; }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .trait_violations
            .iter()
            .any(|detail| detail.contains("missing associated type `Key`")));
        assert!(typed
            .trait_violations
            .iter()
            .any(|detail| detail.contains("missing associated const `VERSION`")));
    }

    #[test]
    fn resolves_self_and_associated_types_inside_trait_impl_methods() {
        let source = r#"
            trait Cache {
                type Key;
                fn get(self: Self, key: Self::Key) -> i32;
            }
            struct Store { value: i32 }
            impl Cache for Store {
                type Key = i32;
                fn get(self: Self, key: i32) -> i32 {
                    return self.value + key;
                }
            }
            fn main() -> i32 {
                let store = Store { value: 3 };
                return Store.get(store, 4);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.trait_violations.is_empty());
    }

    #[test]
    fn allows_generic_trait_impl_targets() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            impl Show for T {
                fn show(v: i32) -> i32 { return v; }
            }
            fn id<U: Show>(v: U) -> U { return v; }
            fn main() -> i32 {
                discard id<i32>(1);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.trait_violations.is_empty());
    }

    #[test]
    fn flags_overlapping_trait_impls_as_ambiguous() {
        let source = r#"
            trait Show { fn show(v: i32) -> i32; }
            struct Point { x: i32 }
            impl Show for Point { fn show(v: i32) -> i32 { return v; } }
            impl Show for Point { fn show(v: i32) -> i32 { return v + 1; } }
            fn id<T: Show>(v: T) -> T { return v; }
            fn main() -> i32 {
                let p = Point { x: 1 };
                discard id<Point>(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .trait_violations
            .iter()
            .any(|detail| detail.contains("overlapping impls for trait `Show`")));
        assert!(typed
            .trait_violations
            .iter()
            .any(|detail| detail.contains("ambiguous bound `Show`")));
    }

    #[test]
    fn flags_unknown_trait_bound_at_declaration_time() {
        let source = r#"
            fn id<T: Missing>(v: T) -> T { return v; }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .trait_violations
            .iter()
            .any(|detail| detail.contains("trait `Missing` is not defined")));
    }

    #[test]
    fn builtin_error_trait_bound_is_available() {
        let source = r#"
            fn wrap<T: Error>(value: T) -> Result<i32, T> {
                discard value;
                return 0;
            }
        "#;
        let module = parser::parse(source, "error_trait").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .trait_violations
            .iter()
            .any(|detail| detail.contains("trait `Error` is not defined")));
    }

    #[test]
    fn flags_invalid_specialization_shape() {
        let source = r#"
            fn id<T>(v: T) -> T { return v; }
            fn main() -> i32 {
                let v: i32 = 1;
                discard id<fn(i32) -> i32>(v);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_error_details.iter().any(|detail| {
            detail.contains("invalid generic specialization syntax for call `id<fn(i32) -> i32>`")
        }));
    }

    #[test]
    fn flags_reference_without_lifetime_annotation() {
        let source = r#"
            fn borrow(v: &str) -> &str {
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.reference_lifetime_violations.is_empty());
    }

    #[test]
    fn net_path_routing_typechecks_and_keeps_entry_i32() {
        let source = r#"
            use core.http;
            fn main() -> i32 {
                let l = http.bind("127.0.0.1:8787");
                http.listen(l);
                let c = http.accept();
                http.read(c);
                let p = http.path(c);
                if p == "/a" {
                    http.write(c, 200, "path-a");
                } else {
                    http.write(c, 200, "path-other");
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(0));
    }

    #[test]
    fn unknown_dotted_call_is_a_type_error() {
        let source = r#"
            fn main() -> i32 {
                fake.module.call();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
    }

    #[test]
    fn process_spawn_string_command_typechecks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                proc.spawn("echo hi");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn process_spawn_non_string_reports_detail() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                proc.spawn(1);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("proc.spawn") && detail.contains("expected `str`")));
    }

    #[test]
    fn process_spawn_cmd_with_typed_builders_typechecks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argv = proc.argv_new();
                proc.argv_push(argv, "hi");
                let env = proc.env_new();
                proc.env_set(env, "K", "V");
                proc.spawn_cmd("echo", argv, env, "stdin");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn process_builder_handles_without_spawn_report_linear_leaks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                proc.argv_push(argv, "hi");
                proc.env_set(env, "K", "V");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `argv` was not consumed/freed")
        }));
        assert!(typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `env` was not consumed/freed")
        }));
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`argv`")));
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`env`")));
    }

    #[test]
    fn process_spawn_cmd_consumes_argv_and_env_builders() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argv = proc.argv_new();
                proc.argv_push(argv, "hi");
                let env = proc.env_new();
                proc.env_set(env, "K", "V");
                let handle = proc.spawn_cmd("echo", argv, env, "");
                discard proc.close(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `argv` was not consumed/freed")
                || detail.contains("function `main` linear value `env` was not consumed/freed")
        }));
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `main` leaks allocation")
                && (detail.contains("`argv`") || detail.contains("`env`"))
        }));
    }

    #[test]
    fn process_spawn_wrapper_can_consume_builder_handles() {
        let source = r#"
            use core.proc;
            fn launch(argv: ProcessArgv, env: ProcessEnv) -> ProcessHandle {
                return proc.spawn_cmd("echo", argv, env, "");
            }
            fn main() -> i32 {
                let argv = proc.argv_new();
                proc.argv_push(argv, "hi");
                let env = proc.env_new();
                proc.env_set(env, "K", "V");
                let handle = launch(argv, env);
                discard proc.close(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("linear value `argv` was not consumed/freed")
                || detail.contains("linear value `env` was not consumed/freed")
        }));
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `main` leaks allocation")
                && (detail.contains("`argv`") || detail.contains("`env`"))
        }));
    }

    #[test]
    fn process_close_typechecks_after_wait_and_observation() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                let handle = proc.spawn_cmd("echo", argv, env, "");
                discard proc.wait(handle, 1000);
                discard proc.stdout(handle);
                discard proc.stderr(handle);
                discard proc.exit_code(handle);
                discard proc.close(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn process_close_wrapper_can_consume_linear_param() {
        let source = r#"
            use core.proc;
            fn close_wrapper(handle: ProcessHandle) -> i32 {
                return proc.close(handle);
            }
            fn main() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                let handle = proc.spawn_cmd("echo", argv, env, "");
                discard close_wrapper(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn kv_store_handles_without_close_report_linear_leaks() {
        let source = r#"
            use core.storage;
            fn main() -> i32 {
                let store = storage.kv_open("session.kv");
                discard storage.kv_put(store, "session:key", "value");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `store` was not consumed/freed")
        }));
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`store`")));
    }

    #[test]
    fn kv_close_consumes_store_handle() {
        let source = r#"
            use core.storage;
            fn main() -> i32 {
                let store = storage.kv_open("session.kv");
                discard storage.kv_put(store, "session:key", "value");
                discard storage.kv_close(store);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `store` was not consumed/freed")
        }));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("function `main` leaks allocation")
                && detail.contains("`store`")));
    }

    #[test]
    fn file_handles_without_close_report_linear_leaks() {
        let source = r#"
            use core.fs;
            fn main() -> i32 {
                let file = fs.open("/tmp/fzy-file-handle-leak");
                discard fs.write(file, "hello");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `file` was not consumed/freed")
        }));
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`file`")));
    }

    #[test]
    fn fs_close_consumes_file_handle() {
        let source = r#"
            use core.fs;
            fn main() -> i32 {
                let file = fs.open("/tmp/fzy-file-handle-close");
                discard fs.write(file, "hello");
                discard fs.flush(file);
                discard fs.close(file);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `file` was not consumed/freed")
        }));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("function `main` leaks allocation")
                && detail.contains("`file`")));
    }

    #[test]
    fn file_close_wrapper_can_consume_linear_param() {
        let source = r#"
            use core.fs;
            fn close_file(file: FileHandle) -> i32 {
                return fs.close(file);
            }
            fn main() -> i32 {
                let file = fs.open("/tmp/fzy-file-handle-wrapper");
                discard fs.write(file, "hello");
                discard close_file(file);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn current_process_cli_intrinsics_typecheck() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argc = proc.argv_count();
                let arg0 = proc.argv_get(0);
                let line = term.read_line();
                discard term.write(arg0);
                discard term.write_err(line);
                discard term.stdin_is_tty();
                discard term.stdout_is_tty();
                return argc + term.stdin_eof();
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn process_spawnl_with_typed_args_typechecks() {
        let source = r#"
            use core.proc;
            fn main() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                proc.spawnl("echo", argv, env, "stdin");
                proc.runl("echo", argv, env, "");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn http_capture_and_json_builders_typecheck() {
        let source = r#"
            use core.http;
            fn main() -> i32 {
                let user = json.str("hello");
                let msg_obj = map.new();
                map.set(msg_obj, "role", json.str("user"));
                map.set(msg_obj, "content", user);
                let msg = json.object(msg_obj);
                let messages_list = list.new();
                list.push(messages_list, msg);
                let messages = json.array(messages_list);
                let payload_obj = map.new();
                map.set(payload_obj, "model", json.str("claude"));
                map.set(payload_obj, "messages", messages);
                let payload = json.object(payload_obj);
                discard http.post_json_capture("https://example.com", payload);
                discard http.last_status();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn http_streaming_and_sse_helpers_typecheck() {
        let source = r#"
            fn main() -> i32 {
                discard http.header_set("accept", "text/event-stream");
                let stream = http.request_stream("POST", "https://example.com", "{\"stream\":true}");
                let line = http.stream_read_line(stream);
                let chunk = http.stream_read(stream, 128);
                discard http.stream_status(stream);
                discard http.stream_error(stream);
                discard http.stream_close(stream);
                if str.len(line) >= 0 && str.len(chunk) >= 0 {
                    return 0;
                }
                return 1;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn extended_runtime_primitives_typecheck() {
        let source = r#"
            use core.http;
            use core.proc;
            fn main() -> i32 {
                discard str.contains("abc", "a");
                discard fs.exists("/tmp");
                discard time.monotonic_ms();
                discard proc.poll(proc.spawn("echo hi"));
                let c = http.accept();
                discard http.header(c, "content-type");
                discard route.match(c, "GET", "/sessions/:id/messages");
                let fields_map = map.new();
                map.set(fields_map, "component", "test");
                map.set(fields_map, "phase", "boot");
                let fields = log.fields(fields_map);
                discard log.info("x", fields);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn json_parse_and_body_json_primitives_typecheck() {
        let source = r#"
            use core.http;
            fn main() -> i32 {
                let c = http.accept();
                let body = http.body_json(c);
                let bound = http.body_bind(c);
                discard bound;
                discard json.has(body, "message");
                let msg = json.get_str(body, "message");
                let nested = json.path(body, "meta.user.id");
                discard json.get(nested, "raw");
                discard json.parse("{\"ok\":true}");
                if str.len(msg) > 0 {
                    http.write(c, 200, msg);
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn json_keys_and_bridges_accept_json_handles() {
        let source = r#"
            fn main() -> i32 {
                let parsed = json.parse("{\"message\":\"hi\",\"count\":\"2\"}")
                let keys = json.keys(parsed)
                let as_map = json.to_map(parsed)
                discard map.keys(as_map)
                return list.len(keys)
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn variadic_str_concat_typechecks() {
        let source = r#"
            fn main() -> i32 {
                let path = str.concat("svc/", "tenant/", "sessions/", "abc", "/latest")
                if str.len(path) > 0 {
                    return 0;
                }
                return 1;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn string_conversion_and_path_helpers_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let rendered = str.concat("port=", str.from_i32(8080), ", enabled=", str.from_bool(true))
                let joined = path.join("/srv/app", "config/runtime.json")
                let base = path.basename(joined)
                let dir = path.dirname(joined)
                let stem = path.stem(joined)
                let extension = path.extension(joined)
                discard rendered
                discard base
                discard dir
                discard stem
                discard extension
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn string_slice_and_ascii_case_helpers_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let first = str.slice("name", 0, 1)
                let middle = str.slice("name", 1, 3)
                let upper = str.upper_ascii("tool_arg_name")
                let lower = str.lower_ascii("TOOL_ARG_NAME")
                discard first
                discard middle
                discard upper
                discard lower
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn fs_listdir_returns_list_handle_for_list_ops() {
        let source = r#"
            use core.fs;
            fn main() -> i32 {
                let entries = fs.listdir("/tmp")
                return list.len(entries)
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn fs_metadata_and_copy_tree_intrinsics_typecheck() {
        let source = r#"
            use core.fs;
            fn main() -> i32 {
                let path = "/tmp/demo"
                let mut score = fs.exists(path)
                score += fs.is_file(path)
                score += fs.is_dir(path)
                score += fs.is_symlink(path)
                score += fs.stat_size(path)
                score += fs.stat_mtime(path)
                score += fs.copy_file("/tmp/a", "/tmp/b")
                score += fs.copy_tree("/tmp/src", "/tmp/out")
                score += fs.remove(path)
                return score % 251
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn string_addition_reports_actionable_concat_guidance() {
        let source = r#"
            fn main() -> i32 {
                let path = "svc/" + "tenant"
                if str.len(path) > 0 {
                    return 0;
                }
                return 1;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("string addition is unsupported")
                    && detail.contains("str.concat")),
            "expected string-addition guidance, got {:?}",
            typed.type_error_details
        );
    }

    #[test]
    fn fixed_arity_concat_reports_variadic_guidance() {
        let source = r#"
            fn main() -> i32 {
                let value = str.concat3("worker=", "7")
                discard value
                return 0
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("str.concat(...)")),
            "expected variadic concat guidance, got {:?}",
            typed.type_error_details
        );
    }

    #[test]
    fn object_literal_json_and_log_paths_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let fields = map.new();
                map.set(fields, "component", json.str("test"));
                map.set(fields, "phase", json.str("boot"));
                discard log.info("boot", log.fields(fields));
                discard http.post_json_capture("https://example.com", json.object(fields));
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn object_literal_can_flow_directly_into_json_object_and_log_fields() {
        let source = r#"
            fn main() -> i32 {
                let payload = json.object(#{"ok": json.raw("true"), "msg": json.str("hi")});
                discard log.fields(#{"component": json.str("boot"), "phase": json.str("init")});
                if payload == "" {
                    return 1;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn removed_json_object_arity_reports_autofix_hint() {
        let source = r#"
            fn main() -> i32 {
                let payload = json.object3("a", json.str("1"), "b", json.str("2"), "c", json.str("3"));
                discard payload;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("autofix")));
    }

    #[test]
    fn match_semantic_hints_track_unreachable_and_duplicate_catchalls() {
        let source = r#"
            fn main() -> i32 {
                let v: i32 = 1;
                match v {
                    _ => 1,
                    2 => 2,
                    x => x,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.match_unreachable_arms, 2);
        assert_eq!(typed.match_duplicate_catchall_arms, 1);
    }

    #[test]
    fn qualified_variant_patterns_typecheck_against_scrutinee_enum() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let m = Maybe::Some(7);
                match m {
                    Maybe::Some(v) => return v,
                    Maybe::None => 0,
                    _ => 0,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn let_pattern_variant_binding_is_available_after_destructure() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let Maybe::Some(v) = Maybe::Some(9);
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(9));
    }

    #[test]
    fn struct_patterns_bind_fields_in_let_and_match() {
        let source = r#"
            struct Pair { left: i32, right: i32 }
            fn main() -> i32 {
                let Pair { left, right: r } = Pair { left: 4, right: 9 };
                match Pair { left: left, right: r } {
                    Pair { left: a, right: b } => return a + b,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(13));
    }

    #[test]
    fn qualified_variant_pattern_rejects_wrong_enum_name() {
        let source = r#"
            enum Left { A(i32) }
            enum Right { A(i32) }
            fn main() -> i32 {
                let v = Left::A(1);
                match v {
                    Right::A(x) => x,
                    _ => 0,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("does not match scrutinee enum")));
    }

    #[test]
    fn match_arm_return_typechecks_and_counts_as_explicit_return() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    1 => return 7,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn match_arm_return_type_mismatch_reports_error() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    1 => return true,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("return type mismatch")));
    }

    #[test]
    fn async_await_typechecks_in_async_function() {
        let source = r#"
            async fn worker() -> i32 { return 1; }
            async fn main() -> i32 {
                let v: i32 = await worker();
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn await_in_non_async_function_reports_semantic_error() {
        let source = r#"
            async fn worker() -> i32 { return 1; }
            fn main() -> i32 {
                let v: i32 = await worker();
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("uses `await` but is not declared async")));
    }

    #[test]
    fn timeout_requires_millis_argument() {
        let source = r#"
            fn main() -> i32 {
                timeout();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
    }

    #[test]
    fn timeout_with_millis_argument_typechecks() {
        let source = r#"
            fn main() -> i32 {
                timeout(25);
                discard deadline(100);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn assignment_to_immutable_binding_reports_error() {
        let source = r#"
            fn main() -> i32 {
                let v: i32 = 0;
                v = 1;
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("assignment to immutable binding")));
    }

    #[test]
    fn assignment_to_mutable_binding_typechecks() {
        let source = r#"
            fn main() -> i32 {
                let mut v: i32 = 0;
                v = 1;
                v += 2;
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn const_and_static_are_resolved_in_function_scope() {
        let source = r#"
            const MAGIC: i32 = 7;
            static LIMIT: i32 = MAGIC + 3;
            fn main() -> i32 {
                let x: i32 = MAGIC;
                let y: i32 = LIMIT;
                return x + y;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.typed_globals.iter().any(|item| item.name == "MAGIC"));
        assert!(typed.typed_globals.iter().any(|item| item.name == "LIMIT"));
    }

    #[test]
    fn const_initializer_requires_compile_time_integer_expression() {
        let source = r#"
            fn runtime() -> i32 { return 1; }
            const BAD: i32 = runtime();
            fn main() -> i32 { return BAD; }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed.type_error_details.iter().any(|detail| {
            detail.contains("must be initialized with an integer/char/bool compile-time expression")
        }));
    }

    #[test]
    fn detects_use_after_free_via_alias_provenance() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                let q = p;
                free(p);
                close(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `q` after provenance root")));
    }

    #[test]
    fn distinguishes_helper_returned_pointer_provenance_by_parameter_index() {
        let source = r#"
            fn first(a: *mut u8, b: *mut u8) -> *mut u8 {
                return a;
            }
            fn second(a: *mut u8, b: *mut u8) -> *mut u8 {
                return b;
            }
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let from_first = first(a, b);
                let from_second = second(a, b);
                free(a);
                close(from_first);
                close(from_second);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `from_first` after provenance root")));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `from_second` after provenance root")));
    }

    #[test]
    fn tuple_pattern_bindings_preserve_element_provenance() {
        let source = r#"
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let (left, right) = (a, b);
                free(a);
                close(left);
                close(right);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `left` after provenance root")));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `right` after provenance root")));
    }

    #[test]
    fn struct_pattern_bindings_preserve_field_provenance() {
        let source = r#"
            struct Pair { left: *mut u8, right: *mut u8 }
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let Pair { left, right } = Pair { left: a, right: b };
                free(a);
                close(left);
                close(right);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `left` after provenance root")));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `right` after provenance root")));
    }

    #[test]
    fn reassignment_clears_stale_provenance_root() {
        let source = r#"
            ext unsafe c fn acquire_owned() -> *u8;
            unsafe fn main() -> i32 {
                let p = alloc(32);
                let q = p;
                q = acquire_owned();
                free(p);
                close(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `q` after provenance root")));
    }

    #[test]
    fn returning_second_pointer_arg_is_not_collapsed_to_first_argument_root() {
        let source = r#"
            fn passthrough(a: *mut u8, b: *mut u8) -> *mut u8 {
                return b;
            }
            fn main() -> i32 {
                let a = alloc(32);
                let b = alloc(32);
                let ret = passthrough(a, b);
                free(a);
                close(ret);
                free(b);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `ret` after provenance root")));
    }

    #[test]
    fn detects_nested_use_after_free_via_control_flow() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                let q = p;
                if true {
                    free(p);
                } else {
                    return 0;
                }
                close(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("uses value `q` after provenance root")));
    }

    #[test]
    fn detects_divergent_ownership_across_branches() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                if true {
                    free(p);
                } else {
                }
                close(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `p`")
                || detail.contains("uses moved value `p` after move/consume")
        }));
    }

    #[test]
    fn detects_conditional_move_before_reuse() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                if true {
                    let q = p;
                    discard q;
                }
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("conditionally consumed value `p`")
                || detail.contains("divergent ownership state for `p`")
                || detail.contains("uses moved value `p` after move/consume")
        }));
    }

    #[test]
    fn borrowed_references_are_not_collected_as_linear_resources() {
        let source = r#"
            fn borrow(v: &'a i32) -> &'a i32 {
                return v;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let r = borrow(x);
                discard r;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_resources.iter().any(|name| name == "r"));
    }

    #[test]
    fn explicit_borrowed_local_via_call_typechecks_without_linear_leak() {
        let source = r#"
            fn borrow(v: &'a *mut u8) -> &'a *mut u8 {
                return v;
            }
            fn main() -> i32 {
                let p = alloc(32);
                let alias: &'a *mut u8 = borrow(p);
                discard alias;
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("linear value `alias` was not consumed/freed")
                || detail.contains("frees non-linear value `alias` as linear resource")
        }));
    }

    #[test]
    fn inferred_alloc_local_is_treated_as_linear_resource() {
        let source = r#"
            fn main() -> i32 {
                let n: usize = 32;
                let p = alloc(n);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .linear_type_violations
            .iter()
            .any(|detail| detail.contains("frees non-linear value `p`")));
    }

    #[test]
    fn alloc_accepts_integer_literals_for_usize_runtime_size() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(!typed
            .linear_type_violations
            .iter()
            .any(|detail| detail.contains("frees non-linear value `p`")));
    }

    #[test]
    fn const_usize_accepts_integer_literal_initializer() {
        let source = r#"
            const LEN: usize = 32
            fn main() -> i32 {
                let p = alloc(LEN);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn raw_pointer_indexing_typechecks_for_borrowed_buffers() {
        let source = r#"
            #[ffi_panic(abort)]
            pubext c fn first(buf_borrowed: *f32, buf_len: usize) -> f32 {
                discard buf_len
                return buf_borrowed[0]
            }
        "#;
        let module = parser::parse(source, "first").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn gpu_upload_accepts_borrowed_pointer_with_sibling_len() {
        let source = r#"
            use core.gpu;
            #[ffi_panic(abort)]
            pubext c fn upload(weights_borrowed: *f32, weights_len: usize) -> i32 {
                let dev = gpu.default_device()
                let buf: GpuBuffer<f32> = gpu.upload_f32(dev, weights_borrowed)
                gpu.free(buf)
                return 0
            }
        "#;
        let module = parser::parse(source, "gpu_upload_ptr").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn kernel_plain_helpers_typecheck_after_default_pure_inference() {
        let source = r#"
            use core.gpu;

            fn bias(value: f32) -> f32 {
                return value + 1.0f32
            }

            kernel fn forward(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x()
                if i < n {
                    output[i] = bias(input[i])
                }
            }

            host fn main() -> i32 {
                return 0
            }
        "#;
        let module = parser::parse(source, "gpu_kernel_plain_helper").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn deferred_cleanup_counts_as_real_release() {
        let source = r#"
            fn main() -> i32 {
                let n: usize = 32;
                let p = alloc(n);
                defer free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.deferred_resources.iter().any(|name| name == "p"));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`p`")));
        assert!(!typed
            .linear_type_violations
            .iter()
            .any(|detail| detail.contains("linear value `p` was not consumed/freed")));
    }

    #[test]
    fn explicit_free_after_defer_is_rejected_as_double_cleanup() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                defer free(p);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("consumes value `p` after scheduling deferred cleanup")
        }));
    }

    #[test]
    fn defer_after_explicit_free_is_rejected_as_double_cleanup() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                free(p);
                defer free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail
                .contains("schedules deferred cleanup for non-owned or already-consumed value `p`")
                || detail.contains("uses moved value `p` after move/consume")
                || detail.contains("uses value `p` after provenance root")
        }));
    }

    #[test]
    fn inferred_pointer_return_without_cleanup_is_tracked() {
        let source = r#"
            ext unsafe c fn acquire_owned() -> *u8;
            unsafe fn main() -> i32 {
                let p = acquire_owned();
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`p`")));
    }

    #[test]
    fn inferred_handle_local_without_cleanup_matches_typed_handle_failure() {
        let inferred = r#"
            fn main() -> i32 {
                let listener = http.accept();
                return 0;
            }
        "#;
        let typed_src = r#"
            fn main() -> i32 {
                let listener: HttpHandle = http.accept();
                return 0;
            }
        "#;
        let inferred_typed = lower(&parser::parse(inferred, "main").expect("parse"));
        let explicit_typed = lower(&parser::parse(typed_src, "main").expect("parse"));
        assert!(inferred_typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`listener`")));
        assert!(explicit_typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`listener`")));
        assert!(inferred_typed
            .linear_type_violations
            .iter()
            .any(|detail| detail.contains("linear value `listener` was not consumed/freed")));
        assert!(explicit_typed
            .linear_type_violations
            .iter()
            .any(|detail| detail.contains("linear value `listener` was not consumed/freed")));
    }

    #[test]
    fn match_arm_cleanup_updates_ownership_state() {
        let source = r#"
            fn main() -> i32 {
                let n: usize = 32;
                let p = alloc(n);
                match true {
                    true => free(p),
                    _ => 0,
                }
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `p`")
                || detail.contains("uses moved value `p` after move/consume")
                || detail.contains("consumes non-owned or already-consumed value `p`")
        }));
    }

    #[test]
    fn if_expression_move_in_one_branch_marks_source_conditionally_consumed() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                let q = if true { p } else { alloc(64) };
                free(p);
                free(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("conditionally consumed value `p`")
                || detail.contains("uses moved value `p` after move/consume")
                || detail.contains("divergent ownership state for `p`")
        }));
    }

    #[test]
    fn match_expression_move_in_one_arm_marks_source_conditionally_consumed() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                let q = match true {
                    true => p,
                    _ => alloc(64),
                };
                free(p);
                free(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("conditionally consumed value `p`")
                || detail.contains("uses moved value `p` after move/consume")
                || detail.contains("divergent ownership state for `p`")
        }));
    }

    #[test]
    fn grouped_binding_move_marks_source_moved() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                let q = (p);
                free(p);
                free(q);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("uses moved value `p` after move/consume")
                || detail.contains("consumes non-owned or already-consumed value `p`")
        }));
    }

    #[test]
    fn return_if_expression_move_in_one_branch_reports_terminal_leak() {
        let source = r#"
            fn produce(flag: i32) -> *mut u8 {
                let p = alloc(32);
                return if flag == 0 { p } else { alloc(64) };
            }
            fn main() -> i32 {
                let p = produce(0);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| detail
            .contains("function `produce` leaks allocation")
            && detail.contains("`p`")));
        assert!(typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `produce` linear value `p` was not consumed/freed")
        }));
    }

    #[test]
    fn return_match_expression_move_in_one_arm_reports_terminal_leak() {
        let source = r#"
            fn produce(flag: i32) -> *mut u8 {
                let p = alloc(32);
                return match flag {
                    0 => p,
                    _ => alloc(64),
                };
            }
            fn main() -> i32 {
                let p = produce(0);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| detail
            .contains("function `produce` leaks allocation")
            && detail.contains("`p`")));
        assert!(typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `produce` linear value `p` was not consumed/freed")
        }));
    }

    #[test]
    fn return_if_expression_owned_transfer_on_all_paths_stays_clean() {
        let source = r#"
            fn produce(flag: i32) -> *mut u8 {
                let p = alloc(32);
                return if flag == 0 { p } else { (p) };
            }
            fn main() -> i32 {
                let p = produce(0);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `produce` leaks allocation")
                || detail.contains("crosses function with potential resource escape")
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `produce` linear value `p` was not consumed/freed")
        }));
    }

    #[test]
    fn return_match_expression_owned_transfer_on_all_paths_stays_clean() {
        let source = r#"
            fn produce(flag: i32) -> *mut u8 {
                let p = alloc(32);
                return match flag {
                    0 => p,
                    _ => (p),
                };
            }
            fn main() -> i32 {
                let p = produce(0);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `produce` leaks allocation")
                || detail.contains("crosses function with potential resource escape")
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `produce` linear value `p` was not consumed/freed")
        }));
    }

    #[test]
    fn detects_mutable_aliasing_across_ref_params() {
        let source = r#"
            fn touch(a: &'a mut i32, b: &'a mut i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                touch(x, x);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("aliases mutable reference parameter `x`")));
    }

    #[test]
    fn detects_mutable_aliasing_through_grouped_ref_argument() {
        let source = r#"
            fn touch(a: &'a mut i32, b: &'a mut i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                touch((x), x);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("aliases mutable reference parameter `x`")));
    }

    #[test]
    fn grouped_owned_ffi_argument_marks_root_consumed() {
        let source = r#"
            ext unsafe c fn take_owned(p_owned: *u8) -> i32;
            unsafe fn main() -> i32 {
                let p = alloc(32);
                take_owned((p));
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("double-frees provenance root")));
    }

    #[test]
    fn projected_owned_ffi_argument_marks_root_consumed() {
        let source = r#"
            struct Holder { ptr: *mut u8 }
            ext unsafe c fn take_owned(p_owned: *u8) -> i32;
            unsafe fn main() -> i32 {
                let holder: Holder = Holder { ptr: alloc(32) };
                take_owned(holder.ptr);
                free(holder.ptr);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("consumes non-owned or already-consumed value `holder`")
                || detail.contains("divergent ownership state for `holder`")
                || detail.contains("double-frees provenance root")
        }));
    }

    #[test]
    fn helper_freeing_owned_param_transfers_ownership_from_caller() {
        let source = r#"
            fn consume(p: *mut u8) -> i32 {
                free(p);
                return 0;
            }
            fn main() -> i32 {
                let p = alloc(32);
                consume(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("consumes non-owned or already-consumed value `p`")
                || detail.contains("function `main` leaks allocation")
        }));
    }

    #[test]
    fn unsafe_extern_owned_param_transfers_ownership_from_caller() {
        let source = r#"
            ext unsafe c fn take_owned(p_owned: *u8) -> i32;
            unsafe fn main() -> i32 {
                let p = alloc(32);
                take_owned(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("function `main` leaks allocation")));
    }

    #[test]
    fn grouped_return_transfers_ownership_without_local_defer() {
        let source = r#"
            fn produce() -> *mut u8 {
                let p = alloc(32);
                return (p);
            }
            fn main() -> i32 {
                let p = produce();
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("function `produce` leaks allocation")));
    }

    #[test]
    fn plain_return_transfers_ownership_without_local_defer() {
        let source = r#"
            fn produce() -> *mut u8 {
                let p = alloc(32);
                return p;
            }
            fn main() -> i32 {
                let p = produce();
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `produce` leaks allocation")
                || detail.contains(
                    "call edge `main -> produce` crosses function with potential resource escape",
                )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `produce` linear value `p` was not consumed/freed")
        }));
    }

    #[test]
    fn branch_relayed_owned_return_transfers_without_lifecycle_fallout() {
        let source = r#"
            fn produce() -> *mut u8 {
                let p = alloc(32);
                return p;
            }
            fn relay(flag: i32) -> *mut u8 {
                if flag == 0 {
                    return produce();
                }
                return produce();
            }
            fn main() -> i32 {
                let p = relay(0);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> relay` crosses function with potential resource escape",
            ) || detail.contains(
                "call edge `relay -> produce` crosses function with potential resource escape",
            )
        }));
    }

    #[test]
    fn if_expression_relayed_owned_return_transfers_without_lifecycle_fallout() {
        let source = r#"
            fn produce() -> *mut u8 {
                let p = alloc(32);
                return p;
            }
            fn relay(flag: i32) -> *mut u8 {
                return if flag == 0 { produce() } else { produce() };
            }
            fn main() -> i32 {
                let p = relay(0);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> relay` crosses function with potential resource escape",
            ) || detail.contains(
                "call edge `relay -> produce` crosses function with potential resource escape",
            )
        }));
    }

    #[test]
    fn task_handle_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.thread;
            fn worker() -> i32 {
                return 7;
            }
            fn start() -> TaskHandle {
                return spawn(worker);
            }
            fn main() -> i32 {
                let handle = start();
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> start` crosses function with potential resource escape",
            )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `start` linear value `handle` was not consumed/freed")
        }));
    }

    #[test]
    fn http_handle_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.http;
            fn open_listener() -> HttpHandle {
                return http.bind("127.0.0.1:8787");
            }
            fn main() -> i32 {
                let listener = open_listener();
                close(listener);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> open_listener` crosses function with potential resource escape",
            )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail
                .contains("function `open_listener` linear value `listener` was not consumed/freed")
        }));
    }

    #[test]
    fn process_handle_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.proc;
            fn start() -> ProcessHandle {
                let argv = proc.argv_new();
                let env = proc.env_new();
                return proc.spawn_cmd("echo", argv, env, "");
            }
            fn main() -> i32 {
                let handle = start();
                discard proc.close(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> start` crosses function with potential resource escape",
            ) || detail.contains("function `start` leaks allocation")
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `start` linear value `handle` was not consumed/freed")
                || detail.contains("function `start` linear value `argv` was not consumed/freed")
                || detail.contains("function `start` linear value `env` was not consumed/freed")
        }));
    }

    #[test]
    fn http_stream_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.http;
            fn open_stream() -> HttpStreamHandle {
                return http.post_json_stream("https://example.com", "{}");
            }
            fn main() -> i32 {
                let stream = open_stream();
                discard http.stream_close(stream);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> open_stream` crosses function with potential resource escape",
            )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `open_stream` linear value `stream` was not consumed/freed")
        }));
    }

    #[test]
    fn task_group_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.thread;
            fn start_group() -> TaskGroupHandle {
                return task.group_begin();
            }
            fn main() -> i32 {
                let group = start_group();
                discard task.group_cancel(group);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> start_group` crosses function with potential resource escape",
            )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `start_group` linear value `group` was not consumed/freed")
        }));
    }

    #[test]
    fn kv_store_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.storage;
            fn open_store() -> KvStoreHandle {
                return storage.kv_open("session.kv");
            }
            fn main() -> i32 {
                let store = open_store();
                discard storage.kv_put(store, "session:key", "value");
                discard storage.kv_close(store);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> open_store` crosses function with potential resource escape",
            )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `open_store` linear value `store` was not consumed/freed")
        }));
    }

    #[test]
    fn file_handle_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.fs;
            fn open_file() -> FileHandle {
                return fs.open("/tmp/fzy-file-handle-return");
            }
            fn main() -> i32 {
                let file = open_file();
                discard fs.write(file, "hello");
                discard fs.close(file);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> open_file` crosses function with potential resource escape",
            )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `open_file` linear value `file` was not consumed/freed")
        }));
    }

    #[test]
    fn websocket_wrapper_return_counts_as_transfer() {
        let source = r#"
            use core.http;
            fn accept_ws(conn: HttpHandle) -> WebSocketHandle {
                return http.websocket_accept(conn);
            }
            fn main() -> i32 {
                let conn = http.accept();
                let ws = accept_ws(conn);
                discard http.websocket_close(ws, 1000, "ok");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `main -> accept_ws` crosses function with potential resource escape",
            )
        }));
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `accept_ws` linear value `ws` was not consumed/freed")
                || detail
                    .contains("function `accept_ws` linear value `conn` was not consumed/freed")
        }));
    }

    #[test]
    fn return_of_consuming_helper_call_does_not_require_local_defer() {
        let source = r#"
            fn consume(p: *mut u8) -> i32 {
                free(p);
                return 0;
            }
            fn main() -> i32 {
                let p = alloc(32);
                return consume(p);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `main` leaks allocation")
                || detail.contains("consumes non-owned or already-consumed value `p`")
        }));
    }

    #[test]
    fn early_return_without_cleanup_reports_leak() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`p`")));
    }

    #[test]
    fn branch_early_return_without_cleanup_reports_leak() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                if true {
                    return 0;
                }
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("leaks allocation")
                || detail.contains("divergent ownership state for `p`")
                || detail.contains("conditionally consumed value `p`")
        }));
    }

    #[test]
    fn loop_scoped_cleanup_gap_reports_leak() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                while false {
                    free(p);
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("leaks allocation")
                || detail.contains("divergent ownership state for `p`")
                || detail.contains("conditionally consumed value `p`")
        }));
    }

    #[test]
    fn let_initializer_join_consumes_task_handle() {
        let source = r#"
            use core.thread;
            fn worker() -> i32 {
                return 7;
            }
            fn main() -> i32 {
                let handle = spawn(worker);
                let result = join(handle);
                return result;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `main` leaks allocation") && detail.contains("`handle`")
        }));
        assert!(!typed
            .linear_type_violations
            .iter()
            .any(|detail| { detail.contains("linear value `handle` was not consumed/freed") }));
    }

    #[test]
    fn binary_expression_joins_consume_task_handles() {
        let source = r#"
            use core.thread;
            fn worker() -> i32 {
                return 1;
            }
            fn main() -> i32 {
                let left = spawn(worker);
                let right = spawn(worker);
                return join(left) + join(right);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `main` leaks allocation")
                && (detail.contains("`left`") || detail.contains("`right`"))
        }));
    }

    #[test]
    fn wrapper_close_consumes_websocket_handle() {
        let source = r#"
            use core.http;

            fn close_ws(ws: WebSocketHandle) -> i32 {
                return http.websocket_close(ws, 1000, "ok");
            }

            fn main() -> i32 {
                let listener = http.bind("127.0.0.1:8787");
                defer close(listener);
                let conn = http.accept();
                let ws = http.websocket_accept(conn);
                discard close_ws(ws);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("function `main` leaks allocation") && detail.contains("`ws`")
        }));
        assert!(!typed
            .linear_type_violations
            .iter()
            .any(|detail| { detail.contains("linear value `ws` was not consumed/freed") }));
    }

    #[test]
    fn pointer_arithmetic_with_integer_typechecks() {
        let source = r#"
            fn plus1(ptr: *mut u8) -> *mut u8 {
                unsafe {
                    return ptr + 1;
                }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn tuple_pattern_partial_move_is_rejected() {
        let source = r#"
            fn main() -> i32 {
                let pair: (*mut u8, *mut u8) = (alloc(32), alloc(32));
                let (left, _) = pair;
                close(left);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| { detail.contains("performs partial move from owned aggregate") }));
    }

    #[test]
    fn nested_struct_field_partial_move_is_rejected() {
        let source = r#"
            struct Inner { ptr: *mut u8 }
            struct Outer { inner: Inner, tag: i32 }
            fn main() -> i32 {
                let outer: Outer = Outer { inner: Inner { ptr: alloc(32) }, tag: 7 };
                let ptr = outer.inner.ptr;
                close(ptr);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| { detail.contains("performs partial move from owned aggregate") }));
    }

    #[test]
    fn partial_move_assignment_from_owned_aggregate_is_rejected() {
        let source = r#"
            struct Inner { ptr: *mut u8 }
            struct Outer { inner: Inner, tag: i32 }
            fn main() -> i32 {
                let mut ptr = alloc(8);
                let outer: Outer = Outer { inner: Inner { ptr: alloc(32) }, tag: 7 };
                ptr = outer.inner.ptr;
                close(ptr);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("performs partial move assignment from owned aggregate")
        }));
    }

    #[test]
    fn struct_pattern_partial_move_is_rejected() {
        let source = r#"
            struct Pair { left: *mut u8, right: *mut u8 }
            fn main() -> i32 {
                let pair: Pair = Pair { left: alloc(32), right: alloc(32) };
                let Pair { left, right: _ } = pair;
                close(left);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| { detail.contains("performs partial move from owned aggregate") }));
    }

    #[test]
    fn compiler_generated_unsafe_sites_are_not_counted_as_reasoned() {
        let source = r#"
            unsafe fn main() -> i32 {
                unsafe {
                    return 0;
                }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.unsafe_sites > 0);
        assert_eq!(typed.unsafe_reasoned_sites, 0);
        assert!(typed
            .unsafe_contract_sites
            .iter()
            .any(|site| site.owner.as_deref() == Some("scope_root")));
    }

    #[test]
    fn documented_ffi_wrapper_call_edges_do_not_require_independent_proof() {
        let source = r#"
            ext unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;

            fn abi_touch(s: str) -> i32 {
                unsafe {
                    return host_touch(s, str.len(s));
                }
            }

            fn safe_touch(s: str) -> i32 {
                return abi_touch(s);
            }

            fn main() -> i32 {
                return safe_touch("ok");
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.unsafe_sites > 0);
        assert_eq!(typed.unsafe_reasoned_sites, 0);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("call edge `abi_touch -> host_touch` reaches unsafe code")
                || detail.contains("call edge `safe_touch -> abi_touch` reaches unsafe code")
        }));
    }

    #[test]
    fn ffi_wrapper_let_bound_unsafe_call_infers_value_type() {
        let source = r#"
            ext unsafe c fn host_touch(buf_borrowed: *u8, len: usize) -> i32;

            fn abi_touch(s: str) -> i32 {
                let code = unsafe {
                    host_touch(s, str.len(s))
                }
                return code
            }

            fn main() -> i32 {
                return abi_touch("ok")
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }

    #[test]
    fn zero_arg_ffi_import_wrapper_call_edges_do_not_require_independent_proof() {
        let source = r#"
            use core.fs;

            ext unsafe c fn host_dispatch() -> i32;

            fn abi_dispatch(raw: str) -> i32 {
                discard fs.write_file("/tmp/in.json", raw);
                return safe_dispatch();
            }

            fn safe_dispatch() -> i32 {
                return raw_dispatch();
            }

            fn raw_dispatch() -> i32 {
                unsafe {
                    return host_dispatch();
                }
            }

            fn main() -> i32 {
                return abi_dispatch("{}");
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("call edge `safe_dispatch -> raw_dispatch` reaches unsafe code")
                || detail.contains("call edge `raw_dispatch -> host_dispatch` reaches unsafe code")
        }));
    }

    #[test]
    fn non_consuming_helper_preserves_caller_ownership() {
        let source = r#"
            fn inspect(p: *mut u8) -> i32 {
                discard p;
                return 0;
            }
            fn main() -> i32 {
                let p = alloc(32);
                inspect(p);
                free(p);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("function `main` leaks allocation")));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| { detail.contains("consumes non-owned or already-consumed value `p`") }));
    }

    #[test]
    fn non_consuming_linear_param_is_not_treated_as_locally_owned() {
        let source = r#"
            fn inspect(stream: HttpStreamHandle) -> i32 {
                if http.stream_eof(stream) == 1 {
                    return 1;
                }
                discard http.stream_status(stream);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `inspect` linear value `stream` was not consumed/freed")
        }));
    }

    #[test]
    fn http_write_json_marks_connection_param_consumed() {
        let source = r#"
            fn respond(conn: HttpHandle) -> i32 {
                return http.write_json(conn, 200, "{\"ok\":true}");
            }
            fn main() -> i32 {
                let conn = http.accept();
                discard respond(conn);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `respond` linear value `conn` was not consumed/freed")
        }));
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("function `main` leaks allocation")
                && detail.contains("`conn`")));
    }

    #[test]
    fn loop_local_consumed_resource_does_not_escape_iteration_merge() {
        let source = r#"
            fn main() -> i32 {
                let mut served = 0;
                while served < 2 {
                    let conn = http.accept();
                    discard http.write_json(conn, 200, "{\"ok\":true}");
                    served = served + 1;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `conn`")
                || detail.contains("uses moved value `conn` after move/consume")
        }));
    }

    #[test]
    fn continue_after_free_marks_later_iteration_reuse_invalid() {
        let source = r#"
            fn main() -> i32 {
                let i: i32 = 0;
                let p = alloc(32);
                while i < 2 {
                    if i == 0 {
                        free(p);
                        i = i + 1;
                        continue;
                    }
                    close(p);
                    i = i + 1;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("conditionally consumed value `p`")
                || detail.contains("uses moved value `p` after move/consume")
                || detail.contains("consumes non-owned or already-consumed value `p`")
        }));
    }

    #[test]
    fn break_after_free_does_not_restore_pre_loop_ownership() {
        let source = r#"
            fn main() -> i32 {
                let p = alloc(32);
                while true {
                    free(p);
                    break;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("leaks allocation") && detail.contains("`p`")));
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("divergent ownership state for `p`")
                || detail.contains("conditionally consumed value `p`")
        }));
    }

    #[test]
    fn task_group_without_terminal_policy_is_rejected() {
        let source = r#"
            fn worker() -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let group = task.group_begin();
                task.group_spawn(group, worker);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `group` was not consumed/freed")
        }));
    }

    #[test]
    fn task_group_join_all_satisfies_terminal_policy() {
        let source = r#"
            fn worker() -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let group = task.group_begin();
                task.group_spawn(group, worker);
                task.group_join_all(group);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(!typed.linear_type_violations.iter().any(|detail| {
            detail.contains("function `main` linear value `group` was not consumed/freed")
        }));
    }

    #[test]
    fn detects_invalid_atomic_ordering_claims() {
        let source = r#"
            fn main() -> i32 {
                let v = atomic.load(1, "Release");
                discard v;
                atomic.fence("Relaxed");
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("atomic.load ordering `Release` is invalid")));
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("atomic.fence ordering `Relaxed` is invalid")));
    }

    #[test]
    fn detects_generic_borrow_across_await_call_edge() {
        let source = r#"
            fn project<T: Show>(value: &'a T) -> &'a T {
                return value;
            }
            async fn worker(v: &'a i32) -> i32 {
                await recv();
                discard project<i32>(v);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains("generic/trait-heavy with borrowed parameters across await")
        }));
    }

    #[test]
    fn detects_mutable_borrow_across_await_call_edge() {
        let source = r#"
            fn touch(value: &'a mut i32) -> i32 {
                discard value;
                return 0;
            }
            async fn worker(v: &'a mut i32) -> i32 {
                await recv();
                return touch(v);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `worker -> touch` can hold mutable borrows across await boundary",
            )
        }));
    }

    #[test]
    fn detects_borrowed_return_across_async_suspension_call_edge() {
        let source = r#"
            fn borrow(v: &'a i32) -> &'a i32 {
                return v;
            }
            async fn worker(v: &'a i32) -> i32 {
                await recv();
                let alias = borrow(v);
                discard alias;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "call edge `worker -> borrow` can propagate borrowed references across async suspension boundary",
            )
        }));
    }

    #[test]
    fn detects_inferred_local_reference_used_across_await() {
        let source = r#"
            fn borrow(v: &'a i32) -> &'a i32 {
                return v;
            }
            async fn worker(v: &'a i32) -> i32 {
                let alias = borrow(v);
                await recv();
                discard alias;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains(
                "cannot use borrowed local reference `alias` across await suspension points",
            )
        }));
    }

    #[test]
    fn detects_shared_reference_used_after_await_in_same_if_body() {
        let source = r#"
            async fn worker(v: &'a i32) -> i32 {
                if true {
                    await recv();
                    discard v;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("cannot use borrowed reference `v` across await suspension points")
        }));
    }

    #[test]
    fn detects_shared_reference_used_after_await_in_same_match_arm() {
        let source = r#"
            async fn worker(v: &'a i32) -> i32 {
                match await recv() {
                    0 => v,
                    _ => 0,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("cannot use borrowed reference `v` across await suspension points")
        }));
    }

    #[test]
    fn detects_shared_reference_used_after_await_in_loop_body() {
        let source = r#"
            async fn worker(v: &'a i32) -> i32 {
                while false {
                    await recv();
                    discard v;
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("cannot use borrowed reference `v` across await suspension points")
        }));
    }

    #[test]
    fn detects_non_async_stable_process_argv_used_after_await() {
        let source = r#"
            use core.proc;
            async fn worker() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                await recv();
                discard proc.argv_push(argv, "-lc");
                let handle = proc.spawn_cmd("/bin/sh", argv, env, "");
                discard proc.close(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains(
                "cannot use non-async-stable handle `argv` (ProcessArgv) across await suspension points",
            )
        }));
    }

    #[test]
    fn detects_non_async_stable_process_env_used_after_await() {
        let source = r#"
            use core.proc;
            async fn worker() -> i32 {
                let argv = proc.argv_new();
                let env = proc.env_new();
                await recv();
                discard proc.env_set(env, "K", "V");
                let handle = proc.spawn_cmd("/bin/sh", argv, env, "");
                discard proc.close(handle);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains(
                "cannot use non-async-stable handle `env` (ProcessEnv) across await suspension points",
            )
        }));
    }

    #[test]
    fn routes_borrowed_return_thread_boundary_failures_out_of_capability_bucket() {
        let source = r#"
            async fn worker(v: &'a i32) -> &'a i32 {
                return v;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "returns borrowed reference across thread-capable boundary; return owned/Send-safe handle instead",
            )
        }));
        assert!(typed.capability_token_violations.is_empty());
    }

    #[test]
    fn routes_mutable_reference_thread_boundary_failures_out_of_capability_bucket() {
        let source = r#"
            async fn worker(v: &'a mut i32) -> i32 {
                discard v;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains("parameter `v` requires Send/Sync-safe wrapper before thread crossing")
        }));
        assert!(typed.capability_token_violations.is_empty());
    }

    #[test]
    fn routes_shared_reference_thread_boundary_failures_out_of_capability_bucket() {
        let source = r#"
            async fn worker(v: &'a i32) -> i32 {
                discard v;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains("parameter `v` requires Send/Sync-safe wrapper before thread crossing")
        }));
        assert!(typed.capability_token_violations.is_empty());
    }

    #[test]
    fn spawn_rejects_closure_capturing_shared_borrow() {
        let source = r#"
            use core.thread;
            fn observe(v: &'a i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let shared: &'a i32 = x;
                let worker = | | observe(shared);
                let handle = spawn(worker);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "spawn captures shared borrowed reference `shared` across thread boundary",
            )
        }));
    }

    #[test]
    fn spawn_rejects_closure_capturing_mutable_borrow() {
        let source = r#"
            use core.thread;
            fn touch(v: &'a mut i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let unique: &'a mut i32 = x;
                let worker = | | touch(unique);
                let handle = spawn(worker);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "spawn captures mutable borrowed reference `unique` across thread boundary",
            )
        }));
    }

    #[test]
    fn task_group_spawn_rejects_closure_capturing_shared_borrow() {
        let source = r#"
            use core.thread;
            fn observe(v: &'a i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let group = task.group_begin();
                let x: i32 = 1;
                let shared: &'a i32 = x;
                let worker = | | observe(shared);
                discard task.group_spawn(group, worker);
                discard task.group_join_all(group);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "task.group_spawn captures shared borrowed reference `shared` across thread boundary",
            )
        }));
    }

    #[test]
    fn spawn_ctx_rejects_closure_capturing_shared_borrow() {
        let source = r#"
            use core.thread;
            fn observe(v: &'a i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let shared: &'a i32 = x;
                let worker = | | observe(shared);
                let handle = spawn_ctx(worker, 7);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "spawn_ctx captures shared borrowed reference `shared` across thread boundary",
            )
        }));
    }

    #[test]
    fn thread_spawn_ctx_rejects_closure_capturing_shared_borrow() {
        let source = r#"
            use core.thread;
            fn observe(v: &'a i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let shared: &'a i32 = x;
                let worker = | | observe(shared);
                let handle = thread.spawn_ctx(worker, 7);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "thread.spawn_ctx captures shared borrowed reference `shared` across thread boundary",
            )
        }));
    }

    #[test]
    fn task_parallel_map_rejects_closure_capturing_shared_borrow() {
        let source = r#"
            use core.thread;
            fn observe(v: &'a i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let group = task.group_begin();
                let x: i32 = 1;
                let shared: &'a i32 = x;
                let worker = | | observe(shared);
                discard task.parallel_map(group, worker);
                discard task.group_join_all(group);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "task.parallel_map captures shared borrowed reference `shared` across thread boundary",
            )
        }));
    }

    #[test]
    fn spawn_allows_closure_capturing_owned_values() {
        let source = r#"
            use core.thread;
            fn main() -> i32 {
                let x: i32 = 1;
                let worker = | | x;
                let handle = spawn(worker);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed.thread_boundary_violations.iter().any(|detail| {
                detail.contains("captures shared borrowed reference")
                    || detail.contains("captures mutable borrowed reference")
            }),
            "{:?}",
            typed.thread_boundary_violations
        );
    }

    #[test]
    fn spawn_rejects_closure_capturing_non_send_safe_http_handle() {
        let source = r#"
            use core.http;
            use core.thread;
            fn main() -> i32 {
                let conn = http.accept();
                let worker = | | close(conn);
                let handle = spawn(worker);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "spawn captures non-Send-safe handle `conn` (HttpHandle) across thread boundary",
            )
        }));
    }

    #[test]
    fn spawn_rejects_closure_capturing_non_send_safe_file_handle() {
        let source = r#"
            use core.fs;
            use core.thread;
            fn main() -> i32 {
                let file = fs.open("/tmp/fzy-non-send-safe-file.txt");
                let worker = | | fs.close(file);
                let handle = spawn(worker);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.thread_boundary_violations.iter().any(|detail| {
            detail.contains(
                "spawn captures non-Send-safe handle `file` (FileHandle) across thread boundary",
            )
        }));
    }

    #[test]
    fn spawn_allows_closure_capturing_send_safe_json_handle() {
        let source = r#"
            use core.thread;
            fn main() -> i32 {
                let payload = json.parse("{}");
                let worker = | | json.has(payload, "ok");
                let handle = spawn(worker);
                return join(handle);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .thread_boundary_violations
                .iter()
                .any(|detail| detail.contains("captures non-Send-safe handle `payload`")),
            "{:?}",
            typed.thread_boundary_violations
        );
    }

    #[test]
    fn detects_mutable_and_shared_aliasing_across_ref_params() {
        let source = r#"
            fn touch(a: &'a mut i32, b: &'a i32) -> i32 {
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                touch(x, x);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("aliases mutable and shared borrows for `x`")));
    }

    #[test]
    fn mutable_borrow_then_shared_local_reborrow_is_rejected() {
        let source = r#"
            fn main() -> i32 {
                let x: i32 = 1;
                let unique: &'a mut i32 = x;
                let shared: &'a i32 = x;
                discard unique;
                discard shared;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "creates shared borrow `shared` from owner `x` while mutable borrowed reference `unique` is still live",
            )
        }));
    }

    #[test]
    fn shared_borrow_then_mutable_local_reborrow_is_rejected() {
        let source = r#"
            fn main() -> i32 {
                let x: i32 = 1;
                let shared: &'a i32 = x;
                let unique: &'a mut i32 = x;
                discard shared;
                discard unique;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "creates mutable borrow `unique` from owner `x` while shared borrowed reference `shared` is still live",
            )
        }));
    }

    #[test]
    fn mutable_borrow_then_shared_call_reborrow_is_rejected() {
        let source = r#"
            fn inspect(v: &'a i32) -> i32 {
                discard v;
                return 0;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let unique: &'a mut i32 = x;
                discard inspect(x);
                discard unique;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "creates shared borrow of owner `x` via `inspect(x)` while mutable borrowed reference `unique` is still live",
            )
        }));
    }

    #[test]
    fn mutable_borrow_then_direct_owner_access_is_rejected() {
        let source = r#"
            fn main() -> i32 {
                let x: i32 = 1;
                let unique: &'a mut i32 = x;
                discard x;
                discard unique;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "accesses owner `x` via `x` while mutable borrowed reference `unique` is still live",
            )
        }));
    }

    #[test]
    fn mutable_borrow_then_plain_owner_call_access_is_rejected() {
        let source = r#"
            fn inspect_value(v: i32) -> i32 {
                return v;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let unique: &'a mut i32 = x;
                discard inspect_value(x);
                discard unique;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "accesses owner `x` via `inspect_value(x)` while mutable borrowed reference `unique` is still live",
            )
        }));
    }

    #[test]
    fn owner_access_after_mutable_borrow_last_use_is_allowed() {
        let source = r#"
            fn inspect_value(v: i32) -> i32 {
                return v;
            }
            fn main() -> i32 {
                let x: i32 = 1;
                let unique: &'a mut i32 = x;
                discard unique;
                discard inspect_value(x);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(!typed.ownership_violations.iter().any(|detail| {
            detail.contains("accesses owner `x`")
                || detail.contains("mutable borrowed reference `unique`")
        }));
    }

    #[test]
    fn detects_mismatched_reference_lifetime_through_returned_call() {
        let source = r#"
            fn borrow(v: &'b i32) -> &'b i32 {
                return v;
            }
            fn relay(a: &'a i32, b: &'b i32) -> &'a i32 {
                return borrow(b);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("returns reference expression with mismatched lifetime")
        }));
    }

    #[test]
    fn assignment_shaped_reference_flow_still_validates_return_lifetimes() {
        let source = r#"
            fn borrow_a(v: &'a i32) -> &'a i32 {
                return v;
            }
            fn borrow_b(v: &'b i32) -> &'b i32 {
                return v;
            }
            fn relay(a: &'a i32, b: &'b i32) -> &'a i32 {
                let out = borrow_a(a);
                if true {
                    out = borrow_b(b);
                }
                return out;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("returns reference expression with mismatched lifetime")
                || detail.contains(
                    "returns reference expression without a statically traced lifetime source",
                )
        }));
    }

    #[test]
    fn if_expression_reference_flow_still_validates_return_lifetimes() {
        let source = r#"
            fn relay(flag: i32, a: &'a i32, b: &'b i32) -> &'a i32 {
                return if flag == 0 { a } else { b };
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.reference_lifetime_violations.iter().any(|detail| {
            detail.contains("returns reference expression with mismatched lifetime")
                || detail.contains(
                    "returns reference expression without a statically traced lifetime source",
                )
        }));
    }

    #[test]
    fn same_lifetime_reference_relay_stays_clean() {
        let source = r#"
            fn borrow(v: &'a i32) -> &'a i32 {
                return v;
            }
            fn relay(a: &'a i32) -> &'a i32 {
                return borrow(a);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.reference_lifetime_violations.is_empty());
    }

    #[test]
    fn borrow_then_free_is_rejected_while_alias_is_still_live() {
        let source = r#"
            fn borrow(v: &'a *mut u8) -> &'a *mut u8 {
                return v;
            }
            fn main() -> i32 {
                let p = alloc(32);
                let alias: &'a *mut u8 = borrow(p);
                free(p);
                discard alias;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "consumes owner `p` via `free(p)` while borrowed reference `alias` is still live",
            )
        }));
        assert!(!typed
            .linear_type_violations
            .iter()
            .any(|detail| { detail.contains("linear value `alias` was not consumed/freed") }));
    }

    #[test]
    fn borrow_then_move_is_rejected_while_alias_is_still_live() {
        let source = r#"
            fn borrow(v: &'a *mut u8) -> &'a *mut u8 {
                return v;
            }
            fn main() -> i32 {
                let p = alloc(32);
                let alias: &'a *mut u8 = borrow(p);
                let y = p;
                discard alias;
                free(y);
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert!(typed.ownership_violations.iter().any(|detail| {
            detail.contains(
                "consumes owner `p` via `let y = p` while borrowed reference `alias` is still live",
            )
        }));
        assert!(!typed
            .linear_type_violations
            .iter()
            .any(|detail| { detail.contains("linear value `alias` was not consumed/freed") }));
    }

    #[test]
    fn enum_pattern_partial_move_is_rejected() {
        let source = r#"
            enum Pairish { Both(*mut u8, *mut u8), Empty }
            fn main() -> i32 {
                let pair = Pairish::Both(alloc(32), alloc(32));
                match pair {
                    Pairish::Both(left, _) => close(left),
                    _ => return 0,
                }
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains("performs partial move from owned aggregate")));
    }

    #[test]
    fn break_continue_outside_loop_reports_type_error() {
        let source = r#"
            fn main() -> i32 {
                break;
                continue;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("`break` is only valid inside loop bodies")));
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("`continue` is only valid inside loop bodies")));
    }

    #[test]
    fn for_in_range_typechecks() {
        let source = r#"
            fn main() -> i32 {
                let sum: i32 = 0;
                for i in 0..5 {
                    discard i;
                }
                return sum;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn logical_short_circuit_skips_rhs_side_effects() {
        let source = r#"
            fn main() -> i32 {
                if false && (1 / 0 == 1) {
                    return 1;
                }
                if true || (1 / 0 == 1) {
                    return 0;
                }
                return 2;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(0));
    }

    #[test]
    fn unit_return_allowed_for_void_functions() {
        let source = r#"
            fn main() -> void {
                return;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn function_type_values_support_higher_order_calls() {
        let source = r#"
            fn id(v: i32) -> i32 {
                return v;
            }
            fn apply(f: fn(i32) -> i32, value: i32) -> i32 {
                return f(value);
            }
            fn main() -> i32 {
                return apply(id, 7);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn execution_space_call_rules_are_enforced() {
        let source = r#"
            kernel fn launch() -> void {}
            fn main() -> i32 {
                launch()
                return 0
            }
        "#;
        let module = parser::parse(source, "gpu_rules").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("host function `main` cannot call kernel function `launch` directly"))
        );
    }

    #[test]
    fn host_gpu_capability_is_inferred() {
        let source = r#"
            host fn main() -> i32 {
                discard gpu.device_count();
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_caps").expect("parse");
        let typed = lower(&module);
        let requirement = typed
            .function_capability_requirements
            .iter()
            .find(|entry| entry.function == "main")
            .expect("main capability requirement");
        assert!(requirement.required.iter().any(|cap| cap == "gpu"));
    }

    #[test]
    fn gpu_buffers_are_linear_resources() {
        let source = r#"
            use core.gpu;
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let buf = gpu.alloc_f32(dev, 16);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_linear").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("linear value `buf` was not consumed/freed"))
                || typed
                    .ownership_violations
                    .iter()
                    .any(|detail| detail.contains("linear value `buf` was not consumed/freed"))
                || typed
                    .linear_type_violations
                    .iter()
                    .any(|detail| detail.contains("linear value `buf` was not consumed/freed"))
        );
    }

    #[test]
    fn host_cannot_call_device_gpu_intrinsics() {
        let source = r#"
            host fn main() -> i32 {
                return gpu.global_id_x();
            }
        "#;
        let module = parser::parse(source, "gpu_host_intrinsic").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains(
                "host function `main` cannot call device-only GPU intrinsic `gpu.global_id_x`"
            )));
    }

    #[test]
    fn device_functions_reject_host_only_gpu_buffer_types() {
        let source = r#"
            device fn bad(buffer: GpuBuffer<f32>) -> i32 {
                discard buffer;
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_device_types").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("device function `bad` parameter `buffer` uses unsupported device type `GpuBuffer<f32>`")));
    }

    #[test]
    fn gpu_slice_index_assignment_typechecks_in_kernel() {
        let source = r#"
            kernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = input[i];
                }
            }
        "#;
        let module = parser::parse(source, "gpu_index_assign").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn gpu_launch_event_must_be_consumed() {
        let source = r#"
            use core.gpu;
            use core.thread;
            kernel fn noop(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = input[i];
                }
            }
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let input = gpu.alloc_f32(dev, 8);
                defer gpu.free(input);
                let output = gpu.alloc_f32(dev, 8);
                defer gpu.free(output);
                let input_view = gpu.slice(input, 0, 8);
                let output_view = gpu.slice(output, 0, 8);
                let event = gpu.launch3(noop, 1, 64, input_view, output_view, 8);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_launch_event").expect("parse");
        let typed = lower(&module);
        assert!(
            typed
                .type_error_details
                .iter()
                .any(|detail| detail.contains("linear value `event` was not consumed/freed"))
                || typed
                    .linear_type_violations
                    .iter()
                    .any(|detail| detail.contains("linear value `event` was not consumed/freed"))
        );
    }

    #[test]
    fn gpu_launch_event_wait_passes() {
        let source = r#"
            use core.gpu;
            use core.thread;
            kernel fn noop(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = input[i];
                }
            }
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let input = gpu.alloc_f32(dev, 8);
                defer gpu.free(input);
                let output = gpu.alloc_f32(dev, 8);
                defer gpu.free(output);
                let input_view = gpu.slice(input, 0, 8);
                let output_view = gpu.slice(output, 0, 8);
                let event = gpu.launch3(noop, 1, 64, input_view, output_view, 8);
                gpu.wait(event);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_launch_wait").expect("parse");
        let typed = lower(&module);
        assert_eq!(
            typed.type_errors, 0,
            "type errors: {:?}; ownership: {:?}; linear: {:?}",
            typed.type_error_details, typed.ownership_violations, typed.linear_type_violations
        );
        assert!(typed
            .linear_type_violations
            .iter()
            .all(|detail| !detail.contains("linear value `event`")));
    }

    #[test]
    fn gpu_launch_event_wait_async_passes() {
        let source = r#"
            use core.gpu;
            kernel fn noop(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = input[i];
                }
            }
            async host fn flush(event: GpuEvent) -> void {
                await gpu.wait_async(event);
            }
            async host fn main() -> i32 {
                let dev = gpu.default_device();
                let input = gpu.alloc_f32(dev, 8);
                defer gpu.free(input);
                let output = gpu.alloc_f32(dev, 8);
                defer gpu.free(output);
                let input_view = gpu.slice(input, 0, 8);
                let output_view = gpu.slice(output, 0, 8);
                let event = gpu.launch3(noop, 1, 64, input_view, output_view, 8);
                await flush(event);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_launch_wait_async").expect("parse");
        let typed = lower(&module);
        assert_eq!(
            typed.type_errors, 0,
            "type errors: {:?}; ownership: {:?}; linear: {:?}",
            typed.type_error_details, typed.ownership_violations, typed.linear_type_violations
        );
        assert!(typed
            .linear_type_violations
            .iter()
            .all(|detail| !detail.contains("linear value `event`")));
    }

    #[test]
    fn gpu_wait_status_is_usable_from_sync_and_async_code() {
        let source = r#"
            use core.gpu;
            kernel fn noop(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = input[i];
                }
            }
            async host fn flush(event: GpuEvent) -> i32 {
                return await gpu.wait_async(event);
            }
            async host fn main() -> i32 {
                let dev = gpu.default_device();
                let input = gpu.alloc_f32(dev, 8);
                defer gpu.free(input);
                let output = gpu.alloc_f32(dev, 8);
                defer gpu.free(output);
                let event = gpu.launch3(noop, 1, 64, gpu.slice(input, 0, 8), gpu.slice(output, 0, 8), 8);
                let direct = gpu.wait(event);
                if direct != 0 {
                    return direct;
                }
                let event2 = gpu.launch3(noop, 1, 64, gpu.slice(input, 0, 8), gpu.slice(output, 0, 8), 8);
                return await flush(event2);
            }
        "#;
        let module = parser::parse(source, "gpu_wait_status").expect("parse");
        let typed = lower(&module);
        assert_eq!(
            typed.type_errors, 0,
            "type errors: {:?}; ownership: {:?}; linear: {:?}",
            typed.type_error_details, typed.ownership_violations, typed.linear_type_violations
        );
    }

    #[test]
    fn gpu_wait_async_requires_async_context() {
        let source = r#"
            use core.gpu;
            kernel fn noop(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = input[i];
                }
            }
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let input = gpu.alloc_f32(dev, 8);
                defer gpu.free(input);
                let output = gpu.alloc_f32(dev, 8);
                defer gpu.free(output);
                let input_view = gpu.slice(input, 0, 8);
                let output_view = gpu.slice(output, 0, 8);
                let event = gpu.launch3(noop, 1, 64, input_view, output_view, 8);
                await gpu.wait_async(event);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_wait_async_async_ctx").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("uses `await` but is not declared async")));
    }

    #[test]
    fn gpu_slice_live_view_blocks_free_of_owner() {
        let source = r#"
            use core.gpu;
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let buffer = gpu.alloc_f32(dev, 8);
                let view = gpu.slice(buffer, 0, 4);
                gpu.free(buffer);
                discard view;
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_slice_live_view_free").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains(
                "consumes owner `buffer` via `gpu.free(buffer)` while borrowed reference `view` is still live"
            )));
    }

    #[test]
    fn gpu_slice_live_view_blocks_owner_access() {
        let source = r#"
            use core.gpu;
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let buffer = gpu.alloc_f32(dev, 8);
                let view = gpu.slice(buffer, 0, 4);
                let downloaded = gpu.download_f32(buffer);
                discard downloaded;
                discard view;
                gpu.free(buffer);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_slice_live_view_owner_access").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains(
                "accesses owner `buffer` via `let downloaded = gpu.download_f32(buffer)` while mutable borrowed reference `view` is still live"
            )));
    }

    #[test]
    fn gpu_competing_live_slices_from_same_buffer_are_rejected() {
        let source = r#"
            use core.gpu;
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let buffer = gpu.alloc_f32(dev, 8);
                let left = gpu.slice(buffer, 0, 4);
                let right = gpu.slice(buffer, 4, 4);
                discard left;
                discard right;
                gpu.free(buffer);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_competing_slices").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains(
                "creates mutable borrow `right` from owner `buffer` while mutable borrowed reference `left` is still live"
            )));
    }

    #[test]
    fn gpu_launch_rejects_aliased_slice_parameters() {
        let source = r#"
            use core.gpu;
            kernel fn saxpy(input: GpuSlice<f32>, output: GpuSlice<f32>) -> void {
                let i = gpu.global_id_x();
                output[i] = input[i];
            }
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let buffer = gpu.alloc_f32(dev, 8);
                let view = gpu.slice(buffer, 0, 8);
                let event = gpu.launch2(saxpy, 1, 8, view, view);
                gpu.wait(event);
                discard view;
                gpu.free(buffer);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_launch_alias").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains(
                "host function `main` launch `saxpy` via `gpu.launch2` aliases GpuSlice parameters `input` and `output` through owner `buffer`"
            )));
    }

    #[test]
    fn gpu_launch_allows_aliased_readonly_slice_parameters() {
        let source = r#"
            use core.gpu;
            kernel fn saxpy(input_a: GpuSlice<f32>, input_b: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = input_a[i] + input_b[i];
                }
            }
            host fn main() -> i32 {
                let dev = gpu.default_device();
                let input = gpu.alloc_f32(dev, 8);
                let output = gpu.alloc_f32(dev, 8);
                let input_view = gpu.slice(input, 0, 8);
                let output_view = gpu.slice(output, 0, 8);
                let event = gpu.launch4(saxpy, 1, 8, input_view, input_view, output_view, 8);
                gpu.wait(event);
                discard input_view;
                discard output_view;
                gpu.free(input);
                gpu.free(output);
                return 0;
            }
        "#;
        let module = parser::parse(source, "gpu_launch_readonly_alias").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("aliases GpuSlice parameters")),
            "ownership violations: {:?}",
            typed.ownership_violations
        );
    }

    #[test]
    fn kernel_param_outside_launch_abi_is_rejected() {
        let source = r#"
            struct Pair { x: f32, y: f32 }
            kernel fn blend(input: GpuSlice<f32>, coeff: Pair, output: GpuSlice<f32>) -> void {
                let i = gpu.global_id_x();
                output[i] = input[i] + coeff.x + coeff.y;
            }
        "#;
        let module = parser::parse(source, "gpu_launch_abi_shape").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains(
                "kernel function `blend` parameter `coeff` uses type `Pair` that is not yet supported by the stable GPU launch ABI"
            )));
    }

    #[test]
    fn kernel_barrier_in_divergent_branch_is_rejected() {
        let source = r#"
            use core.gpu;
            kernel fn sync_then_store(output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    gpu.barrier();
                    output[i] = 1.0;
                }
            }
        "#;
        let module = parser::parse(source, "gpu_barrier_branch").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains(
                "kernel function `sync_then_store` cannot use `gpu.barrier` inside divergent control flow"
            )));
    }

    #[test]
    fn kernel_barrier_helper_in_divergent_branch_is_rejected() {
        let source = r#"
            use core.gpu;
            device fn sync_point() -> void {
                gpu.barrier();
            }
            kernel fn sync_then_store(output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    sync_point();
                    output[i] = 1.0;
                }
            }
        "#;
        let module = parser::parse(source, "gpu_barrier_helper_branch").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .ownership_violations
            .iter()
            .any(|detail| detail.contains(
                "kernel function `sync_then_store` cannot call barrier-carrying function `sync_point` inside divergent control flow"
            )));
    }

    #[test]
    fn kernel_barrier_in_straight_line_code_passes() {
        let source = r#"
            use core.gpu;
            kernel fn sync_then_store(output: GpuSlice<f32>, n: i32) -> void {
                gpu.barrier();
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = 1.0;
                }
            }
        "#;
        let module = parser::parse(source, "gpu_barrier_straight_line").expect("parse");
        let typed = lower(&module);
        assert!(
            !typed
                .ownership_violations
                .iter()
                .any(|detail| detail.contains("gpu.barrier")),
            "ownership violations: {:?}",
            typed.ownership_violations
        );
    }

    #[test]
    fn match_guard_can_reference_variant_payload_binding() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let source = Maybe::Some(9);
                match source {
                    Maybe::Some(v) if v > 4 => return v,
                    _ => return 0,
                }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn match_or_pattern_requires_identical_binding_shapes() {
        let source = r#"
            enum Maybe { Some(i32), Also(i32), None }
            fn main() -> i32 {
                let source = Maybe::Some(9);
                match source {
                    Maybe::Some(v) | Maybe::Also(w) => return 1,
                    _ => return 0,
                }
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed.type_error_details.iter().any(|detail| {
            detail.contains("or-pattern alternatives must bind identical names and types")
        }));
    }

    #[test]
    fn closure_values_capture_outer_bindings_and_typecheck() {
        let source = r#"
            fn main() -> i32 {
                let base: i32 = 5;
                let add = |x: i32| x + base;
                return add(2);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn closure_explicit_return_type_mismatch_is_reported() {
        let source = r#"
            fn main() -> i32 {
                let f = |x: i32| -> bool x + 1;
                return 0;
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("closure return type mismatch")));
    }

    #[test]
    fn non_callable_values_fail_callability_checks() {
        let source = r#"
            fn main() -> i32 {
                let value: i32 = 1;
                return value(2);
            }
        "#;
        let module = parser::parse(source, "main").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("is not callable")));
    }

    #[test]
    fn primitive_parity_fixture_typechecks_and_interprets() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/primitive_parity/main.fzy"),
        )
        .expect("primitive parity fixture should be readable");
        let module = parser::parse(&source, "primitive_parity").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(27));
    }

    #[test]
    fn detects_unsafe_call_outside_unsafe_context() {
        let source = r#"
            unsafe fn danger(v: i32) -> i32 {
                return v + 1;
            }
            fn main() -> i32 {
                return danger(1);
            }
        "#;
        let module = parser::parse(source, "unsafe_ctx").expect("parse");
        let typed = lower(&module);
        assert!(typed
            .unsafe_context_violations
            .iter()
            .any(|detail| detail.contains("outside `unsafe` context")));
    }

    #[test]
    fn flags_non_exhaustive_enum_match_without_catchall() {
        let source = r#"
            enum State { Init, Ready, Done }
            fn main() -> i32 {
                let s = State::Init;
                match s {
                    State::Init => return 1,
                    State::Ready => return 2,
                }
            }
        "#;
        let module = parser::parse(source, "exhaustive").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("non-exhaustive match for enum `State`")));
    }

    #[test]
    fn generic_struct_initialization_inferrs_type_arguments() {
        let source = r#"
            struct Box<T> { value: T }
            fn main() -> i32 {
                let b = Box { value: 7 };
                return b.value;
            }
        "#;
        let module = parser::parse(source, "generic_struct").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        assert_eq!(typed.entry_return_const_i32, Some(7));
    }

    #[test]
    fn await_requires_future_type_surface() {
        let source = r#"
            fn consume(x: Future<i32>) -> i32 {
                return await x;
            }
            fn bad(x: i32) -> i32 {
                return await x;
            }
        "#;
        let module = parser::parse(source, "await_future").expect("parse");
        let typed = lower(&module);
        assert!(typed.type_errors > 0);
        assert!(typed
            .type_error_details
            .iter()
            .any(|detail| detail.contains("await expects `Future<T>`")));
    }

    #[test]
    fn map_set_deque_ring_and_domain_types_typecheck() {
        let source = r#"
            fn main(
                bi: BigInt,
                bu: BigUint,
                id: Uuid,
                d128: Decimal128,
                m: Map<str, i32>,
                s: Set<str>,
                d: Deque<i32>,
                r: Ring<i32>,
                obj: dyn Error,
                p: Path,
                pb: PathBuf,
                u: Url,
                sa: SocketAddr,
                dur: Duration,
                inst: Instant,
                dec: Decimal,
                dt: DateTimeTz,
                es: ExitStatus
            ) -> i32 {
                discard bi; discard bu; discard id; discard d128;
                discard m; discard s; discard d; discard r; discard obj;
                discard p; discard pb; discard u; discard sa; discard dur;
                discard inst; discard dec; discard dt; discard es;
                return 0;
            }
        "#;
        let module = parser::parse(source, "domain_types").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn type_alias_and_newtype_resolve_in_function_signatures() {
        let source = r#"
            type UserId = i32;
            newtype SessionId(UserId);
            fn echo(v: UserId) -> UserId {
                return v;
            }
            fn main(v: SessionId) -> i32 {
                discard v;
                discard echo(7);
                return 0;
            }
        "#;
        let module = parser::parse(source, "aliases").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn enum_struct_variant_payload_typechecks_and_binds() {
        let source = r#"
            enum Message {
                Data { id: i32, body: str },
                Empty,
            }
            fn main() -> i32 {
                let msg = Message::Data { id: 41, body: "ok" };
                match msg {
                    Message::Data { id, body } => return id + str.len(body),
                    Message::Empty => return 0,
                }
            }
        "#;
        let module = parser::parse(source, "enum_struct_variant").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn rpc_declarations_lower_as_extern_rpc_functions() {
        let source = r#"
            rpc Ping(req: str, count: i32) -> str;
            rpc Pong(str) -> i32;
        "#;
        let module = parser::parse(source, "rpc").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
        let mut rpc_functions = typed
            .typed_functions
            .iter()
            .filter(|function| {
                function.is_extern && function.abi.as_deref().is_some_and(|abi| abi == "rpc")
            })
            .collect::<Vec<_>>();
        rpc_functions.sort_by(|left, right| left.name.cmp(&right.name));
        assert_eq!(rpc_functions.len(), 2);
        assert_eq!(rpc_functions[0].name, "Ping");
        assert_eq!(rpc_functions[0].params[0].name, "req");
        assert_eq!(rpc_functions[0].params[1].name, "count");
        assert_eq!(rpc_functions[0].return_type.to_string(), "str");
        assert_eq!(rpc_functions[1].name, "Pong");
        assert_eq!(rpc_functions[1].params[0].name, "arg0");
        assert_eq!(rpc_functions[1].return_type.to_string(), "i32");
    }

    #[test]
    fn rpc_calls_typecheck_against_declared_payload_shapes() {
        let source = r#"
            rpc Ping(req: str, count: i32) -> i32;
            fn main() -> i32 {
                return Ping("ok", 2);
            }
        "#;
        let module = parser::parse(source, "rpc").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0);
    }

    #[test]
    fn lower_recovered_module_reports_type_errors_without_panicking() {
        let source = "fn main() -> i32 {\n    return login()\n}\n";
        let module = parser::parse(source, "main").expect("parse");
        let lowered = std::panic::catch_unwind(|| lower(&module));
        assert!(
            lowered.is_ok(),
            "HIR lowering should not panic on unresolved call"
        );
        let typed = lowered.expect("lowering should return typed module");
        assert!(typed.type_errors > 0, "lowering should surface type errors");
    }

    #[test]
    fn raw_pointer_index_assign_typechecks() {
        let source = "const N: usize = 1\n#[ffi_panic(abort)]\npubext c fn poke(buf_out: *f32, buf_len: usize) -> i32 {\n    discard N\n    discard buf_len\n    buf_out[0] = 1.0f32\n    return 0\n}\n";
        let module = parser::parse(source, "ptrwrite").expect("parse");
        let typed = lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
    }
}
