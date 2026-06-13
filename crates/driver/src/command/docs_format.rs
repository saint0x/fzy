fn render_doc_artifacts(format: Format, artifacts: DocArtifacts) -> String {
    match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", artifacts.mode),
            ("format", artifacts.output_format),
            ("items", artifacts.item_count.to_string()),
            (
                "out",
                artifacts
                    .output_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<stdout>".to_string()),
            ),
            (
                "reference",
                artifacts
                    .reference_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
            ),
        ]),
        Format::Json => serde_json::json!({
            "status": "ok",
            "mode": artifacts.mode,
            "format": artifacts.output_format,
            "items": artifacts.item_count,
            "outputPath": artifacts.output_path.map(|p| p.display().to_string()),
            "referencePath": artifacts.reference_path.map(|p| p.display().to_string()),
            "rendered": artifacts.rendered,
        })
        .to_string(),
    }
}

fn surface_always_available_groups() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "controlFlow",
            vec![
                "spawn",
                "spawn_ctx",
                "join",
                "yield",
                "checkpoint",
                "timeout",
                "cancel",
                "pulse",
            ],
        ),
        (
            "string",
            vec![
                "str.concat",
                "str.from_i32",
                "str.from_bool",
                "str.len",
                "str.slice",
                "str.trim",
                "str.upper_ascii",
                "str.lower_ascii",
            ],
        ),
        (
            "data",
            vec![
                "json.object",
                "json.array",
                "json.parse",
                "json.get_str",
                "list.new",
                "list.push",
                "map.new",
                "map.set",
            ],
        ),
        (
            "hostIntrinsic",
            vec![
                "env.get",
                "proc.argv_count",
                "proc.argv_get",
                "term.read_line",
                "term.write",
                "term.write_err",
                "route.match",
                "route.write_404",
                "route.write_405",
            ],
        ),
    ]
}

fn surface_core_modules() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("text", "stdlib facade", "no explicit capability"),
        ("io", "stdlib facade", "no explicit capability"),
        ("path", "stdlib facade", "no explicit capability"),
        ("concurrency", "stdlib facade", "no explicit capability"),
        (
            "process",
            "stdlib facade over `proc.*`",
            "no explicit capability",
        ),
        (
            "term",
            "stdlib facade over `term.*`",
            "no explicit capability",
        ),
        ("gpu", "stdlib facade", "implies `gpu`"),
        ("thread", "stdlib facade", "implies `thread`"),
        ("log", "stdlib facade", "implies `log`"),
        ("http", "stdlib facade", "implies `http`"),
        ("security", "stdlib facade", "implies `rng`"),
        ("result", "stdlib facade", "no explicit capability"),
        (
            "env",
            "builtin namespace marker only",
            "always available as `env.*`",
        ),
        (
            "str",
            "builtin namespace marker only",
            "always available as `str.*`",
        ),
    ]
}

fn surface_capabilities() -> Vec<&'static str> {
    vec![
        "time", "rng", "fs", "http", "proc", "mem", "thread", "log", "error", "gpu",
    ]
}

fn render_surface_inspection(format: Format) -> String {
    let groups = surface_always_available_groups();
    let modules = surface_core_modules();
    let capabilities = surface_capabilities();
    match format {
        Format::Text => {
            let mut lines = vec![
                "status: ok".to_string(),
                "mode: inspect-surface".to_string(),
                "summary: builtins are always callable by namespace; `use core.*` imports facades and may imply capabilities".to_string(),
                "always_available:".to_string(),
            ];
            for (group, names) in groups {
                lines.push(format!("  {group}: {}", names.join(", ")));
            }
            lines.push("core_modules:".to_string());
            for (name, kind, behavior) in modules {
                lines.push(format!("  {name}: {kind}; {behavior}"));
            }
            lines.push(format!(
                "capability_gated: {}",
                capabilities.join(", ")
            ));
            lines.push("notes: `env.*`, `str.*`, `json.*`, `list.*`, `map.*`, and `route.*` are builtin namespaces; do not import them as ordinary modules".to_string());
            lines.join("\n")
        }
        Format::Json => serde_json::json!({
            "status": "ok",
            "mode": "inspect-surface",
            "summary": "Builtins are always callable by namespace. `use core.*` imports stdlib facades and may imply capability contracts.",
            "alwaysAvailable": groups.into_iter().map(|(group, names)| {
                serde_json::json!({
                    "group": group,
                    "names": names,
                })
            }).collect::<Vec<_>>(),
            "coreModules": modules.into_iter().map(|(name, kind, behavior)| {
                serde_json::json!({
                    "name": name,
                    "kind": kind,
                    "behavior": behavior,
                })
            }).collect::<Vec<_>>(),
            "capabilityGated": capabilities,
            "notes": [
                "`env.*`, `str.*`, `json.*`, `list.*`, `map.*`, and `route.*` are builtin namespaces.",
                "`use core.env;` and `use core.str;` are markers for the builtin namespaces rather than ordinary imported modules.",
            ],
        })
        .to_string(),
    }
}

fn inspect_stdlib_command(module: &str, format: Format) -> Result<String> {
    let Some(source) = embedded_core_stdlib_module_source(module) else {
        let available = surface_core_modules()
            .into_iter()
            .map(|(name, _, _)| name)
            .filter(|name| embedded_core_stdlib_module_source(name).is_some())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("unknown embedded core stdlib module `{module}` (available: {available})");
    };
    let parsed = parser::parse(source, module)
        .map_err(|diagnostics| anyhow!("{}", render_diagnostics_text(&diagnostics)))?;
    let line_count = source.lines().count();
    let source_path = format!("<embedded-core-stdlib:{module}>");
    match format {
        Format::Text => {
            let mut out = render_text_fields(&[
                ("status", "ok".to_string()),
                ("mode", "inspect-stdlib".to_string()),
                ("module", module.to_string()),
                ("source_path", source_path),
                ("lines", line_count.to_string()),
                ("nodes", parsed.items.len().to_string()),
                ("parse", "ok".to_string()),
            ]);
            out.push_str("\nsource:\n");
            out.push_str(source);
            Ok(out)
        }
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "inspect-stdlib",
            "module": module,
            "sourcePath": source_path,
            "lines": line_count,
            "nodes": parsed.items.len(),
            "parse": "ok",
            "source": source,
        })
        .to_string()),
    }
}

fn inspect_artifacts_command(
    path: &Path,
    release: bool,
    backend_override: Option<&str>,
    format: Format,
) -> Result<String> {
    let profile = if release {
        BuildProfile::Release
    } else {
        BuildProfile::Dev
    };
    let resolved = resolve_source(path)?;
    let native = compile_file_with_backend_with_root_guidance(path, profile, backend_override)?;
    let interop = if project_has_c_exports(path)? {
        let library =
            compile_library_with_backend_with_root_guidance(path, profile, backend_override)?;
        let headers = generate_c_headers(path, None)?;
        Some(finalize_build_interop_artifacts(path, &library, headers)?)
    } else {
        None
    };

    match format {
        Format::Text => {
            let mut fields = vec![
                ("status", "ok".to_string()),
                ("mode", "inspect-artifacts".to_string()),
                ("source", resolved.source_path.display().to_string()),
                ("project_root", resolved.project_root.display().to_string()),
                ("profile", if release { "release" } else { "dev" }.to_string()),
                (
                    "native_output",
                    native
                        .output
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ),
            ];
            if let Some(interop) = interop {
                fields.push((
                    "static_lib",
                    interop
                        .library
                        .static_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ));
                fields.push((
                    "shared_lib",
                    interop
                        .library
                        .shared_lib
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                ));
                fields.push(("header", interop.headers.path.display().to_string()));
                fields.push((
                    "abi_manifest",
                    interop.headers.abi_manifest.display().to_string(),
                ));
                fields.push((
                    "artifact_manifest",
                    interop.artifact_manifest.display().to_string(),
                ));
                fields.push(("exports", interop.export_symbols.join(", ")));
            } else {
                fields.push(("interop", "no C exports detected".to_string()));
            }
            Ok(render_text_fields(&fields))
        }
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "inspect-artifacts",
            "source": resolved.source_path.display().to_string(),
            "projectRoot": resolved.project_root.display().to_string(),
            "profile": if release { "release" } else { "dev" },
            "nativeOutput": native.output.as_ref().map(|path| path.display().to_string()),
            "interop": interop.map(|value| serde_json::json!({
                "staticLib": value.library.static_lib.as_ref().map(|path| path.display().to_string()),
                "sharedLib": value.library.shared_lib.as_ref().map(|path| path.display().to_string()),
                "header": value.headers.path.display().to_string(),
                "abiManifest": value.headers.abi_manifest.display().to_string(),
                "artifactManifest": value.artifact_manifest.display().to_string(),
                "exports": value.export_symbols,
            })),
        }).to_string()),
    }
}

fn inspect_embedding_command(path: &Path, format: Format) -> Result<String> {
    if !project_has_c_exports(path)? {
        bail!(
            "no exported `pubext c fn` surface found at `{}`; embedding inspection requires a C-exporting target",
            path.display()
        );
    }
    let resolved = resolve_source(path)?;
    let headers = generate_c_headers(path, None)?;
    let export_symbols = read_abi_export_symbols(&headers.abi_manifest)?;
    match format {
        Format::Text => Ok(render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "inspect-embedding".to_string()),
            ("source", resolved.source_path.display().to_string()),
            ("project_root", resolved.project_root.display().to_string()),
            ("header", headers.path.display().to_string()),
            ("abi_manifest", headers.abi_manifest.display().to_string()),
            ("exports", export_symbols.join(", ")),
            ("host_init", "mandatory before callback registration or exported host-driven calls".to_string()),
            ("host_shutdown", "marks runtime unavailable for further callback registration".to_string()),
            ("host_cleanup", "clears callback slots and transient host state; safe during teardown".to_string()),
            ("last_error", "read immediately after failing call via code/class/message trio".to_string()),
            ("concurrency", "callback registry is process-global and guarded by a mutex; lifecycle state is shared across threads".to_string()),
            ("callback_slots", "64 typed i32 callback slots are currently available".to_string()),
        ])),
        Format::Json => Ok(serde_json::json!({
            "status": "ok",
            "mode": "inspect-embedding",
            "source": resolved.source_path.display().to_string(),
            "projectRoot": resolved.project_root.display().to_string(),
            "header": headers.path.display().to_string(),
            "abiManifest": headers.abi_manifest.display().to_string(),
            "exports": export_symbols,
            "lifecycle": {
                "init": {
                    "symbol": "fz_host_init",
                    "contract": "Call before registering callbacks or issuing exported calls from an in-process host.",
                },
                "shutdown": {
                    "symbol": "fz_host_shutdown",
                    "contract": "Marks the shared host runtime unavailable for further callback registration.",
                },
                "cleanup": {
                    "symbol": "fz_host_cleanup",
                    "contract": "Clears registered callbacks and transient host state during teardown.",
                },
            },
            "lastError": {
                "code": "fz_host_last_error_code",
                "class": "fz_host_last_error_class",
                "message": "fz_host_last_error_message",
                "contract": "Read immediately after a failing exported call or callback operation.",
            },
            "concurrency": {
                "scope": "process-global",
                "callbackRegistry": "mutex-guarded",
                "callbackSlots": 64,
            },
        }).to_string()),
    }
}

fn extract_doc_items_from_module(module: &ResolvedModuleSource) -> Vec<DocItem> {
    let mut items = Vec::new();
    let lines = module.source.lines().collect::<Vec<_>>();
    for item in &module.ast.items {
        if let Some(doc_item) = doc_item_from_ast(module, &lines, item) {
            items.push(doc_item);
        }
    }
    items
}

fn doc_item_from_ast(
    module: &ResolvedModuleSource,
    lines: &[&str],
    item: &ast::Item,
) -> Option<DocItem> {
    match item {
        ast::Item::Function(function) => {
            let line = find_function_decl_line(lines, function).unwrap_or(0);
            Some(DocItem {
                kind: doc_function_kind(function).to_string(),
                name: function.name.clone(),
                signature: render_doc_function_signature(function),
                module: module.module_name.clone(),
                path: module.path.display().to_string(),
                line,
                docs: docs_before_line(lines, line),
            })
        }
        ast::Item::Struct(item) => Some(doc_named_item(
            module,
            lines,
            "struct",
            &item.name,
            line_starts_with(lines, "struct", &item.name),
            render_named_signature("struct", &item.name),
        )),
        ast::Item::Enum(item) => Some(doc_named_item(
            module,
            lines,
            "enum",
            &item.name,
            line_starts_with(lines, "enum", &item.name),
            render_named_signature("enum", &item.name),
        )),
        ast::Item::Trait(item) => Some(doc_named_item(
            module,
            lines,
            "trait",
            &item.name,
            line_starts_with(lines, "trait", &item.name),
            render_named_signature("trait", &item.name),
        )),
        ast::Item::TypeAlias(item) => Some(doc_named_item(
            module,
            lines,
            "type",
            &item.name,
            line_starts_with(lines, "type", &item.name),
            format!("type {} = {};", item.name, item.ty),
        )),
        ast::Item::NewType(item) => Some(doc_named_item(
            module,
            lines,
            "newtype",
            &item.name,
            line_starts_with(lines, "newtype", &item.name),
            format!("newtype {} = {};", item.name, item.inner),
        )),
        ast::Item::Const(item) => Some(doc_named_item(
            module,
            lines,
            "const",
            &item.name,
            line_starts_with(lines, "const", &item.name),
            format!("const {}: {};", item.name, item.ty),
        )),
        ast::Item::Static(item) => Some(doc_named_item(
            module,
            lines,
            "static",
            &item.name,
            line_starts_with(lines, "static", &item.name),
            format!("static {}: {};", item.name, item.ty),
        )),
        ast::Item::Impl(item) => Some(doc_named_item(
            module,
            lines,
            "impl",
            &item.for_type.to_string(),
            line_starts_with(lines, "impl", &item.for_type.to_string()),
            render_impl_signature(item),
        )),
        ast::Item::Test(item) => Some(doc_named_item(
            module,
            lines,
            "test",
            &item.name,
            find_test_line(lines, &item.name),
            format!("test \"{}\"", item.name),
        )),
    }
}

fn doc_named_item(
    module: &ResolvedModuleSource,
    lines: &[&str],
    kind: &str,
    name: &str,
    line: Option<usize>,
    signature: String,
) -> DocItem {
    let line = line.unwrap_or(0);
    DocItem {
        kind: kind.to_string(),
        name: name.to_string(),
        signature,
        module: module.module_name.clone(),
        path: module.path.display().to_string(),
        line,
        docs: docs_before_line(lines, line),
    }
}

fn doc_function_kind(function: &ast::Function) -> &'static str {
    if function.is_extern && function.abi.as_deref() == Some("rpc") {
        "rpc"
    } else if function.is_pubext && function.abi.as_deref() == Some("c") {
        "ffi-export"
    } else if function.is_extern && function.abi.as_deref() == Some("c") {
        "ffi-import"
    } else if function.is_unsafe {
        "unsafe-fn"
    } else {
        "fn"
    }
}

fn render_doc_function_signature(function: &ast::Function) -> String {
    let params = function
        .params
        .iter()
        .map(|param| format!("{}: {}", param.name, param.ty))
        .collect::<Vec<_>>()
        .join(", ");
    if function.is_extern && function.abi.as_deref() == Some("rpc") {
        return format!(
            "rpc {}({}) -> {};",
            function.name, params, function.return_type
        );
    }
    let mut signature = String::new();
    if function.is_pubext {
        signature.push_str("pubext ");
    } else if function.is_pub {
        signature.push_str("pub ");
    }
    if function.is_async {
        signature.push_str("async ");
    }
    if function.is_extern && function.abi.as_deref() == Some("c") && !function.is_pubext {
        signature.push_str("ext ");
    }
    if function.is_unsafe {
        signature.push_str("unsafe ");
    }
    if function.is_extern {
        signature.push_str("c fn ");
    } else {
        signature.push_str("fn ");
    }
    signature.push_str(&function.name);
    signature.push('(');
    signature.push_str(&params);
    signature.push(')');
    if !matches!(function.return_type, ast::Type::Void) {
        signature.push_str(" -> ");
        signature.push_str(&function.return_type.to_string());
    }
    if function.body.is_empty() {
        signature.push(';');
    }
    signature
}

fn render_named_signature(kind: &str, name: &str) -> String {
    format!("{kind} {name}")
}

fn render_impl_signature(item: &ast::Impl) -> String {
    match &item.trait_name {
        Some(trait_name) => format!("impl {} for {}", trait_name, item.for_type),
        None => format!("impl {}", item.for_type),
    }
}

fn line_starts_with(lines: &[&str], keyword: &str, name: &str) -> Option<usize> {
    lines
        .iter()
        .position(|line| {
            let line = strip_leading_attributes_inline(line);
            line.starts_with(&format!("{keyword} {name}"))
                || line.starts_with(&format!("pub {keyword} {name}"))
                || (keyword == "static" && line.starts_with(&format!("static mut {name}")))
        })
        .map(|idx| idx + 1)
}

fn find_test_line(lines: &[&str], name: &str) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.trim_start().starts_with(&format!("test \"{name}\"")))
        .map(|idx| idx + 1)
}

fn docs_before_line(lines: &[&str], line: usize) -> String {
    if line <= 1 || line > lines.len() {
        return String::new();
    }
    let mut cursor = line - 1;
    while cursor > 0 && lines[cursor - 1].trim().is_empty() {
        cursor -= 1;
    }
    if cursor == 0 {
        return String::new();
    }
    if lines[cursor - 1].trim_start().starts_with("///") {
        let mut docs = Vec::new();
        let mut idx = cursor - 1;
        loop {
            let line = lines[idx].trim_start();
            if let Some(doc) = line.strip_prefix("///") {
                docs.push(doc.trim().to_string());
            } else {
                break;
            }
            if idx == 0 {
                break;
            }
            idx -= 1;
        }
        docs.reverse();
        return docs.join("\n");
    }
    if lines[cursor - 1].trim_end().ends_with("*/") {
        let mut docs = Vec::new();
        let mut idx = cursor - 1;
        loop {
            let line = lines[idx].trim();
            let cleaned = line
                .trim_end_matches("*/")
                .trim_start_matches("/**")
                .trim_start_matches('*')
                .trim();
            if !cleaned.is_empty() {
                docs.push(cleaned.to_string());
            }
            if line.contains("/**") || idx == 0 {
                break;
            }
            idx -= 1;
        }
        docs.reverse();
        return docs.join("\n");
    }
    String::new()
}

fn render_docs_markdown(items: &[DocItem]) -> String {
    if items.is_empty() {
        return "# API Documentation\n\n_No documented items found._\n".to_string();
    }
    let mut out = String::from("# API Documentation\n\n");
    for item in items {
        out.push_str(&format!(
            "## `{}` `{}`\n\n- module: `{}`\n- path: `{}`:{}\n- signature: `{}`\n\n",
            item.kind, item.name, item.module, item.path, item.line, item.signature
        ));
        if item.docs.is_empty() {
            out.push_str("_No docs provided._\n\n");
        } else {
            out.push_str(&format!("{}\n\n", item.docs));
        }
    }
    out
}

fn render_docs_html(items: &[DocItem]) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>fz doc</title></head><body>",
    );
    out.push_str("<h1>API Documentation</h1>");
    if items.is_empty() {
        out.push_str("<p><em>No documented items found.</em></p>");
    } else {
        for item in items {
            out.push_str(&format!(
                "<section><h2><code>{}</code> <code>{}</code></h2><ul><li>module: <code>{}</code></li><li>path: <code>{}:{}</code></li><li>signature: <code>{}</code></li></ul><pre>{}</pre></section>",
                html_escape(&item.kind),
                html_escape(&item.name),
                html_escape(&item.module),
                html_escape(&item.path),
                item.line,
                html_escape(&item.signature),
                html_escape(&item.docs),
            ));
        }
    }
    out.push_str("</body></html>");
    out
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn integrate_doc_reference(reference_path: &Path, items: &[DocItem]) -> Result<()> {
    let source = std::fs::read_to_string(reference_path)
        .with_context(|| format!("failed reading {}", reference_path.display()))?;
    let start = source
        .find(DOC_REF_START)
        .ok_or_else(|| anyhow!("reference marker missing: {}", DOC_REF_START))?;
    let end = source
        .find(DOC_REF_END)
        .ok_or_else(|| anyhow!("reference marker missing: {}", DOC_REF_END))?;
    if end <= start {
        bail!(
            "invalid reference markers ordering in {}",
            reference_path.display()
        );
    }
    let replacement = format!(
        "{DOC_REF_START}\n\n{}\n{DOC_REF_END}",
        render_docs_markdown(items).trim_end()
    );
    let mut updated = String::new();
    updated.push_str(&source[..start]);
    updated.push_str(&replacement);
    updated.push_str(&source[(end + DOC_REF_END.len())..]);
    std::fs::write(reference_path, updated.as_bytes())
        .with_context(|| format!("failed writing {}", reference_path.display()))?;
    Ok(())
}

fn format_source_file(path: &Path) -> Result<bool> {
    let original = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading file for formatting: {}", path.display()))?;
    let formatted = format_source(&original);

    if formatted != original {
        std::fs::write(path, formatted)
            .with_context(|| format!("failed writing formatted file: {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn format_source_target(path: &Path, check: bool) -> Result<Vec<PathBuf>> {
    let mut changed = Vec::<PathBuf>::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path).with_context(|| {
            format!(
                "failed reading directory for formatting: {}",
                path.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed reading directory entry for formatting: {}",
                    path.display()
                )
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                changed.extend(format_source_target(&entry_path, check)?);
                continue;
            }
            if entry_path.is_file()
                && is_fzy_source_path(&entry_path)
                && (if check {
                    let original = std::fs::read_to_string(&entry_path).with_context(|| {
                        format!(
                            "failed reading file for formatting: {}",
                            entry_path.display()
                        )
                    })?;
                    format_source(&original) != original
                } else {
                    format_source_file(&entry_path)?
                })
            {
                changed.push(entry_path);
            }
        }
        return Ok(changed);
    }

    if !is_fzy_source_path(path) {
        return Ok(changed);
    }
    if check {
        let original = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading file for formatting: {}", path.display()))?;
        if format_source(&original) != original {
            changed.push(path.to_path_buf());
        }
        return Ok(changed);
    }
    if format_source_file(path)? {
        changed.push(path.to_path_buf());
    }
    Ok(changed)
}

