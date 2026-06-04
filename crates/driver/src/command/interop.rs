use super::source::{
    default_header_path, load_resolved_module_set, resolve_source, ResolvedModuleSource,
    ResolvedSource,
};
use super::*;

#[derive(Debug, Clone)]
pub(super) struct CallbackTypeDef {
    pub(super) signature_key: String,
    pub(super) typedef_name: String,
    pub(super) ty: ast::Type,
}

#[derive(Debug, Clone)]
pub(super) struct HeaderArtifact {
    pub(super) path: PathBuf,
    pub(super) exports: usize,
    pub(super) abi_manifest: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderArtifactCache {
    fingerprint: String,
    exports: usize,
}

const HEADER_ARTIFACT_CACHE_SCHEMA: &str = "fozzylang.header_artifact_cache.v2";

#[derive(Debug, Clone)]
pub(super) struct RpcArtifacts {
    pub(super) schema: PathBuf,
    pub(super) client_stub: PathBuf,
    pub(super) server_stub: PathBuf,
    pub(super) methods: usize,
}

#[derive(Debug, Clone)]
struct RpcMethodArtifact {
    name: String,
    params: Vec<ast::Param>,
    request_type: String,
    response_type: String,
    client_streaming: bool,
    server_streaming: bool,
    mode: &'static str,
    module: String,
    file: String,
    line: usize,
}

pub(super) fn render_headers(format: Format, artifact: HeaderArtifact) -> String {
    match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "headers".to_string()),
            ("header", artifact.path.display().to_string()),
            ("exports", artifact.exports.to_string()),
            ("abi_manifest", artifact.abi_manifest.display().to_string()),
        ]),
        Format::Json => serde_json::json!({
            "header": artifact.path.display().to_string(),
            "exports": artifact.exports,
            "abiManifest": artifact.abi_manifest.display().to_string(),
        })
        .to_string(),
    }
}

pub(super) fn render_rpc_artifacts(format: Format, artifacts: RpcArtifacts) -> String {
    match format {
        Format::Text => render_text_fields(&[
            ("status", "ok".to_string()),
            ("mode", "rpc-gen".to_string()),
            ("schema", artifacts.schema.display().to_string()),
            ("client", artifacts.client_stub.display().to_string()),
            ("server", artifacts.server_stub.display().to_string()),
            ("methods", artifacts.methods.to_string()),
        ]),
        Format::Json => serde_json::json!({
            "schema": artifacts.schema.display().to_string(),
            "client": artifacts.client_stub.display().to_string(),
            "server": artifacts.server_stub.display().to_string(),
            "methods": artifacts.methods,
        })
        .to_string(),
    }
}

pub(super) fn generate_c_headers(path: &Path, output: Option<&Path>) -> Result<HeaderArtifact> {
    let resolved = resolve_source(path)?;
    let header_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_header_path(&resolved));
    let abi_manifest = header_path.with_extension("abi.json");
    if let Some(cached) = try_load_cached_header_artifact(&resolved, &header_path, &abi_manifest)? {
        return Ok(cached);
    }
    let parsed = parse_program(&resolved.source_path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let exports = parsed
        .module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) if is_c_export(function) => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    let imports = parsed
        .module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function) if is_c_import(function) => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    let repr_c_layouts = collect_repr_c_layouts(&parsed.module)?;
    let repr_c_names = repr_c_layouts
        .iter()
        .map(|layout| layout.name.clone())
        .collect::<BTreeSet<_>>();
    let repr_c_aliases = build_repr_c_aliases(&repr_c_layouts)?;
    let callback_types = collect_callback_types(&imports, &exports);
    validate_ffi_contracts(
        &parsed.module,
        &imports,
        &exports,
        &repr_c_names,
        resolved.manifest.as_ref(),
    )?;

    if let Some(parent) = header_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating header output directory: {}",
                parent.display()
            )
        })?;
    }

    let package_name = resolved
        .manifest
        .as_ref()
        .map(|manifest| manifest.package.name.as_str())
        .unwrap_or(module_name);
    let header = render_c_header(
        package_name,
        &parsed.module,
        &exports,
        &repr_c_aliases,
        &callback_types,
    );
    write_if_changed(&header_path, header.as_bytes())
        .with_context(|| format!("failed writing header: {}", header_path.display()))?;
    let panic_boundary = detect_ffi_panic_boundary(&exports, resolved.manifest.as_ref())?;
    let (target_triple, data_layout_hash, compiler_identity_hash) = abi_identity_fields();
    let package_json = serde_json::json!({
        "name": package_name,
        "version": resolved
            .manifest
            .as_ref()
            .map(|manifest| manifest.package.version.as_str())
            .unwrap_or("0.0.0-dev"),
    });
    let abi_payload = serde_json::json!({
        "schemaVersion": "fozzylang.ffi_abi.v1",
        "package": package_json,
        "abiRevision": 1u64,
        "targetTriple": target_triple,
        "dataLayoutHash": data_layout_hash,
        "compilerIdentityHash": compiler_identity_hash,
        "panicBoundary": panic_boundary,
        "layoutPolicy": {
            "reprCStableOnly": true,
            "nonReprCUnstable": true,
        },
        "hostApi": {
            "lifecycle": {
                "init": "fz_host_init",
                "shutdown": "fz_host_shutdown",
                "cleanup": "fz_host_cleanup",
            },
            "callbacks": {
                "registerI32": "fz_host_register_callback_i32",
                "invokeI32": "fz_host_invoke_callback_i32",
            },
            "lastError": {
                "code": "fz_host_last_error_code",
                "class": "fz_host_last_error_class",
                "message": "fz_host_last_error_message",
            },
        },
        "symbolVersioning": "strict-name-signature-v1",
        "contractSchema": "fozzylang.ffi_contracts.v1",
        "callbackAbi": "signature-typed-v1",
        "reprCLayouts": repr_c_layouts.iter().map(|layout| {
            let mut record = serde_json::Map::new();
            record.insert("name".to_string(), serde_json::json!(layout.name));
            record.insert(
                "cName".to_string(),
                serde_json::json!(
                    repr_c_aliases
                        .get(&layout.name)
                        .cloned()
                        .unwrap_or_else(|| layout.name.clone())
                ),
            );
            record.insert("kind".to_string(), serde_json::json!(layout.kind));
            record.insert("size".to_string(), serde_json::json!(layout.size));
            record.insert("align".to_string(), serde_json::json!(layout.align));
            if !layout.fields.is_empty() {
                record.insert(
                    "fields".to_string(),
                    serde_json::json!(layout.fields.iter().map(|field| serde_json::json!({
                        "name": field.name,
                        "fzy": field.ty.to_string(),
                        "c": render_c_surface_type(&field.ty, &repr_c_aliases, &[]),
                        "offset": field.offset,
                        "size": field.size,
                        "align": field.align,
                    })).collect::<Vec<_>>()),
                );
            }
            if !layout.variants.is_empty() {
                record.insert(
                    "variants".to_string(),
                    serde_json::json!(layout.variants.iter().map(|variant| serde_json::json!({
                        "name": variant.name,
                        "value": variant.value,
                    })).collect::<Vec<_>>()),
                );
            }
            if let Some(storage) = layout.storage {
                record.insert("storage".to_string(), serde_json::json!(storage));
            }
            serde_json::Value::Object(record)
        }).collect::<Vec<_>>(),
        "exports": exports.iter().map(|function| {
            let symbol = ffi_symbol_name(function);
            serde_json::json!({
                "name": symbol,
                "async": function.is_async,
                "symbolVersion": 1u64,
                "params": function.params.iter().map(|param| {
                    let contract = ffi_param_contract(function, param, &callback_types);
                    serde_json::json!({
                        "name": param.name.as_str(),
                        "fzy": param.ty.to_string(),
                        "c": render_c_surface_type(&param.ty, &repr_c_aliases, &callback_types),
                        "contract": contract,
                    })
                }).collect::<Vec<_>>(),
                "return": {
                    "fzy": function.return_type.to_string(),
                    "c": render_c_surface_type(&function.return_type, &repr_c_aliases, &callback_types),
                    "contract": ffi_return_contract(&function.return_type),
                },
                "contract": {
                    "execution": if function.is_async { "async-handle-sync-start-v1" } else { "sync" },
                    "callbackBindings": ffi_callback_bindings(function, &callback_types),
                    "asyncBoundary": ffi_async_contract(function),
                },
            })
        }).collect::<Vec<_>>(),
        "imports": imports.iter().map(|function| {
            serde_json::json!({
                "name": ffi_symbol_name(function),
                "unsafe": function.is_unsafe,
                "params": function.params.iter().map(|param| {
                    serde_json::json!({
                        "name": param.name.as_str(),
                        "fzy": param.ty.to_string(),
                        "c": render_c_surface_type(&param.ty, &repr_c_aliases, &callback_types),
                        "contract": ffi_param_contract(function, param, &callback_types),
                    })
                }).collect::<Vec<_>>(),
                "return": {
                    "fzy": function.return_type.to_string(),
                    "c": render_c_surface_type(&function.return_type, &repr_c_aliases, &callback_types),
                    "contract": ffi_return_contract(&function.return_type),
                },
                "contract": {
                    "execution": "sync",
                    "callbackBindings": ffi_callback_bindings(function, &callback_types),
                },
            })
        }).collect::<Vec<_>>(),
    });
    write_if_changed(&abi_manifest, &serde_json::to_vec_pretty(&abi_payload)?).with_context(
        || {
            format!(
                "failed writing ffi abi manifest: {}",
                abi_manifest.display()
            )
        },
    )?;

    let artifact = HeaderArtifact {
        path: header_path,
        exports: exports.len(),
        abi_manifest,
    };
    write_header_cache(&resolved, &artifact)?;
    Ok(artifact)
}

fn is_c_export(function: &ast::Function) -> bool {
    function.is_pub
        && function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
}

fn is_c_import(function: &ast::Function) -> bool {
    function.is_extern
        && !function.is_pub
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
}

fn build_repr_c_aliases(layouts: &[ReprCLayout]) -> Result<BTreeMap<String, String>> {
    let mut aliases = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for layout in layouts {
        let alias = sanitize_c_identifier(&layout.name);
        if !seen.insert(alias.clone()) {
            bail!(
                "repr(C) type name collision after C normalization: `{}`",
                alias
            );
        }
        aliases.insert(layout.name.clone(), alias);
    }
    Ok(aliases)
}

fn collect_callback_types(
    imports: &[&ast::Function],
    exports: &[&ast::Function],
) -> Vec<CallbackTypeDef> {
    let mut seen = BTreeMap::<String, ast::Type>::new();
    for function in imports.iter().chain(exports.iter()) {
        for param in &function.params {
            if let ast::Type::Function { .. } = &param.ty {
                seen.entry(param.ty.to_string())
                    .or_insert_with(|| param.ty.clone());
            }
        }
    }
    seen.into_iter()
        .enumerate()
        .map(|(index, (signature_key, ty))| CallbackTypeDef {
            signature_key,
            typedef_name: format!("fz_callback_sig{}_v0", index),
            ty,
        })
        .collect()
}

pub(super) fn generate_rpc_artifacts(path: &Path, out_dir: Option<&Path>) -> Result<RpcArtifacts> {
    let module_set = load_resolved_module_set(path)?;
    let methods = collect_rpc_methods(&module_set.modules)?;

    let output_dir = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| module_set.resolved.project_root.join(".fz").join("rpc"));
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed creating rpc output dir: {}", output_dir.display()))?;

    let schema = output_dir.join("rpc.schema.json");
    let client_stub = output_dir.join("rpc.client.fzy");
    let server_stub = output_dir.join("rpc.server.fzy");
    let schema_payload = serde_json::json!({
        "schemaVersion": "fozzylang.rpc.v1",
        "source": module_set.resolved.source_path.display().to_string(),
        "projectRoot": module_set.resolved.project_root.display().to_string(),
        "modules": module_set.modules.iter().map(|module| module.path.display().to_string()).collect::<Vec<_>>(),
        "methods": methods.iter().map(|method| serde_json::json!({
            "name": method.name,
            "params": method.params.iter().map(|param| serde_json::json!({
                "name": param.name,
                "type": param.ty.to_string(),
            })).collect::<Vec<_>>(),
            "requestType": method.request_type,
            "responseType": method.response_type,
            "clientStreaming": method.client_streaming,
            "serverStreaming": method.server_streaming,
            "mode": method.mode,
            "module": method.module,
            "file": method.file,
            "line": method.line,
        })).collect::<Vec<_>>(),
    });
    write_if_changed(&schema, &serde_json::to_vec_pretty(&schema_payload)?)
        .with_context(|| format!("failed writing rpc schema: {}", schema.display()))?;

    let mut client = String::from("// generated by fz rpc gen\n");
    client.push_str("// schema: fozzylang.rpc.v1\n");
    client.push_str("mod rpc_client {\n");
    client.push_str("    fn apply_rpc_contract(timeout_ms: i32) -> i32 {\n");
    client.push_str("        timeout(timeout_ms)\n");
    client.push_str("        deadline(timeout_ms)\n");
    client.push_str("        return 0\n");
    client.push_str("    }\n");
    client.push_str("    fn cancel_rpc() -> i32 {\n");
    client.push_str("        cancel()\n");
    client.push_str("        return 0\n");
    client.push_str("    }\n");
    for method in &methods {
        client.push_str(&render_rpc_client_wrapper(method));
    }
    client.push_str("}\n");
    write_if_changed(&client_stub, client.as_bytes())
        .with_context(|| format!("failed writing rpc client stub: {}", client_stub.display()))?;

    let mut server = String::from("// generated by fz rpc gen\n");
    server.push_str("// schema: fozzylang.rpc.v1\n");
    server.push_str("mod rpc_server {\n");
    server.push_str("    fn apply_rpc_handler_contract(timeout_ms: i32) -> i32 {\n");
    server.push_str("        timeout(timeout_ms)\n");
    server.push_str("        deadline(timeout_ms)\n");
    server.push_str("        return 0\n");
    server.push_str("    }\n");
    for method in &methods {
        server.push_str(&render_rpc_server_contract(method));
    }
    server.push_str("}\n");
    write_if_changed(&server_stub, server.as_bytes())
        .with_context(|| format!("failed writing rpc server stub: {}", server_stub.display()))?;

    Ok(RpcArtifacts {
        schema,
        client_stub,
        server_stub,
        methods: methods.len(),
    })
}

fn collect_rpc_methods(modules: &[ResolvedModuleSource]) -> Result<Vec<RpcMethodArtifact>> {
    let mut methods = Vec::new();
    for module in modules {
        let lines = module.source.lines().collect::<Vec<_>>();
        for item in &module.ast.items {
            let ast::Item::Function(function) = item else {
                continue;
            };
            if !is_rpc_function(function) {
                continue;
            }
            let request_type = rpc_request_type(&function.params);
            let response_type = function.return_type.to_string();
            let client_streaming = is_stream_type(&request_type);
            let server_streaming = is_stream_type(&response_type);
            let mode = match (client_streaming, server_streaming) {
                (false, false) => "unary",
                (true, false) => "client_streaming",
                (false, true) => "server_streaming",
                (true, true) => "bidirectional_streaming",
            };
            methods.push(RpcMethodArtifact {
                name: function.name.clone(),
                params: function.params.clone(),
                request_type,
                response_type,
                client_streaming,
                server_streaming,
                mode,
                module: module.module_name.clone(),
                file: module.path.display().to_string(),
                line: find_rpc_decl_line(&lines, function.name.as_str()).unwrap_or(0),
            });
        }
    }
    if methods.is_empty() {
        bail!("no `rpc` declarations found in source");
    }
    Ok(methods)
}

fn is_rpc_function(function: &ast::Function) -> bool {
    function.is_extern && function.abi.as_deref() == Some("rpc")
}

fn rpc_request_type(params: &[ast::Param]) -> String {
    match params {
        [] => "void".to_string(),
        [param] => param.ty.to_string(),
        _ => format!(
            "({})",
            params
                .iter()
                .map(|param| param.ty.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn is_stream_type(ty: &str) -> bool {
    ty.trim().starts_with("stream<")
}

fn render_rpc_client_wrapper(method: &RpcMethodArtifact) -> String {
    let wrapper_name = method.name.to_ascii_lowercase();
    let params = render_rpc_params(&method.params);
    let args = render_rpc_args(&method.params);
    let mut out = String::new();
    out.push_str(&format!(
        "    // {}:{} [{}]\n",
        method.module, method.line, method.mode
    ));
    out.push_str(&format!(
        "    fn {}({}) -> {} {{\n",
        wrapper_name, params, method.response_type
    ));
    out.push_str("        discard apply_rpc_contract(5000)\n");
    out.push_str(&format!("        return {}({})\n", method.name, args));
    out.push_str("    }\n");
    out
}

fn render_rpc_server_contract(method: &RpcMethodArtifact) -> String {
    let handler_name = method.name.to_ascii_lowercase();
    let params = render_rpc_params(&method.params);
    let mut out = String::new();
    out.push_str(&format!(
        "    // {}:{} [{}]\n",
        method.module, method.line, method.mode
    ));
    out.push_str(&format!(
        "    fn prepare_{}_handler({}) -> i32 {{\n",
        handler_name, params
    ));
    out.push_str("        discard apply_rpc_handler_contract(5000)\n");
    for param in &method.params {
        out.push_str(&format!("        discard {}\n", param.name));
    }
    out.push_str("        return 0\n");
    out.push_str("    }\n");
    out
}

fn render_rpc_params(params: &[ast::Param]) -> String {
    if params.is_empty() {
        return String::new();
    }
    params
        .iter()
        .map(|param| format!("{}: {}", param.name, param.ty))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_rpc_args(params: &[ast::Param]) -> String {
    params
        .iter()
        .map(|param| param.name.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

fn find_rpc_decl_line(lines: &[&str], name: &str) -> Option<usize> {
    let needle = format!("rpc {name}(");
    lines
        .iter()
        .position(|line| line.trim_start().starts_with(&needle))
        .map(|idx| idx + 1)
}

fn try_load_cached_header_artifact(
    resolved: &ResolvedSource,
    header_path: &Path,
    abi_manifest: &Path,
) -> Result<Option<HeaderArtifact>> {
    let cache_path = header_cache_path(header_path);
    if !header_path.exists() || !abi_manifest.exists() || !cache_path.exists() {
        return Ok(None);
    }
    let cache: HeaderArtifactCache = serde_json::from_slice(
        &std::fs::read(&cache_path)
            .with_context(|| format!("failed reading {}", cache_path.display()))?,
    )
    .with_context(|| format!("failed parsing {}", cache_path.display()))?;
    if cache.fingerprint != header_cache_fingerprint(resolved)? {
        return Ok(None);
    }
    Ok(Some(HeaderArtifact {
        path: header_path.to_path_buf(),
        exports: cache.exports,
        abi_manifest: abi_manifest.to_path_buf(),
    }))
}

fn write_header_cache(resolved: &ResolvedSource, artifact: &HeaderArtifact) -> Result<()> {
    let cache_path = header_cache_path(&artifact.path);
    let payload = HeaderArtifactCache {
        fingerprint: header_cache_fingerprint(resolved)?,
        exports: artifact.exports,
    };
    write_if_changed(&cache_path, &serde_json::to_vec_pretty(&payload)?)
}

fn header_cache_path(header_path: &Path) -> PathBuf {
    header_path.with_extension("header.cache.json")
}

fn header_cache_fingerprint(resolved: &ResolvedSource) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(HEADER_ARTIFACT_CACHE_SCHEMA.as_bytes());
    hasher.update(resolved.source_path.to_string_lossy().as_bytes());
    hasher.update(
        &std::fs::read(&resolved.source_path)
            .with_context(|| format!("failed reading {}", resolved.source_path.display()))?,
    );
    if let Some(manifest) = resolved.manifest.as_ref() {
        hasher.update(manifest.package.name.as_bytes());
        hasher.update(manifest.package.version.as_bytes());
        let manifest_path = resolved.project_root.join("fozzy.toml");
        if manifest_path.exists() {
            hasher.update(
                &std::fs::read(&manifest_path)
                    .with_context(|| format!("failed reading {}", manifest_path.display()))?,
            );
        }
    }
    let (target_triple, data_layout_hash, compiler_identity_hash) = abi_identity_fields();
    hasher.update(target_triple.as_bytes());
    hasher.update(data_layout_hash.as_bytes());
    hasher.update(compiler_identity_hash.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    std::fs::write(path, bytes).with_context(|| format!("failed writing {}", path.display()))
}
