use super::*;
use super::source::{default_header_path, resolve_source};

#[derive(Debug, Clone)]
pub(super) struct HeaderArtifact {
    pub(super) path: PathBuf,
    pub(super) exports: usize,
    pub(super) abi_manifest: PathBuf,
}

#[derive(Debug, Clone)]
pub(super) struct RpcArtifacts {
    pub(super) schema: PathBuf,
    pub(super) client_stub: PathBuf,
    pub(super) server_stub: PathBuf,
    pub(super) methods: usize,
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
    let parsed = parse_program(&resolved.source_path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let exports: Vec<&ast::Function> = parsed
        .module
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Function(function)
                if function.is_pub
                    && function.is_extern
                    && function
                        .abi
                        .as_deref()
                        .is_some_and(|abi| abi.eq_ignore_ascii_case("c")) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect();
    let repr_c_layouts = collect_repr_c_layouts(&parsed.module)?;
    let repr_c_names = repr_c_layouts
        .iter()
        .map(|layout| layout.name.clone())
        .collect::<BTreeSet<_>>();
    validate_ffi_contract(
        &parsed.module,
        &exports,
        &repr_c_names,
        resolved.manifest.as_ref(),
    )?;

    let header_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_header_path(&resolved));
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
    let header = render_c_header(package_name, &parsed.module, &exports);
    std::fs::write(&header_path, header)
        .with_context(|| format!("failed writing header: {}", header_path.display()))?;
    let abi_manifest = header_path.with_extension("abi.json");
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
        "symbolVersioning": "strict-name-signature-v1",
        "contractSchema": "fozzylang.ffi_contracts.v1",
        "reprCLayouts": repr_c_layouts.iter().map(|layout| {
            serde_json::json!({
                "name": layout.name,
                "kind": layout.kind,
                "size": layout.size,
                "align": layout.align,
            })
        }).collect::<Vec<_>>(),
        "exports": exports.iter().map(|function| {
            let symbol = ffi_symbol_name(function);
            serde_json::json!({
                "name": symbol,
                "async": function.is_async,
                "symbolVersion": 1u64,
                "params": function.params.iter().map(|param| {
                    let contract = ffi_param_contract(function, param);
                    serde_json::json!({
                        "name": param.name.as_str(),
                        "fzy": param.ty.to_string(),
                        "c": to_c_type(&param.ty),
                        "contract": contract,
                    })
                }).collect::<Vec<_>>(),
                "return": {
                    "fzy": function.return_type.to_string(),
                    "c": to_c_type(&function.return_type),
                    "contract": ffi_return_contract(&function.return_type),
                },
                "contract": {
                    "execution": if function.is_async { "async-handle-v1" } else { "sync" },
                    "callbackBindings": ffi_callback_bindings(function),
                    "asyncBoundary": ffi_async_contract(function),
                },
            })
        }).collect::<Vec<_>>(),
    });
    std::fs::write(&abi_manifest, serde_json::to_vec_pretty(&abi_payload)?).with_context(|| {
        format!(
            "failed writing ffi abi manifest: {}",
            abi_manifest.display()
        )
    })?;

    Ok(HeaderArtifact {
        path: header_path,
        exports: exports.len(),
        abi_manifest,
    })
}

pub(super) fn generate_rpc_artifacts(path: &Path, out_dir: Option<&Path>) -> Result<RpcArtifacts> {
    let resolved = resolve_source(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let methods = parse_rpc_declarations(&parsed.combined_source)?;

    let output_dir = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| resolved.project_root.join(".fz").join("rpc"));
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed creating rpc output dir: {}", output_dir.display()))?;

    let schema = output_dir.join("rpc.schema.json");
    let client_stub = output_dir.join("rpc.client.fzy");
    let server_stub = output_dir.join("rpc.server.fzy");
    let schema_payload = serde_json::json!({
        "schemaVersion": "fozzylang.rpc.v0",
        "source": resolved.source_path.display().to_string(),
        "methods": methods.iter().map(|method| serde_json::json!({
            "name": method.name,
            "request": method.request,
            "response": method.response,
            "clientStreaming": method.client_streaming,
            "serverStreaming": method.server_streaming,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(&schema, serde_json::to_vec_pretty(&schema_payload)?)
        .with_context(|| format!("failed writing rpc schema: {}", schema.display()))?;

    let mut client = String::from("// generated by fz rpc gen\n");
    client.push_str("mod rpc_client {\n");
    client.push_str("    fn apply_rpc_contract(timeout_ms: i32) -> i32 {\n");
    client.push_str("        timeout(timeout_ms)\n");
    client.push_str("        deadline(timeout_ms)\n");
    client.push_str("        return 0\n");
    client.push_str("    }\n");
    for method in &methods {
        client.push_str(&format!(
            "    async fn {}(req: {}) -> {} {{\n        discard apply_rpc_contract(5000)\n        let frame = rpc.transport_send(\"{}\", req)\n        if frame == 0 {{\n            cancel()\n        }}\n        let response = recv()\n        return response\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response,
            method.name
        ));
    }
    client.push_str("}\n");
    std::fs::write(&client_stub, client)
        .with_context(|| format!("failed writing rpc client stub: {}", client_stub.display()))?;

    let mut server = String::from("// generated by fz rpc gen\n");
    server.push_str("mod rpc_server {\n");
    server.push_str("    fn apply_rpc_handler_contract(timeout_ms: i32) -> i32 {\n");
    server.push_str("        timeout(timeout_ms)\n");
    server.push_str("        deadline(timeout_ms)\n");
    server.push_str("        return 0\n");
    server.push_str("    }\n");
    for method in &methods {
        server.push_str(&format!(
            "    async fn handle_{}(req: {}) -> {} {{\n        discard apply_rpc_handler_contract(5000)\n        let incoming = rpc.transport_recv(\"{}\")\n        if incoming == 0 {{\n            cancel()\n        }}\n        discard req\n        return incoming\n    }}\n",
            method.name.to_lowercase(),
            method.request,
            method.response,
            method.name
        ));
    }
    server.push_str("}\n");
    std::fs::write(&server_stub, server)
        .with_context(|| format!("failed writing rpc server stub: {}", server_stub.display()))?;

    Ok(RpcArtifacts {
        schema,
        client_stub,
        server_stub,
        methods: methods.len(),
    })
}
