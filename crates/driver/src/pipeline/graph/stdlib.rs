use super::*;

pub(crate) fn merge_module_owned(root: &mut ast::Module, mut module: ast::Module) {
    root.items.append(&mut module.items);
    root.modules.append(&mut module.modules);
    root.imports.append(&mut module.imports);
    root.capabilities.append(&mut module.capabilities);
    root.host_syscall_sites += module.host_syscall_sites;
    root.unsafe_reasoned_sites += module.unsafe_reasoned_sites;
}

pub(crate) fn merge_imported_core_stdlib_modules(root: &mut ast::Module) -> Result<()> {
    let imported = root
        .imports
        .iter()
        .filter_map(|import| {
            if import.path.len() == 1 {
                embedded_core_stdlib_module_source(import.path[0].as_str())
                    .map(|source| (import.path[0].clone(), source))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut merged_names = HashSet::<String>::new();
    for (module_name, source) in imported {
        if !merged_names.insert(module_name.clone()) {
            continue;
        }
        let mut module = parser::parse(source, &module_name).map_err(|diagnostics| {
            anyhow!(
                "{}",
                format_embedded_stdlib_parse_failure(&module_name, source, &diagnostics)
            )
        })?;
        if matches!(module_name.as_str(), "log" | "thread" | "http")
            && !module.capabilities.iter().any(|cap| cap == &module_name)
        {
            module.capabilities.push(module_name.clone());
        }
        qualify_module_symbols(&mut module, &module_name, &HashMap::new());
        merge_module_owned(root, module);
    }
    Ok(())
}

pub(crate) fn format_embedded_stdlib_parse_failure(
    module_name: &str,
    source: &str,
    diagnostics: &[diagnostics::Diagnostic],
) -> String {
    let mut lines = vec![format!(
        "failed parsing embedded core stdlib module `{module_name}` during `parse-embedded-stdlib`"
    )];
    if diagnostics.is_empty() {
        lines.push("  error: unknown parse failure".to_string());
        return lines.join("\n");
    }
    let virtual_path = format!("<embedded-core-stdlib:{module_name}>");
    for diagnostic in diagnostics {
        let code = diagnostic.code.as_deref().unwrap_or("E-PAR-UNKNOWN");
        lines.push(format!("  error[{code}]: {}", diagnostic.message));
        if let Some(span) = &diagnostic.span {
            lines.push(format!(
                "    at {virtual_path}:{}:{}",
                span.start_line, span.start_col
            ));
            if let Some(snippet) = embedded_stdlib_snippet(source, span.start_line) {
                lines.push(format!("    snippet: {snippet}"));
            }
        }
        if let Some(help) = &diagnostic.help {
            lines.push(format!("    help: {help}"));
        }
        for note in &diagnostic.notes {
            lines.push(format!("    note: {note}"));
        }
    }
    lines.join("\n")
}

pub(crate) fn embedded_stdlib_snippet(source: &str, line: usize) -> Option<String> {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .map(|snippet| snippet.trim_end().to_string())
}

#[cfg(test)]
mod embedded_stdlib_dx_tests {
    use super::format_embedded_stdlib_parse_failure;

    #[test]
    fn embedded_stdlib_parse_failure_includes_phase_span_and_help() {
        let diagnostics = vec![diagnostics::Diagnostic::new(
            diagnostics::Severity::Error,
            "unexpected token in expression",
            Some("finish the current expression".to_string()),
        )
        .with_code("E-PAR-12345678")
        .with_span(2, 9, 2, 10)];
        let rendered = format_embedded_stdlib_parse_failure(
            "process",
            "fn ok() -> i32 {\n    let x = )\n}\n",
            &diagnostics,
        );
        assert!(rendered.contains("parse-embedded-stdlib"));
        assert!(rendered.contains("<embedded-core-stdlib:process>:2:9"));
        assert!(rendered.contains("snippet:     let x = )"));
        assert!(rendered.contains("help: finish the current expression"));
    }
}

pub(crate) fn embedded_core_stdlib_module_source(module_name: &str) -> Option<&'static str> {
    match module_name {
        "bytes" => Some(include_str!("../../../../../core/src/bytes.fzy")),
        "collections" => Some(include_str!("../../../../../core/src/collections.fzy")),
        "crypto" => Some(include_str!("../../../../../core/src/crypto.fzy")),
        "duration" => Some(include_str!("../../../../../core/src/duration.fzy")),
        "encoding" => Some(include_str!("../../../../../core/src/encoding.fzy")),
        "error" => Some(include_str!("../../../../../core/src/error.fzy")),
        "fs" => Some(include_str!("../../../../../core/src/fs.fzy")),
        "gpu" => Some(include_str!("../../../../../core/src/gpu.fzy")),
        "http" => Some(include_str!("../../../../../core/src/http.fzy")),
        "io" => Some(include_str!("../../../../../core/src/io.fzy")),
        "log" => Some(include_str!("../../../../../core/src/log.fzy")),
        "mem" => Some(include_str!("../../../../../core/src/mem.fzy")),
        "network" => Some(include_str!("../../../../../core/src/network.fzy")),
        "path" => Some(include_str!("../../../../../core/src/path.fzy")),
        "proc" => Some(include_str!("../../../../../core/src/proc.fzy")),
        "process" => Some(include_str!("../../../../../core/src/process.fzy")),
        "result" => Some(include_str!("../../../../../core/src/result.fzy")),
        "security" => Some(include_str!("../../../../../core/src/security.fzy")),
        "simd" => Some(include_str!("../../../../../core/src/simd.fzy")),
        "storage" => Some(include_str!("../../../../../core/src/storage.fzy")),
        "term" => Some(include_str!("../../../../../core/src/term.fzy")),
        "text" => Some(include_str!("../../../../../core/src/text.fzy")),
        "thread" => Some(include_str!("../../../../../core/src/thread.fzy")),
        "time" => Some(include_str!("../../../../../core/src/time.fzy")),
        _ => None,
    }
}

pub(crate) fn format_module_cycle(stack: &[PathBuf], repeated: &Path) -> String {
    if let Some(start) = stack.iter().position(|entry| entry == repeated) {
        let mut parts = stack[start..]
            .iter()
            .map(|entry| entry.display().to_string())
            .collect::<Vec<_>>();
        parts.push(repeated.display().to_string());
        return parts.join(" -> ");
    }
    repeated.display().to_string()
}
