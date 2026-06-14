use super::*;

pub(crate) fn collect_parse_diagnostics_with_root_source(
    source_path: &Path,
    root_source_override: Option<&str>,
) -> Result<Vec<diagnostics::Diagnostic>> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut visited = HashSet::<PathBuf>::new();
    let mut visiting = HashSet::<PathBuf>::new();
    match collect_parse_diagnostics_recursive(
        &canonical,
        &canonical,
        root_source_override,
        &mut visited,
        &mut visiting,
    )? {
        Some((failed_path, import_chain, diagnostics)) => Ok(diagnostics
            .into_iter()
            .map(|diagnostic| annotate_parse_diagnostic(diagnostic, &failed_path, &import_chain))
            .collect()),
        None => Ok(Vec::new()),
    }
}

pub(crate) type ParseDiagnosticsHit = (PathBuf, Vec<PathBuf>, Vec<diagnostics::Diagnostic>);

pub(crate) fn collect_parse_diagnostics_recursive(
    path: &Path,
    root_path: &Path,
    root_source_override: Option<&str>,
    visited: &mut HashSet<PathBuf>,
    visiting: &mut HashSet<PathBuf>,
) -> Result<Option<ParseDiagnosticsHit>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if visited.contains(&canonical) || visiting.contains(&canonical) {
        return Ok(None);
    }
    visiting.insert(canonical.clone());
    let source = read_module_source(&canonical, root_path, root_source_override)?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = match parser::parse(&source, module_name) {
        Ok(ast) => ast,
        Err(diagnostics) => {
            return Ok(Some((
                canonical.clone(),
                vec![canonical.clone()],
                diagnostics,
            )))
        }
    };
    visited.insert(canonical.clone());

    let base_dir = canonical
        .parent()
        .ok_or_else(|| anyhow!("module has no parent directory: {}", canonical.display()))?;
    for module_decl in &ast.modules {
        let module_path = resolve_declared_module(base_dir, module_decl).with_context(|| {
            format!(
                "while resolving module `{}` from {}",
                module_decl,
                canonical.display()
            )
        })?;
        if let Some((failed_path, mut import_chain, diagnostics)) =
            collect_parse_diagnostics_recursive(
                &module_path,
                root_path,
                root_source_override,
                visited,
                visiting,
            )?
        {
            import_chain.insert(0, canonical.clone());
            return Ok(Some((failed_path, import_chain, diagnostics)));
        }
    }
    visiting.remove(&canonical);
    Ok(None)
}

pub(crate) fn annotate_parse_diagnostic(
    mut diagnostic: diagnostics::Diagnostic,
    module_path: &Path,
    import_chain: &[PathBuf],
) -> diagnostics::Diagnostic {
    diagnostic.path = Some(module_path.display().to_string());
    diagnostic
        .notes
        .push(format!("source: {}", module_path.display()));
    if import_chain.len() > 1 {
        let chain = import_chain
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        diagnostic.notes.push(format!("import chain: {chain}"));
    }
    diagnostic
}

pub(crate) fn render_parse_failure(path: &Path, diagnostics: &[diagnostics::Diagnostic]) -> String {
    let mut summary = format!(
        "parse failed for {} with {} diagnostics",
        path.display(),
        diagnostics.len()
    );
    if diagnostics.is_empty() {
        return summary;
    }
    let details = diagnostics
        .iter()
        .map(|diagnostic| {
            if let Some(span) = &diagnostic.span {
                format!(
                    "{}:{}-{}:{} {}",
                    span.start_line,
                    span.start_col,
                    span.end_line,
                    span.end_col,
                    diagnostic.message
                )
            } else {
                diagnostic.message.clone()
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    summary.push_str(": ");
    summary.push_str(&details);
    summary
}

pub(crate) fn enrich_diagnostics_context(diagnostics: &mut [diagnostics::Diagnostic]) {
    let mut source_cache = HashMap::<String, Vec<String>>::new();
    for diagnostic in diagnostics {
        if let Some(path) = &diagnostic.path {
            let lines = if let Some(lines) = source_cache.get(path) {
                lines
            } else if let Ok(source) = std::fs::read_to_string(path) {
                source_cache.insert(
                    path.clone(),
                    source.lines().map(ToString::to_string).collect::<Vec<_>>(),
                );
                source_cache
                    .get(path)
                    .expect("inserted path is retrievable")
            } else {
                continue;
            };
            if let Some(span) = &diagnostic.span {
                if span.start_line > 0
                    && span.start_line <= lines.len()
                    && diagnostic.snippet.is_none()
                {
                    diagnostic.snippet = Some(lines[span.start_line - 1].clone());
                }
                if diagnostic.labels.is_empty() {
                    diagnostic.labels.push(diagnostics::Label {
                        message: diagnostic.message.clone(),
                        primary: true,
                        span: Some(span.clone()),
                    });
                }
            } else if let Some(anchors) =
                derive_context_anchors_from_message(&diagnostic.message, lines)
            {
                if let Some((primary_token, primary_span)) = anchors.first() {
                    diagnostic.span = Some(primary_span.clone());
                    diagnostic.snippet = Some(lines[primary_span.start_line - 1].clone());
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("while analyzing `{primary_token}`"),
                        primary: true,
                        span: Some(primary_span.clone()),
                    });
                }
                for (token, span) in anchors.iter().skip(1) {
                    diagnostic.labels.push(diagnostics::Label {
                        message: format!("related context `{token}`"),
                        primary: false,
                        span: Some(span.clone()),
                    });
                }
                diagnostic.notes.push(
                    "source anchors derived from diagnostic evidence when explicit semantic spans are unavailable"
                        .to_string(),
                );
            }
        }
    }
}

pub(crate) fn derive_context_anchors_from_message(
    message: &str,
    lines: &[String],
) -> Option<Vec<(String, diagnostics::Span)>> {
    if message.contains("non-exhaustive match for enum `") {
        if let Some(span) = find_token_span(lines, "match") {
            return Some(vec![("match".to_string(), span)]);
        }
    }
    derive_anchors_from_message(message, lines)
}

pub(crate) fn derive_anchors_from_message(
    message: &str,
    lines: &[String],
) -> Option<Vec<(String, diagnostics::Span)>> {
    let quoted = extract_backticked_tokens(message);
    let mut out = Vec::new();
    for token in quoted {
        if token.trim().is_empty() {
            continue;
        }
        if let Some(span) = find_token_span(lines, &token) {
            out.push((token, span));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub(crate) fn extract_backticked_tokens(message: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (idx, ch) in message.char_indices() {
        if ch == '`' {
            if let Some(open) = start.take() {
                if idx > open + 1 {
                    out.push(message[open + 1..idx].to_string());
                }
            } else {
                start = Some(idx);
            }
        }
    }
    out
}

pub(crate) fn find_token_span(lines: &[String], token: &str) -> Option<diagnostics::Span> {
    for (line_idx, line) in lines.iter().enumerate() {
        for (col_idx, _) in line.match_indices(token) {
            if !token_boundary_matches(line, col_idx, token.len()) {
                continue;
            }
            return Some(diagnostics::Span {
                start_line: line_idx + 1,
                start_col: col_idx + 1,
                end_line: line_idx + 1,
                end_col: col_idx + token.len().max(1),
            });
        }
    }
    None
}

pub(crate) fn token_boundary_matches(line: &str, start: usize, len: usize) -> bool {
    let token = &line[start..start.saturating_add(len)];
    if !token.chars().all(is_ident_char) {
        return true;
    }
    let end = start.saturating_add(len);
    let left = line[..start].chars().next_back();
    let right = line[end..].chars().next();
    !(left.is_some_and(is_ident_char) || right.is_some_and(is_ident_char))
}

pub(crate) fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

pub(crate) fn resolve_declared_module(base_dir: &Path, module_decl: &str) -> Result<PathBuf> {
    let normalized = module_decl.trim().replace("::", "/");
    if normalized.is_empty() {
        return Err(anyhow!("empty module declaration"));
    }
    if normalized
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '/'))
    {
        return Err(anyhow!(
            "invalid module declaration `{}` (allowed: [A-Za-z0-9_::])",
            module_decl
        ));
    }

    let file_candidate = base_dir.join(format!("{normalized}.fzy"));
    if file_candidate.is_file() {
        return Ok(file_candidate);
    }
    let mod_candidate = base_dir.join(&normalized).join("mod.fzy");
    if mod_candidate.is_file() {
        return Ok(mod_candidate);
    }
    Err(anyhow!(
        "module `{}` not found; expected {} or {}",
        module_decl,
        file_candidate.display(),
        mod_candidate.display()
    ))
}

