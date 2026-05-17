use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use super::*;

#[derive(Debug, Clone)]
pub(super) struct JsArtifact {
    pub js_path: PathBuf,
    pub sourcemap_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct JsDebugReadiness {
    pub sourcemap_valid: bool,
    pub browser_stacktrace_ready: bool,
    pub async_frame_mapping_ready: bool,
    pub breakpoint_ranges_ready: bool,
    pub generated_lines: usize,
    pub mapped_lines: usize,
    pub async_function_count: usize,
}

#[derive(Debug, Clone)]
struct SourceFile {
    path: PathBuf,
    relative: String,
    content: String,
}

#[derive(Debug, Clone)]
struct ItemSourceInfo {
    source_index: usize,
    start_line: usize,
    end_line: usize,
}

#[derive(Debug, Clone)]
struct MappingEntry {
    generated_line: usize,
    generated_col: usize,
    source_index: usize,
    original_line: usize,
    original_col: usize,
    name_index: Option<usize>,
}

#[derive(Debug, Clone)]
struct EmissionState {
    lines: Vec<String>,
    mappings: Vec<MappingEntry>,
    names: Vec<String>,
    name_index: HashMap<String, usize>,
    scopes: Vec<HashSet<String>>,
    diagnostics: Vec<diagnostics::Diagnostic>,
    indent: usize,
    temp_counter: usize,
    symbol_names: HashMap<String, String>,
    namespace_roots: BTreeSet<String>,
}

impl EmissionState {
    fn new(symbol_names: HashMap<String, String>, namespace_roots: BTreeSet<String>) -> Self {
        Self {
            lines: Vec::new(),
            mappings: Vec::new(),
            names: Vec::new(),
            name_index: HashMap::new(),
            scopes: Vec::new(),
            diagnostics: Vec::new(),
            indent: 0,
            temp_counter: 0,
            symbol_names,
            namespace_roots,
        }
    }

    fn push_line(
        &mut self,
        text: impl Into<String>,
        source_index: usize,
        original_line: usize,
        name: Option<&str>,
    ) {
        let rendered = format!("{}{}", "    ".repeat(self.indent), text.into());
        self.lines.push(rendered);
        let generated_line = self.lines.len().saturating_sub(1);
        let name_index = name.map(|value| self.name_for(value));
        self.mappings.push(MappingEntry {
            generated_line,
            generated_col: 0,
            source_index,
            original_line: original_line.saturating_sub(1),
            original_col: 0,
            name_index,
        });
    }

    fn push_scope(&mut self, bindings: impl IntoIterator<Item = String>) {
        self.scopes.push(bindings.into_iter().collect());
    }

    fn pop_scope(&mut self) {
        let _ = self.scopes.pop();
    }

    fn bind_local(&mut self, name: &str) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string());
        }
    }

    fn is_local(&self, name: &str) -> bool {
        self.scopes.iter().rev().any(|scope| scope.contains(name))
    }

    fn next_temp(&mut self, prefix: &str) -> String {
        let value = format!("{prefix}_{}", self.temp_counter);
        self.temp_counter += 1;
        value
    }

    fn name_for(&mut self, name: &str) -> usize {
        if let Some(index) = self.name_index.get(name) {
            return *index;
        }
        let index = self.names.len();
        self.names.push(name.to_string());
        self.name_index.insert(name.to_string(), index);
        index
    }

    fn symbol_ref(&self, name: &str) -> Option<String> {
        self.symbol_names.get(name).cloned()
    }

    fn unsupported(
        &mut self,
        function_name: &str,
        source_path: &Path,
        line: usize,
        feature: &str,
        help: &str,
    ) {
        self.diagnostics.push(
            diagnostics::Diagnostic::new(
                diagnostics::Severity::Error,
                format!("js backend does not yet support {feature} in function `{function_name}`"),
                Some(help.to_string()),
            )
            .with_path(source_path.display().to_string())
            .with_span(line, 1, line, 1)
            .with_fix("switch backend: `fz build <path> --backend llvm`"),
        );
    }
}

pub(super) fn emit_js_artifact(
    parsed: &ParsedProgram,
    typed: &hir::TypedModule,
    _fir: &fir::FirModule,
    root_source: &Path,
    project_root: &Path,
    emit_sourcemap: bool,
) -> Result<JsArtifact> {
    let source_files = load_source_files(parsed, root_source)?;
    let source_info = collect_item_sources(parsed, &source_files, root_source)?;
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;
    let stem = root_source
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid source filename for {}", root_source.display()))?;
    let js_path = build_dir.join(format!("{stem}.js"));
    let sourcemap_path = build_dir.join(format!("{stem}.js.map"));
    let symbol_names = build_symbol_name_map(parsed, typed);
    let namespace_roots = symbol_names
        .keys()
        .flat_map(|symbol| split_path(symbol).into_iter().take(1).map(str::to_string))
        .filter(|segment| !segment.is_empty())
        .collect::<BTreeSet<_>>();
    let mut state = EmissionState::new(symbol_names, namespace_roots);
    let root_index = source_files
        .iter()
        .position(|file| file.path == root_source)
        .unwrap_or(0);

    emit_prelude(&mut state, root_index);
    emit_namespace_roots(&mut state, root_index);
    emit_items(
        &mut state,
        parsed,
        typed,
        &source_files,
        &source_info,
        root_index,
    )?;
    emit_namespace_assignments(&mut state, parsed, typed, root_index);
    emit_exports(&mut state, parsed, typed, root_index);

    if !state.diagnostics.is_empty() {
        diagnostics::assign_stable_codes(
            &mut state.diagnostics,
            diagnostics::DiagnosticDomain::Driver,
        );
        let rendered = state
            .diagnostics
            .into_iter()
            .map(|diag| diag.message)
            .collect::<Vec<_>>()
            .join("\n");
        bail!("{rendered}");
    }

    let mut js_text = state.lines.join("\n");
    if emit_sourcemap {
        let sourcemap = build_sourcemap_json(&state, &source_files, stem, typed)?;
        std::fs::write(&sourcemap_path, sourcemap).with_context(|| {
            format!("failed writing js sourcemap: {}", sourcemap_path.display())
        })?;
        js_text.push('\n');
        js_text.push_str(&format!(
            "//# sourceMappingURL={}",
            sourcemap_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("app.js.map")
        ));
    }
    js_text.push('\n');
    std::fs::write(&js_path, js_text)
        .with_context(|| format!("failed writing js artifact: {}", js_path.display()))?;
    Ok(JsArtifact {
        js_path,
        sourcemap_path: emit_sourcemap.then_some(sourcemap_path),
    })
}

pub fn inspect_js_debug_readiness(
    js_path: &Path,
    sourcemap_path: Option<&Path>,
) -> Result<JsDebugReadiness> {
    let js_text = std::fs::read_to_string(js_path)
        .with_context(|| format!("failed reading js artifact: {}", js_path.display()))?;
    let generated_lines = js_text.lines().count();
    let Some(sourcemap_path) = sourcemap_path else {
        return Ok(JsDebugReadiness {
            sourcemap_valid: false,
            browser_stacktrace_ready: false,
            async_frame_mapping_ready: false,
            breakpoint_ranges_ready: false,
            generated_lines,
            mapped_lines: 0,
            async_function_count: 0,
        });
    };
    let map_text = std::fs::read_to_string(sourcemap_path)
        .with_context(|| format!("failed reading sourcemap: {}", sourcemap_path.display()))?;
    let payload: serde_json::Value =
        serde_json::from_str(&map_text).context("failed parsing sourcemap json")?;
    let mappings = payload
        .get("mappings")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let mapped_lines = mappings
        .split(';')
        .filter(|entry| !entry.is_empty())
        .count();
    let async_functions = payload
        .get("x_fozzy")
        .and_then(|value| value.get("asyncFunctions"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let names = payload
        .get("names")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(JsDebugReadiness {
        sourcemap_valid: payload.get("version").and_then(serde_json::Value::as_u64) == Some(3)
            && payload
                .get("sources")
                .and_then(serde_json::Value::as_array)
                .is_some(),
        browser_stacktrace_ready: js_text.contains("//# sourceMappingURL=") && !names.is_empty(),
        async_frame_mapping_ready: async_functions.iter().all(|value| value.is_string()),
        breakpoint_ranges_ready: mapped_lines >= generated_lines.saturating_sub(2),
        generated_lines,
        mapped_lines,
        async_function_count: async_functions.len(),
    })
}

fn emit_prelude(state: &mut EmissionState, root_index: usize) {
    state.push_line("// Generated by fozzyc --backend js", root_index, 1, None);
    state.push_line(
        "// Readable ESM emission from the shared typed pipeline.",
        root_index,
        1,
        None,
    );
    state.push_line("", root_index, 1, None);
    state.push_line(
        "const __fz_runtime = globalThis.__fozzyRuntime ?? Object.create(null);",
        root_index,
        1,
        None,
    );
    state.push_line(
        "function __fz_intrinsic(name) {",
        root_index,
        1,
        Some("__fz_intrinsic"),
    );
    state.indent += 1;
    state.push_line(
        "const candidate = __fz_runtime[name] ?? __fz_runtime[name.replaceAll('.', '_')];",
        root_index,
        1,
        None,
    );
    state.push_line(
        "if (typeof candidate !== \"function\") {",
        root_index,
        1,
        None,
    );
    state.indent += 1;
    state.push_line(
        "throw new Error(`missing Fozzy JS runtime intrinsic: ${name}`);",
        root_index,
        1,
        None,
    );
    state.indent -= 1;
    state.push_line("}", root_index, 1, None);
    state.push_line("return candidate;", root_index, 1, None);
    state.indent -= 1;
    state.push_line("}", root_index, 1, Some("__fz_intrinsic"));
    state.push_line(
        "function __fz_match_error(context) { throw new Error(`non-exhaustive Fozzy match: ${context}`); }",
        root_index,
        1,
        Some("__fz_match_error"),
    );
    state.push_line("", root_index, 1, None);
}

fn emit_namespace_roots(state: &mut EmissionState, root_index: usize) {
    for root in state.namespace_roots.clone() {
        if root.is_empty() {
            continue;
        }
        state.push_line(
            format!("const {} = {{}};", sanitize_identifier(&root)),
            root_index,
            1,
            None,
        );
    }
    if !state.namespace_roots.is_empty() {
        state.push_line("", root_index, 1, None);
    }
}

fn emit_items(
    state: &mut EmissionState,
    parsed: &ParsedProgram,
    typed: &hir::TypedModule,
    source_files: &[SourceFile],
    source_info: &HashMap<String, ItemSourceInfo>,
    root_index: usize,
) -> Result<()> {
    for item in &parsed.module.items {
        match item {
            ast::Item::Enum(item) => emit_enum(state, item, source_info, root_index)?,
            ast::Item::Const(item) => {
                emit_const(state, item, source_files, source_info, root_index)?
            }
            ast::Item::Static(item) => {
                emit_static(state, item, source_files, source_info, root_index)?
            }
            ast::Item::Struct(item) => {
                let info = source_info
                    .get(&item.name)
                    .cloned()
                    .unwrap_or(ItemSourceInfo {
                        source_index: root_index,
                        start_line: 1,
                        end_line: 1,
                    });
                state.push_line(
                    format!("// struct {} lowers to plain JS object values", item.name),
                    info.source_index,
                    info.start_line,
                    None,
                );
                state.push_line("", info.source_index, info.start_line, None);
            }
            ast::Item::Trait(item) => {
                let info = source_info
                    .get(&item.name)
                    .cloned()
                    .unwrap_or(ItemSourceInfo {
                        source_index: root_index,
                        start_line: 1,
                        end_line: 1,
                    });
                state.push_line(
                    format!(
                        "// trait {} is enforced by typed lowering before JS emission",
                        item.name
                    ),
                    info.source_index,
                    info.start_line,
                    None,
                );
                state.push_line("", info.source_index, info.start_line, None);
            }
            ast::Item::TypeAlias(item) => {
                let info = source_info
                    .get(&item.name)
                    .cloned()
                    .unwrap_or(ItemSourceInfo {
                        source_index: root_index,
                        start_line: 1,
                        end_line: 1,
                    });
                state.push_line(
                    format!("// type alias {} is erased for JS emission", item.name),
                    info.source_index,
                    info.start_line,
                    None,
                );
                state.push_line("", info.source_index, info.start_line, None);
            }
            ast::Item::NewType(item) => {
                let info = source_info
                    .get(&item.name)
                    .cloned()
                    .unwrap_or(ItemSourceInfo {
                        source_index: root_index,
                        start_line: 1,
                        end_line: 1,
                    });
                state.push_line(
                    format!("// newtype {} is erased for JS emission", item.name),
                    info.source_index,
                    info.start_line,
                    None,
                );
                state.push_line("", info.source_index, info.start_line, None);
            }
            ast::Item::Function(_) | ast::Item::Impl(_) | ast::Item::Test(_) => {}
        }
    }

    for function in &typed.typed_functions {
        emit_function(state, function, source_files, source_info, root_index)?;
    }
    Ok(())
}

fn emit_const(
    state: &mut EmissionState,
    item: &ast::ConstItem,
    source_files: &[SourceFile],
    source_info: &HashMap<String, ItemSourceInfo>,
    root_index: usize,
) -> Result<()> {
    let info = source_info
        .get(&item.name)
        .cloned()
        .unwrap_or(ItemSourceInfo {
            source_index: root_index,
            start_line: 1,
            end_line: 1,
        });
    let source_path = &source_files[info.source_index].path;
    let symbol = state
        .symbol_ref(&item.name)
        .unwrap_or_else(|| symbol_identifier(&item.name));
    let expr = emit_expr(state, "<const>", &item.value, source_path, info.start_line)?;
    state.push_line(
        format!("const {symbol} = {expr};"),
        info.source_index,
        info.start_line,
        Some(&item.name),
    );
    state.push_line("", info.source_index, info.start_line, None);
    Ok(())
}

fn emit_static(
    state: &mut EmissionState,
    item: &ast::StaticItem,
    source_files: &[SourceFile],
    source_info: &HashMap<String, ItemSourceInfo>,
    root_index: usize,
) -> Result<()> {
    let info = source_info
        .get(&item.name)
        .cloned()
        .unwrap_or(ItemSourceInfo {
            source_index: root_index,
            start_line: 1,
            end_line: 1,
        });
    let source_path = &source_files[info.source_index].path;
    let symbol = state
        .symbol_ref(&item.name)
        .unwrap_or_else(|| symbol_identifier(&item.name));
    let expr = emit_expr(state, "<static>", &item.value, source_path, info.start_line)?;
    state.push_line(
        format!("let {symbol} = {expr};"),
        info.source_index,
        info.start_line,
        Some(&item.name),
    );
    state.push_line("", info.source_index, info.start_line, None);
    Ok(())
}

fn emit_enum(
    state: &mut EmissionState,
    item: &ast::Enum,
    source_info: &HashMap<String, ItemSourceInfo>,
    root_index: usize,
) -> Result<()> {
    let info = source_info
        .get(&item.name)
        .cloned()
        .unwrap_or(ItemSourceInfo {
            source_index: root_index,
            start_line: 1,
            end_line: 1,
        });
    let symbol = state
        .symbol_ref(&item.name)
        .unwrap_or_else(|| symbol_identifier(&item.name));
    state.push_line(
        format!("const {symbol} = {{"),
        info.source_index,
        info.start_line,
        Some(&item.name),
    );
    state.indent += 1;
    for variant in &item.variants {
        let ctor = if variant.payload.is_empty() && variant.named_payload.is_empty() {
            format!(
                "{{ $enum: {}, $variant: {} }}",
                js_string(&item.name),
                js_string(&variant.name)
            )
        } else if !variant.named_payload.is_empty() {
            let params = variant
                .named_payload
                .iter()
                .map(|field| sanitize_identifier(&field.name))
                .collect::<Vec<_>>();
            let fields = params
                .iter()
                .map(|field| format!("{field}: {field}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "({}) => ({{ $enum: {}, $variant: {}, {} }})",
                params.join(", "),
                js_string(&item.name),
                js_string(&variant.name),
                fields
            )
        } else {
            let params = (0..variant.payload.len())
                .map(|index| format!("v{index}"))
                .collect::<Vec<_>>();
            format!(
                "({}) => ({{ $enum: {}, $variant: {}, $values: [{}] }})",
                params.join(", "),
                js_string(&item.name),
                js_string(&variant.name),
                params.join(", ")
            )
        };
        state.push_line(
            format!("{}: {},", sanitize_identifier(&variant.name), ctor),
            info.source_index,
            info.start_line,
            Some(&item.name),
        );
    }
    state.indent -= 1;
    state.push_line("};", info.source_index, info.end_line, Some(&item.name));
    state.push_line("", info.source_index, info.end_line, None);
    Ok(())
}

fn emit_function(
    state: &mut EmissionState,
    function: &hir::TypedFunction,
    source_files: &[SourceFile],
    source_info: &HashMap<String, ItemSourceInfo>,
    root_index: usize,
) -> Result<()> {
    let info = source_info
        .get(&function.name)
        .cloned()
        .or_else(|| {
            source_info.iter().find_map(|(name, info)| {
                (strip_generic_suffix(name) == strip_generic_suffix(&function.name))
                    .then_some(info.clone())
            })
        })
        .unwrap_or(ItemSourceInfo {
            source_index: root_index,
            start_line: 1,
            end_line: 1,
        });
    let source_path = &source_files[info.source_index].path;
    let symbol = state
        .symbol_ref(&function.name)
        .unwrap_or_else(|| symbol_identifier(&function.name));
    let source_lines = source_files[info.source_index]
        .content
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let params = function
        .params
        .iter()
        .map(|param| sanitize_identifier(&param.name))
        .collect::<Vec<_>>()
        .join(", ");
    let prefix = if function.is_async { "async " } else { "" };
    state.push_scope(function.params.iter().map(|param| param.name.clone()));
    state.push_line(
        format!("{prefix}function {symbol}({params}) {{"),
        info.source_index,
        info.start_line,
        Some(&function.name),
    );
    state.indent += 1;
    let mut line_cursor = info.start_line;
    for stmt in &function.body {
        let stmt_line = infer_stmt_line(&source_lines, line_cursor, info.end_line, stmt);
        line_cursor = stmt_line.saturating_add(1);
        emit_stmt(
            state,
            &function.name,
            stmt,
            source_path,
            info.source_index,
            stmt_line,
        )?;
    }
    state.indent -= 1;
    state.push_line("}", info.source_index, info.end_line, Some(&function.name));
    state.push_line("", info.source_index, info.end_line, None);
    state.pop_scope();
    Ok(())
}

fn infer_stmt_line(
    source_lines: &[String],
    start_line: usize,
    end_line: usize,
    stmt: &ast::Stmt,
) -> usize {
    let key = stmt_line_key(stmt);
    let start = start_line.saturating_sub(1);
    let end = end_line.min(source_lines.len());
    for index in start..end {
        let trimmed = source_lines[index].trim_start();
        if trimmed.contains(&key) {
            return index + 1;
        }
    }
    start_line.max(1)
}

fn stmt_line_key(stmt: &ast::Stmt) -> String {
    match stmt {
        ast::Stmt::Let { name, .. } => format!("let {name}"),
        ast::Stmt::LetPattern { .. } => "let ".to_string(),
        ast::Stmt::Assign { target, .. } => format!("{target} ="),
        ast::Stmt::CompoundAssign { target, .. } => target.clone(),
        ast::Stmt::If { .. } => "if ".to_string(),
        ast::Stmt::While { .. } => "while ".to_string(),
        ast::Stmt::For { .. } => "for ".to_string(),
        ast::Stmt::ForIn { .. } => "for ".to_string(),
        ast::Stmt::Loop { .. } => "loop".to_string(),
        ast::Stmt::Break(_) => "break".to_string(),
        ast::Stmt::Continue => "continue".to_string(),
        ast::Stmt::Return(_) => "return".to_string(),
        ast::Stmt::Defer(_) => "defer".to_string(),
        ast::Stmt::Requires(_) => "requires".to_string(),
        ast::Stmt::Ensures(_) => "ensures".to_string(),
        ast::Stmt::Match { .. } => "match ".to_string(),
        ast::Stmt::Expr(ast::Expr::Call { callee, .. }) => callee.clone(),
        ast::Stmt::Expr(_) => ";".to_string(),
    }
}

fn emit_stmt(
    state: &mut EmissionState,
    function_name: &str,
    stmt: &ast::Stmt,
    source_path: &Path,
    source_index: usize,
    line: usize,
) -> Result<()> {
    match stmt {
        ast::Stmt::Let {
            name,
            mutable,
            value,
            ..
        } => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.bind_local(name);
            state.push_line(
                format!(
                    "{} {} = {};",
                    if *mutable { "let" } else { "const" },
                    sanitize_identifier(name),
                    expr
                ),
                source_index,
                line,
                Some(name),
            );
        }
        ast::Stmt::LetPattern {
            pattern,
            mutable,
            value,
            ..
        } => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            let temp = state.next_temp("__fz_match");
            state.push_line(
                format!("const {temp} = {expr};"),
                source_index,
                line,
                Some(function_name),
            );
            emit_pattern_bindings(state, pattern, &temp, *mutable, source_index, line);
        }
        ast::Stmt::Assign { target, value } => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.push_line(
                format!("{} = {};", emit_name_ref(state, target), expr),
                source_index,
                line,
                Some(target),
            );
        }
        ast::Stmt::CompoundAssign { target, op, value } => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.push_line(
                format!(
                    "{} {}= {};",
                    emit_name_ref(state, target),
                    binary_op_to_js(*op),
                    expr
                ),
                source_index,
                line,
                Some(target),
            );
        }
        ast::Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            let condition = emit_expr(state, function_name, condition, source_path, line)?;
            state.push_line(
                format!("if ({condition}) {{"),
                source_index,
                line,
                Some(function_name),
            );
            state.indent += 1;
            state.push_scope(Vec::<String>::new());
            for nested in then_body {
                emit_stmt(
                    state,
                    function_name,
                    nested,
                    source_path,
                    source_index,
                    line,
                )?;
            }
            state.pop_scope();
            state.indent -= 1;
            if else_body.is_empty() {
                state.push_line("}", source_index, line, Some(function_name));
            } else {
                state.push_line("} else {", source_index, line, Some(function_name));
                state.indent += 1;
                state.push_scope(Vec::<String>::new());
                for nested in else_body {
                    emit_stmt(
                        state,
                        function_name,
                        nested,
                        source_path,
                        source_index,
                        line,
                    )?;
                }
                state.pop_scope();
                state.indent -= 1;
                state.push_line("}", source_index, line, Some(function_name));
            }
        }
        ast::Stmt::While { condition, body } => {
            let condition = emit_expr(state, function_name, condition, source_path, line)?;
            state.push_line(
                format!("while ({condition}) {{"),
                source_index,
                line,
                Some(function_name),
            );
            state.indent += 1;
            state.push_scope(Vec::<String>::new());
            for nested in body {
                emit_stmt(
                    state,
                    function_name,
                    nested,
                    source_path,
                    source_index,
                    line,
                )?;
            }
            state.pop_scope();
            state.indent -= 1;
            state.push_line("}", source_index, line, Some(function_name));
        }
        ast::Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            let init = init
                .as_deref()
                .map(|stmt| emit_for_fragment(state, function_name, stmt, source_path, line))
                .transpose()?
                .unwrap_or_default();
            let condition = condition
                .as_ref()
                .map(|expr| emit_expr(state, function_name, expr, source_path, line))
                .transpose()?
                .unwrap_or_else(|| "true".to_string());
            let step = step
                .as_deref()
                .map(|stmt| emit_for_fragment(state, function_name, stmt, source_path, line))
                .transpose()?
                .unwrap_or_default();
            state.push_line(
                format!("for ({init}; {condition}; {step}) {{"),
                source_index,
                line,
                Some(function_name),
            );
            state.indent += 1;
            state.push_scope(Vec::<String>::new());
            for nested in body {
                emit_stmt(
                    state,
                    function_name,
                    nested,
                    source_path,
                    source_index,
                    line,
                )?;
            }
            state.pop_scope();
            state.indent -= 1;
            state.push_line("}", source_index, line, Some(function_name));
        }
        ast::Stmt::ForIn {
            binding,
            iterable,
            body,
        } => {
            let iterable = emit_expr(state, function_name, iterable, source_path, line)?;
            state.push_line(
                format!(
                    "for (const {} of {}) {{",
                    sanitize_identifier(binding),
                    iterable
                ),
                source_index,
                line,
                Some(function_name),
            );
            state.indent += 1;
            state.push_scope([binding.clone()]);
            for nested in body {
                emit_stmt(
                    state,
                    function_name,
                    nested,
                    source_path,
                    source_index,
                    line,
                )?;
            }
            state.pop_scope();
            state.indent -= 1;
            state.push_line("}", source_index, line, Some(function_name));
        }
        ast::Stmt::Loop { body } => {
            state.push_line("while (true) {", source_index, line, Some(function_name));
            state.indent += 1;
            state.push_scope(Vec::<String>::new());
            for nested in body {
                emit_stmt(
                    state,
                    function_name,
                    nested,
                    source_path,
                    source_index,
                    line,
                )?;
            }
            state.pop_scope();
            state.indent -= 1;
            state.push_line("}", source_index, line, Some(function_name));
        }
        ast::Stmt::Break(value) => {
            if let Some(value) = value {
                let expr = emit_expr(state, function_name, value, source_path, line)?;
                state.push_line(
                    format!("return {expr};"),
                    source_index,
                    line,
                    Some(function_name),
                );
            } else {
                state.push_line("break;", source_index, line, Some(function_name));
            }
        }
        ast::Stmt::Continue => {
            state.push_line("continue;", source_index, line, Some(function_name));
        }
        ast::Stmt::Return(value) => {
            if let Some(value) = value {
                let expr = emit_expr(state, function_name, value, source_path, line)?;
                state.push_line(
                    format!("return {expr};"),
                    source_index,
                    line,
                    Some(function_name),
                );
            } else {
                state.push_line("return;", source_index, line, Some(function_name));
            }
        }
        ast::Stmt::Defer(value) => {
            state.push_line(
                "// defer lowered eagerly in js backend v1",
                source_index,
                line,
                None,
            );
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.push_line(format!("{expr};"), source_index, line, Some(function_name));
        }
        ast::Stmt::Requires(value) => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.push_line(
                format!("if (!({expr})) throw new Error(\"Fozzy precondition failed\");"),
                source_index,
                line,
                Some(function_name),
            );
        }
        ast::Stmt::Ensures(value) => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.push_line(
                format!("if (!({expr})) throw new Error(\"Fozzy postcondition failed\");"),
                source_index,
                line,
                Some(function_name),
            );
        }
        ast::Stmt::Match { scrutinee, arms } => {
            emit_match_stmt(
                state,
                function_name,
                scrutinee,
                arms,
                source_index,
                line,
                source_path,
            )?;
        }
        ast::Stmt::Expr(value) => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.push_line(format!("{expr};"), source_index, line, Some(function_name));
        }
    }
    Ok(())
}

fn emit_for_fragment(
    state: &mut EmissionState,
    function_name: &str,
    stmt: &ast::Stmt,
    source_path: &Path,
    line: usize,
) -> Result<String> {
    Ok(match stmt {
        ast::Stmt::Let {
            name,
            mutable,
            value,
            ..
        } => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            state.bind_local(name);
            format!(
                "{} {} = {}",
                if *mutable { "let" } else { "const" },
                sanitize_identifier(name),
                expr
            )
        }
        ast::Stmt::Assign { target, value } => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            format!("{} = {}", emit_name_ref(state, target), expr)
        }
        ast::Stmt::CompoundAssign { target, op, value } => {
            let expr = emit_expr(state, function_name, value, source_path, line)?;
            format!(
                "{} {}= {}",
                emit_name_ref(state, target),
                binary_op_to_js(*op),
                expr
            )
        }
        other => {
            state.unsupported(
                function_name,
                source_path,
                line,
                &format!("for-loop fragment `{other:?}`"),
                "use let/assignment/compound-assignment fragments inside `for` for js backend v1",
            );
            return Err(anyhow!("unsupported for-loop fragment"));
        }
    })
}

fn emit_match_stmt(
    state: &mut EmissionState,
    function_name: &str,
    scrutinee: &ast::Expr,
    arms: &[ast::MatchArm],
    source_index: usize,
    line: usize,
    source_path: &Path,
) -> Result<()> {
    let scrutinee = emit_expr(state, function_name, scrutinee, source_path, line)?;
    let temp = state.next_temp("__fz_scrutinee");
    state.push_line(
        format!("const {temp} = {scrutinee};"),
        source_index,
        line,
        Some(function_name),
    );
    for (index, arm) in arms.iter().enumerate() {
        let Some(condition) = emit_pattern_condition(pattern_head(arm), &temp) else {
            state.unsupported(
                function_name,
                source_path,
                line,
                "match statement pattern",
                "use wildcard, literal, struct, or enum-variant patterns for js backend v1",
            );
            return Err(anyhow!("unsupported match pattern"));
        };
        let guard_suffix = if let Some(guard) = &arm.guard {
            format!(
                " && ({})",
                emit_expr(state, function_name, guard, source_path, line)?
            )
        } else {
            String::new()
        };
        state.push_line(
            format!(
                "{} ({condition}{guard_suffix}) {{",
                if index == 0 { "if" } else { "else if" }
            ),
            source_index,
            line,
            Some(function_name),
        );
        state.indent += 1;
        state.push_scope(Vec::<String>::new());
        emit_pattern_bindings(state, &arm.pattern, &temp, false, source_index, line);
        let expr = emit_expr(state, function_name, &arm.value, source_path, line)?;
        if arm.returns {
            state.push_line(
                format!("return {expr};"),
                source_index,
                line,
                Some(function_name),
            );
        } else {
            state.push_line(format!("{expr};"), source_index, line, Some(function_name));
        }
        state.pop_scope();
        state.indent -= 1;
        state.push_line("}", source_index, line, Some(function_name));
    }
    state.push_line("else {", source_index, line, Some(function_name));
    state.indent += 1;
    state.push_line(
        "return __fz_match_error(\"statement match\");",
        source_index,
        line,
        Some(function_name),
    );
    state.indent -= 1;
    state.push_line("}", source_index, line, Some(function_name));
    Ok(())
}

fn emit_expr(
    state: &mut EmissionState,
    function_name: &str,
    expr: &ast::Expr,
    source_path: &Path,
    line: usize,
) -> Result<String> {
    Ok(match expr {
        ast::Expr::Int(value) => value.to_string(),
        ast::Expr::Float { value, .. } => {
            if value.is_finite() {
                value.to_string()
            } else if value.is_nan() {
                "Number.NaN".to_string()
            } else if value.is_sign_negative() {
                "-Infinity".to_string()
            } else {
                "Infinity".to_string()
            }
        }
        ast::Expr::Char(value) => js_string(&value.to_string()),
        ast::Expr::Bool(value) => value.to_string(),
        ast::Expr::Str(value) => js_string(value),
        ast::Expr::Ident(name) => emit_name_ref(state, name),
        ast::Expr::Call { callee, args } => {
            let rendered_args = args
                .iter()
                .map(|arg| emit_expr(state, function_name, arg, source_path, line))
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            let callee_base = strip_generic_suffix(callee);
            if callee_base == "import" {
                format!("import({rendered_args})")
            } else if hir::is_runtime_intrinsic(callee_base) {
                format!(
                    "__fz_intrinsic({})({rendered_args})",
                    js_string(callee_base)
                )
            } else {
                format!("{}({rendered_args})", emit_name_ref(state, callee))
            }
        }
        ast::Expr::UnsafeBlock { body, .. } => {
            emit_iife_block(state, function_name, body, source_path, line, None)?
        }
        ast::Expr::FieldAccess { base, field } => {
            format!(
                "{}.{}",
                emit_expr(state, function_name, base, source_path, line)?,
                sanitize_identifier(field)
            )
        }
        ast::Expr::StructInit { fields, .. } | ast::Expr::ObjectLiteral(fields) => {
            format!(
                "{{ {} }}",
                fields
                    .iter()
                    .map(|(field, value)| Ok(format!(
                        "{}: {}",
                        sanitize_identifier(field),
                        emit_expr(state, function_name, value, source_path, line)?
                    )))
                    .collect::<Result<Vec<_>>>()?
                    .join(", ")
            )
        }
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => {
            let enum_ref = emit_name_ref(state, enum_name);
            if !named_payload.is_empty() {
                let args = named_payload
                    .iter()
                    .map(|(_, value)| emit_expr(state, function_name, value, source_path, line))
                    .collect::<Result<Vec<_>>>()?
                    .join(", ");
                format!("{enum_ref}.{}({args})", sanitize_identifier(variant))
            } else if payload.is_empty() {
                format!("{enum_ref}.{}", sanitize_identifier(variant))
            } else {
                let args = payload
                    .iter()
                    .map(|value| emit_expr(state, function_name, value, source_path, line))
                    .collect::<Result<Vec<_>>>()?
                    .join(", ");
                format!("{enum_ref}.{}({args})", sanitize_identifier(variant))
            }
        }
        ast::Expr::Closure { params, body, .. } => {
            state.push_scope(params.iter().map(|param| param.name.clone()));
            let params = params
                .iter()
                .map(|param| sanitize_identifier(&param.name))
                .collect::<Vec<_>>()
                .join(", ");
            let body = emit_expr(state, function_name, body, source_path, line)?;
            state.pop_scope();
            format!("({params}) => ({body})")
        }
        ast::Expr::Group(inner) => format!(
            "({})",
            emit_expr(state, function_name, inner, source_path, line)?
        ),
        ast::Expr::Await(inner) => format!(
            "await {}",
            emit_expr(state, function_name, inner, source_path, line)?
        ),
        ast::Expr::Discard(inner) => format!(
            "void ({})",
            emit_expr(state, function_name, inner, source_path, line)?
        ),
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => format!(
            "(() => {{ try {{ return {}; }} catch (_error) {{ return {}; }} }})()",
            emit_expr(state, function_name, try_expr, source_path, line)?,
            emit_expr(state, function_name, catch_expr, source_path, line)?,
        ),
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => format!(
            "(({}) ? ({}) : ({}))",
            emit_expr(state, function_name, condition, source_path, line)?,
            emit_expr(state, function_name, then_expr, source_path, line)?,
            emit_expr(state, function_name, else_expr, source_path, line)?,
        ),
        ast::Expr::Match { scrutinee, arms } => {
            emit_match_expr(state, function_name, scrutinee, arms, source_path, line)?
        }
        ast::Expr::While { condition, body } => {
            let condition = emit_expr(state, function_name, condition, source_path, line)?;
            emit_iife_block(
                state,
                function_name,
                body,
                source_path,
                line,
                Some(format!("while ({condition})")),
            )?
        }
        ast::Expr::For {
            init,
            condition,
            step,
            body,
        } => {
            let init = init
                .as_deref()
                .map(|stmt| emit_for_fragment(state, function_name, stmt, source_path, line))
                .transpose()?
                .unwrap_or_default();
            let condition = condition
                .as_ref()
                .map(|expr| emit_expr(state, function_name, expr, source_path, line))
                .transpose()?
                .unwrap_or_else(|| "true".to_string());
            let step = step
                .as_deref()
                .map(|stmt| emit_for_fragment(state, function_name, stmt, source_path, line))
                .transpose()?
                .unwrap_or_default();
            emit_iife_block(
                state,
                function_name,
                body,
                source_path,
                line,
                Some(format!("for ({init}; {condition}; {step})")),
            )?
        }
        ast::Expr::ForIn {
            binding,
            iterable,
            body,
        } => {
            let iterable = emit_expr(state, function_name, iterable, source_path, line)?;
            emit_iife_block(
                state,
                function_name,
                body,
                source_path,
                line,
                Some(format!(
                    "for (const {} of {iterable})",
                    sanitize_identifier(binding),
                )),
            )?
        }
        ast::Expr::Loop { body } => emit_iife_block(
            state,
            function_name,
            body,
            source_path,
            line,
            Some("while (true)".to_string()),
        )?,
        ast::Expr::Break(value) => {
            if let Some(value) = value {
                format!(
                    "(() => {{ return {}; }})()",
                    emit_expr(state, function_name, value, source_path, line)?
                )
            } else {
                "undefined".to_string()
            }
        }
        ast::Expr::Continue => "undefined".to_string(),
        ast::Expr::Return(value) => {
            if let Some(value) = value {
                format!(
                    "(() => {{ return {}; }})()",
                    emit_expr(state, function_name, value, source_path, line)?
                )
            } else {
                "undefined".to_string()
            }
        }
        ast::Expr::Range {
            start,
            end,
            inclusive,
        } => format!(
            "{{ start: {}, end: {}, inclusive: {} }}",
            emit_expr(state, function_name, start, source_path, line)?,
            emit_expr(state, function_name, end, source_path, line)?,
            inclusive
        ),
        ast::Expr::ArrayLiteral(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|item| emit_expr(state, function_name, item, source_path, line))
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        ast::Expr::Index { base, index } => format!(
            "{}[{}]",
            emit_expr(state, function_name, base, source_path, line)?,
            emit_expr(state, function_name, index, source_path, line)?
        ),
        ast::Expr::Unary { op, expr } => format!(
            "({}{})",
            unary_op_to_js(*op),
            emit_expr(state, function_name, expr, source_path, line)?
        ),
        ast::Expr::Binary { op, left, right } => format!(
            "(({}) {} ({}))",
            emit_expr(state, function_name, left, source_path, line)?,
            binary_op_to_js(*op),
            emit_expr(state, function_name, right, source_path, line)?
        ),
    })
}

fn emit_iife_block(
    state: &mut EmissionState,
    function_name: &str,
    body: &[ast::Stmt],
    source_path: &Path,
    line: usize,
    header: Option<String>,
) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(ref header) = header {
        parts.push(format!("{header} {{"));
    }
    let mut local = state.clone();
    local.lines.clear();
    local.mappings.clear();
    local.indent = 0;
    local.push_scope(Vec::<String>::new());
    for stmt in body {
        emit_stmt(&mut local, function_name, stmt, source_path, 0, line)?;
    }
    local.pop_scope();
    for rendered in local.lines {
        parts.push(rendered.trim().to_string());
    }
    if header.is_some() {
        parts.push("}".to_string());
    }
    Ok(format!("(() => {{ {} }})()", parts.join(" ")))
}

fn emit_match_expr(
    state: &mut EmissionState,
    function_name: &str,
    scrutinee: &ast::Expr,
    arms: &[ast::MatchArm],
    source_path: &Path,
    line: usize,
) -> Result<String> {
    let scrutinee = emit_expr(state, function_name, scrutinee, source_path, line)?;
    let temp = state.next_temp("__fz_scrutinee");
    let mut out = format!("(() => {{ const {temp} = {scrutinee}; ");
    for (index, arm) in arms.iter().enumerate() {
        let Some(condition) = emit_pattern_condition(pattern_head(arm), &temp) else {
            state.unsupported(
                function_name,
                source_path,
                line,
                "match expression pattern",
                "use wildcard, literal, struct, or enum-variant patterns for js backend v1",
            );
            return Err(anyhow!("unsupported match expression"));
        };
        let guard_suffix = if let Some(guard) = &arm.guard {
            format!(
                " && ({})",
                emit_expr(state, function_name, guard, source_path, line)?
            )
        } else {
            String::new()
        };
        if index == 0 {
            out.push_str(&format!("if ({condition}{guard_suffix}) {{ "));
        } else {
            out.push_str(&format!("else if ({condition}{guard_suffix}) {{ "));
        }
        out.push_str(&render_pattern_bindings_inline(&arm.pattern, &temp));
        out.push_str(&format!(
            "return {}; }} ",
            emit_expr(state, function_name, &arm.value, source_path, line)?
        ));
    }
    out.push_str("return __fz_match_error(\"expression match\"); })()");
    Ok(out)
}

fn emit_pattern_bindings(
    state: &mut EmissionState,
    pattern: &ast::Pattern,
    source: &str,
    mutable: bool,
    source_index: usize,
    line: usize,
) {
    match pattern {
        ast::Pattern::Ident(name) if name != "_" => {
            state.bind_local(name);
            state.push_line(
                format!(
                    "{} {} = {source};",
                    if mutable { "let" } else { "const" },
                    sanitize_identifier(name)
                ),
                source_index,
                line,
                Some(name),
            );
        }
        ast::Pattern::Struct { fields, .. } => {
            for (field, binding) in fields {
                if binding == "_" {
                    continue;
                }
                state.bind_local(binding);
                state.push_line(
                    format!(
                        "{} {} = {source}.{};",
                        if mutable { "let" } else { "const" },
                        sanitize_identifier(binding),
                        sanitize_identifier(field)
                    ),
                    source_index,
                    line,
                    Some(binding),
                );
            }
        }
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => {
            for (index, binding) in bindings.iter().enumerate() {
                if binding == "_" {
                    continue;
                }
                state.bind_local(binding);
                state.push_line(
                    format!(
                        "{} {} = {source}.$values[{}];",
                        if mutable { "let" } else { "const" },
                        sanitize_identifier(binding),
                        index
                    ),
                    source_index,
                    line,
                    Some(binding),
                );
            }
            for (field, binding) in named_bindings {
                if binding == "_" {
                    continue;
                }
                state.bind_local(binding);
                state.push_line(
                    format!(
                        "{} {} = {source}.{};",
                        if mutable { "let" } else { "const" },
                        sanitize_identifier(binding),
                        sanitize_identifier(field)
                    ),
                    source_index,
                    line,
                    Some(binding),
                );
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(first) = patterns.first() {
                emit_pattern_bindings(state, first, source, mutable, source_index, line);
            }
        }
        ast::Pattern::Ident(_)
        | ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_) => {}
    }
}

fn render_pattern_bindings_inline(pattern: &ast::Pattern, source: &str) -> String {
    let mut out = String::new();
    match pattern {
        ast::Pattern::Ident(name) if name != "_" => {
            let _ = write!(out, "const {} = {source}; ", sanitize_identifier(name));
        }
        ast::Pattern::Struct { fields, .. } => {
            for (field, binding) in fields {
                if binding == "_" {
                    continue;
                }
                let _ = write!(
                    out,
                    "const {} = {source}.{}; ",
                    sanitize_identifier(binding),
                    sanitize_identifier(field)
                );
            }
        }
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => {
            for (index, binding) in bindings.iter().enumerate() {
                if binding == "_" {
                    continue;
                }
                let _ = write!(
                    out,
                    "const {} = {source}.$values[{}]; ",
                    sanitize_identifier(binding),
                    index
                );
            }
            for (field, binding) in named_bindings {
                if binding == "_" {
                    continue;
                }
                let _ = write!(
                    out,
                    "const {} = {source}.{}; ",
                    sanitize_identifier(binding),
                    sanitize_identifier(field)
                );
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(first) = patterns.first() {
                out.push_str(&render_pattern_bindings_inline(first, source));
            }
        }
        ast::Pattern::Ident(_)
        | ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_) => {}
    }
    out
}

fn emit_pattern_condition(pattern: &ast::Pattern, source: &str) -> Option<String> {
    Some(match pattern {
        ast::Pattern::Wildcard => "true".to_string(),
        ast::Pattern::Int(value) => format!("{source} === {value}"),
        ast::Pattern::Bool(value) => format!("{source} === {}", if *value { "true" } else { "false" }),
        ast::Pattern::Ident(_) => "true".to_string(),
        ast::Pattern::Struct { fields, .. } => {
            let mut parts = vec![
                format!("typeof {source} === \"object\""),
                format!("{source} !== null"),
            ];
            for (field, _) in fields {
                parts.push(format!(
                    "Object.prototype.hasOwnProperty.call({source}, {})",
                    js_string(field)
                ));
            }
            parts.join(" && ")
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            ..
        } => format!(
            "typeof {source} === \"object\" && {source} !== null && {source}.$enum === {} && {source}.$variant === {}",
            js_string(enum_name),
            js_string(variant)
        ),
        ast::Pattern::Or(patterns) => patterns
            .iter()
            .filter_map(|pattern| emit_pattern_condition(pattern, source))
            .collect::<Vec<_>>()
            .join(" || "),
    })
}

fn pattern_head(arm: &ast::MatchArm) -> &ast::Pattern {
    &arm.pattern
}

fn emit_namespace_assignments(
    state: &mut EmissionState,
    parsed: &ParsedProgram,
    typed: &hir::TypedModule,
    root_index: usize,
) {
    let mut assigned = BTreeSet::new();
    for symbol in parsed
        .module
        .items
        .iter()
        .filter_map(item_symbol_name)
        .chain(
            typed
                .typed_functions
                .iter()
                .map(|function| function.name.as_str()),
        )
    {
        let segments = split_path(symbol);
        if segments.len() < 2 {
            continue;
        }
        let Some(symbol_ref) = state.symbol_ref(symbol) else {
            continue;
        };
        let path = namespace_path(&segments);
        if assigned.insert((path.clone(), symbol_ref.clone())) {
            state.push_line(
                format!("{path} = {symbol_ref};"),
                root_index,
                1,
                Some(symbol),
            );
        }
    }
    if !assigned.is_empty() {
        state.push_line("", root_index, 1, None);
    }
}

fn emit_exports(
    state: &mut EmissionState,
    parsed: &ParsedProgram,
    _typed: &hir::TypedModule,
    root_index: usize,
) {
    let mut exports = BTreeSet::<String>::new();
    for item in &parsed.module.items {
        match item {
            ast::Item::Function(function) if function.is_pub => {
                if let Some(symbol) = state.symbol_ref(&function.name) {
                    exports.insert(symbol);
                }
            }
            ast::Item::Const(item) if item.is_pub => {
                if let Some(symbol) = state.symbol_ref(&item.name) {
                    exports.insert(symbol);
                }
            }
            ast::Item::Static(item) if item.is_pub => {
                if let Some(symbol) = state.symbol_ref(&item.name) {
                    exports.insert(symbol);
                }
            }
            ast::Item::Enum(item) if item.is_pub => {
                if let Some(symbol) = state.symbol_ref(&item.name) {
                    exports.insert(symbol);
                }
            }
            ast::Item::Struct(item) if item.is_pub => {
                if let Some(root) = split_path(&item.name).first() {
                    exports.insert(sanitize_identifier(root));
                }
            }
            _ => {}
        }
    }
    for root in &state.namespace_roots {
        exports.insert(sanitize_identifier(root));
    }
    if exports.is_empty() {
        return;
    }
    state.push_line("export {", root_index, 1, None);
    state.indent += 1;
    for export in exports {
        state.push_line(format!("{export},"), root_index, 1, None);
    }
    state.indent -= 1;
    state.push_line("};", root_index, 1, None);
}

fn load_source_files(parsed: &ParsedProgram, root_source: &Path) -> Result<Vec<SourceFile>> {
    let root_dir = root_source.parent().unwrap_or_else(|| Path::new("."));
    parsed
        .module_paths
        .iter()
        .map(|path| {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed reading source file: {}", path.display()))?;
            let relative = path
                .strip_prefix(root_dir)
                .ok()
                .map(|value| value.display().to_string())
                .unwrap_or_else(|| path.display().to_string())
                .replace('\\', "/");
            Ok(SourceFile {
                path: path.clone(),
                relative,
                content,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn collect_item_sources(
    parsed: &ParsedProgram,
    source_files: &[SourceFile],
    root_source: &Path,
) -> Result<HashMap<String, ItemSourceInfo>> {
    let mut out = HashMap::new();
    for (source_index, source_file) in source_files.iter().enumerate() {
        let namespace = super::module_namespace(root_source, &source_file.path)?;
        let lines = source_file.content.lines().collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            for keyword in ["fn ", "const ", "static ", "enum ", "struct ", "trait "] {
                if let Some(name) = parse_decl_name(trimmed, keyword) {
                    let qualified = if namespace.is_empty() {
                        name.clone()
                    } else {
                        format!("{namespace}.{name}")
                    };
                    let info = ItemSourceInfo {
                        source_index,
                        start_line: index + 1,
                        end_line: find_block_end(&lines, index + 1),
                    };
                    out.insert(name.clone(), info.clone());
                    out.insert(qualified, info);
                }
            }
        }
    }
    for symbol in parsed.module.items.iter().filter_map(item_symbol_name) {
        out.entry(symbol.to_string()).or_insert(ItemSourceInfo {
            source_index: 0,
            start_line: 1,
            end_line: 1,
        });
    }
    Ok(out)
}

fn parse_decl_name(line: &str, needle: &str) -> Option<String> {
    let idx = line.find(needle)?;
    let after = &line[idx + needle.len()..];
    let mut name = String::new();
    for ch in after.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            break;
        }
    }
    (!name.is_empty()).then_some(name)
}

fn find_block_end(lines: &[&str], start_line: usize) -> usize {
    let mut saw_open = false;
    let mut depth = 0isize;
    for (offset, line) in lines.iter().enumerate().skip(start_line.saturating_sub(1)) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                saw_open = true;
            } else if ch == '}' {
                depth -= 1;
                if saw_open && depth <= 0 {
                    return offset + 1;
                }
            }
        }
        if !saw_open && line.trim_end().ends_with(';') {
            return offset + 1;
        }
    }
    lines.len().max(start_line)
}

fn build_symbol_name_map(
    parsed: &ParsedProgram,
    typed: &hir::TypedModule,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for symbol in parsed.module.items.iter().filter_map(item_symbol_name) {
        out.insert(symbol.to_string(), symbol_identifier(symbol));
    }
    for function in &typed.typed_functions {
        out.insert(function.name.clone(), symbol_identifier(&function.name));
    }
    out
}

fn build_sourcemap_json(
    state: &EmissionState,
    source_files: &[SourceFile],
    file_name: &str,
    typed: &hir::TypedModule,
) -> Result<String> {
    let mappings = encode_mappings(&state.mappings);
    let async_functions = typed
        .typed_functions
        .iter()
        .filter(|function| function.is_async)
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "version": 3,
        "file": format!("{file_name}.js"),
        "sources": source_files.iter().map(|source| source.relative.clone()).collect::<Vec<_>>(),
        "sourcesContent": source_files.iter().map(|source| source.content.clone()).collect::<Vec<_>>(),
        "names": state.names,
        "mappings": mappings,
        "x_fozzy": {
            "schemaVersion": "fozzylang.js.debug.v1",
            "mappedLines": state.mappings.len(),
            "generatedLines": state.lines.len(),
            "asyncFunctions": async_functions,
        }
    })
    .to_string())
}

fn encode_mappings(entries: &[MappingEntry]) -> String {
    let mut by_line = BTreeMap::<usize, Vec<&MappingEntry>>::new();
    for entry in entries {
        by_line.entry(entry.generated_line).or_default().push(entry);
    }
    let last_line = entries
        .iter()
        .map(|entry| entry.generated_line)
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    let mut prev_source = 0i64;
    let mut prev_original_line = 0i64;
    let mut prev_original_col = 0i64;
    let mut prev_name = 0i64;
    for line in 0..=last_line {
        if line > 0 {
            out.push(';');
        }
        let mut prev_generated_col = 0i64;
        let Some(items) = by_line.get(&line) else {
            continue;
        };
        for (idx, entry) in items.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(&encode_vlq(entry.generated_col as i64 - prev_generated_col));
            prev_generated_col = entry.generated_col as i64;
            out.push_str(&encode_vlq(entry.source_index as i64 - prev_source));
            prev_source = entry.source_index as i64;
            out.push_str(&encode_vlq(entry.original_line as i64 - prev_original_line));
            prev_original_line = entry.original_line as i64;
            out.push_str(&encode_vlq(entry.original_col as i64 - prev_original_col));
            prev_original_col = entry.original_col as i64;
            if let Some(name_index) = entry.name_index {
                out.push_str(&encode_vlq(name_index as i64 - prev_name));
                prev_name = name_index as i64;
            }
        }
    }
    out
}

const BASE64_VLQ: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_vlq(value: i64) -> String {
    let mut value = if value < 0 {
        ((-value) << 1) + 1
    } else {
        value << 1
    };
    let mut out = String::new();
    loop {
        let mut digit = (value & 31) as usize;
        value >>= 5;
        if value > 0 {
            digit |= 32;
        }
        out.push(BASE64_VLQ[digit] as char);
        if value == 0 {
            break;
        }
    }
    out
}

fn item_symbol_name(item: &ast::Item) -> Option<&str> {
    match item {
        ast::Item::Function(item) => Some(item.name.as_str()),
        ast::Item::Const(item) => Some(item.name.as_str()),
        ast::Item::Static(item) => Some(item.name.as_str()),
        ast::Item::TypeAlias(item) => Some(item.name.as_str()),
        ast::Item::NewType(item) => Some(item.name.as_str()),
        ast::Item::Struct(item) => Some(item.name.as_str()),
        ast::Item::Enum(item) => Some(item.name.as_str()),
        ast::Item::Trait(item) => Some(item.name.as_str()),
        ast::Item::Impl(_) | ast::Item::Test(_) => None,
    }
}

fn emit_name_ref(state: &EmissionState, name: &str) -> String {
    let exact_segments = split_path(name);
    if exact_segments.len() == 1 && state.is_local(exact_segments[0]) {
        return sanitize_identifier(exact_segments[0]);
    }
    if let Some(symbol) = state.symbol_ref(name) {
        return symbol;
    }
    let base = strip_generic_suffix(name);
    let segments = split_path(base);
    if segments.len() == 1 && state.is_local(segments[0]) {
        sanitize_identifier(segments[0])
    } else if let Some(symbol) = state.symbol_ref(base) {
        symbol
    } else {
        symbol_identifier(base)
    }
}

fn strip_generic_suffix(name: &str) -> &str {
    name.split('<').next().unwrap_or(name)
}

fn split_path(name: &str) -> Vec<&str> {
    name.split('.')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn namespace_path(segments: &[&str]) -> String {
    if segments.len() < 2 {
        return sanitize_identifier(segments.first().copied().unwrap_or_default());
    }
    let mut rendered = sanitize_identifier(segments[0]);
    for segment in &segments[1..segments.len() - 1] {
        rendered.push('.');
        rendered.push_str(&sanitize_identifier(segment));
    }
    rendered.push('.');
    rendered.push_str(&sanitize_identifier(segments[segments.len() - 1]));
    rendered
}

fn symbol_identifier(name: &str) -> String {
    format!("__fz_{}", sanitize_identifier(name))
}

fn sanitize_identifier(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if (index == 0 && (ch.is_ascii_alphabetic() || ch == '_'))
            || (index > 0 && (ch.is_ascii_alphanumeric() || ch == '_'))
        {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".to_string()
    } else if is_reserved_js_word(&out) {
        format!("_{out}")
    } else {
        out
    }
}

fn is_reserved_js_word(value: &str) -> bool {
    matches!(
        value,
        "await"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "export"
            | "extends"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "new"
            | "return"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "try"
            | "typeof"
            | "var"
            | "void"
            | "while"
            | "with"
            | "yield"
            | "let"
            | "static"
    )
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<string-encode-error>\"".to_string())
}

fn binary_op_to_js(op: ast::BinaryOp) -> &'static str {
    match op {
        ast::BinaryOp::Add => "+",
        ast::BinaryOp::Sub => "-",
        ast::BinaryOp::Mul => "*",
        ast::BinaryOp::Div => "/",
        ast::BinaryOp::Mod => "%",
        ast::BinaryOp::BitAnd => "&",
        ast::BinaryOp::BitOr => "|",
        ast::BinaryOp::BitXor => "^",
        ast::BinaryOp::Shl => "<<",
        ast::BinaryOp::Shr => ">>",
        ast::BinaryOp::And => "&&",
        ast::BinaryOp::Or => "||",
        ast::BinaryOp::Lt => "<",
        ast::BinaryOp::Lte => "<=",
        ast::BinaryOp::Gt => ">",
        ast::BinaryOp::Gte => ">=",
        ast::BinaryOp::Eq => "===",
        ast::BinaryOp::Neq => "!==",
    }
}

fn unary_op_to_js(op: ast::UnaryOp) -> &'static str {
    match op {
        ast::UnaryOp::Not => "!",
        ast::UnaryOp::Plus => "+",
        ast::UnaryOp::Neg => "-",
        ast::UnaryOp::BitNot => "~",
    }
}
