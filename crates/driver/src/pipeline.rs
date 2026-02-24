use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{types, AbiParam, InstBuilder};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_module::{default_libcall_names, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    Dev,
    Release,
    Verify,
}

#[derive(Debug, Clone)]
pub struct BuildArtifact {
    pub module: String,
    pub profile: BuildProfile,
    pub status: &'static str,
    pub diagnostics: usize,
    pub output: Option<PathBuf>,
    pub dependency_graph_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub module: String,
    pub nodes: usize,
    pub diagnostics: usize,
    pub diagnostic_details: Vec<diagnostics::Diagnostic>,
    pub backend_ir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedProgram {
    pub module: ast::Module,
    pub combined_source: String,
    pub module_paths: Vec<PathBuf>,
}

pub fn compile_file(path: &Path, profile: BuildProfile) -> Result<BuildArtifact> {
    compile_file_with_backend(path, profile, None)
}

pub fn compile_file_with_backend(
    path: &Path,
    profile: BuildProfile,
    backend_override: Option<&str>,
) -> Result<BuildArtifact> {
    let resolved = resolve_source_path(path)?;
    let parsed = parse_program(&resolved.source_path)?;
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify_with_policy(
        &fir,
        verifier::VerifyPolicy {
            safe_profile: matches!(profile, BuildProfile::Verify),
        },
    );

    let checks_enabled = resolved
        .manifest
        .as_ref()
        .and_then(|manifest| profile_config(manifest, profile).and_then(|config| config.checks))
        .unwrap_or(true);
    let has_errors = report
        .diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, diagnostics::Severity::Error));
    let status = if checks_enabled && has_errors {
        "error"
    } else {
        "ok"
    };
    let output = if status == "ok" {
        Some(emit_native_artifact(
            &fir,
            &resolved.project_root,
            profile,
            resolved.manifest.as_ref(),
            backend_override,
        )?)
    } else {
        None
    };

    Ok(BuildArtifact {
        module: fir.name,
        profile,
        status,
        diagnostics: report.diagnostics.len(),
        output,
        dependency_graph_hash: resolved.dependency_graph_hash,
    })
}

pub fn verify_file(path: &Path) -> Result<Output> {
    let resolved = resolve_source_path(path)?;
    let module_name = resolved
        .source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;
    let parsed = match parse_program(&resolved.source_path) {
        Ok(parsed) => parsed,
        Err(error) => {
            let diagnostics =
                collect_parse_diagnostics(&resolved.source_path).unwrap_or_else(|_| {
                    vec![diagnostics::Diagnostic::new(
                        diagnostics::Severity::Error,
                        error.to_string(),
                        None,
                    )]
                });
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: diagnostics.len(),
                diagnostic_details: diagnostics,
                backend_ir: None,
            });
        }
    };
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify(&fir);
    let diagnostics = report.diagnostics;

    Ok(Output {
        module: fir.name,
        nodes: fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: None,
    })
}

pub fn emit_ir(path: &Path) -> Result<Output> {
    let resolved = resolve_source_path(path)?;
    let source_path = resolved.source_path;
    let module_name = source_path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("invalid module filename"))?;

    let parsed = match parse_program(&source_path) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(Output {
                module: module_name.to_string(),
                nodes: 0,
                diagnostics: 1,
                diagnostic_details: vec![diagnostics::Diagnostic::new(
                    diagnostics::Severity::Error,
                    error.to_string(),
                    None,
                )],
                backend_ir: None,
            });
        }
    };
    let typed = hir::lower(&parsed.module);
    let fir = fir::build(&typed);
    let report = verifier::verify(&fir);
    let diagnostics = report.diagnostics;
    let llvm = lower_backend_ir(&fir, BackendKind::Llvm);
    let cranelift = lower_backend_ir(&fir, BackendKind::Cranelift);

    Ok(Output {
        module: fir.name,
        nodes: fir.nodes,
        diagnostics: diagnostics.len(),
        diagnostic_details: diagnostics,
        backend_ir: Some(format!(
            "; backend=llvm\n{llvm}\n; backend=cranelift\n{cranelift}\n"
        )),
    })
}

pub fn parse_program(source_path: &Path) -> Result<ParsedProgram> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut state = ModuleLoadState::default();
    load_module_recursive(&canonical, &mut state)?;

    let root = state
        .loaded
        .get(&canonical)
        .ok_or_else(|| anyhow!("failed to load root module {}", canonical.display()))?;
    let mut merged = root.ast.clone();
    let mut combined_source = String::new();

    for path in &state.load_order {
        let loaded = state
            .loaded
            .get(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        combined_source.push_str("// module: ");
        combined_source.push_str(&loaded.path.display().to_string());
        combined_source.push('\n');
        combined_source.push_str(&loaded.source);
        if !loaded.source.ends_with('\n') {
            combined_source.push('\n');
        }
    }

    for path in state.load_order.iter().filter(|path| **path != canonical) {
        let loaded = state
            .loaded
            .get(path)
            .ok_or_else(|| anyhow!("internal module cache miss for {}", path.display()))?;
        merge_module(&mut merged, &loaded.ast);
    }

    Ok(ParsedProgram {
        module: merged,
        combined_source,
        module_paths: state.load_order,
    })
}

#[derive(Debug, Clone)]
struct LoadedModule {
    ast: ast::Module,
    source: String,
    path: PathBuf,
}

#[derive(Debug, Default)]
struct ModuleLoadState {
    loaded: HashMap<PathBuf, LoadedModule>,
    load_order: Vec<PathBuf>,
    visiting: Vec<PathBuf>,
    visiting_set: HashSet<PathBuf>,
}

fn load_module_recursive(path: &Path, state: &mut ModuleLoadState) -> Result<()> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if state.loaded.contains_key(&canonical) {
        return Ok(());
    }
    if state.visiting_set.contains(&canonical) {
        let cycle = format_module_cycle(&state.visiting, &canonical);
        return Err(anyhow!("cyclic module declaration detected: {}", cycle));
    }

    state.visiting_set.insert(canonical.clone());
    state.visiting.push(canonical.clone());

    let source = std::fs::read_to_string(&canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = parser::parse(&source, module_name)
        .map_err(|diagnostics| anyhow!(render_parse_failure(&canonical, &diagnostics)))?;

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
        load_module_recursive(&module_path, state)?;
    }

    state.visiting.pop();
    state.visiting_set.remove(&canonical);
    state.load_order.push(canonical.clone());
    state.loaded.insert(
        canonical.clone(),
        LoadedModule {
            ast,
            source,
            path: canonical,
        },
    );
    Ok(())
}

fn collect_parse_diagnostics(source_path: &Path) -> Result<Vec<diagnostics::Diagnostic>> {
    let canonical = source_path
        .canonicalize()
        .with_context(|| format!("failed resolving source file: {}", source_path.display()))?;
    let mut visited = HashSet::<PathBuf>::new();
    let mut visiting = HashSet::<PathBuf>::new();
    match collect_parse_diagnostics_recursive(&canonical, &mut visited, &mut visiting)? {
        Some((failed_path, diagnostics)) => Ok(diagnostics
            .into_iter()
            .map(|diagnostic| annotate_parse_diagnostic(diagnostic, &failed_path))
            .collect()),
        None => Ok(Vec::new()),
    }
}

fn collect_parse_diagnostics_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    visiting: &mut HashSet<PathBuf>,
) -> Result<Option<(PathBuf, Vec<diagnostics::Diagnostic>)>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed resolving module path: {}", path.display()))?;
    if visited.contains(&canonical) || visiting.contains(&canonical) {
        return Ok(None);
    }
    visiting.insert(canonical.clone());
    let source = std::fs::read_to_string(&canonical)
        .with_context(|| format!("failed reading source file: {}", canonical.display()))?;
    let module_name = canonical
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid module filename for {}", canonical.display()))?;
    let ast = match parser::parse(&source, module_name) {
        Ok(ast) => ast,
        Err(diagnostics) => return Ok(Some((canonical.clone(), diagnostics))),
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
        if let Some(failure) = collect_parse_diagnostics_recursive(&module_path, visited, visiting)?
        {
            return Ok(Some(failure));
        }
    }
    visiting.remove(&canonical);
    Ok(None)
}

fn annotate_parse_diagnostic(
    mut diagnostic: diagnostics::Diagnostic,
    module_path: &Path,
) -> diagnostics::Diagnostic {
    let mut help = diagnostic.help.unwrap_or_default();
    if !help.is_empty() {
        help.push(' ');
    }
    help.push_str(&format!("source: {}", module_path.display()));
    diagnostic.help = Some(help);
    diagnostic
}

fn render_parse_failure(path: &Path, diagnostics: &[diagnostics::Diagnostic]) -> String {
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

fn resolve_declared_module(base_dir: &Path, module_decl: &str) -> Result<PathBuf> {
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

fn merge_module(root: &mut ast::Module, module: &ast::Module) {
    root.items.extend(module.items.iter().cloned());
    root.modules.extend(module.modules.iter().cloned());
    root.imports.extend(module.imports.iter().cloned());
    root.capabilities
        .extend(module.capabilities.iter().cloned());
    root.host_syscall_sites += module.host_syscall_sites;
    root.unsafe_reasoned_sites += module.unsafe_reasoned_sites;
}

fn format_module_cycle(stack: &[PathBuf], repeated: &Path) -> String {
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

#[derive(Debug, Clone, Copy)]
enum BackendKind {
    Llvm,
    Cranelift,
}

fn lower_backend_ir(fir: &fir::FirModule, backend: BackendKind) -> String {
    match backend {
        BackendKind::Llvm => lower_llvm_ir(fir, true),
        BackendKind::Cranelift => lower_cranelift_ir(fir, true),
    }
}

fn lower_llvm_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> String {
    let forced_main_return = if enforce_contract_checks {
        if fir
            .entry_requires
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            Some(120)
        } else if fir
            .entry_ensures
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            Some(121)
        } else {
            None
        }
    } else {
        None
    };
    if fir.typed_functions.is_empty() {
        let ret = forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return format!(
            "; ModuleID = '{name}'\ndefine i32 @main() {{\nentry:\n  ret i32 {ret}\n}}\n",
            name = fir.name
        );
    }

    let mut out = format!("; ModuleID = '{}'\n", fir.name);
    for function in &fir.typed_functions {
        out.push_str(&llvm_emit_function(
            function,
            forced_main_return.filter(|_| function.name == "main"),
        ));
        out.push('\n');
    }
    out
}

fn lower_cranelift_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> String {
    let ret = if enforce_contract_checks {
        if fir
            .entry_requires
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            120
        } else if fir
            .entry_ensures
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            121
        } else {
            fir.entry_return_const_i32.unwrap_or(0)
        }
    } else {
        fir.entry_return_const_i32.unwrap_or(0)
    };
    format!("function %main() -> i32 {{\nblock0:\n  v0 = iconst.i32 {ret}\n  return v0\n}}\n")
}

struct LlvmFuncCtx {
    next_value: usize,
    next_label: usize,
    slots: HashMap<String, String>,
    code: String,
}

impl LlvmFuncCtx {
    fn new() -> Self {
        Self {
            next_value: 0,
            next_label: 0,
            slots: HashMap::new(),
            code: String::new(),
        }
    }

    fn value(&mut self) -> String {
        let id = self.next_value;
        self.next_value += 1;
        format!("%v{id}")
    }

    fn label(&mut self, prefix: &str) -> String {
        let id = self.next_label;
        self.next_label += 1;
        format!("{prefix}.{id}")
    }
}

fn llvm_emit_function(function: &hir::TypedFunction, forced_return: Option<i32>) -> String {
    let params = function
        .params
        .iter()
        .enumerate()
        .map(|(i, _)| format!("i32 %arg{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut ctx = LlvmFuncCtx::new();
    let mut out = format!("define i32 @{}({params}) {{\nentry:\n", function.name);
    for (index, param) in function.params.iter().enumerate() {
        let slot = format!("%slot_{}", param.name);
        ctx.code.push_str(&format!(
            "  {slot} = alloca i32\n  store i32 %arg{index}, ptr {slot}\n"
        ));
        ctx.slots.insert(param.name.clone(), slot);
    }
    let terminated = llvm_emit_block(&function.body, &mut ctx);
    out.push_str(&ctx.code);
    if !terminated {
        let fallback = forced_return.unwrap_or(0);
        out.push_str(&format!("  ret i32 {fallback}\n"));
    }
    out.push_str("}\n");
    out
}

fn llvm_emit_block(body: &[ast::Stmt], ctx: &mut LlvmFuncCtx) -> bool {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                let rendered = llvm_emit_expr(value, ctx);
                let slot = format!("%slot_{}_{}", name, ctx.next_value);
                ctx.code.push_str(&format!(
                    "  {slot} = alloca i32\n  store i32 {rendered}, ptr {slot}\n"
                ));
                ctx.slots.insert(name.clone(), slot);
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value = llvm_emit_expr(field_expr, ctx);
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.code.push_str(&format!(
                            "  {field_slot} = alloca i32\n  store i32 {field_value}, ptr {field_slot}\n"
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                    }
                }
            }
            ast::Stmt::Assign { target, value } => {
                let value = llvm_emit_expr(value, ctx);
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                if !ctx.code.contains(&format!("{slot} = alloca i32")) {
                    ctx.code.push_str(&format!("  {slot} = alloca i32\n"));
                }
                ctx.code
                    .push_str(&format!("  store i32 {value}, ptr {slot}\n"));
            }
            ast::Stmt::Return(expr) => {
                let value = llvm_emit_expr(expr, ctx);
                ctx.code.push_str(&format!("  ret i32 {value}\n"));
                return true;
            }
            ast::Stmt::Expr(expr)
            | ast::Stmt::Requires(expr)
            | ast::Stmt::Ensures(expr)
            | ast::Stmt::Defer(expr) => {
                let _ = llvm_emit_expr(expr, ctx);
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let cond = llvm_emit_expr(condition, ctx);
                let pred = ctx.value();
                let then_label = ctx.label("then");
                let else_label = ctx.label("else");
                let cont_label = ctx.label("ifend");
                ctx.code.push_str(&format!(
                    "  {pred} = icmp ne i32 {cond}, 0\n  br i1 {pred}, label %{then_label}, label %{else_label}\n{then_label}:\n"
                ));
                let then_terminated = llvm_emit_block(then_body, ctx);
                if !then_terminated {
                    ctx.code.push_str(&format!("  br label %{cont_label}\n"));
                }
                ctx.code.push_str(&format!("{else_label}:\n"));
                let else_terminated = llvm_emit_block(else_body, ctx);
                if !else_terminated {
                    ctx.code.push_str(&format!("  br label %{cont_label}\n"));
                }
                if then_terminated && else_terminated {
                    return true;
                }
                ctx.code.push_str(&format!("{cont_label}:\n"));
            }
            ast::Stmt::While { condition, body } => {
                let head_label = ctx.label("while_head");
                let body_label = ctx.label("while_body");
                let end_label = ctx.label("while_end");
                ctx.code
                    .push_str(&format!("  br label %{head_label}\n{head_label}:\n"));
                let cond = llvm_emit_expr(condition, ctx);
                let pred = ctx.value();
                ctx.code.push_str(&format!(
                    "  {pred} = icmp ne i32 {cond}, 0\n  br i1 {pred}, label %{body_label}, label %{end_label}\n{body_label}:\n"
                ));
                let terminated = llvm_emit_block(body, ctx);
                if !terminated {
                    ctx.code.push_str(&format!("  br label %{head_label}\n"));
                }
                ctx.code.push_str(&format!("{end_label}:\n"));
            }
            ast::Stmt::Match { .. } => {}
        }
    }
    false
}

fn llvm_emit_expr(expr: &ast::Expr, ctx: &mut LlvmFuncCtx) -> String {
    match expr {
        ast::Expr::Int(v) => v.to_string(),
        ast::Expr::Bool(v) => {
            if *v {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        ast::Expr::Str(_) => "0".to_string(),
        ast::Expr::Ident(name) => {
            if let Some(slot) = ctx.slots.get(name).cloned() {
                let val = ctx.value();
                ctx.code
                    .push_str(&format!("  {val} = load i32, ptr {slot}\n"));
                val
            } else {
                "0".to_string()
            }
        }
        ast::Expr::Group(inner) => llvm_emit_expr(inner, ctx),
        ast::Expr::FieldAccess { base, field } => {
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(slot) = ctx.slots.get(&format!("{name}.{field}")).cloned() {
                    let val = ctx.value();
                    ctx.code
                        .push_str(&format!("  {val} = load i32, ptr {slot}\n"));
                    return val;
                }
            }
            llvm_emit_expr(base, ctx)
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut first = None;
            for (_, value) in fields {
                let current = llvm_emit_expr(value, ctx);
                if first.is_none() {
                    first = Some(current);
                }
            }
            first.unwrap_or_else(|| "0".to_string())
        }
        ast::Expr::EnumInit {
            enum_name: _,
            variant,
            payload,
        } => {
            for value in payload {
                let _ = llvm_emit_expr(value, ctx);
            }
            (variant.bytes().fold(0u32, |acc, byte| {
                acc.wrapping_mul(33).wrapping_add(byte as u32)
            }) & 0x7fff_ffff)
                .to_string()
        }
        ast::Expr::TryCatch { try_expr, .. } => llvm_emit_expr(try_expr, ctx),
        ast::Expr::Call { callee, args } => {
            let args = args
                .iter()
                .map(|arg| format!("i32 {}", llvm_emit_expr(arg, ctx)))
                .collect::<Vec<_>>()
                .join(", ");
            let val = ctx.value();
            ctx.code
                .push_str(&format!("  {val} = call i32 @{callee}({args})\n"));
            val
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = llvm_emit_expr(left, ctx);
            let rhs = llvm_emit_expr(right, ctx);
            let out = ctx.value();
            match op {
                ast::BinaryOp::Add => ctx
                    .code
                    .push_str(&format!("  {out} = add i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Sub => ctx
                    .code
                    .push_str(&format!("  {out} = sub i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Mul => ctx
                    .code
                    .push_str(&format!("  {out} = mul i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Div => ctx
                    .code
                    .push_str(&format!("  {out} = sdiv i32 {lhs}, {rhs}\n")),
                ast::BinaryOp::Eq
                | ast::BinaryOp::Neq
                | ast::BinaryOp::Lt
                | ast::BinaryOp::Lte
                | ast::BinaryOp::Gt
                | ast::BinaryOp::Gte => {
                    let pred = ctx.value();
                    let cmp = match op {
                        ast::BinaryOp::Eq => "eq",
                        ast::BinaryOp::Neq => "ne",
                        ast::BinaryOp::Lt => "slt",
                        ast::BinaryOp::Lte => "sle",
                        ast::BinaryOp::Gt => "sgt",
                        ast::BinaryOp::Gte => "sge",
                        _ => unreachable!(),
                    };
                    ctx.code
                        .push_str(&format!("  {pred} = icmp {cmp} i32 {lhs}, {rhs}\n"));
                    ctx.code
                        .push_str(&format!("  {out} = zext i1 {pred} to i32\n"));
                }
            }
            out
        }
    }
}

struct ResolvedSource {
    source_path: PathBuf,
    project_root: PathBuf,
    manifest: Option<manifest::Manifest>,
    dependency_graph_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockfileMode {
    ValidateOrCreate,
    ForceRewrite,
}

fn resolve_source_path(input: &Path) -> Result<ResolvedSource> {
    if input.is_file() {
        let root = input
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedSource {
            source_path: input.to_path_buf(),
            project_root: root,
            manifest: None,
            dependency_graph_hash: None,
        });
    }
    if !input.is_dir() {
        return Err(anyhow!(
            "path is neither a source file nor a project directory: {}",
            input.display()
        ));
    }

    let (manifest, manifest_path, dependency_graph_hash) =
        load_manifest(input, LockfileMode::ValidateOrCreate)?;

    let relative = manifest
        .primary_bin_path()
        .ok_or_else(|| anyhow!("no [[target.bin]] entry in {}", manifest_path.display()))?;
    Ok(ResolvedSource {
        source_path: input.join(relative),
        project_root: input.to_path_buf(),
        manifest: Some(manifest),
        dependency_graph_hash: Some(dependency_graph_hash),
    })
}

fn load_manifest(
    dir: &Path,
    lock_mode: LockfileMode,
) -> Result<(manifest::Manifest, std::path::PathBuf, String)> {
    let primary = dir.join("fozzy.toml");
    let contents = std::fs::read_to_string(&primary)
        .with_context(|| format!("no valid compiler manifest found at {}", primary.display()))?;
    let parsed = manifest::load(&contents).context("failed parsing fozzy.toml")?;
    parsed
        .validate()
        .map_err(|err| anyhow!("invalid fozzy.toml: {err}"))?;
    validate_dependency_paths(dir, &parsed)?;
    let graph_hash = write_lockfile(dir, &parsed, &contents, lock_mode)?;
    Ok((parsed, primary, graph_hash))
}

fn validate_dependency_paths(dir: &Path, manifest: &manifest::Manifest) -> Result<()> {
    for (name, dependency) in &manifest.deps {
        let manifest::Dependency::Path { path } = dependency;
        let resolved = dir.join(path);
        if !resolved.exists() {
            return Err(anyhow!(
                "path dependency `{}` not found at {}",
                name,
                resolved.display()
            ));
        }
    }
    Ok(())
}

pub fn refresh_lockfile(dir: &Path) -> Result<String> {
    let (_, _, graph_hash) = load_manifest(dir, LockfileMode::ForceRewrite)?;
    Ok(graph_hash)
}

fn write_lockfile(
    dir: &Path,
    manifest: &manifest::Manifest,
    root_manifest_contents: &str,
    mode: LockfileMode,
) -> Result<String> {
    let root_manifest_hash = sha256_hex(root_manifest_contents.as_bytes());
    let graph = build_dependency_graph(dir, manifest, &root_manifest_hash)?;
    let graph_bytes = serde_json::to_vec(&graph)?;
    let graph_hash = sha256_hex(&graph_bytes);
    let payload = serde_json::json!({
        "schemaVersion": "fozzylang.lock.v0",
        "dependencyGraphHash": graph_hash,
        "graph": graph,
    });
    let lock_path = dir.join("fozzy.lock");
    let should_write = match mode {
        LockfileMode::ForceRewrite => true,
        LockfileMode::ValidateOrCreate => {
            if !lock_path.exists() {
                true
            } else {
                let existing_text = std::fs::read_to_string(&lock_path)
                    .with_context(|| format!("failed reading lockfile: {}", lock_path.display()))?;
                let existing_json: serde_json::Value = serde_json::from_str(&existing_text)
                    .with_context(|| format!("failed parsing lockfile: {}", lock_path.display()))?;
                let existing_hash = existing_json
                    .get("dependencyGraphHash")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let existing_graph = existing_json.get("graph").cloned().unwrap_or_default();
                let existing_schema = existing_json
                    .get("schemaVersion")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                if existing_schema == "fozzylang.lock.v0"
                    && existing_hash == graph_hash
                    && existing_graph == graph
                {
                    false
                } else {
                    return Err(anyhow!(
                        "lockfile drift detected at {}: expected dependencyGraphHash={} (run `fz vendor {}` to refresh)",
                        lock_path.display(),
                        graph_hash,
                        dir.display()
                    ));
                }
            }
        }
    };
    if should_write {
        std::fs::write(&lock_path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("failed writing lockfile: {}", lock_path.display()))?;
    }
    Ok(graph_hash)
}

fn build_dependency_graph(
    dir: &Path,
    manifest: &manifest::Manifest,
    root_manifest_hash: &str,
) -> Result<serde_json::Value> {
    let mut dep_entries = Vec::new();
    for (name, dependency) in &manifest.deps {
        let manifest::Dependency::Path { path } = dependency;
        let resolved = dir.join(path);
        let canonical = resolved.canonicalize().with_context(|| {
            format!(
                "failed canonicalizing path dependency `{}` at {}",
                name,
                resolved.display()
            )
        })?;
        let dep_manifest_path = canonical.join("fozzy.toml");
        let dep_manifest_text = std::fs::read_to_string(&dep_manifest_path).with_context(|| {
            format!(
                "path dependency `{}` missing manifest at {}",
                name,
                dep_manifest_path.display()
            )
        })?;
        let dep_manifest = manifest::load(&dep_manifest_text).with_context(|| {
            format!(
                "failed parsing dependency manifest for `{}` at {}",
                name,
                dep_manifest_path.display()
            )
        })?;
        dep_manifest.validate().map_err(|err| {
            anyhow!(
                "invalid dependency manifest for `{}` at {}: {}",
                name,
                dep_manifest_path.display(),
                err
            )
        })?;
        let dep_source_hash = hash_directory_tree(&canonical)?;
        dep_entries.push(serde_json::json!({
            "name": name,
            "path": normalize_rel_path(path),
            "canonicalPath": canonical.display().to_string(),
            "package": {
                "name": dep_manifest.package.name,
                "version": dep_manifest.package.version,
            },
            "manifestHash": sha256_hex(dep_manifest_text.as_bytes()),
            "sourceHash": dep_source_hash,
        }));
    }
    Ok(serde_json::json!({
        "package": {
            "name": manifest.package.name,
            "version": manifest.package.version,
            "manifestHash": root_manifest_hash,
        },
        "deps": dep_entries,
    }))
}

fn normalize_rel_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn hash_directory_tree(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    let mut hasher = Sha256::new();
    for (rel, full) in files {
        hasher.update(rel.as_bytes());
        let bytes = std::fs::read(&full).with_context(|| {
            format!(
                "failed reading dependency file for hashing: {}",
                full.display()
            )
        })?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn collect_files_recursive(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(current)
        .with_context(|| format!("failed reading dependency directory: {}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed iterating dependency directory: {}",
                current.display()
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let full = entry.path();
        let rel = full
            .strip_prefix(root)
            .with_context(|| format!("failed deriving relative path for {}", full.display()))?;
        let rel_str = normalize_rel_path(&rel.display().to_string());
        if should_skip_hash_path(&rel_str) {
            continue;
        }
        if entry
            .file_type()
            .with_context(|| format!("failed reading file type for {}", full.display()))?
            .is_dir()
        {
            collect_files_recursive(root, &full, out)?;
        } else {
            out.push((rel_str, full));
        }
    }
    Ok(())
}

fn should_skip_hash_path(rel: &str) -> bool {
    rel.starts_with(".git/")
        || rel.starts_with(".fz/")
        || rel.starts_with("vendor/")
        || rel.starts_with("target/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn emit_native_artifact(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
    backend_override: Option<&str>,
) -> Result<PathBuf> {
    let backend = resolve_native_backend(profile, backend_override)?;
    match backend.as_str() {
        "llvm" => emit_native_artifact_llvm(fir, project_root, profile, manifest),
        "cranelift" => emit_native_artifact_cranelift(fir, project_root, profile, manifest),
        other => Err(anyhow!(
            "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
            other
        )),
    }
}

fn resolve_native_backend(profile: BuildProfile, backend_override: Option<&str>) -> Result<String> {
    if let Some(explicit) = backend_override {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown backend `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    if let Ok(explicit) = std::env::var("FZ_NATIVE_BACKEND") {
        let normalized = explicit.trim().to_ascii_lowercase();
        return match normalized.as_str() {
            "llvm" | "cranelift" => Ok(normalized),
            other => Err(anyhow!(
                "unknown FZ_NATIVE_BACKEND `{}`; expected `llvm` or `cranelift`",
                other
            )),
        };
    }
    Ok(match profile {
        BuildProfile::Release => "llvm".to_string(),
        BuildProfile::Dev => "cranelift".to_string(),
        BuildProfile::Verify => "llvm".to_string(),
    })
}

fn emit_native_artifact_llvm(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let ll_path = build_dir.join(format!("{}.ll", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let llvm_ir = lower_llvm_ir(fir, enforce_contract_checks);
    std::fs::write(&ll_path, llvm_ir)
        .with_context(|| format!("failed writing llvm ir: {}", ll_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg("-x")
            .arg("ir")
            .arg(&ll_path)
            .arg("-o")
            .arg(&bin_path);
        apply_target_link_flags(&mut cmd);
        let optimize_override = manifest
            .and_then(|manifest| profile_config(manifest, profile))
            .and_then(|config| config.optimize);
        match (profile, optimize_override) {
            (_, Some(true)) => {
                cmd.arg("-O2");
            }
            (_, Some(false)) => {
                cmd.arg("-O0");
            }
            (BuildProfile::Dev, None) => {
                cmd.arg("-O0");
            }
            (BuildProfile::Release, None) => {
                cmd.arg("-O2");
            }
            (BuildProfile::Verify, None) => {
                cmd.arg("-O1").arg("-g");
            }
        }
        apply_extra_linker_args(&mut cmd);

        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(bin_path),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }

    Err(anyhow!(
        "failed to compile llvm native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

fn emit_native_artifact_cranelift(
    fir: &fir::FirModule,
    project_root: &Path,
    profile: BuildProfile,
    manifest: Option<&manifest::Manifest>,
) -> Result<PathBuf> {
    let build_dir = project_root.join(".fz").join("build");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed creating build directory: {}", build_dir.display()))?;

    let object_path = build_dir.join(format!("{}.o", fir.name));
    let bin_path = build_dir.join(fir.name.as_str());
    let mut flags_builder = settings::builder();
    let optimize_override = manifest
        .and_then(|manifest| profile_config(manifest, profile))
        .and_then(|config| config.optimize);
    let opt_level = match (profile, optimize_override) {
        (_, Some(true)) => "speed",
        (_, Some(false)) => "none",
        (BuildProfile::Dev, None) => "none",
        (BuildProfile::Release, None) => "speed",
        (BuildProfile::Verify, None) => "speed",
    };
    flags_builder
        .set("opt_level", opt_level)
        .map_err(|error| anyhow!("failed setting cranelift opt_level={opt_level}: {error}"))?;
    let flags = settings::Flags::new(flags_builder);
    let isa_builder = cranelift_native::builder()
        .map_err(|error| anyhow!("failed constructing cranelift native isa: {error}"))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|error| anyhow!("failed finalizing cranelift isa: {error}"))?;

    let object_builder = ObjectBuilder::new(isa, fir.name.clone(), default_libcall_names())
        .map_err(|error| anyhow!("failed creating cranelift object builder: {error}"))?;
    let mut module = ObjectModule::new(object_builder);
    let enforce_contract_checks = !matches!(profile, BuildProfile::Release);
    let forced_main_return = if enforce_contract_checks {
        if fir
            .entry_requires
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            Some(120)
        } else if fir
            .entry_ensures
            .iter()
            .any(|condition| matches!(condition, Some(false)))
        {
            Some(121)
        } else {
            None
        }
    } else {
        None
    };

    let mut function_ids = HashMap::new();
    for function in &fir.typed_functions {
        let mut sig = module.make_signature();
        for _ in &function.params {
            sig.params.push(AbiParam::new(types::I32));
        }
        sig.returns.push(AbiParam::new(types::I32));
        let linkage = if function.name == "main" {
            Linkage::Export
        } else {
            Linkage::Local
        };
        let id = module
            .declare_function(function.name.as_str(), linkage, &sig)
            .map_err(|error| {
                anyhow!(
                    "failed declaring cranelift symbol `{}`: {error}",
                    function.name
                )
            })?;
        function_ids.insert(function.name.clone(), id);
    }

    for function in &fir.typed_functions {
        let Some(function_id) = function_ids.get(&function.name).copied() else {
            continue;
        };
        let mut context = module.make_context();
        context.func.signature.params.clear();
        context.func.signature.returns.clear();
        for _ in &function.params {
            context
                .func
                .signature
                .params
                .push(AbiParam::new(types::I32));
        }
        context
            .func
            .signature
            .returns
            .push(AbiParam::new(types::I32));

        let mut function_builder_context = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut context.func, &mut function_builder_context);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);
        builder.seal_block(entry);

        let mut locals = HashMap::<String, Variable>::new();
        for (index, param) in function.params.iter().enumerate() {
            let var = Variable::from_u32(index as u32);
            builder.declare_var(var, types::I32);
            let value = builder.block_params(entry)[index];
            builder.def_var(var, value);
            locals.insert(param.name.clone(), var);
        }
        let mut next_var = function.params.len();

        let terminated = clif_emit_block(
            &mut builder,
            &mut module,
            &function_ids,
            &function.body,
            &mut locals,
            &mut next_var,
        )?;
        if !terminated {
            let fallback = if function.name == "main" {
                forced_main_return
                    .or(fir.entry_return_const_i32)
                    .unwrap_or(0)
            } else {
                0
            };
            let ret = builder.ins().iconst(types::I32, fallback as i64);
            builder.ins().return_(&[ret]);
        }
        builder.finalize();

        module
            .define_function(function_id, &mut context)
            .map_err(|error| {
                anyhow!(
                    "failed defining cranelift function `{}`: {error}",
                    function.name
                )
            })?;
        module.clear_context(&mut context);
    }
    let object_product = module.finish();
    let object_bytes = object_product
        .emit()
        .map_err(|error| anyhow!("failed emitting cranelift object bytes: {error}"))?;
    std::fs::write(&object_path, object_bytes)
        .with_context(|| format!("failed writing cranelift object: {}", object_path.display()))?;

    let candidates = linker_candidates();
    let mut last_error = None;
    for tool in candidates {
        let mut cmd = Command::new(&tool);
        cmd.arg(&object_path).arg("-o").arg(&bin_path);
        apply_target_link_flags(&mut cmd);
        // Object code is already generated at selected Cranelift optimization level.
        apply_extra_linker_args(&mut cmd);

        match cmd.output() {
            Ok(output) if output.status.success() => return Ok(bin_path),
            Ok(output) => {
                last_error = Some(format!(
                    "{} failed: {}",
                    tool,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(err) => {
                last_error = Some(format!("{tool} unavailable: {err}"));
            }
        }
    }

    Err(anyhow!(
        "failed to link cranelift native artifact: {}",
        last_error.unwrap_or_else(|| "unknown compiler error".to_string())
    ))
}

fn clif_emit_block(
    builder: &mut FunctionBuilder,
    module: &mut ObjectModule,
    function_ids: &HashMap<String, cranelift_module::FuncId>,
    body: &[ast::Stmt],
    locals: &mut HashMap<String, Variable>,
    next_var: &mut usize,
) -> Result<bool> {
    for stmt in body {
        match stmt {
            ast::Stmt::Let { name, value, .. } => {
                let val = clif_emit_expr(builder, module, function_ids, value, locals, next_var)?;
                let var = if let Some(existing) = locals.get(name).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, types::I32);
                    locals.insert(name.clone(), var);
                    var
                };
                builder.def_var(var, val);
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_val = clif_emit_expr(
                            builder,
                            module,
                            function_ids,
                            field_expr,
                            locals,
                            next_var,
                        )?;
                        let field_var = Variable::from_u32(*next_var as u32);
                        *next_var += 1;
                        builder.declare_var(field_var, types::I32);
                        builder.def_var(field_var, field_val);
                        locals.insert(format!("{name}.{field}"), field_var);
                    }
                }
            }
            ast::Stmt::Assign { target, value } => {
                let val = clif_emit_expr(builder, module, function_ids, value, locals, next_var)?;
                let var = if let Some(existing) = locals.get(target).copied() {
                    existing
                } else {
                    let var = Variable::from_u32(*next_var as u32);
                    *next_var += 1;
                    builder.declare_var(var, types::I32);
                    locals.insert(target.clone(), var);
                    var
                };
                builder.def_var(var, val);
            }
            ast::Stmt::Return(expr) => {
                let value = clif_emit_expr(builder, module, function_ids, expr, locals, next_var)?;
                builder.ins().return_(&[value]);
                return Ok(true);
            }
            ast::Stmt::Expr(expr)
            | ast::Stmt::Requires(expr)
            | ast::Stmt::Ensures(expr)
            | ast::Stmt::Defer(expr) => {
                let _ = clif_emit_expr(builder, module, function_ids, expr, locals, next_var)?;
            }
            ast::Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let cond_val =
                    clif_emit_expr(builder, module, function_ids, condition, locals, next_var)?;
                let zero = builder.ins().iconst(types::I32, 0);
                let cond = builder.ins().icmp(IntCC::NotEqual, cond_val, zero);
                let then_block = builder.create_block();
                let else_block = builder.create_block();
                let cont_block = builder.create_block();
                builder.ins().brif(cond, then_block, &[], else_block, &[]);

                builder.switch_to_block(then_block);
                let then_terminated =
                    clif_emit_block(builder, module, function_ids, then_body, locals, next_var)?;
                if !then_terminated {
                    builder.ins().jump(cont_block, &[]);
                }
                builder.seal_block(then_block);

                builder.switch_to_block(else_block);
                let else_terminated =
                    clif_emit_block(builder, module, function_ids, else_body, locals, next_var)?;
                if !else_terminated {
                    builder.ins().jump(cont_block, &[]);
                }
                builder.seal_block(else_block);

                if then_terminated && else_terminated {
                    return Ok(true);
                }
                builder.switch_to_block(cont_block);
                builder.seal_block(cont_block);
            }
            ast::Stmt::While { condition, body } => {
                let head = builder.create_block();
                let loop_body = builder.create_block();
                let exit = builder.create_block();
                builder.ins().jump(head, &[]);
                builder.switch_to_block(head);
                let cond_val =
                    clif_emit_expr(builder, module, function_ids, condition, locals, next_var)?;
                let zero = builder.ins().iconst(types::I32, 0);
                let cond = builder.ins().icmp(IntCC::NotEqual, cond_val, zero);
                builder.ins().brif(cond, loop_body, &[], exit, &[]);
                builder.seal_block(head);

                builder.switch_to_block(loop_body);
                let body_terminated =
                    clif_emit_block(builder, module, function_ids, body, locals, next_var)?;
                if !body_terminated {
                    builder.ins().jump(head, &[]);
                }
                builder.seal_block(loop_body);

                builder.switch_to_block(exit);
                builder.seal_block(exit);
            }
            ast::Stmt::Match { .. } => {}
        }
    }
    Ok(false)
}

fn clif_emit_expr(
    builder: &mut FunctionBuilder,
    module: &mut ObjectModule,
    function_ids: &HashMap<String, cranelift_module::FuncId>,
    expr: &ast::Expr,
    locals: &mut HashMap<String, Variable>,
    next_var: &mut usize,
) -> Result<cranelift_codegen::ir::Value> {
    Ok(match expr {
        ast::Expr::Int(v) => builder.ins().iconst(types::I32, *v as i64),
        ast::Expr::Bool(v) => builder.ins().iconst(types::I32, if *v { 1 } else { 0 }),
        ast::Expr::Str(_) => builder.ins().iconst(types::I32, 0),
        ast::Expr::Ident(name) => {
            if let Some(var) = locals.get(name).copied() {
                builder.use_var(var)
            } else {
                builder.ins().iconst(types::I32, 0)
            }
        }
        ast::Expr::Group(inner) => {
            clif_emit_expr(builder, module, function_ids, inner, locals, next_var)?
        }
        ast::Expr::FieldAccess { base, field } => {
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(var) = locals.get(&format!("{name}.{field}")).copied() {
                    builder.use_var(var)
                } else {
                    clif_emit_expr(builder, module, function_ids, base, locals, next_var)?
                }
            } else {
                clif_emit_expr(builder, module, function_ids, base, locals, next_var)?
            }
        }
        ast::Expr::StructInit { fields, .. } => {
            let mut first = None;
            for (_, value) in fields {
                let out = clif_emit_expr(builder, module, function_ids, value, locals, next_var)?;
                if first.is_none() {
                    first = Some(out);
                }
            }
            first.unwrap_or_else(|| builder.ins().iconst(types::I32, 0))
        }
        ast::Expr::EnumInit {
            variant, payload, ..
        } => {
            for value in payload {
                let _ = clif_emit_expr(builder, module, function_ids, value, locals, next_var)?;
            }
            let tag = variant.bytes().fold(0u32, |acc, byte| {
                acc.wrapping_mul(33).wrapping_add(byte as u32)
            });
            builder.ins().iconst(types::I32, (tag & 0x7fff_ffff) as i64)
        }
        ast::Expr::TryCatch {
            try_expr,
            catch_expr,
        } => clif_emit_expr(builder, module, function_ids, try_expr, locals, next_var).or_else(
            |_| clif_emit_expr(builder, module, function_ids, catch_expr, locals, next_var),
        )?,
        ast::Expr::Binary { op, left, right } => {
            let lhs = clif_emit_expr(builder, module, function_ids, left, locals, next_var)?;
            let rhs = clif_emit_expr(builder, module, function_ids, right, locals, next_var)?;
            match op {
                ast::BinaryOp::Add => builder.ins().iadd(lhs, rhs),
                ast::BinaryOp::Sub => builder.ins().isub(lhs, rhs),
                ast::BinaryOp::Mul => builder.ins().imul(lhs, rhs),
                ast::BinaryOp::Div => builder.ins().sdiv(lhs, rhs),
                ast::BinaryOp::Eq => {
                    let c = builder.ins().icmp(IntCC::Equal, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Neq => {
                    let c = builder.ins().icmp(IntCC::NotEqual, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Lt => {
                    let c = builder.ins().icmp(IntCC::SignedLessThan, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Lte => {
                    let c = builder.ins().icmp(IntCC::SignedLessThanOrEqual, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Gt => {
                    let c = builder.ins().icmp(IntCC::SignedGreaterThan, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
                ast::BinaryOp::Gte => {
                    let c = builder
                        .ins()
                        .icmp(IntCC::SignedGreaterThanOrEqual, lhs, rhs);
                    let one = builder.ins().iconst(types::I32, 1);
                    let zero = builder.ins().iconst(types::I32, 0);
                    builder.ins().select(c, one, zero)
                }
            }
        }
        ast::Expr::Call { callee, args } => {
            let Some(function_id) = function_ids.get(callee).copied() else {
                return Ok(builder.ins().iconst(types::I32, 0));
            };
            let func_ref = module.declare_func_in_func(function_id, builder.func);
            let mut values = Vec::with_capacity(args.len());
            for arg in args {
                values.push(clif_emit_expr(
                    builder,
                    module,
                    function_ids,
                    arg,
                    locals,
                    next_var,
                )?);
            }
            let call = builder.ins().call(func_ref, &values);
            if let Some(value) = builder.inst_results(call).first().copied() {
                value
            } else {
                builder.ins().iconst(types::I32, 0)
            }
        }
    })
}

fn linker_candidates() -> Vec<String> {
    if let Ok(explicit) = std::env::var("FZ_CC") {
        if !explicit.trim().is_empty() {
            return vec![explicit];
        }
    }
    let mut candidates = Vec::new();
    let target = std::env::var("TARGET")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if target.contains("apple-darwin") {
        candidates.push("clang".to_string());
        candidates.push("cc".to_string());
        candidates.push("gcc".to_string());
    } else if target.contains("linux") {
        candidates.push("cc".to_string());
        candidates.push("clang".to_string());
        candidates.push("gcc".to_string());
    } else {
        candidates.push("clang".to_string());
        candidates.push("cc".to_string());
        candidates.push("gcc".to_string());
    }
    candidates
}

fn apply_target_link_flags(cmd: &mut Command) {
    if let Ok(target) = std::env::var("TARGET") {
        let target = target.trim();
        if !target.is_empty() {
            cmd.arg("-target").arg(target);
        }
    }
}

fn apply_extra_linker_args(cmd: &mut Command) {
    if let Ok(extra) = std::env::var("FZ_LINKER_ARGS") {
        for arg in extra.split_whitespace() {
            if !arg.trim().is_empty() {
                cmd.arg(arg);
            }
        }
    }
}

fn profile_config(
    manifest: &manifest::Manifest,
    profile: BuildProfile,
) -> Option<&manifest::Profile> {
    match profile {
        BuildProfile::Dev => manifest.profiles.dev.as_ref(),
        BuildProfile::Release => manifest.profiles.release.as_ref(),
        BuildProfile::Verify => manifest.profiles.verify.as_ref(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        compile_file, compile_file_with_backend, emit_ir, parse_program, refresh_lockfile,
        BuildProfile,
    };

    #[test]
    fn compile_file_runs_pipeline() {
        let file_name = format!(
            "fozzylang-pipeline-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use cap.time;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should compile");
        assert_eq!(artifact.module, path.file_stem().unwrap().to_string_lossy());
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_project_directory_uses_manifest_target() {
        let project_name = format!(
            "fozzylang-project-{}",
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
            "use cap.time;\nfn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
        assert_eq!(artifact.module, "main");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_project_uses_capabilities_from_declared_modules() {
        let project_name = format!(
            "fozzylang-mod-cap-{}",
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
            "mod infra;\nfn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("main source should be written");
        std::fs::write(root.join("src/infra.fzy"), "use cap.net;\n")
            .expect("module source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_with_verify_errors_skips_native_output() {
        let file_name = format!(
            "fozzylang-error-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_project_fails_for_missing_path_dependency() {
        let project_name = format!(
            "fozzylang-deps-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let error = compile_file(&root, BuildProfile::Dev).expect_err("build should fail");
        assert!(error.to_string().contains("path dependency"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn compile_project_fails_when_lockfile_drifts() {
        let project_name = format!(
            "fozzylang-lock-drift-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
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

        let first = compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
        assert_eq!(first.status, "ok");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 1\n}\n",
        )
        .expect("dep source should mutate");
        let error = compile_file(&root, BuildProfile::Dev).expect_err("drift should fail build");
        assert!(error.to_string().contains("lockfile drift detected"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn refresh_lockfile_unblocks_drifted_project_build() {
        let project_name = format!(
            "fozzylang-lock-refresh-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        let dep_dir = root.join("deps/util");
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::create_dir_all(dep_dir.join("src")).expect("dep src dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[deps]\nutil={path=\"deps/util\"}\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");
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

        compile_file(&root, BuildProfile::Dev).expect("first build should succeed");
        std::fs::write(
            dep_dir.join("src/main.fzy"),
            "fn main() -> i32 {\n    return 2\n}\n",
        )
        .expect("dep source should mutate");
        refresh_lockfile(&root).expect("refresh lockfile should succeed");
        let artifact = compile_file(&root, BuildProfile::Dev).expect("build should recover");
        assert_eq!(artifact.status, "ok");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn profile_checks_can_be_disabled() {
        let project_name = format!(
            "fozzylang-profile-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(project_name);
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(
            root.join("fozzy.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n\n[profiles.dev]\nchecks=false\noptimize=false\n",
        )
        .expect("manifest should be written");
        std::fs::write(
            root.join("src/main.fzy"),
            "fn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("source should be written");

        let artifact = compile_file(&root, BuildProfile::Dev).expect("build should run");
        assert_eq!(artifact.status, "ok");
        assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_profile_rejects_unsafe_capabilities_even_if_declared() {
        let file_name = format!(
            "fozzylang-safe-profile-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "use cap.net;\nfn main() -> i32 {\n    let c = net.connect()\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Verify).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn compile_rejects_false_contracts() {
        let file_name = format!(
            "fozzylang-contract-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(
            &path,
            "fn main() -> i32 {\n    requires false\n    ensures false\n    return 0\n}\n",
        )
        .expect("temp source should be written");

        let artifact = compile_file(&path, BuildProfile::Dev).expect("pipeline should run");
        assert_eq!(artifact.status, "error");
        assert!(artifact.output.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn emit_ir_includes_llvm_and_cranelift_forms() {
        let file_name = format!(
            "fozzylang-ir-{}.fzy",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(file_name);
        std::fs::write(&path, "fn main() -> i32 {\n    return 0\n}\n")
            .expect("temp source should be written");

        let output = emit_ir(&path).expect("emit ir should run");
        let ir = output.backend_ir.expect("backend ir should be available");
        assert!(ir.contains("backend=llvm"));
        assert!(ir.contains("backend=cranelift"));

        let _ = std::fs::remove_file(path);
    }

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
    fn backend_defaults_dev_cranelift_release_llvm() {
        let project_name = format!(
            "fozzylang-backend-defaults-{}",
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
            "fn main() -> i32 {\n    return 0\n}\n",
        )
        .expect("source should be written");

        let dev = compile_file_with_backend(&root, BuildProfile::Dev, None)
            .expect("dev build should succeed");
        assert_eq!(dev.status, "ok");
        assert!(root.join(".fz/build/main.o").exists());

        let release = compile_file_with_backend(&root, BuildProfile::Release, None)
            .expect("release build should succeed");
        assert_eq!(release.status, "ok");
        assert!(root.join(".fz/build/main.ll").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parse_program_fails_for_missing_declared_module() {
        let root_name = format!(
            "fozzylang-mod-missing-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(root_name);
        std::fs::create_dir_all(&root).expect("temp dir should be created");
        let path = root.join("main.fzy");
        std::fs::write(&path, "mod util;\nfn main() -> i32 {\n    return 0\n}\n")
            .expect("root source should be written");

        let error = parse_program(&path).expect_err("missing module should fail parsing");
        assert!(error.to_string().contains("resolving module `util`"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parse_program_detects_cycle() {
        let root_name = format!(
            "fozzylang-mod-cycle-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(root_name);
        std::fs::create_dir_all(&root).expect("temp dir should be created");
        let main = root.join("main.fzy");
        let a = root.join("a.fzy");
        let b = root.join("b.fzy");
        std::fs::write(&main, "mod a;\nfn main() -> i32 {\n return 0\n}\n")
            .expect("main source should be written");
        std::fs::write(&a, "mod b;\n").expect("module a should be written");
        std::fs::write(&b, "mod a;\n").expect("module b should be written");

        let error = parse_program(&main).expect_err("cycle should fail parsing");
        assert!(error.to_string().contains("cyclic module declaration"));

        let _ = std::fs::remove_dir_all(root);
    }
}
