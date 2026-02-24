use std::collections::BTreeSet;

use ast::{Expr, Module, Stmt};
use diagnostics::{Diagnostic, Severity};

pub fn parse(source: &str, module_name: &str) -> Result<Module, Vec<Diagnostic>> {
    if source.trim().is_empty() {
        return Err(vec![Diagnostic::new(
            Severity::Error,
            "source is empty",
            Some("provide at least one declaration".to_string()),
        )]);
    }

    let mut module = Module {
        name: module_name.to_string(),
        items: Vec::new(),
        modules: Vec::new(),
        imports: Vec::new(),
        capabilities: Vec::new(),
        inferred_capabilities: Vec::new(),
        host_syscall_sites: 0,
        unsafe_sites: 0,
        reference_sites: 0,
        alloc_sites: 0,
        free_sites: 0,
    };
    let mut diagnostics = Vec::new();
    let mut inferred = BTreeSet::new();
    let mut current_function_index: Option<usize> = None;
    let mut pending_repr: Option<String> = None;

    for (line_number, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        if let Some(repr) = parse_repr_attribute(line) {
            pending_repr = Some(repr);
            continue;
        }

        if let Some(signature) = parse_extern_signature(line) {
            match signature {
                Ok((name, params, return_type, abi, is_pub)) => {
                    if !is_supported_type(&return_type) {
                        diagnostics.push(
                            line_diagnostic(
                                line_number + 1,
                                line.len(),
                                format!("unsupported return type `{}`", return_type),
                                Some(
                                    "use v0-supported type forms (i32/u32/bool/str, pointers, slices, arrays)",
                                ),
                            )
                            .with_fix("change return type to a supported v0 type"),
                        );
                    }
                    if is_ffi_unstable_type(&return_type) {
                        diagnostics.push(
                            line_diagnostic(
                                line_number + 1,
                                line.len(),
                                format!(
                                    "extern ABI return type `{}` is not stable for C interop",
                                    return_type
                                ),
                                Some("use fixed-size primitives or explicit pointer+length pairs"),
                            )
                            .with_fix("replace `str`/slice/error-union types in extern signatures"),
                        );
                    }
                    for param in &params {
                        if is_ffi_unstable_type(&param.ty) {
                            diagnostics.push(
                                line_diagnostic(
                                    line_number + 1,
                                    line.len(),
                                    format!(
                                        "extern ABI param `{}` uses unstable type `{}`",
                                        param.name, param.ty
                                    ),
                                    Some(
                                        "use fixed-size primitives or explicit pointer+length pairs",
                                    ),
                                )
                                .with_fix(
                                    "replace `str`/slice/error-union types in extern signatures",
                                ),
                            );
                        }
                    }
                    module.items.push(ast::Item::Function(ast::Function {
                        name,
                        params,
                        return_type,
                        body: Vec::new(),
                        is_pub,
                        is_extern: true,
                        abi: Some(abi),
                    }));
                }
                Err(message) => diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    message,
                    Some("expected `extern \"C\" fn name(...) -> Type;`"),
                )),
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("use cap.") {
            let capability = rest.trim().trim_end_matches(';').to_string();
            if capability.is_empty() {
                diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    "empty capability declaration",
                    Some("declare as `use cap.time;`"),
                ));
            } else {
                module.capabilities.push(capability);
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("mod ") {
            let name = rest.trim().trim_end_matches(';').to_string();
            if name.is_empty() {
                diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    "invalid module declaration",
                    Some("use `mod name;`"),
                ));
            } else {
                module.modules.push(name);
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("use ") {
            let import = rest.trim().trim_end_matches(';').to_string();
            if import.is_empty() {
                diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    "invalid import",
                    Some("use `use path::item;`"),
                ));
            } else {
                module.imports.push(import);
            }
            continue;
        }

        if let Some(signature) = parse_fn_signature(line) {
            match signature {
                Ok((name, params, return_type, is_pub)) => {
                    if !is_supported_type(&return_type) {
                        diagnostics.push(
                            line_diagnostic(
                                line_number + 1,
                                line.len(),
                                format!("unsupported return type `{}`", return_type),
                                Some(
                                    "use v0-supported type forms (i32/u32/bool/str, pointers, slices, arrays)",
                                ),
                            )
                            .with_fix("change return type to a supported v0 type"),
                        );
                    }
                    module.items.push(ast::Item::Function(ast::Function {
                        name,
                        params,
                        return_type,
                        body: Vec::new(),
                        is_pub,
                        is_extern: false,
                        abi: None,
                    }));
                    current_function_index = Some(module.items.len() - 1);
                }
                Err(message) => diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    message,
                    Some("expected `fn name(...) -> Type`"),
                )),
            }
            continue;
        }

        if let Some(function_index) = current_function_index {
            if line.starts_with('}') {
                current_function_index = None;
                continue;
            }

            infer_capabilities(line, &mut inferred);
            module.host_syscall_sites += count_host_syscalls(line);
            module.unsafe_sites += count_unsafe_markers(line);
            module.reference_sites += count_reference_markers(line);
            module.alloc_sites += count_alloc_markers(line);
            module.free_sites += count_free_markers(line);
            match parse_statement(line) {
                Ok(statement) => {
                    if let Some(ast::Item::Function(function)) =
                        module.items.get_mut(function_index)
                    {
                        function.body.push(statement);
                    }
                }
                Err(message) => diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    message,
                    Some("check statement syntax in function body"),
                )),
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("struct ") {
            let name = rest
                .split_whitespace()
                .next()
                .map(str::trim)
                .filter(|v| !v.is_empty());
            match name {
                Some(name) => module.items.push(ast::Item::Struct(ast::Struct {
                    name: name.trim_end_matches('{').to_string(),
                    fields: Vec::new(),
                    repr: pending_repr.take(),
                })),
                None => diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    "invalid struct declaration",
                    Some("expected `struct Name { ... }`"),
                )),
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("enum ") {
            let name = rest
                .split_whitespace()
                .next()
                .map(str::trim)
                .filter(|v| !v.is_empty());
            match name {
                Some(name) => module.items.push(ast::Item::Enum(ast::Enum {
                    name: name.trim_end_matches('{').to_string(),
                    variants: Vec::new(),
                    repr: pending_repr.take(),
                })),
                None => diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    "invalid enum declaration",
                    Some("expected `enum Name { ... }`"),
                )),
            }
            continue;
        }

        if line.starts_with("test ") {
            match parse_test_block(line, line_number + 1) {
                Ok(block) => module.items.push(ast::Item::Test(block)),
                Err(message) => diagnostics.push(line_diagnostic(
                    line_number + 1,
                    line.len(),
                    message,
                    Some("expected `test \"name\" {}` or `test \"name\" nondet {}`"),
                )),
            }
            continue;
        }

        infer_capabilities(line, &mut inferred);
        module.host_syscall_sites += count_host_syscalls(line);
        module.unsafe_sites += count_unsafe_markers(line);
        module.reference_sites += count_reference_markers(line);
        module.alloc_sites += count_alloc_markers(line);
        module.free_sites += count_free_markers(line);
    }

    module.inferred_capabilities = inferred.into_iter().collect();

    if diagnostics.is_empty() {
        Ok(module)
    } else {
        Err(diagnostics)
    }
}

fn line_diagnostic(
    line: usize,
    line_len: usize,
    message: impl Into<String>,
    help: Option<&str>,
) -> Diagnostic {
    Diagnostic::new(Severity::Error, message.into(), help.map(str::to_string)).with_span(
        line,
        1,
        line,
        line_len.max(1),
    )
}

fn parse_repr_attribute(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with("#[repr(") || !trimmed.ends_with(")]") {
        return None;
    }
    let inner = &trimmed["#[repr(".len()..(trimmed.len() - 2)];
    let repr = inner.trim();
    if repr.is_empty() {
        None
    } else {
        Some(repr.to_string())
    }
}

fn parse_test_block(line: &str, _line_number: usize) -> Result<ast::TestBlock, String> {
    let trimmed = line.trim();
    if !trimmed.starts_with("test ") {
        return Err("invalid test declaration".to_string());
    }
    let quote_start = trimmed
        .find('"')
        .ok_or_else(|| "invalid test declaration: missing quoted name".to_string())?;
    let remainder = &trimmed[(quote_start + 1)..];
    let quote_end_rel = remainder
        .find('"')
        .ok_or_else(|| "invalid test declaration: missing closing quote".to_string())?;
    let name = remainder[..quote_end_rel].trim();
    if name.is_empty() {
        return Err("invalid test declaration: empty test name".to_string());
    }

    let after_name = remainder[(quote_end_rel + 1)..].trim();
    let deterministic = !after_name.contains("nondet");
    Ok(ast::TestBlock {
        name: name.to_string(),
        deterministic,
    })
}

fn parse_fn_signature(
    line: &str,
) -> Option<Result<(String, Vec<ast::Param>, String, bool), String>> {
    let trimmed = line.trim();
    if trimmed.starts_with("extern ") || trimmed.starts_with("pub extern ") {
        return None;
    }

    let (is_pub, rest) = if let Some(rest) = trimmed.strip_prefix("pub fn ") {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix("fn ") {
        (false, rest)
    } else {
        return None;
    };

    Some(
        parse_function_core(rest)
            .map(|(name, params, return_type)| (name, params, return_type, is_pub)),
    )
}

fn parse_extern_signature(
    line: &str,
) -> Option<Result<(String, Vec<ast::Param>, String, String, bool), String>> {
    let trimmed = line.trim();
    let (is_pub, rest) = if let Some(rest) = trimmed.strip_prefix("pub extern ") {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix("extern ") {
        (false, rest)
    } else {
        return None;
    };

    let after_extern = rest;
    let Some(rest_after_quote) = after_extern.get(1..) else {
        return Some(Err(
            "invalid extern declaration: missing ABI string".to_string()
        ));
    };
    let Some(abi_end) = rest_after_quote.find('"').map(|index| index + 1) else {
        return Some(Err(
            "invalid extern declaration: missing ABI string".to_string()
        ));
    };
    if !after_extern.starts_with('"') {
        return Some(Err(
            "invalid extern declaration: expected ABI string".to_string()
        ));
    }
    let abi = after_extern[1..abi_end].to_string();
    let rest = after_extern[(abi_end + 1)..].trim_start();
    let Some(rest) = rest.strip_prefix("fn ") else {
        return Some(Err("invalid extern declaration: expected `fn`".to_string()));
    };
    let parsed = parse_function_core(rest)
        .map(|(name, params, return_type)| (name, params, return_type, abi, is_pub));
    Some(parsed)
}

fn parse_function_core(signature: &str) -> Result<(String, Vec<ast::Param>, String), String> {
    let Some(open) = signature.find('(') else {
        return Err("invalid function declaration: missing `(`".to_string());
    };
    let Some(close) = signature.rfind(')') else {
        return Err("invalid function declaration: missing `)`".to_string());
    };
    if close < open {
        return Err("invalid function declaration: malformed parameters".to_string());
    }
    let name = signature[..open].trim();
    if name.is_empty() {
        return Err("invalid function declaration: missing function name".to_string());
    }
    let params = parse_params(&signature[(open + 1)..close])?;
    let return_type = parse_return_type(signature);
    Ok((name.to_string(), params, return_type))
}

fn parse_params(params_src: &str) -> Result<Vec<ast::Param>, String> {
    let mut params = Vec::new();
    let trimmed = params_src.trim();
    if trimmed.is_empty() {
        return Ok(params);
    }

    for raw in trimmed.split(',') {
        let param = raw.trim();
        let Some((name, ty)) = param.split_once(':') else {
            return Err(format!(
                "invalid parameter `{param}`: expected `name: Type`"
            ));
        };
        let name = name.trim();
        let ty = ty.trim();
        if name.is_empty() || ty.is_empty() {
            return Err(format!(
                "invalid parameter `{param}`: expected `name: Type`"
            ));
        }
        if !is_supported_type(ty) {
            return Err(format!("unsupported parameter type `{ty}`"));
        }
        params.push(ast::Param {
            name: name.to_string(),
            ty: ty.to_string(),
        });
    }
    Ok(params)
}

fn parse_return_type(signature: &str) -> String {
    if let Some((_, right)) = signature.split_once("->") {
        let ty = right
            .trim()
            .trim_end_matches('{')
            .trim_end_matches(';')
            .trim();
        if ty.is_empty() {
            "void".to_string()
        } else {
            ty.to_string()
        }
    } else {
        "void".to_string()
    }
}

fn parse_statement(line: &str) -> Result<Stmt, String> {
    if let Some(rest) = line.strip_prefix("let ") {
        return parse_let(rest);
    }
    if let Some(rest) = line.strip_prefix("requires ") {
        let expr = parse_expr(rest.trim_end_matches(';'))?;
        return Ok(Stmt::Requires(expr));
    }
    if let Some(rest) = line.strip_prefix("ensures ") {
        let expr = parse_expr(rest.trim_end_matches(';'))?;
        return Ok(Stmt::Ensures(expr));
    }
    if let Some(rest) = line.strip_prefix("return ") {
        let expr = parse_expr(rest.trim_end_matches(';'))?;
        return Ok(Stmt::Return(expr));
    }
    if let Some(rest) = line.strip_prefix("defer ") {
        let expr = parse_expr(rest.trim_end_matches(';'))?;
        return Ok(Stmt::Defer(expr));
    }
    if let Some(rest) = line.strip_prefix("match ") {
        return parse_match_statement(rest.trim_end_matches(';'));
    }

    let expr = parse_expr(line.trim_end_matches(';'))?;
    Ok(Stmt::Expr(expr))
}

fn parse_let(rest: &str) -> Result<Stmt, String> {
    let (lhs, rhs) = rest
        .split_once('=')
        .ok_or_else(|| "invalid let statement: expected `let name = expr`".to_string())?;
    let lhs = lhs.trim();
    let (name, ty) = if let Some((name, ty)) = lhs.split_once(':') {
        let parsed = ty.trim().to_string();
        if !is_supported_type(&parsed) {
            return Err(format!("unsupported type annotation `{parsed}`"));
        }
        (name.trim().to_string(), Some(parsed))
    } else {
        (lhs.to_string(), None)
    };
    if name.is_empty() {
        return Err("invalid let statement: missing identifier".to_string());
    }

    let value = parse_expr(rhs.trim_end_matches(';').trim())?;
    Ok(Stmt::Let { name, ty, value })
}

fn parse_expr(input: &str) -> Result<Expr, String> {
    let expr = input.trim();
    if expr.is_empty() {
        return Err("empty expression".to_string());
    }

    if let Some(rest) = expr.strip_prefix("try ") {
        let (try_side, catch_side) = rest.split_once(" catch ").ok_or_else(|| {
            "invalid try/catch expression: expected `try <expr> catch <expr>`".to_string()
        })?;
        return Ok(Expr::TryCatch {
            try_expr: Box::new(parse_expr(try_side)?),
            catch_expr: Box::new(parse_expr(catch_side)?),
        });
    }

    if let Some((left, right)) = split_binary(expr, "==") {
        return Ok(Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(parse_expr(left)?),
            right: Box::new(parse_expr(right)?),
        });
    }
    if let Some((left, right)) = split_binary(expr, "!=") {
        return Ok(Expr::Binary {
            op: ast::BinaryOp::Neq,
            left: Box::new(parse_expr(left)?),
            right: Box::new(parse_expr(right)?),
        });
    }
    if let Some((left, right)) = split_binary(expr, "+") {
        return Ok(Expr::Binary {
            op: ast::BinaryOp::Add,
            left: Box::new(parse_expr(left)?),
            right: Box::new(parse_expr(right)?),
        });
    }
    if let Some((left, right)) = split_binary(expr, "-") {
        return Ok(Expr::Binary {
            op: ast::BinaryOp::Sub,
            left: Box::new(parse_expr(left)?),
            right: Box::new(parse_expr(right)?),
        });
    }

    if let Ok(value) = expr.parse::<i32>() {
        return Ok(Expr::Int(value));
    }
    if expr == "true" {
        return Ok(Expr::Bool(true));
    }
    if expr == "false" {
        return Ok(Expr::Bool(false));
    }

    if expr.ends_with(')') {
        if let Some(open) = expr.find('(') {
            let callee = expr[..open].trim();
            if !callee.is_empty() {
                let args_inner = &expr[(open + 1)..(expr.len() - 1)];
                let mut args = Vec::new();
                if !args_inner.trim().is_empty() {
                    for arg in args_inner.split(',') {
                        args.push(parse_expr(arg.trim())?);
                    }
                }
                return Ok(Expr::Call {
                    callee: callee.to_string(),
                    args,
                });
            }
        }
    }

    if is_identifier(expr) {
        return Ok(Expr::Ident(expr.to_string()));
    }

    Err(format!("unsupported expression syntax: `{expr}`"))
}

fn parse_match_statement(rest: &str) -> Result<Stmt, String> {
    let open = rest
        .find('{')
        .ok_or_else(|| "invalid match statement: missing `{`".to_string())?;
    let close = rest
        .rfind('}')
        .ok_or_else(|| "invalid match statement: missing `}`".to_string())?;
    if close <= open {
        return Err("invalid match statement: malformed arm block".to_string());
    }

    let scrutinee = parse_expr(rest[..open].trim())?;
    let arms_source = rest[(open + 1)..close].trim();
    if arms_source.is_empty() {
        return Err("invalid match statement: at least one arm is required".to_string());
    }

    let mut arms = Vec::new();
    for raw_arm in arms_source.split(',') {
        let arm = raw_arm.trim();
        if arm.is_empty() {
            continue;
        }
        let (pattern_raw, value_raw) = arm
            .split_once("=>")
            .ok_or_else(|| format!("invalid match arm `{arm}`: expected `pattern => expr`"))?;
        let pattern = parse_pattern(pattern_raw.trim())?;
        let value = parse_expr(value_raw.trim())?;
        arms.push(ast::MatchArm { pattern, value });
    }
    if arms.is_empty() {
        return Err("invalid match statement: no valid arms parsed".to_string());
    }

    Ok(Stmt::Match { scrutinee, arms })
}

fn parse_pattern(input: &str) -> Result<ast::Pattern, String> {
    let pattern = input.trim();
    if pattern == "_" {
        return Ok(ast::Pattern::Wildcard);
    }
    if let Ok(value) = pattern.parse::<i32>() {
        return Ok(ast::Pattern::Int(value));
    }
    if pattern == "true" {
        return Ok(ast::Pattern::Bool(true));
    }
    if pattern == "false" {
        return Ok(ast::Pattern::Bool(false));
    }
    if is_identifier(pattern) {
        return Ok(ast::Pattern::Ident(pattern.to_string()));
    }
    Err(format!("unsupported match pattern: `{pattern}`"))
}

fn split_binary<'a>(input: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    input.find(op).map(|index| {
        let left = input[..index].trim();
        let right = input[(index + op.len())..].trim();
        (left, right)
    })
}

fn is_identifier(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

fn infer_capabilities(line: &str, inferred: &mut BTreeSet<String>) {
    if line.contains("time.") || line.contains("std.time") {
        inferred.insert("time".to_string());
    }
    if line.contains("rng.") || line.contains("random.") || line.contains("std.rand") {
        inferred.insert("rng".to_string());
    }
    if line.contains("fs.") || line.contains("file.") || line.contains("std.io") {
        inferred.insert("fs".to_string());
    }
    if line.contains("net.") || line.contains("socket.") || line.contains("std.net") {
        inferred.insert("net".to_string());
    }
    if line.contains("proc.") || line.contains("process.") || line.contains("std.proc") {
        inferred.insert("proc".to_string());
    }
    if line.contains("alloc.") || line.contains("std.alloc") {
        inferred.insert("mem".to_string());
    }
    if line.contains("thread.") || line.contains("std.thread") || line.contains("spawn(") {
        inferred.insert("thread".to_string());
    }
    if line.contains("await ")
        || line.contains(".await")
        || line.contains("yield(")
        || line.contains("checkpoint(")
    {
        inferred.insert("thread".to_string());
    }
    if line.contains("timeout(") || line.contains("deadline(") || line.contains("cancel(") {
        inferred.insert("net".to_string());
    }
    if line.contains("syscall.") {
        inferred.insert("proc".to_string());
    }
}

fn count_host_syscalls(line: &str) -> usize {
    line.match_indices("syscall.").count()
}

fn count_unsafe_markers(line: &str) -> usize {
    line.match_indices("unsafe ").count()
}

fn count_reference_markers(line: &str) -> usize {
    let mut count = 0usize;
    if line.contains(": &") || line.contains("-> &") {
        count += 1;
    }
    if line.contains("&mut ") {
        count += 1;
    }
    count
}

fn count_alloc_markers(line: &str) -> usize {
    line.match_indices("alloc(").count()
}

fn count_free_markers(line: &str) -> usize {
    line.match_indices("free(").count()
}

fn is_supported_type(ty: &str) -> bool {
    let ty = ty.trim();
    if ty.is_empty() {
        return false;
    }
    if let Some(inner) = ty.strip_suffix('?') {
        return is_supported_type(inner);
    }
    if let Some((left, right)) = ty.split_once('!') {
        return is_supported_type(left) && is_supported_type(right);
    }
    if let Some(inner) = ty.strip_prefix("*mut ") {
        return is_supported_type(inner);
    }
    if let Some(inner) = ty.strip_prefix('*') {
        return is_supported_type(inner);
    }
    if let Some(inner) = ty.strip_prefix("&mut ") {
        return is_supported_type(inner);
    }
    if let Some(inner) = ty.strip_prefix('&') {
        return is_supported_type(inner);
    }
    if let Some(inner) = ty.strip_prefix("[]") {
        return is_supported_type(inner);
    }
    if ty.starts_with('[') && ty.ends_with(']') {
        let inner = &ty[1..(ty.len() - 1)];
        if let Some((elem, len)) = inner.split_once(';') {
            return is_supported_type(elem.trim()) && len.trim().parse::<usize>().is_ok();
        }
        return false;
    }

    matches!(
        ty,
        "i8" | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "isize"
            | "f32"
            | "f64"
            | "bool"
            | "char"
            | "str"
            | "void"
    )
}

fn is_ffi_unstable_type(ty: &str) -> bool {
    let ty = ty.trim();
    ty == "str" || ty.starts_with("[]") || ty.starts_with('[') || ty.contains('!')
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_core_items_and_capabilities() {
        let source = r#"
            use cap.time;
            use cap.fs;
            fn main() -> i32 {
                requires true
                let x: i32 = 3
                let y = x + 4
                let z = try maybe_fail() catch 7
                defer cleanup()
                match x { 0 => 1, _ => 7 }
                ensures y == 7
                return 7
            }
            extern "C" fn c_add() -> i32;
            #[repr(C)]
            struct App {}
            #[repr(C, packed)]
            enum State {}
            mod store;
            use store::Client;
            test "smoke" {}
            let t = time.now()
            let n = net.connect()
        "#;

        let module = parse(source, "main").expect("parser should succeed");
        assert_eq!(module.name, "main");
        assert_eq!(module.capabilities.len(), 2);
        assert_eq!(module.items.len(), 5);
        assert_eq!(module.modules.len(), 1);
        assert_eq!(module.imports.len(), 1);
        let main_stmt_count = module.items.iter().find_map(|item| match item {
            ast::Item::Function(function) if function.name == "main" => Some(function.body.len()),
            _ => None,
        });
        assert_eq!(main_stmt_count, Some(8));
        assert!(module.items.iter().any(|item| {
            matches!(
                item,
                ast::Item::Function(ast::Function {
                    is_pub: false,
                    is_extern: true,
                    abi: Some(abi),
                    ..
                }) if abi == "C"
            )
        }));
        assert!(module.items.iter().any(|item| {
            matches!(
                item,
                ast::Item::Struct(ast::Struct {
                    repr: Some(repr),
                    ..
                }) if repr == "C"
            )
        }));
        assert!(module
            .inferred_capabilities
            .iter()
            .any(|cap| cap.as_str() == "time"));
        assert!(module
            .inferred_capabilities
            .iter()
            .any(|cap| cap.as_str() == "net"));
        assert!(!module
            .inferred_capabilities
            .iter()
            .any(|cap| cap.as_str() == "thread"));
        assert!(module.items.iter().any(|item| {
            matches!(
                item,
                ast::Item::Test(ast::TestBlock {
                    name,
                    deterministic: true
                }) if name == "smoke"
            )
        }));
    }

    #[test]
    fn infers_thread_capability() {
        let source = r#"
            fn main() -> i32 {
                let t = thread.spawn()
                return 0
            }
        "#;
        let module = parse(source, "threads").expect("parser should succeed");
        assert!(module
            .inferred_capabilities
            .iter()
            .any(|cap| cap.as_str() == "thread"));
    }

    #[test]
    fn parses_nondet_test_mode() {
        let source = r#"
            test "network" nondet {}
        "#;
        let module = parse(source, "tests").expect("parser should succeed");
        assert!(module.items.iter().any(|item| {
            matches!(
                item,
                ast::Item::Test(ast::TestBlock {
                    name,
                    deterministic: false
                }) if name == "network"
            )
        }));
    }

    #[test]
    fn empty_input_fails() {
        let diagnostics = parse("   ", "empty").expect_err("empty source should fail");
        assert!(!diagnostics.is_empty());
    }

    #[test]
    fn rejects_invalid_type_annotations() {
        let source = r#"
            fn main() -> weird_type {
                let x: nope = 1
                return 0
            }
        "#;
        let diagnostics = parse(source, "bad").expect_err("type errors should fail");
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("unsupported return type")));
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("unsupported type annotation")));
        assert!(diagnostics.iter().any(|d| d.span.is_some()));
        assert!(diagnostics.iter().any(|d| d.fix.is_some()));
    }

    #[test]
    fn rejects_invalid_match_arms() {
        let source = r#"
            fn main() -> i32 {
                match x { 0 1 }
                return 0
            }
        "#;
        let diagnostics = parse(source, "bad_match").expect_err("invalid match should fail");
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("invalid match arm")));
    }

    #[test]
    fn parses_pub_extern_with_params() {
        let source = r#"
            pub extern "C" fn add(left: i32, right: i32) -> i32;
        "#;
        let module = parse(source, "ffi").expect("parser should accept pub extern");
        let exported = module.items.iter().find_map(|item| match item {
            ast::Item::Function(function) if function.name == "add" => Some(function),
            _ => None,
        });
        let function = exported.expect("exported function should exist");
        assert!(function.is_pub);
        assert!(function.is_extern);
        assert_eq!(function.abi.as_deref(), Some("C"));
        assert_eq!(function.params.len(), 2);
        assert_eq!(function.params[0].name, "left");
        assert_eq!(function.params[0].ty, "i32");
    }
}
