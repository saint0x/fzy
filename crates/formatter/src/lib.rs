#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Word,
    String,
    Comment,
    Symbol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    text: String,
}

pub fn is_fzy_source_path(path: &std::path::Path) -> bool {
    path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "fzy")
}

pub fn format_source(source: &str) -> String {
    let tokens = tokenize(source);
    if tokens.is_empty() {
        return "\n".to_string();
    }

    let mut out = String::new();
    let mut indent = 0usize;
    let mut line_start = true;
    let mut prev: Option<&Token> = None;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;

    for (index, token) in tokens.iter().enumerate() {
        let next = tokens.get(index + 1);
        match token.kind {
            TokenKind::Comment => {
                if !line_start {
                    out.push(' ');
                }
                write_indent(&mut out, line_start, indent);
                line_start = false;
                out.push_str(&token.text);
                push_newline(&mut out, &mut line_start);
                prev = None;
                continue;
            }
            TokenKind::Word | TokenKind::String => {
                write_indent(&mut out, line_start, indent);
                line_start = false;
                if needs_word_space(prev, token) {
                    out.push(' ');
                }
                out.push_str(&token.text);
            }
            TokenKind::Symbol => {
                let sym = token.text.as_str();
                match sym {
                    "(" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        if needs_space_before_open_paren(prev) {
                            out.push(' ');
                        }
                        out.push('(');
                        paren_depth += 1;
                    }
                    ")" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push(')');
                        paren_depth = paren_depth.saturating_sub(1);
                    }
                    "[" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        if needs_space_before_open_bracket(prev) {
                            out.push(' ');
                        }
                        out.push('[');
                        bracket_depth += 1;
                    }
                    "]" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push(']');
                        bracket_depth = bracket_depth.saturating_sub(1);
                    }
                    "{" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        if needs_space_before_open_brace(prev) {
                            out.push(' ');
                        }
                        out.push('{');
                        indent += 1;
                        push_newline(&mut out, &mut line_start);
                    }
                    "}" => {
                        indent = indent.saturating_sub(1);
                        if !line_start {
                            push_newline(&mut out, &mut line_start);
                        }
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push('}');
                        if next.is_some_and(|t| t.kind == TokenKind::Word && t.text == "else") {
                            out.push(' ');
                        } else if next.is_some_and(|t| t.kind == TokenKind::Symbol && t.text == ";")
                        {
                        } else {
                            push_newline(&mut out, &mut line_start);
                        }
                    }
                    ";" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push(';');
                        if paren_depth == 0 && bracket_depth == 0 {
                            push_newline(&mut out, &mut line_start);
                        } else if !next.is_some_and(|t| t.kind == TokenKind::Symbol && t.text == "]") {
                            out.push(' ');
                        }
                    }
                    "," => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push(',');
                        if !next.is_some_and(|t| t.kind == TokenKind::Symbol && (t.text == ")" || t.text == "]" || t.text == "}"))
                        {
                            out.push(' ');
                        }
                    }
                    ":" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push(':');
                        if !next.is_some_and(|t| t.kind == TokenKind::Symbol && t.text == ":") {
                            out.push(' ');
                        }
                    }
                    "::" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push_str("::");
                    }
                    "." => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push('.');
                    }
                    "#" | "'" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        out.push_str(sym);
                    }
                    "->" | "=>" | "==" | "!=" | "<=" | ">=" | "=" | "+" | "-" | "/" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        trim_trailing_space(&mut out);
                        out.push(' ');
                        out.push_str(sym);
                        out.push(' ');
                    }
                    "*" | "&" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        if is_prefix_operator(prev) {
                            out.push_str(sym);
                        } else {
                            trim_trailing_space(&mut out);
                            out.push(' ');
                            out.push_str(sym);
                            out.push(' ');
                        }
                    }
                    "<" | ">" | "|" => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        if should_tight_symbol(sym, prev, next) {
                            out.push_str(sym);
                        } else {
                            trim_trailing_space(&mut out);
                            out.push(' ');
                            out.push_str(sym);
                            out.push(' ');
                        }
                    }
                    _ => {
                        write_indent(&mut out, line_start, indent);
                        line_start = false;
                        if needs_symbol_space(prev, token) {
                            out.push(' ');
                        }
                        out.push_str(sym);
                    }
                }
            }
        }
        prev = Some(token);
    }

    trim_trailing_space(&mut out);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn needs_word_space(prev: Option<&Token>, current: &Token) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    match prev.kind {
        TokenKind::Word | TokenKind::String => true,
        TokenKind::Symbol => {
            !matches!(
                prev.text.as_str(),
                "("
                    | "["
                    | "{"
                    | "#"
                    | "."
                    | "::"
                    | "'"
                    | ","
                    | "}"
                    | ";"
                    | ":"
                    | "="
                    | "->"
                    | "=>"
                    | "=="
                    | "!="
                    | "<"
                    | "<="
                    | ">"
                    | ">="
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "&"
                    | "|"
            )
                && !matches!(current.kind, TokenKind::Comment)
        }
        TokenKind::Comment => true,
    }
}

fn needs_space_before_open_paren(prev: Option<&Token>) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    matches!(
        prev.kind,
        TokenKind::Word if matches!(prev.text.as_str(), "if" | "while" | "match" | "catch")
    )
}

fn needs_space_before_open_bracket(prev: Option<&Token>) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    matches!(prev.kind, TokenKind::Word | TokenKind::String)
}

fn needs_space_before_open_brace(prev: Option<&Token>) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    matches!(prev.kind, TokenKind::Word | TokenKind::String)
        || matches!(prev.kind, TokenKind::Symbol)
            && !matches!(prev.text.as_str(), "(" | "[" | "{" | "#" | "::" | ".")
}

fn needs_symbol_space(prev: Option<&Token>, current: &Token) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    matches!(prev.kind, TokenKind::Word | TokenKind::String)
        && matches!(current.kind, TokenKind::Word | TokenKind::String)
}

fn is_prefix_operator(prev: Option<&Token>) -> bool {
    let Some(prev) = prev else {
        return true;
    };
    matches!(prev.kind, TokenKind::Symbol)
        && matches!(
            prev.text.as_str(),
            "(" | "[" | "{" | "," | ":" | "=" | "->" | "=>" | "|" | ";"
        )
}

fn should_tight_symbol(sym: &str, prev: Option<&Token>, next: Option<&Token>) -> bool {
    let _ = (sym, prev, next);
    false
}

fn write_indent(out: &mut String, line_start: bool, indent: usize) {
    if !line_start {
        return;
    }
    for _ in 0..indent {
        out.push_str("    ");
    }
}

fn trim_trailing_space(out: &mut String) {
    while out.ends_with(' ') || out.ends_with('\t') {
        out.pop();
    }
}

fn push_newline(out: &mut String, line_start: &mut bool) {
    trim_trailing_space(out);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    *line_start = true;
}

fn tokenize(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] as char == '/' {
            let start = i;
            i += 2;
            while i < bytes.len() && bytes[i] as char != '\n' {
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Comment,
                text: source[start..i].to_string(),
            });
            continue;
        }

        if c == '"' {
            let start = i;
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let ch = bytes[i] as char;
                i += 1;
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == '"' {
                    break;
                }
            }
            tokens.push(Token {
                kind: TokenKind::String,
                text: source[start..i].to_string(),
            });
            continue;
        }

        if is_word_start(c) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_word_continue(bytes[i] as char) {
                i += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Word,
                text: source[start..i].to_string(),
            });
            continue;
        }

        if i + 1 < bytes.len() {
            let pair = &source[i..i + 2];
            if matches!(pair, "::" | "->" | "=>" | "==" | "!=" | "<=" | ">=") {
                tokens.push(Token {
                    kind: TokenKind::Symbol,
                    text: pair.to_string(),
                });
                i += 2;
                continue;
            }
        }

        tokens.push(Token {
            kind: TokenKind::Symbol,
            text: c.to_string(),
        });
        i += 1;
    }

    tokens
}

fn is_word_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c.is_ascii_digit()
}

fn is_word_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::format_source;

    #[test]
    fn canonicalizes_spacing_and_blocks() {
        let source = "fn   main( )  ->  i32{let x:i32=1;if x<3{return x;}else{return 0;}}";
        let got = format_source(source);
        let expected = "fn main() -> i32 {\n    let x: i32 = 1;\n    if x < 3 {\n        return x;\n    } else {\n        return 0;\n    }\n}\n";
        assert_eq!(got, expected);
    }

    #[test]
    fn preserves_comments_and_strings() {
        let source = "fn main()->i32{//comment\nlet s:str=\"a\\\"b\\n\";return 0;}";
        let got = format_source(source);
        assert!(got.contains("//comment"));
        assert!(got.contains("\"a\\\"b\\n\""));
    }

    #[test]
    fn is_idempotent() {
        let source = "fn main() -> i32 {\n    return 0;\n}\n";
        let once = format_source(source);
        let twice = format_source(&once);
        assert_eq!(once, twice);
    }
}
