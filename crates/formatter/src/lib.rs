#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Word,
    String,
    Char,
    Comment,
    Symbol,
    Newline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    text: String,
}

pub fn is_fzy_source_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "fzy")
}

pub fn format_source(source: &str) -> String {
    let tokens = tokenize(source);
    if tokens.is_empty() {
        return "\n".to_string();
    }

    let mut formatter = FormatterState::default();
    for (index, token) in tokens.iter().enumerate() {
        let prev_owned = formatter.prev_token.clone();
        let prev = prev_owned.as_ref();
        let next = next_significant_token(&tokens, index + 1);
        match token.kind {
            TokenKind::Newline => formatter.emit_newline_boundary(prev, next),
            TokenKind::Comment => formatter.emit_comment(token),
            TokenKind::Word | TokenKind::String | TokenKind::Char => formatter.emit_atom(token),
            TokenKind::Symbol => formatter.emit_symbol(token, next),
        }
    }

    formatter.finish()
}

#[derive(Default)]
struct FormatterState {
    out: String,
    indent: usize,
    line_start: bool,
    prev_token: Option<Token>,
    paren_depth: usize,
    bracket_depth: usize,
    brace_depth: usize,
    generic_depth: usize,
}

impl FormatterState {
    fn emit_newline_boundary(&mut self, prev: Option<&Token>, next: Option<&Token>) {
        if self.line_start {
            return;
        }
        if self.paren_depth > 0 || self.bracket_depth > 0 {
            if needs_inline_separation(prev, next) {
                self.push_space_if_missing();
            }
            return;
        }
        if should_render_newline(prev, next) {
            self.push_newline();
        } else if needs_inline_separation(prev, next) {
            self.push_space_if_missing();
        }
    }

    fn emit_comment(&mut self, token: &Token) {
        if !self.line_start {
            self.out.push(' ');
        }
        self.write_indent();
        self.line_start = false;
        self.out.push_str(&token.text);
        self.push_newline();
        self.prev_token = None;
    }

    fn emit_atom(&mut self, token: &Token) {
        let was_line_start = self.line_start;
        self.write_indent();
        self.line_start = false;
        if !was_line_start && needs_word_space(self.prev_token.as_ref(), token) {
            self.out.push(' ');
        }
        self.out.push_str(&token.text);
        self.prev_token = Some(token.clone());
    }

    fn emit_symbol(&mut self, token: &Token, next: Option<&Token>) {
        let sym = token.text.as_str();
        match sym {
            "(" => {
                self.write_indent();
                self.line_start = false;
                if needs_space_before_open_paren(self.prev_token.as_ref()) {
                    self.out.push(' ');
                }
                self.out.push('(');
                self.paren_depth += 1;
            }
            ")" => {
                self.write_indent();
                self.line_start = false;
                self.out.push(')');
                self.paren_depth = self.paren_depth.saturating_sub(1);
            }
            "[" => {
                self.write_indent();
                self.line_start = false;
                if needs_space_before_open_bracket(self.prev_token.as_ref()) {
                    self.out.push(' ');
                }
                self.out.push('[');
                self.bracket_depth += 1;
            }
            "]" => {
                self.write_indent();
                self.line_start = false;
                self.out.push(']');
                self.bracket_depth = self.bracket_depth.saturating_sub(1);
            }
            "{" => {
                self.write_indent();
                self.line_start = false;
                if needs_space_before_open_brace(self.prev_token.as_ref()) {
                    self.out.push(' ');
                }
                self.out.push('{');
                self.indent += 1;
                self.brace_depth += 1;
                self.push_newline();
            }
            "}" => {
                self.indent = self.indent.saturating_sub(1);
                self.brace_depth = self.brace_depth.saturating_sub(1);
                if !self.line_start {
                    self.push_newline();
                }
                self.write_indent();
                self.line_start = false;
                self.out.push('}');
                if next.is_some_and(|t| t.kind == TokenKind::Word && t.text == "else") {
                    self.out.push(' ');
                } else if next.is_some_and(|t| t.kind == TokenKind::Symbol && t.text == ";") {
                } else {
                    self.push_newline();
                }
            }
            ";" => {
                self.write_indent();
                self.line_start = false;
                self.out.push(';');
                if self.paren_depth == 0 && self.bracket_depth == 0 {
                    self.push_newline();
                } else if !next.is_some_and(|t| t.kind == TokenKind::Symbol && t.text == "]") {
                    self.out.push(' ');
                }
            }
            "," => {
                self.write_indent();
                self.line_start = false;
                self.out.push(',');
                if !next.is_some_and(|t| {
                    t.kind == TokenKind::Symbol && matches!(t.text.as_str(), ")" | "]" | "}")
                }) {
                    self.out.push(' ');
                }
            }
            ":" => {
                self.write_indent();
                self.line_start = false;
                self.out.push(':');
                if !next.is_some_and(|t| t.kind == TokenKind::Symbol && t.text == ":") {
                    self.out.push(' ');
                }
            }
            "::" | "." | "#" | "'" | ".." | "..=" => {
                self.write_indent();
                self.line_start = false;
                self.out.push_str(sym);
            }
            "=" | "==" | "!=" | "<=" | ">=" | "+" | "-" | "/" | "%" | "&&" | "||" | "->" | "=>"
            | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<" | ">>" | "<<="
            | ">>=" => {
                self.write_indent();
                self.line_start = false;
                trim_trailing_space(&mut self.out);
                self.out.push(' ');
                self.out.push_str(sym);
                self.out.push(' ');
            }
            "*" | "&" => {
                self.write_indent();
                self.line_start = false;
                if is_prefix_operator(self.prev_token.as_ref()) {
                    self.out.push_str(sym);
                } else {
                    trim_trailing_space(&mut self.out);
                    self.out.push(' ');
                    self.out.push_str(sym);
                    self.out.push(' ');
                }
            }
            "<" => {
                self.write_indent();
                self.line_start = false;
                if starts_generic_argument_list(self.prev_token.as_ref(), next, self.generic_depth)
                {
                    trim_trailing_space(&mut self.out);
                    self.out.push('<');
                    self.generic_depth += 1;
                } else {
                    trim_trailing_space(&mut self.out);
                    self.out.push(' ');
                    self.out.push('<');
                    self.out.push(' ');
                }
            }
            ">" => {
                self.write_indent();
                self.line_start = false;
                if self.generic_depth > 0 {
                    trim_trailing_space(&mut self.out);
                    self.out.push('>');
                    self.generic_depth -= 1;
                } else {
                    trim_trailing_space(&mut self.out);
                    self.out.push(' ');
                    self.out.push('>');
                    self.out.push(' ');
                }
            }
            _ => {
                self.write_indent();
                self.line_start = false;
                if needs_symbol_space(self.prev_token.as_ref(), token) {
                    self.out.push(' ');
                }
                self.out.push_str(sym);
            }
        }
        self.prev_token = Some(token.clone());
    }

    fn finish(mut self) -> String {
        trim_trailing_space(&mut self.out);
        if !self.out.ends_with('\n') {
            self.out.push('\n');
        }
        self.out
    }

    fn write_indent(&mut self) {
        if !self.line_start {
            return;
        }
        for _ in 0..self.indent {
            self.out.push_str("    ");
        }
    }

    fn push_space_if_missing(&mut self) {
        if !self.out.ends_with(' ') && !self.out.ends_with('\n') {
            self.out.push(' ');
        }
    }

    fn push_newline(&mut self) {
        trim_trailing_space(&mut self.out);
        if !self.out.ends_with('\n') {
            self.out.push('\n');
        }
        self.line_start = true;
    }
}

fn next_significant_token(tokens: &[Token], mut index: usize) -> Option<&Token> {
    while let Some(token) = tokens.get(index) {
        if token.kind != TokenKind::Newline {
            return Some(token);
        }
        index += 1;
    }
    None
}

fn needs_word_space(prev: Option<&Token>, current: &Token) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    match prev.kind {
        TokenKind::Word | TokenKind::String | TokenKind::Char => true,
        TokenKind::Symbol => {
            !matches!(
                prev.text.as_str(),
                "(" | "["
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
                    | "%"
                    | "&"
                    | "&&"
                    | "|"
                    | "||"
            ) && !matches!(current.kind, TokenKind::Comment)
        }
        TokenKind::Comment | TokenKind::Newline => true,
    }
}

fn needs_inline_separation(prev: Option<&Token>, next: Option<&Token>) -> bool {
    let (Some(prev), Some(next)) = (prev, next) else {
        return false;
    };
    !matches!(prev.kind, TokenKind::Symbol if matches!(prev.text.as_str(), "(" | "[" | "{" | "." | "::"))
        && !matches!(next.kind, TokenKind::Symbol if matches!(next.text.as_str(), ")" | "]" | "}" | "," | ";" | "."))
}

fn should_render_newline(prev: Option<&Token>, next: Option<&Token>) -> bool {
    let (Some(prev), Some(next)) = (prev, next) else {
        return false;
    };
    if matches!(prev.kind, TokenKind::Symbol if matches!(prev.text.as_str(), "{" | "(" | "[")) {
        return false;
    }
    if matches!(next.kind, TokenKind::Symbol if matches!(next.text.as_str(), "}" | ")" | "]")) {
        return false;
    }
    if next.kind == TokenKind::Word && next.text == "else" {
        return false;
    }
    true
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
    matches!(
        prev.kind,
        TokenKind::Word | TokenKind::String | TokenKind::Char
    )
}

fn needs_space_before_open_brace(prev: Option<&Token>) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    matches!(
        prev.kind,
        TokenKind::Word | TokenKind::String | TokenKind::Char
    ) || matches!(prev.kind, TokenKind::Symbol)
        && !matches!(prev.text.as_str(), "(" | "[" | "{" | "#" | "::" | ".")
}

fn needs_symbol_space(prev: Option<&Token>, current: &Token) -> bool {
    let Some(prev) = prev else {
        return false;
    };
    matches!(
        prev.kind,
        TokenKind::Word | TokenKind::String | TokenKind::Char
    ) && matches!(
        current.kind,
        TokenKind::Word | TokenKind::String | TokenKind::Char
    )
}

fn is_prefix_operator(prev: Option<&Token>) -> bool {
    let Some(prev) = prev else {
        return true;
    };
    matches!(prev.kind, TokenKind::Symbol)
        && matches!(
            prev.text.as_str(),
            "(" | "[" | "{" | "," | ":" | "=" | "->" | "=>" | "|" | ";" | "<"
        )
}

fn starts_generic_argument_list(
    prev: Option<&Token>,
    next: Option<&Token>,
    current_generic_depth: usize,
) -> bool {
    let (Some(prev), Some(next)) = (prev, next) else {
        return false;
    };
    if current_generic_depth > 0 {
        return true;
    }
    if !matches!(
        prev.kind,
        TokenKind::Word | TokenKind::String | TokenKind::Char
    ) && !(prev.kind == TokenKind::Symbol && matches!(prev.text.as_str(), ">" | ")" | "::"))
    {
        return false;
    }
    if prev.kind == TokenKind::Word
        && matches!(
            prev.text.as_str(),
            "if" | "while" | "return" | "let" | "discard" | "then" | "else"
        )
    {
        return false;
    }
    if !is_generic_argument_token(next) {
        return false;
    }
    if next.kind == TokenKind::Word
        && next
            .text
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
    {
        return false;
    }
    true
}

fn is_generic_argument_token(token: &Token) -> bool {
    matches!(
        token.kind,
        TokenKind::Word | TokenKind::String | TokenKind::Char
    ) || matches!(token.kind, TokenKind::Symbol if matches!(token.text.as_str(), "&" | "*" | "[" | "]" | "'" | "::"))
}

fn trim_trailing_space(out: &mut String) {
    while out.ends_with(' ') || out.ends_with('\t') {
        out.pop();
    }
}

fn tokenize(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\n' => {
                if !matches!(
                    tokens.last().map(|token: &Token| &token.kind),
                    Some(TokenKind::Newline)
                ) {
                    tokens.push(Token {
                        kind: TokenKind::Newline,
                        text: "\n".to_string(),
                    });
                }
                i += 1;
            }
            ' ' | '\t' | '\r' => i += 1,
            '/' if i + 1 < bytes.len() && bytes[i + 1] as char == '/' => {
                let start = i;
                i += 2;
                while i < bytes.len() && bytes[i] as char != '\n' {
                    i += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Comment,
                    text: source[start..i].to_string(),
                });
            }
            '"' => {
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
            }
            '\'' => {
                if let Some(end) = lex_char_literal(source, i) {
                    tokens.push(Token {
                        kind: TokenKind::Char,
                        text: source[i..end].to_string(),
                    });
                    i = end;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Symbol,
                        text: "'".to_string(),
                    });
                    i += 1;
                }
            }
            c if c.is_ascii_digit() => {
                let end = lex_number_literal(source, i);
                tokens.push(Token {
                    kind: TokenKind::Word,
                    text: source[i..end].to_string(),
                });
                i = end;
            }
            c if is_word_start(c) => {
                let start = i;
                i += 1;
                while i < bytes.len() && is_word_continue(bytes[i] as char) {
                    i += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Word,
                    text: source[start..i].to_string(),
                });
            }
            _ => {
                if let Some((len, sym)) = multi_char_symbol(source, i) {
                    tokens.push(Token {
                        kind: TokenKind::Symbol,
                        text: sym.to_string(),
                    });
                    i += len;
                } else {
                    tokens.push(Token {
                        kind: TokenKind::Symbol,
                        text: c.to_string(),
                    });
                    i += 1;
                }
            }
        }
    }

    tokens
}

fn lex_char_literal(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(start).copied()? as char != '\'' {
        return None;
    }
    let mut i = start + 1;
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
        if ch == '\'' {
            return Some(i);
        }
        if ch == '\n' {
            return None;
        }
    }
    None
}

fn lex_number_literal(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut i = start;
    while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
        i += 1;
    }

    if i + 1 < bytes.len() && bytes[i] as char == '.' && (bytes[i + 1] as char).is_ascii_digit() {
        i += 1;
        while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
            i += 1;
        }
    }

    if i < bytes.len() && matches!(bytes[i] as char, 'e' | 'E') {
        let mut cursor = i + 1;
        if cursor < bytes.len() && matches!(bytes[cursor] as char, '+' | '-') {
            cursor += 1;
        }
        let exponent_start = cursor;
        while cursor < bytes.len() && (bytes[cursor] as char).is_ascii_digit() {
            cursor += 1;
        }
        if cursor > exponent_start {
            i = cursor;
        }
    }

    if i + 2 <= bytes.len() {
        let suffix = &source[i..bytes.len().min(i + 3)];
        if suffix.starts_with("f32") || suffix.starts_with("f64") {
            i += 3;
        }
    }

    i
}

fn multi_char_symbol(source: &str, start: usize) -> Option<(usize, &'static str)> {
    for symbol in [
        "<<=", ">>=", "..=", "&&", "||", "==", "!=", "<=", ">=", "<<", ">>", "+=", "-=", "*=",
        "/=", "%=", "&=", "|=", "^=", "::", "->", "=>", "..",
    ] {
        if source[start..].starts_with(symbol) {
            return Some((symbol.len(), symbol));
        }
    }
    None
}

fn is_word_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
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
    fn preserves_newline_delimited_statements_and_logical_operators() {
        let source = "test \"det_reference_contract\" {\n    let score = runtime.surface_score()\n    if model.service_name() == \"fzweb\" && model.route_count() == 12 {\n        checkpoint()\n    }\n}\n";
        let got = format_source(source);
        let expected = "test \"det_reference_contract\" {\n    let score = runtime.surface_score()\n    if model.service_name() == \"fzweb\" && model.route_count() == 12 {\n        checkpoint()\n    }\n}\n";
        assert_eq!(got, expected);
    }

    #[test]
    fn preserves_generic_angle_brackets() {
        let source = "fn keep<T: Score>(v: T) -> T {\n    return v\n}\n";
        let got = format_source(source);
        assert!(got.contains("keep<T: Score>"));
    }

    #[test]
    fn is_idempotent() {
        let source = "fn main() -> i32 {\n    return 0;\n}\n";
        let once = format_source(source);
        let twice = format_source(&once);
        assert_eq!(once, twice);
    }
}
