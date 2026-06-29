use crate::*;

pub(crate) struct CoreStdlibBinding {
    pub(crate) name: &'static str,
    pub(crate) module_name: Option<&'static str>,
}

pub(crate) fn core_stdlib_binding(name: &str) -> Option<CoreStdlibBinding> {
    match name {
        "process" => Some(CoreStdlibBinding {
            name: "process",
            module_name: Some("process"),
        }),
        "term" => Some(CoreStdlibBinding {
            name: "term",
            module_name: Some("term"),
        }),
        "thread" => Some(CoreStdlibBinding {
            name: "thread",
            module_name: Some("thread"),
        }),
        "concurrency" => Some(CoreStdlibBinding {
            name: "concurrency",
            module_name: Some("concurrency"),
        }),
        "log" => Some(CoreStdlibBinding {
            name: "log",
            module_name: Some("log"),
        }),
        "security" => Some(CoreStdlibBinding {
            name: "security",
            module_name: Some("security"),
        }),
        "simd" => Some(CoreStdlibBinding {
            name: "simd",
            module_name: Some("simd"),
        }),
        "bytes" => Some(CoreStdlibBinding {
            name: "bytes",
            module_name: Some("bytes"),
        }),
        "gpu" => Some(CoreStdlibBinding {
            name: "gpu",
            module_name: Some("gpu"),
        }),
        "text" => Some(CoreStdlibBinding {
            name: "text",
            module_name: Some("text"),
        }),
        "io" => Some(CoreStdlibBinding {
            name: "io",
            module_name: Some("io"),
        }),
        "path" => Some(CoreStdlibBinding {
            name: "path",
            module_name: Some("path"),
        }),
        "http" => Some(CoreStdlibBinding {
            name: "http",
            module_name: Some("http"),
        }),
        "result" => Some(CoreStdlibBinding {
            name: "result",
            module_name: Some("result"),
        }),
        "env" => Some(CoreStdlibBinding {
            name: "env",
            module_name: None,
        }),
        "str" => Some(CoreStdlibBinding {
            name: "str",
            module_name: None,
        }),
        _ => None,
    }
}

pub(crate) fn core_stdlib_implied_capability(name: &str) -> Option<&'static str> {
    match name {
        "thread" => Some("thread"),
        "log" => Some("log"),
        "security" => Some("rng"),
        "http" => Some("http"),
        "gpu" => Some("gpu"),
        _ => None,
    }
}

pub(crate) fn parser_help(message: &str) -> Option<String> {
    if message == "expected parameter name" {
        Some(
            "add a parameter name before `:` or remove the stray punctuation in the function signature, then rerun `fz check`"
                .to_string(),
        )
    } else if message == "expected function body `{ ... }` or `;`" {
        Some(
            "finish the signature with a function body or terminate an extern-style declaration with `;`, then rerun `fz check`"
                .to_string(),
        )
    } else if message.starts_with("expected `") {
        Some(
            "insert the expected syntax at the highlighted location, then rerun `fz check`"
                .to_string(),
        )
    } else if message.contains("unexpected token in expression") {
        Some(
            "finish the current expression before starting a new one; check for a missing delimiter, separator, or operator immediately before this token"
                .to_string(),
        )
    } else if message.contains("invalid match pattern") {
        Some(
            "rewrite the pattern into a supported match form and keep qualifiers explicit for enum variants"
                .to_string(),
        )
    } else if message.contains("invalid") || message.contains("unsupported") {
        Some(
            "rewrite the highlighted syntax into a supported language form, then rerun `fz check`"
                .to_string(),
        )
    } else {
        Some("fix the highlighted syntax issue and rerun `fz check`".to_string())
    }
}

pub(crate) fn parser_catalog_key(message: &str) -> &'static str {
    match message {
        "expected parameter name" => "parser.expected_parameter_name",
        "expected function body `{ ... }` or `;`" => "parser.expected_function_body_or_semi",
        _ if message.starts_with("expected `") => "parser.expected_token",
        _ if message.contains("unexpected token in expression") => {
            "parser.unexpected_token_in_expression"
        }
        _ if message.contains("invalid match pattern") => "parser.invalid_match_pattern",
        _ if message.contains("invalid") || message.contains("unsupported") => {
            "parser.unsupported_syntax"
        }
        _ => "parser.syntax_error",
    }
}

pub(crate) struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    source: &'a str,
    line: usize,
    col: usize,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) identifiers: Vec<IdentifierLexeme>,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(source: &'a str) -> Self {
        Self {
            chars: source.char_indices().peekable(),
            source,
            line: 1,
            col: 1,
            diagnostics: Vec::new(),
            identifiers: Vec::new(),
        }
    }

    pub(crate) fn lex(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        while let Some((idx, ch)) = self.peek_char() {
            if ch.is_whitespace() {
                self.advance_char();
                continue;
            }
            if ch == '/' && self.peek_next('/') {
                while let Some((_, c)) = self.peek_char() {
                    self.advance_char();
                    if c == '\n' {
                        break;
                    }
                }
                continue;
            }

            let line = self.line;
            let col = self.col;
            let kind = match ch {
                '(' => {
                    self.advance_char();
                    TokenKind::LParen
                }
                ')' => {
                    self.advance_char();
                    TokenKind::RParen
                }
                '{' => {
                    self.advance_char();
                    TokenKind::LBrace
                }
                '}' => {
                    self.advance_char();
                    TokenKind::RBrace
                }
                '[' => {
                    self.advance_char();
                    TokenKind::LBracket
                }
                ']' => {
                    self.advance_char();
                    TokenKind::RBracket
                }
                ',' => {
                    self.advance_char();
                    TokenKind::Comma
                }
                ':' => {
                    self.advance_char();
                    TokenKind::Colon
                }
                ';' => {
                    self.advance_char();
                    TokenKind::Semi
                }
                '.' => {
                    self.advance_char();
                    if self.match_char('.') {
                        if self.match_char('=') {
                            TokenKind::DotDotEq
                        } else {
                            TokenKind::DotDot
                        }
                    } else {
                        TokenKind::Dot
                    }
                }
                '|' => {
                    self.advance_char();
                    if self.match_char('|') {
                        TokenKind::PipePipe
                    } else if self.match_char('=') {
                        TokenKind::PipeEq
                    } else {
                        TokenKind::Pipe
                    }
                }
                '+' => {
                    self.advance_char();
                    if self.match_char('=') {
                        TokenKind::PlusEq
                    } else {
                        TokenKind::Plus
                    }
                }
                '-' => {
                    self.advance_char();
                    if self.match_char('>') {
                        TokenKind::Arrow
                    } else if self.match_char('=') {
                        TokenKind::MinusEq
                    } else {
                        TokenKind::Minus
                    }
                }
                '*' => {
                    self.advance_char();
                    if self.match_char('=') {
                        TokenKind::StarEq
                    } else {
                        TokenKind::Star
                    }
                }
                '/' => {
                    self.advance_char();
                    if self.match_char('=') {
                        TokenKind::SlashEq
                    } else {
                        TokenKind::Slash
                    }
                }
                '%' => {
                    self.advance_char();
                    if self.match_char('=') {
                        TokenKind::PercentEq
                    } else {
                        TokenKind::Percent
                    }
                }
                '=' => {
                    self.advance_char();
                    if self.match_char('=') {
                        TokenKind::EqEq
                    } else if self.match_char('>') {
                        TokenKind::FatArrow
                    } else {
                        TokenKind::Eq
                    }
                }
                '!' => {
                    self.advance_char();
                    if self.match_char('=') {
                        TokenKind::Neq
                    } else {
                        TokenKind::Bang
                    }
                }
                '~' => {
                    self.advance_char();
                    TokenKind::Tilde
                }
                '<' => {
                    self.advance_char();
                    if self.match_char('<') {
                        if self.match_char('=') {
                            TokenKind::LtLtEq
                        } else {
                            TokenKind::LtLt
                        }
                    } else if self.match_char('=') {
                        TokenKind::Lte
                    } else {
                        TokenKind::Lt
                    }
                }
                '>' => {
                    self.advance_char();
                    if self.match_char('>') {
                        if self.match_char('=') {
                            TokenKind::GtGtEq
                        } else {
                            TokenKind::GtGt
                        }
                    } else if self.match_char('=') {
                        TokenKind::Gte
                    } else {
                        TokenKind::Gt
                    }
                }
                '&' => {
                    self.advance_char();
                    if self.match_char('&') {
                        TokenKind::AmpAmp
                    } else if self.match_char('=') {
                        TokenKind::AmpEq
                    } else {
                        TokenKind::Amp
                    }
                }
                '^' => {
                    self.advance_char();
                    if self.match_char('=') {
                        TokenKind::CaretEq
                    } else {
                        TokenKind::Caret
                    }
                }
                '\'' => {
                    if let Some((value, consumed_cols)) = self.try_lex_char_literal() {
                        for _ in 0..consumed_cols {
                            self.advance_char();
                        }
                        TokenKind::Char(value)
                    } else {
                        self.advance_char();
                        TokenKind::Apostrophe
                    }
                }
                '#' => {
                    self.advance_char();
                    TokenKind::Hash
                }
                '"' => {
                    self.advance_char();
                    TokenKind::Str(self.lex_string_literal(line, col, idx).into_boxed_str())
                }
                c if c.is_ascii_digit() => self.lex_number_literal(idx),
                c if is_ident_start(c) => {
                    let start = idx;
                    let mut end = idx + 1;
                    let start_line = line;
                    let start_col = col;
                    self.advance_char();
                    while let Some((i, next)) = self.peek_char() {
                        if is_ident_continue(next) {
                            end = i + 1;
                            self.advance_char();
                        } else {
                            break;
                        }
                    }
                    let ident = &self.source[start..end];
                    let kind = keyword_or_ident(ident);
                    if matches!(kind, TokenKind::Ident(_)) {
                        self.identifiers.push(IdentifierLexeme {
                            name: ident.to_string(),
                            line: start_line.saturating_sub(1),
                            col: start_col.saturating_sub(1),
                            len: ident.len(),
                        });
                    }
                    kind
                }
                _ => {
                    let message = format!("unknown token `{ch}`");
                    self.diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            message,
                            Some("remove or replace unsupported symbol".to_string()),
                        )
                        .with_span(line, col, line, col + 1),
                    );
                    self.advance_char();
                    continue;
                }
            };
            tokens.push(Token { kind, line, col });
        }
        tokens.push(Token {
            kind: TokenKind::Eof,
            line: self.line,
            col: self.col,
        });
        tokens
    }

    fn lex_number_literal(&mut self, start_idx: usize) -> TokenKind {
        self.advance_char();
        while let Some((_, next)) = self.peek_char() {
            if next.is_ascii_digit() {
                self.advance_char();
            } else {
                break;
            }
        }

        let mut is_float = false;
        if self.peek_char().is_some_and(|(_, c)| c == '.')
            && self.peek_nth_char(1).is_some_and(|c| c.is_ascii_digit())
        {
            is_float = true;
            self.advance_char();
            while let Some((_, next)) = self.peek_char() {
                if next.is_ascii_digit() {
                    self.advance_char();
                } else {
                    break;
                }
            }
        }

        if self.peek_char().is_some_and(|(_, c)| c == 'e' || c == 'E')
            && self
                .peek_nth_char(1)
                .is_some_and(|c| c.is_ascii_digit() || c == '+' || c == '-')
        {
            is_float = true;
            self.advance_char();
            if self.peek_char().is_some_and(|(_, c)| c == '+' || c == '-') {
                self.advance_char();
            }
            let mut saw_digit = false;
            while let Some((_, next)) = self.peek_char() {
                if next.is_ascii_digit() {
                    saw_digit = true;
                    self.advance_char();
                } else {
                    break;
                }
            }
            if !saw_digit {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        "malformed float exponent",
                        Some("expected digits after exponent marker".to_string()),
                    )
                    .with_span(
                        self.line,
                        self.col.saturating_sub(1),
                        self.line,
                        self.col,
                    ),
                );
            }
        }

        let mut bits = None;
        if self.peek_char().is_some_and(|(_, c)| c == 'f') {
            let tail = [self.peek_nth_char(1), self.peek_nth_char(2)];
            match tail {
                [Some('3'), Some('2')] => {
                    bits = Some(32);
                    self.advance_char();
                    self.advance_char();
                    self.advance_char();
                }
                [Some('6'), Some('4')] => {
                    bits = Some(64);
                    self.advance_char();
                    self.advance_char();
                    self.advance_char();
                }
                _ => {}
            }
        }

        let end_idx = self.peek_char().map_or(self.source.len(), |(idx, _)| idx);
        let literal = &self.source[start_idx..end_idx];
        if is_float || bits.is_some() {
            match literal
                .trim_end_matches("f32")
                .trim_end_matches("f64")
                .parse::<f64>()
            {
                Ok(value) => {
                    if !value.is_finite() {
                        self.diagnostics.push(Diagnostic::new(
                            Severity::Error,
                            "float literal overflow",
                            Some("value must be finite".to_string()),
                        ));
                        return TokenKind::Float { value: 0.0, bits };
                    }
                    if bits == Some(32) {
                        let narrowed = value as f32;
                        if !narrowed.is_finite() || (value != 0.0 && narrowed == 0.0) {
                            self.diagnostics.push(Diagnostic::new(
                                Severity::Error,
                                "f32 literal precision/overflow failure",
                                Some("use smaller magnitude or `f64`".to_string()),
                            ));
                        }
                    }
                    TokenKind::Float { value, bits }
                }
                Err(_) => {
                    self.diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        "invalid float literal",
                        Some("use decimal/exponent form like `1.5`, `1e3`, `1.0f32`".to_string()),
                    ));
                    TokenKind::Float { value: 0.0, bits }
                }
            }
        } else {
            match literal.parse::<i128>() {
                Ok(value) => TokenKind::Int(value),
                Err(_) => {
                    self.diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        "integer literal exceeds i128 range",
                        Some("use smaller literal or explicit narrowing".to_string()),
                    ));
                    TokenKind::Int(0)
                }
            }
        }
    }

    fn try_lex_char_literal(&mut self) -> Option<(char, usize)> {
        let start_idx = self.peek_char()?.0;
        let mut iter = self.source[start_idx..].char_indices().peekable();
        let _ = iter.next();
        let (_, first) = iter.next()?;
        if first == '\\' {
            let mut scratch = Vec::new();
            let value = self.decode_escape_sequence_from_iter(
                &mut iter,
                self.line,
                self.col + 1,
                "char",
                &mut scratch,
            )?;
            let (_, end_quote) = iter.next()?;
            if end_quote != '\'' {
                return None;
            }
            let consumed_cols = scratch.len() + 3;
            return Some((value, consumed_cols));
        }
        let (_, end_quote) = iter.next()?;
        if end_quote != '\'' {
            return None;
        }
        Some((first, 3))
    }

    fn peek_char(&mut self) -> Option<(usize, char)> {
        self.chars.peek().copied()
    }

    fn match_char(&mut self, expected: char) -> bool {
        if self.peek_char().is_some_and(|(_, c)| c == expected) {
            self.advance_char();
            true
        } else {
            false
        }
    }

    fn peek_next(&mut self, expected: char) -> bool {
        self.peek_next_char().is_some_and(|c| c == expected)
    }

    fn peek_next_char(&mut self) -> Option<char> {
        let start_idx = self.peek_char()?.0;
        self.source[start_idx..].chars().nth(1)
    }

    fn peek_nth_char(&mut self, n: usize) -> Option<char> {
        let start_idx = self.peek_char()?.0;
        self.source[start_idx..].chars().nth(n)
    }

    fn advance_char(&mut self) {
        if let Some((_, ch)) = self.chars.next() {
            if ch == '\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
        }
    }

    fn lex_string_literal(
        &mut self,
        start_line: usize,
        start_col: usize,
        opening_quote_idx: usize,
    ) -> String {
        let mut value = String::new();
        let mut terminated = false;
        while let Some((_, ch)) = self.peek_char() {
            self.advance_char();
            match ch {
                '"' => {
                    terminated = true;
                    break;
                }
                '\\' => {
                    if self.peek_char().is_none() {
                        self.diagnostics.push(
                            Diagnostic::new(
                                Severity::Error,
                                "unterminated string escape",
                                Some(
                                    "complete the escape sequence or close the string".to_string(),
                                ),
                            )
                            .with_span(start_line, start_col, self.line, self.col),
                        );
                        break;
                    }
                    let mut raw = Vec::new();
                    match self.decode_escape_sequence(self.line, self.col, "string", &mut raw) {
                        Some(decoded) => value.push(decoded),
                        None => {
                            if let Some(last) = raw.last() {
                                value.push(*last);
                            }
                        }
                    }
                }
                _ => value.push(ch),
            }
        }

        if !terminated {
            let string_start = opening_quote_idx + 1;
            let end_idx = self.peek_char().map_or(self.source.len(), |(idx, _)| idx);
            let fallback = if string_start < end_idx {
                self.source[string_start..end_idx].to_string()
            } else {
                String::new()
            };
            self.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    "unterminated string literal",
                    Some("add a closing `\"`".to_string()),
                )
                .with_span(start_line, start_col, self.line, self.col),
            );
            return if value.is_empty() { fallback } else { value };
        }
        value
    }

    fn decode_escape_sequence(
        &mut self,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
    ) -> Option<char> {
        let Some((_, escape)) = self.peek_char() else {
            self.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!("unterminated {literal_kind} escape"),
                    Some("complete the escape sequence".to_string()),
                )
                .with_span(start_line, start_col, self.line, self.col),
            );
            return None;
        };
        self.advance_char();
        raw.push(escape);
        self.decode_escape_tail(
            escape,
            start_line,
            start_col,
            literal_kind,
            raw,
            |lexer| lexer.peek_char(),
            |lexer| lexer.advance_char(),
        )
    }

    fn decode_escape_sequence_from_iter(
        &mut self,
        iter: &mut std::iter::Peekable<std::str::CharIndices<'a>>,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
    ) -> Option<char> {
        let (_, escape) = iter.next()?;
        raw.push(escape);
        match escape {
            '"' => Some('"'),
            '\'' => Some('\''),
            '\\' => Some('\\'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            '0'..='7' => {
                let mut digits = String::from(escape);
                for _ in 0..2 {
                    let Some((_, next)) = iter.peek().copied() else {
                        break;
                    };
                    if !matches!(next, '0'..='7') {
                        break;
                    }
                    let _ = iter.next();
                    raw.push(next);
                    digits.push(next);
                }
                self.finish_numeric_escape(&digits, 8, start_line, start_col, literal_kind, "octal")
            }
            'x' => self.decode_fixed_width_escape_from_iter(
                iter,
                2,
                16,
                start_line,
                start_col,
                literal_kind,
                raw,
                "hex",
            ),
            'u' => {
                if let Some((_, '{')) = iter.peek().copied() {
                    let _ = iter.next();
                    raw.push('{');
                    self.decode_braced_unicode_escape_from_iter(
                        iter,
                        start_line,
                        start_col,
                        literal_kind,
                        raw,
                    )
                } else {
                    self.decode_fixed_width_escape_from_iter(
                        iter,
                        4,
                        16,
                        start_line,
                        start_col,
                        literal_kind,
                        raw,
                        "unicode",
                    )
                }
            }
            _ => {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("unsupported {literal_kind} escape `\\{escape}`"),
                        Some(
                            "supported escapes: \\\\, \\\", \\\', \\n, \\r, \\t, \\0, \\xNN, \\uNNNN, \\u{NN...}, \\NNN"
                                .to_string(),
                        ),
                    )
                    .with_span(start_line, start_col, self.line, self.col),
                );
                Some(escape)
            }
        }
    }

    fn decode_escape_tail<Peek, Advance>(
        &mut self,
        escape: char,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
        mut peek: Peek,
        mut advance: Advance,
    ) -> Option<char>
    where
        Peek: FnMut(&mut Self) -> Option<(usize, char)>,
        Advance: FnMut(&mut Self),
    {
        match escape {
            '"' => Some('"'),
            '\'' => Some('\''),
            '\\' => Some('\\'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            '0'..='7' => self.decode_octal_escape(
                escape,
                start_line,
                start_col,
                literal_kind,
                raw,
                &mut peek,
                &mut advance,
            ),
            'x' => self.decode_fixed_width_escape(
                2,
                16,
                start_line,
                start_col,
                literal_kind,
                raw,
                "hex",
                &mut peek,
                &mut advance,
            ),
            'u' => {
                if let Some((_, '{')) = peek(self) {
                    advance(self);
                    raw.push('{');
                    self.decode_braced_unicode_escape(
                        start_line,
                        start_col,
                        literal_kind,
                        raw,
                        &mut peek,
                        &mut advance,
                    )
                } else {
                    self.decode_fixed_width_escape(
                        4,
                        16,
                        start_line,
                        start_col,
                        literal_kind,
                        raw,
                        "unicode",
                        &mut peek,
                        &mut advance,
                    )
                }
            }
            _ => {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("unsupported {literal_kind} escape `\\{escape}`"),
                        Some(
                            "supported escapes: \\\\, \\\", \\\', \\n, \\r, \\t, \\0, \\xNN, \\uNNNN, \\u{NN...}, \\NNN"
                                .to_string(),
                        ),
                    )
                    .with_span(start_line, start_col, self.line, self.col),
                );
                Some(escape)
            }
        }
    }

    fn decode_octal_escape<Peek, Advance>(
        &mut self,
        first: char,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
        peek: &mut Peek,
        advance: &mut Advance,
    ) -> Option<char>
    where
        Peek: FnMut(&mut Self) -> Option<(usize, char)>,
        Advance: FnMut(&mut Self),
    {
        let mut digits = String::from(first);
        for _ in 0..2 {
            let Some((_, next)) = peek(self) else {
                break;
            };
            if !matches!(next, '0'..='7') {
                break;
            }
            advance(self);
            raw.push(next);
            digits.push(next);
        }
        self.finish_numeric_escape(&digits, 8, start_line, start_col, literal_kind, "octal")
    }

    fn decode_fixed_width_escape<Peek, Advance>(
        &mut self,
        width: usize,
        radix: u32,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
        label: &str,
        peek: &mut Peek,
        advance: &mut Advance,
    ) -> Option<char>
    where
        Peek: FnMut(&mut Self) -> Option<(usize, char)>,
        Advance: FnMut(&mut Self),
    {
        let mut digits = String::new();
        for _ in 0..width {
            let Some((_, next)) = peek(self) else {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("incomplete {literal_kind} {label} escape"),
                        Some(format!(
                            "expected {width} hexadecimal digit(s) after `\\{}`",
                            if label == "unicode" { "u" } else { "x" }
                        )),
                    )
                    .with_span(start_line, start_col, self.line, self.col),
                );
                return None;
            };
            if !next.is_ascii_hexdigit() {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("invalid {literal_kind} {label} escape"),
                        Some(format!(
                            "use only hexadecimal digits in `\\{}` escapes",
                            if label == "unicode" { "u" } else { "x" }
                        )),
                    )
                    .with_span(start_line, start_col, self.line, self.col + 1),
                );
                return Some(next);
            }
            advance(self);
            raw.push(next);
            digits.push(next);
        }
        self.finish_numeric_escape(&digits, radix, start_line, start_col, literal_kind, label)
    }

    fn decode_braced_unicode_escape<Peek, Advance>(
        &mut self,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
        peek: &mut Peek,
        advance: &mut Advance,
    ) -> Option<char>
    where
        Peek: FnMut(&mut Self) -> Option<(usize, char)>,
        Advance: FnMut(&mut Self),
    {
        let mut digits = String::new();
        while let Some((_, next)) = peek(self) {
            if next == '}' {
                advance(self);
                raw.push('}');
                if digits.is_empty() || digits.len() > 6 {
                    self.diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            format!("invalid {literal_kind} unicode escape"),
                            Some(
                                "use between 1 and 6 hexadecimal digits inside `\\u{...}`"
                                    .to_string(),
                            ),
                        )
                        .with_span(start_line, start_col, self.line, self.col),
                    );
                    return None;
                }
                return self.finish_numeric_escape(
                    &digits,
                    16,
                    start_line,
                    start_col,
                    literal_kind,
                    "unicode",
                );
            }
            if !next.is_ascii_hexdigit() {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("invalid {literal_kind} unicode escape"),
                        Some("use only hexadecimal digits inside `\\u{...}`".to_string()),
                    )
                    .with_span(start_line, start_col, self.line, self.col + 1),
                );
                return Some(next);
            }
            advance(self);
            raw.push(next);
            digits.push(next);
        }
        self.diagnostics.push(
            Diagnostic::new(
                Severity::Error,
                format!("unterminated {literal_kind} unicode escape"),
                Some("close the escape with `}`".to_string()),
            )
            .with_span(start_line, start_col, self.line, self.col),
        );
        None
    }

    fn decode_fixed_width_escape_from_iter(
        &mut self,
        iter: &mut std::iter::Peekable<std::str::CharIndices<'a>>,
        width: usize,
        radix: u32,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
        label: &str,
    ) -> Option<char> {
        let mut digits = String::new();
        for _ in 0..width {
            let Some((_, next)) = iter.peek().copied() else {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("incomplete {literal_kind} {label} escape"),
                        Some(format!(
                            "expected {width} hexadecimal digit(s) after `\\{}`",
                            if label == "unicode" { "u" } else { "x" }
                        )),
                    )
                    .with_span(start_line, start_col, self.line, self.col),
                );
                return None;
            };
            if !next.is_ascii_hexdigit() {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("invalid {literal_kind} {label} escape"),
                        Some(format!(
                            "use only hexadecimal digits in `\\{}` escapes",
                            if label == "unicode" { "u" } else { "x" }
                        )),
                    )
                    .with_span(start_line, start_col, self.line, self.col + 1),
                );
                return Some(next);
            }
            let _ = iter.next();
            raw.push(next);
            digits.push(next);
        }
        self.finish_numeric_escape(&digits, radix, start_line, start_col, literal_kind, label)
    }

    fn decode_braced_unicode_escape_from_iter(
        &mut self,
        iter: &mut std::iter::Peekable<std::str::CharIndices<'a>>,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        raw: &mut Vec<char>,
    ) -> Option<char> {
        let mut digits = String::new();
        while let Some((_, next)) = iter.peek().copied() {
            if next == '}' {
                let _ = iter.next();
                raw.push('}');
                if digits.is_empty() || digits.len() > 6 {
                    self.diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            format!("invalid {literal_kind} unicode escape"),
                            Some(
                                "use between 1 and 6 hexadecimal digits inside `\\u{...}`"
                                    .to_string(),
                            ),
                        )
                        .with_span(start_line, start_col, self.line, self.col),
                    );
                    return None;
                }
                return self.finish_numeric_escape(
                    &digits,
                    16,
                    start_line,
                    start_col,
                    literal_kind,
                    "unicode",
                );
            }
            if !next.is_ascii_hexdigit() {
                self.diagnostics.push(
                    Diagnostic::new(
                        Severity::Error,
                        format!("invalid {literal_kind} unicode escape"),
                        Some("use only hexadecimal digits inside `\\u{...}`".to_string()),
                    )
                    .with_span(start_line, start_col, self.line, self.col + 1),
                );
                return Some(next);
            }
            let _ = iter.next();
            raw.push(next);
            digits.push(next);
        }
        self.diagnostics.push(
            Diagnostic::new(
                Severity::Error,
                format!("unterminated {literal_kind} unicode escape"),
                Some("close the escape with `}`".to_string()),
            )
            .with_span(start_line, start_col, self.line, self.col),
        );
        None
    }

    fn finish_numeric_escape(
        &mut self,
        digits: &str,
        radix: u32,
        start_line: usize,
        start_col: usize,
        literal_kind: &str,
        label: &str,
    ) -> Option<char> {
        let Ok(value) = u32::from_str_radix(digits, radix) else {
            self.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!("invalid {literal_kind} {label} escape"),
                    Some(format!("could not parse {label} digits `{digits}`")),
                )
                .with_span(start_line, start_col, self.line, self.col),
            );
            return None;
        };
        let Some(decoded) = char::from_u32(value) else {
            self.diagnostics.push(
                Diagnostic::new(
                    Severity::Error,
                    format!("{literal_kind} {label} escape is out of range"),
                    Some("use a valid Unicode scalar value".to_string()),
                )
                .with_span(start_line, start_col, self.line, self.col),
            );
            return None;
        };
        Some(decoded)
    }
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn keyword_or_ident(ident: &str) -> TokenKind {
    match ident {
        "fn" => TokenKind::KwFn,
        "pub" => TokenKind::KwPub,
        "pubext" => TokenKind::KwPubext,
        "const" => TokenKind::KwConst,
        "static" => TokenKind::KwStatic,
        "type" => TokenKind::KwType,
        "newtype" => TokenKind::KwNewtype,
        "ext" => TokenKind::KwExt,
        "unsafe" => TokenKind::KwUnsafe,
        "async" => TokenKind::KwAsync,
        "host" => TokenKind::KwHost,
        "pure" => TokenKind::KwPure,
        "device" => TokenKind::KwDevice,
        "kernel" => TokenKind::KwKernel,
        "await" => TokenKind::KwAwait,
        "rpc" => TokenKind::KwRpc,
        "use" => TokenKind::KwUse,
        "core" => TokenKind::KwCore,
        "mod" => TokenKind::KwMod,
        "struct" => TokenKind::KwStruct,
        "enum" => TokenKind::KwEnum,
        "trait" => TokenKind::KwTrait,
        "impl" => TokenKind::KwImpl,
        "for" => TokenKind::KwFor,
        "in" => TokenKind::KwIn,
        "loop" => TokenKind::KwLoop,
        "break" => TokenKind::KwBreak,
        "continue" => TokenKind::KwContinue,
        "test" => TokenKind::KwTest,
        "nondet" => TokenKind::KwNondet,
        "let" => TokenKind::KwLet,
        "requires" => TokenKind::KwRequires,
        "ensures" => TokenKind::KwEnsures,
        "return" => TokenKind::KwReturn,
        "defer" => TokenKind::KwDefer,
        "match" => TokenKind::KwMatch,
        "if" => TokenKind::KwIf,
        "then" => TokenKind::KwThen,
        "else" => TokenKind::KwElse,
        "while" => TokenKind::KwWhile,
        "try" => TokenKind::KwTry,
        "catch" => TokenKind::KwCatch,
        "discard" => TokenKind::KwDiscard,
        "true" => TokenKind::KwTrue,
        "false" => TokenKind::KwFalse,
        _ => TokenKind::Ident(ident.into()),
    }
}
