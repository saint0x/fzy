use ast::{BinaryOp, Expr, MatchArm, Module, Pattern, Stmt, Type, UnaryOp};
use diagnostics::{assign_stable_codes, Diagnostic, DiagnosticDomain, Severity};

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    line: usize,
    col: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum TokenKind {
    Ident(String),
    Int(i128),
    Float { value: f64, bits: Option<u16> },
    Char(char),
    Str(String),
    KwFn,
    KwPub,
    KwExtern,
    KwAsync,
    KwAwait,
    KwRpc,
    KwUse,
    KwCore,
    KwMod,
    KwStruct,
    KwEnum,
    KwTrait,
    KwImpl,
    KwFor,
    KwIn,
    KwLoop,
    KwBreak,
    KwContinue,
    KwTest,
    KwNondet,
    KwLet,
    KwRequires,
    KwEnsures,
    KwReturn,
    KwDefer,
    KwMatch,
    KwIf,
    KwElse,
    KwWhile,
    KwTry,
    KwCatch,
    KwTrue,
    KwFalse,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Colon,
    Semi,
    Dot,
    DotDot,
    DotDotEq,
    Pipe,
    PipePipe,
    Plus,
    PlusEq,
    Minus,
    MinusEq,
    Star,
    StarEq,
    Slash,
    SlashEq,
    Percent,
    PercentEq,
    Eq,
    EqEq,
    Neq,
    Lt,
    LtLt,
    LtLtEq,
    Lte,
    Gt,
    GtGt,
    GtGtEq,
    Gte,
    AmpAmp,
    AmpEq,
    Caret,
    CaretEq,
    PipeEq,
    Arrow,
    FatArrow,
    Amp,
    Apostrophe,
    Bang,
    Tilde,
    Hash,
    Eof,
}

pub fn parse(source: &str, module_name: &str) -> Result<Module, Vec<Diagnostic>> {
    if source.trim().is_empty() {
        return Err(vec![Diagnostic::new(
            Severity::Error,
            "source is empty",
            Some("provide at least one declaration".to_string()),
        )]);
    }

    let mut lexer = Lexer::new(source);
    let tokens = lexer.lex();
    let mut diagnostics = lexer.diagnostics;
    let mut parser = Parser::new(tokens, module_name);
    let module = parser.parse_module();
    diagnostics.extend(parser.diagnostics);
    if diagnostics.is_empty() {
        Ok(module)
    } else {
        assign_stable_codes(&mut diagnostics, DiagnosticDomain::Parser);
        Err(diagnostics)
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    diagnostics: Vec<Diagnostic>,
    module: Module,
    pending_repr: Option<String>,
    pending_ffi_panic: Option<String>,
}

impl Parser {
    fn new(tokens: Vec<Token>, module_name: &str) -> Self {
        Self {
            tokens,
            pos: 0,
            diagnostics: Vec::new(),
            module: Module {
                name: module_name.to_string(),
                items: Vec::new(),
                modules: Vec::new(),
                imports: Vec::new(),
                capabilities: Vec::new(),
                host_syscall_sites: 0,
                unsafe_sites: 0,
                unsafe_reasoned_sites: 0,
                reference_sites: 0,
                alloc_sites: 0,
                free_sites: 0,
            },
            pending_repr: None,
            pending_ffi_panic: None,
        }
    }

    fn parse_module(&mut self) -> Module {
        while !self.at(&TokenKind::Eof) {
            let start = self.pos;
            if self.at(&TokenKind::Hash) {
                self.parse_attribute();
                continue;
            }
            match self.parse_item() {
                Some(item) => self.module.items.push(item),
                None => {
                    if self.pos == start {
                        self.recover_item();
                    }
                }
            }
        }
        std::mem::take(&mut self.module)
    }

    fn parse_attribute(&mut self) {
        let Some(hash) = self.advance() else {
            return;
        };
        if !self.consume(&TokenKind::LBracket) {
            self.push_diag_at(hash.line, hash.col, "expected `[` after `#`");
            return;
        }
        let Some(name_token) = self.advance() else {
            return;
        };
        let TokenKind::Ident(name) = &name_token.kind else {
            self.push_diag_at(name_token.line, name_token.col, "expected attribute name");
            return;
        };
        match name.as_str() {
            "repr" => {
                if !self.consume(&TokenKind::LParen) {
                    self.push_diag_at(name_token.line, name_token.col, "expected `(` after `repr`");
                    return;
                }
                let mut parts = Vec::new();
                while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                    let Some(tok) = self.advance() else {
                        break;
                    };
                    match tok.kind {
                        TokenKind::Ident(part) => parts.push(part),
                        TokenKind::Comma => {}
                        _ => {
                            self.push_diag_at(tok.line, tok.col, "invalid repr attribute component")
                        }
                    }
                }
                let _ = self.consume(&TokenKind::RParen);
                let _ = self.consume(&TokenKind::RBracket);
                if !parts.is_empty() {
                    self.pending_repr = Some(parts.join(", "));
                }
            }
            "ffi_panic" => {
                if !self.consume(&TokenKind::LParen) {
                    self.push_diag_at(
                        name_token.line,
                        name_token.col,
                        "expected `(` after `ffi_panic`",
                    );
                    return;
                }
                let mode = match self.advance() {
                    Some(Token {
                        kind: TokenKind::Ident(mode),
                        ..
                    }) => mode,
                    Some(tok) => {
                        self.push_diag_at(tok.line, tok.col, "invalid ffi_panic mode");
                        String::new()
                    }
                    None => String::new(),
                };
                if !mode.is_empty() && mode != "abort" && mode != "error" {
                    self.push_diag_at(
                        name_token.line,
                        name_token.col,
                        "ffi_panic mode must be `abort` or `error`",
                    );
                } else if !mode.is_empty() {
                    self.pending_ffi_panic = Some(mode);
                }
                let _ = self.consume(&TokenKind::RParen);
                let _ = self.consume(&TokenKind::RBracket);
            }
            _ => {
                self.push_diag_at(name_token.line, name_token.col, "unsupported attribute");
                self.consume_until(&[TokenKind::RBracket]);
                let _ = self.consume(&TokenKind::RBracket);
            }
        }
    }

    fn parse_item(&mut self) -> Option<ast::Item> {
        if self.pending_ffi_panic.is_some()
            && !matches!(
                self.peek_kind(),
                TokenKind::KwFn | TokenKind::KwAsync | TokenKind::KwPub | TokenKind::KwExtern
            )
        {
            self.push_diag_here("`#[ffi_panic(...)]` applies only to functions");
            self.pending_ffi_panic = None;
        }
        if self.at(&TokenKind::KwUse) {
            self.parse_use_or_cap();
            return None;
        }
        if self.at(&TokenKind::KwMod) {
            self.parse_mod_decl();
            return None;
        }
        if self.at(&TokenKind::KwTest) {
            return self.parse_test();
        }
        if self.at(&TokenKind::KwStruct) {
            return self.parse_struct();
        }
        if self.at(&TokenKind::KwEnum) {
            return self.parse_enum();
        }
        if self.at(&TokenKind::KwTrait) {
            return self.parse_trait();
        }
        if self.at(&TokenKind::KwImpl) {
            return self.parse_impl();
        }
        if self.at(&TokenKind::KwRpc) {
            self.parse_rpc_decl();
            return None;
        }
        self.parse_function()
    }

    fn parse_rpc_decl(&mut self) {
        let _ = self.consume(&TokenKind::KwRpc);
        let Some(name) = self.expect_ident("expected rpc method name") else {
            self.consume_until(&[TokenKind::Semi]);
            let _ = self.consume(&TokenKind::Semi);
            return;
        };
        if !self.consume(&TokenKind::LParen) {
            self.push_diag_here("expected `(` after rpc method name");
            self.consume_until(&[TokenKind::Semi]);
            let _ = self.consume(&TokenKind::Semi);
            return;
        }
        let mut params = Vec::new();
        let mut positional = 0usize;
        while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
            let (param_name, ty) = if matches!(self.peek_kind(), TokenKind::Ident(_))
                && matches!(self.peek_n(1).map(|tok| &tok.kind), Some(TokenKind::Colon))
            {
                let Some(param_name) = self.expect_ident("expected rpc parameter name") else {
                    break;
                };
                let _ = self.consume(&TokenKind::Colon);
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                };
                (param_name, ty)
            } else {
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                };
                let name = format!("arg{positional}");
                positional += 1;
                (name, ty)
            };
            params.push(ast::Param {
                name: param_name,
                ty,
            });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        let _ = self.consume(&TokenKind::RParen);
        let return_type = if self.consume(&TokenKind::Arrow) {
            self.parse_type().unwrap_or(Type::Void)
        } else {
            Type::Void
        };
        let _ = self.consume(&TokenKind::Semi);
        self.module.items.push(ast::Item::Function(ast::Function {
            name,
            generics: Vec::new(),
            params,
            return_type,
            body: Vec::new(),
            is_async: false,
            is_pub: false,
            is_extern: true,
            abi: Some("rpc".to_string()),
            ffi_panic: None,
        }));
    }

    fn parse_use_or_cap(&mut self) {
        let _ = self.consume(&TokenKind::KwUse);
        if self.consume(&TokenKind::KwCore) {
            if !self.consume(&TokenKind::Dot) {
                self.push_diag_here("expected `.` after `use core`");
                return;
            }
            let Some(cap) = self.expect_ident("expected capability name") else {
                return;
            };
            self.module.capabilities.push(cap);
            let _ = self.consume(&TokenKind::Semi);
            return;
        }

        let mut path = String::new();
        let Some(first) = self.expect_ident("expected import path") else {
            return;
        };
        path.push_str(&first);
        while self.consume(&TokenKind::Colon) {
            if !self.consume(&TokenKind::Colon) {
                self.push_diag_here("expected `::` in import path");
                break;
            }
            if let Some(seg) = self.expect_ident("expected import path segment") {
                path.push_str("::");
                path.push_str(&seg);
            } else {
                break;
            }
        }
        self.module.imports.push(path);
        let _ = self.consume(&TokenKind::Semi);
    }

    fn parse_mod_decl(&mut self) {
        let _ = self.consume(&TokenKind::KwMod);
        let Some(name) = self.expect_ident("expected module name") else {
            return;
        };
        self.module.modules.push(name);
        let _ = self.consume(&TokenKind::Semi);
    }

    fn parse_test(&mut self) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwTest);
        let name = match self.advance()?.kind {
            TokenKind::Str(value) => value,
            _ => {
                self.push_diag_here("expected quoted test name");
                return None;
            }
        };
        let deterministic = !self.consume(&TokenKind::KwNondet);
        let body = if self.at(&TokenKind::LBrace) {
            self.parse_block()?
        } else {
            self.push_diag_here("expected `{` to start test body");
            return None;
        };
        Some(ast::Item::Test(ast::TestBlock {
            name,
            deterministic,
            body,
        }))
    }

    fn parse_struct(&mut self) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwStruct);
        let name = self.expect_ident("expected struct name")?;
        let mut fields = Vec::new();
        if self.consume(&TokenKind::LBrace) {
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                let field_name = match self.expect_ident("expected field name") {
                    Some(v) => v,
                    None => break,
                };
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in field declaration");
                    self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                }
                let field_ty = match self.parse_type() {
                    Some(ty) => ty,
                    None => {
                        self.consume_until(&[TokenKind::Comma, TokenKind::RBrace]);
                        let _ = self.consume(&TokenKind::Comma);
                        continue;
                    }
                };
                fields.push(ast::Field {
                    name: field_name,
                    ty: field_ty,
                });
                let _ = self.consume(&TokenKind::Comma);
            }
            let _ = self.consume(&TokenKind::RBrace);
        }
        Some(ast::Item::Struct(ast::Struct {
            name,
            fields,
            repr: self.pending_repr.take(),
        }))
    }

    fn parse_enum(&mut self) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwEnum);
        let name = self.expect_ident("expected enum name")?;
        let mut variants = Vec::new();
        if self.consume(&TokenKind::LBrace) {
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                let Some(variant_name) = self.expect_ident("expected variant name") else {
                    break;
                };
                let mut payload = Vec::new();
                if self.consume(&TokenKind::LParen) {
                    while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                        if let Some(ty) = self.parse_type() {
                            payload.push(ty);
                        }
                        if !self.consume(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let _ = self.consume(&TokenKind::RParen);
                }
                variants.push(ast::Variant {
                    name: variant_name,
                    payload,
                });
                let _ = self.consume(&TokenKind::Comma);
            }
            let _ = self.consume(&TokenKind::RBrace);
        }
        Some(ast::Item::Enum(ast::Enum {
            name,
            variants,
            repr: self.pending_repr.take(),
        }))
    }

    fn parse_trait(&mut self) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwTrait);
        let name = self.expect_ident("expected trait name")?;
        if !self.consume(&TokenKind::LBrace) {
            self.push_diag_here("expected `{` after trait name");
            return None;
        }
        let mut methods = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            if !self.consume(&TokenKind::KwFn) {
                self.push_diag_here("expected `fn` in trait body");
                self.recover_item();
                continue;
            }
            let method_name = self.expect_ident("expected trait method name")?;
            if !self.consume(&TokenKind::LParen) {
                self.push_diag_here("expected `(` after trait method name");
                return None;
            }
            let mut params = Vec::new();
            while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                let param_name = match self.expect_ident("expected parameter name") {
                    Some(v) => v,
                    None => break,
                };
                if !self.consume(&TokenKind::Colon) {
                    self.push_diag_here("expected `:` in parameter declaration");
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                }
                let Some(ty) = self.parse_type() else {
                    self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                };
                params.push(ast::Param {
                    name: param_name,
                    ty,
                });
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::RParen);
            let return_type = if self.consume(&TokenKind::Arrow) {
                self.parse_type().unwrap_or(Type::Void)
            } else {
                Type::Void
            };
            let _ = self.consume(&TokenKind::Semi);
            methods.push(ast::TraitMethod {
                name: method_name,
                params,
                return_type,
            });
        }
        let _ = self.consume(&TokenKind::RBrace);
        Some(ast::Item::Trait(ast::Trait { name, methods }))
    }

    fn parse_impl(&mut self) -> Option<ast::Item> {
        let _ = self.consume(&TokenKind::KwImpl);
        let first = self.parse_type()?;
        let (trait_name, for_type) = if self.consume(&TokenKind::KwFor) {
            let Some(ty) = self.parse_type() else {
                self.push_diag_here("expected type after `for`");
                return None;
            };
            let trait_name = match first {
                Type::Named { name, args } if args.is_empty() => Some(name),
                Type::TypeVar(name) => Some(name),
                _ => {
                    self.push_diag_here("trait in impl must be a named trait");
                    None
                }
            };
            (trait_name, ty)
        } else {
            (None, first)
        };
        if !self.consume(&TokenKind::LBrace) {
            self.push_diag_here("expected `{` after impl header");
            return None;
        }
        let mut methods = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            match self.parse_function()? {
                ast::Item::Function(function) => methods.push(function),
                _ => {
                    self.push_diag_here("expected function in impl body");
                    self.recover_item();
                }
            }
        }
        let _ = self.consume(&TokenKind::RBrace);
        Some(ast::Item::Impl(ast::Impl {
            trait_name,
            for_type,
            methods,
        }))
    }

    fn parse_function(&mut self) -> Option<ast::Item> {
        let is_async = self.consume(&TokenKind::KwAsync);
        let is_pub = self.consume(&TokenKind::KwPub);
        let is_extern = self.consume(&TokenKind::KwExtern);
        let abi = if is_extern {
            match self.advance()?.kind {
                TokenKind::Str(v) => Some(v),
                _ => {
                    self.push_diag_here("expected ABI string in extern declaration");
                    return None;
                }
            }
        } else {
            None
        };
        if !self.consume(&TokenKind::KwFn) {
            if is_pub || is_extern {
                self.push_diag_here("expected `fn` declaration");
            }
            return None;
        }
        let name = self.expect_ident("expected function name")?;
        let generics = self.parse_generic_params();

        if !self.consume(&TokenKind::LParen) {
            self.push_diag_here("expected `(` after function name");
            return None;
        }
        let mut params = Vec::new();
        while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
            let param_name = match self.expect_ident("expected parameter name") {
                Some(v) => v,
                None => break,
            };
            if !self.consume(&TokenKind::Colon) {
                self.push_diag_here("expected `:` in parameter declaration");
                self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                let _ = self.consume(&TokenKind::Comma);
                continue;
            }
            let Some(ty) = self.parse_type() else {
                self.consume_until(&[TokenKind::Comma, TokenKind::RParen]);
                let _ = self.consume(&TokenKind::Comma);
                continue;
            };
            params.push(ast::Param {
                name: param_name,
                ty,
            });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        let _ = self.consume(&TokenKind::RParen);

        let return_type = if self.consume(&TokenKind::Arrow) {
            self.parse_type().unwrap_or(Type::Void)
        } else {
            Type::Void
        };

        let mut body = Vec::new();
        if self.consume(&TokenKind::Semi) {
            // extern declaration
        } else if self.consume(&TokenKind::LBrace) {
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                match self.parse_stmt() {
                    Some(stmt) => body.push(stmt),
                    None => self.recover_stmt(),
                }
            }
            let _ = self.consume(&TokenKind::RBrace);
        } else {
            self.push_diag_here("expected function body `{ ... }` or `;`");
        }

        Some(ast::Item::Function(ast::Function {
            name,
            generics,
            params,
            return_type,
            body,
            is_async,
            is_pub,
            is_extern,
            abi,
            ffi_panic: self.pending_ffi_panic.take(),
        }))
    }

    fn parse_stmt(&mut self) -> Option<Stmt> {
        if self.consume(&TokenKind::KwLet) {
            let name = self.expect_ident("expected let binding name")?;
            let ty = if self.consume(&TokenKind::Colon) {
                self.parse_type()
            } else {
                None
            };
            if !self.consume(&TokenKind::Eq) {
                self.push_diag_here("expected `=` in let binding");
                return None;
            }
            let value = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Let { name, ty, value });
        }

        if self.consume(&TokenKind::KwIf) {
            let condition = self.parse_expr(0)?;
            let then_body = self.parse_block()?;
            let else_body = if self.consume(&TokenKind::KwElse) {
                if self.at(&TokenKind::KwIf) {
                    vec![self.parse_stmt()?]
                } else {
                    self.parse_block()?
                }
            } else {
                Vec::new()
            };
            return Some(Stmt::If {
                condition,
                then_body,
                else_body,
            });
        }

        if self.consume(&TokenKind::KwWhile) {
            let condition = self.parse_expr(0)?;
            let body = self.parse_block()?;
            return Some(Stmt::While { condition, body });
        }

        if self.consume(&TokenKind::KwFor) {
            return self.parse_for_stmt();
        }

        if self.consume(&TokenKind::KwLoop) {
            let body = self.parse_block()?;
            return Some(Stmt::Loop { body });
        }

        if self.consume(&TokenKind::KwBreak) {
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Break);
        }

        if self.consume(&TokenKind::KwContinue) {
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Continue);
        }

        if self.consume(&TokenKind::KwRequires) {
            let expr = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Requires(expr));
        }

        if self.consume(&TokenKind::KwEnsures) {
            let expr = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Ensures(expr));
        }

        if self.consume(&TokenKind::KwReturn) {
            let expr = if self.at(&TokenKind::Semi) {
                None
            } else {
                Some(self.parse_expr(0)?)
            };
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Return(expr));
        }

        if self.consume(&TokenKind::KwDefer) {
            let expr = self.parse_expr(0)?;
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Defer(expr));
        }

        if self.consume(&TokenKind::KwMatch) {
            let scrutinee = self.parse_expr(0)?;
            if !self.consume(&TokenKind::LBrace) {
                self.push_diag_here("expected `{` after match scrutinee");
                return None;
            }
            let mut arms = Vec::new();
            while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                let pattern = self.parse_pattern()?;
                if !self.consume(&TokenKind::FatArrow) {
                    let guard = if self.consume(&TokenKind::KwIf) {
                        self.parse_expr(0)
                    } else {
                        None
                    };
                    if !self.consume(&TokenKind::FatArrow) {
                        self.push_diag_here("expected `=>` in match arm");
                        return None;
                    }
                    let returns = self.consume(&TokenKind::KwReturn);
                    let value = self.parse_expr(0)?;
                    arms.push(MatchArm {
                        pattern,
                        guard,
                        returns,
                        value,
                    });
                    let _ = self.consume(&TokenKind::Comma);
                    continue;
                }
                let returns = self.consume(&TokenKind::KwReturn);
                let value = self.parse_expr(0)?;
                arms.push(MatchArm {
                    pattern,
                    guard: None,
                    returns,
                    value,
                });
                let _ = self.consume(&TokenKind::Comma);
            }
            let _ = self.consume(&TokenKind::RBrace);
            let _ = self.consume(&TokenKind::Semi);
            return Some(Stmt::Match { scrutinee, arms });
        }

        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_))) {
            if self.peek_n(1).is_some_and(|t| t.kind == TokenKind::Eq) {
                let target = self.expect_ident("expected assignment target")?;
                let _ = self.consume(&TokenKind::Eq);
                let value = self.parse_expr(0)?;
                let _ = self.consume(&TokenKind::Semi);
                return Some(Stmt::Assign { target, value });
            }
            if let Some(op) = self.compound_assign_op() {
                let target = self.expect_ident("expected assignment target")?;
                let _ = self.advance();
                let value = self.parse_expr(0)?;
                let _ = self.consume(&TokenKind::Semi);
                return Some(Stmt::CompoundAssign { target, op, value });
            }
        }

        let expr = self.parse_expr(0)?;
        let _ = self.consume(&TokenKind::Semi);
        Some(Stmt::Expr(expr))
    }

    fn parse_block(&mut self) -> Option<Vec<Stmt>> {
        if !self.consume(&TokenKind::LBrace) {
            self.push_diag_here("expected `{` to start block");
            return None;
        }
        let mut body = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            if let Some(stmt) = self.parse_stmt() {
                body.push(stmt);
            } else {
                self.recover_stmt();
            }
        }
        let _ = self.consume(&TokenKind::RBrace);
        Some(body)
    }

    fn parse_for_stmt(&mut self) -> Option<Stmt> {
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_)))
            && self.peek_n(1).is_some_and(|t| t.kind == TokenKind::KwIn)
        {
            let binding = self.expect_ident("expected loop binding name after `for`")?;
            let _ = self.consume(&TokenKind::KwIn);
            let iterable = self.parse_expr(0)?;
            let body = self.parse_block()?;
            return Some(Stmt::ForIn {
                binding,
                iterable,
                body,
            });
        }

        let init = if self.consume(&TokenKind::Semi) {
            None
        } else {
            Some(Box::new(self.parse_for_clause_stmt(true)?))
        };
        let condition = if self.consume(&TokenKind::Semi) {
            None
        } else {
            let condition = self.parse_expr(0)?;
            if !self.consume(&TokenKind::Semi) {
                self.push_diag_here("expected `;` after for-loop condition");
                return None;
            }
            Some(condition)
        };
        let step = if self.at(&TokenKind::LBrace) {
            None
        } else {
            Some(Box::new(self.parse_for_clause_stmt(false)?))
        };
        let body = self.parse_block()?;
        Some(Stmt::For {
            init,
            condition,
            step,
            body,
        })
    }

    fn parse_for_clause_stmt(&mut self, expect_trailing_semi: bool) -> Option<Stmt> {
        let stmt = if self.consume(&TokenKind::KwLet) {
            let name = self.expect_ident("expected let binding name")?;
            let ty = if self.consume(&TokenKind::Colon) {
                self.parse_type()
            } else {
                None
            };
            if !self.consume(&TokenKind::Eq) {
                self.push_diag_here("expected `=` in let binding");
                return None;
            }
            let value = self.parse_expr(0)?;
            Stmt::Let { name, ty, value }
        } else if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_)))
            && self.peek_n(1).is_some_and(|t| t.kind == TokenKind::Eq)
        {
            let target = self.expect_ident("expected assignment target")?;
            let _ = self.consume(&TokenKind::Eq);
            let value = self.parse_expr(0)?;
            Stmt::Assign { target, value }
        } else if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Ident(_)))
            && self.compound_assign_op().is_some()
        {
            let op = self.compound_assign_op()?;
            let target = self.expect_ident("expected assignment target")?;
            let _ = self.advance();
            let value = self.parse_expr(0)?;
            Stmt::CompoundAssign { target, op, value }
        } else {
            let value = self.parse_expr(0)?;
            Stmt::Expr(value)
        };

        if expect_trailing_semi && !self.consume(&TokenKind::Semi) {
            self.push_diag_here("expected `;` in for-loop header");
            return None;
        }
        Some(stmt)
    }

    fn parse_pattern(&mut self) -> Option<Pattern> {
        let mut patterns = Vec::new();
        patterns.push(self.parse_single_pattern()?);
        while self.consume(&TokenKind::Pipe) {
            patterns.push(self.parse_single_pattern()?);
        }
        if patterns.len() == 1 {
            patterns.pop()
        } else {
            Some(Pattern::Or(patterns))
        }
    }

    fn parse_single_pattern(&mut self) -> Option<Pattern> {
        let token = self.peek()?.clone();
        let expr = self.parse_prefix_expr()?;
        match expr {
            Expr::Int(v) => Some(Pattern::Int(v)),
            Expr::Bool(v) => Some(Pattern::Bool(v)),
            Expr::Ident(name) if name == "_" => Some(Pattern::Wildcard),
            Expr::Ident(name) => {
                if name.chars().next().is_some_and(char::is_uppercase) {
                    self.push_diag_at(
                        token.line,
                        token.col,
                        "capitalized bare pattern is not supported; use `Enum::Variant` or a lowercase binding",
                    );
                    return None;
                }
                Some(Pattern::Ident(name))
            }
            Expr::EnumInit {
                enum_name,
                variant,
                payload,
            } => {
                let mut bindings = Vec::with_capacity(payload.len());
                for value in payload {
                    let Expr::Ident(name) = value else {
                        self.push_diag_at(
                            token.line,
                            token.col,
                            "enum variant pattern bindings must be identifiers",
                        );
                        return None;
                    };
                    bindings.push(name);
                }
                Some(Pattern::Variant {
                    enum_name,
                    variant,
                    bindings,
                })
            }
            Expr::Call { callee, .. } => {
                let _ = callee;
                self.push_diag_at(
                    token.line,
                    token.col,
                    "unqualified enum variant pattern is not supported; use `Enum::Variant(...)`",
                );
                None
            }
            _ => {
                self.push_diag_at(token.line, token.col, "invalid match pattern");
                None
            }
        }
    }

    fn parse_expr(&mut self, min_prec: u8) -> Option<Expr> {
        let mut left = self.parse_prefix_expr()?;
        loop {
            if min_prec == 0 {
                if self.consume(&TokenKind::DotDot) {
                    let right = self.parse_expr(1)?;
                    left = Expr::Range {
                        start: Box::new(left),
                        end: Box::new(right),
                        inclusive: false,
                    };
                    continue;
                }
                if self.consume(&TokenKind::DotDotEq) {
                    let right = self.parse_expr(1)?;
                    left = Expr::Range {
                        start: Box::new(left),
                        end: Box::new(right),
                        inclusive: true,
                    };
                    continue;
                }
            }
            let Some((op, prec)) = self.current_binary_op() else {
                break;
            };
            if prec < min_prec {
                break;
            }
            let _ = self.advance();
            let right = self.parse_expr(prec + 1)?;
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Some(left)
    }

    fn parse_prefix_expr(&mut self) -> Option<Expr> {
        if self.consume(&TokenKind::KwTry) {
            let try_expr = self.parse_expr(0)?;
            if !self.consume(&TokenKind::KwCatch) {
                self.push_diag_here("expected `catch` in try/catch expression");
                return None;
            }
            let catch_expr = self.parse_expr(0)?;
            return Some(Expr::TryCatch {
                try_expr: Box::new(try_expr),
                catch_expr: Box::new(catch_expr),
            });
        }
        if self.consume(&TokenKind::KwAwait) {
            let awaited = self.parse_prefix_expr()?;
            return Some(Expr::Await(Box::new(awaited)));
        }
        if self.consume(&TokenKind::Bang) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(expr),
            });
        }
        if self.consume(&TokenKind::Minus) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::Neg,
                expr: Box::new(expr),
            });
        }
        if self.consume(&TokenKind::Plus) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::Plus,
                expr: Box::new(expr),
            });
        }
        if self.consume(&TokenKind::Tilde) {
            let expr = self.parse_prefix_expr()?;
            return Some(Expr::Unary {
                op: UnaryOp::BitNot,
                expr: Box::new(expr),
            });
        }

        let token = self.advance()?;
        let mut expr = match token.kind {
            TokenKind::Int(v) => Expr::Int(v),
            TokenKind::Float { value, bits } => Expr::Float { value, bits },
            TokenKind::Char(value) => Expr::Char(value),
            TokenKind::KwTrue => Expr::Bool(true),
            TokenKind::KwFalse => Expr::Bool(false),
            TokenKind::Str(v) => Expr::Str(v),
            TokenKind::KwRpc => Expr::Ident("rpc".to_string()),
            TokenKind::Ident(name) => {
                if self.looks_like_struct_initializer() {
                    let _ = self.consume(&TokenKind::LBrace);
                    let mut fields = Vec::new();
                    while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                        let field_name =
                            self.expect_ident("expected field name in struct initializer")?;
                        if !self.consume(&TokenKind::Colon) {
                            self.push_diag_here("expected `:` in struct initializer");
                            return None;
                        }
                        let value = self.parse_expr(0)?;
                        fields.push((field_name, value));
                        if !self.consume(&TokenKind::Comma) {
                            break;
                        }
                    }
                    let _ = self.consume(&TokenKind::RBrace);
                    Expr::StructInit { name, fields }
                } else if self.at(&TokenKind::Colon)
                    && self.peek_n(1).is_some_and(|t| t.kind == TokenKind::Colon)
                {
                    let _ = self.consume(&TokenKind::Colon);
                    let _ = self.consume(&TokenKind::Colon);
                    let variant = self.expect_ident("expected enum variant name")?;
                    let mut payload = Vec::new();
                    if self.consume(&TokenKind::LParen) {
                        while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                            payload.push(self.parse_expr(0)?);
                            if !self.consume(&TokenKind::Comma) {
                                break;
                            }
                        }
                        let _ = self.consume(&TokenKind::RParen);
                    }
                    Expr::EnumInit {
                        enum_name: name,
                        variant,
                        payload,
                    }
                } else {
                    Expr::Ident(name)
                }
            }
            TokenKind::LParen => {
                let inner = self.parse_expr(0)?;
                let _ = self.consume(&TokenKind::RParen);
                Expr::Group(Box::new(inner))
            }
            TokenKind::LBracket => {
                let mut items = Vec::new();
                while !self.at(&TokenKind::RBracket) && !self.at(&TokenKind::Eof) {
                    items.push(self.parse_expr(0)?);
                    if !self.consume(&TokenKind::Comma) {
                        break;
                    }
                }
                let _ = self.consume(&TokenKind::RBracket);
                Expr::ArrayLiteral(items)
            }
            _ => {
                self.push_diag_at(token.line, token.col, "unexpected token in expression");
                return None;
            }
        };

        loop {
            if self.consume(&TokenKind::Dot) {
                let seg = self.expect_member_name("expected member name after `.`")?;
                expr = Expr::FieldAccess {
                    base: Box::new(expr),
                    field: seg,
                };
                continue;
            }
            if self.at(&TokenKind::Lt) {
                if let Some(generic_callee) = self.try_parse_generic_callee(&expr) {
                    expr = generic_callee;
                    continue;
                }
            }
            if self.consume(&TokenKind::LParen) {
                let mut args = Vec::new();
                while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
                    if let Some(arg) = self.parse_expr(0) {
                        args.push(arg);
                    }
                    if !self.consume(&TokenKind::Comma) {
                        break;
                    }
                }
                let _ = self.consume(&TokenKind::RParen);
                let Some(callee) = Self::expr_to_callee_name(&expr) else {
                    self.push_diag_here("callee must be an identifier");
                    return None;
                };
                expr = Expr::Call { callee, args };
                continue;
            }
            if self.consume(&TokenKind::LBracket) {
                let index = self.parse_expr(0)?;
                if !self.consume(&TokenKind::RBracket) {
                    self.push_diag_here("expected `]` after index expression");
                    return None;
                }
                expr = Expr::Index {
                    base: Box::new(expr),
                    index: Box::new(index),
                };
                continue;
            }
            break;
        }

        Some(expr)
    }

    fn parse_type(&mut self) -> Option<Type> {
        if self.consume(&TokenKind::Star) {
            let mutable = self.consume(&TokenKind::Ident("mut".to_string()));
            let inner = self.parse_type()?;
            return Some(Type::Ptr {
                mutable,
                to: Box::new(inner),
            });
        }
        if self.consume(&TokenKind::Amp) {
            let lifetime = if self.consume(&TokenKind::Apostrophe) {
                Some(self.expect_ident("expected lifetime name after `'`")?)
            } else {
                None
            };
            let mutable = self.consume(&TokenKind::Ident("mut".to_string()));
            let inner = self.parse_type()?;
            return Some(Type::Ref {
                mutable,
                lifetime,
                to: Box::new(inner),
            });
        }
        if self.consume(&TokenKind::LBracket) {
            if self.consume(&TokenKind::RBracket) {
                let elem = self.parse_type()?;
                return Some(Type::Slice(Box::new(elem)));
            }
            let elem = self.parse_type()?;
            if !self.consume(&TokenKind::Semi) {
                self.push_diag_here("expected `;` in array type");
                return None;
            }
            let len = match self.advance()?.kind {
                TokenKind::Int(v) if v >= 0 => match usize::try_from(v) {
                    Ok(value) => value,
                    Err(_) => {
                        self.push_diag_here("array length exceeds target usize");
                        return None;
                    }
                },
                _ => {
                    self.push_diag_here("expected array length integer");
                    return None;
                }
            };
            let _ = self.consume(&TokenKind::RBracket);
            return Some(Type::Array {
                elem: Box::new(elem),
                len,
            });
        }

        let name = self.expect_ident("expected type")?;
        let mut args = Vec::new();
        if self.consume(&TokenKind::Lt) {
            while !self.at(&TokenKind::Gt) && !self.at(&TokenKind::Eof) {
                if let Some(ty) = self.parse_type() {
                    args.push(ty);
                }
                if !self.consume(&TokenKind::Comma) {
                    break;
                }
            }
            let _ = self.consume(&TokenKind::Gt);
        }

        let ty = match (name.as_str(), args.as_slice()) {
            ("void", []) => Type::Void,
            ("bool", []) => Type::Bool,
            ("char", []) => Type::Char,
            ("str", []) => Type::Str,
            ("i8", []) => Type::Int {
                signed: true,
                bits: 8,
            },
            ("i16", []) => Type::Int {
                signed: true,
                bits: 16,
            },
            ("i32", []) => Type::Int {
                signed: true,
                bits: 32,
            },
            ("i64", []) => Type::Int {
                signed: true,
                bits: 64,
            },
            ("i128", []) => Type::Int {
                signed: true,
                bits: 128,
            },
            ("isize", []) => Type::ISize,
            ("u8", []) => Type::Int {
                signed: false,
                bits: 8,
            },
            ("u16", []) => Type::Int {
                signed: false,
                bits: 16,
            },
            ("u32", []) => Type::Int {
                signed: false,
                bits: 32,
            },
            ("u64", []) => Type::Int {
                signed: false,
                bits: 64,
            },
            ("u128", []) => Type::Int {
                signed: false,
                bits: 128,
            },
            ("usize", []) => Type::USize,
            ("f32", []) => Type::Float { bits: 32 },
            ("f64", []) => Type::Float { bits: 64 },
            ("Vec", [inner]) => Type::Vec(Box::new(inner.clone())),
            ("Option", [inner]) => Type::Option(Box::new(inner.clone())),
            ("Result", [ok, err]) => Type::Result {
                ok: Box::new(ok.clone()),
                err: Box::new(err.clone()),
            },
            _ => {
                if args.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                    Type::TypeVar(name)
                } else {
                    Type::Named { name, args }
                }
            }
        };
        Some(ty)
    }

    fn parse_generic_params(&mut self) -> Vec<ast::GenericParam> {
        let mut out = Vec::new();
        if !self.consume(&TokenKind::Lt) {
            return out;
        }
        while !self.at(&TokenKind::Gt) && !self.at(&TokenKind::Eof) {
            let Some(name) = self.expect_ident("expected generic parameter name") else {
                break;
            };
            let mut bounds = Vec::new();
            if self.consume(&TokenKind::Colon) {
                loop {
                    let Some(bound) = self.expect_ident("expected trait bound") else {
                        break;
                    };
                    bounds.push(bound);
                    if !self.consume(&TokenKind::Plus) {
                        break;
                    }
                }
            }
            out.push(ast::GenericParam { name, bounds });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        let _ = self.consume(&TokenKind::Gt);
        out
    }

    fn looks_like_struct_initializer(&self) -> bool {
        if !self.at(&TokenKind::LBrace) {
            return false;
        }
        match (self.peek_n(1), self.peek_n(2), self.peek_n(3)) {
            (
                Some(Token {
                    kind: TokenKind::RBrace,
                    ..
                }),
                _,
                _,
            ) => true,
            (
                Some(Token {
                    kind: TokenKind::Ident(_),
                    ..
                }),
                Some(Token {
                    kind: TokenKind::Colon,
                    ..
                }),
                next,
            ) => !matches!(
                next,
                Some(Token {
                    kind: TokenKind::Colon,
                    ..
                })
            ),
            _ => false,
        }
    }

    fn try_parse_generic_callee(&mut self, expr: &Expr) -> Option<Expr> {
        let save = self.pos;
        let diag_len = self.diagnostics.len();
        let mut args = Vec::new();
        let _ = self.consume(&TokenKind::Lt);
        while !self.at(&TokenKind::Gt) && !self.at(&TokenKind::Eof) {
            let Some(ty) = self.parse_type() else {
                self.pos = save;
                self.diagnostics.truncate(diag_len);
                return None;
            };
            args.push(ty);
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        if !self.consume(&TokenKind::Gt) || !self.at(&TokenKind::LParen) {
            self.pos = save;
            self.diagnostics.truncate(diag_len);
            return None;
        }
        let callee = match expr {
            Expr::Ident(name) => name.clone(),
            _ => {
                self.pos = save;
                self.diagnostics.truncate(diag_len);
                return None;
            }
        };
        let rendered = args
            .iter()
            .map(|ty| ty.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Some(Expr::Ident(format!("{callee}<{rendered}>")))
    }

    fn expr_to_callee_name(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Ident(name) => Some(name.clone()),
            Expr::Group(inner) => Self::expr_to_callee_name(inner),
            Expr::FieldAccess { base, field } => {
                let base = Self::expr_to_callee_name(base)?;
                Some(format!("{base}.{field}"))
            }
            _ => None,
        }
    }

    fn current_binary_op(&self) -> Option<(BinaryOp, u8)> {
        let kind = &self.peek()?.kind;
        let (op, prec) = match kind {
            TokenKind::PipePipe => (BinaryOp::Or, 1),
            TokenKind::AmpAmp => (BinaryOp::And, 2),
            TokenKind::Pipe => (BinaryOp::BitOr, 3),
            TokenKind::Caret => (BinaryOp::BitXor, 4),
            TokenKind::Amp => (BinaryOp::BitAnd, 5),
            TokenKind::EqEq => (BinaryOp::Eq, 6),
            TokenKind::Neq => (BinaryOp::Neq, 6),
            TokenKind::Lt => (BinaryOp::Lt, 7),
            TokenKind::Lte => (BinaryOp::Lte, 7),
            TokenKind::Gt => (BinaryOp::Gt, 7),
            TokenKind::Gte => (BinaryOp::Gte, 7),
            TokenKind::LtLt => (BinaryOp::Shl, 8),
            TokenKind::GtGt => (BinaryOp::Shr, 8),
            TokenKind::Plus => (BinaryOp::Add, 9),
            TokenKind::Minus => (BinaryOp::Sub, 9),
            TokenKind::Star => (BinaryOp::Mul, 10),
            TokenKind::Slash => (BinaryOp::Div, 10),
            TokenKind::Percent => (BinaryOp::Mod, 10),
            _ => return None,
        };
        Some((op, prec))
    }

    fn compound_assign_op(&self) -> Option<BinaryOp> {
        match self.peek_n(1).map(|token| &token.kind) {
            Some(TokenKind::PlusEq) => Some(BinaryOp::Add),
            Some(TokenKind::MinusEq) => Some(BinaryOp::Sub),
            Some(TokenKind::StarEq) => Some(BinaryOp::Mul),
            Some(TokenKind::SlashEq) => Some(BinaryOp::Div),
            Some(TokenKind::PercentEq) => Some(BinaryOp::Mod),
            Some(TokenKind::LtLtEq) => Some(BinaryOp::Shl),
            Some(TokenKind::GtGtEq) => Some(BinaryOp::Shr),
            Some(TokenKind::AmpEq) => Some(BinaryOp::BitAnd),
            Some(TokenKind::CaretEq) => Some(BinaryOp::BitXor),
            Some(TokenKind::PipeEq) => Some(BinaryOp::BitOr),
            _ => None,
        }
    }

    fn at(&self, kind: &TokenKind) -> bool {
        self.peek().is_some_and(|tok| tok.kind == *kind)
    }

    fn peek_kind(&self) -> TokenKind {
        self.peek()
            .map(|token| token.kind.clone())
            .unwrap_or(TokenKind::Eof)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_n(&self, n: usize) -> Option<&Token> {
        self.tokens.get(self.pos + n)
    }

    fn advance(&mut self) -> Option<Token> {
        let tok = self.tokens.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn consume(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_ident(&mut self, message: &str) -> Option<String> {
        let token = self.advance()?;
        match token.kind {
            TokenKind::Ident(value) => Some(value),
            // `rpc` is a contextual keyword: declarations use keyword position, but
            // module names and paths may still legally use `rpc`.
            TokenKind::KwRpc => Some("rpc".to_string()),
            _ => {
                self.push_diag_at(token.line, token.col, message);
                None
            }
        }
    }

    fn expect_member_name(&mut self, message: &str) -> Option<String> {
        let token = self.advance()?;
        match token.kind {
            TokenKind::Ident(value) => Some(value),
            TokenKind::KwFn => Some("fn".to_string()),
            TokenKind::KwPub => Some("pub".to_string()),
            TokenKind::KwExtern => Some("extern".to_string()),
            TokenKind::KwAsync => Some("async".to_string()),
            TokenKind::KwAwait => Some("await".to_string()),
            TokenKind::KwRpc => Some("rpc".to_string()),
            TokenKind::KwUse => Some("use".to_string()),
            TokenKind::KwCore => Some("core".to_string()),
            TokenKind::KwMod => Some("mod".to_string()),
            TokenKind::KwStruct => Some("struct".to_string()),
            TokenKind::KwEnum => Some("enum".to_string()),
            TokenKind::KwTrait => Some("trait".to_string()),
            TokenKind::KwImpl => Some("impl".to_string()),
            TokenKind::KwFor => Some("for".to_string()),
            TokenKind::KwIn => Some("in".to_string()),
            TokenKind::KwLoop => Some("loop".to_string()),
            TokenKind::KwBreak => Some("break".to_string()),
            TokenKind::KwContinue => Some("continue".to_string()),
            TokenKind::KwTest => Some("test".to_string()),
            TokenKind::KwNondet => Some("nondet".to_string()),
            TokenKind::KwLet => Some("let".to_string()),
            TokenKind::KwRequires => Some("requires".to_string()),
            TokenKind::KwEnsures => Some("ensures".to_string()),
            TokenKind::KwReturn => Some("return".to_string()),
            TokenKind::KwDefer => Some("defer".to_string()),
            TokenKind::KwMatch => Some("match".to_string()),
            TokenKind::KwIf => Some("if".to_string()),
            TokenKind::KwElse => Some("else".to_string()),
            TokenKind::KwWhile => Some("while".to_string()),
            TokenKind::KwTry => Some("try".to_string()),
            TokenKind::KwCatch => Some("catch".to_string()),
            TokenKind::KwTrue => Some("true".to_string()),
            TokenKind::KwFalse => Some("false".to_string()),
            _ => {
                self.push_diag_at(token.line, token.col, message);
                None
            }
        }
    }

    fn push_diag_here(&mut self, message: &str) {
        let (line, col) = self
            .peek()
            .map(|t| (t.line, t.col))
            .unwrap_or((1usize, 1usize));
        self.push_diag_at(line, col, message);
    }

    fn push_diag_at(&mut self, line: usize, col: usize, message: &str) {
        self.diagnostics
            .push(Diagnostic::new(Severity::Error, message, None).with_span(
                line,
                col,
                line,
                col + 1,
            ));
    }

    fn consume_until(&mut self, kinds: &[TokenKind]) {
        while !self.at(&TokenKind::Eof) {
            if kinds.iter().any(|kind| self.at(kind)) {
                break;
            }
            self.pos += 1;
        }
    }

    fn recover_item(&mut self) {
        self.consume_until(&[
            TokenKind::KwUse,
            TokenKind::KwMod,
            TokenKind::KwFn,
            TokenKind::KwPub,
            TokenKind::KwExtern,
            TokenKind::KwAsync,
            TokenKind::KwRpc,
            TokenKind::KwStruct,
            TokenKind::KwEnum,
            TokenKind::KwTrait,
            TokenKind::KwImpl,
            TokenKind::KwTest,
            TokenKind::Hash,
            TokenKind::Semi,
            TokenKind::Eof,
        ]);
        if self.consume(&TokenKind::Semi) {
            return;
        }
        if !self.at(&TokenKind::Eof) && self.pos < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn recover_stmt(&mut self) {
        self.consume_until(&[
            TokenKind::Semi,
            TokenKind::RBrace,
            TokenKind::KwLet,
            TokenKind::KwIf,
            TokenKind::KwWhile,
            TokenKind::KwFor,
            TokenKind::KwLoop,
            TokenKind::KwBreak,
            TokenKind::KwContinue,
            TokenKind::KwReturn,
            TokenKind::KwMatch,
            TokenKind::Eof,
        ]);
        let _ = self.consume(&TokenKind::Semi);
    }
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    source: &'a str,
    line: usize,
    col: usize,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            chars: source.char_indices().peekable(),
            source,
            line: 1,
            col: 1,
            diagnostics: Vec::new(),
        }
    }

    fn lex(&mut self) -> Vec<Token> {
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
                    TokenKind::Str(self.lex_string_literal(line, col, idx))
                }
                c if c.is_ascii_digit() => self.lex_number_literal(idx),
                c if is_ident_start(c) => {
                    let start = idx;
                    let mut end = idx + 1;
                    self.advance_char();
                    while let Some((i, next)) = self.peek_char() {
                        if is_ident_continue(next) {
                            end = i + 1;
                            self.advance_char();
                        } else {
                            break;
                        }
                    }
                    keyword_or_ident(&self.source[start..end])
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
        if self.peek_char().is_some_and(|(_, c)| c == '.') {
            let mut iter = self.chars.clone();
            let _ = iter.next();
            if iter.next().is_some_and(|(_, c)| c.is_ascii_digit()) {
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
        }

        if self.peek_char().is_some_and(|(_, c)| c == 'e' || c == 'E') {
            let mut iter = self.chars.clone();
            let _ = iter.next();
            if iter
                .next()
                .is_some_and(|(_, c)| c.is_ascii_digit() || c == '+' || c == '-')
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
        }

        let mut bits = None;
        if self.peek_char().is_some_and(|(_, c)| c == 'f') {
            let mut iter = self.chars.clone();
            let _ = iter.next();
            let tail = [iter.next().map(|(_, c)| c), iter.next().map(|(_, c)| c)];
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
        let mut iter = self.chars.clone();
        let _ = iter.next();
        let (_, first) = iter.next()?;
        if first == '\\' {
            let (_, esc) = iter.next()?;
            let (_, end_quote) = iter.next()?;
            if end_quote != '\'' {
                return None;
            }
            let value = match esc {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '\'' => '\'',
                '0' => '\0',
                _ => {
                    self.diagnostics.push(Diagnostic::new(
                        Severity::Error,
                        format!("unsupported char escape `\\{esc}`"),
                        Some("supported escapes: \\\\, \\\', \\n, \\r, \\t, \\0".to_string()),
                    ));
                    esc
                }
            };
            return Some((value, 4));
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

    fn peek_next(&self, expected: char) -> bool {
        let mut iter = self.chars.clone();
        let _ = iter.next();
        iter.next().is_some_and(|(_, c)| c == expected)
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
                    let Some((_, escape)) = self.peek_char() else {
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
                    };
                    self.advance_char();
                    match escape {
                        '"' => value.push('"'),
                        '\\' => value.push('\\'),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        't' => value.push('\t'),
                        '0' => value.push('\0'),
                        _ => {
                            self.diagnostics.push(
                                Diagnostic::new(
                                    Severity::Error,
                                    format!("unsupported string escape `\\{escape}`"),
                                    Some(
                                        "supported escapes: \\\\, \\\", \\n, \\r, \\t, \\0"
                                            .to_string(),
                                    ),
                                )
                                .with_span(
                                    self.line,
                                    self.col.saturating_sub(1),
                                    self.line,
                                    self.col,
                                ),
                            );
                            value.push(escape);
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
        "extern" => TokenKind::KwExtern,
        "async" => TokenKind::KwAsync,
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
        "else" => TokenKind::KwElse,
        "while" => TokenKind::KwWhile,
        "try" => TokenKind::KwTry,
        "catch" => TokenKind::KwCatch,
        "true" => TokenKind::KwTrue,
        "false" => TokenKind::KwFalse,
        _ => TokenKind::Ident(ident.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_if_while_and_calls() {
        let source = r#"
            use core.net;
            fn add(x: i32, y: i32) -> i32 { return x + y; }
            fn main() -> i32 {
                let v: i32 = add(1, 2);
                let i: i32 = 0;
                while i < 3 {
                    if v == 3 { return v; } else { return 9; }
                }
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        assert_eq!(module.capabilities, vec!["net".to_string()]);
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Function(f) if f.name == "main")));
    }

    #[test]
    fn reports_multiple_errors() {
        let source = r#"
            fn main( -> i32 {
                let = 3
                if { return 1; }
            }
        "#;
        let diagnostics = parse(source, "bad").expect_err("should fail");
        assert!(diagnostics.len() >= 2);
    }

    #[test]
    fn parses_traits_impls_and_struct_enum_exprs() {
        let source = r#"
            trait Printable {
                fn render(v: i32) -> i32;
            }
            struct Point { x: i32, y: i32 }
            enum Maybe { Some(i32), None }
            impl Printable for Point {
                fn render(v: i32) -> i32 { return v; }
            }
            fn id<T: Printable>(v: T) -> T { return v; }
            fn main() -> i32 {
                let p = Point { x: 7, y: 3 };
                let px = p.x;
                let m = Maybe::Some(px);
                let _ = id<Point>(p);
                match m {
                    Maybe::Some(v) => v,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Trait(_))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Impl(_))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Struct(_))));
        assert!(module
            .items
            .iter()
            .any(|item| matches!(item, ast::Item::Enum(_))));
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::StructInit { .. },
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::FieldAccess { .. },
                ..
            }
        )));
    }

    #[test]
    fn rejects_unqualified_enum_variant_patterns() {
        let source = r#"
            enum Maybe { Some(i32), None }
            fn main() -> i32 {
                let m = Maybe::Some(1);
                match m {
                    Some(v) => v,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics.iter().any(|diag| {
            diag.message
                .contains("unqualified enum variant pattern is not supported")
        }));
    }

    #[test]
    fn rejects_capitalized_bare_patterns() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    Value => Value,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics.iter().any(|diag| {
            diag.message
                .contains("capitalized bare pattern is not supported")
        }));
    }

    #[test]
    fn allows_return_in_match_arm_expression() {
        let source = r#"
            fn main() -> i32 {
                match 1 {
                    1 => return 1,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main should exist");
        let arm_returns = main_fn
            .body
            .iter()
            .find_map(|stmt| match stmt {
                ast::Stmt::Match { arms, .. } => {
                    Some(arms.iter().map(|arm| arm.returns).collect::<Vec<_>>())
                }
                _ => None,
            })
            .expect("match should exist");
        assert_eq!(arm_returns, vec![true, false]);
    }

    #[test]
    fn parses_reference_lifetime_annotations() {
        let source = r#"
            fn borrow(value: &'req str) -> &'req str {
                return value;
            }
        "#;
        let module = parse(source, "lifetimes").expect("parse should succeed");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "borrow" => Some(function),
                _ => None,
            })
            .expect("borrow function should exist");
        assert!(matches!(
            function.params[0].ty,
            ast::Type::Ref {
                lifetime: Some(_),
                ..
            }
        ));
        assert!(matches!(
            function.return_type,
            ast::Type::Ref {
                lifetime: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn rpc_can_be_used_as_module_name_and_call_path() {
        let source = r#"
            mod rpc;

            fn main() -> i32 {
                rpc.touch();
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        assert!(module.modules.iter().any(|decl| decl == "rpc"));
    }

    #[test]
    fn escaped_json_string_round_trips_and_remains_lexically_inert() {
        let source = r#"
            fn main() -> i32 {
                let body: str = "{\"model\":\"claude-sonnet-4-6\",\"msg\":\"x:y\"}";
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function");
        let ast::Stmt::Let { value, .. } = &main_fn.body[0] else {
            panic!("expected first statement to be let");
        };
        let ast::Expr::Str(value) = value else {
            panic!("expected string literal");
        };
        assert_eq!(value, "{\"model\":\"claude-sonnet-4-6\",\"msg\":\"x:y\"}");
    }

    #[test]
    fn reports_unterminated_string_literal_with_span() {
        let source = "fn main() -> i32 { let body: str = \"abc; return 0; }";
        let diagnostics = parse(source, "main").expect_err("should fail");
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("unterminated string literal") && d.span.is_some()));
    }

    #[test]
    fn parses_async_function_and_await_expression() {
        let source = r#"
            async fn worker() -> i32 { return 7; }
            async fn main() -> i32 {
                let v = await worker();
                return v;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.is_async);
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Await(_),
                ..
            }
        )));
    }

    #[test]
    fn parses_ffi_panic_attribute_on_function() {
        let source = r#"
            #[ffi_panic(abort)]
            pub extern "C" fn add(left: i32, right: i32) -> i32;
        "#;
        let module = parse(source, "ffi").expect("parse should succeed");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "add" => Some(function),
                _ => None,
            })
            .expect("ffi function should exist");
        assert_eq!(function.ffi_panic.as_deref(), Some("abort"));
    }

    #[test]
    fn rejects_invalid_ffi_panic_mode() {
        let source = r#"
            #[ffi_panic(ignore)]
            pub extern "C" fn add(left: i32, right: i32) -> i32;
        "#;
        let diagnostics = parse(source, "ffi").expect_err("invalid mode should fail");
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("ffi_panic mode must be")));
    }

    #[test]
    fn parses_pointer_sized_types_and_wide_integer_literals() {
        let source = r#"
            fn main() -> usize {
                let small: isize = 7;
                let wide: i128 = 170141183460469231731687303715884105727;
                let ptr: usize = 42;
                let _ = small;
                let _ = wide;
                return ptr;
            }
        "#;
        let module = parse(source, "wide").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(matches!(main_fn.return_type, ast::Type::USize));
        assert!(matches!(main_fn.params.len(), 0));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                ty: Some(ast::Type::ISize),
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                ty: Some(ast::Type::Int {
                    signed: true,
                    bits: 128
                }),
                ..
            }
        )));
    }

    #[test]
    fn unknown_token_is_hard_error() {
        let source = r#"
            fn main() -> i32 {
                let x = 1 @ 2;
                return x;
            }
        "#;
        let diagnostics = parse(source, "main").expect_err("parse should fail");
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("unknown token `@`")));
    }

    #[test]
    fn parses_percent_operator_expression() {
        let source = r#"
            fn main() -> i32 {
                let x = 7 % 3;
                return x;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Binary {
                    op: ast::BinaryOp::Mod,
                    ..
                },
                ..
            }
        )));
    }

    #[test]
    fn parses_loop_for_for_in_and_control_flow() {
        let source = r#"
            fn main() -> i32 {
                let total: i32 = 0;
                for let i: i32 = 0; i < 10; i = i + 1 {
                    if i == 3 { continue; }
                    if i == 8 { break; }
                }
                for n in 0..=3 {
                    let _ = n;
                }
                loop { break; }
                return total;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::For { .. })));
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::ForIn { .. })));
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::Loop { .. })));
    }

    #[test]
    fn parses_operator_completeness_and_unit_return() {
        let source = r#"
            fn main() -> void {
                let flags: i32 = 7;
                let ok: bool = !false && true || false;
                let mix: i32 = (~flags) ^ (flags << 1) | (flags >> 1);
                let value: i32 = +flags + (-1);
                flags += 1;
                flags &= 3;
                flags |= 2;
                flags ^= 1;
                flags <<= 1;
                flags >>= 1;
                flags %= 3;
                let _ = ok;
                let _ = mix;
                let _ = value;
                return;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::CompoundAssign {
                op: ast::BinaryOp::BitAnd,
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Binary {
                    op: ast::BinaryOp::Or,
                    ..
                },
                ..
            }
        )));
        assert!(main_fn
            .body
            .iter()
            .any(|stmt| matches!(stmt, ast::Stmt::Return(None))));
    }

    #[test]
    fn match_pattern_or_remains_supported() {
        let source = r#"
            fn main() -> i32 {
                match 2 {
                    1 | 2 => 7,
                    _ => 0,
                };
                return 0;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Match {
                arms,
                ..
            } if matches!(arms.first().map(|arm| &arm.pattern), Some(ast::Pattern::Or(_)))
        )));
    }

    #[test]
    fn parses_float_char_array_and_index_literals() {
        let source = r#"
            fn main() -> i32 {
                let pi: f64 = 3.14159;
                let ratio: f32 = 1.5f32;
                let ch: char = '\n';
                let arr = [1, 2, 3];
                let v = arr[1];
                let _ = pi;
                let _ = ratio;
                let _ = ch;
                return v;
            }
        "#;
        let module = parse(source, "main").expect("parse should succeed");
        let main_fn = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Float { .. },
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Char(_),
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::ArrayLiteral(_),
                ..
            }
        )));
        assert!(main_fn.body.iter().any(|stmt| matches!(
            stmt,
            ast::Stmt::Let {
                value: ast::Expr::Index { .. },
                ..
            }
        )));
    }

    #[test]
    fn test_block_body_is_preserved() {
        let source = r#"
            test "smoke" {
                let values = [1, 2];
                let _ = values[0];
            }
        "#;
        let module = parse(source, "tests").expect("parse should succeed");
        let test = module
            .items
            .iter()
            .find_map(|item| match item {
                ast::Item::Test(test) => Some(test),
                _ => None,
            })
            .expect("test block should exist");
        assert!(!test.body.is_empty());
    }
}
