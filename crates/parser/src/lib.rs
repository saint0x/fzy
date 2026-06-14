use ast::{BinaryOp, Expr, MatchArm, Module, Pattern, Stmt, Type, UnaryOp};
use diagnostics::{assign_stable_codes, Diagnostic, DiagnosticDomain, Severity};

#[path = "parser/lex.rs"]
mod lex;
#[path = "parser/parse.rs"]
mod parse_impl;
#[cfg(test)]
#[path = "parser/tests.rs"]
mod tests;

use self::lex::Lexer;

#[derive(Debug, Clone)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) line: usize,
    pub(crate) col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TokenKind {
    Ident(Box<str>),
    Int(i128),
    Float { value: f64, bits: Option<u16> },
    Char(char),
    Str(Box<str>),
    KwFn,
    KwPub,
    KwPubext,
    KwConst,
    KwStatic,
    KwType,
    KwNewtype,
    KwExt,
    KwUnsafe,
    KwAsync,
    KwHost,
    KwPure,
    KwDevice,
    KwKernel,
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
    KwThen,
    KwElse,
    KwWhile,
    KwTry,
    KwCatch,
    KwDiscard,
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
    analyze_module(source, module_name).into_parse_result()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierLexeme {
    pub name: String,
    pub line: usize,
    pub col: usize,
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct ModuleAnalysis {
    pub module: Option<Module>,
    pub diagnostics: Vec<Diagnostic>,
    pub identifiers: Vec<IdentifierLexeme>,
}

impl ModuleAnalysis {
    pub fn into_parse_result(mut self) -> Result<Module, Vec<Diagnostic>> {
        if self.diagnostics.is_empty() {
            if let Some(module) = self.module.take() {
                Ok(module)
            } else {
                Err(vec![Diagnostic::new(
                    Severity::Error,
                    "source is empty",
                    Some("provide at least one declaration".to_string()),
                )])
            }
        } else {
            Err(self.diagnostics)
        }
    }
}

pub fn analyze_module(source: &str, module_name: &str) -> ModuleAnalysis {
    if source.trim().is_empty() {
        return ModuleAnalysis {
            module: None,
            diagnostics: vec![Diagnostic::new(
                Severity::Error,
                "source is empty",
                Some("provide at least one declaration".to_string()),
            )],
            identifiers: Vec::new(),
        };
    }

    let mut lexer = Lexer::new(source);
    let tokens = lexer.lex();
    let mut diagnostics = std::mem::take(&mut lexer.diagnostics);
    let identifiers = std::mem::take(&mut lexer.identifiers);
    let mut parser = Parser::new(tokens, module_name);
    let module = parser.parse_module();
    diagnostics.extend(parser.diagnostics);
    if !diagnostics.is_empty() {
        assign_stable_codes(&mut diagnostics, DiagnosticDomain::Parser);
    }
    ModuleAnalysis {
        module: Some(module),
        diagnostics,
        identifiers,
    }
}

pub(crate) struct Parser {
    pub(crate) tokens: Vec<Token>,
    pub(crate) pos: usize,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) module: Module,
    pub(crate) pending_repr: Option<String>,
    pub(crate) pending_ffi_panic: Option<String>,
}
