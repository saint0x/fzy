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
    let mut diagnostics = lexer.diagnostics;
    let identifiers = lexer.identifiers;
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

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    diagnostics: Vec<Diagnostic>,
    module: Module,
    pending_repr: Option<String>,
    pending_ffi_panic: Option<String>,
}
