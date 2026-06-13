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

