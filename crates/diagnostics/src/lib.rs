use serde::{Deserialize, Serialize};

pub const DIAGNOSTICS_SCHEMA_VERSION: &str = "fozzylang.diagnostics.v2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub message: String,
    pub primary: bool,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    #[serde(default)]
    pub code: Option<String>,
    pub message: String,
    pub help: Option<String>,
    pub span: Option<Span>,
    pub fix: Option<String>,
    pub path: Option<String>,
    pub snippet: Option<String>,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub suggested_fixes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum DiagnosticDomain {
    Parser,
    Hir,
    Verifier,
    NativeLowering,
    Driver,
}

impl Diagnostic {
    pub fn new(severity: Severity, message: impl Into<String>, help: Option<String>) -> Self {
        Self {
            severity,
            code: None,
            message: message.into(),
            help,
            span: None,
            fix: None,
            path: None,
            snippet: None,
            labels: Vec::new(),
            notes: Vec::new(),
            suggested_fixes: Vec::new(),
        }
    }

    pub fn with_span(
        mut self,
        start_line: usize,
        start_col: usize,
        end_line: usize,
        end_col: usize,
    ) -> Self {
        self.span = Some(Span {
            start_line,
            start_col,
            end_line,
            end_col,
        });
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        let fix = fix.into();
        self.fix = Some(fix.clone());
        self.suggested_fixes.push(fix);
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_label(
        mut self,
        message: impl Into<String>,
        primary: bool,
        span: Option<Span>,
    ) -> Self {
        self.labels.push(Label {
            message: message.into(),
            primary,
            span,
        });
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn with_suggested_fix(mut self, fix: impl Into<String>) -> Self {
        self.suggested_fixes.push(fix.into());
        self
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }
}

pub fn assign_stable_codes(diagnostics: &mut [Diagnostic], domain: DiagnosticDomain) {
    for diagnostic in diagnostics {
        if diagnostic.code.is_some() {
            continue;
        }
        let code = stable_code_for_diagnostic(domain, diagnostic);
        diagnostic.code = Some(code);
    }
}

fn stable_code_for_diagnostic(domain: DiagnosticDomain, diagnostic: &Diagnostic) -> String {
    let severity = severity_code_prefix(&diagnostic.severity);
    let domain = domain_code_prefix(domain);
    let mut material = String::new();
    material.push_str(domain);
    material.push('|');
    material.push_str(&diagnostic.message);
    material.push('|');
    if let Some(help) = &diagnostic.help {
        material.push_str(help);
    }
    material.push('|');
    if let Some(span) = &diagnostic.span {
        material.push_str(&format!(
            "{}:{}:{}:{}",
            span.start_line, span.start_col, span.end_line, span.end_col
        ));
    }
    let digest = fnv1a_32(material.as_bytes());
    format!("{severity}-{domain}-{digest:08X}")
}

fn severity_code_prefix(severity: &Severity) -> &'static str {
    match severity {
        Severity::Error => "E",
        Severity::Warning => "W",
        Severity::Note => "N",
    }
}

fn domain_code_prefix(domain: DiagnosticDomain) -> &'static str {
    match domain {
        DiagnosticDomain::Parser => "PAR",
        DiagnosticDomain::Hir => "HIR",
        DiagnosticDomain::Verifier => "VER",
        DiagnosticDomain::NativeLowering => "NAT",
        DiagnosticDomain::Driver => "DRV",
    }
}

fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    for byte in bytes {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}
