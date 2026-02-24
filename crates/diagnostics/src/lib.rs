use serde::{Deserialize, Serialize};

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
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub help: Option<String>,
    pub span: Option<Span>,
    pub fix: Option<String>,
}

impl Diagnostic {
    pub fn new(severity: Severity, message: impl Into<String>, help: Option<String>) -> Self {
        Self {
            severity,
            message: message.into(),
            help,
            span: None,
            fix: None,
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
        self.fix = Some(fix.into());
        self
    }
}
