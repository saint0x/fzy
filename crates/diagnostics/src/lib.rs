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
pub struct Label {
    pub message: String,
    pub primary: bool,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub help: Option<String>,
    pub span: Option<Span>,
    pub fix: Option<String>,
    pub path: Option<String>,
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub suggested_fixes: Vec<String>,
}

impl Diagnostic {
    pub fn new(severity: Severity, message: impl Into<String>, help: Option<String>) -> Self {
        Self {
            severity,
            message: message.into(),
            help,
            span: None,
            fix: None,
            path: None,
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
}
