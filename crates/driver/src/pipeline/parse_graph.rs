use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone)]
pub(super) struct ModuleSourceText {
    pub(super) path: PathBuf,
    pub(super) source: Arc<str>,
}

#[derive(Debug)]
pub struct ParsedProgram {
    pub module: ast::Module,
    pub module_paths: Vec<PathBuf>,
    pub(super) cache_paths: Arc<Vec<PathBuf>>,
    pub module_fingerprint: String,
    pub input_bytes: usize,
    pub(super) module_sources: Arc<Vec<ModuleSourceText>>,
    pub(super) combined_source: OnceLock<String>,
}

impl Clone for ParsedProgram {
    fn clone(&self) -> Self {
        let cloned = Self {
            module: self.module.clone(),
            module_paths: self.module_paths.clone(),
            cache_paths: Arc::clone(&self.cache_paths),
            module_fingerprint: self.module_fingerprint.clone(),
            input_bytes: self.input_bytes,
            module_sources: Arc::clone(&self.module_sources),
            combined_source: OnceLock::new(),
        };
        if let Some(existing) = self.combined_source.get() {
            let _ = cloned.combined_source.set(existing.clone());
        }
        cloned
    }
}

impl ParsedProgram {
    pub fn combined_source(&self) -> &str {
        self.combined_source.get_or_init(|| {
            let mut combined = String::with_capacity(self.input_bytes);
            for module in self.module_sources.iter() {
                combined.push_str("// module: ");
                combined.push_str(&module.path.display().to_string());
                combined.push('\n');
                combined.push_str(&module.source);
                if !module.source.ends_with('\n') {
                    combined.push('\n');
                }
            }
            combined
        })
    }

    pub fn module_sources(&self) -> impl Iterator<Item = (&std::path::Path, &str)> {
        self.module_sources
            .iter()
            .map(|module| (module.path.as_path(), module.source.as_ref()))
    }
}
