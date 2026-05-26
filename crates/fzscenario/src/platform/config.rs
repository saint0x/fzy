//! `fozzy.toml` config loading.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// Base directory for fozzy runtime artifacts.
    #[serde(default = "default_base_dir")]
    pub base_dir: PathBuf,

    /// Default reporter for CLI commands.
    #[serde(default = "default_reporter")]
    pub reporter: crate::Reporter,

    /// Process backend for proc_spawn steps.
    #[serde(default = "default_proc_backend")]
    pub proc_backend: crate::ProcBackend,

    /// Filesystem backend for fs_* steps.
    #[serde(default = "default_fs_backend")]
    pub fs_backend: crate::FsBackend,

    /// HTTP backend for http_request/http_when steps.
    #[serde(default = "default_http_backend")]
    pub http_backend: crate::HttpBackend,

    /// Enable deterministic memory capability tracking by default.
    #[serde(default = "default_mem_track")]
    pub mem_track: bool,

    /// Optional deterministic memory ceiling (MB).
    #[serde(default)]
    pub mem_limit_mb: Option<u64>,

    /// Optional deterministic allocation failure after N allocs.
    #[serde(default)]
    pub mem_fail_after: Option<u64>,

    /// Fail run when leaks are detected.
    #[serde(default)]
    pub fail_on_leak: bool,

    /// Leak budget in bytes; exceed => finding/fail.
    #[serde(default)]
    pub leak_budget: Option<u64>,

    /// Deterministic fragmentation overhead seed.
    #[serde(default)]
    pub mem_fragmentation_seed: Option<u64>,

    /// Deterministic pressure wave pattern, e.g. "1,2,4".
    #[serde(default)]
    pub mem_pressure_wave: Option<String>,

    /// Emit dedicated memory artifacts.
    #[serde(default = "default_mem_artifacts")]
    pub mem_artifacts: bool,

    /// Optional heap total-allocation budget in bytes (profile-derived).
    #[serde(default)]
    pub profile_heap_alloc_budget: Option<u64>,

    /// Optional heap in-use budget in bytes (profile-derived).
    #[serde(default)]
    pub profile_heap_in_use_budget: Option<u64>,
}

fn default_base_dir() -> PathBuf {
    PathBuf::from(".fozzy")
}

fn default_reporter() -> crate::Reporter {
    crate::Reporter::Pretty
}

fn default_proc_backend() -> crate::ProcBackend {
    crate::ProcBackend::Scripted
}

fn default_fs_backend() -> crate::FsBackend {
    crate::FsBackend::Virtual
}

fn default_http_backend() -> crate::HttpBackend {
    crate::HttpBackend::Scripted
}

fn default_mem_track() -> bool {
    true
}

fn default_mem_artifacts() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_dir: default_base_dir(),
            reporter: default_reporter(),
            proc_backend: default_proc_backend(),
            fs_backend: default_fs_backend(),
            http_backend: default_http_backend(),
            mem_track: default_mem_track(),
            mem_limit_mb: None,
            mem_fail_after: None,
            fail_on_leak: false,
            leak_budget: None,
            mem_fragmentation_seed: None,
            mem_pressure_wave: None,
            mem_artifacts: default_mem_artifacts(),
            profile_heap_alloc_budget: None,
            profile_heap_in_use_budget: None,
        }
    }
}

impl Config {
    pub fn load_optional_checked(path: &Path) -> crate::FozzyResult<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => match toml::from_str::<Config>(&s) {
                Ok(cfg) => Ok(cfg),
                Err(err) => Err(crate::FozzyError::Config(format!(
                    "failed to parse config {}: {err}",
                    path.display()
                ))),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(crate::FozzyError::Config(format!(
                "failed to read config {}: {err}",
                path.display()
            ))),
        }
    }

    pub fn runs_dir(&self) -> PathBuf {
        self.base_dir.join("runs")
    }

    pub fn corpora_dir(&self) -> PathBuf {
        self.base_dir.join("corpora")
    }
}
