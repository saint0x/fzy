//! Environment and version metadata for `fozzy env` / `fozzy version`.

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvInfo {
    pub os: String,
    pub arch: String,
    pub fozzy: VersionInfo,
    pub capabilities: BTreeMap<String, CapabilityInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityInfo {
    pub backend: String,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_date: Option<String>,
}

pub fn version_info() -> VersionInfo {
    static VERSION_INFO: OnceLock<VersionInfo> = OnceLock::new();
    VERSION_INFO
        .get_or_init(|| VersionInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: resolved_commit_hash(),
            build_date: option_env!("FOZZY_BUILD_DATE").map(|s| s.to_string()),
        })
        .clone()
}

fn resolved_commit_hash() -> Option<String> {
    if let Some(commit) = option_env!("FOZZY_COMMIT")
        && !commit.trim().is_empty()
    {
        return Some(commit.to_string());
    }
    let out = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let commit = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if commit.is_empty() {
        None
    } else {
        Some(commit)
    }
}

pub fn env_info(config: &crate::Config) -> EnvInfo {
    let mut capabilities = BTreeMap::new();
    capabilities.insert(
        "time".to_string(),
        CapabilityInfo {
            backend: "virtual".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "rng".to_string(),
        CapabilityInfo {
            backend: "chacha20".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "fs".to_string(),
        CapabilityInfo {
            backend: match config.fs_backend {
                crate::FsBackend::Virtual => "virtual_overlay".to_string(),
                crate::FsBackend::Host => "host".to_string(),
            },
            deterministic: matches!(config.fs_backend, crate::FsBackend::Virtual),
        },
    );
    capabilities.insert(
        "http".to_string(),
        CapabilityInfo {
            backend: match config.http_backend {
                crate::HttpBackend::Scripted => "scripted".to_string(),
                crate::HttpBackend::Host => "host".to_string(),
            },
            deterministic: matches!(config.http_backend, crate::HttpBackend::Scripted),
        },
    );
    capabilities.insert(
        "net".to_string(),
        CapabilityInfo {
            backend: "simulated".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "proc".to_string(),
        CapabilityInfo {
            backend: match config.proc_backend {
                crate::ProcBackend::Scripted => "scripted".to_string(),
                crate::ProcBackend::Host => "host".to_string(),
            },
            deterministic: matches!(config.proc_backend, crate::ProcBackend::Scripted),
        },
    );
    capabilities.insert(
        "memory".to_string(),
        CapabilityInfo {
            backend: "deterministic_allocator".to_string(),
            deterministic: true,
        },
    );

    EnvInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        fozzy: version_info(),
        capabilities,
    }
}
