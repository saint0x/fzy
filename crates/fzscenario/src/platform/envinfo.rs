//! Environment and version metadata for `fz env` / `fz version`.

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvInfo {
    pub os: String,
    pub arch: String,
    pub fz: VersionInfo,
    pub capabilities: BTreeMap<String, CapabilityInfo>,
    pub install: InstallInfo,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallInfo {
    pub executable: String,
    pub bin_dir: String,
    pub dir_on_path: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_profile: Option<String>,
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
        fz: version_info(),
        capabilities,
        install: install_info(),
    }
}

fn install_info() -> InstallInfo {
    let executable = std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "fz".to_string());
    let bin_dir = std::path::Path::new(&executable)
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| ".".to_string());
    InstallInfo {
        dir_on_path: dir_on_path(&bin_dir),
        shell_profile: default_shell_profile(),
        executable,
        bin_dir,
    }
}

fn dir_on_path(dir: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|value| {
        std::env::split_paths(&value).any(|entry| entry == std::path::Path::new(dir))
    })
}

fn default_shell_profile() -> Option<String> {
    if let Some(shell) = std::env::var_os("SHELL") {
        let shell = shell.to_string_lossy();
        if shell.ends_with("/zsh") {
            return Some(
                std::env::var("ZDOTDIR")
                    .map(|dir| format!("{dir}/.zshrc"))
                    .unwrap_or_else(|_| "~/.zshrc".to_string()),
            );
        }
        if shell.ends_with("/bash") {
            return Some("~/.bashrc".to_string());
        }
    }
    Some("~/.profile".to_string())
}
