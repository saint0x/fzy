use capabilities::{Capability, CapabilityToken};
use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::capability::{require_capability, CapabilityError};

pub fn required_capability_for_process() -> Capability {
    Capability::Process
}

pub fn run_child_with_capability(
    spec: &ProcessSpec,
    cancelled: bool,
    token: &CapabilityToken,
) -> Result<ProcessResult, CapabilityError> {
    require_capability(token, required_capability_for_process())?;
    Ok(run_child_process(spec, cancelled))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Sigterm,
    Sigint,
}

#[derive(Default)]
pub struct SignalHooks {
    hooks: Vec<Box<dyn Fn(Signal) + Send + Sync + 'static>>,
}

impl SignalHooks {
    pub fn register<F>(&mut self, hook: F)
    where
        F: Fn(Signal) + Send + Sync + 'static,
    {
        self.hooks.push(Box::new(hook));
    }

    pub fn emit(&self, signal: Signal) {
        for hook in &self.hooks {
            hook(signal);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(String),
    Invalid { key: String, message: String },
}

#[derive(Debug, Clone, Default)]
pub struct EnvConfig {
    values: BTreeMap<String, String>,
}

impl EnvConfig {
    pub fn from_current_env() -> Self {
        Self {
            values: std::env::vars().collect(),
        }
    }

    pub fn with_values(values: BTreeMap<String, String>) -> Self {
        Self { values }
    }

    pub fn get_required(&self, key: &str) -> Result<String, ConfigError> {
        self.values
            .get(key)
            .cloned()
            .ok_or_else(|| ConfigError::Missing(key.to_string()))
    }

    pub fn parse_u16(&self, key: &str) -> Result<u16, ConfigError> {
        let raw = self.get_required(key)?;
        raw.parse::<u16>().map_err(|_| ConfigError::Invalid {
            key: key.to_string(),
            message: "expected u16".to_string(),
        })
    }

    pub fn parse_usize(&self, key: &str) -> Result<usize, ConfigError> {
        let raw = self.get_required(key)?;
        raw.parse::<usize>().map_err(|_| ConfigError::Invalid {
            key: key.to_string(),
            message: "expected usize".to_string(),
        })
    }

    pub fn parse_bool(&self, key: &str) -> Result<bool, ConfigError> {
        let raw = self.get_required(key)?;
        match raw.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ConfigError::Invalid {
                key: key.to_string(),
                message: "expected bool".to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub program: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitClass {
    Success,
    NonZero(i32),
    Timeout,
    Cancelled,
    SpawnError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    pub class: ExitClass,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_child_process(spec: &ProcessSpec, cancelled: bool) -> ProcessResult {
    if cancelled {
        return ProcessResult {
            class: ExitClass::Cancelled,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    let mut child = match Command::new(&spec.program)
        .args(&spec.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return ProcessResult {
                class: ExitClass::SpawnError,
                stdout: String::new(),
                stderr: err.to_string(),
            }
        }
    };

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut stderr);
                }
                let class = match status.code() {
                    Some(0) => ExitClass::Success,
                    Some(code) => ExitClass::NonZero(code),
                    None => ExitClass::NonZero(-1),
                };
                return ProcessResult {
                    class,
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                if started.elapsed() >= Duration::from_millis(spec.timeout_ms) {
                    let _ = child.kill();
                    return ProcessResult {
                        class: ExitClass::Timeout,
                        stdout: String::new(),
                        stderr: "timed out".to_string(),
                    };
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => {
                return ProcessResult {
                    class: ExitClass::SpawnError,
                    stdout: String::new(),
                    stderr: err.to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{run_child_process, EnvConfig, ExitClass, ProcessSpec};

    #[test]
    fn env_config_parses_typed_values() {
        let mut map = BTreeMap::new();
        map.insert("PORT".to_string(), "8080".to_string());
        map.insert("WORKERS".to_string(), "16".to_string());
        map.insert("TLS".to_string(), "true".to_string());
        let env = EnvConfig::with_values(map);

        assert_eq!(env.parse_u16("PORT").expect("port parse"), 8080);
        assert_eq!(env.parse_usize("WORKERS").expect("workers parse"), 16);
        assert!(env.parse_bool("TLS").expect("bool parse"));
    }

    #[test]
    fn process_runner_classifies_exit_code() {
        let spec = ProcessSpec {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), "exit 7".to_string()],
            timeout_ms: 500,
        };
        let result = run_child_process(&spec, false);
        assert_eq!(result.class, ExitClass::NonZero(7));
    }

    #[test]
    fn process_runner_respects_cancellation() {
        let spec = ProcessSpec {
            program: "echo".to_string(),
            args: vec!["hello".to_string()],
            timeout_ms: 500,
        };
        let result = run_child_process(&spec, true);
        assert_eq!(result.class, ExitClass::Cancelled);
    }
}
