use capabilities::{Capability, CapabilityToken};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

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
    Sighup,
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

#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    pub max_open_files: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub max_cpu_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub timeout_ms: u64,
    pub stdin: Option<Vec<u8>>,
    pub set_process_group: bool,
    pub limits: ResourceLimits,
    pub drop_uid: Option<u32>,
    pub drop_gid: Option<u32>,
}

impl Default for ProcessSpec {
    fn default() -> Self {
        Self {
            program: String::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            timeout_ms: 5_000,
            stdin: None,
            set_process_group: false,
            limits: ResourceLimits::default(),
            drop_uid: None,
            drop_gid: None,
        }
    }
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

    let mut command = Command::new(&spec.program);
    command.args(&spec.args);
    if !spec.env.is_empty() {
        command.envs(&spec.env);
    }
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if spec.stdin.is_some() {
        command.stdin(Stdio::piped());
    }

    let set_process_group = spec.set_process_group;
    let limits = spec.limits.clone();
    let drop_uid = spec.drop_uid;
    let drop_gid = spec.drop_gid;
    // Safety: pre_exec only performs async-signal-safe libc calls to configure child process.
    unsafe {
        command.pre_exec(move || {
            if set_process_group && libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(max) = limits.max_open_files {
                let lim = libc::rlimit {
                    rlim_cur: max,
                    rlim_max: max,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(max) = limits.max_memory_bytes {
                let lim = libc::rlimit {
                    rlim_cur: max,
                    rlim_max: max,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(max) = limits.max_cpu_seconds {
                let lim = libc::rlimit {
                    rlim_cur: max,
                    rlim_max: max,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(gid) = drop_gid {
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(uid) = drop_uid {
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return ProcessResult {
                class: ExitClass::SpawnError,
                stdout: String::new(),
                stderr: err.to_string(),
            }
        }
    };

    if let Some(stdin_data) = &spec.stdin {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(stdin_data);
        }
    }

    match child.wait_timeout(Duration::from_millis(spec.timeout_ms)) {
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
            ProcessResult {
                class,
                stdout,
                stderr,
            }
        }
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            ProcessResult {
                class: ExitClass::Timeout,
                stdout: String::new(),
                stderr: "timed out".to_string(),
            }
        }
        Err(err) => ProcessResult {
            class: ExitClass::SpawnError,
            stdout: String::new(),
            stderr: err.to_string(),
        },
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
            ..ProcessSpec::default()
        };
        let result = run_child_process(&spec, false);
        assert_eq!(result.class, ExitClass::NonZero(7));
    }

    #[test]
    fn process_runner_supports_stdin_piping() {
        let spec = ProcessSpec {
            program: "cat".to_string(),
            stdin: Some(b"hello".to_vec()),
            timeout_ms: 500,
            ..ProcessSpec::default()
        };
        let result = run_child_process(&spec, false);
        assert_eq!(result.class, ExitClass::Success);
        assert_eq!(result.stdout, "hello");
    }
}
