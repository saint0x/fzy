use capabilities::Capability;
use std::collections::BTreeMap;
use std::path::Path;

pub fn required_capability_for_file_io() -> Capability {
    Capability::FileSystem
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    Host,
    Deterministic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    NotFound(String),
    Backend(String),
}

pub trait IoBackend {
    fn read_to_string(&self, path: &str) -> Result<String, IoError>;
    fn write_string(&mut self, path: &str, value: &str) -> Result<(), IoError>;
}

#[derive(Default)]
pub struct HostIo;

impl IoBackend for HostIo {
    fn read_to_string(&self, path: &str) -> Result<String, IoError> {
        std::fs::read_to_string(path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                IoError::NotFound(path.to_string())
            } else {
                IoError::Backend(err.to_string())
            }
        })
    }

    fn write_string(&mut self, path: &str, value: &str) -> Result<(), IoError> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|err| IoError::Backend(err.to_string()))?;
        }
        std::fs::write(path, value).map_err(|err| IoError::Backend(err.to_string()))
    }
}

#[derive(Default)]
pub struct DeterministicIo {
    files: BTreeMap<String, String>,
}

impl DeterministicIo {
    pub fn with_seeded_files(files: BTreeMap<String, String>) -> Self {
        Self { files }
    }
}

impl IoBackend for DeterministicIo {
    fn read_to_string(&self, path: &str) -> Result<String, IoError> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| IoError::NotFound(path.to_string()))
    }

    fn write_string(&mut self, path: &str, value: &str) -> Result<(), IoError> {
        self.files.insert(path.to_string(), value.to_string());
        Ok(())
    }
}

pub enum IoRuntime {
    Host(HostIo),
    Deterministic(DeterministicIo),
}

impl IoRuntime {
    pub fn new(mode: IoMode) -> Self {
        match mode {
            IoMode::Host => Self::Host(HostIo),
            IoMode::Deterministic => Self::Deterministic(DeterministicIo::default()),
        }
    }

    pub fn read_to_string(&self, path: &str) -> Result<String, IoError> {
        match self {
            Self::Host(backend) => backend.read_to_string(path),
            Self::Deterministic(backend) => backend.read_to_string(path),
        }
    }

    pub fn write_string(&mut self, path: &str, value: &str) -> Result<(), IoError> {
        match self {
            Self::Host(backend) => backend.write_string(path, value),
            Self::Deterministic(backend) => backend.write_string(path, value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicIo, IoBackend, IoError};

    #[test]
    fn deterministic_backend_reads_and_writes() {
        let mut io = DeterministicIo::default();
        io.write_string("/tmp/demo.txt", "abc")
            .expect("det write should succeed");
        assert_eq!(
            io.read_to_string("/tmp/demo.txt")
                .expect("det read should succeed"),
            "abc"
        );
        assert_eq!(
            io.read_to_string("/tmp/missing.txt"),
            Err(IoError::NotFound("/tmp/missing.txt".to_string()))
        );
    }
}
