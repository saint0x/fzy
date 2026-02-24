use capabilities::{Capability, CapabilityToken};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::capability::{require_capability, CapabilityError};

pub fn required_capability_for_file_io() -> Capability {
    Capability::FileSystem
}

pub fn read_to_string_with_capability(
    backend: &dyn IoBackend,
    path: &str,
    token: &CapabilityToken,
) -> Result<String, CapabilityError> {
    require_capability(token, required_capability_for_file_io())?;
    backend
        .read_to_string(path)
        .map_err(|_| CapabilityError::Missing(required_capability_for_file_io()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    Host,
    Deterministic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    Truncate,
    Append,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    NotFound(String),
    PermissionDenied(String),
    SymlinkDetected(String),
    InvalidPath(String),
    Backend(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub path: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub len: u64,
    pub mode: u32,
    pub modified_unix_secs: Option<u64>,
}

pub trait IoBackend {
    fn read_to_string(&self, path: &str) -> Result<String, IoError>;
    fn write_string(&mut self, path: &str, value: &str) -> Result<(), IoError>;

    fn read_binary(&self, path: &str) -> Result<Vec<u8>, IoError>;
    fn write_binary(&mut self, path: &str, value: &[u8], mode: WriteMode) -> Result<(), IoError>;
    fn read_stream(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, IoError>;

    fn list_dir(&self, path: &str) -> Result<Vec<String>, IoError>;
    fn metadata(&self, path: &str) -> Result<FileMetadata, IoError>;
    fn delete(&mut self, path: &str) -> Result<(), IoError>;
    fn check_permission(&self, path: &str, mode: u32) -> Result<bool, IoError>;

    fn write_atomic_checked(&mut self, path: &str, value: &[u8]) -> Result<(), IoError>;
}

#[derive(Default)]
pub struct HostIo;

impl HostIo {
    fn map_io(path: &str, err: std::io::Error) -> IoError {
        match err.kind() {
            std::io::ErrorKind::NotFound => IoError::NotFound(path.to_string()),
            std::io::ErrorKind::PermissionDenied => IoError::PermissionDenied(path.to_string()),
            _ => IoError::Backend(err.to_string()),
        }
    }

    fn ensure_parent_safe(path: &Path) -> Result<(), IoError> {
        let parent = path
            .parent()
            .ok_or_else(|| IoError::InvalidPath(path.display().to_string()))?;
        let mut current = PathBuf::new();
        for part in parent.components() {
            current.push(part);
            if let Ok(meta) = std::fs::symlink_metadata(&current) {
                if meta.file_type().is_symlink() {
                    return Err(IoError::SymlinkDetected(current.display().to_string()));
                }
            }
        }
        std::fs::create_dir_all(parent).map_err(|e| IoError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl IoBackend for HostIo {
    fn read_to_string(&self, path: &str) -> Result<String, IoError> {
        std::fs::read_to_string(path).map_err(|err| Self::map_io(path, err))
    }

    fn write_string(&mut self, path: &str, value: &str) -> Result<(), IoError> {
        self.write_binary(path, value.as_bytes(), WriteMode::Truncate)
    }

    fn read_binary(&self, path: &str) -> Result<Vec<u8>, IoError> {
        std::fs::read(path).map_err(|err| Self::map_io(path, err))
    }

    fn write_binary(&mut self, path: &str, value: &[u8], mode: WriteMode) -> Result<(), IoError> {
        let path_ref = Path::new(path);
        if let Some(parent) = path_ref.parent() {
            std::fs::create_dir_all(parent).map_err(|e| IoError::Backend(e.to_string()))?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true);
        match mode {
            WriteMode::Truncate => {
                options.truncate(true);
            }
            WriteMode::Append => {
                options.append(true);
            }
        }
        let mut file = options.open(path).map_err(|err| Self::map_io(path, err))?;
        file.write_all(value)
            .map_err(|err| IoError::Backend(err.to_string()))
    }

    fn read_stream(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, IoError> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|err| Self::map_io(path, err))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| IoError::Backend(err.to_string()))?;
        let mut buffer = vec![0_u8; len];
        let read = file
            .read(&mut buffer)
            .map_err(|err| IoError::Backend(err.to_string()))?;
        buffer.truncate(read);
        Ok(buffer)
    }

    fn list_dir(&self, path: &str) -> Result<Vec<String>, IoError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path).map_err(|err| Self::map_io(path, err))? {
            let entry = entry.map_err(|err| IoError::Backend(err.to_string()))?;
            entries.push(entry.path().display().to_string());
        }
        entries.sort();
        Ok(entries)
    }

    fn metadata(&self, path: &str) -> Result<FileMetadata, IoError> {
        let meta = std::fs::symlink_metadata(path).map_err(|err| Self::map_io(path, err))?;
        let modified = meta
            .modified()
            .ok()
            .and_then(|ts| ts.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        Ok(FileMetadata {
            path: path.to_string(),
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            is_symlink: meta.file_type().is_symlink(),
            len: meta.len(),
            mode: meta.mode(),
            modified_unix_secs: modified,
        })
    }

    fn delete(&mut self, path: &str) -> Result<(), IoError> {
        let meta = std::fs::symlink_metadata(path).map_err(|err| Self::map_io(path, err))?;
        if meta.is_dir() {
            std::fs::remove_dir_all(path).map_err(|err| IoError::Backend(err.to_string()))
        } else {
            std::fs::remove_file(path).map_err(|err| IoError::Backend(err.to_string()))
        }
    }

    fn check_permission(&self, path: &str, mode: u32) -> Result<bool, IoError> {
        let meta = std::fs::symlink_metadata(path).map_err(|err| Self::map_io(path, err))?;
        Ok((meta.mode() & mode) == mode)
    }

    fn write_atomic_checked(&mut self, path: &str, value: &[u8]) -> Result<(), IoError> {
        let path_ref = Path::new(path);
        Self::ensure_parent_safe(path_ref)?;
        let tmp = path_ref.with_extension("tmp");
        {
            let mut file =
                std::fs::File::create(&tmp).map_err(|e| IoError::Backend(e.to_string()))?;
            file.write_all(value)
                .map_err(|e| IoError::Backend(e.to_string()))?;
            file.sync_all()
                .map_err(|e| IoError::Backend(e.to_string()))?;
        }
        std::fs::rename(&tmp, path_ref).map_err(|e| IoError::Backend(e.to_string()))
    }
}

#[derive(Default)]
pub struct DeterministicIo {
    files: BTreeMap<String, Vec<u8>>,
    directories: BTreeMap<String, Vec<String>>,
    permissions: BTreeMap<String, u32>,
}

impl DeterministicIo {
    pub fn with_seeded_files(files: BTreeMap<String, String>) -> Self {
        let mut out = Self::default();
        for (path, content) in files {
            out.files.insert(path, content.into_bytes());
        }
        out
    }
}

impl IoBackend for DeterministicIo {
    fn read_to_string(&self, path: &str) -> Result<String, IoError> {
        self.files
            .get(path)
            .map(|v| String::from_utf8_lossy(v).to_string())
            .ok_or_else(|| IoError::NotFound(path.to_string()))
    }

    fn write_string(&mut self, path: &str, value: &str) -> Result<(), IoError> {
        self.files
            .insert(path.to_string(), value.as_bytes().to_vec());
        Ok(())
    }

    fn read_binary(&self, path: &str) -> Result<Vec<u8>, IoError> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| IoError::NotFound(path.to_string()))
    }

    fn write_binary(&mut self, path: &str, value: &[u8], mode: WriteMode) -> Result<(), IoError> {
        match mode {
            WriteMode::Truncate => {
                self.files.insert(path.to_string(), value.to_vec());
            }
            WriteMode::Append => {
                self.files
                    .entry(path.to_string())
                    .or_default()
                    .extend_from_slice(value);
            }
        }
        Ok(())
    }

    fn read_stream(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, IoError> {
        let bytes = self
            .files
            .get(path)
            .ok_or_else(|| IoError::NotFound(path.to_string()))?;
        let start = (offset as usize).min(bytes.len());
        let end = (start + len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }

    fn list_dir(&self, path: &str) -> Result<Vec<String>, IoError> {
        Ok(self.directories.get(path).cloned().unwrap_or_default())
    }

    fn metadata(&self, path: &str) -> Result<FileMetadata, IoError> {
        if let Some(bytes) = self.files.get(path) {
            return Ok(FileMetadata {
                path: path.to_string(),
                is_dir: false,
                is_file: true,
                is_symlink: false,
                len: bytes.len() as u64,
                mode: *self.permissions.get(path).unwrap_or(&0o644),
                modified_unix_secs: Some(0),
            });
        }
        if self.directories.contains_key(path) {
            return Ok(FileMetadata {
                path: path.to_string(),
                is_dir: true,
                is_file: false,
                is_symlink: false,
                len: 0,
                mode: *self.permissions.get(path).unwrap_or(&0o755),
                modified_unix_secs: Some(0),
            });
        }
        Err(IoError::NotFound(path.to_string()))
    }

    fn delete(&mut self, path: &str) -> Result<(), IoError> {
        let existed = self.files.remove(path).is_some() || self.directories.remove(path).is_some();
        if existed {
            Ok(())
        } else {
            Err(IoError::NotFound(path.to_string()))
        }
    }

    fn check_permission(&self, path: &str, mode: u32) -> Result<bool, IoError> {
        let have = *self.permissions.get(path).unwrap_or(&0o777);
        Ok((have & mode) == mode)
    }

    fn write_atomic_checked(&mut self, path: &str, value: &[u8]) -> Result<(), IoError> {
        self.files.insert(path.to_string(), value.to_vec());
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

    pub fn backend(&self) -> &dyn IoBackend {
        match self {
            Self::Host(backend) => backend,
            Self::Deterministic(backend) => backend,
        }
    }

    pub fn backend_mut(&mut self) -> &mut dyn IoBackend {
        match self {
            Self::Host(backend) => backend,
            Self::Deterministic(backend) => backend,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicIo, IoBackend, IoError, WriteMode};

    #[test]
    fn deterministic_backend_binary_and_streaming() {
        let mut io = DeterministicIo::default();
        io.write_binary("/tmp/demo.bin", b"abcdef", WriteMode::Truncate)
            .expect("write");
        assert_eq!(io.read_stream("/tmp/demo.bin", 2, 3).expect("read"), b"cde");
        io.write_binary("/tmp/demo.bin", b"+", WriteMode::Append)
            .expect("append");
        assert_eq!(io.read_binary("/tmp/demo.bin").expect("read"), b"abcdef+");
    }

    #[test]
    fn deterministic_backend_errors_when_missing() {
        let io = DeterministicIo::default();
        assert_eq!(
            io.read_binary("/tmp/missing"),
            Err(IoError::NotFound("/tmp/missing".to_string()))
        );
    }
}
