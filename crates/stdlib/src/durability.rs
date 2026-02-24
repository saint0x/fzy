use capabilities::{Capability, CapabilityToken};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::capability::{require_capability, CapabilityError};

pub fn required_capability_for_durable_fs() -> Capability {
    Capability::FileSystem
}

pub fn write_atomic_with_capability(
    path: &Path,
    bytes: &[u8],
    token: &CapabilityToken,
) -> Result<(), CapabilityError> {
    require_capability(token, required_capability_for_durable_fs())?;
    write_atomic(path, bytes).map_err(|_| CapabilityError::Missing(required_capability_for_durable_fs()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    Io(String),
    LockBusy,
    QueueFull,
    Injected(String),
}

#[derive(Debug)]
pub struct FileLock {
    lock_path: PathBuf,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), FsError> {
    let parent = path
        .parent()
        .ok_or_else(|| FsError::Io("path has no parent".to_string()))?;
    fs::create_dir_all(parent).map_err(|e| FsError::Io(e.to_string()))?;

    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp).map_err(|e| FsError::Io(e.to_string()))?;
        file.write_all(bytes)
            .map_err(|e| FsError::Io(e.to_string()))?;
        file.flush().map_err(|e| FsError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| FsError::Io(e.to_string()))?;
    }
    fs::rename(&tmp, path).map_err(|e| FsError::Io(e.to_string()))?;
    Ok(())
}

pub fn fsync_file(path: &Path) -> Result<(), FsError> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| FsError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| FsError::Io(e.to_string()))
}

pub fn acquire_file_lock(path: &Path) -> Result<FileLock, FsError> {
    let lock_path = path.with_extension("lock");
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(mut file) => {
            file.write_all(b"locked")
                .map_err(|e| FsError::Io(e.to_string()))?;
            Ok(FileLock { lock_path })
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Err(FsError::LockBusy),
        Err(err) => Err(FsError::Io(err.to_string())),
    }
}

pub struct BoundedReader {
    source: VecDeque<u8>,
    chunk_limit: usize,
}

impl BoundedReader {
    pub fn new(data: Vec<u8>, chunk_limit: usize) -> Self {
        Self {
            source: VecDeque::from(data),
            chunk_limit,
        }
    }

    pub fn read_chunk(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.chunk_limit);
        for _ in 0..self.chunk_limit {
            if let Some(byte) = self.source.pop_front() {
                out.push(byte);
            } else {
                break;
            }
        }
        out
    }
}

pub struct BoundedWriter {
    queue: VecDeque<u8>,
    max_buffer: usize,
    overflow_cb: Option<Box<dyn Fn(usize, usize) + Send + Sync + 'static>>,
}

impl BoundedWriter {
    pub fn new(max_buffer: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_buffer,
            overflow_cb: None,
        }
    }

    pub fn with_overflow_callback<F>(max_buffer: usize, callback: F) -> Self
    where
        F: Fn(usize, usize) + Send + Sync + 'static,
    {
        Self {
            queue: VecDeque::new(),
            max_buffer,
            overflow_cb: Some(Box::new(callback)),
        }
    }

    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<usize, FsError> {
        if self.queue.len() + chunk.len() > self.max_buffer {
            if let Some(callback) = &self.overflow_cb {
                callback(self.queue.len() + chunk.len(), self.max_buffer);
            }
            return Err(FsError::QueueFull);
        }
        self.queue.extend(chunk.iter().copied());
        Ok(chunk.len())
    }

    pub fn drain_to<W: Write>(&mut self, sink: &mut W, limit: usize) -> Result<usize, FsError> {
        let mut drained = Vec::new();
        for _ in 0..limit {
            if let Some(byte) = self.queue.pop_front() {
                drained.push(byte);
            } else {
                break;
            }
        }
        sink.write_all(&drained)
            .map_err(|e| FsError::Io(e.to_string()))?;
        Ok(drained.len())
    }

    pub fn buffered_len(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Default)]
pub struct DeterministicDurableFs {
    files: BTreeMap<String, Vec<u8>>,
    fail_writes: BTreeMap<String, usize>,
    fail_reads: BTreeMap<String, usize>,
}

impl DeterministicDurableFs {
    pub fn inject_write_failures(&mut self, path: impl Into<String>, remaining: usize) {
        self.fail_writes.insert(path.into(), remaining);
    }

    pub fn inject_read_failures(&mut self, path: impl Into<String>, remaining: usize) {
        self.fail_reads.insert(path.into(), remaining);
    }

    pub fn write_atomic(&mut self, path: &str, bytes: &[u8]) -> Result<(), FsError> {
        if let Some(remaining) = self.fail_writes.get_mut(path) {
            if *remaining > 0 {
                *remaining -= 1;
                return Err(FsError::Injected(format!("write failure for {path}")));
            }
        }
        self.files.insert(path.to_string(), bytes.to_vec());
        Ok(())
    }

    pub fn read_all(&mut self, path: &str) -> Result<Option<Vec<u8>>, FsError> {
        if let Some(remaining) = self.fail_reads.get_mut(path) {
            if *remaining > 0 {
                *remaining -= 1;
                return Err(FsError::Injected(format!("read failure for {path}")));
            }
        }
        Ok(self.files.get(path).cloned())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        acquire_file_lock, fsync_file, write_atomic, BoundedReader, BoundedWriter, FsError,
    };

    #[test]
    fn write_atomic_and_fsync_work() {
        let dir = std::env::temp_dir().join("fozzy_durable_test");
        let file = dir.join("data.txt");
        write_atomic(&file, b"abc").expect("atomic write should work");
        fsync_file(&file).expect("fsync should work");
        let read = fs::read(&file).expect("read should work");
        assert_eq!(read, b"abc");
        let _ = fs::remove_file(file);
    }

    #[test]
    fn lock_contention_is_detected() {
        let file = std::env::temp_dir().join("fozzy_lock_contention.txt");
        let lock_one = acquire_file_lock(&file).expect("first lock should work");
        let lock_two = acquire_file_lock(&file);
        assert!(matches!(lock_two, Err(FsError::LockBusy)));
        drop(lock_one);
    }

    #[test]
    fn bounded_streaming_enforces_backpressure() {
        let mut writer = BoundedWriter::new(4);
        writer.write_chunk(b"ab").expect("write should work");
        assert_eq!(writer.write_chunk(b"cde"), Err(FsError::QueueFull));

        let mut sink = Vec::new();
        writer.drain_to(&mut sink, 8).expect("drain should work");
        assert_eq!(sink, b"ab");

        let mut reader = BoundedReader::new(b"hello".to_vec(), 2);
        assert_eq!(reader.read_chunk(), b"he");
        assert_eq!(reader.read_chunk(), b"ll");
        assert_eq!(reader.read_chunk(), b"o");
    }

    #[test]
    fn deterministic_fs_supports_error_injection() {
        let mut fs = super::DeterministicDurableFs::default();
        fs.inject_write_failures("/tmp/fail", 1);
        assert!(matches!(
            fs.write_atomic("/tmp/fail", b"x"),
            Err(FsError::Injected(_))
        ));
        fs.write_atomic("/tmp/fail", b"ok")
            .expect("second write should succeed");
        fs.inject_read_failures("/tmp/fail", 1);
        assert!(matches!(
            fs.read_all("/tmp/fail"),
            Err(FsError::Injected(_))
        ));
        assert_eq!(fs.read_all("/tmp/fail").expect("read").as_deref(), Some(&b"ok"[..]));
    }
}
