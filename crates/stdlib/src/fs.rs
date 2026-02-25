use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum FsError {
    Io(std::io::Error),
    InvalidRange {
        offset: u64,
        len: usize,
        file_size: u64,
    },
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::InvalidRange {
                offset,
                len,
                file_size,
            } => write!(
                f,
                "invalid file range offset={} len={} file_size={}",
                offset, len, file_size
            ),
        }
    }
}

impl std::error::Error for FsError {}

impl From<std::io::Error> for FsError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct TempFile {
    path: PathBuf,
    file: File,
}

impl TempFile {
    pub fn create(prefix: &str) -> Result<Self, FsError> {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let name = format!(
            "{}-{}-{}-{}.tmp",
            sanitize_prefix(prefix),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            nonce
        );
        let path = std::env::temp_dir().join(name);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        self.file.write_all(bytes)?;
        self.file.flush()?;
        Ok(())
    }

    pub fn read_to_end(&mut self) -> Result<Vec<u8>, FsError> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut out = Vec::new();
        self.file.read_to_end(&mut out)?;
        Ok(out)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmapPolicy {
    Disabled,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingSource {
    ReadCopy,
}

#[derive(Debug, Clone)]
pub struct ReadOnlyMapping {
    bytes: Vec<u8>,
    source: MappingSource,
}

impl ReadOnlyMapping {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn source(&self) -> MappingSource {
        self.source
    }
}

pub fn map_read_only(path: &Path, _policy: MmapPolicy) -> Result<ReadOnlyMapping, FsError> {
    let bytes = std::fs::read(path)?;
    Ok(ReadOnlyMapping {
        bytes,
        source: MappingSource::ReadCopy,
    })
}

pub fn read_region(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let end = offset.saturating_add(len as u64);
    if end > size {
        return Err(FsError::InvalidRange {
            offset,
            len,
            file_size: size,
        });
    }

    file.seek(SeekFrom::Start(offset))?;
    let mut out = vec![0u8; len];
    file.read_exact(&mut out)?;
    Ok(out)
}

pub fn write_region(path: &Path, offset: u64, bytes: &[u8]) -> Result<(), FsError> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn sanitize_prefix(prefix: &str) -> String {
    let out: String = prefix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        "tmp".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{map_read_only, read_region, write_region, MmapPolicy, TempFile};

    #[test]
    fn tempfile_lifecycle_and_region_io() {
        let mut tmp = TempFile::create("fozzy-fs").expect("tempfile create");
        tmp.write_all(b"abcdefgh").expect("write");

        let full = tmp.read_to_end().expect("read");
        assert_eq!(full, b"abcdefgh");

        write_region(tmp.path(), 2, b"ZZ").expect("write region");
        let region = read_region(tmp.path(), 1, 4).expect("read region");
        assert_eq!(region, b"bZZe");
    }

    #[test]
    fn optional_mapping_has_safe_fallback() {
        let mut tmp = TempFile::create("fozzy-map").expect("tempfile create");
        tmp.write_all(b"map me").expect("write");
        let mapping = map_read_only(tmp.path(), MmapPolicy::Optional).expect("map");
        assert_eq!(mapping.as_slice(), b"map me");
    }
}
