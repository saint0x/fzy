//! Fuzz corpus management.

use clap::Subcommand;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::{Config, FozzyError, FozzyResult};

#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    List {
        dir: PathBuf,
    },
    Add {
        dir: PathBuf,
        file: PathBuf,
    },
    Minimize {
        dir: PathBuf,
        #[arg(long)]
        budget: Option<crate::FozzyDuration>,
    },
    Export {
        dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Import {
        zip: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

pub fn corpus_command(_config: &Config, command: &CorpusCommand) -> FozzyResult<serde_json::Value> {
    match command {
        CorpusCommand::List { dir } => {
            let mut files = Vec::new();
            if dir.exists() {
                for entry in WalkDir::new(dir).min_depth(1).max_depth(1) {
                    let entry = entry.map_err(|e| {
                        let msg = e.to_string();
                        FozzyError::Io(
                            e.into_io_error()
                                .unwrap_or_else(|| std::io::Error::other(msg)),
                        )
                    })?;
                    if entry.file_type().is_file() {
                        files.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
            files.sort();
            Ok(serde_json::to_value(files)?)
        }

        CorpusCommand::Add { dir, file } => {
            std::fs::create_dir_all(dir)?;
            let bytes = std::fs::read(file)?;
            let name = format!("input-{}.bin", blake3::hash(&bytes).to_hex());
            let out_path = dir.join(name);
            std::fs::write(&out_path, bytes)?;
            Ok(serde_json::json!({"added": out_path.to_string_lossy().to_string()}))
        }

        CorpusCommand::Minimize { dir, budget: _ } => {
            // Placeholder: true corpus minimization depends on the target + coverage signals.
            Ok(serde_json::json!({"ok": true, "dir": dir.to_string_lossy().to_string()}))
        }

        CorpusCommand::Export { dir, out } => {
            export_zip(dir, out)?;
            Ok(serde_json::json!({"ok": true, "zip": out.to_string_lossy().to_string()}))
        }

        CorpusCommand::Import { zip, out } => {
            import_zip(zip, out)?;
            Ok(serde_json::json!({"ok": true, "dir": out.to_string_lossy().to_string()}))
        }
    }
}

fn export_zip(dir: &Path, out_zip: &Path) -> FozzyResult<()> {
    if !dir.exists() {
        return Err(FozzyError::InvalidArgument(format!(
            "corpus directory not found: {}",
            dir.display()
        )));
    }
    if !dir.is_dir() {
        return Err(FozzyError::InvalidArgument(format!(
            "corpus export source is not a directory: {}",
            dir.display()
        )));
    }

    validate_output_file_path_secure(out_zip)?;
    if let Some(parent) = out_zip.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file_name = out_zip
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("corpus.zip");
    let tmp_name = format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let tmp_path = out_zip
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(tmp_name);

    let write_result = (|| -> FozzyResult<()> {
        let file = File::create(&tmp_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);

        let mut wrote_any = false;
        for entry in WalkDir::new(dir).min_depth(1) {
            let entry = entry.map_err(|e| {
                let msg = e.to_string();
                FozzyError::Io(
                    e.into_io_error()
                        .unwrap_or_else(|| std::io::Error::other(msg)),
                )
            })?;
            if !entry.file_type().is_file() {
                continue;
            }

            let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
            let name = rel.to_string_lossy().replace('\\', "/");
            zip.start_file(name, options)?;
            let bytes = std::fs::read(entry.path())?;
            zip.write_all(&bytes)?;
            wrote_any = true;
        }

        if !wrote_any {
            return Err(FozzyError::InvalidArgument(format!(
                "corpus directory has no files to export: {}",
                dir.display()
            )));
        }

        zip.finish()?;
        Ok(())
    })();

    match write_result {
        Ok(()) => {
            std::fs::rename(&tmp_path, out_zip)?;
            Ok(())
        }
        Err(err) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(err)
        }
    }
}

fn validate_output_file_path_secure(out_file: &Path) -> FozzyResult<()> {
    if out_file.exists() {
        let md = std::fs::symlink_metadata(out_file)?;
        if md.file_type().is_symlink() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite symlinked output file: {}",
                out_file.display()
            )));
        }
    }
    validate_output_dir_path_secure(out_file.parent().unwrap_or_else(|| Path::new(".")))
}

fn validate_output_dir_path_secure(path: &Path) -> FozzyResult<()> {
    let is_abs = path.is_absolute();
    let mut cur = if is_abs {
        PathBuf::from(Path::new(std::path::MAIN_SEPARATOR_STR))
    } else {
        std::env::current_dir()?
    };
    let mut normal_seen = 0usize;
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::Prefix(prefix) => cur.push(prefix.as_os_str()),
            Component::RootDir => {}
            Component::CurDir => continue,
            Component::ParentDir => cur.push(".."),
            Component::Normal(seg) => {
                normal_seen += 1;
                cur.push(seg);
            }
        }
        if cur.exists() {
            let md = std::fs::symlink_metadata(&cur)?;
            let skip_abs_top_component = is_abs && normal_seen == 1;
            if md.file_type().is_symlink() && !skip_abs_top_component {
                return Err(FozzyError::InvalidArgument(format!(
                    "refusing to write through symlinked output path: {}",
                    cur.display()
                )));
            }
        }
    }
    Ok(())
}

fn import_zip(zip_path: &Path, out_dir: &Path) -> FozzyResult<()> {
    std::fs::create_dir_all(out_dir)?;
    if std::fs::symlink_metadata(out_dir)?.file_type().is_symlink() {
        return Err(FozzyError::InvalidArgument(format!(
            "refusing to import into symlinked output directory: {}",
            out_dir.display()
        )));
    }

    validate_zip_archive_raw_entries(zip_path)?;

    let file = File::open(zip_path)?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| FozzyError::InvalidArgument(format!("invalid zip: {e}")))?;
    let mut seen_targets = HashSet::new();
    for i in 0..zip.len() {
        let f = zip
            .by_index(i)
            .map_err(|e| FozzyError::InvalidArgument(format!("zip read error: {e}")))?;
        if f.is_dir() {
            continue;
        }
        validate_zip_entry_name_raw(f.name_raw(), f.name())?;
        let rel = normalize_zip_entry_rel_path(f.name())?;
        validate_zip_target_secure(out_dir, &rel, &mut seen_targets)?;
    }

    let file = File::open(zip_path)?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| FozzyError::InvalidArgument(format!("invalid zip: {e}")))?;
    for i in 0..zip.len() {
        let mut f = zip
            .by_index(i)
            .map_err(|e| FozzyError::InvalidArgument(format!("zip read error: {e}")))?;
        if f.is_dir() {
            continue;
        }
        validate_zip_entry_name_raw(f.name_raw(), f.name())?;
        let name = f.name().to_string();
        write_zip_entry_secure(out_dir, &name, &mut f)?;
    }
    Ok(())
}

fn validate_zip_archive_raw_entries(zip_path: &Path) -> FozzyResult<()> {
    let bytes = std::fs::read(zip_path)?;
    let raw_names = parse_zip_central_directory_names(&bytes)?;
    let mut seen = HashSet::<String>::new();
    for raw in raw_names {
        if raw.contains(&0) {
            return Err(FozzyError::InvalidArgument(format!(
                "unsafe archive entry path rejected: {}",
                String::from_utf8_lossy(&raw)
            )));
        }
        let name = std::str::from_utf8(&raw).map_err(|_| {
            FozzyError::InvalidArgument(format!(
                "unsafe archive entry path rejected: {}",
                String::from_utf8_lossy(&raw)
            ))
        })?;
        let rel = normalize_zip_entry_rel_path(name)?;
        let key = portable_rel_key(&rel);
        if !seen.insert(key) {
            return Err(FozzyError::InvalidArgument(format!(
                "duplicate output file in archive is not allowed: {}",
                rel.display()
            )));
        }
    }
    Ok(())
}

fn parse_zip_central_directory_names(bytes: &[u8]) -> FozzyResult<Vec<Vec<u8>>> {
    const CEN_SIG: u32 = 0x0201_4b50;
    const ZIP64_U16_MAX: u16 = 0xFFFF;
    const ZIP64_U32_MAX: u32 = 0xFFFF_FFFF;

    let Some(eocd) = find_eocd_offset(bytes) else {
        return Err(FozzyError::InvalidArgument(
            "invalid zip: missing end-of-central-directory".to_string(),
        ));
    };
    let total_entries = read_u16_le(bytes, eocd + 10)?;
    let cd_size = read_u32_le(bytes, eocd + 12)?;
    let cd_offset = read_u32_le(bytes, eocd + 16)?;
    if total_entries == ZIP64_U16_MAX || cd_size == ZIP64_U32_MAX || cd_offset == ZIP64_U32_MAX {
        return Err(FozzyError::InvalidArgument(
            "invalid zip: zip64 archives are not supported for corpus import".to_string(),
        ));
    }

    let total_entries = total_entries as usize;
    let cd_offset = cd_offset as usize;
    let cd_size = cd_size as usize;
    let cd_end = cd_offset.checked_add(cd_size).ok_or_else(|| {
        FozzyError::InvalidArgument("invalid zip: central directory overflow".to_string())
    })?;
    if cd_end > bytes.len() {
        return Err(FozzyError::InvalidArgument(
            "invalid zip: central directory out of bounds".to_string(),
        ));
    }

    let mut names = Vec::with_capacity(total_entries);
    let mut pos = cd_offset;
    for _ in 0..total_entries {
        if pos + 46 > cd_end {
            return Err(FozzyError::InvalidArgument(
                "invalid zip: malformed central directory entry".to_string(),
            ));
        }
        let sig = read_u32_le(bytes, pos)?;
        if sig != CEN_SIG {
            return Err(FozzyError::InvalidArgument(
                "invalid zip: bad central directory signature".to_string(),
            ));
        }
        let name_len = read_u16_le(bytes, pos + 28)? as usize;
        let extra_len = read_u16_le(bytes, pos + 30)? as usize;
        let comment_len = read_u16_le(bytes, pos + 32)? as usize;
        let name_start = pos + 46;
        let name_end = name_start.checked_add(name_len).ok_or_else(|| {
            FozzyError::InvalidArgument("invalid zip: filename length overflow".to_string())
        })?;
        if name_end > cd_end {
            return Err(FozzyError::InvalidArgument(
                "invalid zip: filename out of bounds".to_string(),
            ));
        }
        names.push(bytes[name_start..name_end].to_vec());
        pos = name_end
            .checked_add(extra_len)
            .and_then(|p| p.checked_add(comment_len))
            .ok_or_else(|| {
                FozzyError::InvalidArgument("invalid zip: central directory overflow".to_string())
            })?;
    }

    Ok(names)
}

fn find_eocd_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 {
        return None;
    }
    let start = bytes.len().saturating_sub(22 + 65_535);
    (start..=bytes.len() - 22)
        .rev()
        .find(|&i| bytes[i..].starts_with(&[0x50, 0x4b, 0x05, 0x06]))
}

fn read_u16_le(bytes: &[u8], off: usize) -> FozzyResult<u16> {
    if off + 2 > bytes.len() {
        return Err(FozzyError::InvalidArgument(
            "invalid zip: truncated data".to_string(),
        ));
    }
    Ok(u16::from_le_bytes([bytes[off], bytes[off + 1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> FozzyResult<u32> {
    if off + 4 > bytes.len() {
        return Err(FozzyError::InvalidArgument(
            "invalid zip: truncated data".to_string(),
        ));
    }
    Ok(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

fn write_zip_entry_secure(
    out_dir: &Path,
    entry_name: &str,
    reader: &mut dyn Read,
) -> FozzyResult<()> {
    let rel = normalize_zip_entry_rel_path(entry_name)?;
    let out_path = out_dir.join(&rel);

    // Reject symlinked parent components before creating/writing.
    let mut cur = out_dir.to_path_buf();
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            use std::path::Component;
            let Component::Normal(seg) = comp else {
                continue;
            };
            cur.push(seg);
            if cur.exists() {
                let md = std::fs::symlink_metadata(&cur)?;
                if md.file_type().is_symlink() {
                    return Err(FozzyError::InvalidArgument(format!(
                        "refusing to write through symlinked output path: {}",
                        cur.display()
                    )));
                }
            } else {
                std::fs::create_dir(&cur)?;
            }
        }
    }

    if out_path.exists() {
        let md = std::fs::symlink_metadata(&out_path)?;
        if md.file_type().is_symlink() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite symlinked output file: {}",
                out_path.display()
            )));
        }
        if !md.is_file() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite non-file output path: {}",
                out_path.display()
            )));
        }
        return Err(FozzyError::InvalidArgument(format!(
            "refusing to overwrite existing output file: {}",
            out_path.display()
        )));
    }

    let parent = out_path.parent().unwrap_or(out_dir);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        out_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("corpus"),
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let tmp = parent.join(tmp_name);
    let mut out = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)?;
    std::io::copy(reader, &mut out)?;
    std::fs::rename(&tmp, &out_path)?;
    Ok(())
}

fn validate_zip_target_secure(
    out_dir: &Path,
    rel: &Path,
    seen_targets: &mut HashSet<String>,
) -> FozzyResult<()> {
    let key = portable_rel_key(rel);
    if !seen_targets.insert(key) {
        return Err(FozzyError::InvalidArgument(format!(
            "duplicate output file in archive is not allowed: {}",
            rel.display()
        )));
    }

    // Reject symlinked parent components before creating/writing.
    let mut cur = out_dir.to_path_buf();
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            use std::path::Component;
            let Component::Normal(seg) = comp else {
                continue;
            };
            cur.push(seg);
            if cur.exists() {
                let md = std::fs::symlink_metadata(&cur)?;
                if md.file_type().is_symlink() {
                    return Err(FozzyError::InvalidArgument(format!(
                        "refusing to write through symlinked output path: {}",
                        cur.display()
                    )));
                }
            }
        }
    }

    let out_path = out_dir.join(rel);
    if out_path.exists() {
        let md = std::fs::symlink_metadata(&out_path)?;
        if md.file_type().is_symlink() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite symlinked output file: {}",
                out_path.display()
            )));
        }
        if !md.is_file() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite non-file output path: {}",
                out_path.display()
            )));
        }
        return Err(FozzyError::InvalidArgument(format!(
            "refusing to overwrite existing output file: {}",
            out_path.display()
        )));
    }

    Ok(())
}

fn portable_rel_key(rel: &Path) -> String {
    let mut out = String::new();
    for (idx, comp) in rel.components().enumerate() {
        use std::path::Component;
        if let Component::Normal(seg) = comp {
            if idx > 0 {
                out.push('/');
            }
            out.push_str(&seg.to_string_lossy().to_lowercase());
        }
    }
    out
}

fn normalize_zip_entry_rel_path(name: &str) -> FozzyResult<PathBuf> {
    // Archive entry names must be portable relative POSIX-style paths.
    // Reject Windows-style separators/prefixes/UNC roots on every host.
    if name.starts_with("//")
        || name.starts_with("\\\\")
        || name.contains('\\')
        || is_windows_drive_prefixed(name)
    {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {name}"
        )));
    }

    let path = Path::new(name);
    let mut rel = PathBuf::new();
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::Normal(seg) => {
                let seg = seg.to_str().ok_or_else(|| {
                    FozzyError::InvalidArgument(format!(
                        "unsafe archive entry path rejected: {name}"
                    ))
                })?;
                validate_archive_path_segment(seg, name)?;
                rel.push(seg);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FozzyError::InvalidArgument(format!(
                    "unsafe archive entry path rejected: {name}"
                )));
            }
        }
    }
    if rel.as_os_str().is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {name}"
        )));
    }
    Ok(rel)
}

fn validate_zip_entry_name_raw(raw_name: &[u8], display_name: &str) -> FozzyResult<()> {
    if raw_name.contains(&0) {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {display_name}"
        )));
    }
    Ok(())
}

fn is_windows_drive_prefixed(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn validate_archive_path_segment(seg: &str, original_name: &str) -> FozzyResult<()> {
    if seg.is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    // Keep entry names portable and safe across platforms/tools.
    if seg.ends_with('.') || seg.ends_with(' ') {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    if seg
        .chars()
        .any(|c| c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    if is_windows_reserved_name(seg) {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    Ok(())
}

fn is_windows_reserved_name(seg: &str) -> bool {
    let trimmed = seg.trim_end_matches(['.', ' ']);
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in bytes {
            crc ^= b as u32;
            for _ in 0..8 {
                let lsb = crc & 1;
                crc >>= 1;
                if lsb != 0 {
                    crc ^= 0xEDB8_8320;
                }
            }
        }
        !crc
    }

    fn build_zip_with_raw_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        let mut central = Vec::<u8>::new();
        let mut offsets = Vec::<u32>::new();

        for (name, payload) in entries {
            let offset = out.len() as u32;
            offsets.push(offset);
            let crc = crc32(payload);
            let name_len = name.len() as u16;
            let size = payload.len() as u32;

            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(payload);
        }

        let cd_offset = out.len() as u32;
        for ((name, payload), offset) in entries.iter().zip(offsets.iter().copied()) {
            let crc = crc32(payload);
            let name_len = name.len() as u16;
            let size = payload.len() as u32;
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&name_len.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name);
        }
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);

        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[cfg(unix)]
    #[test]
    fn import_rejects_symlink_target_overwrite() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("fozzy-corpus-symlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("payload.bin", opts).expect("start");
            zip.write_all(b"evil").expect("write");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");
        let victim = root.join("victim.bin");
        std::fs::write(&victim, b"safe").expect("victim");
        symlink(&victim, out.join("payload.bin")).expect("symlink");

        let err = import_zip(&zip_path, &out).expect_err("must fail");
        assert!(err.to_string().contains("symlinked output file"));
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"safe");
    }

    #[cfg(unix)]
    #[test]
    fn import_failure_atomic_on_symlink_error() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-atomic-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("good-1.bin", opts).expect("start 1");
            zip.write_all(b"one").expect("write 1");
            zip.start_file("good-2.bin", opts).expect("start 2");
            zip.write_all(b"two").expect("write 2");
            zip.start_file("bad.bin", opts).expect("start bad");
            zip.write_all(b"bad").expect("write bad");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");
        let victim = root.join("victim.bin");
        std::fs::write(&victim, b"safe").expect("victim");
        symlink(&victim, out.join("bad.bin")).expect("symlink");

        let err = import_zip(&zip_path, &out).expect_err("must fail");
        assert!(err.to_string().contains("symlinked output file"));
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"safe");
        assert!(
            !out.join("good-1.bin").exists(),
            "good-1 should not be written"
        );
        assert!(
            !out.join("good-2.bin").exists(),
            "good-2 should not be written"
        );
    }

    #[test]
    fn normalize_rejects_windows_style_unsafe_paths() {
        for bad in [
            r"..\\evil_win.bin",
            r"C:\evil_drive.bin",
            "C:evil_drive.bin",
            r"\\server\share\evil_unc.bin",
            "//server/share/evil_unc.bin",
        ] {
            let err = normalize_zip_entry_rel_path(bad)
                .expect_err("must reject windows-style unsafe path");
            assert!(
                err.to_string()
                    .contains("unsafe archive entry path rejected")
            );
        }
    }

    #[test]
    fn normalize_rejects_special_unsafe_filenames() {
        for bad in [
            "\u{0001}.bin",
            "\u{0000}TRUNC.bin",
            "CON",
            "aux.txt",
            "name-with-trailing-dot.",
            "name-with-trailing-space ",
            "bad:name.bin",
            "bad*name.bin",
            "bad?name.bin",
        ] {
            let err =
                normalize_zip_entry_rel_path(bad).expect_err("must reject unsafe special filename");
            assert!(
                err.to_string()
                    .contains("unsafe archive entry path rejected")
            );
        }
    }

    #[test]
    fn import_rejects_duplicate_entry_aliases() {
        let root =
            std::env::temp_dir().join(format!("fozzy-corpus-dup-alias-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("dup.bin", opts).expect("start 1");
            zip.write_all(b"first").expect("write 1");
            zip.start_file("./dup.bin", opts).expect("start 2");
            zip.write_all(b"second").expect("write 2");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let err = import_zip(&zip_path, &out).expect_err("must reject alias duplicates");
        assert!(
            err.to_string()
                .contains("duplicate output file in archive is not allowed")
        );
        assert!(
            !out.join("dup.bin").exists(),
            "duplicate rejection should be failure-atomic"
        );
    }

    #[test]
    fn import_rejects_case_insensitive_duplicate_entry_names() {
        let root =
            std::env::temp_dir().join(format!("fozzy-corpus-dup-case-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("dup.bin", opts).expect("start 1");
            zip.write_all(b"first").expect("write 1");
            zip.start_file("DUP.BIN", opts).expect("start 2");
            zip.write_all(b"second").expect("write 2");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let err = import_zip(&zip_path, &out).expect_err("must reject case-insensitive duplicates");
        assert!(
            err.to_string()
                .contains("duplicate output file in archive is not allowed")
        );
        assert!(
            !out.join("dup.bin").exists(),
            "duplicate rejection should be failure-atomic"
        );
        assert!(
            !out.join("DUP.BIN").exists(),
            "duplicate rejection should be failure-atomic"
        );
    }

    #[test]
    fn import_rejects_overwrite_of_existing_file() {
        let root =
            std::env::temp_dir().join(format!("fozzy-corpus-overwrite-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("dup.bin", opts).expect("start");
            zip.write_all(b"new").expect("write");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");
        std::fs::write(out.join("dup.bin"), b"old").expect("seed existing");

        let err = import_zip(&zip_path, &out).expect_err("must reject overwrite");
        assert!(
            err.to_string()
                .contains("refusing to overwrite existing output file")
        );
        assert_eq!(std::fs::read(out.join("dup.bin")).expect("read"), b"old");
    }

    #[test]
    fn import_rejects_nul_in_raw_entry_name() {
        let root = std::env::temp_dir().join(format!("fozzy-corpus-nul-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("bad\0name.bin", opts).expect("start");
            zip.write_all(b"payload").expect("write");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let err = import_zip(&zip_path, &out).expect_err("must reject nul entry names");
        assert!(
            err.to_string()
                .contains("unsafe archive entry path rejected")
        );
        assert!(!out.join("bad").exists(), "must not write truncated output");
    }

    #[test]
    fn import_rejects_duplicate_entry_names_from_raw_headers() {
        let root =
            std::env::temp_dir().join(format!("fozzy-corpus-rawdup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("dup.zip");
        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let zip = build_zip_with_raw_entries(&[(b"dup.bin", b"FIRST"), (b"dup.bin", b"SECOND")]);
        std::fs::write(&zip_path, zip).expect("zip write");

        let err = import_zip(&zip_path, &out).expect_err("must reject duplicates");
        assert!(
            err.to_string()
                .contains("duplicate output file in archive is not allowed")
        );
        assert!(!out.join("dup.bin").exists(), "should fail before writes");
    }

    #[test]
    fn import_rejects_nul_collision_aliases_from_raw_headers() {
        let root =
            std::env::temp_dir().join(format!("fozzy-corpus-rawnuldup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("dup.zip");
        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let zip =
            build_zip_with_raw_entries(&[(b"bad\0suffix.bin", b"FIRST"), (b"bad", b"SECOND")]);
        std::fs::write(&zip_path, zip).expect("zip write");

        let err = import_zip(&zip_path, &out).expect_err("must reject nul-collision aliases");
        assert!(
            err.to_string()
                .contains("unsafe archive entry path rejected")
        );
        assert!(!out.join("bad").exists(), "should fail before writes");
    }

    #[cfg(unix)]
    #[test]
    fn export_rejects_symlinked_output_file() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-export-symlink-file-{}",
            uuid::Uuid::new_v4()
        ));
        let corpus = root.join("corpus");
        std::fs::create_dir_all(&corpus).expect("corpus");
        std::fs::write(corpus.join("input.bin"), b"data").expect("input");

        let victim = root.join("victim.zip");
        std::fs::write(&victim, b"safe").expect("victim");
        let out = root.join("out.zip");
        symlink(&victim, &out).expect("symlink");

        let err = export_zip(&corpus, &out).expect_err("must reject symlinked output file");
        assert!(err.to_string().contains("symlinked output file"));
        assert_eq!(std::fs::read(&victim).expect("victim"), b"safe");
    }

    #[cfg(unix)]
    #[test]
    fn export_rejects_symlinked_parent_path() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-export-symlink-parent-{}",
            uuid::Uuid::new_v4()
        ));
        let corpus = root.join("corpus");
        std::fs::create_dir_all(&corpus).expect("corpus");
        std::fs::write(corpus.join("input.bin"), b"data").expect("input");

        let real_dir = root.join("real");
        std::fs::create_dir_all(&real_dir).expect("real");
        let link_parent = root.join("linkp");
        symlink(&real_dir, &link_parent).expect("symlink parent");
        let out = link_parent.join("out.zip");

        let err = export_zip(&corpus, &out).expect_err("must reject symlink parent");
        assert!(err.to_string().contains("symlinked output path"));
        assert!(!out.exists(), "must not create zip via symlinked parent");
    }

    #[test]
    fn export_rejects_missing_source_directory() {
        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-export-missing-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("root");
        let out = root.join("out.zip");
        let src = root.join("does-not-exist");

        let err = export_zip(&src, &out).expect_err("must reject missing source");
        assert!(err.to_string().contains("corpus directory not found"));
        assert!(!out.exists(), "must not create zip for missing source");
    }

    #[test]
    fn export_rejects_empty_source_directory() {
        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-export-empty-{}",
            uuid::Uuid::new_v4()
        ));
        let src = root.join("corpus");
        std::fs::create_dir_all(&src).expect("src");
        let out = root.join("out.zip");

        let err = export_zip(&src, &out).expect_err("must reject empty source");
        assert!(
            err.to_string()
                .contains("corpus directory has no files to export")
        );
        assert!(!out.exists(), "must not create zip for empty source");
    }

    #[test]
    fn export_rejects_file_source_path() {
        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-export-file-source-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("root");
        let src = root.join("source.bin");
        std::fs::write(&src, b"payload").expect("source");
        let out = root.join("out.zip");

        let err = export_zip(&src, &out).expect_err("must reject non-directory source");
        assert!(
            err.to_string()
                .contains("corpus export source is not a directory")
        );
        assert!(
            !out.exists(),
            "must not create zip for non-directory source"
        );
    }

    #[cfg(unix)]
    #[test]
    fn export_failure_does_not_clobber_existing_output_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-export-clobber-{}",
            uuid::Uuid::new_v4()
        ));
        let src = root.join("corpus");
        std::fs::create_dir_all(&src).expect("src");
        let unreadable = src.join("secret.bin");
        std::fs::write(&unreadable, b"secret").expect("file");
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
            .expect("chmod");

        let out = root.join("out.zip");
        std::fs::write(&out, b"KEEP").expect("seed output");

        let err = export_zip(&src, &out).expect_err("must fail on unreadable source");
        assert!(err.to_string().contains("Permission denied"));
        assert_eq!(std::fs::read(&out).expect("out read"), b"KEEP");

        // cleanup for tempdir removal
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600))
            .expect("restore chmod");
    }
}
