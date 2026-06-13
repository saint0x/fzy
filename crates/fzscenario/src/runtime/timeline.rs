//! Timeline artifact generation from trace events.

use serde::Serialize;
use serde::ser::Serializer as _;

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use crate::{FozzyResult, TraceEvent};

#[derive(Serialize)]
struct TimelineEntryRef<'a> {
    index: usize,
    time_ms: u64,
    name: &'a str,
    fields: &'a serde_json::Map<String, serde_json::Value>,
}

pub fn write_timeline(events: &[TraceEvent], out_path: &Path) -> FozzyResult<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(out_path)?;
    let mut writer = BufWriter::new(file);
    let mut ser = serde_json::Serializer::new(&mut writer);
    use serde::ser::SerializeSeq as _;
    let mut seq = ser.serialize_seq(Some(events.len()))?;
    for (idx, e) in events.iter().enumerate() {
        seq.serialize_element(&TimelineEntryRef {
            index: idx,
            time_ms: e.time_ms,
            name: &e.name,
            fields: &e.fields,
        })?;
    }
    seq.end()?;
    Ok(())
}
