//! Timeline artifact generation from trace events.

use serde::ser::Serializer as _;
use serde::{Deserialize, Serialize};

use std::path::Path;

use crate::{FozzyResult, TraceEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub index: usize,
    pub time_ms: u64,
    pub name: String,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

pub fn write_timeline(events: &[TraceEvent], out_path: &Path) -> FozzyResult<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut buf = Vec::with_capacity(events.len().saturating_mul(64));
    {
        let mut ser = serde_json::Serializer::new(&mut buf);
        use serde::ser::SerializeSeq as _;
        let mut seq = ser.serialize_seq(Some(events.len()))?;
        for (idx, e) in events.iter().enumerate() {
            seq.serialize_element(&TimelineEntry {
                index: idx,
                time_ms: e.time_ms,
                name: e.name.clone(),
                fields: e.fields.clone(),
            })?;
        }
        seq.end()?;
    }
    std::fs::write(out_path, buf)?;
    Ok(())
}
