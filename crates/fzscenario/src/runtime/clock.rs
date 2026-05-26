//! Virtual clock for deterministic time control.

use serde::{Deserialize, Serialize};

use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VirtualClock {
    now_ms: u64,
    frozen: bool,
}

impl VirtualClock {
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    pub fn freeze(&mut self, at_ms: Option<u64>) {
        if let Some(ms) = at_ms {
            self.now_ms = ms;
        }
        self.frozen = true;
    }

    pub fn unfreeze(&mut self) {
        self.frozen = false;
    }

    pub fn sleep(&mut self, d: Duration) {
        self.advance(d);
    }

    pub fn advance(&mut self, d: Duration) {
        let ms = d.as_millis().min(u128::from(u64::MAX)) as u64;
        self.now_ms = self.now_ms.saturating_add(ms);
    }
}

pub fn wall_time_iso_utc() -> String {
    // This is for metadata (startedAt/finishedAt), not for deterministic execution decisions.
    // We use `SystemTime` here to avoid the `time` crate's implicit local timezone issues.
    let now = SystemTime::now();
    let dt: time::OffsetDateTime = now.into();
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
