//! Decision logging for deterministic replay.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    RandU64 {
        value: u64,
    },
    RandBytes {
        hex: String,
    },
    TimeSleepMs {
        ms: u64,
    },
    TimeAdvanceMs {
        ms: u64,
    },
    FsWrite {
        path: String,
        data_hex: String,
    },
    FsReadAssert {
        path: String,
        data_hex: String,
    },
    FsSnapshot {
        name: String,
        entries: BTreeMap<String, Option<String>>,
    },
    FsRestore {
        name: String,
    },
    HttpRequest {
        method: String,
        path: String,
        status_code: u16,
        #[serde(default)]
        headers: std::collections::BTreeMap<String, String>,
        body: String,
    },
    HttpRequestTimeout {
        method: String,
        path: String,
    },
    ProcSpawn {
        cmd: String,
        args: Vec<String>,
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    ProcSpawnTimeout {
        cmd: String,
        args: Vec<String>,
        stdout: String,
        stderr: String,
    },
    SchedulerPick {
        task_id: u64,
        label: String,
    },
    NetDeliverPick {
        message_id: u64,
    },
    NetDrop {
        message_id: u64,
        dropped: bool,
    },
    MemoryAlloc {
        bytes: u64,
        alloc_id: Option<u64>,
        callsite_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failed_reason: Option<String>,
    },
    MemoryFree {
        alloc_id: u64,
        existed: bool,
    },
    Step {
        index: usize,
        name: String,
    },
    ExploreDeliver {
        msg_id: u64,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecisionLog {
    pub decisions: Vec<Decision>,
}

impl DecisionLog {
    pub fn push(&mut self, decision: Decision) {
        self.decisions.push(decision);
    }
}

#[derive(Debug)]
pub struct DecisionCursor<'a> {
    decisions: &'a [Decision],
    index: usize,
}

impl<'a> DecisionCursor<'a> {
    pub fn new(decisions: &'a [Decision]) -> Self {
        Self {
            decisions,
            index: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        self.decisions.len().saturating_sub(self.index)
    }
}

impl<'a> Iterator for DecisionCursor<'a> {
    type Item = &'a Decision;

    fn next(&mut self) -> Option<Self::Item> {
        let d = self.decisions.get(self.index);
        self.index = self.index.saturating_add(1);
        d
    }
}
