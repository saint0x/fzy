//! Fozzy core library: shared types used by the CLI and future SDK bindings.

#[path = "cmd/artifacts.rs"]
mod artifacts;
#[path = "cmd/ci.rs"]
mod ci;
#[path = "runtime/clock.rs"]
mod clock;
#[path = "platform/config.rs"]
mod config;
#[path = "cmd/corpus.rs"]
mod corpus;
#[path = "model/decisions.rs"]
mod decisions;
#[path = "runtime/doctor.rs"]
mod doctor;
#[path = "platform/duration.rs"]
mod duration;
#[path = "runtime/engine.rs"]
mod engine;
#[path = "platform/envinfo.rs"]
mod envinfo;
#[path = "platform/error.rs"]
mod error;
#[path = "modes/explore.rs"]
mod explore;
#[path = "runtime/finalize.rs"]
mod finalize;
#[path = "platform/fsutil.rs"]
mod fsutil;
#[path = "modes/fuzz.rs"]
mod fuzz;
#[path = "runtime/host.rs"]
mod host;
#[path = "runtime/init_scaffold.rs"]
mod init_scaffold;
#[path = "cmd/map_cmd.rs"]
mod map_cmd;
#[path = "model/memory.rs"]
mod memory;
#[path = "cmd/memory_cmd.rs"]
mod memory_cmd;
#[path = "runtime/memorycap.rs"]
mod memorycap;
#[path = "cmd/profile_cmd.rs"]
mod profile_cmd;
#[path = "model/reporting.rs"]
mod reporting;
#[path = "cmd/reporting_cmd.rs"]
mod reporting_cmd;
#[path = "runtime/run_flow.rs"]
mod run_flow;
#[path = "model/scenario.rs"]
mod scenario;
#[path = "runtime/scheduler.rs"]
mod scheduler;
#[path = "cmd/schema.rs"]
mod schema;
#[path = "runtime/test_runner.rs"]
mod test_runner;
#[path = "runtime/timeline.rs"]
mod timeline;
#[path = "runtime/tracefile.rs"]
mod tracefile;
#[path = "cmd/usage.rs"]
mod usage;

pub(crate) use artifacts::*;
pub(crate) use clock::*;
pub(crate) use decisions::*;
pub(crate) use duration::*;
pub(crate) use engine::*;
pub(crate) use envinfo::*;
pub(crate) use error::*;
pub(crate) use explore::*;
pub(crate) use fsutil::*;
pub(crate) use fuzz::*;
pub(crate) use memory::*;
pub(crate) use memorycap::*;
pub(crate) use profile_cmd::*;
pub(crate) use reporting::*;
pub(crate) use run_flow::*;
pub(crate) use scenario::*;
pub(crate) use timeline::*;
pub(crate) use tracefile::*;

pub use artifacts::{ArtifactCommand, artifacts_command};
pub use ci::{CiOptions, CiReport, ci_command, ci_evaluate};
pub use clock::VirtualClock;
pub use config::Config;
pub use corpus::{CorpusCommand, corpus_command};
pub use decisions::{Decision, DecisionCursor};
pub use doctor::{DoctorOptions, DoctorReport, doctor};
pub use engine::{
    FsBackend, HttpBackend, InitTemplate, InitTestType, ProcBackend, ProfileCaptureLevel,
    RecordCollisionPolicy, ReplayOptions, RunOptions, RunResult, ShrinkMinimize, ShrinkOptions,
};
pub use envinfo::{compatibility_info, env_info, version_info};
pub use explore::{ExploreOptions, ScheduleStrategy, explore};
pub use fsutil::find_matching_files;
pub use fuzz::{FuzzMode, FuzzOptions, FuzzTarget, fuzz};
pub use init_scaffold::{InitProjectOptions, init_project, init_project_with_options};
pub use map_cmd::{MapCommand, ShrinkCoveragePolicy, TopologyProfile, map_command};
pub use memory::MemoryOptions;
pub use memory_cmd::{MemoryCommand, memory_command};
pub use profile_cmd::heap_budget_findings_from_trace;
pub use reporting::ReportOutput;
pub use reporting::{ExitStatus, FindingKind, Reporter, RunSummary};
pub use reporting_cmd::{ReportCommand, report_command};
pub use run_flow::{replay_trace, run_scenario, shrink_trace};
pub use scenario::{Scenario, ScenarioFile, ScenarioPath};
pub use scheduler::{DeterministicScheduler, SchedulerMode};
pub use schema::schema_doc;
pub use test_runner::run_tests;
pub use tracefile::{TracePath, TraceVerifyReport, verify_trace_file};
pub use usage::{UsageDoc, UsageItem, usage_doc};
