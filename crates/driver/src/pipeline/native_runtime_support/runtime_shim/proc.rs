#[path = "proc/env.rs"]
mod env;
#[path = "proc/host.rs"]
mod host;
#[path = "proc/run.rs"]
mod run;
#[path = "proc/spawn.rs"]
mod spawn;
#[path = "proc/task.rs"]
mod task;

pub(super) fn runtime_shim_section_proc() -> String {
    let mut out = String::new();
    out.push_str(self::env::section());
    out.push_str(self::spawn::section());
    out.push_str(self::run::section());
    out.push_str(self::task::section());
    out.push_str(self::host::section());
    out
}
