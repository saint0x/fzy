use super::*;

#[path = "runtime/core.rs"]
mod core;
#[path = "runtime/fs.rs"]
mod fs;
#[path = "runtime/gpu.rs"]
mod gpu;
#[path = "runtime/http.rs"]
mod http;
#[path = "runtime/json.rs"]
mod json;
#[path = "runtime/log.rs"]
mod log;
#[path = "runtime/misc.rs"]
mod misc;
#[path = "runtime/proc.rs"]
mod proc;
#[path = "runtime/task.rs"]
mod task;

pub(crate) fn native_runtime_imports() -> impl Iterator<Item = &'static NativeRuntimeImport> {
    [
        core::IMPORTS,
        http::IMPORTS,
        gpu::IMPORTS,
        json::IMPORTS,
        fs::IMPORTS,
        log::IMPORTS,
        task::IMPORTS,
        proc::IMPORTS,
        misc::IMPORTS,
    ]
    .into_iter()
    .flatten()
}
