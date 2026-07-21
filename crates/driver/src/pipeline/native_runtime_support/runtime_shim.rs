#[path = "runtime_shim/build.rs"]
mod build;
#[path = "runtime_shim/core.rs"]
mod core;
#[path = "runtime_shim/gpu.rs"]
mod gpu;
#[path = "runtime_shim/http.rs"]
mod http;
#[path = "runtime_shim/proc.rs"]
mod proc;
#[path = "runtime_shim/render.rs"]
mod render;
#[path = "runtime_shim/services.rs"]
mod services;
#[path = "runtime_shim/term.rs"]
mod term;

pub(crate) use self::build::{
    compile_runtime_shim_object, ensure_native_runtime_shim, native_runtime_gpu_backend,
    native_runtime_shim_uses_objc,
};
#[cfg(test)]
pub(crate) use self::render::render_native_runtime_shim;
