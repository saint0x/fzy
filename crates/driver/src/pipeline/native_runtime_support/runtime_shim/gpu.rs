#[path = "gpu/buf.rs"]
mod buf;
#[path = "gpu/defs.rs"]
mod defs;
#[path = "gpu/launch.rs"]
mod launch;

use super::super::super::gpu_backend::GpuBackendKind;

pub(super) fn runtime_shim_section_gpu(backend: Option<GpuBackendKind>) -> String {
    let mut out = String::new();
    match backend {
        Some(GpuBackendKind::Cuda) => out.push_str("#define FZ_GPU_BACKEND_CUDA 1\n"),
        Some(GpuBackendKind::Nvptx) => {
            out.push_str("#define FZ_GPU_BACKEND_CUDA 1\n");
            out.push_str("#define FZ_GPU_BACKEND_NVPTX 1\n");
        }
        Some(GpuBackendKind::Rocm) => out.push_str("#define FZ_GPU_BACKEND_ROCM 1\n"),
        Some(GpuBackendKind::Metal) => out.push_str("#define FZ_GPU_BACKEND_METAL 1\n"),
        _ => {}
    }
    out.push_str(self::defs::section());
    out.push_str(self::buf::section());
    out.push_str(self::launch::section());
    out
}
