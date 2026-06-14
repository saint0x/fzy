use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "gpu.device_count",
        symbol: "fz_native_gpu_device_count",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "gpu.default_device",
        symbol: "fz_native_gpu_default_device",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "gpu.device_name",
        symbol: "fz_native_gpu_device_name",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.device_memory_bytes",
        symbol: "fz_native_gpu_device_memory_bytes",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.alloc_f32",
        symbol: "fz_native_gpu_alloc_f32",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "gpu.alloc_i32",
        symbol: "fz_native_gpu_alloc_i32",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "gpu.alloc_u32",
        symbol: "fz_native_gpu_alloc_u32",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "gpu.upload_f32",
        symbol: "fz_native_gpu_upload_f32",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.upload_i32",
        symbol: "fz_native_gpu_upload_i32",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.upload_u32",
        symbol: "fz_native_gpu_upload_u32",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.download_f32",
        symbol: "fz_native_gpu_download_f32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.download_i32",
        symbol: "fz_native_gpu_download_i32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.download_u32",
        symbol: "fz_native_gpu_download_u32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.free",
        symbol: "fz_native_gpu_buffer_free",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.slice",
        symbol: "fz_native_gpu_slice",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "gpu.launch0",
        symbol: "fz_native_gpu_launch0",
        arity: 5,
    },
    NativeRuntimeImport {
        callee: "gpu.launch1",
        symbol: "fz_native_gpu_launch1",
        arity: 6,
    },
    NativeRuntimeImport {
        callee: "gpu.launch2",
        symbol: "fz_native_gpu_launch2",
        arity: 7,
    },
    NativeRuntimeImport {
        callee: "gpu.launch3",
        symbol: "fz_native_gpu_launch3",
        arity: 8,
    },
    NativeRuntimeImport {
        callee: "gpu.launch4",
        symbol: "fz_native_gpu_launch4",
        arity: 9,
    },
    NativeRuntimeImport {
        callee: "gpu.wait",
        symbol: "fz_native_gpu_wait",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "gpu.wait_async",
        symbol: "fz_native_gpu_wait_async",
        arity: 1,
    },
];
