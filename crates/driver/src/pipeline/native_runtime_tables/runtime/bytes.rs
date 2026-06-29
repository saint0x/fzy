use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "bytes.len",
        symbol: "fz_native_bytes_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "bytes.slice",
        symbol: "fz_native_bytes_slice",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "bytes.at",
        symbol: "fz_native_bytes_at",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "bytes.read_u16_le",
        symbol: "fz_native_bytes_read_u16_le",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "bytes.read_u32_le",
        symbol: "fz_native_bytes_read_u32_le",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "bytes.read_u64_le",
        symbol: "fz_native_bytes_read_u64_le",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "bytes.read_f32_le",
        symbol: "fz_native_bytes_read_f32_le",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "bytes.read_f16_le",
        symbol: "fz_native_bytes_read_f16_le",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "bytes.as_str",
        symbol: "fz_native_bytes_as_str",
        arity: 1,
    },
];
