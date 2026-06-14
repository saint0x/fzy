use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "log.info",
        symbol: "fz_native_log_info",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.warn",
        symbol: "fz_native_log_warn",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.error",
        symbol: "fz_native_log_error",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "log.fields",
        symbol: "fz_native_log_fields_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_json",
        symbol: "fz_native_log_set_json",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_enabled",
        symbol: "fz_native_log_set_enabled",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_level",
        symbol: "fz_native_log_set_level",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.set_sink",
        symbol: "fz_native_log_set_sink",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "log.correlation_id",
        symbol: "fz_native_log_correlation_id",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "error.code",
        symbol: "fz_native_error_code",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.class",
        symbol: "fz_native_error_class",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.message",
        symbol: "fz_native_error_message",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "error.context",
        symbol: "fz_native_error_context",
        arity: 1,
    },
];
