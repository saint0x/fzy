use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "alloc",
        symbol: "fz_native_alloc",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "free",
        symbol: "fz_native_free",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "mem.freeze",
        symbol: "fz_native_mem_freeze",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "mem.unfreeze",
        symbol: "fz_native_mem_unfreeze",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "env.get",
        symbol: "fz_native_env_get",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "term.read_line",
        symbol: "fz_native_term_read_line",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "term.stdin_eof",
        symbol: "fz_native_term_stdin_eof",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "term.write",
        symbol: "fz_native_term_write",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "term.write_err",
        symbol: "fz_native_term_write_err",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "term.stdin_is_tty",
        symbol: "fz_native_term_stdin_is_tty",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "term.stdout_is_tty",
        symbol: "fz_native_term_stdout_is_tty",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "time.now",
        symbol: "fz_native_time_now",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "time.monotonic_ms",
        symbol: "fz_native_time_now",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "time.sleep_ms",
        symbol: "fz_native_time_sleep_ms",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.interval",
        symbol: "fz_native_time_interval",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.tick",
        symbol: "fz_native_time_tick",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.elapsed_ms",
        symbol: "fz_native_time_elapsed_ms",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "time.deadline_after",
        symbol: "fz_native_time_deadline_after",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "close",
        symbol: "fz_native_close",
        arity: 1,
    },
];
