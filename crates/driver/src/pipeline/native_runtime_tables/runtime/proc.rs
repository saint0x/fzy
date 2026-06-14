use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "proc.argv_count",
        symbol: "fz_native_proc_argv_count",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.argv_get",
        symbol: "fz_native_proc_argv_get",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.run",
        symbol: "fz_native_proc_run",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.runl",
        symbol: "fz_native_proc_runl",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.argv_new",
        symbol: "fz_native_proc_argv_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.argv_push",
        symbol: "fz_native_proc_argv_push",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.env_new",
        symbol: "fz_native_proc_env_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.env_set",
        symbol: "fz_native_proc_env_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "proc.spawn_cmd",
        symbol: "fz_native_proc_spawn_cmd",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.run_cmd",
        symbol: "fz_native_proc_run_cmd",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.spawnl",
        symbol: "fz_native_proc_spawnl",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "proc.spawn",
        symbol: "fz_native_proc_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exec_timeout",
        symbol: "fz_native_proc_exec_timeout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.close",
        symbol: "fz_native_proc_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exit_class",
        symbol: "fz_native_proc_exit_class",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "proc.wait",
        symbol: "fz_native_proc_wait",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.poll",
        symbol: "fz_native_proc_poll",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.event",
        symbol: "fz_native_proc_event",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.read_stdout",
        symbol: "fz_native_proc_read_stdout",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.read_stderr",
        symbol: "fz_native_proc_read_stderr",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "proc.stdout",
        symbol: "fz_native_proc_stdout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.stderr",
        symbol: "fz_native_proc_stderr",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "proc.exit_code",
        symbol: "fz_native_proc_exit_code",
        arity: 1,
    },
];
