use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "spawn",
        symbol: "fz_native_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "thread.spawn",
        symbol: "fz_native_spawn",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "spawn_ctx",
        symbol: "fz_native_spawn_ctx",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "thread.spawn_ctx",
        symbol: "fz_native_spawn_ctx",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "join",
        symbol: "fz_native_join",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "detach",
        symbol: "fz_native_detach",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "cancel_task",
        symbol: "fz_native_cancel_task",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task_result",
        symbol: "fz_native_task_result",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.context_id",
        symbol: "fz_native_task_context_id",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "task.group_begin",
        symbol: "fz_native_task_group_begin",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "task.group_spawn",
        symbol: "fz_native_task_group_spawn",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "task.group_spawn_n",
        symbol: "fz_native_task_group_spawn_n",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "task.group_join",
        symbol: "fz_native_task_group_join",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.group_join_all",
        symbol: "fz_native_task_group_join_all",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.group_cancel",
        symbol: "fz_native_task_group_cancel",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "task.parallel_map",
        symbol: "fz_native_task_parallel_map",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "timeout",
        symbol: "fz_native_timeout",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "deadline",
        symbol: "fz_native_deadline",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "cancel",
        symbol: "fz_native_cancel",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "recv",
        symbol: "fz_native_recv",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "yield",
        symbol: "fz_native_yield",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "checkpoint",
        symbol: "fz_native_checkpoint",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "pulse",
        symbol: "fz_native_pulse",
        arity: 0,
    },
];
