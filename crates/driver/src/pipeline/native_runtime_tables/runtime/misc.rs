use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "assert.eq_i32",
        symbol: "fz_native_assert_eq_i32",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "list.new",
        symbol: "fz_native_list_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "list.push",
        symbol: "fz_native_list_push",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "list.pop",
        symbol: "fz_native_list_pop",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.len",
        symbol: "fz_native_list_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.get",
        symbol: "fz_native_list_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "list.set",
        symbol: "fz_native_list_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "list.clear",
        symbol: "fz_native_list_clear",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "list.join",
        symbol: "fz_native_list_join",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.new",
        symbol: "fz_native_map_new",
        arity: 0,
    },
    NativeRuntimeImport {
        callee: "map.set",
        symbol: "fz_native_map_set",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "map.get",
        symbol: "fz_native_map_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.has",
        symbol: "fz_native_map_has",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.delete",
        symbol: "fz_native_map_delete",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "map.keys",
        symbol: "fz_native_map_keys",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "map.len",
        symbol: "fz_native_map_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "storage.append",
        symbol: "fz_native_storage_append",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "storage.atomic_append",
        symbol: "fz_native_storage_atomic_append",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "storage.kv_open",
        symbol: "fz_native_storage_kv_open",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "storage.kv_close",
        symbol: "fz_native_storage_kv_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "storage.kv_get",
        symbol: "fz_native_storage_kv_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "storage.kv_put",
        symbol: "fz_native_storage_kv_put",
        arity: 3,
    },
];
