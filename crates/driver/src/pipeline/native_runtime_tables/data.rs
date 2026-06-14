use super::*;

pub(crate) const NATIVE_DATA_PLANE_IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "str.concat",
        symbol: "fz_native_str_concat2",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.concat2",
        symbol: "fz_native_str_concat2",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.concat3",
        symbol: "fz_native_str_concat3",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.concat4",
        symbol: "fz_native_str_concat4",
        arity: 4,
    },
    NativeRuntimeImport {
        callee: "str.from_i32",
        symbol: "fz_native_str_from_i32",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.from_bool",
        symbol: "fz_native_str_from_bool",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.repeat",
        symbol: "fz_native_str_repeat",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.contains",
        symbol: "fz_native_str_contains",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.starts_with",
        symbol: "fz_native_str_starts_with",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.ends_with",
        symbol: "fz_native_str_ends_with",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.replace",
        symbol: "fz_native_str_replace",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.trim",
        symbol: "fz_native_str_trim",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.split",
        symbol: "fz_native_str_split",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "str.len",
        symbol: "fz_native_str_len",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.visible_len_ansi",
        symbol: "fz_native_str_visible_len_ansi",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.slice",
        symbol: "fz_native_str_slice",
        arity: 3,
    },
    NativeRuntimeImport {
        callee: "str.upper_ascii",
        symbol: "fz_native_str_upper_ascii",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "str.lower_ascii",
        symbol: "fz_native_str_lower_ascii",
        arity: 1,
    },
];

pub(crate) fn native_runtime_import_for_callee(
    callee: &str,
) -> Option<&'static NativeRuntimeImport> {
    native_runtime_imports().find(|import| import.callee == callee)
}

pub(crate) fn native_data_plane_import_for_callee(
    callee: &str,
) -> Option<&'static NativeRuntimeImport> {
    NATIVE_DATA_PLANE_IMPORTS
        .iter()
        .find(|import| import.callee == callee)
}
