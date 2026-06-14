use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "fs.open",
        symbol: "fz_native_fs_open",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.close",
        symbol: "fz_native_fs_close",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.write",
        symbol: "fz_native_fs_write",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.read",
        symbol: "fz_native_fs_read",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.flush",
        symbol: "fz_native_fs_flush",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.fsync",
        symbol: "fz_native_fs_fsync",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.lock",
        symbol: "fz_native_fs_lock",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.atomic_write",
        symbol: "fz_native_fs_atomic_write",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.read_file",
        symbol: "fz_native_fs_read_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.write_file",
        symbol: "fz_native_fs_write_file",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.mkdir",
        symbol: "fz_native_fs_mkdir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.exists",
        symbol: "fz_native_fs_exists",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.is_file",
        symbol: "fz_native_fs_is_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.is_dir",
        symbol: "fz_native_fs_is_dir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.is_symlink",
        symbol: "fz_native_fs_is_symlink",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.stat_size",
        symbol: "fz_native_fs_stat_size",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.stat_mtime",
        symbol: "fz_native_fs_stat_mtime",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.listdir",
        symbol: "fz_native_fs_listdir",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.remove_file",
        symbol: "fz_native_fs_remove_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.remove",
        symbol: "fz_native_fs_remove",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.temp_file",
        symbol: "fz_native_fs_temp_file",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "fs.copy_file",
        symbol: "fz_native_fs_copy_file",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "fs.copy_tree",
        symbol: "fz_native_fs_copy_tree",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "path.join",
        symbol: "fz_native_path_join",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "path.basename",
        symbol: "fz_native_path_basename",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.dirname",
        symbol: "fz_native_path_dirname",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.stem",
        symbol: "fz_native_path_stem",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.extension",
        symbol: "fz_native_path_extension",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "path.normalize",
        symbol: "fz_native_path_normalize",
        arity: 1,
    },
];
