use super::*;

pub(crate) const IMPORTS: &[NativeRuntimeImport] = &[
    NativeRuntimeImport {
        callee: "crypto.random_hex",
        symbol: "fz_native_crypto_random_hex",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.random_base64",
        symbol: "fz_native_crypto_random_base64",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.sha256",
        symbol: "fz_native_crypto_sha256",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.hmac_sha256",
        symbol: "fz_native_crypto_hmac_sha256",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "crypto.constant_time_eq",
        symbol: "fz_native_crypto_constant_time_eq",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "crypto.base64_encode",
        symbol: "fz_native_crypto_base64_encode",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.base64_decode",
        symbol: "fz_native_crypto_base64_decode",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.base64_url_encode",
        symbol: "fz_native_crypto_base64_url_encode",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "crypto.base64_url_decode",
        symbol: "fz_native_crypto_base64_url_decode",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.escape",
        symbol: "fz_native_json_escape",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.str",
        symbol: "fz_native_json_str",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.raw",
        symbol: "fz_native_json_raw",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.from_list",
        symbol: "fz_native_json_from_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.array",
        symbol: "fz_native_json_from_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.from_map",
        symbol: "fz_native_json_from_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.object",
        symbol: "fz_native_json_from_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.to_list",
        symbol: "fz_native_json_to_list",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.to_map",
        symbol: "fz_native_json_to_map",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.keys",
        symbol: "fz_native_json_keys",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.parse",
        symbol: "fz_native_json_parse",
        arity: 1,
    },
    NativeRuntimeImport {
        callee: "json.get",
        symbol: "fz_native_json_get",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.get_str",
        symbol: "fz_native_json_get_str",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.has",
        symbol: "fz_native_json_has",
        arity: 2,
    },
    NativeRuntimeImport {
        callee: "json.path",
        symbol: "fz_native_json_path",
        arity: 2,
    },
];
