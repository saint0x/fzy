# C Interop Production Guide (v1)

## Scope
This guide covers production C interoperability for Fozzy in both directions:
- C host calling Fozzy exports.
- Fozzy code importing C linker symbols.

## Contract
- `pubext c fn` is the C-export surface.
- `pubext async c fn` exports use async-handle ABI (`*_async_start/poll/await/drop`).
- `ext c fn` is the C-import surface.
- `fozzy.toml` is the policy source of truth for C panic boundary:
  - `[ffi] panic_boundary = "abort"` or `"error"` is required for projects with C interop symbols.
- `#[ffi_panic(...)]` is per-symbol override only.
- Mixed panic modes across exports are rejected.
- Missing panic contract rejects header/ABI generation.

## Exporting Fozzy to C
1. Declare C exports in `.fzy`:

```fzy
pubext c fn add(left: i32, right: i32) -> i32 {
    return left + right
}
```

Async export:

```fzy
pubext async c fn flush(code: i32) -> i32 {
    checkpoint()
    return code
}
```

```toml
[ffi]
panic_boundary = "abort"
```

2. Build production libraries and headers:

```bash
fz build path/to/module.fzy --lib --release --json
```

3. Outputs include:
- `staticLib`: `.a`
- `sharedLib`: `.so` or `.dylib`
- `header`: installable C header
- `abiManifest`: ABI manifest JSON

For async exports, generated headers expose:
- `typedef uint64_t fz_async_handle_t;`
- `int32_t <name>_async_start(..., fz_async_handle_t* handle_out);`
- `int32_t <name>_async_poll(fz_async_handle_t handle, int32_t* done_out);`
- `int32_t <name>_async_await(fz_async_handle_t handle, int32_t* result_out);`
- `int32_t <name>_async_drop(fz_async_handle_t handle);`

Async export requirements:
- must be defined (no declaration-only `;` exports),
- must return `i32` for `async-handle-v1`.

## Importing C into Fozzy
Declare linker imports with `ext` declarations:

```fzy
ext c fn c_mul(left: i32, right: i32) -> i32;

#[ffi_panic(abort)]
pubext c fn call_mul(left: i32, right: i32) -> i32 {
    return c_mul(left, right)
}
```

`ext c fn` imports are lowered as real linker imports (no generated stub definitions).

## Link Configuration
`fz build` supports explicit linker inputs:

```bash
fz build path/to/module.fzy --lib -L /opt/lib -l ssl -l crypto -framework CoreFoundation
```

Manifest link config is also supported:

```toml
[link]
libs = ["ssl", "crypto"]
search = ["/opt/lib"]
frameworks = ["CoreFoundation"]
```

## C Host Lifecycle + Callback ABI
Generated headers expose lifecycle and callback ABI:
- `int32_t fz_host_init(void);`
- `int32_t fz_host_shutdown(void);`
- `int32_t fz_host_cleanup(void);`
- `int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb);`
- `int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg);`

Callback signature is validated by C type contract (`fz_callback_i32_v0`).

## `repr(C)` Layout Validation
`repr(C)` layout entries are emitted in ABI manifests for validated structs/enums.
- Structs: size/align computed with C-style field alignment.
- Enums: C-style fieldless enums only.
- Unsupported `repr(C)` payload layouts are rejected.

## Production Matrix Gate
Run the canonical ship gate (includes compiler/workspace/FFI + host-backed C interop matrix):

```bash
./scripts/ship_release_gate.sh
```

Standalone matrix probe:

```bash
./scripts/c_ffi_matrix.sh
```
