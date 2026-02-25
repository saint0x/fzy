# C Interop Production Guide (v1)

## Scope
This guide covers production C interoperability for Fozzy in both directions:
- C host calling Fozzy exports.
- Fozzy code importing C linker symbols.

## Contract
- `#[ffi_panic(abort)]` or `#[ffi_panic(error)]` is required on every exported `pub extern "C" fn`.
- Mixed panic modes across exports are rejected.
- Missing panic contract rejects header/ABI generation.

## Exporting Fozzy to C
1. Declare C exports in `.fzy`:

```fzy
#[ffi_panic(abort)]
pub extern "C" fn add(left: i32, right: i32) -> i32 {
    return left + right
}
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

## Importing C into Fozzy
Declare linker imports with extern declarations:

```fzy
extern "C" fn c_mul(left: i32, right: i32) -> i32;

#[ffi_panic(abort)]
pub extern "C" fn call_mul(left: i32, right: i32) -> i32 {
    return c_mul(left, right)
}
```

Extern declaration imports are lowered as real linker imports (no generated stub definitions).

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
