# C Interop Cookbook v1

## 1) Import a third-party C symbol

```fzy
ext unsafe c fn c_mul(left: i32, right: i32) -> i32;

fn mul(left: i32, right: i32) -> i32 {
    unsafe {
        return c_mul(left, right)
    }
}
```

## 2) Export a stable C ABI function

```fzy
#[ffi_panic(abort)]
pubext c fn add(left: i32, right: i32) -> i32 {
    return left + right
}
```

## 3) Callback/context lifecycle contract

```fzy
ext unsafe c fn register_callback(
    cb_callback: *u8,
    cb_ctx: *u8,
) -> i32;
```

Use ownership suffixes for pointer params:

- `_owned`
- `_borrowed`
- `_out`
- `_inout`

## 4) Build + header + ABI gate

```bash
fz build path/to/module.fzy --lib --release --json
fz headers path/to/module.fzy --out include/module.h --json
fz abi-check include/module.abi.json --baseline baseline/module.abi.json --json
```
