# Unsafe Islands Authoring v1

## Fzy Unsafe Surface

Unsafe is first-class:

```fzy
unsafe fn copy_into(ptr: *u8, len: usize) -> i32 {
    unsafe("reason:ffi boundary write", "invariant:owner_live(ptr) && ptr_nonnull(ptr) && ptr_len_ge(ptr,len)", "owner:ptr", "scope:copy_into", "risk_class:ffi", "proof_ref:trace://copy-into-2026-02-26") {
        return 0
    }
}
```

Use:
- `unsafe fn` for unsafe function boundaries.
- `unsafe { ... }` for local unsafe islands.
- Optional metadata on unsafe blocks:
  - `reason`
  - `invariant`
  - `owner`
  - `scope`
  - `risk_class` (`memory|ffi|process|io|concurrency|crypto|other`)
  - `proof_ref` (`trace://|test://|rfc://|gate://|run://|ci://`)

Removed:
- `unsafe_reason(...)`
- executable `unsafe(...)` expression form without block

## Unsafe FFI Imports

Prefer unsafe imports when contract is not statically safe:

```fzy
ext unsafe c fn c_write(ptr: *u8, len: usize) -> i32;

fn write(ptr: *u8, len: usize) -> i32 {
    unsafe {
        return c_write(ptr, len)
    }
}
```

`ext c fn` remains available for safe contracts only.

## Audit + Docs Artifacts

`fz audit unsafe --workspace` emits:
- `.fz/unsafe-map.workspace.json`
- `.fz/unsafe-docs.workspace.json`
- `.fz/unsafe-docs.workspace.md`
- `.fz/unsafe-docs.workspace.html`

Default policy:
- Metadata is non-blocking.

Strict CI/release mode:
- `FZ_UNSAFE_STRICT=1`
- Fails on missing/invalid metadata.
- Fails on unsafe-context violations (unsafe calls outside unsafe context).

## Rust Unsafe Boundary Rules

Rust `unsafe` is restricted to approved unsafe-island files declared in
`policy/rust_unsafe_islands.json`.

Every `unsafe` site must include nearby `Safety:`/`SAFETY:` rationale comments.

Current gate:

```bash
python3 scripts/rust_unsafe_inventory.py --root . --out artifacts/rust_unsafe_inventory.json --budget 2 --policy policy/rust_unsafe_islands.json
```

## FFI Contract Rules

- Pointer params must use ownership suffix: `_owned`, `_borrowed`, `_out`, `_inout`.
- Pointer params must provide paired length (`<base>_len` or `len`) unless context pointer (`*_ctx|*_context`).
- Callback params require context params (`*_ctx|*_context`).
- ABI manifests are `fozzylang.ffi_abi.v1` and include structured contract metadata.
