# Unsafe Islands Authoring v1

## Fzy Unsafe Surface

Unsafe is first-class:

```fzy
unsafe fn copy_into(ptr: *u8, len: usize) -> i32 {
    // Compiler generates reason/invariant/owner/scope/risk_class/proof_ref for this unsafe site.
    unsafe {
        return 0
    }
}
```

Use:
- `unsafe fn` for unsafe function boundaries.
- `unsafe { ... }` for local unsafe islands.
- Compiler-generated contract fields in unsafe docs:
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
- Generated contracts are enforced by profile policy from `fozzy.toml`.

Strict CI/release mode:
- `enforce_verify = true` / `enforce_release = true` in `[unsafe]`
- Fails on missing/invalid generated contracts.
- Fails on unsafe-context violations (unsafe calls outside unsafe context).
- Optional hardened scope controls in `[unsafe]`:
  - `deny_unsafe_in = ["tests::*"]` denies unsafe sites in matching modules.
  - `allow_unsafe_in = ["runtime::*"]` allows unsafe sites only in matching modules.

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
