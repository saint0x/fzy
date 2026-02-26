# Unsafe Contract Authoring v1

## Fzy Unsafe Contract

Unsafe contracts are first-class and mandatory:

```fzy
unsafe(
  "reason:ffi boundary write",
  "invariant:owner_live(buf) && ptr_nonnull(buf) && ptr_len_ge(buf,buf_len)",
  "owner:buf",
  "scope:fs_write",
  "risk_class:ffi",
  "proof_ref:trace://ffi-write-2026-02-26"
)
```

Required fields:

- `reason`
- `invariant` (predicate DSL only)
- `owner`
- `scope`
- `risk_class` (`memory|ffi|process|io|concurrency|crypto|other`)
- `proof_ref` (`trace://|test://|rfc://|gate://|run://|ci://`)

Supported invariant predicates:

- `owner_live(x)`
- `ptr_nonnull(p)`
- `ptr_aligned(p,n)`
- `ptr_len_ge(p,n)`
- `no_alias(a,b)`
- `range_within(start,end,bound)`

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
