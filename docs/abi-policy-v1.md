# ABI Policy v1

## Stability Contract

- ABI manifests use schema `fozzylang.ffi_abi.v0`.
- Exported symbols are derived from `pub extern "C" fn` declarations only.
- ABI compatibility in v1 is defined by normalized export signatures:
  - function name
  - ordered C parameter types
  - C return type
- Additive exports are allowed.
- Existing export signatures are immutable across compatible revisions.

## Stable Layout Rules

- `repr(C)` types are the only supported stable layout contract for cross-language boundaries.
- Non-`repr(C)` layout must be treated as unstable/internal.
- FFI-unstable types (slices/`str`/error-union-like signatures) are rejected at header generation boundaries.

## Panic Boundary Policy

- Panics must not cross the C boundary.
- If panic markers exist in exported modules, a panic contract attribute is required:
  - `#[ffi_panic(abort)]` or
  - `#[ffi_panic(error)]`
- `panicBoundary` in ABI manifests is compatibility-checked against baseline.

## Breaking Change Policy

Breaking ABI changes include:

- Removing an export.
- Renaming an export.
- Changing parameter order/type.
- Changing return type.
- Regressing `symbolVersion` for an existing export.
- Changing package identity within a compatibility baseline comparison.

Non-breaking in v1:

- adding a new export with a unique symbol name

Use `fz abi-check <current.abi.json> --baseline <baseline.abi.json>` to gate compatibility.

`fz abi-check` validates:

- schema version correctness
- package identity compatibility
- panic boundary compatibility
- baseline export presence
- baseline export signature immutability
- symbol version non-regression

## Explicitly Unsupported At FFI Boundary (v1)

- Async closures/task handles as ABI payload types.
- Non-FFI-stable generic abstractions without concrete C-compatible lowering.
