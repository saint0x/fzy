# Traits + Generics Contract v1

## Scope

This document defines production-enforced trait and generic behavior for v1.

## Traits

- `trait Name { fn method(...) -> ...; }` is supported.
- `impl Trait for Type { fn method(...) -> ... { ... } }` is supported.
- Impl methods are lowered as callable symbols using canonical name `<Type>.<method>`.
- Method call resolution supports canonical type-qualified dispatch (`Type.method(...)`) and receiver-name dispatch when receiver type is known.
- Unsupported method-call forms fail with explicit diagnostics.

### Trait Conformance Rules

- Impl must reference an existing trait.
- Impl must include all required trait methods.
- Impl may not define extra methods that are absent from the trait.
- Method parameter count and parameter types must match trait declarations.
- Method return type must match trait declarations.
- In v1, trait-impl methods must not be generic, async, or unsafe.

### Trait Coherence Rules (v1)

- Impl targets for trait impls must be concrete types.
- Overlapping impl targets for the same trait are rejected.
- Bound resolution with more than one matching impl is rejected as ambiguous.

## Generics

- Function generic parameters are supported (`fn f<T: Bound>(...) -> ...`).
- Generic calls require explicit specialization in production mode (`f<Type>(...)`).
- Nested/composite specialization arguments are parsed as top-level-separated type argument lists.
- Monomorphization uses canonical specialized symbols (`f<T1, T2>` rendering).

## Inference and Specialization Policy (v1)

- Type-argument inference for generic function calls is disabled in production mode.
- Generic calls must use explicit specialization.
- Invalid specialization syntax and specialization arity mismatches are deterministic hard errors.

### Generic Bound Rules

- Every declared generic bound must reference an existing trait.
- Specialization-time bound checks are enforced.
- Missing bound impls are hard errors.
- Ambiguous bound impl matches are hard errors.

## Monomorphization Controls (v1)

- Monomorphized symbols are deduplicated by canonical specialized symbol identity.
- Recursive instantiation depth is bounded with explicit diagnostics.
- Total specialization count is bounded with explicit diagnostics for code-size control.

## Unsupported in v1 (Hard Rejected)

- Generic struct declarations.
- Generic enum declarations.
- Generic trait declarations.
- Generic impl headers (`impl<T> ...`).
- Trait associated constants.
- Trait associated types.
- Trait default method bodies.
- Generic trait methods.

## Backend and Determinism Contract

- Trait/generic semantics are type-checked before native lowering.
- Deterministic mode, LLVM, and Cranelift must agree on observable behavior for trait/generic fixtures used in release gates.
- No backend-specific semantic exceptions are allowed for documented implemented behavior.

## Macro Status (Current)

- In-language attribute surface is constrained to supported attributes such as `#[repr(...)]` and `#[ffi_panic(abort|error)]`.
- Unsupported attributes are rejected with diagnostics.
- Broader macro expansion is out of v1 scope and may be added later under deterministic and auditable compile-time constraints.
