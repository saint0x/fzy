# Control-Flow Lowering Contract

## Scope
- Applies to all native codegen backends (`llvm`, `cranelift`).
- Defines one shared, backend-neutral CFG as the control-flow source of truth.

## Shared CFG Model
- A function lowers to `ControlFlowCfg` with:
- explicit blocks (`entry` + indexed blocks)
- linear statements per block (non-control statements only)
- exactly one explicit terminator per block
- loop metadata for `break`/`continue` target validation

## Canonical Terminators
- `return <expr?>`
- `jump <target>` with edge kind (`normal`, `loop_back`, `break`, `continue`)
- `branch <cond> <then> <else>`
- `unreachable`

There is no implicit fallthrough. If lowering reaches end-of-function, lowering emits an explicit `return`.

## Verifier Invariants (Release-Blocking)
- every block has exactly one terminator
- branch/jump targets are in-range
- all declared blocks are reachable from entry
- `break`/`continue` edges reference known loop ids and exact loop targets

CFG verification runs before backend emission. Any violation is a hard compile failure.

## Backend Responsibilities
- Backends consume the shared verified CFG and only differ in instruction selection/encoding.
- Backends must not introduce independent statement-level control-flow semantics.
- LLVM and Cranelift both emit from CFG blocks + terminators.

## Regression Gates
- cross-backend execute-and-compare tests for primitive control-flow fixture
- cross-backend execute-and-compare tests for non-`i32`/aggregate signatures
- non-entry infinite loop regression fixture (`fn spin() -> i32 { loop { ... } }`)
