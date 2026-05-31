# GPU.md

# FZY GPU Remaining Roadmap

This document tracks only the GPU work that is still open for production.

The following foundation is already landed on the `gpu` branch and should not be treated as roadmap work anymore:

- `core.gpu` exists as a stdlib module
- `host fn`, `pure fn`, `device fn`, and `kernel fn` are parsed and typechecked
- execution-space call rules are enforced
- `gpu` is a first-class capability
- `GpuDevice`, `GpuBuffer<T>`, `GpuSlice<T>`, and `GpuEvent` are modeled in HIR
- host/device intrinsic split is enforced
- typed GPU alloc/upload/download/free/slice/wait wrappers exist in `core.gpu`
- host launch wrappers `launch0` through `launch4` exist
- kernel indexed slice reads and writes typecheck
- linear ownership checks cover `GpuBuffer<T>` and `GpuEvent`
- dedicated `kernel_ir` lowering exists for the current GPU-safe subset
- host GPU lifecycle events are emitted into native/non-scenario trace artifacts
- deterministic Fozzy coverage exists for execution-space safety, typed handles, launch events, and kernel slice assignment
- the `metal` adapter now has a live native host runtime path on Apple for device enumeration, device info, GPU buffer allocation/free, host uploads/downloads, downloaded `Vec<T>` readback indexing, and host-side `GpuSlice` construction
- backend-neutral GPU kernel package artifacts are now emitted into `.fz/gpu-kernel-package.json` and `.fz/gpu-kernel-package.md`

## 1. Immediate Production Goal

Ship a real end-to-end GPU path:

- compile that IR through a first real backend
- execute launches against a real runtime contract
- emit trace-visible GPU lifecycle events
- keep verifier guarantees intact across host/device boundaries

## 1.1 Backend Architecture Contract

GPU support must ship behind one stable architecture from day one:

- one shared GPU contract for verifier, stdlib, launch metadata, tracing, and diagnostics
- one backend-neutral kernel package / launch packet boundary
- one modular backend family with explicit adapters for:
  - `metal`
  - `spirv`
  - `nvptx`
- one shared conformance surface so the same scenarios can validate every backend

This is not a license to simulate missing backends. Production rules are:

- no fake GPU execution path
- no host-side “pretend backend” that claims kernel execution without a real device/runtime path
- only mark a backend executable when its real runtime contract, launch path, and diagnostics are live
- shared architecture may land before all backend implementations are complete, but incomplete backends must fail clearly and truthfully

## 1.2 Phase Ordering

Phase 1 should still start with `metal` as the first live backend because it is the fastest real execution path from the current macOS environment.

That does not change the architecture target:

- `metal`, `spirv`, and `nvptx` must all exist as first-class backend modules/interfaces from the start
- shared verifier and ABI decisions must remain backend-neutral
- `metal` must not leak backend-specific assumptions into the core GPU model
- `spirv` and `nvptx` should use the same kernel package and launch packet contract when their live implementations land

## 2. Remaining Compiler Work

### 2.1 Verifier Hardening

The current verifier covers execution spaces, linear handles, and basic device-safe restrictions. The remaining production checks are:

- prove host buffer/view lifetime rules more precisely
- reject freeing a buffer while derived views are still live
- add alias rules for kernel parameters
- add `readonly` / `writeonly` parameter annotations
- reject unsafe mutable alias patterns at launch boundaries
- validate barrier placement in obviously divergent control flow
- broaden device-safe aggregate support for structs, arrays, tuples, and enums
- validate kernel parameter ABI shapes for backend lowering

### 2.2 Launch Surface Completion

The current launch path is intentionally minimal. Production still needs:

- a canonical launch API instead of only arity-specific wrappers
- kernel symbol representation (`GpuKernel` / compiled module shape)
- stream/module abstractions only if they are truly needed by the backend
- launch configuration validation
  - grid and block dimensions
  - argument ABI layout
  - backend-specific launch limits
- a clean split between compile-time kernel identity and runtime launch packets

The compile-time side is now partially in place:

- a backend-neutral kernel package artifact is emitted from current `kernel_ir` lowering
- launch packet execution is still pending; the package is not yet consumed by live `metal` submission

## 3. Remaining Runtime Work

### 3.1 Real Backend Runtime Contract

Replace the current intrinsic-only surface with a backend-facing runtime contract that can:

- upload and download typed buffers
- launch kernels
- wait on events
- surface runtime failures with stable diagnostics

The runtime contract should be split into:

- shared opaque handles for device, buffer, slice/view, module/kernel, and event state
- shared launch packet ABI and kernel identity metadata
- backend-specific driver shims/adapters for `metal`, `spirv`, and `nvptx`
- explicit capability/limit reporting so backend-specific launch constraints become verifier/runtime diagnostics instead of hidden behavior

Current status of that contract:

- `metal` host/runtime data path is live on Apple for device enumeration, device info, GPU buffer allocation/free, host uploads/downloads, downloaded `Vec<T>` readback indexing, and host-side slice/view construction
- `metal` kernel launch and event completion are still pending
- `spirv` and `nvptx` remain declared adapter families with truthful non-executable diagnostics until their real codegen/runtime paths land

### 3.2 Trace Integration Hardening

GPU lifecycle events are now emitted in native/non-scenario trace artifacts. Remaining trace work is to harden that into full replay-grade coverage:

- add `gpu.error` event emission
- bind trace evidence to real backend execution instead of only the current host-side lifecycle surface
- verify launch order, kernel identity, dimensions, and resource lifecycle during replay
- ensure failure classes stay stable across backends

### 3.3 Async Integration

The blocking `gpu.wait` path and async `gpu.wait_async` path now exist. Remaining async/runtime work:

- cancellation policy for pending launches/events
- deadline/trace integration for GPU-backed async workflows

## 4. Backend Plan

### 4.1 First Backend

Ship all three backends in the architecture from day one, while making one backend live first.

Immediate implementation order:

- `metal` first live backend
- `spirv` adapter/module scaffolded against the same shared contract
- `nvptx` adapter/module scaffolded against the same shared contract

The first live backend must support:

- scalar arithmetic kernels
- typed buffer arguments
- bounds-checked indexing
- launch from host
- deterministic failure diagnostics

The day-one architecture work must also define:

- backend selection/configuration surface
- backend-neutral kernel package format
- backend-neutral launch packet ABI
- per-backend codegen entrypoints
- per-backend runtime shim entrypoints
- clear “backend declared but not yet executable” diagnostics for incomplete adapters

### 4.1.1 Shared/Custom Split

Maximize reusable code, then isolate vendor-specific code cleanly.

Shared code should own:

- verifier rules
- handle and ABI modeling
- kernel package generation
- launch packet construction
- trace schema and replay validation
- conformance scenarios
- backend selection and diagnostics policy

Backend-specific code should own only:

- shader/module emission details
- vendor runtime/device interop
- memory object creation and teardown
- command submission and synchronization
- backend-specific capability limits/errors

Fzy itself is acceptable for orchestration and adapter tooling when it improves maintainability, but platform/runtime seams may still require C / ObjC / vendor-native shims where that is the most stable production boundary.

### 4.2 Backend Conformance

Before calling GPU support production-ready, verify:

- kernel parameter lowering is stable
- generated backend IR is reproducible enough for tests
- unsupported operations fail clearly
- backend-specific ABI mismatches produce actionable verifier errors

Conformance must be reported both per backend and across backends:

- shared scenario results should prove consistent language/runtime semantics
- backend-specific failures must be attributable to capability gaps or unsupported features, not silent divergence
- adding `spirv` and `nvptx` later must extend the same conformance matrix rather than creating parallel ad hoc tests

## 5. Immediate Architecture Tasks

The next production chunks should explicitly burn down the shared architecture before backend proliferation creates drift:

- introduce a backend-neutral launch packet and kernel identity model
- add backend selection/configuration plumbing for `metal`, `spirv`, and `nvptx`
- split shared GPU verifier/runtime metadata from backend-specific codegen/runtime code
- scaffold backend adapter modules for all three backends
- land the first live `metal` runtime/codegen path with real device execution
- add truthful “not yet executable” diagnostics for incomplete `spirv` / `nvptx` adapters
- extend trace artifacts so backend identity and real runtime evidence are recorded
- add backend-conformance scenario structure so all three adapters grow under one test matrix
- extend the live `metal` path from host transfers/slices into kernel package consumption, launch packet execution, launch submission, and event completion

## 6. Fozzy Expansion

Current Fozzy coverage is good for the frontend/verifier foundation. Remaining scenario work:

- valid kernel launch-and-copy scenarios against the real backend path
- invalid aliasing scenarios
- invalid barrier/control-flow scenarios
- backend rejection scenarios for unsupported kernel shapes
- trace/replay scenarios that assert GPU event emission and lifecycle behavior
- host-backed and deterministic mode coverage for every new runtime feature

Every completed chunk should add at least:

- deterministic `doctor`
- strict deterministic `test`
- one recorded trace
- `trace verify`
- `replay`
- `ci`

## 7. Performance and Safety Gates

Production is not complete when code merely compiles.

Still required:

- baseline kernels such as vector add, saxpy, relu, and image brightness
- verifier-preserved noalias opportunities where proven safe
- checks for accidental scalarization or unsupported fallback behavior
- explicit unsafe escape hatches for vendor intrinsics only after the safe path works
- stable diagnostics for:
  - host calls from device code
  - unsupported device types
  - aliasing violations
  - barrier misuse
  - backend lowering failures

## 8. Done Means Removed

This file should keep shrinking.

When a GPU chunk is fully shipped and validated:

- remove it from this document
- do not leave completed items as stale roadmap text
- keep only unresolved production work here
