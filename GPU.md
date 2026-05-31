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

## 1. Immediate Production Goal

Ship a real end-to-end GPU path:

- compile that IR through a first real backend
- execute launches against a real runtime contract
- emit trace-visible GPU lifecycle events
- keep verifier guarantees intact across host/device boundaries

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

## 3. Remaining Runtime Work

### 3.1 Real Backend Runtime Contract

Replace the current intrinsic-only surface with a backend-facing runtime contract that can:

- enumerate devices
- allocate and free device memory
- upload and download typed buffers
- create device views for launches
- launch kernels
- wait on events
- surface runtime failures with stable diagnostics

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

Pick and ship the first real backend based on implementation speed and developer tooling. The decision should be explicit and final for phase 1.

Current likely options:

- SPIR-V path
- NVPTX / NVVM path

Whichever path is chosen must support:

- scalar arithmetic kernels
- typed buffer arguments
- bounds-checked indexing
- launch from host
- deterministic failure diagnostics

### 4.2 Backend Conformance

Before calling GPU support production-ready, verify:

- kernel parameter lowering is stable
- generated backend IR is reproducible enough for tests
- unsupported operations fail clearly
- backend-specific ABI mismatches produce actionable verifier errors

## 5. Fozzy Expansion

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

## 6. Performance and Safety Gates

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

## 7. Done Means Removed

This file should keep shrinking.

When a GPU chunk is fully shipped and validated:

- remove it from this document
- do not leave completed items as stale roadmap text
- keep only unresolved production work here
