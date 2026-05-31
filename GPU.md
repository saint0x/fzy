# GPU.md

# FZY GPU Roadmap

## 0. Purpose

This document defines the production roadmap for GPU programming in FZY.

The goal is to make GPU programming fit the same language philosophy as the rest of FZY:

- memory-safe by default
- verifier-aware
- high-performance by design
- explicit about host/device boundaries
- unified with CPU/runtime code where it makes sense
- portable-first, vendor-specialized second
- traceable and replay-aware like FZY async/RPC/process systems
- integrated into core.* instead of bolted on as a separate DSL

The intended result is:

> FZY should let users write host CPU orchestration, shared pure compute logic, and GPU kernels in one language, while the compiler enforces execution-space safety, memory ownership, resource cleanup, and backend-specific validity.

This is not “GPU support as a library.”

This is:

> GPU programming as a first-class systems/runtime capability.

## 1. Context

FZY already has several foundational ingredients:

- native backends through LLVM and Cranelift
- typed HIR/FIR/verifier architecture
- runtime import tables for host effects
- explicit capabilities
- ownership and linear-resource tracking
- unsafe contracts
- async/task/RPC/checkpoint runtime model
- core.* standard-library structure
- shipped core.simd portable SIMD subset
- verifier/backend rejection for unsupported ABI shapes
- deterministic scenario/trace testing through Fozzy

GPU should build on these existing systems.

The GPU design should not start from scratch.

It should reuse:

- parser/AST item model
- type system
- function metadata
- native lowerability diagnostics
- verifier policy system
- capability inference
- unsafe metadata
- runtime intrinsic table
- backend selection
- Fozzy scenario artifacts
- existing core.simd principles
- existing corelib/src organization

## 2. Design Thesis

FZY’s GPU system should not be a separate mini-language.

It should be a unified execution-space model:

text pure fn      may compile for host and device host fn      runs on CPU/runtime only device fn    callable from device/kernel code kernel fn    GPU entrypoint launched from host 

The programmer should be able to write:

fzy pure fn square(x: f32) -> f32 {     return x * x }  kernel fn square_kernel(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) {     let i = gpu.global_id_x()     if i < n {         output[i] = square(input[i])     } }  host fn main() -> i32 {     let input_gpu = gpu.upload_f32(input)     defer gpu.free(input_gpu)      let output_gpu = gpu.alloc_f32(1024)     defer gpu.free(output_gpu)      gpu.launch(square_kernel, grid: 4, block: 256, input_gpu, output_gpu, 1024)      let output = gpu.download_f32(output_gpu)     return 0 } 

This is the core idea:

> shared pure logic, explicit host orchestration, explicit GPU entrypoints, compiler-checked boundaries.

## 3. Non-Goals

GPU support should not initially attempt to include:

- arbitrary host code inside kernels
- dynamic strings in kernels
- JSON handles in kernels
- HTTP/process/RPC/log calls inside kernels
- async/await inside kernels
- arbitrary heap allocation inside kernels
- garbage collection
- device-side closures
- full trait object dispatch on device
- vendor-specific intrinsic dump as the primary API
- handwritten GPU assembly as the main backend
- CUDA compatibility syntax
- full PyTorch/XLA-style graph compiler in v1
- automatic GPU offload of arbitrary loops in v1

FZY should not try to become CUDA, Mojo, Triton, Rust-GPU, and MLIR all at once.

The first target is:

> a small, explicit, safe, high-performance GPU kernel model that fits FZY’s systems-language identity.

## 4. Core Module

GPU support should live in:

fzy use core.gpu; 

Add a new standard-library module:

text corelib/src/gpu.fzy 

And update:

text corelib/src/main.fzy 

with:

fzy mod gpu; 

The public surface should be core.gpu, not core.GPU, matching the existing lowercase core.* style.

## 5. Execution Spaces

### 5.1 host fn

A host fn runs on CPU and may use normal FZY runtime capabilities.

Allowed:

- fs
- http
- proc
- rpc
- log
- async
- task groups
- checkpoint
- JSON
- strings
- heap allocation
- GPU allocation/upload/download/launch APIs

Example:

fzy host fn run_gpu_pipeline() -> i32 {     let device = gpu.default_device()     let buffer = gpu.alloc_f32(device, 1024)     defer gpu.free(buffer)      return 0 } 

Plain fn may initially default to host unless marked pure, device, or kernel.

### 5.2 pure fn

A pure fn is side-effect-free compute logic.

It may compile for both host and device if it only uses portable operations.

Allowed:

- scalar math
- boolean logic
- branches
- loops
- fixed arrays
- simple structs
- simple enums
- core.simd portable operations where supported
- calls to other pure fn

Disallowed:

- fs/http/proc/rpc/log
- JSON handles
- strings, except maybe compile-time literals for diagnostics later
- dynamic allocation
- raw pointer deref unless unsafe and device-supported
- async/await
- spawn/task groups
- host-only runtime imports

Example:

fzy pure fn clamp01(x: f32) -> f32 {     if x < 0.0 {         return 0.0     }     if x > 1.0 {         return 1.0     }     return x } 

### 5.3 device fn

A device fn is callable from GPU code.

It may call:

- pure fn
- other device fn
- approved core.gpu device intrinsics
- approved core.simd device-compatible operations

It may not call host functions.

Example:

fzy device fn relu(x: f32) -> f32 {     if x < 0.0 {         return 0.0     }     return x } 

### 5.4 kernel fn

A kernel fn is a GPU entrypoint.

It is launched from host code.

It may call:

- pure fn
- device fn
- approved device intrinsics

It may not return complex values. Initial return type should be void.

Example:

fzy kernel fn relu_kernel(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {     let i = gpu.global_id_x()     if i < n {         output[i] = relu(input[i])     } } 

## 6. Execution-Space Call Rules

The compiler should enforce:

text host fn      can call host fn + pure fn pure fn      can call pure fn only device fn    can call device fn + pure fn kernel fn    can call device fn + pure fn host fn      can launch kernel fn host fn      cannot directly call kernel fn as ordinary function device fn    cannot call host fn kernel fn    cannot call host fn pure fn      cannot call host/device/kernel unless explicitly specialized later 

Invalid:

fzy host fn read_file() -> str {     return fs.read_text("data.txt") }  device fn bad() -> str {     return read_file() } 

Diagnostic:

text device function `bad` calls host-only function `read_file`. Move host effects outside the kernel or pass data through a GPU buffer. 

## 7. Type System Additions

### 7.1 GPU Handle Types

Add opaque linear handle types:

fzy GpuDevice GpuBuffer<T> GpuSlice<T> GpuKernel GpuEvent GpuStream GpuModule GpuLaunch 

Initial public surface can be smaller:

fzy GpuDevice GpuBufferF32 GpuBufferI32 GpuBufferU32 GpuSliceF32 GpuSliceI32 GpuSliceU32 GpuEvent GpuStream 

Generic forms can come after the initial typed aliases.

### 7.2 Device-Safe Types

Supported in phase 1:

text i32 u32 f32 bool void [i32; N] [u32; N] [f32; N] simple structs of device-safe fields GpuSlice<i32> GpuSlice<u32> GpuSlice<f32> 

Later:

text i64 u64 f64 half/f16 bf16 Simd<T, N> simple enums fixed tuples 

### 7.3 Forbidden in Device Code

Initially forbidden:

text str JsonHandle ListHandle MapHandle HttpHandle ProcHandle TaskHandle TaskGroup FileHandle WebSocketHandle RpcFrame Host pointer types closures trait objects dynamic arrays heap-owned host objects 

## 8. Memory Model

GPU memory should use the same FZY principle as the rest of the language:

> owned resources must have a clear terminal state.

### 8.1 Linear GPU Resources

These are linear:

text GpuBuffer<T> GpuStream GpuEvent GpuModule GpuLaunch 

Every GPU resource must be:

text freed closed completed returned transferred or deferred 

Invalid:

fzy host fn leak() -> i32 {     let buf = gpu.alloc_f32(1024)     return 0 } 

Valid:

fzy host fn ok() -> i32 {     let buf = gpu.alloc_f32(1024)     defer gpu.free(buf)     return 0 } 

### 8.2 Host/Device Ownership

A GPU buffer is owned by the host runtime but accessible by device kernels.

The host owns the handle.

The device sees a GpuSlice<T> view.

Rules:

text host owns allocation and cleanup kernel receives bounded slice view device cannot free host-owned buffer device cannot resize buffer device cannot escape slice beyond kernel execution 

### 8.3 Borrowing GPU Buffers

Host-side borrowed views:

fzy let view = gpu.slice(buffer, offset, len) 

The verifier must reject freeing buffer while any view is live.

Device-side views are only valid during kernel execution.

### 8.4 Aliasing Policy

Phase 1 should be conservative.

Kernel parameters default to possibly aliasing unless marked otherwise.

Optional later annotations:

fzy kernel fn saxpy(     #[readonly] x: GpuSlice<f32>,     #[readonly] y: GpuSlice<f32>,     #[writeonly] out: GpuSlice<f32>,     n: i32, ) 

Verifier rules:

text readonly slices may alias writeonly/mutable slices may not alias with other mutable slices noalias metadata may be emitted when verifier proves disjointness 

This matters for performance.

GPU codegen should preserve aliasing facts when safe.

## 9. Core GPU API

Initial core.gpu surface:

### 9.1 Device Discovery

fzy fn device_count() -> i32 fn default_device() -> GpuDevice fn device_name(device: GpuDevice) -> str fn device_memory_bytes(device: GpuDevice) -> i64 

### 9.2 Allocation

Typed phase-1 APIs:

fzy fn alloc_f32(device: GpuDevice, len: i32) -> GpuBufferF32 fn alloc_i32(device: GpuDevice, len: i32) -> GpuBufferI32 fn alloc_u32(device: GpuDevice, len: i32) -> GpuBufferU32  fn free(buffer: GpuBufferF32) -> void fn free(buffer: GpuBufferI32) -> void fn free(buffer: GpuBufferU32) -> void 

Generic later:

fzy fn alloc<T>(device: GpuDevice, len: i32) -> GpuBuffer<T> fn free<T>(buffer: GpuBuffer<T>) -> void 

### 9.3 Upload / Download

Phase 1:

fzy fn upload_f32(device: GpuDevice, values: [f32]) -> GpuBufferF32 fn upload_i32(device: GpuDevice, values: [i32]) -> GpuBufferI32 fn upload_u32(device: GpuDevice, values: [u32]) -> GpuBufferU32  fn download_f32(buffer: GpuBufferF32) -> [f32] fn download_i32(buffer: GpuBufferI32) -> [i32] fn download_u32(buffer: GpuBufferU32) -> [u32] 

Later, avoid dynamic host arrays if not ready; use fixed-array or host slice APIs first.

### 9.4 Slicing

fzy fn slice_f32(buffer: GpuBufferF32, offset: i32, len: i32) -> GpuSliceF32 fn slice_i32(buffer: GpuBufferI32, offset: i32, len: i32) -> GpuSliceI32 fn slice_u32(buffer: GpuBufferU32, offset: i32, len: i32) -> GpuSliceU32 

### 9.5 Launch

Minimal:

fzy fn launch(kernel: GpuKernel, grid: i32, block: i32, args: ...) -> GpuEvent fn wait(event: GpuEvent) -> void 

Preferred language syntax:

fzy gpu.launch(square_kernel, grid: 4, block: 256, input, output, n) 

or later:

fzy launch square_kernel(grid: 4, block: 256)(input, output, n) 

Do not overdesign launch syntax until the lowering model is proven.

### 9.6 Device Intrinsics

Available only in kernel fn / device fn:

fzy fn global_id_x() -> i32 fn global_id_y() -> i32 fn global_id_z() -> i32  fn thread_id_x() -> i32 fn thread_id_y() -> i32 fn thread_id_z() -> i32  fn block_id_x() -> i32 fn block_id_y() -> i32 fn block_id_z() -> i32  fn block_dim_x() -> i32 fn block_dim_y() -> i32 fn block_dim_z() -> i32  fn grid_dim_x() -> i32 fn grid_dim_y() -> i32 fn grid_dim_z() -> i32  fn barrier() -> void 

Later:

fzy fn warp_id() -> i32 fn lane_id() -> i32 fn warp_size() -> i32 fn ballot(mask: bool) -> u32 fn shfl_down(value: f32, offset: i32) -> f32 

Vendor-specific intrinsics must remain explicitly marked.

## 10. Kernel IR

Do not lower GPU directly from AST.

Introduce a dedicated Kernel IR:

text AST → HIR → FIR → Kernel IR → GPU backend 

Kernel IR should represent:

text kernel entrypoints device functions pure functions used by kernels typed parameters thread/block/grid intrinsics device memory loads/stores device-safe control flow local variables simple loops bounds checks barriers shared memory later 

Kernel IR should exclude:

text host runtime calls JSON HTTP proc RPC async file system host allocation host pointers unsupported dynamic dispatch 

Kernel IR gives the verifier and backend one clean subset to reason about.

## 11. Backend Strategy

### 11.1 Do Not Start With Direct GPU Assembly

Direct handwritten GPU assembly should not be the main backend.

The main backend should use structured compiler targets:

text Kernel IR → MLIR GPU / LLVM GPU stack / SPIR-V path → NVVM/PTX for NVIDIA → ROCDL/AMDGPU for AMD → SPIR-V for Vulkan/WebGPU-style portability 

Reason:

- direct GPU assembly is highly vendor-specific
- hardware changes quickly
- register allocation and scheduling are hard
- debugging becomes brutal
- portability collapses
- PTX/SPIR-V/ROCDL exist for a reason

### 11.2 Supported Backend Targets

Roadmap targets:

text gpu-spirv      portable initial route gpu-nvptx      NVIDIA route gpu-amdgpu     AMD route gpu-metal      possible Apple route later 

The first backend should be selected based on implementation speed and local developer tooling.

Recommended order:

text 1. SPIR-V or NVPTX prototype 2. NVIDIA PTX/NVVM if CUDA ecosystem is primary target 3. AMDGPU/ROCDL later 4. Metal later 

### 11.3 Custom Assembly Escape Hatch

Allow limited custom intrinsic/asm hooks only after the safe model works.

Example:

fzy unsafe(     reason: "vendor warp shuffle intrinsic",     invariant: "lane offset is within warp size",     owner: "core.gpu",     scope: "warp_shuffle_down",     risk_class: "gpu.vendor_intrinsic",     proof_ref: "tests/gpu/warp_shuffle_down.fozzy" ) {     return gpu.__nv_shfl_down(value, offset) } 

Custom asm is for:

text vendor intrinsics microkernels warp ops barriers/special registers fast math variants runtime launch stubs 

Not for the entire GPU compiler.

## 12. Unified CPU/GPU Code

The highest-leverage FZY feature is shared pure compute.

Example:

fzy pure fn normalize(x: f32, mean: f32, scale: f32) -> f32 {     return (x - mean) * scale }  host fn normalize_one(x: f32) -> f32 {     return normalize(x, 0.5, 2.0) }  kernel fn normalize_kernel(input: GpuSliceF32, output: GpuSliceF32, n: i32) -> void {     let i = gpu.global_id_x()     if i < n {         output[i] = normalize(input[i], 0.5, 2.0)     } } 

The compiler should compile normalize for both host and device if needed.

This is the Mojo-like ergonomic win, but with FZY’s runtime/verifier identity.

## 13. Relationship To core.simd

GPU should reuse the existing core.simd philosophy.

The SIMD roadmap already established:

text portable first explicit lane counts safe APIs where possible backend lowering must be predictable unsupported shapes fail clearly 

GPU should follow the same rules.

### 13.1 CPU SIMD vs GPU SIMT

CPU SIMD and GPU SIMT are related but not identical.

CPU SIMD:

text one instruction operates on multiple lanes in a CPU vector register 

GPU SIMT:

text many GPU threads execute the same program over many data elements 

FZY should support both without conflating them.

Recommended mental model:

text pure scalar fn      shared everywhere core.simd          explicit CPU vector/data-plane helpers kernel fn          GPU parallel entrypoint device fn          GPU helper 

Later, core.simd may be allowed inside device code where it maps cleanly.

### 13.2 Shared Math Kernels

Examples:

fzy pure fn clamp255(x: f32) -> f32 {     if x < 0.0 { return 0.0 }     if x > 255.0 { return 255.0 }     return x } 

This can be used in:

text CPU scalar loops CPU SIMD helpers GPU kernels 

This is the main reuse story.

## 14. Capability Model

Add a new capability:

fzy use core.gpu; 

Host functions using GPU allocation, upload, download, launch, wait, stream, or event APIs require the GPU capability.

Device functions do not “use” host capability; they compile into GPU modules.

Capability rules:

text host GPU API requires gpu capability device intrinsics only valid in device/kernel execution space kernel launch requires gpu capability kernel code cannot access host capabilities 

Invalid:

fzy kernel fn bad() -> void {     log.info("hello") } 

Diagnostic:

text kernel function `bad` uses host capability `log`. Kernel/device code may only use device-safe operations. 

## 15. Async/RPC Integration

GPU should become part of FZY’s runtime story.

Example:

fzy rpc Infer(req: InferRequest) -> InferResponse     deadline 5000 {     let task = spawn run_gpu_inference(req)     return await task } 

Inside:

fzy async host fn run_gpu_inference(req: InferRequest) -> InferResponse {     let input_gpu = gpu.upload_f32(req.input)     defer gpu.free(input_gpu)      let output_gpu = gpu.alloc_f32(gpu.default_device(), req.len)     defer gpu.free(output_gpu)      let event = gpu.launch(infer_kernel, grid: req.grid, block: 256, input_gpu, output_gpu, req.len)     defer gpu.cancel_if_pending(event)      await gpu.wait_async(event)      let output = gpu.download_f32(output_gpu)     return InferResponse { output: output } } 

GPU events should participate in:

text deadline cancel trace resource cleanup task ownership 

This is where FZY can be meaningfully different from Mojo/CUDA/Rust.

## 16. Trace / Replay

GPU events should be trace-visible.

Add trace events:

text gpu.device_select gpu.alloc gpu.free gpu.upload gpu.download gpu.kernel_compile gpu.kernel_launch gpu.kernel_complete gpu.kernel_cancel gpu.stream_create gpu.stream_wait gpu.event_wait gpu.error 

Trace payload example:

json {   "kind": "gpu.kernel_launch",   "kernel": "normalize_kernel",   "grid": [4, 1, 1],   "block": [256, 1, 1],   "device": 0,   "args": ["input_gpu", "output_gpu", "1024"],   "timestamp": 123456789 } 

Replay policy:

- deterministic replay does not necessarily re-run GPU nondeterminism bit-for-bit at first
- replay should verify launch order, resource lifecycle, kernel identity, dimensions, and error codes
- optional deterministic numeric replay can run CPU fallback for supported kernels

## 17. CPU Fallback

Every phase-1 kernel should optionally support CPU fallback where possible.

This is valuable for:

text tests CI without GPU debugging semantic parity Fozzy scenarios trace replay 

Example:

fzy kernel fn square_kernel(...) 

can have:

fzy host fn square_kernel_cpu_fallback(...) 

or compiler-generated fallback for simple kernels later.

Initial policy:

text manual CPU fallback examples first compiler-generated fallback later 

## 18. Safety Rules

### 18.1 Bounds

All GpuSlice<T> indexing must be bounds-checked unless explicitly unsafe.

Safe:

fzy if i < n {     output[i] = input[i] } 

Unsafe fast path:

fzy unsafe(     reason: "manual bounds proof for tiled kernel",     invariant: "i < n checked by block/grid launch math",     owner: "image.pipeline",     scope: "blur_kernel",     risk_class: "gpu.bounds",     proof_ref: "tests/gpu/blur_bounds.fozzy" ) {     output.unchecked_write(i, value) } 

### 18.2 Kernel Resource Escape

Device code cannot store a GpuSlice<T> or pointer into a global host-visible location.

### 18.3 Host Handle Escape

Device code cannot receive host handles.

Forbidden:

text HttpHandle ProcHandle JsonHandle TaskHandle FileHandle 

### 18.4 Barriers

gpu.barrier() is only valid in kernel/device code.

Barrier use should be rejected if control-flow shape is obviously divergent in unsafe ways.

Phase 1 may conservatively reject barriers inside non-uniform branches.

### 18.5 Shared Memory

Later:

fzy let tile = gpu.shared<f32>(256) 

Shared memory rules:

text only inside kernel fixed size or launch-known size barrier required before cross-thread read no escaping references 

## 19. Performance Model

GPU performance comes from:

text coalesced memory access low branch divergence enough occupancy minimal host/device transfers kernel fusion where practical no hidden allocations no dynamic dispatch in kernels no host runtime calls in kernels canonical loop lowering alias/noalias metadata 

FZY should expose fz gpu perf advisories:

text uncoalesced access possible out-of-bounds branch divergence host/device transfer inside hot loop small launch too tiny for GPU kernel uses unsupported operation kernel scalarized unexpectedly missing noalias opportunity 

## 20. Diagnostics

Diagnostics should be direct and fix-oriented.

Examples:

text kernel function `blur_kernel` calls host-only function `fs.read_text`. Move file IO to host code and pass data through `GpuSlice`. 

text device function `score` uses `JsonHandle`, which is not device-safe. Parse JSON on host and pass typed numeric fields into the kernel. 

text GPU buffer `weights_gpu` is allocated but not freed. Add `defer gpu.free(weights_gpu)` after allocation. 

text kernel `saxpy` writes to `out` and reads from `x`, but verifier cannot prove they do not alias. Annotate slices as readonly/writeonly or split buffers before launch. 

## 21. Compiler Implementation Plan

### Phase 1 — Syntax and AST

Add item/function metadata:

text host pure device kernel 

Possible syntax:

fzy host fn pure fn device fn kernel fn 

Parser changes:

- recognize execution-space modifiers
- store execution-space in Function
- reject invalid combinations early

Invalid combinations:

text async kernel fn unsafe kernel fn without unsafe metadata extern kernel fn rpc kernel fn pubext kernel fn c 

### Phase 2 — Type System

Add types:

text GpuDevice GpuBuffer<T> GpuSlice<T> GpuEvent GpuStream 

If generics are too much initially, ship aliases:

text GpuBufferF32 GpuBufferI32 GpuBufferU32 GpuSliceF32 GpuSliceI32 GpuSliceU32 

### Phase 3 — Corelib

Create:

text corelib/src/gpu.fzy 

Add sample function to corelib sanity.

Expose host APIs and device intrinsics through runtime imports.

### Phase 4 — Verifier

Add:

text execution-space checker device-safe type checker kernel parameter checker kernel call graph checker GPU linear resource checker GPU borrow/alias checker GPU capability checker 

### Phase 5 — Kernel IR

Create:

text crates/kernel_ir 

or integrate under FIR initially:

text crates/fir/src/kernel.rs 

Represent:

text KernelModule KernelFunction DeviceFunction KernelParam KernelBlock KernelInstruction GpuLoad GpuStore GpuIntrinsic Barrier 

### Phase 6 — Backend Prototype

Pick first backend.

Recommended:

text SPIR-V for portability or NVPTX for NVIDIA-first practical testing 

Do not start with AMD/Metal simultaneously.

### Phase 7 — Runtime Shims

Add host runtime imports:

text gpu.device_count gpu.default_device gpu.device_name gpu.alloc_f32 gpu.free_f32 gpu.upload_f32 gpu.download_f32 gpu.launch gpu.wait gpu.wait_async 

Add device intrinsics separately:

text gpu.global_id_x gpu.thread_id_x gpu.block_id_x gpu.block_dim_x gpu.barrier 

### Phase 8 — Fozzy Scenarios

Add scenarios:

text gpu_square.pass.fozzy.json gpu_saxpy.pass.fozzy.json gpu_relu.pass.fozzy.json gpu_invalid_host_call.fail.fozzy.json gpu_buffer_leak.fail.fozzy.json gpu_kernel_bounds.fail.fozzy.json gpu_trace.pass.fozzy.json 

### Phase 9 — Perf Gates

Add benchmarks:

text saxpy relu vector add image brightness softmax partial matrix tile microkernel audio mix byte classification 

Compare:

text FZY CPU scalar FZY core.simd FZY GPU kernel Rust CPU baseline CUDA/C baseline where practical Mojo baseline where practical 

## 22. Initial Examples

### 22.1 Vector Add

fzy use core.gpu;  pure fn add_one(x: f32) -> f32 {     return x + 1.0 }  kernel fn add_one_kernel(input: GpuSliceF32, output: GpuSliceF32, n: i32) -> void {     let i = gpu.global_id_x()     if i < n {         output[i] = add_one(input[i])     } }  host fn main() -> i32 {     let device = gpu.default_device()      let input_gpu = gpu.upload_f32(device, [1.0, 2.0, 3.0, 4.0])     defer gpu.free(input_gpu)      let output_gpu = gpu.alloc_f32(device, 4)     defer gpu.free(output_gpu)      let event = gpu.launch(add_one_kernel, 1, 256, input_gpu, output_gpu, 4)     gpu.wait(event)      let output = gpu.download_f32(output_gpu)     return 0 } 

### 22.2 SAXPY

fzy pure fn saxpy_value(a: f32, x: f32, y: f32) -> f32 {     return a * x + y }  kernel fn saxpy_kernel(x: GpuSliceF32, y: GpuSliceF32, out: GpuSliceF32, a: f32, n: i32) -> void {     let i = gpu.global_id_x()     if i < n {         out[i] = saxpy_value(a, x[i], y[i])     } } 

### 22.3 RPC + GPU

fzy rpc Infer(req: InferRequest) -> InferResponse     deadline 5000 {     return await run_infer_gpu(req) }  async host fn run_infer_gpu(req: InferRequest) -> InferResponse {     let device = gpu.default_device()      let input_gpu = gpu.upload_f32(device, req.input)     defer gpu.free(input_gpu)      let output_gpu = gpu.alloc_f32(device, req.len)     defer gpu.free(output_gpu)      let event = gpu.launch(infer_kernel, req.grid, 256, input_gpu, output_gpu, req.len)     await gpu.wait_async(event)      let output = gpu.download_f32(output_gpu)     return InferResponse { output: output } } 

## 23. Relationship To Mojo

FZY should not copy Mojo’s positioning directly.

Mojo is oriented around:

text Python-like ergonomics AI/numerics MLIR-based performance accelerator programming 

FZY should compete from a different center:

text runtime systems memory safety async/RPC/process orchestration trace/replay CPU/GPU ownership agent/tool/control-plane infrastructure 

The pitch is not:

> FZY is Python for GPUs.

The pitch is:

> FZY is a native runtime language where CPU orchestration, GPU kernels, async tasks, RPC frames, memory ownership, and trace artifacts live in one verified system.

That is the differentiated lane.

## 24. Success Criteria

GPU support is production-ready when FZY can claim:

- core.gpu exists as a stable stdlib module
- pure fn, host fn, device fn, and kernel fn are compiler-checked
- kernels cannot call host-only functions
- host code can allocate/upload/launch/download/free GPU resources
- GPU handles are linear resources
- GPU buffer leaks are rejected
- kernel parameters are device-safe
- GPU launches emit trace events
- basic kernels work on at least one real backend
- CI can run GPU tests or CPU fallback tests
- unsupported GPU shapes fail clearly
- safe GPU code requires no unsafe blocks
- unsafe GPU intrinsics require complete unsafe metadata
- benchmarks show real performance wins against CPU scalar paths
- FZY can share pure compute functions between CPU and GPU

## 25. Phase Roadmap

### Phase 0 — Design Freeze

- write GPU.md
- decide execution-space syntax
- decide first backend target
- decide phase-1 supported types
- decide launch syntax

### Phase 1 — Frontend

- parser recognizes host, pure, device, kernel
- AST stores execution space
- diagnostics for invalid modifier combinations
- call graph execution-space checker

### Phase 2 — Corelib Stub

- add corelib/src/gpu.fzy
- add mod gpu in corelib main
- define API stubs
- runtime import names reserved

### Phase 3 — Verifier

- device-safe type checker
- host/device call checker
- GPU resource linear checker
- GPU capability checker
- unsafe GPU contract checker

### Phase 4 — Kernel IR

- lower kernel/device/pure subset into Kernel IR
- reject unsupported expressions
- preserve bounds/alias metadata
- preserve source spans for diagnostics

### Phase 5 — First Backend

- choose SPIR-V or NVPTX
- lower simple scalar kernels
- support global_id_x
- support load/store
- support arithmetic/branches
- support launch from host

### Phase 6 — Runtime

- implement device discovery
- implement alloc/free
- implement upload/download
- implement launch/wait
- emit trace events

### Phase 7 — Testing

- valid/invalid kernel tests
- verifier tests
- runtime resource tests
- Fozzy scenarios
- CPU fallback tests
- backend output tests

### Phase 8 — Performance

- benchmark scalar CPU vs SIMD vs GPU
- add fz gpu perf
- add advisory diagnostics
- add kernel trace/profiling artifacts

### Phase 9 — Advanced GPU

Later only:

- shared memory
- warp intrinsics
- atomics
- reductions
- tiled matmul
- async GPU streams
- multi-device
- vendor-specific unsafe intrinsics
- auto-offload candidates
- kernel fusion

## 26. Hard Rules

Do not sacrifice FZY’s identity.

GPU support must remain:

text small explicit verifier-aware runtime-integrated memory-safe by default traceable high-performance 

Do not build a giant magical framework.

Do not hide host/device transfers.

Do not make unsupported kernels silently scalarize.

Do not allow GPU resources to leak.

Do not let device code call host runtime APIs.

Do not make direct assembly the default backend.

Do not chase every CUDA feature before the core model is hardened.

## 27. Final Principle

FZY GPU should not be “CUDA syntax in FZY.”

It should be:

> a unified CPU/GPU runtime programming model where pure compute is shared, host effects are explicit, kernel code is constrained, memory ownership is checked, launches are traceable, and performance-critical code remains direct.

The goal is not just to run on GPUs.

The goal is to make GPU work part of FZY’s larger thesis:

> serious native runtimes should be fast, safe, observable, and small enough to understand.