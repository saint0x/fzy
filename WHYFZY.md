# Why fzy

fzy is for teams that want a modern systems language without treating reproducibility, safety evidence, and runtime validation as separate tools bolted on later.

It is not just "a compiler plus some tests." The pitch is that language design, compiler behavior, runtime contracts, and Fozzy validation all line up around one goal: make serious systems software easier to ship, easier to trust, and easier to debug when reality gets messy.

## The Short Version

Choose fzy if you want:

- memory safety by default, with explicit unsafe islands instead of ambient unsafety
- manual memory management when you need it, without abandoning the compiler's ownership model
- native async, tasks, and RPC as first-class language/runtime features
- ADTs, pattern matching, traits, generics, and other modern language tools for real application structure
- deterministic traces, replay, verification, and incident artifacts as part of the normal workflow
- strong C interop in both directions, including generated headers and async-handle exports
- a compiler/toolchain that produces operational evidence, not just binaries
- a DX story aimed at production systems work, not only toy examples or compiler experiments

## Why It Stands Out

### 1. Fozzy is built into the story, not bolted on

This is the biggest difference.

Many systems languages give you a compiler, a package manager, maybe a test runner, and then leave determinism, replay, scenario validation, fuzzing workflows, and production evidence to the rest of your stack. fzy is designed to pair directly with Fozzy so the validation lifecycle is part of the language's normal operating model.

That means you can:

- run strict deterministic tests first
- record a real trace for the behavior you care about
- verify the trace, replay it, and feed it through CI-oriented validation
- keep host-backed checks separate from deterministic checks instead of blurring them together

If you care about reproducing failures instead of hand-waving about them, this is a very different experience from "please retry locally and hope the bug reappears."

## 2. Memory safety is the default, but unsafe is still practical

fzy aims at a safe-by-default posture while still acknowledging that systems work sometimes needs sharp tools.

The important distinction is that unsafe behavior is:

- explicit
- auditable
- policy-driven
- surfaced in generated artifacts

Instead of hiding low-level escape hatches in an ambient culture of "be careful," fzy makes unsafe islands first-class and reviewable. The toolchain can emit unsafe inventory and docs artifacts, and projects can tighten enforcement in policy.

That is attractive if you want low-level control without giving up reviewability.

Just as importantly, fzy now supports explicit manual memory management inside that broader safety story. You can work with owned heap allocation flows such as `alloc(...)` and `free(...)`, and the verifier can still reason about lifecycle mistakes like invalid consumption, imbalance, or escape paths in stricter profiles. So the model is not "safety or control." The pitch is "default safety, with explicit memory control when the job actually needs it."

The key line is that manual memory management is not automatically treated as unsafe. If the compiler can still justify ownership, provenance, and guaranteed cleanup through real `defer` execution semantics, that workflow stays on the safe side of the language instead of being forced behind ceremonial `unsafe`.

## 3. Native async and RPC are first-class, not awkward add-ons

A lot of languages can do concurrency. Fewer make async behavior, scheduling, and RPC feel like they belong to the core model.

fzy treats async functions, task/runtime behavior, and RPC declarations as part of the language/runtime contract. That matters because the surrounding tooling understands them too:

- deterministic scheduling modes exist for validation
- async checkpoints become replay-visible events
- RPC send/receive/deadline/cancel behavior shows up in trace data
- RPC schemas and stubs can be generated from the declared surface

If your software is service-shaped, protocol-shaped, or concurrency-heavy, this is a real advantage.

## 4. It has modern language features without pretending systems code should stay primitive

fzy is not chasing a minimal "just pointers and structs" philosophy.

The language already leans into features teams actually use to keep large codebases manageable:

- ADTs and pattern matching
- traits and generics
- explicit ownership-aware allocation and cleanup flows
- modules and re-exports
- structured JSON helpers
- filesystem, process, terminal, path, and logging stdlib surfaces
- outbound HTTP and streaming support

That makes it easier to write systems software that still feels ergonomic at the application and service layers.

## 5. C interop goes both ways

Interop is often where "modern language" promises get awkward. fzy takes this seriously.

The toolchain supports:

- exported C functions with generated headers
- imported C functions through explicit `ext unsafe c fn`
- ABI checks
- panic-boundary policy
- async C exports through handle-based generated interfaces

This makes fzy more compelling when you need to sit between native libraries, older platform code, or external runtimes instead of living in a perfectly pure ecosystem.

## 6. The compiler is trying to help you operate software, not just compile it

One of the most interesting parts of the fzy story is that the compiler/driver surface is unusually operational.

The CLI is not just `build` and `test`. It also includes:

- verify and lint flows
- docs and header generation
- RPC generation
- ABI compatibility checks
- unsafe audits
- parity/equivalence checks
- deterministic artifact capture
- LSP and editor-facing tooling

That means the compiler output is not only about acceptance or rejection of code. It is part of a broader "make this shippable, inspectable, and explainable" workflow.

## 7. The DX is unusually production-aware

A lot of languages have decent developer experience for greenfield demos but become hand-assembled once you care about release evidence, deterministic reproduction, or operator-facing behavior.

fzy pushes in the opposite direction:

- `dx-check` exists as a first-class conventions gate
- docs and policy live close to the toolchain
- deterministic and host-backed checks are treated as different confidence signals
- traces, reports, manifests, and replay flows are normal artifacts
- runtime defaults and CLI behavior are documented as operational contracts

That is a niche but important kind of DX: not just "easy to type," but "easier to trust under pressure."

## Compared With Other Systems Languages

### Versus C and C++

fzy is appealing when you want stronger default safety, more structured validation, and less reliance on manual discipline around memory, concurrency, and reproducibility.

### Versus Rust

Rust is a much larger and more established ecosystem, but fzy has a different center of gravity. The pitch is less "maximum expressiveness inside Rust's model" and more "safe-by-default systems programming with deterministic validation, replay, RPC, and Fozzy-backed evidence deeply integrated into the workflow."

If what you want most is a unified compiler-plus-replay-plus-runtime-validation story, fzy is aiming at a different sweet spot.

### Versus Go

Go keeps things simple, but fzy targets a richer systems-language feature set: stronger explicit safety posture, ADTs, traits/generics, lower-level interop contracts, deterministic replay workflows, and more formalized runtime evidence.

### Versus Zig

Zig is excellent when you want explicitness and control with very little abstraction overhead. fzy is more attractive if you want stronger safe-by-default semantics, richer high-level language constructs, and a tighter integration between the language and deterministic validation tooling.

## Who This Is For

fzy is especially attractive for teams building:

- services and control-plane software
- native CLIs and operational tooling
- systems that need reproducible bug reports and replayable failures
- mixed-language stacks with real C boundaries
- software where correctness evidence matters, not just benchmark numbers

## Who Might Not Need It

fzy may be more than you need if:

- you only want a tiny low-level language with minimal surface area
- deterministic replay and trace evidence are not valuable in your environment
- you do not need strong validation tooling around async, RPC, or runtime behavior
- your main priority is ecosystem size over integrated workflow design

## The Core Bet

The core bet behind fzy is simple:

systems programming gets a lot better when the language, compiler, runtime, and validation stack are designed together.

That is why the interesting part is not any single feature in isolation. Plenty of languages have async. Plenty have traits, generics, or C interop. Plenty can claim safety goals. The differentiator is the combination:

- safe-by-default systems programming
- explicit manual memory control when needed
- modern language ergonomics
- native async and RPC
- bidirectional C interop
- deterministic replay and incident evidence
- Fozzy-driven validation as a normal development habit

If that combination is what you have been missing, that is the case for fzy.
