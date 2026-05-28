# Why Choose fzy

If you are evaluating systems languages, the question is not whether fzy has one interesting feature. The question is whether you want a language built around shipping production systems with stronger safety defaults, better runtime evidence, and a validation story that does not depend on stitching together a half-dozen external tools.

That is the real case for fzy. It is a modern systems language for teams that care not only about writing low-level software, but also about reproducing failures, auditing unsafe code, validating behavior deterministically, and operating software under real pressure.

## The Short Answer

Choose fzy over other systems languages if you want:

- memory safety by default, with explicit unsafe islands instead of ambient unsafety
- a more sane mental model than Rust with the same safety guarantees
- manual memory management when needed, without throwing away the ownership model
- native async, protocol, and RPC support as first-class language/runtime features
- ADTs, pattern matching, traits, generics, and other modern language tools for large codebases
- deterministic traces, replay, verification, and incident artifacts as part of the normal workflow
- stronger bidirectional C interop, including generated headers and async-handle exports
- a better unsafe paradigm: explicit, auditable, and policy-driven instead of ambient
- a compiler/toolchain that produces operational evidence, not just binaries
- a developer experience aimed at production systems work, not only greenfield demos

## Why Teams Pick fzy

### Integrated validation instead of bolted-on tooling

Most systems languages give you a compiler, maybe a package manager, and maybe a test runner. After that, deterministic replay, scenario validation, fuzzing workflows, and incident evidence are usually somebody else's problem.

fzy is different because it is designed to pair directly with Fozzy. That makes validation part of the language's operating model instead of an afterthought. In practice, that means teams can:

- run strict deterministic tests first
- record a real trace for the behavior they care about
- verify the trace, replay it, and feed it into CI-oriented validation
- keep host-backed checks separate from deterministic checks instead of mixing confidence levels together

Compared with most systems languages, this is one of the clearest reasons to choose fzy. If reproducibility matters, "retry and hope the bug comes back" is a much weaker workflow.

### Safe by default without giving up low-level control

fzy is aimed at teams that want a stronger safety posture than C, C++, or other ambiently unsafe environments, but who still need practical escape hatches for systems work.

It is also aimed at teams that like what Rust is trying to guarantee, but want a more sane mental model for everyday systems programming. Part of the reason fzy exists is that we wanted the same safety guarantees without making the language feel harder than the problem.

Unsafe behavior in fzy is meant to be:

- explicit
- auditable
- policy-driven
- surfaced in generated artifacts

That changes the tradeoff. Instead of relying mostly on discipline and code review culture, unsafe regions become first-class and reviewable.

Just as importantly, manual memory management still fits inside that broader safety story. You can use owned heap allocation flows such as `alloc(...)` and `free(...)`, and the verifier can still reason about lifecycle mistakes such as invalid consumption, imbalance, or escape paths in stricter profiles.

That is an important distinction from languages that force a harsher choice between safety and control. In fzy, manual memory management is not automatically treated as unsafe if the compiler can still justify ownership, provenance, and guaranteed cleanup through real `defer` execution semantics.

That is also part of what makes the unsafe paradigm feel better. Unsafe code is not a vague background condition and it is not the default price of doing low-level work. It is a clearly bounded tool with reviewable consequences.

### Async and RPC belong to the core model

Many languages support concurrency. Fewer treat async behavior, scheduling, and RPC as core parts of the language/runtime contract.

fzy does, and the surrounding tooling understands those features too. That enables:

- deterministic scheduling modes for validation
- replay-visible async checkpoints
- trace-level visibility into RPC send, receive, deadline, and cancel behavior
- generated RPC schemas and stubs from the declared surface

If you are comparing languages for service-heavy, protocol-heavy, or concurrency-heavy systems, this matters. One of the core design goals here was to offer far better native async, protocol, and RPC support than you usually get from systems languages where these capabilities live mostly in libraries or framework conventions.

The result is a more coherent workflow than adding framework conventions on top of a language that never really modeled those concerns directly.

### Modern language ergonomics for real systems code

Some systems languages lean hard into minimalism and expect teams to rebuild higher-level structure themselves. fzy makes a different bet: large systems codebases benefit from modern language features.

That includes:

- ADTs and pattern matching
- traits and generics
- explicit ownership-aware allocation and cleanup flows
- modules and re-exports
- structured JSON helpers
- filesystem, process, terminal, path, and logging stdlib surfaces
- outbound HTTP and streaming support

This makes fzy easier to choose when you want systems-level control without forcing the entire codebase to feel primitive.

### Strong C interop in both directions

Interop is where a lot of language pitches get less convincing. fzy treats mixed-language reality as normal, not exceptional.

The toolchain supports:

- exported C functions with generated headers
- imported C functions through explicit `ext unsafe c fn`
- ABI checks
- panic-boundary policy
- async C exports through handle-based generated interfaces

This is one of the places where fzy is intentionally opinionated. We wanted a better bidirectional C interop API, not just basic foreign-function escape hatches.

That makes fzy more compelling than "pure ecosystem only" languages when your software needs to sit between native libraries, older platform code, or external runtimes.

### A compiler and CLI that help you operate software

Another reason to choose fzy is that the toolchain is not only focused on turning source into binaries. It is also trying to help teams produce software that is inspectable, explainable, and shippable.

The CLI surface includes more than `build` and `test`. It also covers:

- verify and lint flows
- docs and header generation
- RPC generation
- ABI compatibility checks
- unsafe audits
- parity and equivalence checks
- deterministic artifact capture
- LSP and editor-facing tooling

That gives fzy a more operational character than many systems languages whose official workflow effectively stops at compilation and unit tests.

### Production-aware developer experience

A lot of languages feel polished in examples and rougher in production. fzy is more opinionated about the latter.

Its workflow emphasizes:

- `dx-check` as a first-class conventions gate
- docs and policy living close to the toolchain
- deterministic and host-backed checks as different confidence signals
- traces, reports, manifests, and replay flows as normal artifacts
- runtime defaults and CLI behavior documented as operational contracts

That is a narrower value proposition than "best beginner experience" or "largest package ecosystem," but it is a strong one for teams that optimize for trust under pressure.

## Compared With Other Systems Languages

### Versus C and C++

Choose fzy over C or C++ when you want stronger default safety, a better unsafe paradigm, more structured validation, and less dependence on manual discipline around memory, concurrency, and reproducibility.

### Versus Rust

Rust has a much larger ecosystem and a far more established footprint. fzy is not trying to win on ecosystem scale. Its center of gravity is different: safe-by-default systems programming with deterministic validation, replay, RPC, and Fozzy-backed evidence integrated much more deeply into the normal workflow.

The more direct distinction is mental model. fzy is for teams that want the same safety guarantees, but a more sane model for writing and reasoning about systems code day to day.

It also puts more emphasis on native async, protocol, and RPC support, a stronger bidirectional C interop surface, and a better-bounded unsafe story.

If the main thing you want from a language is a unified compiler-plus-runtime-validation story without taking on as much conceptual overhead, fzy is aiming at a different sweet spot.

### Versus Go

Go favors simplicity and a narrower language model. Choose fzy when you want a richer systems-language feature set: stronger explicit safety posture, better native async and RPC semantics, lower-level interop contracts, ADTs, traits and generics, deterministic replay workflows, and more formal runtime evidence.

### Versus Zig

Zig is compelling when you want explicitness, control, and very little abstraction overhead. Choose fzy when you want stronger safe-by-default semantics, a better unsafe paradigm, richer high-level language constructs, stronger native async and RPC support, and tighter integration between the language and deterministic validation tooling.

## Who fzy Is For

fzy is especially attractive for teams building:

- services and control-plane software
- native CLIs and operational tooling
- systems that need reproducible bug reports and replayable failures
- mixed-language stacks with real C boundaries
- software where correctness evidence matters, not just benchmark numbers

## Who May Prefer Something Else

fzy may not be the best fit if:

- you want the smallest possible low-level language surface
- deterministic replay and trace evidence are not valuable in your environment
- you do not need strong validation around async, RPC, or runtime behavior
- your top priority is ecosystem size rather than integrated workflow design

## The Core Reason

The strongest argument for choosing fzy is that it treats systems programming as more than writing fast code. It treats language design, compiler behavior, runtime contracts, and validation evidence as one connected problem.

Plenty of languages offer async. Plenty offer traits, generics, or C interop. Plenty make safety claims. What stands out about fzy is the combination:

- safe-by-default systems programming
- a more sane mental model with the same safety guarantees teams want from modern safe systems languages
- explicit manual memory control when needed
- modern language ergonomics
- native async, protocol, and RPC support
- stronger bidirectional C interop
- a better unsafe paradigm
- deterministic replay and incident evidence
- Fozzy-driven validation as a normal development habit

If that is the combination you want, that is why you choose fzy.
