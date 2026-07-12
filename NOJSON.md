# NOJSON

Architectural policy for keeping Fzy/Fozzylang a serious systems language rather than a stringly typed runtime that happens to compile.

This document does not ban JSON from the product. It bans JSON as an internal substitute for language-level types, compiler IR, runtime state, and protocol contracts that should be modeled natively.

This is a repository-facing production contract for architecture, review, examples, and release readiness. Unless a section below explicitly allows a JSON use, treat new internal JSON-shaped design as policy-breaking work.

## Contract Status

- This policy applies to all new architecture work in this repository.
- This policy is release-facing, not aspirational guidance.
- Existing boundary JSON outputs remain supported.
- Existing internal debt should be migrated over time, but new debt should not be added.
- Reviewers should treat violations as contract failures unless the change documents a real external boundary and why a typed internal model is insufficient.

## Scope

This contract applies to:

- Rust compiler, verifier, runtime, driver, and tooling crates
- Fzy stdlib and framework surface design
- examples, docs, and cookbook material that teach users how to structure systems
- persistence, replay, trace, RPC, FFI, HTTP, and operator-tooling architecture

This contract does not ban:

- JSON as an external interoperability format
- JSON artifacts emitted for operators, tools, ecosystems, or compatibility
- JSON transport framing at genuine protocol boundaries

## Core Rule

JSON is a boundary format.

JSON is not:

- the compiler's semantic substrate
- the verifier's internal fact store
- the runtime's core state model
- the transport between compiler phases
- the default persistence representation for language-owned objects
- a substitute for typed RPC/FFI/domain contracts

## Why This Matters

If we allow important semantics to collapse into JSON too early, we get:

- stringly typed invariants instead of compiler-enforced ones
- parse/serialize churn between phases and layers
- weaker optimization opportunities
- harder refactors because field names become hidden contracts
- silent schema drift across tools, examples, and artifacts
- poor memory/perf characteristics on hot paths
- lower confidence in production-scale behavior
- code that feels like "typed shell glue" instead of a real systems language

For a serious language, the internal architecture has to remain typed all the way down until a true external boundary is crossed.

## Allowed JSON

JSON is explicitly allowed at product boundaries:

- CLI `--json` output
- machine-readable compiler diagnostics
- generated artifact manifests
- trace/report/export files
- OpenAPI and HTTP JSON request/response bodies
- LSP JSON-RPC framing
- embedding/interop manifests consumed by non-Fzy hosts
- config files that are intentionally external and tool-facing
- tests that need to inspect emitted artifacts from the outside

The rule is:

- inside the compiler/runtime/tooling core: native types first
- at the edge: encode/decode JSON once, as late as possible

## Production Contract

The repo-wide production contract is:

1. model internal semantics with typed structs/enums/handles/IR/fact records first
2. generate or project JSON outward only when a real external boundary requires it
3. decode inbound JSON once at the boundary, then move immediately into typed models
4. keep examples and docs aligned with the same typed-first architecture expected in production code

A change does not satisfy this contract if JSON is acting as the hidden source of truth for internal semantics, even when the user-visible feature still works.

## Forbidden Patterns

These patterns should be treated as architectural debt unless they are clearly boundary-only and documented:

- compiler phases passing JSON blobs between parser, AST, HIR, FIR, verifier, backend, or runtime
- storing language-owned semantic state in `serde_json::Value`
- using JSON maps as a substitute for typed structs/enums in Rust crates
- Fzy services returning JSON strings to each other instead of typed records
- ad hoc `"status"`, `"kind"`, `"payload"` string protocols in internal calls
- using `json.parse(...)` as a generic object model inside business logic
- re-parsing the same payload across multiple layers
- manually concatenated JSON strings for internal state transitions
- bespoke wire strings when a typed in-memory model should exist
- persisting core compiler/runtime state as JSON by default when schema evolution, indexing, or performance matter

## Architecture Rules By Layer

## Compiler

The compiler must keep native typed representations for:

- tokens
- AST
- name resolution state
- HIR
- FIR
- kernel IR
- verifier facts
- capability facts
- ownership/borrow facts
- diagnostics before final rendering
- backend lowering state

Compiler phases must exchange typed Rust data structures, not JSON text or `serde_json::Value`.

JSON is only appropriate when the compiler emits:

- diagnostics for CLI/LSP consumers
- artifact manifests
- generated reports
- compatibility/trace metadata for external inspection

## Verifier

Verifier logic must operate on typed facts, not field-name lookups into generic objects.

Required direction:

- explicit fact types for ownership, lifetime, capability, async, FFI, and safety evidence
- typed diagnostic payloads before rendering
- typed autofix models before text/JSON projection

Avoid:

- verifier rules that inspect generic JSON payloads to decide language semantics

## Runtime

Runtime internals should model:

- requests
- responses
- task state
- cancellation state
- handles
- network frames
- scheduler decisions
- replay events
- memory reports

as native types first.

JSON should only appear when:

- accepting/emitting JSON over HTTP
- exporting traces/reports
- printing machine-readable operator output

Raw `json.parse(http.body(...))` should remain a boundary decode, not a downstream internal representation.

## Stdlib

The stdlib may expose JSON helpers, but must not force JSON-shaped programming for normal typed work.

Direction:

- typed HTTP request/response helpers
- typed log-field builders
- typed payload builders for common protocols
- typed config readers where schema is known

Avoid making `map.new() + map.set() + json.object()` the dominant idiom for ordinary application modeling.

## FFI / RPC / OpenAPI

RPC, FFI, and OpenAPI surfaces should be defined from typed contracts and generated outward.

Good:

- typed RPC declarations
- typed request/response structs
- generated schema/manifests

Bad:

- schema-first internal design where the JSON schema becomes the real source of truth and language types merely mirror it

The source of truth should be the language-level contract.

## Persistence

Default rule:

- if the data is language-owned and long-lived, prefer typed storage schemas
- if the data is external, portable, or export-oriented, JSON is acceptable

Use JSON persistence for:

- export artifacts
- snapshots intended for interchange
- debug dumps
- compatibility fixtures

Prefer typed persistence or structured stores for:

- compiler caches
- symbol indexes
- incremental build state
- runtime registries
- session/state stores
- scheduler and replay internals

## Examples And Apps

Examples should demonstrate the idiomatic direction we want users to copy.

That means examples should not normalize:

- internal JSON-as-domain-model design
- hand-built string protocols
- repeated parse/reparse flows
- generic `payload_json` everywhere for core semantics

Examples may still use JSON at real boundaries, but they should show how to decode once into a typed model and then stay typed.

## Migration Guidance

When you find JSON in the codebase, classify it first.

## Keep

Keep JSON when it is:

- a true external protocol
- generated output for humans/tools
- trace/report/manifest emission
- compatibility data for ecosystems that require JSON

## Refactor

Refactor JSON away when it is:

- carrying internal compiler/runtime meaning
- used repeatedly inside hot paths
- standing in for a real enum/struct/union/domain object
- forcing callers to know magic field names
- being parsed and immediately rewrapped elsewhere

## Preferred Replacement Ladder

Replace internal JSON with:

1. typed structs
2. enums for tagged states
3. typed collections
4. typed handles/IDs instead of generic string keys
5. generated serializers at the edge

Only use custom wire formats when they are clearly justified by:

- performance
- deterministic replay encoding
- ABI constraints
- storage density

and even then, keep a typed API over the wire format.

## Remaining High-Priority Fronts

The biggest remaining cleanup fronts are:

- Rust-side `serde_json::Value` and JSON-tree inspection in remaining compiler/audit paths
- examples and support code that still teach JSON-first internal modeling

## Current Codebase Implications

For this repository specifically, the intended direction is:

- `crates/parser`, `crates/ast`, `crates/hir`, `crates/fir`, `crates/kernel_ir`, `crates/verifier`, and `crates/runtime` stay fully typed internally
- `crates/driver` may emit JSON for CLI, LSP, reports, manifests, and external tools, but remaining audit/report internals should keep moving onto typed report models before final serialization
- `crates/fzscenario` may continue to own JSON artifacts and scenario/report emission, because that is a genuine interchange surface
- `core`, `examples`, and framework code should keep JSON shaping in API/transport layers and avoid teaching JSON-as-domain-model as the default authoring style

## Enforcement Strategy

This policy only matters if it is enforceable.

We should add and maintain the following enforcement directions:

- lint for new internal uses of `serde_json::Value` in compiler/runtime core crates
- lint for new compiler phase boundaries that serialize to JSON and immediately deserialize in-process
- lint for new Fzy example code that uses JSON as its primary internal domain model
- verifier or static tooling warnings for repeated `json.parse(...)` chains in hot-path service code
- review rule that any new `payload_json` field must explain why the shape is not statically known
- review rule that any new custom wire encoding must document why typed structs were insufficient

Not every one of these needs to ship as a compiler diagnostic immediately, but they should all become reviewable policy.

## Merge And Release Expectations

Before merge:

- new compiler/runtime/verifier architecture must satisfy this contract in code review
- new examples and docs must not teach JSON-first internal modeling as the preferred style
- any new boundary JSON surface should identify the typed source of truth behind it
- any unavoidable exception should be called out explicitly in the change description with the boundary reason

Before release:

- release-facing docs should continue to describe Fzy as typed internally and JSON at the edge
- production examples should still show decode-once boundary handling rather than parse/reparse flows
- no newly introduced internal JSON protocol should be part of the ship surface

## Exception Bar

An exception is only acceptable when all of the following are true:

- the JSON shape is required by an external protocol, ecosystem, or compatibility surface
- the internal typed model still exists and owns the semantics
- the JSON encode/decode boundary is narrow and explicit
- the change documents why a generic payload is necessary instead of a typed internal contract

Convenience, speed of prototyping, and "we might change the shape later" are not sufficient reasons by themselves.

## Migration Order

Do not try to delete all JSON usage in one sweep. Migrate in the order that produces the most architectural leverage.

### Phase 1

- stop introducing new internal JSON-shaped protocols
- stop introducing new `serde_json::Value` core state in Rust crates
- stop introducing new `payload_json` escape hatches where the shape is known
- keep existing artifact/report/boundary JSON untouched

### Phase 2

- replace internal service-to-service JSON strings with typed request/response structs
- replace repeated parse/reparse flows with decode-once typed boundary adapters
- move domain modeling out of `map.set(...)` JSON builders and into typed records/enums

### Phase 3

- replace ad hoc framed string or pseudo-wire encodings with typed APIs over compact internal representations
- audit persistence layers and move language-owned long-lived state onto typed schemas where appropriate
- update examples and docs so the idiomatic path is visibly typed-first

### Phase 4

- add stronger compiler/lint enforcement
- add regression tests that fail when forbidden patterns reappear
- make "typed internally, JSON only at the edge" part of the language's published architecture contract

## Decision Framework For New Work

When designing a new subsystem, decide in this order:

1. What is the native typed model?
2. What invariants should the compiler enforce?
3. What storage/transport shape is best internally?
4. What external boundary formats must be supported?
5. What JSON projection should be generated from the typed model?

Do not start from:

1. a JSON schema
2. a generic key/value payload
3. a `payload_json` field
4. a map of strings pretending to be a type system

unless the subsystem is genuinely external-protocol-first.

## Non-Negotiable Style Rules

- Do not introduce new internal compiler phase boundaries that communicate through JSON.
- Do not introduce new verifier logic that depends on generic JSON object inspection for core semantics.
- Do not introduce new runtime domain models as raw JSON strings unless the domain itself is external JSON.
- Do not introduce `payload_json` fields as a lazy escape hatch when the shape is actually known.
- Do not make examples more stringly than the production architecture.
- Generate JSON from typed models; do not treat JSON as the typed model.

## Definition Of Done

We should consider this policy successful when the following become true:

- compiler and verifier semantics live in typed IR/fact models end-to-end
- runtime core state transitions are typed and inspectable without generic JSON trees
- JSON exists mostly in emitted artifacts, protocol edges, and operator tooling
- examples teach typed-first modeling by default
- new contributors can tell, by reading the codebase, that Fzy is a systems language with strong boundary tooling rather than a JSON-oriented glue stack

## Review Checklist

Before merging new architecture work, ask:

- Is this JSON crossing a real external boundary?
- If I renamed a field, would the compiler catch breakage?
- Should this be a struct/enum instead of a generic object?
- Are we parsing this more than once?
- Is this hot-path work paying avoidable serialization costs?
- Is this example teaching users the architecture we actually want?
- Could this schema be generated from typed declarations instead of handwritten?

If the answer points toward internal semantics, JSON is probably the wrong tool.

## Long-Term Goal

The long-term goal is not "less JSON."

The goal is:

- typed internals
- generated boundaries
- explicit contracts
- lower parse churn
- stronger optimization potential
- safer refactors
- more idiomatic Fzy application architecture

Fzy should feel like a serious systems language with first-class boundary tooling, not like a JSON orchestration layer with a compiler attached.
