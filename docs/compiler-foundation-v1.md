# Compiler Foundation v1

## Status

This document captures the production baseline implemented for PLAN section 1.5.

Implemented:
- Lexer/token stream parser (line-splitting parser removed).
- Recursive-descent parser with precedence-climbing expression parsing.
- Parser error recovery with multi-diagnostic reporting.
- Structured type system (`ast::Type`) propagated through AST/parser/HIR/FIR/verifier/driver.
- Scoped symbol tables and function call signature validation in HIR.
- Control-flow statements (`if`/`else`, `while`) across AST/parser/HIR/FIR.
- Tree-walking interpreter semantics for typed `main` evaluation.
- FIR upgraded to typed function IR with basic blocks and instruction nodes.
- Call graph construction and reusable AST visitor/walker traversal.
- Extended match patterns with variant-destructuring form, guard clauses, and or-patterns.
- Added FIR def-use and liveness analysis output per basic block.
- Production verifier integration for capability and memory-safety contracts (including ownership-transfer and lowerability diagnostics).

Current known limits:
- Optimization depth is intentionally conservative (no aggressive SSA-level optimization pipeline in v1).
- Traits/generics are production-supported for the v1 contract surface (function generics with explicit specialization, concrete trait impl targets, strict coherence diagnostics).
- Advanced trait/generic forms remain intentionally out of scope and are hard-rejected in v1 (generic struct/enum/trait/impl headers, associated items, trait method defaults, generic trait methods).
- Native lowering is production-hardened for supported signatures; unsupported native signatures are verifier-rejected by policy.

## Architecture

Pipeline:
1. `parser`: source -> `ast::Module`.
2. `hir`: typed semantic analysis + call validation + interpreter-ready typed module.
3. `fir`: typed CFG/basic-block IR.
4. `verifier`: capability/safety/type diagnostics.
5. `driver`: native backend emission + CLI integration.

Core implementation files:
- `crates/ast/src/lib.rs`
- `crates/parser/src/lib.rs`
- `crates/hir/src/lib.rs`
- `crates/fir/src/lib.rs`
- `crates/verifier/src/lib.rs`
- `crates/driver/src/pipeline.rs`
- `crates/driver/src/command.rs`

## Validation Commands

Compiler/tests:
```bash
cargo check -q
cargo test -p parser -p hir -p fir -p verifier -p driver
```

Deterministic lifecycle (example):
```bash
cargo run -p fz -- run /tmp/p15_smoke.fzy --det --strict-verify --record /tmp/p15_smoke.trace.fozzy --json
cargo run -p fz -- replay /tmp/p15_smoke.trace.fozzy --json
cargo run -p fz -- ci /tmp/p15_smoke.trace.fozzy --json
cargo run -p fz -- test /tmp/p15_smoke.fzy --det --strict-verify --json
```
