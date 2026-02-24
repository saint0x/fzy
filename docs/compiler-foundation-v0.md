# Compiler Foundation v0 (1.5)

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
- Started 1.6 capability/memory work: function-scoped capability requirement propagation and ownership-transfer violation detection.

Still pending in 1.5:
- Full Cranelift and LLVM instruction selection for all expression/statement forms.
- Full function ABI lowering (stack frames/calling convention details beyond current baseline).
- Advanced pattern match lowering (destructuring/guards/or-patterns).
- Dataflow/liveness/def-use analyses and DCE-quality optimization passes.
- Generic specialization and trait/interface-bounded polymorphism.

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
