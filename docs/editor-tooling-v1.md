# Editor Tooling v1

This document defines the production editor contract for `.fzy` sources.

## Language Token Classes (Frozen)

- Keywords: `fn`, `async`, `test`, `nondet`, `let`, `discard`, `if`, `then`, `else`, `while`, `match`, `return`, `defer`, `requires`, `ensures`, `mod`, `use`, `rpc`, `trait`, `impl`, `for`, `struct`, `enum`, `pub`, `pubext`, `ext`
- Types: `void`, `bool`, `str`, `char`, integer widths (`i8..i128`, `u8..u128`), float widths (`f32`, `f64`)
- Functions: declaration names in `fn` and `rpc` headers
- Struct/Enum symbols: declaration names in `struct`/`enum`
- Variables: `let` bindings
- Literals: strings and integer numbers
- Comments: `//` line comments
- Operators: `->`, `=>`, `==`, `!=`, `<=`, `>=`, `+`, `-`, `*`, `/`, `=`, `<`, `>`

## LSP Surface (Production)

`fz lsp serve` exposes stdio JSON-RPC with:

- Lifecycle: `initialize`, `shutdown`, `exit`
- Sync: `textDocument/didOpen`, `textDocument/didChange` (incremental), `textDocument/didClose`
- Features: diagnostics, hover, definition, completion, references, rename, semantic tokens
- Diagnostics include parser/type/verifier classes and stable severity/range/source payloads.

## VS Code Packaging

`tooling/vscode` ships:

- language registration + file association for `.fzy`
- language configuration (`language-configuration.json`)
- TextMate grammar (`syntaxes/fozzy.tmLanguage.json`)
- LSP client bootstrap (`extension.js`) targeting `fz lsp serve`

## Deterministic Validation Gate

Production validation includes deterministic and strict Fozzy gates.

Required checks:

- `fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json`
- `fozzy test --det --strict tests/*.fozzy.json --seed 4242 --json`
- `./scripts/ship_release_gate.sh`
