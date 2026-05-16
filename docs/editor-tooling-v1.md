# Editor Tooling v1

This document defines the production editor contract for `.fzy` sources.

## Language Token Classes (Frozen)

- Keywords: `fn`, `async`, `test`, `nondet`, `let`, `discard`, `if`, `then`, `else`, `while`, `match`, `return`, `defer`, `requires`, `ensures`, `mod`, `use`, `rpc`, `trait`, `impl`, `for`, `struct`, `enum`, `type`, `newtype`, `dyn`, `pub`, `pubext`, `ext`
- Types: `void`, `bool`, `str`, `char`, `bytes`, integer widths (`i8..i128`, `u8..u128`), float widths (`f32`, `f64`), and production domain/generic surfaces (for example `Future<T>`, `Map<K,V>`, `Set<T>`, `Deque<T>`, `Ring<T>`, `Path`, `Url`, `Duration`, `DateTimeTz`, `Decimal`, `Uuid`)
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
- Features: diagnostics, hover, definition, completion, signatureHelp, references, rename, inlayHint, semantic tokens, documentSymbol, workspaceSymbol, codeAction
- Diagnostics include parser/type/verifier classes and stable severity/range/source payloads.

## Browser DX Surface

`fz dev-server [path] [--entry path] [--host addr] [--port N]` is the browser-target development surface for frontend iteration.

The dev server contract is:

- Serves browser assets from the project root or `public/` when present.
- Injects `GET /__fz/overlay.js` into HTML responses for compiler/runtime overlays.
- Exposes `GET /__fz/health` for readiness checks.
- Exposes `GET /__fz/diagnostics` for browser-target diagnostic payloads derived from the shared CLI/LSP diagnostic model.
- Exposes `GET /__fz/events` as the live-reload/HMR transport channel.
- Accepts `POST /__fz/runtime-error` for surfaced browser runtime failures.
- Accepts `POST /__fz/runtime-error/clear` to clear overlay runtime failures during local iteration.

Current HMR transport behavior is conservative by design:

- The transport emits `hmr` events with a defined fallback strategy of `reload`.
- Runtime patch boundaries remain owned by the runtime/loader contract; this server only transports change notifications and browser diagnostics.

## JS Interop Contract

Browser/package interop stays explicit and documented rather than implicit.

- Fzy-emitted browser modules remain the ABI source of truth for Fzy symbols.
- Imported JavaScript/npm modules are treated as foreign-module boundaries that must be named explicitly and typed deliberately.
- Source-mapped browser overlays prefer original frame metadata when runtime or sourcemap tooling provides it.
- Package resolution strategy for browser projects is ESM-first and bundler-compatible: emitted modules must remain loadable by direct browser ESM, Vite, Rollup, ESBuild, and Bun-compatible loaders.
- Foreign-module typing is a contract surface, not an inference surface. Tooling should surface missing or ambiguous foreign boundaries rather than guessing.

## VS Code Packaging

`tooling/vscode` ships:

- language registration + file association for `.fzy`
- language configuration (`language-configuration.json`)
- TextMate grammar (`syntaxes/fozzy.tmLanguage.json`)
- LSP client bootstrap (`extension.js`) targeting `fz lsp serve`
- editor workflows that can pair with `fz dev-server` for browser-target iteration

## Deterministic Validation Gate

Production validation includes deterministic and strict Fozzy gates.

Required checks:

- `fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json`
- `fozzy test --det --strict tests/*.fozzy.json --seed 4242 --json`
- `fozzy test --det --strict tests/browser_debug_js_sourcemap.pass.fozzy.json --seed 4242 --json`
- `./scripts/browser_dev_server_smoke.sh`
- `./scripts/ship_release_gate.sh`
