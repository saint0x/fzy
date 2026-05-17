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
- Exposes `GET /__fz/build/<artifact>` for emitted browser JS artifacts tied to the configured entry source.
- Exposes `GET /__fz/source/<graph-relative-path>` for original `.fzy` module source content referenced by emitted browser sourcemaps.
- Accepts `POST /__fz/runtime-error` for surfaced browser runtime failures.
- Accepts `POST /__fz/runtime-error/clear` to clear overlay runtime failures during local iteration.
- When an entry `.fzy` source is configured, runtime error ingestion enriches emitted-JS frames from the generated sourcemap before overlays render them.

Current HMR transport behavior is conservative by design:

- The transport emits `hmr` events with a defined fallback strategy of `reload`.
- Changed-file detection follows the official parsed module graph for the configured entry source rather than a second browser-only dependency graph.
- Runtime patch boundaries remain owned by the runtime/loader contract; this server only transports change notifications and browser diagnostics.
- Unsafe or ambiguous patch cases fall back to full reload rather than claiming state preservation.
- The browser overlay script exposes `window.__fozzyHot` boundary hooks so reload-safe state capture/restore stays explicit instead of hiding implicit patch behavior in the compiler.
- Production DX budgets are gated with `scripts/browser_incremental_budget_gate.py` and `scripts/browser_editor_responsiveness_gate.sh`:
  - compile/rebuild budgets use the recorded browser compile-bench artifact
  - editor responsiveness budgets use the `fz lsp` diagnostics/definition/hover/smoke path on a browser-target sample project
- The current v1 browser ESM model does not require a separate loader manifest: emitted JS artifacts, sourcemaps, and original source URLs are served directly from the official module graph and native browser ESM resolution surface.

## JS Interop Contract

Browser/package interop stays explicit and documented rather than implicit.

- Fzy-emitted browser modules remain the ABI source of truth for Fzy symbols.
- Dynamic `import(...)` is a supported browser-target call surface and lowers directly to emitted ESM `import(...)` rather than a backend-local shim.
- Browser-native code splitting and lazy loading are exercised through those preserved dynamic `import(...)` boundaries rather than a browser-only compiler path.
- Imported JavaScript/npm modules are treated as foreign-module boundaries that must be named explicitly and typed deliberately.
- Source-mapped browser overlays render original file/line/column metadata when sourcemap enrichment resolves emitted JS frames.
- Package resolution strategy for browser projects is ESM-first and bundler-compatible: emitted modules must remain loadable by direct browser ESM, Vite, Rollup, ESBuild, and Bun-compatible loaders.
- Foreign-module typing is a contract surface, not an inference surface. Tooling should surface missing or ambiguous foreign boundaries rather than guessing.
- Production compatibility smoke: `scripts/browser_js_compat_smoke.sh` verifies direct browser loading in Chromium plus bundler/build compatibility across Vite, Rollup, ESBuild, and Bun for the emitted JS artifact.
- Browser scheduler compatibility smoke: `scripts/browser_scheduler_compat_smoke.sh` verifies that emitted browser JS can execute against a browser runtime stub with preserved microtask-vs-timer ordering and cancellation semantics for the supported scheduler surface.
- Browser hot-runtime smoke: `scripts/browser_hot_runtime_smoke.sh` verifies that `window.__fozzyHot` boundary registration, pre-reload capture, and post-reload state restore stay stable in a real browser.
- Browser DevTools sourcemap smoke: `scripts/browser_devtools_sourcemap_smoke.sh` launches Chromium headless, attaches the real local DevTools frontend to the browser target, verifies that the authored `.fzy` source is present in the DevTools workspace, sets an authored-source breakpoint, and proves that the raw pause in emitted `main.js` maps back to the original `.fzy` UI location.
- Framework-on-core proof: `python3 scripts/verify_fzweb_framework.py` keeps the in-repo framework package building above the language/runtime primitives without pushing component or UI abstractions into compiler core.

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
- `./scripts/browser_devtools_sourcemap_smoke.sh`
- `./scripts/ship_release_gate.sh`
