# Fozzy VS Code Extension

This extension provides:
- `.fzy` language registration
- TextMate syntax highlighting
- LSP client bootstrap to `fz lsp serve`
- compatibility with browser-target workflows that run `fz dev-server` alongside the editor
- browser overlay and source-mapped diagnostics workflows driven by `fz debug-check` and `fz dev-server`

## Development

1. `cd tooling/vscode`
2. `npm install`
3. Launch the extension host from VS Code.

## Settings

- `fozzy.fzPath`: optional custom path to `fz` binary.
