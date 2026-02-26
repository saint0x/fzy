# Workspace Policy v1

## Goal

Provide root-level governance with optional per-package overrides.

## Workspace Policy File

Place `fozzy.workspace.toml` at a repository root:

```toml
[policy]
language_tier = "core_v1"
allow_experimental = false
unsafe_enforce_verify = true
unsafe_enforce_release = true

[packages.my_pkg]
language_tier = "experimental"
allow_experimental = true
```

## Merge Rules

- Compiler searches upward from project root for `fozzy.workspace.toml`.
- Root `policy` applies first.
- `packages.<name>` overrides root policy for matching `package.name`.
- Effective values are applied before manifest validation.

## Scope

Current inherited keys:

- `language_tier`
- `allow_experimental`
- `unsafe_enforce_verify`
- `unsafe_enforce_release`
