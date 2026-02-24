# Dependency Locking v0

## Contract

- Project builds (`fozzyc build|run|test <project>`) enforce a deterministic dependency graph lock.
- Lockfile path: `fozzy.lock`.
- Schema: `fozzylang.lock.v0`.
- Graph hash covers:
  - root package name/version + manifest hash
  - each path dependency name/path/canonical path
  - each dependency package name/version + manifest hash
  - deterministic source tree hash of each dependency

## Drift Policy

- If `fozzy.lock` is missing, it is created automatically.
- If `fozzy.lock` exists and does not match the current dependency graph hash+graph payload, build fails with lockfile drift.
- Drift must be resolved explicitly via:
  - `fozzyc vendor <project>`

## Vendor Workflow

- `fozzyc vendor <project>` is the explicit lock refresh and dependency snapshot step.
- It rewrites `fozzy.lock` from current manifests + dependency source hashes.
- It copies path dependencies into `vendor/<dep_name>`.
- It writes `vendor/fozzy-vendor.json` with:
  - `lockHash`
  - lockfile path
  - per-dependency source and vendor hashes
  - copied package metadata

## Reproducibility Scope

- Hashing ignores ephemeral/build outputs:
  - `.git/`
  - `.fozzyc/`
  - `vendor/`
  - `target/`
- Same project + dependency sources produce the same dependency graph hash.
