# Dependency Locking v1

## Contract

- Project builds (`fz build|run|test [project]`) enforce a deterministic dependency graph lock.
- Lockfile path: `fozzy.lock`.
- Schema: `fozzylang.lock.v0`.
- Graph hash covers:
  - root package name/version + manifest hash
  - each local dependency name + normalized project-relative path identity
  - each dependency package name/version + manifest hash (path dependencies)
  - deterministic source tree hash of each path dependency
  - version/source identity hash for versioned dependencies
  - git/rev identity hash for git dependencies

## Drift Policy

- If `fozzy.lock` is missing, it is created automatically.
- If `fozzy.lock` exists and does not match the current dependency graph hash+graph payload, build fails with lockfile drift.
- Drift must be resolved explicitly via:
  - `fz vendor [project]`

## Vendor Workflow

- `fz vendor [project]` is the explicit lock refresh and dependency snapshot step.
- `fz vendor [project] --check` is the no-write verifier for frozen lock state plus any checked-in vendor snapshot.
- It rewrites `fozzy.lock` from current manifests + dependency source hashes.
- It copies path dependencies into `vendor/<dep_name>`.
- It records version/git dependencies in `vendor/fozzy-vendor.json` as lock-pinned, non-vendored sources.
- Checked-in lock/vendor artifacts must serialize local paths in normalized project-relative form rather than machine-specific absolute paths.
- It writes `vendor/fozzy-vendor.json` with:
  - `lockHash`
  - relative lockfile path
  - per-dependency relative source/target paths plus source/vendor hashes
  - copied package metadata

## Reproducibility Scope

- Hashing ignores ephemeral/build outputs:
  - `.git/`
  - `.fz/`
  - `vendor/`
  - `target/`
- Same project + dependency sources produce the same dependency graph hash.
