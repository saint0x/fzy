# Snapshot Builds v1

## Contract

Snapshot builds are the production mechanism for isolated parallel compilation of one codebase.

The contract is:

- every build runs against a frozen snapshot, not against the mutable live checkout
- every snapshot gets its own build root and final artifact paths
- unchanged modules are reused across snapshots through a shared content-addressed object store
- changed modules rebuild independently
- diagnostics and incremental reports are remapped back to the original source paths

This is the supported alternative to per-agent worktrees for build isolation when multiple agents are collaborating on the same project.

## Snapshot Model

A snapshot is created from the saved project state at build start.

Operationally:

1. agent saves source changes
2. build captures a frozen snapshot from that saved state
3. compiler resolves modules from the snapshot tree
4. final outputs are emitted under the snapshot build root
5. reusable module objects are pulled from or written to the shared object store

This means two agents can save different states of the same project and compile them in parallel without reading each other's later edits during build execution.

## Identity Model

The implementation uses two levels of identity.

### 1. Snapshot Identity

The snapshot hash identifies the full build view.

It covers:

- project source files
- `fozzy.toml`
- `fozzy.lock`
- path dependency source trees
- path dependency manifests
- workspace policy files such as `fozzy.workspace.toml`
- compiler/package version inputs used by the snapshot schema

The snapshot hash is used for:

- snapshot tree path
- snapshot-local build root
- final artifact isolation

### 2. Unit Identity

The unit hash identifies one reusable compiled module object.

It covers:

- stable module identity
- backend
- build profile
- module source fingerprint
- global interface fingerprint
- manifest fingerprint
- local function/global ownership for the emitted object slice

The unit hash is used for:

- cross-snapshot object reuse
- avoiding rebuilds for unchanged modules

## Storage Layout

The production layout is:

```text
.fz/
  snapshots/
    <snapshot-hash>/
      tree/
        <project snapshot tree>
  cache/
    obj/
      <shard>/
        <unit-hash>.o
```

Important properties:

- snapshot-local outputs are isolated under `.fz/snapshots/<snapshot-hash>/...`
- reusable objects are shared under `.fz/cache/obj/...`
- object reuse is content-addressed, not rooted in one mutable incremental directory

## Parallelism

Parallelism works in two layers:

- different snapshots compile in parallel because they have isolated build roots
- identical modules reuse shared objects instead of recompiling

This is intentionally different from the older shared-root incremental model:

- old model: one mutable incremental root, concurrency protected by locking
- snapshot model: isolated per-snapshot roots plus shared content-addressed reuse

The remaining lock scope is for publishing shared objects safely, not for serializing all snapshot builds through one mutable build directory.

## What This Solves

Snapshot builds solve:

- agent A compiling snapshot A while agent B compiles snapshot B
- stable build-time source views for each agent
- cross-snapshot reuse for unchanged modules
- no output-path collisions between different build states
- no shared incremental-cache corruption

## What This Does Not Require

Snapshot builds do not require:

- a separate git worktree per agent
- a separate full checkout per agent
- one mutable incremental directory shared by all builds

The model assumes that a save is the boundary that creates the next buildable snapshot.

## Validation

Minimum validation commands:

```bash
cargo check -q
cargo test -q -p driver incremental_build_
fozzy doctor --deep --scenario tests/pedantic.crates_driver.pipeline.host_backends_run.pass.fozzy.json --runs 5 --seed 4242 --json
fozzy test --det --strict-verify tests/pedantic.crates_driver.pipeline.host_backends_run.pass.fozzy.json --json
fozzy run tests/pedantic.crates_driver.pipeline.host_backends_run.pass.fozzy.json --det --record /tmp/fozzylang-snapshot-prod.trace.fozzy --proc-backend host --fs-backend host --http-backend host --json
fozzy trace verify /tmp/fozzylang-snapshot-prod.trace.fozzy --strict --json
fozzy replay /tmp/fozzylang-snapshot-prod.trace.fozzy --json
fozzy ci /tmp/fozzylang-snapshot-prod.trace.fozzy --json
```

## References

- `crates/driver/src/pipeline/snapshot.rs`
- `crates/driver/src/pipeline/native_emit/incr.rs`
- `crates/driver/src/pipeline/compile/build/bin.rs`
- `crates/driver/src/pipeline/compile/build/lib.rs`
- `crates/driver/src/command/tests.rs`
