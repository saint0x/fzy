# NOJSON

1. Keep compiler, verifier, lowering, typechecking, scheduling, runtime planning, and dependency-resolution state in typed structures. Internal semantics must not use ad hoc JSON blobs as their source of truth.
2. Limit JSON to real boundaries only: CLI JSON output, persisted reports/artifacts, lockfiles, trace files, interop manifests, and external protocol surfaces that are explicitly defined as JSON contracts.
3. Do not introduce `serde_json::Value` or untyped `json!` assembly inside core compilation paths when a typed Rust struct or enum can represent the data. Model the shape first, then serialize at the boundary.
4. When a boundary must emit JSON, define a stable typed payload with named fields, explicit schema/version markers where needed, and deterministic serialization requirements that are covered by tests.
5. Never compute production cache identity, provenance hashes, or replay-significant fingerprints from unstable ad hoc field ordering. If JSON bytes participate in identity, the field order must be intentional, deterministic, and regression-tested.
6. Fozzy framework/application code should keep request/session/domain state typed in memory. JSON parsing and shaping belong in request/response adapters, API presenters, and artifact writers, not in business logic or runtime control flow.
7. Replacing JSON with custom wire formats is only acceptable when the new format is versioned, validated, deterministic, and safe to deploy without silently corrupting or invalidating live state.
8. Production changes that touch typed-vs-JSON boundaries must add or update tests that lock down the contract being relied on: schema shape, field order when identity depends on bytes, replay compatibility, and migration/deploy safety where persisted state is involved.
