# Operational Insights v1

## Lint Tiers

Command:

```bash
fz lint [path] --tier production|pedantic|compat
```

- `production`: strict production posture checks.
- `pedantic`: additional style/scheduler-pressure warnings.
- `compat`: migration/deprecation warnings.

## Perf Summary

Command:

```bash
fz perf [--artifact artifacts/bench_corelibs_rust_vs_fzy.json]
```

Outputs:

- benchmark count
- average `ratio_fzy_over_rust`
- worst kernel ratio

## Stability Dashboard

Command:

```bash
fz stability-dashboard
```

Artifact:

- `artifacts/stability_dashboard.json`

Dashboard includes:

- maturity flag from exit criteria
- criteria details
- source pointers for auditability
