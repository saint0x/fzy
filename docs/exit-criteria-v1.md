# Exit Criteria Tracking v1

This document defines the production tracking and exit criteria workflow.

## Source of Truth

State file:

- `release/exit_criteria_state.json`

Tracker command:

- `scripts/exit_criteria.py`

Strict gate wrapper:

- `scripts/exit_criteria_gate.sh`

## Criteria Model

The tracker computes readiness from four enforced criteria:

1. Workspace + `driver` green streak of 14 consecutive recorded days.
2. Pedantic hotspot closure (`uncoveredHotspotCount=0`) across the two most recent recorded release candidates.
3. Local clean-checkout reproducibility pass (`scripts/ship_release_gate.sh` executed from an archived checkout).
4. Blocker sections in `PLAN.md` fully closed.

`seriousSystemsLanguageMaturity=true` only when all four are true.

## Commands

Record daily workspace evidence:

```bash
python3 scripts/exit_criteria.py record-day
```

Record release-candidate hotspot closure:

```bash
python3 scripts/exit_criteria.py record-rc --rc-id rc-2026-02-25.1
```

Record local clean-checkout reproducibility (requires clean working tree unless `--allow-dirty`):

```bash
python3 scripts/exit_criteria.py record-local-repro
```

View status:

```bash
python3 scripts/exit_criteria.py status
```

Strict fail-unless-ready gate:

```bash
./scripts/exit_criteria_gate.sh
```

## Policy Notes

- CI evidence is intentionally not required in this local workflow.
- The tracker is strict: missing/dirty evidence does not count toward readiness.
- Re-running a record command updates evidence for the same date (`record-day`) or same RC id (`record-rc`).
- Safety claim integrity is release-blocking through `scripts/safety_claim_integrity_gate.py` (wired by `scripts/ship_release_gate.sh` and production gate workflow).
