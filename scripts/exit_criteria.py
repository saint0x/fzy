#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Tuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
STATE_PATH = ROOT / "release" / "exit_criteria_state.json"
PLAN_PATH = ROOT / "PLAN.md"

SCHEMA_VERSION = "fozzylang.exit_criteria.v1"

BLOCKER_SECTIONS = [
    "### Release Gate Unification (Blockers)",
    "### Systems Language Semantics Parity",
    "### Memory Safety Hardening Depth",
    "### Bidirectional Trace/Interop Closure",
    "### Tooling + DX Solidification (High Value, Not Overkill)",
    "### Core Stdlib Expansion Priorities (`core`)",
]


def run(cmd: List[str], cwd: pathlib.Path = ROOT, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), check=check, text=True, capture_output=True)


def utc_now_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_state() -> Dict[str, Any]:
    if not STATE_PATH.exists():
        return {
            "schemaVersion": SCHEMA_VERSION,
            "daily": [],
            "releaseCandidates": [],
            "localRepro": [],
        }
    payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        raise SystemExit(
            f"unsupported exit-criteria state schema: {payload.get('schemaVersion')}"
        )
    payload.setdefault("daily", [])
    payload.setdefault("releaseCandidates", [])
    payload.setdefault("localRepro", [])
    return payload


def save_state(state: Dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def upsert_by_key(rows: List[Dict[str, Any]], key: str, value: str, row: Dict[str, Any]) -> None:
    for idx, existing in enumerate(rows):
        if existing.get(key) == value:
            rows[idx] = row
            return
    rows.append(row)


def record_day(args: argparse.Namespace) -> int:
    date = args.date or dt.date.today().isoformat()
    workspace_green = True
    driver_green = True
    diagnostics: List[Dict[str, Any]] = []

    for cmd, label in [
        (["cargo", "test", "--workspace"], "workspace"),
        (["cargo", "test", "-p", "driver"], "driver"),
    ]:
        proc = subprocess.run(cmd, cwd=str(ROOT), text=True, capture_output=True)
        ok = proc.returncode == 0
        diagnostics.append(
            {
                "label": label,
                "ok": ok,
                "returncode": proc.returncode,
                "stdoutTail": "\n".join(proc.stdout.splitlines()[-20:]),
                "stderrTail": "\n".join(proc.stderr.splitlines()[-20:]),
            }
        )
        if label == "workspace":
            workspace_green = ok
        if label == "driver":
            driver_green = ok

    state = load_state()
    upsert_by_key(
        state["daily"],
        "date",
        date,
        {
            "date": date,
            "workspaceGreen": workspace_green,
            "driverGreen": driver_green,
            "recordedAt": utc_now_iso(),
            "checks": diagnostics,
        },
    )
    state["daily"] = sorted(state["daily"], key=lambda row: row["date"])
    save_state(state)

    print(json.dumps({"date": date, "workspaceGreen": workspace_green, "driverGreen": driver_green}, indent=2))
    return 0 if (workspace_green and driver_green) else 2


def record_rc(args: argparse.Namespace) -> int:
    rc_id = args.rc_id
    if not rc_id:
        raise SystemExit("record-rc requires --rc-id")
    date = args.date or dt.date.today().isoformat()

    proc = run(
        [
            "fozzy",
            "map",
            "suites",
            "--root",
            ".",
            "--scenario-root",
            "tests",
            "--profile",
            "pedantic",
            "--json",
        ],
        check=True,
    )
    payload = json.loads(proc.stdout)
    required = int(payload.get("requiredHotspotCount", 0))
    uncovered = int(payload.get("uncoveredHotspotCount", 0))

    state = load_state()
    upsert_by_key(
        state["releaseCandidates"],
        "id",
        rc_id,
        {
            "id": rc_id,
            "date": date,
            "requiredHotspotCount": required,
            "uncoveredHotspotCount": uncovered,
            "recordedAt": utc_now_iso(),
        },
    )
    state["releaseCandidates"] = sorted(
        state["releaseCandidates"], key=lambda row: (row["date"], row["id"])
    )
    save_state(state)

    print(json.dumps({"id": rc_id, "requiredHotspotCount": required, "uncoveredHotspotCount": uncovered}, indent=2))
    return 0 if uncovered == 0 else 2


def ensure_clean_checkout() -> Tuple[bool, str]:
    proc = subprocess.run(["git", "status", "--porcelain"], cwd=str(ROOT), text=True, capture_output=True)
    if proc.returncode != 0:
        return False, "failed to query git status"
    if proc.stdout.strip():
        return False, "working tree is dirty; clean checkout reproducibility requires committed state"
    return True, "clean"


def record_local_repro(args: argparse.Namespace) -> int:
    if not args.allow_dirty:
        ok, detail = ensure_clean_checkout()
        if not ok:
            print(json.dumps({"ok": False, "detail": detail}, indent=2))
            return 2

    commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="fozzylang-clean-repro-"))
    try:
        run(["git", "worktree", "add", "--detach", str(tmp_dir), "HEAD"], check=True)

        gate_path = tmp_dir / "scripts" / "ship_release_gate.sh"
        if not gate_path.exists():
            gate_path = tmp_dir / "scripts" / "fozzy_production_gate.sh"
        proc = subprocess.run(
            [str(gate_path)],
            cwd=str(tmp_dir),
            text=True,
            capture_output=True,
        )
        ok = proc.returncode == 0
        row = {
            "date": args.date or dt.date.today().isoformat(),
            "commit": commit,
            "ok": ok,
            "recordedAt": utc_now_iso(),
            "stdoutTail": "\n".join(proc.stdout.splitlines()[-40:]),
            "stderrTail": "\n".join(proc.stderr.splitlines()[-40:]),
        }
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(tmp_dir)],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
        )
        shutil.rmtree(tmp_dir, ignore_errors=True)

    state = load_state()
    state["localRepro"].append(row)
    state["localRepro"] = sorted(state["localRepro"], key=lambda item: item["recordedAt"])
    save_state(state)
    print(json.dumps({"ok": row["ok"], "commit": commit, "date": row["date"]}, indent=2))
    return 0 if row["ok"] else 2


def parse_section_checklist_status() -> Dict[str, Dict[str, Any]]:
    text = PLAN_PATH.read_text(encoding="utf-8")
    lines = text.splitlines()
    result: Dict[str, Dict[str, Any]] = {}
    for section in BLOCKER_SECTIONS:
        start = None
        for idx, line in enumerate(lines):
            if line.strip() == section:
                start = idx + 1
                break
        if start is None:
            result[section] = {"found": False, "open": []}
            continue
        end = len(lines)
        for idx in range(start, len(lines)):
            if lines[idx].startswith("### "):
                end = idx
                break
        open_items = [line.strip() for line in lines[start:end] if line.strip().startswith("- [ ]")]
        result[section] = {"found": True, "open": open_items}
    return result


def compute_green_streak_days(daily_rows: List[Dict[str, Any]]) -> int:
    if not daily_rows:
        return 0
    parsed: List[Tuple[dt.date, bool]] = []
    for row in daily_rows:
        try:
            date = dt.date.fromisoformat(row["date"])
        except Exception:
            continue
        ok = bool(row.get("workspaceGreen")) and bool(row.get("driverGreen"))
        parsed.append((date, ok))
    parsed.sort(key=lambda item: item[0])
    if not parsed:
        return 0

    streak = 0
    prev_date = None
    for date, ok in parsed:
        if not ok:
            streak = 0
            prev_date = date
            continue
        if prev_date is None:
            streak = 1
        else:
            delta = (date - prev_date).days
            if delta == 1:
                streak += 1
            elif delta == 0:
                pass
            else:
                streak = 1
        prev_date = date
    return streak


def compute_status() -> Dict[str, Any]:
    state = load_state()
    section_status = parse_section_checklist_status()

    green_streak_days = compute_green_streak_days(state.get("daily", []))
    green_14 = green_streak_days >= 14

    rc_rows = sorted(
        state.get("releaseCandidates", []), key=lambda row: (row.get("date", ""), row.get("id", ""))
    )
    rc_two = False
    if len(rc_rows) >= 2:
        last_two = rc_rows[-2:]
        rc_two = all(int(item.get("uncoveredHotspotCount", 1)) == 0 for item in last_two)

    local_rows = sorted(state.get("localRepro", []), key=lambda row: row.get("recordedAt", ""))
    local_ok = bool(local_rows and local_rows[-1].get("ok") is True)

    blocker_sections_complete = all(
        info.get("found") and len(info.get("open", [])) == 0 for info in section_status.values()
    )

    maturity_ready = green_14 and rc_two and local_ok and blocker_sections_complete

    return {
        "schemaVersion": SCHEMA_VERSION,
        "criteria": {
            "workspaceGreen14ConsecutiveDays": {
                "ok": green_14,
                "streakDays": green_streak_days,
                "requiredDays": 14,
            },
            "pedanticClosureTwoConsecutiveReleaseCandidates": {
                "ok": rc_two,
                "totalRecordedReleaseCandidates": len(rc_rows),
                "lastTwo": rc_rows[-2:] if len(rc_rows) >= 2 else rc_rows,
            },
            "localCleanCheckoutReproducibility": {
                "ok": local_ok,
                "latest": local_rows[-1] if local_rows else None,
            },
            "blockerSectionsComplete": {
                "ok": blocker_sections_complete,
                "sections": section_status,
            },
        },
        "seriousSystemsLanguageMaturity": maturity_ready,
    }


def status_cmd(args: argparse.Namespace) -> int:
    status = compute_status()
    print(json.dumps(status, indent=2, sort_keys=True))
    if args.strict and not status.get("seriousSystemsLanguageMaturity"):
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Track and enforce production exit criteria")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_day = sub.add_parser("record-day", help="Run workspace + driver tests and record daily streak evidence")
    p_day.add_argument("--date", help="ISO date override")
    p_day.set_defaults(func=record_day)

    p_rc = sub.add_parser("record-rc", help="Record a release candidate pedantic hotspot snapshot")
    p_rc.add_argument("--rc-id", required=True, help="Release candidate identifier (e.g. rc-2026-03-01.1)")
    p_rc.add_argument("--date", help="ISO date override")
    p_rc.set_defaults(func=record_rc)

    p_repro = sub.add_parser(
        "record-local-repro",
        help="Run ship gate on a clean archived checkout and record reproducibility evidence",
    )
    p_repro.add_argument("--date", help="ISO date override")
    p_repro.add_argument("--allow-dirty", action="store_true", help="Allow dirty tree when recording local reproducibility")
    p_repro.set_defaults(func=record_local_repro)

    p_status = sub.add_parser("status", help="Show computed exit-criteria status")
    p_status.add_argument("--strict", action="store_true", help="Exit non-zero unless maturity criteria are satisfied")
    p_status.set_defaults(func=status_cmd)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
