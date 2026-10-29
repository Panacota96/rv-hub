#!/usr/bin/env python3
"""Writes tampered copies of the sample case (examples/sample/case) for `rv-hub verify` tests.

Usage: python3 tests/samples/make_tampered.py OUT_DIR [--case DIR] [--evidence DIR]

Standard library only. Each variant is OUT_DIR/<variant>/case (a full copy of the case folder) and
OUT_DIR/<variant>/evidence (a copy of the evidence, for --rehash --evidence-dir). The variants and the finding
codes `rv-hub verify` must report for each are listed in examples/sample/expected_findings.json.

  clean                   unchanged copy
  case_log_line_edited    one case-log line edited (the actor of the rv-pdfauth run_started entry)
  run_audit_entry_edited  one audit entry of the rv-pdfauth run edited (its run_started actor)
  run_folder_deleted      the rv-pdfauth run folder removed (the case log still announces it)
  run_unlinked            the last run's run_started / run_finished removed from the case log and the
                          case log re-chained, so the chain is intact and only the link is missing
  review_reanchored       a review.jsonl added to the rv-imgauth run, consistently chained but anchored to
                          its run_started entry instead of run_finished. (rv-imgauth writes review.jsonl from its
                          GUI viewer only, so the CLI-made sample has none: the log is built here with the same
                          rules as rv-imgauth's review.rs, then re-anchored.)
  evidence_byte_changed   one byte of the evidence copy contrato.pdf changed (detected with --rehash)

Prints a JSON object {variant: path} on stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

GENESIS = "0" * 64


def canon(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(entry: dict) -> str:
    e = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(canon(e)).hexdigest()


def line(entry: dict) -> str:
    return canon(entry).decode("utf-8")


def read_jsonl(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def write_jsonl(p: Path, entries: list[dict]) -> None:
    p.write_text("".join(line(e) + "\n" for e in entries), encoding="utf-8")


def rechain(entries: list[dict]) -> list[dict]:
    """Renumbers and re-hashes a chain (seq from 1, prev_entry_hash links) after entries were removed."""
    prev, out = GENESIS, []
    for n, e in enumerate(entries, 1):
        e = dict(e)
        e["seq"], e["prev_entry_hash"] = n, prev
        e["entry_hash"] = entry_hash(e)
        prev = e["entry_hash"]
        out.append(e)
    return out


def run_dir(case: Path, tool: str) -> Path:
    runs = sorted(p for p in (case / "runs" / tool).iterdir() if p.is_dir())
    if len(runs) != 1:
        sys.exit(f"expected one {tool} run in {case}, found {len(runs)}")
    return runs[0]


def edit_first(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        sys.exit(f"{path}: {old!r} not found")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def case_log_line_edited(case: Path, _ev: Path) -> None:
    log = case / "case-log.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    i = next(n for n, x in enumerate(lines) if json.loads(x)["action"] == "run_started" and '"tool":"rv-pdfauth"' in x)
    e = json.loads(lines[i])
    lines[i] = lines[i].replace(json.dumps(e["actor"]), json.dumps("Mallory"), 1)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_audit_entry_edited(case: Path, _ev: Path) -> None:
    audit = run_dir(case, "rv-pdfauth") / "logs" / "audit.jsonl"
    first = read_jsonl(audit)[0]
    edit_first(audit, '"actor":' + json.dumps(first["actor"]), '"actor":"Mallory"')


def run_folder_deleted(case: Path, _ev: Path) -> None:
    shutil.rmtree(run_dir(case, "rv-pdfauth"))


def run_unlinked(case: Path, _ev: Path) -> None:
    log = case / "case-log.jsonl"
    entries = read_jsonl(log)
    last_run = next(e["run_id"] for e in reversed(entries) if e["action"] == "run_started")
    kept = [e for e in entries if not (e["run_id"] == last_run and e["action"] in ("run_started", "run_finished"))]
    write_jsonl(log, rechain(kept))


def review_reanchored(case: Path, _ev: Path) -> None:
    logs = run_dir(case, "rv-imgauth") / "logs"
    audit = read_jsonl(logs / "audit.jsonl")
    wrong = audit[0]  # run_started, not run_finished
    prev, out = wrong["entry_hash"], []
    for n, item in enumerate(["00001-captura.png", "00002-foto-1.jpg"], 1):
        e = {"seq": n, "at_utc": "2026-10-29T12:00:0%dZ" % n, "run_id": wrong["run_id"], "actor": "Mallory",
             "action": "ui_map_viewed", "details": {"item": item, "map": "maps/original.png"}}
        if n == 1:
            e["anchor_seq"], e["anchor_hash"] = wrong["seq"], wrong["entry_hash"]
        e["prev_entry_hash"] = prev
        e["entry_hash"] = entry_hash(e)
        prev = e["entry_hash"]
        out.append(e)
    write_jsonl(logs / "review.jsonl", out)


def evidence_byte_changed(_case: Path, ev: Path) -> None:
    p = ev / "contrato.pdf"
    b = bytearray(p.read_bytes())
    b[len(b) // 2] ^= 0x01
    p.write_bytes(bytes(b))


VARIANTS = {
    "clean": None,
    "case_log_line_edited": case_log_line_edited,
    "run_audit_entry_edited": run_audit_entry_edited,
    "run_folder_deleted": run_folder_deleted,
    "run_unlinked": run_unlinked,
    "review_reanchored": review_reanchored,
    "evidence_byte_changed": evidence_byte_changed,
}


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", type=Path)
    ap.add_argument("--case", type=Path, default=root / "examples" / "sample" / "case")
    ap.add_argument("--evidence", type=Path, default=root / "examples" / "sample" / "evidence")
    a = ap.parse_args()
    written = {}
    for name, fn in VARIANTS.items():
        d = a.out / name
        if d.exists():
            shutil.rmtree(d)
        shutil.copytree(a.case, d / "case")
        shutil.copytree(a.evidence, d / "evidence")
        if fn:
            fn(d / "case", d / "evidence")
        written[name] = str(d)
    print(json.dumps(written, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
