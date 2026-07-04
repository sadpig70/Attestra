#!/usr/bin/env python3
"""Hash-chain append-only audit ledger (deterministic).

Promoted from ActionHandbackVerifier's ledger. Canonical JSON, no timestamps in
the hash input — record_hash re-computes identically regardless of wall time, so
`now`/`*_at` are metadata only. Tampering is detectable by chain re-verification.
"""

import hashlib
import json
import os


def canonical_json(obj):
    """Canonical JSON: sorted keys, tight separators, no whitespace drift."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_records(ledger_path):
    if not ledger_path or not os.path.exists(ledger_path):
        return []
    records = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def last_record_hash(ledger_path):
    records = _read_records(ledger_path)
    return records[-1]["record_hash"] if records else ""


def next_index(ledger_path):
    return len(_read_records(ledger_path))


def _strip_volatile(result):
    """Drop wall-time metadata so the result hash is time-independent."""
    return {k: v for k, v in result.items() if not (k == "evaluated_at" or k.endswith("_at"))}


def build_record(ledger_path, result, pack, now=""):
    """Build (without writing) the next deterministic chain record."""
    prev = last_record_hash(ledger_path)
    result_hash = sha256(canonical_json(_strip_volatile(result)))
    record = {
        "index": next_index(ledger_path),
        "subject": result.get("subject", ""),
        "pack": pack,
        "verdict": result["verdict"],
        "result_hash": result_hash,
        "prev_hash": prev,
    }
    record["record_hash"] = sha256(canonical_json(record))
    record["recorded_at"] = now  # metadata — excluded from record_hash above
    return record


def append_record(ledger_path, result, pack, now=""):
    """Append a deterministic hash-chain record and return it."""
    record = build_record(ledger_path, result, pack, now=now)
    os.makedirs(os.path.dirname(ledger_path) or ".", exist_ok=True)
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(canonical_json(record) + "\n")
    return record


def verify_ledger(ledger_path):
    """Re-verify chain integrity — detects tampering. Returns {valid, records, error}."""
    records = _read_records(ledger_path)
    prev = ""
    for i, rec in enumerate(records):
        if rec.get("index") != i:
            return {"valid": False, "records": len(records), "error": f"index mismatch at {i}"}
        if rec.get("prev_hash", "") != prev:
            return {"valid": False, "records": len(records), "error": f"broken chain at {i}"}
        core = {k: v for k, v in rec.items() if k not in ("record_hash", "recorded_at")}
        if sha256(canonical_json(core)) != rec.get("record_hash"):
            return {"valid": False, "records": len(records), "error": f"record_hash mismatch at {i}"}
        prev = rec["record_hash"]
    return {"valid": True, "records": len(records), "error": ""}
