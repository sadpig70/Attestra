#!/usr/bin/env python3
"""Attestation event ledger — hash-chained issue/revoke events (deterministic).

Same chain discipline as the verdict ledger: canonical JSON, record_hash excludes
wall-time metadata, tamper-evident. An attestation is 'revoked' if a revoke event
for its id appears in the ledger. now is injected metadata, never a clock read.
"""

import json
import os

from .ledger import canonical_json, sha256


def _read(ledger_path):
    if not ledger_path or not os.path.exists(ledger_path):
        return []
    records = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def append_event(ledger_path, event, *, attestation_id, subject="", pack=None,
                 grade=None, reason="", now=""):
    """Append one issue/revoke event as a hash-chain record."""
    records = _read(ledger_path)
    prev = records[-1]["record_hash"] if records else ""
    record = {
        "index": len(records), "event": event, "attestation_id": attestation_id,
        "subject": subject, "pack": pack, "grade": grade, "reason": reason,
        "prev_hash": prev,
    }
    record["record_hash"] = sha256(canonical_json(record))
    record["recorded_at"] = now  # metadata — excluded from record_hash above
    os.makedirs(os.path.dirname(ledger_path) or ".", exist_ok=True)
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(canonical_json(record) + "\n")
    return record


def record_issue(ledger_path, attestation, now=""):
    return append_event(ledger_path, "issue", attestation_id=attestation["attestation_id"],
                        subject=attestation.get("subject", ""), pack=attestation.get("pack"),
                        grade=attestation.get("grade"), now=now)


def record_revoke(ledger_path, attestation_id, reason="", now=""):
    return append_event(ledger_path, "revoke", attestation_id=attestation_id,
                        reason=reason, now=now)


def revoked_ids(ledger_path):
    """Set of attestation_ids that have a revoke event."""
    return {r["attestation_id"] for r in _read(ledger_path) if r.get("event") == "revoke"}


def list_events(ledger_path):
    return _read(ledger_path)


def verify_attestation_ledger(ledger_path):
    """Chain integrity check — detects tampering. Returns {valid, records, error}."""
    records = _read(ledger_path)
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
