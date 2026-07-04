#!/usr/bin/env python3
"""Verdict severity algebra (valid < thin < breach) and CheckResult constructors.

Deterministic: pure functions, no clock/network/AI. Lifted and generalized from
the HELIX corpus governance/trust cluster (single source of truth for all packs).
"""

SEVERITY = {"valid": 0, "thin": 1, "breach": 2}  # higher = more severe


def _check(gate, verdict, reason, evidence_path=""):
    return {
        "gate": gate,
        "verdict": verdict,
        "reason": reason,
        "evidence_path": evidence_path or "",
        "evidence_ok": verdict != "breach",
    }


def valid(gate, evidence_path=""):
    return _check(gate, "valid", "predicate satisfied", evidence_path)


def thin(gate, reason, evidence_path=""):
    return _check(gate, "thin", reason, evidence_path)


def breach(gate, reason, evidence_path=""):
    return _check(gate, "breach", reason, evidence_path)


def missing(required, obj):
    """Return required keys absent or empty in obj (deterministic)."""
    if not isinstance(obj, dict):
        return list(required)
    return [k for k in required if k not in obj or obj[k] in ("", None)]


def thin_or_breach(gate, missing_fields):
    """Missing evidence_path is a breach; other missing fields are thin."""
    fields = ", ".join(missing_fields)
    if "evidence_path" in missing_fields:
        return breach(gate, f"missing evidence path; also missing: {fields}")
    return thin(gate, f"missing fields: {fields}")


def aggregate_verdict(checks):
    """Aggregate CheckResults to the highest severity (breach > thin > valid).

    Order-independent: pure max over severity. Returns the worst check's context.
    """
    if not checks:
        return {"verdict": "thin", "reason": "no_checks", "worst": None}
    worst = max(checks, key=lambda c: SEVERITY[c["verdict"]])
    return {"verdict": worst["verdict"], "reason": worst["reason"], "worst": worst["gate"]}
