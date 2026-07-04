#!/usr/bin/env python3
"""Provenance — deterministic trace of how a verdict was reached.

Walks the check results and pack lineage into a compact, public trace embedded in
the attestation. No clock/network/AI.
"""

from .ledger import canonical_json, sha256


def digest_checks(checks):
    """Order-independent digest of the per-gate verdicts (deterministic)."""
    surface = sorted(
        ({"gate": c.get("gate"), "verdict": c.get("verdict")} for c in checks),
        key=lambda x: (str(x["gate"]), str(x["verdict"])),
    ) if checks else []
    return sha256(canonical_json(surface))


def trace_provenance(result, chain=None):
    """Build a public provenance trace from a run_gates result.

    chain optionally supplies source lineage (pack -> source_project -> corpus).
    """
    chain = chain or {}
    gates = [
        {"gate": c.get("gate"), "verdict": c.get("verdict"), "reason": c.get("reason")}
        for c in result.get("checks", [])
    ]
    return {
        "subject": result.get("subject", ""),
        "pack": result.get("pack") or chain.get("pack"),
        "source_project": chain.get("source_project"),
        "gates": gates,
        "worst": result.get("worst"),
    }
