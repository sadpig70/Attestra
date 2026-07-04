#!/usr/bin/env python3
"""Attestation issuance — a valid/thin verdict becomes an issuable warrant.

Generalizes the corpus 'provenance warrant' idea. breach never issues. The
attestation_id is a digest of the body, so re-issuing the same result yields the
same id (idempotent). issued_at is metadata, excluded from the id.
"""

from .ledger import canonical_json, sha256
from .provenance import digest_checks, trace_provenance


def issue_attestation(result, chain=None, now=""):
    """Issue an attestation for a non-breach verdict; return None on breach."""
    if result.get("verdict") == "breach":
        return None
    body = {
        "subject": result.get("subject", ""),
        "pack": result.get("pack") or (chain or {}).get("pack"),
        "verdict": result["verdict"],
        "checks_digest": digest_checks(result.get("checks", [])),
        "provenance": trace_provenance(result, chain),
        "grade": "full" if result["verdict"] == "valid" else "conditional",
    }
    body["attestation_id"] = "ATT-" + sha256(canonical_json(body))[:16]
    body["issued_at"] = now  # metadata — excluded from id digest above
    return body
