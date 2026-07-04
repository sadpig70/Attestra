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


def recompute_attestation_id(attestation):
    """Recompute the id from the body (excluding id + issued_at) — same rule as issue."""
    body = {k: v for k, v in attestation.items() if k not in ("attestation_id", "issued_at")}
    return "ATT-" + sha256(canonical_json(body))[:16]


def verify_attestation(attestation, revoked=None):
    """Independently verify an issued attestation: id binds body AND not revoked.

    revoked is a set of revoked attestation_ids (e.g. from the attestation ledger).
    """
    revoked = revoked or set()
    expected = recompute_attestation_id(attestation)
    got = attestation.get("attestation_id")
    id_ok = expected == got
    is_revoked = got in revoked
    if not id_ok:
        reason = "attestation_id does not bind body (tampered)"
    elif is_revoked:
        reason = "attestation revoked"
    else:
        reason = ""
    return {"valid": id_ok and not is_revoked, "id_ok": id_ok, "revoked": is_revoked,
            "expected_id": expected, "attestation_id": got, "reason": reason}
