#!/usr/bin/env python3
"""Gate runtime — apply a pack's predicates to a packet and aggregate the verdict.

The heart of the kernel. Predicates are pure functions supplied by packs:
    predicate(packet, P) -> CheckResult
Side effects (ledger append, attestation issuance) live in separate actuators.
"""

from .packet import validate_packet, subject_id
from .verdict import aggregate_verdict


def run_gates(packet, predicates, P=None, now="", id_field="packet_id"):
    """Validate the packet, run every predicate, aggregate to highest severity.

    now is injected (never read from the clock) and only appears as metadata.
    """
    P = P or {}
    pv = validate_packet(packet, id_field=id_field)
    subj = subject_id(packet, id_field=id_field)
    if not pv["ok"]:
        return {
            "subject": subj, "verdict": "breach", "reason": pv["reason"],
            "worst": "packet", "checks": [], "packet_ok": False,
            "packet_fields": pv["fields"], "evaluated_at": now,
        }
    checks = [pred(packet, P) for pred in predicates]
    agg = aggregate_verdict(checks)
    return {
        "subject": subj, "verdict": agg["verdict"], "reason": agg["reason"],
        "worst": agg["worst"], "checks": checks, "packet_ok": True,
        "evaluated_at": now,
    }
