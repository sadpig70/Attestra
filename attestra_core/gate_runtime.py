#!/usr/bin/env python3
"""Gate runtime — apply a pack's predicates to a packet and aggregate the verdict.

The heart of the kernel. Predicates are pure functions supplied by packs:
    predicate(packet, P) -> CheckResult
Side effects (ledger append, attestation issuance) live in separate actuators.
"""

from .packet import validate_packet, subject_id
from .verdict import aggregate_verdict
from .schema import validate_against_schema


def run_gates(packet, predicates, P=None, now="", id_field="packet_id", schema=None):
    """Validate the packet, enforce its declared schema, run predicates, aggregate.

    Order: universal packet check (private payload + identifier) -> structural
    schema check (if the pack declares one) -> pack predicates. A schema violation
    is a breach before any predicate runs. now is injected metadata, never a clock read.
    """
    P = P or {}
    subj = subject_id(packet, id_field=id_field)
    pv = validate_packet(packet, id_field=id_field)
    if not pv["ok"]:
        return {
            "subject": subj, "verdict": "breach", "reason": pv["reason"],
            "worst": "packet", "checks": [], "packet_ok": False,
            "packet_fields": pv["fields"], "evaluated_at": now,
        }
    if schema is not None:
        sv = validate_against_schema(packet, schema)
        if not sv["ok"]:
            return {
                "subject": subj, "verdict": "breach", "reason": "schema_violation",
                "worst": "schema", "checks": [], "packet_ok": False,
                "schema_errors": sv["errors"], "evaluated_at": now,
            }
    checks = [pred(packet, P) for pred in predicates]
    agg = aggregate_verdict(checks)
    return {
        "subject": subj, "verdict": agg["verdict"], "reason": agg["reason"],
        "worst": agg["worst"], "checks": checks, "packet_ok": True,
        "evaluated_at": now,
    }
