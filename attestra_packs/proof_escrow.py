#!/usr/bin/env python3
"""ProofEscrowPack — evidence-bound release escrow as an Attestra gate pack.

source_project: github.com/sadpig70/ProofEscrow
"""

from ._base import valid, thin, breach, section, require


def _decision(packet):
    escrow = section(packet, "escrow")
    return escrow.get("decision", "")


def _reason_codes(packet):
    escrow = section(packet, "escrow")
    return {r.get("code", "") for r in escrow.get("reasons", []) if isinstance(r, dict)}


def step_signature(packet, P=None):
    escrow = section(packet, "escrow")
    err = require("step_signature", escrow, ["decision"])
    if err:
        return err
    decision = _decision(packet)
    if decision == "RELEASED":
        return valid("step_signature")
    if decision == "HELD" and (
        "INVALID_STEP_SIGNATURE" in _reason_codes(packet)
        or "REQUIRED_SIGNER_MISSING" in _reason_codes(packet)
    ):
        return breach("step_signature", "artifact step signature did not satisfy escrow policy")
    if decision == "HELD":
        return valid("step_signature")
    return thin("step_signature", f"unknown escrow decision: {decision}")


def behavior_binding(packet, P=None):
    escrow = section(packet, "escrow")
    err = require("behavior_binding", escrow, ["decision"])
    if err:
        return err
    decision = _decision(packet)
    if decision == "RELEASED":
        return valid("behavior_binding")
    if decision == "HELD" and "BEHAVIOR_DRIFT" in _reason_codes(packet):
        return breach("behavior_binding", "observed behavior drifted from approved baseline")
    if decision == "HELD":
        return valid("behavior_binding")
    return thin("behavior_binding", f"unknown escrow decision: {decision}")


MANIFEST = {
    "name": "proof-escrow", "version": "1.0",
    "predicates": ["step_signature", "behavior_binding"],
    "packet_schema": "schemas/packet-proofescrow.schema.json",
    "source_project": "github.com/sadpig70/ProofEscrow",
}
PREDICATES = [step_signature, behavior_binding]


def _p(pid, decision, reasons=None):
    return {"packet_id": pid, "subject": pid,
            "escrow": {"decision": decision, "reasons": reasons or []}}


SAMPLES = {
    "valid": _p("PE-V", "RELEASED"),
    "thin": _p("PE-T", "PENDING"),
    "breach": _p("PE-B", "HELD", [{"code": "INVALID_STEP_SIGNATURE"}]),
}

