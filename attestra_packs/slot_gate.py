#!/usr/bin/env python3
"""SlotGatePack — time-boxed execution slot with re-authorization gates.

source_project: github.com/sadpig70/SlotGate
"""

from ._base import valid, thin, breach, section, require


def slot_authorization(packet, P=None):
    s = section(packet, "slot")
    err = require("slot_authorization", s, ["slot_authorized"])
    if err:
        return err
    if s.get("slot_authorized") is True:
        return valid("slot_authorization")
    return breach("slot_authorization", "execution outside an authorized slot")


def slot_expiry(packet, P=None):
    s = section(packet, "slot")
    state = s.get("expiry_state")
    if state == "valid":
        return valid("slot_expiry")
    if state == "near":
        return thin("slot_expiry", "slot near expiry")
    return breach("slot_expiry", f"slot expired or unknown state: {state}")


def reauth_trace(packet, P=None):
    s = section(packet, "slot")
    if s.get("extended") is True and s.get("reauth") is not True:
        return breach("reauth_trace", "slot extended without re-authorization")
    return valid("reauth_trace")


MANIFEST = {
    "name": "slot-gate", "version": "1.0",
    "predicates": ["slot_authorization", "slot_expiry", "reauth_trace"],
    "packet_schema": "schemas/packet-slot.schema.json",
    "source_project": "github.com/sadpig70/SlotGate",
}
PREDICATES = [slot_authorization, slot_expiry, reauth_trace]


def _p(pid, authorized, expiry, extended, reauth):
    return {"packet_id": pid, "subject": pid,
            "slot": {"slot_authorized": authorized, "expiry_state": expiry,
                     "extended": extended, "reauth": reauth}}


SAMPLES = {
    "valid": _p("SG-VALID-001", True, "valid", False, False),
    "thin": _p("SG-THIN-001", True, "near", False, False),
    "breach": _p("SG-BREACH-001", False, "valid", False, False),
}
