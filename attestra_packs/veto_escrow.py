#!/usr/bin/env python3
"""VetoEscrowPack — interruptible clearing gate for high-risk decisions.

source_project: github.com/sadpig70/VetoEscrow
"""

from ._base import valid, thin, breach, section, require


def veto_window(packet, P=None):
    d = section(packet, "decision")
    err = require("veto_window", d, ["in_veto_window"])
    if err:
        return err
    if d.get("in_veto_window") is not True:
        return breach("veto_window", "decision is outside the veto window")
    return valid("veto_window")


def escrow_state(packet, P=None):
    d = section(packet, "decision")
    state = d.get("escrow_state")
    if state in ("locked", "released"):
        return valid("escrow_state")
    if state == "pending":
        return thin("escrow_state", "escrow state still pending")
    return breach("escrow_state", f"invalid escrow state: {state}")


def interrupt_bound(packet, P=None):
    d = section(packet, "decision")
    err = require("interrupt_bound", d, ["interrupt_latency_ms", "interrupt_bound_ms"])
    if err:
        return err
    latency, bound = d["interrupt_latency_ms"], d["interrupt_bound_ms"]
    if latency <= bound:
        return valid("interrupt_bound")
    if latency <= 2 * bound:
        return thin("interrupt_bound", "interrupt latency over bound but recoverable")
    return breach("interrupt_bound", "interrupt latency exceeds hard bound")


MANIFEST = {
    "name": "veto-escrow", "version": "1.0",
    "predicates": ["veto_window", "escrow_state", "interrupt_bound"],
    "packet_schema": "schemas/packet-veto.schema.json",
    "source_project": "github.com/sadpig70/VetoEscrow",
}
PREDICATES = [veto_window, escrow_state, interrupt_bound]


def _p(pid, in_window, escrow, latency, bound=100):
    return {"packet_id": pid, "subject": pid,
            "decision": {"in_veto_window": in_window, "escrow_state": escrow,
                         "interrupt_latency_ms": latency, "interrupt_bound_ms": bound}}


SAMPLES = {
    "valid": _p("VE-VALID-001", True, "released", 50),
    "thin": _p("VE-THIN-001", True, "pending", 50),
    "breach": _p("VE-BREACH-001", False, "released", 50),
}
