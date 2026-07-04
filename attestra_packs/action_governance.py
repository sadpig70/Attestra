#!/usr/bin/env python3
"""ActionGovernancePack — judge an agent action pre-approval / in-flight / post-hoc.

source_project: github.com/sadpig70/AgentActionGovernanceOS
"""

from ._base import valid, thin, breach, section, require


def pre_approval(packet, P=None):
    a = section(packet, "action")
    err = require("pre_approval", a, ["pre_approved"])
    if err:
        return err
    if a.get("pre_approved") is True:
        return valid("pre_approval")
    return breach("pre_approval", "action executed without pre-approval")


def in_flight_safety(packet, P=None):
    a = section(packet, "action")
    err = require("in_flight_safety", a, ["safety_ok"])
    if err:
        return err
    if a.get("safety_ok") is True:
        return valid("in_flight_safety")
    return breach("in_flight_safety", "in-flight safety invariant violated")


def post_justification(packet, P=None):
    a = section(packet, "action")
    if a.get("post_justified") is True:
        return valid("post_justification")
    return thin("post_justification", "post-hoc justification missing")


MANIFEST = {
    "name": "action-governance", "version": "1.0",
    "predicates": ["pre_approval", "in_flight_safety", "post_justification"],
    "packet_schema": "schemas/packet-action.schema.json",
    "source_project": "github.com/sadpig70/AgentActionGovernanceOS",
}
PREDICATES = [pre_approval, in_flight_safety, post_justification]


def _p(pid, pre, safety, post):
    return {"packet_id": pid, "subject": pid,
            "action": {"pre_approved": pre, "safety_ok": safety, "post_justified": post}}


SAMPLES = {
    "valid": _p("AG-VALID-001", True, True, True),
    "thin": _p("AG-THIN-001", True, True, False),
    "breach": _p("AG-BREACH-001", False, True, True),
}
