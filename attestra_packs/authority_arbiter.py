#!/usr/bin/env python3
"""AuthorityArbiterPack — delegated policy conflict arbitration as Attestra gates.

source_project: github.com/sadpig70/AuthorityArbiter
"""

from ._base import valid, thin, breach, section, require


def authority_decision(packet, P=None):
    arbiter = section(packet, "arbiter")
    err = require("authority_decision", arbiter, ["decision"])
    if err:
        return err
    decision = arbiter.get("decision")
    if decision == "ARBITRATED_ALLOW":
        return valid("authority_decision")
    if decision == "ESCALATE":
        return thin("authority_decision", "authority conflict requires escalation")
    if decision == "ARBITRATED_DENY":
        return breach("authority_decision", "highest authority policy denied the action")
    return thin("authority_decision", f"unknown authority decision: {decision}")


def custody_route(packet, P=None):
    handback = section(packet, "handback")
    err = require("custody_route", handback, ["route_id", "return_to", "confirmed"])
    if err:
        return err
    if handback.get("confirmed") is True:
        return valid("custody_route")
    return breach("custody_route", "delegated custody route is not confirmed")


MANIFEST = {
    "name": "authority-arbiter", "version": "1.0",
    "predicates": ["authority_decision", "custody_route"],
    "packet_schema": "schemas/packet-authorityarbiter.schema.json",
    "source_project": "github.com/sadpig70/AuthorityArbiter",
}
PREDICATES = [authority_decision, custody_route]


def _p(pid, decision, confirmed=True):
    return {"packet_id": pid, "subject": pid,
            "arbiter": {"decision": decision},
            "handback": {"route_id": "deploy-review", "return_to": "platform-owner", "confirmed": confirmed}}


SAMPLES = {
    "valid": _p("AA-V", "ARBITRATED_ALLOW"),
    "thin": _p("AA-T", "ESCALATE"),
    "breach": _p("AA-B", "ARBITRATED_DENY"),
}

