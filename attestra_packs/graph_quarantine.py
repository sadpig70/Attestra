#!/usr/bin/env python3
"""GraphQuarantinePack — path-aware evidence quarantine as Attestra gates.

source_project: github.com/sadpig70/GraphQuarantine
"""

from ._base import valid, thin, breach, section, require


def quarantine_state(packet, P=None):
    graph = section(packet, "graph")
    err = require("quarantine_state", graph, ["decision"])
    if err:
        return err
    decision = graph.get("decision")
    if decision == "CLEAR":
        return valid("quarantine_state")
    if decision == "INVALID":
        return thin("quarantine_state", "graph case is structurally invalid or baseline-mismatched")
    if decision == "QUARANTINED":
        return breach("quarantine_state", "evidence graph contains quarantined paths")
    return thin("quarantine_state", f"unknown graph decision: {decision}")


def clean_branch_preservation(packet, P=None):
    graph = section(packet, "graph")
    decision = graph.get("decision")
    if decision == "INVALID":
        return thin("clean_branch_preservation", "invalid case cannot prove clean-branch preservation")
    err = require("clean_branch_preservation", graph, ["clean_branches"])
    if err:
        return err
    if isinstance(graph.get("clean_branches"), list) and graph["clean_branches"]:
        return valid("clean_branch_preservation")
    if decision == "CLEAR":
        return valid("clean_branch_preservation")
    return thin("clean_branch_preservation", "quarantine lacks clean branch evidence")


MANIFEST = {
    "name": "graph-quarantine", "version": "1.0",
    "predicates": ["quarantine_state", "clean_branch_preservation"],
    "packet_schema": "schemas/packet-graphquarantine.schema.json",
    "source_project": "github.com/sadpig70/GraphQuarantine",
}
PREDICATES = [quarantine_state, clean_branch_preservation]


def _p(pid, decision, clean_branches=None):
    return {"packet_id": pid, "subject": pid,
            "graph": {"decision": decision, "clean_branches": clean_branches or []}}


SAMPLES = {
    "valid": _p("GQ-V", "CLEAR", ["root"]),
    "thin": _p("GQ-T", "INVALID"),
    "breach": _p("GQ-B", "QUARANTINED", ["root"]),
}

