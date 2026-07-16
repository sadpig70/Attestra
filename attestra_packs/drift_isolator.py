#!/usr/bin/env python3
"""DriftIsolatorPack — minimal runtime drift evidence as Attestra gates.

source_project: github.com/sadpig70/DriftIsolator
"""

from ._base import valid, thin, breach, section, require


def drift_state(packet, P=None):
    drift = section(packet, "drift")
    err = require("drift_state", drift, ["decision"])
    if err:
        return err
    decision = drift.get("decision")
    if decision == "NO_DRIFT":
        return valid("drift_state")
    if decision == "INVALID":
        return thin("drift_state", "drift case is structurally invalid or baseline-mismatched")
    if decision == "ISOLATED":
        return breach("drift_state", "runtime drift was isolated")
    return thin("drift_state", f"unknown drift decision: {decision}")


def minimal_counterexample(packet, P=None):
    drift = section(packet, "drift")
    decision = drift.get("decision")
    if decision == "NO_DRIFT":
        return valid("minimal_counterexample")
    if decision == "INVALID":
        return thin("minimal_counterexample", "invalid case cannot prove a counterexample")
    if decision == "ISOLATED":
        err = require("minimal_counterexample", drift, ["minimal_event_count", "one_minimal"])
        if err:
            return err
        if drift.get("one_minimal") is True and drift.get("minimal_event_count", 0) >= 1:
            return valid("minimal_counterexample")
        return thin("minimal_counterexample", "drift isolated but minimality proof is incomplete")
    return thin("minimal_counterexample", "unknown drift decision")


MANIFEST = {
    "name": "drift-isolator", "version": "1.0",
    "predicates": ["drift_state", "minimal_counterexample"],
    "packet_schema": "schemas/packet-driftisolator.schema.json",
    "source_project": "github.com/sadpig70/DriftIsolator",
}
PREDICATES = [drift_state, minimal_counterexample]


def _p(pid, decision, count=0, one_minimal=False):
    return {"packet_id": pid, "subject": pid,
            "drift": {"decision": decision, "minimal_event_count": count, "one_minimal": one_minimal}}


SAMPLES = {
    "valid": _p("DI-V", "NO_DRIFT"),
    "thin": _p("DI-T", "INVALID"),
    "breach": _p("DI-B", "ISOLATED", 1, True),
}

