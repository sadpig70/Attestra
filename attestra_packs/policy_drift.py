#!/usr/bin/env python3
"""PolicyDriftPack — has a deployment drifted from its approved policy baseline?

source_project: github.com/sadpig70/PolicyDriftDossier
"""

from ._base import valid, thin, breach, section, require


def baseline_match(packet, P=None):
    d = section(packet, "policy")
    if d.get("baseline_id") and d.get("current_id"):
        return valid("baseline_match")
    return thin("baseline_match", "baseline or current deployment id missing")


def drift_magnitude(packet, P=None):
    d = section(packet, "policy")
    err = require("drift_magnitude", d, ["drift", "drift_threshold"])
    if err:
        return err
    drift, thr = d["drift"], d["drift_threshold"]
    if drift <= thr:
        return valid("drift_magnitude")
    if drift <= thr * 1.2:
        return thin("drift_magnitude", "drift marginally over threshold")
    return breach("drift_magnitude", "drift exceeds threshold")


def approval_trace(packet, P=None):
    d = section(packet, "policy")
    if d.get("approval_trace"):
        return valid("approval_trace")
    return breach("approval_trace", "policy change without approval trace")


MANIFEST = {
    "name": "policy-drift", "version": "1.0",
    "predicates": ["baseline_match", "drift_magnitude", "approval_trace"],
    "packet_schema": "schemas/packet-policy.schema.json",
    "source_project": "github.com/sadpig70/PolicyDriftDossier",
}
PREDICATES = [baseline_match, drift_magnitude, approval_trace]


def _p(pid, baseline, current, drift, approval):
    return {"packet_id": pid, "subject": pid,
            "policy": {"baseline_id": baseline, "current_id": current,
                       "drift": drift, "drift_threshold": 0.2, "approval_trace": approval}}


SAMPLES = {
    "valid": _p("PD-VALID-001", "base-1", "cur-1", 0.1, "evidence/approval/a1.json"),
    "thin": _p("PD-THIN-001", "base-1", "cur-1", 0.22, "evidence/approval/a1.json"),
    "breach": _p("PD-BREACH-001", "base-1", "cur-1", 0.1, ""),
}
