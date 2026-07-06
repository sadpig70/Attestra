#!/usr/bin/env python3
"""AfferentCorePack — reflex-interruption coverage as an Attestra predicate gate.

source_project: github.com/sadpig70/AfferentCore

ROUTING (HELIX BUILD_ON_PLATFORM, machine-aware): AfferentCore verifies whether a
human-in-the-loop reflex-interruption path can perceive an AI action-risk signal and
intervene BEFORE the action commits — a latency race whose verdict is reflex_covered /
marginal / reflex_missed (plus sub_threshold / unsignalled). Its domain is AI action-risk
governance (the same cluster as handback / action-governance / withheld-action), and the
product is a safety VERDICT on a delegated action — Attestra's machine. So it lands here
as a gate pack (covered ≅ valid, marginal ≅ thin, missed ≅ breach).

Weights, thresholds, and the efferent-return constant are AfferentCore's published
reference values. See tests/test_afferent_core_parity.py (checks vs the real AfferentCore).
"""

from ._base import valid, thin, breach

# Severity = weighted risk + irreversibility (mirror AfferentCore.mapping.event_severity).
RISK_WEIGHT = 0.6
IRREVERSIBILITY_WEIGHT = 0.4
SUB_THRESHOLD_SEVERITY = 0.20   # below this, no reflex signal is required
EFFERENT_RETURN_MS = 50.0       # fixed motor-return leg of the reflex loop
SAFETY_MARGIN_MS = 100.0        # margin at/above which coverage is comfortable


def _severity(event):
    return round(RISK_WEIGHT * float(event.get("risk", 0.0) or 0.0)
                 + IRREVERSIBILITY_WEIGHT * float(event.get("irreversibility", 0.0) or 0.0), 6)


def reflex_status(packet):
    """Reproduce AfferentCore.reflex.verify_reflex -> status string."""
    event = packet.get("event", {}) if isinstance(packet.get("event"), dict) else {}
    signal = packet.get("signal")
    operator = packet.get("operator", {}) if isinstance(packet.get("operator"), dict) else {}
    severity = _severity(event)
    if severity < SUB_THRESHOLD_SEVERITY:
        return "sub_threshold", severity, 0.0
    if not isinstance(signal, dict):
        return "unsignalled", severity, 0.0
    total = round(float(signal.get("transmit_latency_ms", 0.0) or 0.0)
                  + float(signal.get("perception_latency_ms", 0.0) or 0.0)
                  + float(operator.get("reflex_latency_ms", 0.0) or 0.0)
                  + EFFERENT_RETURN_MS, 6)
    margin = round(float(event.get("commit_delay_ms", 0.0) or 0.0) - total, 6)
    if margin >= SAFETY_MARGIN_MS:
        return "reflex_covered", severity, margin
    if margin >= 0:
        return "marginal", severity, margin
    return "reflex_missed", severity, margin


def reflex_coverage(packet, P=None):
    """Can the reflex path interrupt the action before it commits?

    reflex_covered / sub_threshold -> valid ; marginal -> thin ;
    reflex_missed / unsignalled -> breach (the risky action commits uncovered).
    """
    event = packet.get("event", {}) if isinstance(packet.get("event"), dict) else {}
    eid = event.get("event_id", packet.get("packet_id"))
    status, severity, margin = reflex_status(packet)
    if status == "sub_threshold":
        return valid("reflex_coverage", f"{eid}: severity {severity:.4g} < {SUB_THRESHOLD_SEVERITY:g} (sub-threshold)")
    if status == "unsignalled":
        return breach("reflex_coverage", f"{eid}: severity {severity:.4g} but no afferent signal (unsignalled; uncovered)")
    if status == "reflex_covered":
        return valid("reflex_coverage", f"{eid}: margin {margin:g}ms >= {SAFETY_MARGIN_MS:g} (reflex covered)")
    if status == "marginal":
        return thin("reflex_coverage", f"{eid}: margin {margin:g}ms in [0, {SAFETY_MARGIN_MS:g}) (marginal)")
    return breach("reflex_coverage", f"{eid}: margin {margin:g}ms < 0 (reflex missed; action commits first)")


MANIFEST = {
    "name": "afferent-core", "version": "1.0",
    "predicates": ["reflex_coverage"],
    "packet_schema": "schemas/packet-afferentcore.schema.json",
    "source_project": "github.com/sadpig70/AfferentCore",
}

PREDICATES = [reflex_coverage]


def _packet(pid, event, signal, operator):
    return {"packet_id": pid, "subject": pid, "event": event, "signal": signal, "operator": operator}


def _event(eid, risk, irrev, commit_delay):
    return {"event_id": eid, "risk": risk, "irreversibility": irrev, "commit_delay_ms": commit_delay}


def _signal(transmit, perception):
    return {"transmit_latency_ms": transmit, "perception_latency_ms": perception}


SAMPLES = {
    # severe event, fast signal, generous commit delay -> margin 200 >= 100 -> covered
    "valid": _packet("AC-V", _event("e1", 0.9, 0.8, 400.0), _signal(20.0, 30.0), {"reflex_latency_ms": 100.0}),
    # same latency (total 200), commit delay 250 -> margin 50 in [0,100) -> marginal
    "thin": _packet("AC-T", _event("e2", 0.9, 0.8, 250.0), _signal(20.0, 30.0), {"reflex_latency_ms": 100.0}),
    # commit delay 150 < total 200 -> margin -50 < 0 -> reflex missed
    "breach": _packet("AC-B", _event("e3", 0.9, 0.8, 150.0), _signal(20.0, 30.0), {"reflex_latency_ms": 100.0}),
}
