#!/usr/bin/env python3
"""CoverGatePack — synthesis underwriting decision as an Attestra predicate gate.

source_project: github.com/sadpig70/CoverGate

ROUTING (HELIX BUILD_ON_PLATFORM, machine-aware): CoverGate "gates synthesis on
insurability, not enforceability" — it scores a design request (payments-fraud
transplant), prices a liability-cover premium, and decides cover / refer / decline,
allowing synthesis only when covered. It is a HYBRID: the *product* is a threshold
decision gate (covered/referred/declined -> allow/manual/block), while premium + pool
solvency are the internal pricing mechanism. The gate is Attestra's machine —
covered/referred/declined ≅ valid/thin/breach — so CoverGate lands here as a gate pack.
(The premium/pool aggregation could be a future Clearstra market; this pack reproduces
the underwriting DECISION, i.e. CoverGate.engine.underwrite_one.)

Scoring weights and thresholds are CoverGate's published reference values. See
tests/test_cover_gate_parity.py, which checks the pack against the real CoverGate.
"""

from ._base import valid, thin, breach

# Published fraud-score weights (mirror CoverGate.models).
W_NOVELTY = 0.35
W_VELOCITY = 0.20
W_CONCERN = 0.35
W_REPUTATION = 0.30
PROVENANCE_PENALTY = 0.15
CONCERN_SEQ_CAP = 5

# Underwriting policy defaults (mirror CoverGate.models.UnderwritingPolicy).
_DEFAULT_MAX_INSURABLE = 0.8   # above -> declined at any price
_DEFAULT_REFER = 0.5           # [refer, max] -> referred to manual review


def _clamp01(x):
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _policy(packet):
    p = packet.get("policy", {}) if isinstance(packet.get("policy"), dict) else {}
    return (float(p.get("max_insurable_risk", _DEFAULT_MAX_INSURABLE)),
            float(p.get("refer_risk", _DEFAULT_REFER)))


def fraud_score(request):
    """Payments-fraud-style risk score in [0,1]. Mirrors CoverGate.engine.fraud_score."""
    raw = (
        W_NOVELTY * float(request.get("novelty_distance", 0.0) or 0.0)
        + W_VELOCITY * float(request.get("submission_velocity", 0.0) or 0.0)
        + W_CONCERN * min(1.0, int(request.get("concern_sequence_hits", 0) or 0) / CONCERN_SEQ_CAP)
        - W_REPUTATION * float(request.get("requester_reputation", 0.0) or 0.0)
    )
    if not request.get("tool_provenance_verified", False):
        raw += PROVENANCE_PENALTY
    return _clamp01(raw)


def underwriting_decision(packet, P=None):
    """cover / refer / decline from the fraud score vs the policy thresholds.

    Mirrors CoverGate.engine.underwrite_one: risk > max_insurable -> declined (breach);
    risk >= refer -> referred (thin); else covered (valid, synthesis allowed).
    """
    request = packet.get("request", {}) if isinstance(packet.get("request"), dict) else {}
    max_insurable, refer = _policy(packet)
    risk = fraud_score(request)
    did = request.get("design_id", packet.get("packet_id"))
    if risk > max_insurable:
        return breach("underwriting_decision", f"{did}: uninsurable risk {risk:.4g} > {max_insurable:g} (declined)")
    if risk >= refer:
        return thin("underwriting_decision", f"{did}: risk {risk:.4g} in [{refer:g}, {max_insurable:g}] (referred)")
    return valid("underwriting_decision", f"{did}: risk {risk:.4g} < {refer:g} (covered; synthesis allowed)")


MANIFEST = {
    "name": "cover-gate", "version": "1.0",
    "predicates": ["underwriting_decision"],
    "packet_schema": "schemas/packet-covergate.schema.json",
    "source_project": "github.com/sadpig70/CoverGate",
}

PREDICATES = [underwriting_decision]


def _packet(pid, request, policy=None):
    pkt = {"packet_id": pid, "subject": pid, "request": request}
    if policy is not None:
        pkt["policy"] = policy
    return pkt


def _req(did, reputation, novelty, seq, velocity, prov, exposure=1000.0):
    return {"design_id": did, "requester_reputation": reputation, "novelty_distance": novelty,
            "concern_sequence_hits": seq, "submission_velocity": velocity,
            "tool_provenance_verified": prov, "exposure_value": exposure}


SAMPLES = {
    # trusted, low-novelty, verified -> risk clamps to 0 -> covered
    "valid": _packet("CG-V", _req("d-low", 0.9, 0.1, 0, 0.1, True)),
    # high novelty + some concern hits, verified -> risk in [0.5, 0.8) -> referred
    "thin": _packet("CG-T", _req("d-mid", 0.1, 0.9, 3, 0.5, True)),
    # max novelty + concern + velocity, untrusted + unverified -> risk > 0.8 -> declined
    "breach": _packet("CG-B", _req("d-high", 0.0, 1.0, 5, 1.0, False)),
}
