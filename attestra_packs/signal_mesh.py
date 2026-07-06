#!/usr/bin/env python3
"""SignalMeshPack — operational-exhaust exchange admissibility as an Attestra gate.

source_project: github.com/sadpig70/SignalMesh

CONDENSE FINDING (HELIX Condense, refined): the "Compatibility Mesh" cluster shares a
name (L11 interconnection-mesh transplant) but NOT one machine. Machine-aware routing
splits it:
  - SovMesh, PqcMesh, SignalMesh -> per-item assessment + set-level admissibility
    verdict -> Attestra predicate gate (BUILD_ON_PLATFORM).
  - AgentMesh -> pricing + cost rollup (no verdict algebra) -> Clearstra's machine, NOT
    an Attestra pack.
SignalMesh mines each exhaust stream into tradeable/restricted/blocked and rolls the
set up into an exchange posture exchange_ready/conditional/blocked, which aligns with
Attestra valid/thin/breach.

PARITY NOTE — SignalMesh's posture is NOT a plain max-severity of the per-stream
outcomes: a single `blocked` stream alongside any `tradeable` one yields `conditional`,
not `blocked`; only zero-tradeable is `blocked`. This pack reproduces that exact rule
with three predicates whose max-severity equals the source posture:
    exchange_ready  <- integrity ok, liquidity ok, admissibility ok      (all tradeable)
    conditional     <- some restricted/blocked but >=1 tradeable         (admissibility thin)
    blocked         <- no tradeable stream, or a validation error        (liquidity/integrity breach)
See tests/test_signal_mesh_parity.py, which checks the pack against the real SignalMesh.
"""

from ._base import valid, thin, breach

# Sensitivities that need consent before a stream can be traded (mirrors SignalMesh).
CONSENT_SENSITIVE = {"restricted", "pii"}


def _policy(packet):
    p = packet.get("policy", {}) if isinstance(packet.get("policy"), dict) else {}
    return {
        "block_pii": p.get("block_pii", True),
        "require_consent_for_restricted": p.get("require_consent_for_restricted", True),
        "min_quality": float(p.get("min_quality", 0.5) or 0.0),
    }


def _streams(packet):
    s = packet.get("streams", [])
    return [x for x in s if isinstance(x, dict)]


def outcome(policy, stream):
    """Per-stream admissibility -> (outcome, reasons). Mirrors SignalMesh._appraise."""
    sensitivity = str(stream.get("sensitivity", "internal")).lower()
    quality = float(stream.get("quality", 1.0) or 0.0)
    if sensitivity == "pii" and policy["block_pii"]:
        return "blocked", ["pii_blocked"]
    reasons = []
    if (sensitivity in CONSENT_SENSITIVE and policy["require_consent_for_restricted"]
            and not stream.get("consent_obtained", False)):
        reasons.append("consent_required")
    if quality < policy["min_quality"]:
        reasons.append("low_quality")
    return ("restricted", reasons) if reasons else ("tradeable", [])


def stream_integrity(packet, P=None):
    """SignalMesh validation errors that force posture=blocked (the parts a structural
    schema cannot express: duplicate stream_id, quality/min_quality out of [0, 1])."""
    policy = _policy(packet)
    problems = []
    if not 0.0 <= policy["min_quality"] <= 1.0:
        problems.append(f"min_quality {policy['min_quality']} not in [0, 1]")
    seen = set()
    for s in _streams(packet):
        sid = s.get("stream_id")
        if sid in seen:
            problems.append(f"duplicate stream_id '{sid}'")
        seen.add(sid)
        q = float(s.get("quality", 1.0) or 0.0)
        if not 0.0 <= q <= 1.0:
            problems.append(f"{sid}: quality {q} not in [0, 1]")
    if problems:
        return breach("stream_integrity", "; ".join(problems))
    return valid("stream_integrity")


def exchange_liquidity(packet, P=None):
    """Posture 'blocked' when nothing is tradeable — the exchange cannot operate."""
    policy = _policy(packet)
    tradeable = [s for s in _streams(packet) if outcome(policy, s)[0] == "tradeable"]
    if not tradeable:
        return breach("exchange_liquidity", "no tradeable signal stream")
    return valid("exchange_liquidity")


def stream_admissibility(packet, P=None):
    """Posture 'conditional' when some streams are restricted/blocked (caveats present)."""
    policy = _policy(packet)
    flagged = []
    for s in _streams(packet):
        result, reasons = outcome(policy, s)
        if result != "tradeable":
            flagged.append(f"{s.get('stream_id')}: {result} ({','.join(reasons) or '-'})")
    if flagged:
        return thin("stream_admissibility", "; ".join(flagged))
    return valid("stream_admissibility")


MANIFEST = {
    "name": "signal-mesh", "version": "1.0",
    "predicates": ["stream_integrity", "exchange_liquidity", "stream_admissibility"],
    "packet_schema": "schemas/packet-signalmesh.schema.json",
    "source_project": "github.com/sadpig70/SignalMesh",
}

PREDICATES = [stream_integrity, exchange_liquidity, stream_admissibility]


def _packet(pid, streams, policy=None):
    return {"packet_id": pid, "subject": pid,
            "policy": policy or {"block_pii": True, "require_consent_for_restricted": True,
                                 "min_quality": 0.5},
            "streams": streams}


def _s(sid, exhaust_type, sensitivity, volume=100.0, quality=0.9, consent=False):
    return {"stream_id": sid, "exhaust_type": exhaust_type, "sensitivity": sensitivity,
            "volume": volume, "quality": quality, "consent_obtained": consent}


SAMPLES = {
    # all streams tradeable -> exchange_ready -> valid
    "valid": _packet("SIG-V", [
        _s("s1", "logs", "public", quality=0.9),
        _s("s2", "latency_traces", "internal", quality=0.8),
    ]),
    # one tradeable + one restricted (consent) -> conditional -> thin
    "thin": _packet("SIG-T", [
        _s("s1", "logs", "public", quality=0.9),
        _s("s2", "disputes", "restricted", consent=False, quality=0.9),
    ]),
    # zero tradeable (pii blocked + restricted) -> blocked -> breach
    "breach": _packet("SIG-B", [
        _s("s1", "compliance_traces", "pii", quality=0.9),
        _s("s2", "disputes", "restricted", consent=False, quality=0.9),
    ]),
}
