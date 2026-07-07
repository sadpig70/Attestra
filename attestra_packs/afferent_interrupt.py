#!/usr/bin/env python3
"""AfferentInterruptPack — agent runaway-loop / safety interrupt as an Attestra gate.

source_project: github.com/sadpig70/AfferentInterrupt

ROUTING (HELIX BUILD_ON_PLATFORM, machine-aware): AfferentInterrupt watches an autonomous
agent's execution trace, detects runaway action loops and safety-policy breaches, and
(on interception) issues a tamper-evident attestation. Its verdict is cleared /
intercepted / breached — a per-trace safety judgment on a delegated agent, squarely
Attestra's machine (cleared ≅ valid, intercepted ≅ thin, breached ≅ breach). So it lands
here as a gate pack. Thresholds and the score formula are AfferentInterrupt's reference
values. See tests/test_afferent_interrupt_parity.py (checks vs the real engine).
"""

from ._base import valid, thin, breach

LOOP_THRESHOLD = 3        # a pattern must repeat >= this many times to count as a loop
MAX_WINDOW = 100          # only the most recent N steps are scanned
INTERCEPT_SCORE = 0.7     # detected loop at/above this score is intercepted
_REPEAT_W = 0.12          # score weight per repeat
_COST_W = 0.05            # score weight per unit of in-loop resource cost


def _trace(packet):
    t = packet.get("trace", [])
    return [x for x in t if isinstance(x, dict)]


def detect_trace_loop(trace, threshold=LOOP_THRESHOLD, max_window=MAX_WINDOW):
    """Highest-repeat state->action pattern in the recent window. Mirrors the source."""
    window = trace[-max_window:] if len(trace) > max_window else trace
    n = len(window)
    best = {"detected": False, "sequence": [], "repeat_count": 0, "start_step": 0, "end_step": 0}
    if n < threshold:
        return best
    repr_list = [f"{item.get('state')}->{item.get('action')}" for item in window]
    for k in range(1, (n // threshold) + 1):
        for i in range(n - k * threshold + 1):
            pattern = repr_list[i:i + k]
            repeats = 1
            j = i + k
            while j + k <= n and repr_list[j:j + k] == pattern:
                repeats += 1
                j += k
            if repeats >= threshold and repeats > best["repeat_count"]:
                best = {"detected": True, "sequence": pattern, "repeat_count": repeats,
                        "start_step": window[i].get("step"), "end_step": window[j - 1].get("step")}
    return best


def assess_safety_rule(trace, safety_policies):
    """True iff any item is unchecked or performs a policy-listed action."""
    policies = set(safety_policies or [])
    for item in trace:
        if not item.get("safety_checked", True):
            return True
        if item.get("action") in policies:
            return True
    return False


def compute_loop_score(loop_info, trace):
    """repeat_count (60%) + in-loop resource cost (40%), capped at 1.0. Mirrors the source."""
    if not loop_info.get("detected", False):
        return 0.0
    start, end = loop_info["start_step"], loop_info["end_step"]
    total_cost = sum(float(item.get("resource_cost", 0) or 0) for item in trace
                     if start is not None and end is not None
                     and start <= item.get("step", -1) <= end)
    return round(min(1.0, loop_info["repeat_count"] * _REPEAT_W + total_cost * _COST_W), 3)


def trace_verdict(packet):
    """Reproduce AfferentInterruptEngine.determine_verdict -> verdict string."""
    trace = _trace(packet)
    loop = detect_trace_loop(trace)
    if assess_safety_rule(trace, packet.get("safety_policies", [])):
        return "breached", 1.0, loop
    score = compute_loop_score(loop, trace)
    if loop.get("detected", False) and score >= INTERCEPT_SCORE:
        return "intercepted", score, loop
    return "cleared", score, loop


def loop_safety(packet, P=None):
    """cleared -> valid ; intercepted -> thin ; breached -> breach."""
    pid = packet.get("packet_id")
    verdict, score, loop = trace_verdict(packet)
    if verdict == "breached":
        return breach("loop_safety", f"{pid}: safety policy breached by an execution item")
    if verdict == "intercepted":
        rc = loop.get("repeat_count")
        return thin("loop_safety", f"{pid}: runaway loop intercepted (repeats={rc}, score={score})")
    return valid("loop_safety", f"{pid}: within cleared safety margins (score={score})")


MANIFEST = {
    "name": "afferent-interrupt", "version": "1.0",
    "predicates": ["loop_safety"],
    "packet_schema": "schemas/packet-afferentinterrupt.schema.json",
    "source_project": "github.com/sadpig70/AfferentInterrupt",
}

PREDICATES = [loop_safety]


def _step(step, state, action, cost=1.0, checked=True):
    return {"step": step, "state": state, "action": action,
            "resource_cost": cost, "safety_checked": checked}


def _packet(pid, trace, policies=None):
    return {"packet_id": pid, "subject": pid, "trace": trace, "safety_policies": policies or []}


SAMPLES = {
    # short, non-repeating, all checked -> no loop, no breach -> cleared
    "valid": _packet("AI-V", [
        _step(1, "s0", "read"), _step(2, "s1", "plan"), _step(3, "s2", "write")]),
    # one state->action repeated 4x with cost -> score >= 0.7, no safety breach -> intercepted
    "thin": _packet("AI-T", [
        _step(1, "loop", "retry", cost=3.0), _step(2, "loop", "retry", cost=3.0),
        _step(3, "loop", "retry", cost=3.0), _step(4, "loop", "retry", cost=3.0)]),
    # an execution item performs a policy-listed unsafe action -> breached
    "breach": _packet("AI-B", [
        _step(1, "s0", "read"), _step(2, "s1", "delete_all")], policies=["delete_all"]),
}
