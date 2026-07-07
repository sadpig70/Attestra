#!/usr/bin/env python3
"""SlotSettleGatePack — time-boxed settlement authorization as Attestra predicates.

source_project: github.com/sadpig70/SlotSettleGate

ROUTING (HELIX BUILD_ON_PLATFORM, machine-aware): SlotSettleGate asks "does a time-boxed
autonomous settlement run have valid slot authorization, pass settlement compliance, and
stay within veto-escrow interrupt bounds?" — three independent checks aggregated by max
severity, with its own {authorized, review, vetoed} algebra that is *identical in shape*
to Attestra's {valid, thin, breach}. It is a predicate gate through and through, so it
lands here as a three-predicate pack (authorized->valid, review->thin, vetoed->breach).

This is a near-verbatim port of SlotSettleGate.engine (check_slot / check_settlement /
check_veto_escrow). See tests/test_slot_settle_gate_parity.py (checks vs the real engine).
"""

import re

from ._base import valid, thin, breach

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _missing(required, obj):
    if not isinstance(obj, dict):
        return list(required)
    return [k for k in required if k not in obj or obj[k] in ("", None)]


def slot(packet, P=None):
    """Slot authorization: valid window, hash, and (re)authorization. Mirrors check_slot."""
    s = packet.get("slot", {})
    required = ["slot_id", "slot_start_unix", "slot_end_unix", "execution_unix",
                "duration_limit_sec", "reauth_required", "reauth_granted", "authorization_hash"]
    miss = _missing(required, s)
    if miss:
        return breach("slot", f"missing fields: {', '.join(miss)}")
    if not _SHA256_RE.fullmatch(str(s.get("authorization_hash", ""))):
        return breach("slot", "invalid authorization_hash sha256 hex")
    start, end = int(s["slot_start_unix"]), int(s["slot_end_unix"])
    execution, duration = int(s["execution_unix"]), int(s["duration_limit_sec"])
    if end <= start:
        return breach("slot", "slot_end_unix must be after slot_start_unix")
    if duration <= 0:
        return breach("slot", "duration_limit_sec must be positive")
    if (end - start) > duration:
        return breach("slot", "slot window exceeds duration_limit_sec")
    if execution < start or execution > end:
        return breach("slot", "execution_unix outside slot window")
    if s.get("reauth_required") is True and s.get("reauth_granted") is not True:
        return breach("slot", "re-authorization required but not granted")
    span, elapsed = end - start, execution - start
    if span > 0 and elapsed / span >= 0.9 and s.get("reauth_required") is True:
        return thin("slot", "execution near slot end with reauth policy active")
    return valid("slot", "slot authorization valid")


def settlement(packet, P=None):
    """Settlement compliance: rules passed + compliance score. Mirrors check_settlement."""
    s = packet.get("settlement", {})
    required = ["amount_usd", "rules_passed", "rules_total", "compliance_score", "jurisdiction"]
    miss = _missing(required, s)
    if miss:
        return breach("settlement", f"missing fields: {', '.join(miss)}")
    rules_passed, rules_total = int(s["rules_passed"]), int(s["rules_total"])
    compliance, amount = float(s["compliance_score"]), float(s["amount_usd"])
    if rules_total <= 0:
        return breach("settlement", "rules_total must be positive")
    if rules_passed < 0 or rules_passed > rules_total:
        return breach("settlement", "rules_passed out of range")
    if amount < 0:
        return breach("settlement", "amount_usd must be non-negative")
    if compliance < 0.0 or compliance > 1.0:
        return breach("settlement", "compliance_score must be between 0 and 1")
    if rules_passed < rules_total:
        if rules_passed < (rules_total * 0.75):
            return breach("settlement", f"only {rules_passed}/{rules_total} settlement rules passed")
        return thin("settlement", f"partial compliance: {rules_passed}/{rules_total} rules passed")
    if compliance < 0.85:
        return breach("settlement", f"compliance_score {compliance} below floor 0.85")
    if compliance < 0.95:
        return thin("settlement", f"compliance_score {compliance} below target 0.95")
    return valid("settlement", "settlement compliance satisfied")


def veto_escrow(packet, P=None):
    """Veto-escrow interrupt bounds: risk vs threshold, escrow active. Mirrors check_veto_escrow."""
    v = packet.get("veto_escrow", {})
    required = ["risk_score", "escrow_active", "veto_threshold", "interrupt_requested"]
    miss = _missing(required, v)
    if miss:
        return breach("veto_escrow", f"missing fields: {', '.join(miss)}")
    risk, threshold = float(v["risk_score"]), float(v["veto_threshold"])
    if risk < 0.0 or risk > 1.0:
        return breach("veto_escrow", "risk_score must be between 0 and 1")
    if threshold <= 0.0 or threshold > 1.0:
        return breach("veto_escrow", "veto_threshold must be between 0 and 1")
    if v.get("escrow_active") is not True:
        return breach("veto_escrow", "veto escrow not active")
    if v.get("interrupt_requested") is True:
        return breach("veto_escrow", "interrupt requested on veto escrow")
    if risk >= threshold:
        return breach("veto_escrow", f"risk_score {risk} at or above veto_threshold {threshold}")
    if risk >= threshold * 0.75:
        return thin("veto_escrow", f"risk_score {risk} approaching veto_threshold {threshold}")
    return valid("veto_escrow", "veto escrow bounds satisfied")


MANIFEST = {
    "name": "slot-settle-gate", "version": "1.0",
    "predicates": ["slot", "settlement", "veto_escrow"],
    "packet_schema": "schemas/packet-slotsettlegate.schema.json",
    "source_project": "github.com/sadpig70/SlotSettleGate",
}

PREDICATES = [slot, settlement, veto_escrow]

_HASH = "a" * 64


def _packet(pid, slot_sec, settle_sec, veto_sec):
    return {"packet_id": pid, "subject": pid,
            "slot": slot_sec, "settlement": settle_sec, "veto_escrow": veto_sec}


_SLOT_OK = {"slot_id": "s1", "slot_start_unix": 1000, "slot_end_unix": 2000,
            "execution_unix": 1400, "duration_limit_sec": 2000, "reauth_required": False,
            "reauth_granted": False, "authorization_hash": _HASH}
_VETO_OK = {"risk_score": 0.2, "escrow_active": True, "veto_threshold": 0.8,
            "interrupt_requested": False}


SAMPLES = {
    # all three checks authorized -> valid
    "valid": _packet("SSG-V", _SLOT_OK,
                     {"amount_usd": 100.0, "rules_passed": 10, "rules_total": 10,
                      "compliance_score": 0.98, "jurisdiction": "US"}, _VETO_OK),
    # settlement partial (8/10 >= 75%) -> review, others authorized -> thin
    "thin": _packet("SSG-T", _SLOT_OK,
                    {"amount_usd": 100.0, "rules_passed": 8, "rules_total": 10,
                     "compliance_score": 0.98, "jurisdiction": "US"}, _VETO_OK),
    # veto-escrow risk at/above threshold -> vetoed -> breach
    "breach": _packet("SSG-B", _SLOT_OK,
                      {"amount_usd": 100.0, "rules_passed": 10, "rules_total": 10,
                       "compliance_score": 0.98, "jurisdiction": "US"},
                      {"risk_score": 0.9, "escrow_active": True, "veto_threshold": 0.8,
                       "interrupt_requested": False}),
}
