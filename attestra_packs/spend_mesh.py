#!/usr/bin/env python3
"""SpendMeshPack — agent treasury-control gate as Attestra predicates.

source_project: github.com/sadpig70/SpendMesh

ROUTING (HELIX BUILD_ON_PLATFORM, machine-aware): SpendMesh puts a treasury control in
front of every agent spend — it runs six independent controls (budget, transaction,
category, rate, vendor, approval) over one spend request and aggregates them to a single
verdict approve / review / deny. That is exactly Attestra's predicate-gate machine
(independent predicates -> max-severity), with approve/review/deny ≅ valid/thin/breach.
So it lands here as a six-predicate gate pack. (Distinct from the existing spend-boundary
pack: different controls -> different behavior fingerprint, so the loader keeps both.)

Reproduces SpendMesh.evaluate's controls + _decide_verdict (max by approve<review<deny).
See tests/test_spend_mesh_parity.py (checks vs the real SpendMesh).
"""

from ._base import valid, thin, breach


def _policy(packet):
    return packet.get("policy", {}) if isinstance(packet.get("policy"), dict) else {}


def _request(packet):
    return packet.get("request", {}) if isinstance(packet.get("request"), dict) else {}


def _amount(packet):
    return float(_request(packet).get("amount", 0.0) or 0.0)


def budget(packet, P=None):
    """Spend must fit the remaining budget (total_budget - spent_to_date)."""
    pol = _policy(packet)
    remaining = float(pol.get("total_budget", 0.0) or 0.0) - float(pol.get("spent_to_date", 0.0) or 0.0)
    amt = _amount(packet)
    if amt > remaining:
        return breach("budget", f"amount {amt:g} exceeds remaining budget {remaining:g}")
    return valid("budget")


def transaction(packet, P=None):
    """Per-transaction ceiling (0 = no limit)."""
    limit = float(_policy(packet).get("per_transaction_limit", 0.0) or 0.0)
    amt = _amount(packet)
    if limit > 0 and amt > limit:
        return breach("transaction", f"amount {amt:g} exceeds per-transaction limit {limit:g}")
    return valid("transaction")


def category(packet, P=None):
    """Category budget: uncategorized -> review; over the category limit -> deny."""
    limits = _policy(packet).get("category_limits", {}) or {}
    if not limits:
        return valid("category")
    cat = _request(packet).get("category", "uncategorized")
    if cat not in limits:
        return thin("category", f"uncategorized spend: '{cat}' has no policy limit")
    amt = _amount(packet)
    limit = float(limits[cat] or 0.0)
    if amt > limit:
        return breach("category", f"amount {amt:g} exceeds category '{cat}' limit {limit:g}")
    return valid("category")


def rate(packet, P=None):
    """Rolling spend-rate window (0 = no rate limit)."""
    pol = _policy(packet)
    rate_limit = float(pol.get("rate_limit_amount", 0.0) or 0.0)
    if rate_limit <= 0:
        return valid("rate")
    projected = float(_request(packet).get("window_spend_to_date", 0.0) or 0.0) + _amount(packet)
    if projected > rate_limit:
        window = pol.get("rate_window", "24h")
        return breach("rate", f"window spend {projected:g} exceeds rate limit {rate_limit:g} per {window}")
    return valid("rate")


def vendor(packet, P=None):
    """Blocked vendor -> deny; off-allowlist vendor -> review."""
    pol = _policy(packet)
    v = _request(packet).get("vendor", "")
    if v in (pol.get("blocked_vendors", []) or []):
        return breach("vendor", f"vendor '{v}' is blocked")
    allowed = pol.get("allowed_vendors", []) or []
    if allowed and v not in allowed:
        return thin("vendor", f"vendor '{v}' is not on the allowlist")
    return valid("vendor")


def approval(packet, P=None):
    """At/above the approval threshold -> human review (0 = never)."""
    threshold = float(_policy(packet).get("approval_threshold", 0.0) or 0.0)
    amt = _amount(packet)
    if threshold > 0 and amt >= threshold:
        return thin("approval", f"amount {amt:g} at/above approval threshold {threshold:g}; human approval required")
    return valid("approval")


MANIFEST = {
    "name": "spend-mesh", "version": "1.0",
    "predicates": ["budget", "transaction", "category", "rate", "vendor", "approval"],
    "packet_schema": "schemas/packet-spendmesh.schema.json",
    "source_project": "github.com/sadpig70/SpendMesh",
}

PREDICATES = [budget, transaction, category, rate, vendor, approval]


def _packet(pid, policy, request):
    return {"packet_id": pid, "subject": pid, "policy": policy, "request": request}


SAMPLES = {
    # within budget, no thresholds tripped -> all controls clear -> approve
    "valid": _packet("SM-V",
                     {"total_budget": 10000.0, "spent_to_date": 0.0},
                     {"request_id": "r1", "agent_id": "a1", "amount": 100.0, "category": "compute", "vendor": "acme"}),
    # at/above approval threshold (review), nothing denied -> review
    "thin": _packet("SM-T",
                    {"total_budget": 10000.0, "spent_to_date": 0.0, "approval_threshold": 50.0},
                    {"request_id": "r2", "agent_id": "a1", "amount": 100.0, "category": "compute", "vendor": "acme"}),
    # amount exceeds remaining budget -> deny
    "breach": _packet("SM-B",
                      {"total_budget": 100.0, "spent_to_date": 0.0},
                      {"request_id": "r3", "agent_id": "a1", "amount": 500.0, "category": "compute", "vendor": "acme"}),
}
