#!/usr/bin/env python3
"""SpendBoundaryPack — AI agent context-boundary spend gate.

source_project: github.com/sadpig70/SpendBoundary (ContextCreep+SpendMesh+VetoEscrow)
"""

from ._base import valid, thin, breach, section, require, index_gap

CONTEXT_ORDER = ["session", "task", "tool", "external"]


def context_boundary(packet, P=None):
    s = section(packet, "spend")
    err = require("context_boundary", s, ["current_context", "spend_context", "amount"])
    if err:
        return err
    crossed, gap = index_gap(CONTEXT_ORDER, s["current_context"], s["spend_context"])
    # spend reaching a more external context than the agent's current one is a crossing
    outward = CONTEXT_ORDER.index(s["spend_context"]) - CONTEXT_ORDER.index(s["current_context"])
    if outward <= 0:
        return valid("context_boundary")
    if outward == 1:
        return thin("context_boundary", "spend crosses one context boundary")
    return breach("context_boundary", f"spend jumps {outward} context boundaries")


def veto_policy(packet, P=None):
    P = P or {}
    s = section(packet, "spend")
    blocked = set(P.get("blocked_recipients", []) or packet.get("blocked_recipients", []))
    restricted = set(P.get("restricted_tools", []) or packet.get("restricted_tools", []))
    soft_limit = P.get("soft_limit", packet.get("soft_limit", 1000))
    if s.get("recipient") in blocked:
        return breach("veto_policy", "recipient is blocked")
    if s.get("tool_name") in restricted and s.get("amount", 0) > soft_limit:
        return breach("veto_policy", "restricted tool over soft limit")
    if s.get("amount", 0) > soft_limit:
        return thin("veto_policy", "amount exceeds soft limit")
    return valid("veto_policy")


MANIFEST = {
    "name": "spend-boundary", "version": "1.0",
    "predicates": ["context_boundary", "veto_policy"],
    "packet_schema": "schemas/packet-spend.schema.json",
    "source_project": "github.com/sadpig70/SpendBoundary",
}
PREDICATES = [context_boundary, veto_policy]


def _p(pid, current, spend_ctx, amount, recipient="acct-ok", tool="search"):
    return {"packet_id": pid, "subject": pid,
            "spend": {"agent_id": "agent-1", "amount": amount, "currency": "USD",
                      "recipient": recipient, "current_context": current,
                      "spend_context": spend_ctx, "tool_name": tool},
            "soft_limit": 1000, "blocked_recipients": ["acct-blocked"],
            "restricted_tools": ["wire"]}


SAMPLES = {
    "valid": _p("SPB-VALID-001", "task", "task", 200),
    "thin": _p("SPB-THIN-001", "session", "task", 200),
    "breach": _p("SPB-BREACH-001", "session", "external", 5000, recipient="acct-blocked"),
}
