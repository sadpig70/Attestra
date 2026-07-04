#!/usr/bin/env python3
"""DelegationPack — pre-screen delegated agent work vs trust envelopes & liability.

source_project: github.com/sadpig70/DelegationUnderwriter
"""

from ._base import valid, thin, breach, section, require


def trust_envelope(packet, P=None):
    d = section(packet, "delegation")
    err = require("trust_envelope", d, ["work_risk", "envelope_max_risk"])
    if err:
        return err
    risk, cap = d["work_risk"], d["envelope_max_risk"]
    if risk <= cap:
        return valid("trust_envelope")
    if risk <= cap * 1.1:
        return thin("trust_envelope", "work risk marginally over envelope")
    return breach("trust_envelope", "work risk exceeds trust envelope")


def liability_limit(packet, P=None):
    d = section(packet, "delegation")
    err = require("liability_limit", d, ["expected_liability", "liability_limit"])
    if err:
        return err
    exp, limit = d["expected_liability"], d["liability_limit"]
    if exp <= 0.8 * limit:
        return valid("liability_limit")
    if exp <= limit:
        return thin("liability_limit", "expected liability near limit")
    return breach("liability_limit", "expected liability over limit")


def authority_scope(packet, P=None):
    d = section(packet, "delegation")
    delegated = set(d.get("delegated_scope", []))
    delegator = set(d.get("delegator_scope", []))
    if not delegated:
        return thin("authority_scope", "delegated scope not declared")
    if delegated <= delegator:
        return valid("authority_scope")
    return breach("authority_scope", "delegated scope exceeds delegator authority")


MANIFEST = {
    "name": "delegation", "version": "1.0",
    "predicates": ["trust_envelope", "liability_limit", "authority_scope"],
    "packet_schema": "schemas/packet-delegation.schema.json",
    "source_project": "github.com/sadpig70/DelegationUnderwriter",
}
PREDICATES = [trust_envelope, liability_limit, authority_scope]


def _p(pid, risk, exp_liab, delegated, delegator):
    return {"packet_id": pid, "subject": pid,
            "delegation": {"work_risk": risk, "envelope_max_risk": 0.5,
                           "expected_liability": exp_liab, "liability_limit": 1000,
                           "delegated_scope": delegated, "delegator_scope": delegator}}


SAMPLES = {
    "valid": _p("DL-VALID-001", 0.3, 500, ["read"], ["read", "write"]),
    "thin": _p("DL-THIN-001", 0.3, 950, ["read"], ["read", "write"]),
    "breach": _p("DL-BREACH-001", 0.3, 500, ["read", "admin"], ["read", "write"]),
}
