#!/usr/bin/env python3
"""HookCircuitPack — plugin hook circuit breaker evidence as Attestra gates.

source_project: github.com/sadpig70/HookCircuit
"""

from ._base import valid, thin, breach, section, require


def hook_contract(packet, P=None):
    hook = section(packet, "hook")
    err = require("hook_contract", hook, ["decision"])
    if err:
        return err
    if hook.get("decision") == "INVALID":
        return thin("hook_contract", "hook contract or baseline is invalid")
    return valid("hook_contract")


def interruption_state(packet, P=None):
    hook = section(packet, "hook")
    err = require("interruption_state", hook, ["decision"])
    if err:
        return err
    decision = hook.get("decision")
    if decision == "ALLOWED":
        return valid("interruption_state")
    if decision == "INVALID":
        return thin("interruption_state", "invalid hook case cannot prove interruption state")
    if decision == "TRIPPED":
        return breach("interruption_state", "hook circuit was tripped and isolated")
    return thin("interruption_state", f"unknown hook decision: {decision}")


MANIFEST = {
    "name": "hook-circuit", "version": "1.0",
    "predicates": ["hook_contract", "interruption_state"],
    "packet_schema": "schemas/packet-hookcircuit.schema.json",
    "source_project": "github.com/sadpig70/HookCircuit",
}
PREDICATES = [hook_contract, interruption_state]


def _p(pid, decision):
    return {"packet_id": pid, "subject": pid, "hook": {"decision": decision}}


SAMPLES = {
    "valid": _p("HC-V", "ALLOWED"),
    "thin": _p("HC-T", "INVALID"),
    "breach": _p("HC-B", "TRIPPED"),
}

