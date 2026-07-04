#!/usr/bin/env python3
"""Shared helpers for packs. A pack module exposes MANIFEST, PREDICATES, SAMPLES.

Every predicate is a pure function `predicate(packet, P) -> CheckResult`. Packs
never define verdict/ledger/attestation logic — they only contribute predicates.
"""

from attestra_core.verdict import valid, thin, breach, missing, thin_or_breach

__all__ = ["valid", "thin", "breach", "missing", "thin_or_breach",
           "require", "section", "index_gap"]


def section(packet, name):
    """Return packet[name] as a dict (empty dict if absent)."""
    value = packet.get(name, {})
    return value if isinstance(value, dict) else {}


def require(gate, obj, fields):
    """If any required field is missing, return the thin/breach CheckResult; else None."""
    miss = missing(fields, obj)
    if miss:
        return thin_or_breach(gate, miss)
    return None


def index_gap(order, current, target):
    """Positional gap between two labels in an ordered scope list.

    Returns (crossed, gap): crossed=True when target is more privileged (lower
    index) than current, gap = current_index - target_index (>0 when crossed).
    """
    if current not in order or target not in order:
        return (False, 0)
    gap = order.index(current) - order.index(target)
    return (gap > 0, gap)
