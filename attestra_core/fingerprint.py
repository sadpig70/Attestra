#!/usr/bin/env python3
"""Identity primitive (promoted from HELIX-Core).

Deterministic normalization + fingerprint. Used to dedup packs: two packs that
declare the same predicate set + packet schema share a fingerprint and the loader
rejects the duplicate (guards against SpendBoundary-style silent recombination).
"""

import hashlib
import re

_WS = re.compile(r"\s+")
_NONWORD = re.compile(r"[^a-z0-9]+")


def normalize(text):
    """Lowercase, collapse punctuation/whitespace to single spaces, strip."""
    text = str(text or "").lower()
    text = _NONWORD.sub(" ", text)
    return _WS.sub(" ", text).strip()


def tokenize(text):
    norm = normalize(text)
    return norm.split() if norm else []


def fingerprint(*parts):
    """Order-independent fingerprint over normalized parts (deterministic)."""
    tokens = sorted({normalize(p) for p in parts if str(p).strip()})
    return hashlib.sha256("|".join(tokens).encode("utf-8")).hexdigest()


def fingerprint_pack(manifest):
    """Fingerprint a pack by its behavior surface (predicates + schema), not its name.

    Excludes name/version/source so a renamed duplicate cannot evade dedup.
    """
    preds = sorted(str(p) for p in manifest.get("predicates", []))
    schema = str(manifest.get("packet_schema", ""))
    return fingerprint(schema, *preds)
