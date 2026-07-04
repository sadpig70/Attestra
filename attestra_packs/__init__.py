"""Attestra domain packs. Each pack module exposes MANIFEST, PREDICATES, SAMPLES.

Loaded and deduped by attestra_packs.loader. Packs contribute predicates only —
never verdict/ledger/attestation logic (that lives once in attestra_core).
"""
