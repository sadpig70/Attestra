#!/usr/bin/env python3
"""Pack loader + registry.

Discovers pack modules under attestra_packs/, validates their contract, and
dedups by behavior fingerprint (predicates + schema). Duplicate packs (same
surface, different name) are rejected — this is what keeps the platform from
silently re-registering recombinations.
"""

import importlib
import os
import pkgutil

from attestra_core.fingerprint import fingerprint_pack
from attestra_core.schema import load_schema

_RESERVED = {"loader", "_base"}
_REQUIRED_MANIFEST = ("name", "version", "predicates", "packet_schema", "source_project")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def discover_module_names(package="attestra_packs"):
    pkg = importlib.import_module(package)
    names = []
    for _finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
        short = name.split(".")[-1]
        if short in _RESERVED or short.startswith("__"):
            continue
        names.append(name)
    return sorted(names)


def _validate_manifest(mod, name):
    m = getattr(mod, "MANIFEST", None)
    preds = getattr(mod, "PREDICATES", None)
    if not isinstance(m, dict):
        return None, f"{name}: no MANIFEST dict"
    miss = [k for k in _REQUIRED_MANIFEST if not m.get(k)]
    if miss:
        return None, f"{name}: manifest missing {miss}"
    if not isinstance(preds, list) or not all(callable(p) for p in preds):
        return None, f"{name}: PREDICATES must be a list of callables"
    return m, ""


def load_packs(package="attestra_packs"):
    """Load, validate, and dedup packs. Returns a registry.

    registry = {
      "packs":   {name: {**manifest, fingerprint, module, predicates, samples}},
      "dropped": [{name, reason}], "errors": [str],
    }
    """
    registry = {"packs": {}, "dropped": [], "errors": []}
    seen_fp = {}
    for mod_name in discover_module_names(package):
        try:
            mod = importlib.import_module(f"{package}.{mod_name}")
        except Exception as exc:  # noqa: BLE001 — surfaced as an error entry
            registry["errors"].append(f"{mod_name}: import failed: {exc}")
            continue
        manifest, err = _validate_manifest(mod, mod_name)
        if err:
            registry["errors"].append(err)
            continue
        fp = fingerprint_pack(manifest)
        if fp in seen_fp:
            registry["dropped"].append(
                {"name": manifest["name"], "reason": f"duplicate_fingerprint_of:{seen_fp[fp]}"})
            continue
        schema_path = os.path.join(_REPO_ROOT, manifest["packet_schema"])
        schema = None
        if os.path.exists(schema_path):
            try:
                schema = load_schema(schema_path)
            except Exception as exc:  # noqa: BLE001
                registry["errors"].append(f"{manifest['name']}: schema unreadable: {exc}")
                continue
        else:
            registry["errors"].append(
                f"{manifest['name']}: declared packet_schema not found: {manifest['packet_schema']}")
            continue
        seen_fp[fp] = manifest["name"]
        registry["packs"][manifest["name"]] = {
            **manifest,                                  # keeps manifest["predicates"] = gate-key strings
            "fingerprint": fp,
            "module": f"{package}.{mod_name}",
            "predicate_fns": list(getattr(mod, "PREDICATES")),  # callables, kept separate
            "samples": dict(getattr(mod, "SAMPLES", {})),
            "id_field": manifest.get("id_field", "packet_id"),
            "schema": schema,
        }
    return registry


def get_pack(registry, name):
    if name not in registry["packs"]:
        raise KeyError(f"unknown pack: {name} (have: {sorted(registry['packs'])})")
    return registry["packs"][name]
