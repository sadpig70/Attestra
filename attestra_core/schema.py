#!/usr/bin/env python3
"""Minimal deterministic JSON Schema validator (stdlib only).

Supports the subset Attestra packet schemas use: type (incl. unions), properties,
required, enum, minimum, minItems, pattern, items, anyOf, not, additionalProperties.
Structural contract only — evidence completeness & policy stay in pack predicates.
No clock/network/random.
"""

import json
import re

_TYPE_MAP = {
    "object": dict, "array": list, "string": str,
    "boolean": bool, "null": type(None),
}


def _type_ok(value, type_name):
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    py = _TYPE_MAP.get(type_name)
    return isinstance(value, py) if py is not None else True


def _validate(value, schema, path, errors):
    if not isinstance(schema, dict):
        return

    if "type" in schema:
        types = schema["type"]
        types = types if isinstance(types, list) else [types]
        if not any(_type_ok(value, t) for t in types):
            errors.append(f"{path or '<root>'}: expected type {types}, got {type(value).__name__}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path or '<root>'}: {value!r} not in enum {schema['enum']}")

    if "pattern" in schema and isinstance(value, str):
        if not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match /{schema['pattern']}/")

    if "minimum" in schema and isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema["minimum"]:
            errors.append(f"{path}: {value} < minimum {schema['minimum']}")

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path or '<root>'}: missing required '{req}'")
        for key, sub in value.items():
            if key in props:
                _validate(sub, props[key], f"{path}.{key}" if path else key, errors)
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{path or '<root>'}: unexpected property '{key}'")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: {len(value)} items < minItems {schema['minItems']}")
        if "items" in schema:
            for i, item in enumerate(value):
                _validate(item, schema["items"], f"{path}[{i}]", errors)

    if "anyOf" in schema:
        if not any(_matches(value, sub) for sub in schema["anyOf"]):
            errors.append(f"{path or '<root>'}: matches none of anyOf")

    if "not" in schema and _matches(value, schema["not"]):
        errors.append(f"{path or '<root>'}: must not match 'not' schema")


def _matches(value, schema):
    local = []
    _validate(value, schema, "", local)
    return not local


def validate_against_schema(obj, schema):
    """Return {ok, errors}. ok=True when obj satisfies the schema."""
    errors = []
    _validate(obj, schema, "", errors)
    return {"ok": not errors, "errors": errors}


def load_schema(path):
    """Load a JSON Schema file. Returns the schema dict (raises on unreadable)."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
