#!/usr/bin/env python3
"""Determinism boundary checker.

Scans Python sources for violations of the Attestra determinism boundary:
clock reads, randomness, and network access. Parsing dates (datetime.fromisoformat)
is allowed — only *reading the clock* is forbidden. Time is injected via `now`.
"""

import ast
import os

FORBIDDEN_IMPORTS = {"random", "socket", "requests", "urllib", "http", "aiohttp", "secrets"}
FORBIDDEN_CALLS = {
    ("time", "time"), ("time", "monotonic"), ("time", "perf_counter"), ("time", "time_ns"),
    ("datetime", "now"), ("datetime", "utcnow"), ("datetime", "today"),
    ("date", "today"), ("random", "random"),
}
FORBIDDEN_ATTRS = {"now", "utcnow", "today", "monotonic", "perf_counter"}


def check_source(path):
    """Return a list of {line, kind, detail} violations for one .py file."""
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=path)
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORTS:
                    violations.append({"line": node.lineno, "kind": "import", "detail": alias.name})
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_IMPORTS:
                violations.append({"line": node.lineno, "kind": "import_from", "detail": node.module})
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            base = node.func.value
            base_name = base.id if isinstance(base, ast.Name) else (
                base.attr if isinstance(base, ast.Attribute) else "")
            if (base_name, attr) in FORBIDDEN_CALLS or attr in FORBIDDEN_ATTRS:
                violations.append({"line": node.lineno, "kind": "call",
                                   "detail": f"{base_name}.{attr}()"})
    return violations


def check_tree(root, subdirs=("attestra_core", "attestra_packs")):
    """Scan the given package dirs; return {clean, files_scanned, violations}."""
    report = {"clean": True, "files_scanned": 0, "violations": {}}
    for sub in subdirs:
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirs, files in os.walk(base):
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(dirpath, name)
                report["files_scanned"] += 1
                v = check_source(path)
                if v:
                    report["clean"] = False
                    report["violations"][os.path.relpath(path, root)] = v
    return report
