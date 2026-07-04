#!/usr/bin/env python3
"""Closed audit loop — batch-evaluate a directory of packets into one audit ledger.

Ingest every packet in a directory, route each to its pack, evaluate, issue an
attestation for every non-breach verdict, append all verdicts to a single
hash-chained ledger (deterministic, file-sorted order), and verify the chain.
This is the operational surface: sample -> audit -> attest-all -> verify.

Meta/IO layer (like cli.py): file I/O + injected `now`, still clock/network-free.
"""

import json
import os

from attestra_core.gate_runtime import run_gates
from attestra_core.ledger import append_record, verify_ledger
from attestra_core.attestation import issue_attestation
from attestra_packs.loader import get_pack


def _route(packet, path, registry, override):
    """Resolve which pack a packet belongs to: override > packet['pack'] > filename prefix."""
    if override:
        return override
    if isinstance(packet, dict) and packet.get("pack"):
        return packet["pack"]
    prefix = os.path.basename(path).split(".")[0]  # e.g. reserve-flow.valid.json -> reserve-flow
    return prefix if prefix in registry["packs"] else None


def discover_packets(directory):
    """Return sorted *.json packet paths, skipping ledgers and attestation outputs."""
    out = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json") or name.endswith(".attestation.json"):
            continue
        if "ledger" in name:
            continue
        out.append(os.path.join(directory, name))
    return out


def run_audit(directory, registry, ledger_path, now="", attest_out=None, pack_override=None):
    """Batch audit a directory. Rewrites its own ledger fresh so re-runs are idempotent."""
    if os.path.exists(ledger_path):
        os.remove(ledger_path)  # audit owns this ledger; fresh each run
    if attest_out:
        os.makedirs(attest_out, exist_ok=True)

    entries, unroutable = [], []
    by_verdict = {"valid": 0, "thin": 0, "breach": 0}
    by_pack = {}
    packets = discover_packets(directory)

    for path in packets:
        fname = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8") as f:
                packet = json.load(f)
        except (ValueError, OSError) as exc:
            unroutable.append({"file": fname, "reason": f"invalid json: {exc}"})
            continue
        pack_name = _route(packet, path, registry, pack_override)
        if not pack_name or pack_name not in registry["packs"]:
            unroutable.append({"file": fname, "reason": f"unroutable (pack={pack_name})"})
            continue

        pack = get_pack(registry, pack_name)
        result = run_gates(packet, pack["predicate_fns"], now=now,
                           id_field=pack.get("id_field", "packet_id"), schema=pack.get("schema"))
        result["pack"] = pack_name
        result["source_project"] = pack.get("source_project")
        record = append_record(ledger_path, result, pack_name, now=now)

        by_verdict[result["verdict"]] = by_verdict.get(result["verdict"], 0) + 1
        by_pack[pack_name] = by_pack.get(pack_name, 0) + 1

        att = None
        if result["verdict"] != "breach":
            att = issue_attestation(
                result, chain={"pack": pack_name, "source_project": pack.get("source_project")}, now=now)
            if attest_out and att:
                with open(os.path.join(attest_out, f"{att['attestation_id']}.json"),
                          "w", encoding="utf-8") as f:
                    json.dump(att, f, ensure_ascii=False, indent=2, sort_keys=True)
                    f.write("\n")
        entries.append({
            "file": fname, "pack": pack_name, "subject": result["subject"],
            "verdict": result["verdict"], "ledger_index": record["index"],
            "attestation_id": att["attestation_id"] if att else None,
        })

    return {
        "directory": directory, "ledger": ledger_path,
        "packets_seen": len(packets), "processed": len(entries),
        "by_verdict": by_verdict, "by_pack": by_pack,
        "unroutable": unroutable, "chain": verify_ledger(ledger_path),
        "attestations_issued": sum(1 for e in entries if e["attestation_id"]),
        "entries": entries,
    }


def render_audit_markdown(report):
    v = report["by_verdict"]
    lines = [
        f"# Attestra Audit — {report['directory']}",
        "",
        f"- processed: {report['processed']} / {report['packets_seen']} packets",
        f"- verdicts: valid={v['valid']} thin={v['thin']} breach={v['breach']}",
        f"- attestations issued: {report['attestations_issued']}",
        f"- ledger: `{report['ledger']}` — chain valid: {report['chain']['valid']} "
        f"({report['chain']['records']} records)",
        f"- unroutable: {len(report['unroutable'])}",
        "",
        "| # | file | pack | subject | verdict | attestation |",
        "|---|---|---|---|---|---|",
    ]
    for e in report["entries"]:
        lines.append(
            f"| {e['ledger_index']} | {e['file']} | {e['pack']} | {e['subject']} | "
            f"{e['verdict']} | {e['attestation_id'] or '—'} |")
    if report["unroutable"]:
        lines += ["", "## Unroutable", ""]
        lines += [f"- `{u['file']}` — {u['reason']}" for u in report["unroutable"]]
    lines.append("")
    return "\n".join(lines)
