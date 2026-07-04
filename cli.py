#!/usr/bin/env python3
"""Attestra CLI — sample / run / verify / report / attest / pack / determinism.

stdlib only. `now` is injected via --now (default ""), never read from the clock,
so the whole tool is deterministic.
"""

import argparse
import json
import os
import sys

from attestra_core.gate_runtime import run_gates
from attestra_core.ledger import append_record, verify_ledger
from attestra_core.attestation import issue_attestation
from attestra_core.determinism import check_tree
from attestra_packs.loader import load_packs, get_pack
from attestra_pipeline import run_pipeline

ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dump(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def _evaluate(registry, pack_name, packet, now):
    pack = get_pack(registry, pack_name)
    result = run_gates(packet, pack["predicate_fns"], now=now,
                       id_field=pack.get("id_field", "packet_id"),
                       schema=pack.get("schema"))
    result["pack"] = pack_name
    result["source_project"] = pack.get("source_project")
    return result


def cmd_sample(args, registry):
    pack = get_pack(registry, args.pack)
    os.makedirs(args.out, exist_ok=True)
    written = {}
    for name, packet in pack["samples"].items():
        path = os.path.join(args.out, f"{args.pack}.{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(packet, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        written[name] = path
    _dump({"pack": args.pack, "written": written})
    return 0


def cmd_run(args, registry):
    packet = _load_json(args.input)
    if args.pipeline:
        names = [n.strip() for n in args.pipeline.split(",") if n.strip()]
        result = run_pipeline(packet, names, registry, now=args.now)
    else:
        result = _evaluate(registry, args.pack, packet, args.now)
        if args.ledger:
            record = append_record(args.ledger, result, args.pack, now=args.now)
            result["ledger_record"] = {"index": record["index"], "record_hash": record["record_hash"]}
    _dump(result)
    return 0 if result["verdict"] != "breach" else 1


def cmd_attest(args, registry):
    packet = _load_json(args.input)
    result = _evaluate(registry, args.pack, packet, args.now)
    chain = {"pack": args.pack, "source_project": result.get("source_project")}
    att = issue_attestation(result, chain=chain, now=args.now)
    if att is None:
        _dump({"issued": False, "reason": "breach verdict — attestation refused",
               "verdict": result["verdict"]})
        return 1
    _dump({"issued": True, "attestation": att})
    return 0


def cmd_verify(args, _registry):
    _dump(verify_ledger(args.ledger))
    return 0


def cmd_report(args, registry):
    packet = _load_json(args.input)
    result = _evaluate(registry, args.pack, packet, args.now)
    md = render_markdown(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
        _dump({"report": args.out, "verdict": result["verdict"]})
    else:
        print(md)
    return 0


def cmd_pack(args, registry):
    _dump({
        "packs": [
            {"name": p["name"], "version": p["version"], "predicates": p["predicates"],
             "source_project": p["source_project"], "fingerprint": p["fingerprint"][:16]}
            for p in registry["packs"].values()
        ],
        "dropped": registry["dropped"],
        "errors": registry["errors"],
    })
    return 0


def cmd_determinism(_args, _registry):
    report = check_tree(ROOT)
    _dump(report)
    return 0 if report["clean"] else 1


def render_markdown(result):
    lines = [
        f"# Attestra Report — {result.get('subject', '')} ({result.get('pack', '')})",
        "",
        f"- verdict: **{result['verdict']}**",
        f"- worst: {result.get('worst')}",
        f"- source_project: {result.get('source_project', '')}",
        "",
        "## Checks",
        "",
        "| gate | verdict | evidence_path | reason |",
        "|---|---|---|---|",
    ]
    for c in result.get("checks", []):
        lines.append(f"| {c['gate']} | {c['verdict']} | `{c.get('evidence_path','')}` | {c['reason']} |")
    lines.append("")
    return "\n".join(lines)


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--now", default="", help="injected timestamp metadata (default empty)")

    p = argparse.ArgumentParser(prog="attestra", parents=[common],
                                description="Deterministic verdict/attestation platform")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sample", parents=[common], help="write a pack's sample packets")
    s.add_argument("--pack", required=True)
    s.add_argument("--out", default="examples")

    s = sub.add_parser("run", parents=[common], help="evaluate a packet (single pack or --pipeline)")
    s.add_argument("--pack")
    s.add_argument("--pipeline", help="comma-separated pack names")
    s.add_argument("--input", required=True)
    s.add_argument("--ledger")

    s = sub.add_parser("attest", parents=[common], help="issue an attestation for a non-breach verdict")
    s.add_argument("--pack", required=True)
    s.add_argument("--input", required=True)

    s = sub.add_parser("verify", parents=[common], help="verify a ledger's hash chain")
    s.add_argument("--ledger", required=True)

    s = sub.add_parser("report", parents=[common], help="render a markdown verdict report")
    s.add_argument("--pack", required=True)
    s.add_argument("--input", required=True)
    s.add_argument("--out")

    sub.add_parser("pack", parents=[common], help="list loaded packs").add_argument(
        "list", nargs="?", help="(positional, optional)")

    sub.add_parser("determinism", parents=[common], help="scan kernel+packs for boundary violations")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    registry = load_packs()
    dispatch = {
        "sample": cmd_sample, "run": cmd_run, "attest": cmd_attest, "verify": cmd_verify,
        "report": cmd_report, "pack": cmd_pack, "determinism": cmd_determinism,
    }
    if args.cmd == "run" and not args.pack and not args.pipeline:
        print("run requires --pack or --pipeline", file=sys.stderr)
        return 2
    return dispatch[args.cmd](args, registry)


if __name__ == "__main__":
    raise SystemExit(main())
