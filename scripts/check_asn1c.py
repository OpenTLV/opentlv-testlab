#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Rerun the asn1c capability probes on the adapter from a passed setup, without rebuilding it."""

import argparse
import json
from pathlib import Path
import sys

if __package__:
    from .check_asn1 import ROOT
    from .setup_asn1c import (ADAPTER_SOURCE, CAPABILITIES, audit, inventory, load_capabilities, load_pin,
                              schema_identity, select_probes, verify_install)
    from .setup_lua import digest, require, write_json
else:
    from check_asn1 import ROOT
    from setup_asn1c import (ADAPTER_SOURCE, CAPABILITIES, audit, inventory, load_capabilities, load_pin,
                             schema_identity, select_probes, verify_install)
    from setup_lua import digest, require, write_json


def newest_receipt(runs):
    candidates = []
    for path in runs.glob("*/provenance.json"):
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("status") == "passed":
            candidates.append((report["completed_at"], path))
    require(candidates, f"No passed asn1c setup in {runs}; run scripts/setup_asn1c.py first")
    return max(candidates)[1]


def load_receipt(path):
    """Results may only come from the committed pin, schema and adapter, built as recorded."""
    report = json.loads(path.read_text(encoding="utf-8"))
    require(report.get("status") == "passed", f"Receipt is not a passed asn1c setup: {path}")
    pin, schema = load_pin(), schema_identity()
    external, generation, adapter = report["external"], report["generation"], report["adapter"]
    require(external["pin"] == pin, "Receipt uses a different asn1c pin")
    require(generation["schema"] == schema, "Schema changed after setup; run scripts/setup_asn1c.py again")
    require(adapter["source_sha256"] == digest(ADAPTER_SOURCE),
            "Adapter source changed after setup; run scripts/setup_asn1c.py again")
    verify_install(Path(external["directory"]), pin, report["configuration"])
    require(inventory(path.parent / "generated") == generation["files"], "Generated sources changed after setup")
    require(digest(Path(adapter["path"])) == adapter["sha256"], "Adapter binary changed after setup")
    return report, pin, schema


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=ROOT / "build/asn1c-runs")
    parser.add_argument("--provenance", type=Path, help="Setup receipt; default is the newest passed one")
    parser.add_argument("--probe", action="append", default=[], help="Run only this probe id; repeatable")
    parser.add_argument("--output", type=Path, help="Write every observation as JSON")
    args = parser.parse_args()
    try:
        receipt = (args.provenance or newest_receipt(args.runs_dir)).resolve()
        report, pin, schema = load_receipt(receipt)
        probes = select_probes(load_capabilities()["probes"], args.probe)
        results = audit(report["adapter"]["path"], probes, pin, schema)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            write_json(args.output, {"schema": 1, "receipt": str(receipt), "asn1c": pin["version"],
                                     "reference": schema, "capabilities": digest(CAPABILITIES),
                                     "results": results})
        changed = [r["id"] for r in results if r["status"] != "pass"]
        require(not changed, f"asn1c behavior differs from the capability probes: {', '.join(changed)}")
    except (OSError, ValueError, KeyError) as error:
        print(f"asn1c capability audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
