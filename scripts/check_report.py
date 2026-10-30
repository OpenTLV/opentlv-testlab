#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Check that a mismatch report is complete and that its own commands reproduce each mismatch."""

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

if __package__:
    from .check_asn1 import ROOT
    from .run_differential import ADAPTER_TIMEOUT, MISMATCH_EXIT
    from .setup_lua import require
else:
    from check_asn1 import ROOT
    from run_differential import ADAPTER_TIMEOUT, MISMATCH_EXIT
    from setup_lua import require

REQUIRED_FIELDS = ("wire", "operation", "schema", "expected", "differences", "differing_libraries", "reproduce")


def rerun(result, provenance):
    """Run the final step only: the same receipt stands in for the setup steps before it."""
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "rerun.json"
        command = [*shlex.split(result["reproduce"][-1]), "--provenance", provenance, "--output", str(output)]
        status = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                timeout=2 * ADAPTER_TIMEOUT).returncode
        require(status == MISMATCH_EXIT, f"{result['id']}: reproduction exited {status}, not {MISMATCH_EXIT}")
        return json.loads(output.read_text(encoding="utf-8"))


def check_report(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    require(report.get("status") == "mismatch", f"Report status is {report.get('status')}, not mismatch")
    require(report.get("runtime"), "Report does not name the runtime")
    packages = report.get("packages", {})
    require(packages.keys() == {"opentlv", "lua-asn1"} and all(p.get("version") for p in packages.values()),
            "Report does not name both package versions")
    mismatches = [result for result in report["fixtures"] if result["outcome"] == "mismatch"]
    require(mismatches, "Report contains no mismatch")
    for result in mismatches:
        for field in REQUIRED_FIELDS:
            require(result.get(field), f"{result['id']}: report has no {field}")
        require(result["observed"].keys() == packages.keys(), f"{result['id']}: report lacks an observation")
        again = rerun(result, report["provenance"])["fixtures"]
        require(again == [result], f"{result['id']}: reproduction gave a different result")
    return len(mismatches)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="JSON report from run_differential.py --output")
    args = parser.parse_args(arguments)
    try:
        print(f"Reproduced {check_report(args.report)} mismatches from {args.report}")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Report check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
