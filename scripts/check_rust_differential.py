#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Exercise the real adapters and CLI's pass, mismatch and setup-failure gates."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

if __package__:
    from . import check_report, run_rust_differential as runner, setup_rust_differential as setup
    from .setup_lua import require
else:
    import check_report
    import run_rust_differential as runner
    import setup_rust_differential as setup
    from setup_lua import require


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, default=setup.RECEIPT)
    parser.add_argument("--output-dir", type=Path, default=runner.REPORTS / "probes")
    args = parser.parse_args(arguments)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    try:
        def execute(name, options, expected):
            output = args.output_dir / (name + ".json")
            command = [sys.executable, str(runner.ROOT / "scripts/run_rust_differential.py"),
                       "--provenance", str(args.provenance), "--output", str(output),
                       "--report", str(output.with_suffix(".md")), *options]
            status = subprocess.run(command, cwd=runner.ROOT, timeout=60).returncode
            require(status == expected, f"{name}: expected exit {expected}, received {status}")
            return json.loads(output.read_text(encoding="utf-8"))

        for fixture, expected, status in (("der-sequence", 0, "passed"), ("ber-high-tag-leading-80", 3, "mismatch")):
            first = execute(fixture, ["--fixture", fixture], expected)
            second = execute(fixture + "-repeat", ["--fixture", fixture], expected)
            require(first == second and first["status"] == status, "non-reproducible adapter result")
        check_report.check_report(args.output_dir / "ber-high-tag-leading-80.json")
        failure = execute("setup-failure", ["--provenance", str(args.output_dir / "absent-receipt.json")], 1)
        require(failure["status"] == "failed" and failure["error"] and not failure["fixtures"],
                "setup failure masqueraded as a verdict")
        print("Verified deterministic agreement, real shared mismatch, report reproduction and setup failure.")
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Rust differential probes failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
