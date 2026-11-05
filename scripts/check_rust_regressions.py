#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Gate a fresh full comparison against explicit, exact reference divergences."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

if __package__:
    from . import check_rust_reference as reference, run_rust_differential as runner
    from . import setup_rust_differential as setup
    from .setup_lua import require, write_json
else:
    import check_rust_reference as reference
    import run_rust_differential as runner
    import setup_rust_differential as setup
    from setup_lua import require, write_json

BASELINE = reference.ROOT / "differential/rust/divergences.json"


def identity(value):
    """JSON content identity is independent of checkout newline conventions."""
    return reference.digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def validate(report, baseline, corpus, packages):
    require(baseline.get("schema") == 1, "unknown divergence baseline schema")
    require(baseline["corpus_sha256"] == identity(corpus), "corpus changed; review divergence baseline")
    require(baseline["packages_sha256"] == identity(packages) and report.get("packages") == packages,
            "package pins changed; review divergence baseline")
    require(report.get("schema") == 1 and report.get("runner") == "run_rust_differential.py" and
            report.get("status") in ("passed", "mismatch") and not report.get("error"),
            "comparison did not complete successfully")
    expected = {f["id"]: f for f in corpus["fixtures"]}
    rows = report.get("fixtures", [])
    require(len(rows) == len(expected) and {f["id"] for f in rows} == set(expected),
            "regression gate requires the entire corpus exactly once")
    cases = baseline["cases"]
    require(isinstance(cases, list), "invalid divergence cases")
    known = {c["fixture"]: c for c in cases}
    require(len(known) == len(cases) and known.keys() <= expected.keys(), "duplicate or unknown baseline fixture")
    for name, case in known.items():
        require(expected[name]["classification"] == "shared" and
                case["kind"] in ("reference-acceptance", "diagnostic-category") and
                isinstance(case["reason"], str) and case["reason"].strip() and
                isinstance(case["evidence"], list) and case["evidence"] and all(case["evidence"]),
                f"{name}: missing divergence rationale/evidence")
    matched = []
    for row in rows:
        name = row["id"]
        fixture = expected[name]
        require(all(row.get(k) == v for k, v in fixture.items()), f"{name}: fixture contract differs")
        observed = row["observed"]
        require(set(observed) == {"core", "der-parser"}, f"{name}: missing participant")
        outcome, differences, reasons = runner.classify(fixture, observed)
        require((row["outcome"], row["differences"], row["reasons"]) == (outcome, differences, reasons),
                f"{name}: inconsistent comparison verdict")
        if name in known:
            case = known[name]
            require(outcome == "mismatch", f"{name}: recorded divergence disappeared; review baseline")
            require(observed == case["observed"], f"{name}: recorded participant observation changed")
            require(runner.classify(fixture, {"core": observed["core"]})[0] == "pass",
                    f"{name}: Core must still meet the independent expectation")
            matched.append(name)
        elif fixture["classification"] == "shared":
            require(outcome == "pass", f"{name}: unexpected shared {outcome}: {differences or reasons}")
    require(report["coverage"] == runner.coverage(rows), "inconsistent coverage")
    require(report["status"] == ("mismatch" if matched else "passed"), "inconsistent standards status")
    return sorted(matched)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, default=setup.RECEIPT)
    parser.add_argument("--output-dir", type=Path, default=runner.REPORTS)
    args = parser.parse_args(arguments)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    gate = {"schema": 1, "status": "failed", "standards_status": None,
            "matched_divergences": [], "error": "regression check incomplete",
            "checker_sha256": reference.digest(Path(__file__).read_text(encoding="utf-8").encode())}
    gate_path = args.output_dir / "regressions.json"
    write_json(gate_path, gate)
    try:
        baseline = reference.load_json(BASELINE)
        corpus = reference.load_json(reference.CORPUS)
        reference.verify_corpus(corpus, reference.load_json(reference.MATRIX))
        packages = {"core": reference.load_json(setup.PIN), "der-parser": reference.load_json(reference.PIN)}
        gate["baseline_sha256"] = identity(baseline)
        # Never accept a stale report after a crash or an invocation that writes nothing.
        with tempfile.TemporaryDirectory(prefix=".regression-", dir=args.output_dir) as directory:
            output = Path(directory) / "comparison.json"
            markdown = output.with_suffix(".md")
            command = [sys.executable, str(reference.ROOT / "scripts/run_rust_differential.py"),
                       "--provenance", str(args.provenance), "--output", str(output), "--report", str(markdown)]
            status = subprocess.run(command, cwd=reference.ROOT, timeout=600).returncode
            if output.is_file():
                shutil.copyfile(output, args.output_dir / output.name)
            if markdown.is_file():
                shutil.copyfile(markdown, args.output_dir / markdown.name)
            require(status in (0, 3), f"comparison process failed with exit {status}")
            report = reference.load_json(output)
            gate["standards_status"] = report.get("status")
            gate["comparison_sha256"] = identity(report)
            require(status == (3 if report.get("status") == "mismatch" else 0), "exit/status mismatch")
            matched = validate(report, baseline, corpus, packages)
            gate.update(status="passed", matched_divergences=matched, error=None)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        gate["error"] = str(error)
    write_json(gate_path, gate)
    summary = (f"Regression gate: {gate['status']}; standards comparison: {gate['standards_status']}; "
               f"{len(gate['matched_divergences'])} exact reference divergences")
    print(summary)
    if gate["error"]:
        print(gate["error"], file=sys.stderr)
    (args.output_dir / "regressions.md").write_text(
        "# Rust differential regression gate\n\n" + summary + "\n\n" +
        (gate["error"] or "The standards report and its mismatch counts are unchanged. "
         "Each listed divergence matches both participant observations exactly; "
         "every other shared fixture meets the independent expectation.") + "\n", encoding="utf-8")
    return 0 if gate["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
