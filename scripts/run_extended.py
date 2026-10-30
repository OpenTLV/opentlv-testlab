#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Run the manual extended suite: cold and repeated setup, every corpus and the mismatch probe."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

if __package__:
    from .check_asn1 import ROOT
    from .run_differential import MISMATCH_EXIT, OUTCOMES, testlab_revision
    from .setup_lua import require
else:
    from check_asn1 import ROOT
    from run_differential import MISMATCH_EXIT, OUTCOMES, testlab_revision
    from setup_lua import require

CORPORA = ("differential/fixtures/seed.json", "differential/fixtures/asn1-ber.json")
PROBE = "tests/fixtures/differential_mismatch.json"
TOOL_TIMEOUT = 1200
EXIT_CODES = {"passed": 0, "failed": 1, "mismatch": MISMATCH_EXIT}


class MismatchFound(ValueError):
    """A committed corpus disagrees with a library, as opposed to the suite failing to run."""


def run_tool(script, arguments, log):
    """Run one TestLab script and keep its output as an artifact."""
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / script), *arguments], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace", timeout=TOOL_TIMEOUT)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(result.stdout, encoding="utf-8")
    return result.returncode, result.stdout


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class Suite:
    def __init__(self, args):
        self.output = args.output_dir.resolve()
        self.lua = args.lua
        self.setup_tools = ["--lua", args.lua, "--luarocks", args.luarocks, "--make", args.make]
        if args.lua_prefix:
            self.setup_tools += ["--lua-prefix", str(args.lua_prefix)]
        self.receipts = {}
        self.platform = None

    def tool(self, script, arguments, log_name):
        return run_tool(script, arguments, self.output / "logs" / f"{log_name}.log")

    def setup(self, name, *extra):
        code, output = self.tool("setup_lua.py", [*self.setup_tools, "--cache-dir", str(self.output / "cache"),
                                                  "--runs-dir", str(self.output / "runs"), *extra], name)
        require(code == 0, f"Setup exited {code}; see logs/{name}.log")
        receipt = re.search(r"^Provenance: (.+)$", output, re.MULTILINE)
        require(receipt, f"Setup named no receipt; see logs/{name}.log")
        path = Path(receipt.group(1).strip())
        self.receipts[name] = path
        return read_json(path)

    def cold_setup(self):
        receipt = self.setup("cold-setup")
        self.platform = receipt["configuration"]["platform"]
        require(not receipt["external"]["cache_hit"], "A new cache reported a hit")
        require(receipt["opentlv"]["acquisition"] == "fresh", "OpenTLV was not freshly acquired")
        return f"external cache miss; OpenTLV {receipt['selected_opentlv']['version']} installed fresh"

    def repeat_setup(self):
        first = read_json(self.receipts["cold-setup"])
        receipt = self.setup("repeat-setup")
        require(receipt["external"]["cache_hit"], "A second setup missed the external cache")
        require(receipt["external"]["key"] == first["external"]["key"], "A second setup used another cache key")
        require(receipt["opentlv"]["acquisition"] == "fresh", "OpenTLV was not freshly acquired")
        return "external cache hit; OpenTLV installed fresh again"

    def offline_cache(self):
        require(self.setup("offline-cache", "--external-only", "--offline")["external"]["cache_hit"],
                "Offline setup missed the external cache")
        return "external cache hit without network acquisition"

    def standalone_audit(self):
        code, _ = self.tool("check_asn1.py", ["--lua", self.lua, "--download",
                                              "--source-dir", str(self.output / "source")], "standalone-audit")
        require(code == 0, f"Audit exited {code}; see logs/standalone-audit.log")
        return "pinned upstream source downloaded and audited"

    def differential(self, corpus, name, receipt):
        reports = self.output / "reports"
        code, _ = self.tool("run_differential.py",
                            ["--fixtures", corpus, "--provenance", str(self.receipts[receipt]),
                             "--output", str(reports / f"{name}.json"), "--report", str(reports / f"{name}.md")], name)
        return code, reports / f"{name}.json", reports / f"{name}.md"

    def compare(self, corpus):
        name = Path(corpus).stem
        code, first_json, first_report = self.differential(corpus, name, "cold-setup")
        if code == MISMATCH_EXIT:
            raise MismatchFound(f"Mismatch; see reports/{name}.md")
        require(code == 0, f"Run exited {code}; see logs/{name}.log")
        code, again_json, again_report = self.differential(corpus, f"{name}-repeat", "cold-setup")
        require(code == 0, f"Repeat exited {code}; see logs/{name}-repeat.log")
        require(first_json.read_bytes() == again_json.read_bytes() and
                first_report.read_bytes() == again_report.read_bytes(), "Repeating the run changed its reports")
        code, other_json, _ = self.differential(corpus, f"{name}-second-install", "repeat-setup")
        require(code == 0, f"Second install exited {code}; see logs/{name}-second-install.log")
        report = read_json(first_json)
        require(report["fixtures"] == read_json(other_json)["fixtures"], "A second install changed the results")
        summary = ", ".join(f"{report['summary'][outcome]} {outcome}" for outcome in OUTCOMES)
        return f"{summary}; repeat and second install identical"

    def mismatch_probe(self):
        code, report, _ = self.differential(PROBE, "mismatch-probe", "cold-setup")
        require(code == MISMATCH_EXIT, f"Probe exited {code}, not {MISMATCH_EXIT}; see logs/mismatch-probe.log")
        code, output = self.tool("check_report.py", [str(report)], "mismatch-probe-check")
        require(code == 0, f"Report check exited {code}; see logs/mismatch-probe-check.log")
        return output.strip()


def run_checks(suite):
    """Later checks need both receipts, so a failed setup ends the suite; every other check still runs."""
    results = []

    def attempt(name, check, *arguments):
        try:
            result = {"name": name, "status": "passed", "detail": check(*arguments)}
        except MismatchFound as error:
            result = {"name": name, "status": "mismatch", "detail": str(error)}
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            result = {"name": name, "status": "failed", "detail": str(error)}
        results.append(result)
        print(f"{result['status']:<9} {name}: {result['detail']}", flush=True)
        return result["status"] == "passed"

    if attempt("cold-setup", suite.cold_setup) and attempt("repeat-setup", suite.repeat_setup):
        attempt("offline-cache", suite.offline_cache)
        attempt("standalone-audit", suite.standalone_audit)
        for corpus in CORPORA:
            attempt(f"compare-{Path(corpus).stem}", suite.compare, corpus)
        attempt("mismatch-probe", suite.mismatch_probe)
    return results


def overall_status(results):
    statuses = {result["status"] for result in results}
    return next(status for status in ("failed", "mismatch", "passed") if status in statuses)


def render_summary(summary):
    testlab = summary["testlab"]
    state = " with uncommitted changes" if testlab["modified"] else ""
    lines = ["# Extended suite", "", f"- Status: {summary['status']}",
             f"- TestLab commit: `{testlab['commit'] or 'unknown'}`{state}"]
    platform = summary["platform"]
    if platform:
        lines.append(f"- Platform: {platform.get('system')} {platform.get('machine')}")
    lines += ["", "| Check | Status | Detail |", "| --- | --- | --- |"]
    for result in summary["checks"]:
        detail = result["detail"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {result['name']} | {result['status']} | {detail} |")
    return "\n".join(lines) + "\n"


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lua", default="lua5.2")
    parser.add_argument("--luarocks", default="luarocks")
    parser.add_argument("--make", default="make")
    parser.add_argument("--lua-prefix", type=Path, help="Interpreter/headers prefix; default inferred from bin/lua")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/extended",
                        help="Must be new or empty, so that the cold setup really starts without a cache")
    args = parser.parse_args(arguments)
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error(f"Output directory is not empty: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    suite = Suite(args)
    results = run_checks(suite)
    status = overall_status(results)
    summary = {"schema": 1, "status": status, "testlab": testlab_revision(), "platform": suite.platform,
               "checks": results}
    (suite.output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (suite.output / "summary.md").write_text(render_summary(summary), encoding="utf-8")
    print(f"Extended suite {status}: {suite.output / 'summary.md'}")
    return EXIT_CODES[status]


if __name__ == "__main__":
    sys.exit(main())
