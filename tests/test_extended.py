# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_extended as extended

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
SETUP_CHECKS = ["cold-setup", "repeat-setup"]
ALL_CHECKS = [*SETUP_CHECKS, "offline-cache", "standalone-audit", "compare-seed", "compare-asn1-ber", "mismatch-probe"]


def option(arguments, name):
    return arguments[arguments.index(name) + 1]


class FakeTools:
    """Stands in for the real scripts, so each check's decision is tested without Lua or a network."""

    def __init__(self):
        self.calls = []
        self.setups = 0
        self.setup_code = {}
        self.hits = {}
        self.codes = {}
        self.fixtures = {}
        self.reports = {}

    def __call__(self, script, arguments, log):
        name = log.stem
        self.calls.append((name, script, arguments))
        if script == "setup_lua.py":
            return self.setup(name, arguments)
        if script == "run_differential.py":
            return self.differential(name, arguments)
        return self.codes.get(name, 0), "Reproduced 2 mismatches\n"

    def setup(self, name, arguments):
        if self.setup_code.get(name):
            return self.setup_code[name], ""
        self.setups += 1
        path = Path(option(arguments, "--runs-dir")) / str(self.setups) / "provenance.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "configuration": {"platform": {"system": "Linux", "machine": "aarch64"}},
            "external": {"key": "key", "cache_hit": self.hits.get(name, name != "cold-setup")},
            "selected_opentlv": {"version": "0.3.0"}, "opentlv": {"acquisition": "fresh"},
        }), encoding="utf-8")
        return 0, f"External cache miss: key\nProvenance: {path}\n"

    def differential(self, name, arguments):
        code = self.codes.get(name, extended.MISMATCH_EXIT if name == "mismatch-probe" else 0)
        report = {"summary": {"pass": 2, "mismatch": 0, "unsupported": 1, "inconclusive": 0},
                  "fixtures": self.fixtures.get(name, [{"id": "same"}])}
        output, markdown = Path(option(arguments, "--output")), Path(option(arguments, "--report"))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report), encoding="utf-8")
        markdown.write_text(self.reports.get(name, "report"), encoding="utf-8")
        return code, ""


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "extended"
        self.tools = FakeTools()

    def run_suite(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(extended, "run_tool", self.tools), \
                patch.object(extended, "testlab_revision", return_value={"commit": "abc", "modified": False}), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = extended.main(["--output-dir", str(self.output), *extra])
        summary = json.loads((self.output / "summary.json").read_text(encoding="utf-8"))
        return code, summary

    def statuses(self, summary):
        return {check["name"]: check["status"] for check in summary["checks"]}

    def test_clean_run_passes_every_check_and_keeps_its_summary(self):
        code, summary = self.run_suite()
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual([check["name"] for check in summary["checks"]], ALL_CHECKS)
        self.assertEqual(set(self.statuses(summary).values()), {"passed"})
        self.assertEqual(summary["platform"]["machine"], "aarch64")
        rendered = (self.output / "summary.md").read_text(encoding="utf-8")
        self.assertIn("| compare-asn1-ber | passed | 2 pass, 0 mismatch, 1 unsupported, 0 inconclusive;", rendered)
        self.assertIn("Linux aarch64", rendered)

    def test_each_corpus_runs_twice_on_one_install_and_once_on_the_other(self):
        self.run_suite()
        receipts = {name: option(arguments, "--provenance") for name, script, arguments in self.tools.calls
                    if script == "run_differential.py"}
        self.assertEqual(receipts["seed"], receipts["seed-repeat"])
        self.assertNotEqual(receipts["seed"], receipts["seed-second-install"])
        self.assertEqual(receipts["asn1-ber"], receipts["asn1-ber-repeat"])
        self.assertNotEqual(receipts["asn1-ber"], receipts["asn1-ber-second-install"])

    def test_every_setup_shares_a_cache_and_the_tools_are_forwarded(self):
        self.run_suite("--lua", "/opt/lua", "--luarocks", "/opt/rocks", "--make", "/opt/make", "--lua-prefix", "/opt")
        setups = [arguments for _, script, arguments in self.tools.calls if script == "setup_lua.py"]
        self.assertEqual(len(setups), 3)
        self.assertEqual({option(arguments, "--cache-dir") for arguments in setups},
                         {str(self.output.resolve() / "cache")})
        for arguments in setups:
            self.assertEqual((option(arguments, "--lua"), option(arguments, "--luarocks"),
                              option(arguments, "--make"), option(arguments, "--lua-prefix")),
                             ("/opt/lua", "/opt/rocks", "/opt/make", str(Path("/opt"))))
        self.assertIn("--offline", setups[2])
        audit = next(arguments for _, script, arguments in self.tools.calls if script == "check_asn1.py")
        self.assertEqual(option(audit, "--lua"), "/opt/lua")
        self.assertIn("--download", audit)

    def test_failed_setup_ends_the_suite_without_a_verdict(self):
        for failing, expected in (("cold-setup", ["cold-setup"]), ("repeat-setup", SETUP_CHECKS)):
            with self.subTest(failing), tempfile.TemporaryDirectory() as directory:
                self.output, self.tools = Path(directory) / "out", FakeTools()
                self.tools.setup_code[failing] = 1
                code, summary = self.run_suite()
                self.assertEqual(code, 1)
                self.assertEqual(summary["status"], "failed")
                self.assertEqual([check["name"] for check in summary["checks"]], expected)

    def test_cache_behavior_is_asserted_in_both_directions(self):
        for name, hit in (("cold-setup", True), ("repeat-setup", False), ("offline-cache", False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                self.output, self.tools = Path(directory) / "out", FakeTools()
                self.tools.hits[name] = hit
                code, summary = self.run_suite()
                self.assertEqual(code, 1)
                self.assertEqual(self.statuses(summary)[name], "failed")

    def test_corpus_mismatch_keeps_its_exit_code_and_the_other_checks_still_run(self):
        self.tools.codes["seed"] = extended.MISMATCH_EXIT
        code, summary = self.run_suite()
        self.assertEqual(code, extended.MISMATCH_EXIT)
        self.assertEqual(summary["status"], "mismatch")
        statuses = self.statuses(summary)
        self.assertEqual(statuses["compare-seed"], "mismatch")
        self.assertEqual(statuses["compare-asn1-ber"], "passed")
        self.assertEqual(statuses["mismatch-probe"], "passed")

    def test_run_failure_outranks_a_mismatch(self):
        self.tools.codes.update({"seed": extended.MISMATCH_EXIT, "asn1-ber": 1})
        code, summary = self.run_suite()
        self.assertEqual(code, 1)
        self.assertEqual(self.statuses(summary)["compare-asn1-ber"], "failed")

    def test_unstable_or_install_dependent_results_fail(self):
        for field, name, value in (("reports", "seed-repeat", "other report"),
                                   ("fixtures", "seed-repeat", [{"id": "other"}]),
                                   ("fixtures", "seed-second-install", [{"id": "other"}])):
            with self.subTest(name=name, field=field), tempfile.TemporaryDirectory() as directory:
                self.output, self.tools = Path(directory) / "out", FakeTools()
                getattr(self.tools, field)[name] = value
                code, summary = self.run_suite()
                self.assertEqual(code, 1)
                self.assertEqual(self.statuses(summary)["compare-seed"], "failed")

    def test_probe_must_mismatch_and_reproduce(self):
        for name, value in (("mismatch-probe", 0), ("mismatch-probe", 1), ("mismatch-probe-check", 1)):
            with self.subTest(name=name, value=value), tempfile.TemporaryDirectory() as directory:
                self.output, self.tools = Path(directory) / "out", FakeTools()
                self.tools.codes[name] = value
                code, summary = self.run_suite()
                self.assertEqual(code, 1)
                self.assertEqual(self.statuses(summary)["mismatch-probe"], "failed")

    def test_timeout_or_missing_tool_is_a_failed_check(self):
        def broken(script, arguments, log):
            raise extended.subprocess.TimeoutExpired(script, 1)

        self.tools = broken
        code, summary = self.run_suite()
        self.assertEqual(code, 1)
        self.assertEqual(self.statuses(summary), {"cold-setup": "failed"})

    def test_an_existing_output_directory_cannot_stand_in_for_a_cold_cache(self):
        self.output.mkdir()
        (self.output / "cache").mkdir()
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            extended.main(["--output-dir", str(self.output)])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("not empty", stderr.getvalue())

    def test_summary_table_cannot_be_broken_by_a_detail(self):
        rendered = extended.render_summary({
            "status": "failed", "testlab": {"commit": None, "modified": None}, "platform": None,
            "checks": [{"name": "x", "status": "failed", "detail": "a|b\nc"}]})
        self.assertIn("| x | failed | a\\|b c |", rendered)
        self.assertIn("`unknown`", rendered)


def triggers(workflow):
    """The workflow's `on` block: these tests must not need a YAML package on the Fast runner."""
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    return re.search(r"^on:\n(.*?)^permissions:", text, re.MULTILINE | re.DOTALL).group(1)


class WorkflowTests(unittest.TestCase):
    def test_extended_never_runs_on_every_pull_request(self):
        on = triggers("extended.yml")
        self.assertIn("workflow_dispatch:", on)
        self.assertNotRegex(on, r"(?m)^  (push|schedule|pull_request_target):")
        self.assertEqual(re.findall(r"(?m)^      - (\S+)$", on),
                         [".github/workflows/extended.yml", "scripts/run_extended.py"])

    def test_extended_starts_cold_and_keeps_its_artifacts_after_a_failure(self):
        text = (WORKFLOWS / "extended.yml").read_text(encoding="utf-8")
        self.assertNotIn("actions/cache", text)
        self.assertRegex(text, r"if: always\(\)\n\s+uses: actions/upload-artifact@")
        self.assertIn("scripts/run_extended.py", text)
        self.assertIn("build/extended/reports/", text)

    def test_fast_gates_every_pull_request_on_setup_and_a_small_corpus(self):
        self.assertRegex(triggers("fast.yml"), r"(?m)^  pull_request:$")
        text = (WORKFLOWS / "fast.yml").read_text(encoding="utf-8")
        for command in ("-m unittest discover", "scripts/setup_lua.py --lua lua5.2 --external-only --offline",
                        "scripts/run_differential.py", "differential/fixtures/asn1-ber.json",
                        "tests/fixtures/differential_mismatch.json", "scripts/check_report.py"):
            self.assertIn(command, text)
        self.assertNotIn("run_extended", text)


if __name__ == "__main__":
    unittest.main()
