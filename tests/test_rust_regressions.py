# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import check_rust_regressions as gate


class RustRegressionTests(unittest.TestCase):
    def setUp(self):
        self.corpus = gate.reference.load_json(gate.reference.CORPUS)
        self.baseline = gate.reference.load_json(gate.BASELINE)
        self.packages = gate.setup.package_pins()
        cases = {c["fixture"]: c for c in self.baseline["cases"]}
        rows = []
        for fixture in self.corpus["fixtures"]:
            # Model compliant participants outside the six exact recorded cases.
            expected = fixture["expected"]
            observed = {name: {"result": expected["result"], "tree": copy.deepcopy(expected.get("tree")),
                               "error": {"category": expected.get("error")}}
                        for name in gate.setup.PARTICIPANTS}
            if fixture["id"] in cases:
                observed = copy.deepcopy(cases[fixture["id"]]["observed"])
            outcome, differences, reasons = gate.runner.classify(fixture, observed)
            rows.append({**copy.deepcopy(fixture), "observed": observed, "outcome": outcome,
                         "differences": differences, "reasons": reasons})
        self.report = {"schema": 1, "runner": "run_rust_differential.py", "status": "mismatch",
                       "packages": self.packages, "fixtures": rows, "coverage": gate.runner.coverage(rows)}

    def validate(self):
        return gate.validate(self.report, self.baseline, self.corpus, self.packages)

    def row(self, name):
        return next(f for f in self.report["fixtures"] if f["id"] == name)

    def reclassify(self, row):
        observed = {name: row["observed"][name] for name in gate.setup.PARTICIPANTS}
        row["outcome"], row["differences"], row["reasons"] = gate.runner.classify(row, observed)
        self.report["coverage"] = gate.runner.coverage(self.report["fixtures"])

    def test_exact_divergences_pass_regression_gate_without_changing_standards_report(self):
        before = copy.deepcopy(self.report)
        self.assertEqual(len(self.validate()), 6)
        self.assertEqual(self.report, before)
        self.assertEqual(self.report["status"], "mismatch")
        self.assertEqual(self.report["coverage"]["all"]["outcomes"],
                         {"pass": 46, "mismatch": 6, "unsupported": 2, "inconclusive": 9})

    def test_sorted_json_keys_preserve_multi_participant_difference_order(self):
        row = self.row("der-default-encoded")
        for name in gate.setup.PARTICIPANTS:
            row["observed"][name] = {"result": "accept", "tree": {}}
        self.reclassify(row)
        self.assertEqual(len(row["differences"]), 3)
        self.report = json.loads(json.dumps(self.report, sort_keys=True))
        self.assertEqual(len(self.validate()), 6)

    def test_new_shared_mismatch_fails(self):
        row = self.row("der-sequence")
        row["observed"]["der-parser"]["tree"]["number"] = "17"
        self.reclassify(row)
        with self.assertRaisesRegex(ValueError, "unexpected shared mismatch"):
            self.validate()

    def test_core_regression_on_a_known_reference_case_fails(self):
        row = self.row("ber-high-tag-leading-80")
        row["observed"]["core"] = copy.deepcopy(row["observed"]["der-parser"])
        self.reclassify(row)
        with self.assertRaisesRegex(ValueError, "participant observation changed"):
            self.validate()

    def test_binding_regression_or_missing_binding_cannot_hide_behind_reference_baseline(self):
        original = copy.deepcopy(self.report)
        row = self.row("ber-high-tag-leading-80")
        row["observed"]["rust-binding"] = copy.deepcopy(row["observed"]["der-parser"])
        self.reclassify(row)
        with self.assertRaisesRegex(ValueError, "participant observation changed"):
            self.validate()
        self.report = original
        self.row("der-sequence")["observed"].pop("rust-binding")
        with self.assertRaisesRegex(ValueError, "missing participant"):
            self.validate()

    def test_changed_reference_tree_and_native_error_fail(self):
        for name, change in (
            ("ber-high-tag-leading-80", lambda o: o["tree"].update(number="32")),
            ("der-truncated-identifier", lambda o: o["error"].update(native_code="other error")),
        ):
            original = copy.deepcopy(self.report)
            change(self.row(name)["observed"]["der-parser"])
            self.reclassify(self.row(name))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "participant observation changed"):
                self.validate()
            self.report = original

    def test_disappeared_divergence_requires_review(self):
        row = self.row("ber-high-tag-leading-80")
        row["observed"]["der-parser"] = copy.deepcopy(row["observed"]["core"])
        self.reclassify(row)
        with self.assertRaisesRegex(ValueError, "divergence disappeared"):
            self.validate()

    def test_missing_duplicate_and_selected_only_reports_fail(self):
        original = copy.deepcopy(self.report)
        for change in (lambda rows: rows.pop(), lambda rows: rows.append(rows[0]),
                       lambda rows: rows.__setitem__(0, rows[1])):
            change(self.report["fixtures"])
            with self.assertRaisesRegex(ValueError, "entire corpus exactly once"):
                self.validate()
            self.report = copy.deepcopy(original)

    def test_changed_pins_corpus_and_stale_baseline_fail(self):
        for field in ("packages_sha256", "corpus_sha256"):
            old = self.baseline[field]
            self.baseline[field] = "0" * 64
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "changed"):
                self.validate()
            self.baseline[field] = old
        self.baseline["cases"].append(copy.deepcopy(self.baseline["cases"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.validate()

    def test_fixture_expectation_and_classification_cannot_be_rewritten(self):
        for change in (lambda r: r.update(classification="unsupported"),
                       lambda r: r["expected"].update(result="accept")):
            original = copy.deepcopy(self.report)
            change(self.row("ber-high-tag-leading-80"))
            with self.assertRaisesRegex(ValueError, "fixture contract differs"):
                self.validate()
            self.report = original

    def test_forged_status_counts_or_missing_participant_fail(self):
        for change in (lambda r: r.update(status="passed"),
                       lambda r: r["coverage"]["all"].update(shared_pass=52),
                       lambda r: r["fixtures"][0]["observed"].pop("core")):
            original = copy.deepcopy(self.report)
            change(self.report)
            with self.assertRaises(ValueError):
                self.validate()
            self.report = original

    def test_failed_and_inconclusive_shared_evidence_never_passes(self):
        self.report["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "did not complete"):
            self.validate()
        self.report["status"] = "mismatch"
        row = self.row("der-sequence")
        row["observed"]["der-parser"] = {"result": "reject", "error": {"category": "unknown"}}
        self.reclassify(row)
        with self.assertRaisesRegex(ValueError, "unexpected shared inconclusive"):
            self.validate()

    def test_cli_requires_fresh_report_and_overwrites_stale_gate_success(self):
        for result in (subprocess.CompletedProcess([], 3), subprocess.CompletedProcess([], 1),
                       subprocess.TimeoutExpired("comparison", 600)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "comparison.json").write_text(json.dumps(self.report))
                (root / "regressions.json").write_text('{"status":"passed"}')
                kwargs = {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
                with mock.patch.object(gate.subprocess, "run", **kwargs):
                    self.assertEqual(gate.main(["--output-dir", directory]), 1)
                self.assertEqual(json.loads((root / "regressions.json").read_text())["status"], "failed")

    def test_cli_preserves_standards_exit_three_report(self):
        def execute(command, **kwargs):
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps(self.report))
            output.with_suffix(".md").write_text("Standards: mismatch\n")
            return subprocess.CompletedProcess(command, 3)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(gate.subprocess, "run", side_effect=execute):
            self.assertEqual(gate.main(["--output-dir", directory]), 0)
            root = Path(directory)
            self.assertEqual(json.loads((root / "comparison.json").read_text()), self.report)
            self.assertEqual(json.loads((root / "regressions.json").read_text())["standards_status"], "mismatch")


if __name__ == "__main__":
    unittest.main()
