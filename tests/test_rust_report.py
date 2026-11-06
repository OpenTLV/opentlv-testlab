# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import report_rust_differential as report

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/rust-report.md"


class RustReportTests(unittest.TestCase):
    def setUp(self):
        load = report.reference.load_json
        self.corpus = load(report.reference.CORPUS)
        self.baseline = load(report.gate.BASELINE)
        self.gaps = load(report.audit.GAPS)
        self.triage = load(report.TRIAGE)
        self.ergonomics = load(report.ERGONOMICS)

    def check(self):
        return report.validate_triage(self.triage, self.corpus, self.baseline, self.gaps)

    def finding(self, name):
        return next(f for f in self.triage["findings"] if f["id"] == name)

    def test_every_nonpass_outcome_has_exactly_one_finding(self):
        summary = self.check()
        diverging = {c["fixture"] for c in self.baseline["cases"]}
        nonshared = {f["id"] for f in self.corpus["fixtures"] if f["classification"] != "shared"}
        self.assertEqual(set(summary["outcomes"]), diverging | nonshared)
        self.assertEqual(summary["opentlv_defects"], 0)
        self.assertEqual(sum(summary["classification"].values()), summary["findings"])

    def test_untriaged_or_doubly_triaged_fixture_fails(self):
        self.finding("reference-eoc-objects")["fixtures"].remove("ber-eoc-root")
        with self.assertRaisesRegex(ValueError, "untriaged outcomes: ber-eoc-root"):
            self.check()
        self.setUp()
        self.finding("ber-boolean-typed-validity")["fixtures"].append("ber-eoc-root")
        with self.assertRaisesRegex(ValueError, "triaged by"):
            self.check()

    def test_defect_requires_a_diverging_shared_fixture(self):
        self.finding("reference-eoc-objects")["classification"] = "defect"
        with self.assertRaisesRegex(ValueError, "a defect needs diverging shared fixtures"):
            self.check()

    def test_shared_mismatch_cannot_be_inconclusive(self):
        self.finding("reference-truncated-identifier-category")["classification"] = "inconclusive"
        with self.assertRaisesRegex(ValueError, "definite expectation"):
            self.check()

    def test_minimized_cases_must_not_grow_and_must_name_all_participants(self):
        case = self.finding("reference-nonminimal-der-length")["minimized"][0]
        case["wire"] = "04 82 00 01 aa 00"
        with self.assertRaisesRegex(ValueError, "not minimal"):
            self.check()
        self.setUp()
        del self.finding("reference-nonminimal-der-length")["minimized"][0]["observed"]["core"]
        with self.assertRaisesRegex(ValueError, "invalid minimized observation"):
            self.check()

    def test_tracked_state_requires_issue_link_and_gaps_match_inventory(self):
        self.finding("reference-nonminimal-identifier")["upstream"]["issue"] = None
        with self.assertRaisesRegex(ValueError, "needs an issue link"):
            self.check()
        self.setUp()
        self.finding("rust-der-schema")["upstream"]["state"] = "closed"
        with self.assertRaisesRegex(ValueError, "published gap inventory"):
            self.check()
        self.setUp()
        self.triage["findings"] = [f for f in self.triage["findings"] if f["id"] != "rust-asn1-codecs"]
        with self.assertRaisesRegex(ValueError, "every published Rust gap"):
            self.check()

    def test_ergonomics_anchors_and_entry_points_must_exist(self):
        metrics = report.assess_ergonomics(self.ergonomics)
        self.assertEqual(tuple(metrics), report.setup.PARTICIPANTS)
        self.assertEqual(metrics["der-parser"]["registry_packages"], 19)
        self.assertEqual(metrics["rust-binding"]["unsafe_code"], "forbidden")
        broken = copy.deepcopy(self.ergonomics)
        broken["dimensions"][0]["assessments"]["core"]["evidence"][0]["contains"] = "no such text"
        with self.assertRaisesRegex(ValueError, "stale anchor"):
            report.assess_ergonomics(broken)
        broken = copy.deepcopy(self.ergonomics)
        broken["participants"]["core"]["entry_points"].append("tlv_missing_function")
        with self.assertRaisesRegex(ValueError, "entry points not used"):
            report.assess_ergonomics(broken)

    def test_code_lines_exclude_tests_comments_and_blank_lines(self):
        text = "// c\nfn a() {}\n\n/* x\n * y\n */\nlet b = 1;\n#[cfg(test)]\nmod tests { fn t() {} }\n"
        self.assertEqual(report.code_lines(text), 2)

    def test_coverage_denominators_follow_the_gate(self):
        built = report.build()
        total = built["scenarios"]["all"]
        shared = sum(f["classification"] == "shared" for f in self.corpus["fixtures"])
        self.assertEqual(total["shared"], report.ratio(shared, len(self.corpus["fixtures"])))
        self.assertEqual(total["agreement"], report.ratio(shared - len(self.baseline["cases"]), shared))
        self.assertEqual(total["participants"]["core"], report.ratio(shared, shared))
        caps = built["capabilities"]
        self.assertEqual(caps["binding_missing"], ["schema"])
        self.assertEqual(caps["binding_not_tested"], ["cer"])
        self.assertIsNone(built["execution"])

    def comparison(self):
        """A run where only the recorded divergences differ from the expectations."""
        cases = {c["fixture"]: c for c in self.baseline["cases"]}
        rows = []
        for fixture in self.corpus["fixtures"]:
            expected = fixture["expected"]
            observed = {name: {"result": expected["result"], "tree": copy.deepcopy(expected.get("tree")),
                               "error": {"category": expected.get("error")}}
                        for name in report.setup.PARTICIPANTS}
            if fixture["id"] in cases:
                observed = copy.deepcopy(cases[fixture["id"]]["observed"])
            outcome, differences, reasons = report.runner.classify(fixture, observed)
            rows.append({**copy.deepcopy(fixture), "observed": observed, "outcome": outcome,
                         "differences": differences, "reasons": reasons})
        return {"schema": 1, "runner": "run_rust_differential.py", "status": "mismatch",
                "packages": report.setup.package_pins(), "fixtures": rows,
                "coverage": report.runner.coverage(rows)}

    def test_execution_matches_gated_coverage(self):
        expected = report.scenarios(self.corpus, self.baseline)
        result = report.execution(self.comparison(), self.corpus, self.baseline, expected)
        self.assertEqual(len(result["matched_divergences"]), len(self.baseline["cases"]))
        self.assertEqual(result["participants"]["all"], expected["all"]["participants"])

    def test_execution_rejects_coverage_that_differs_from_the_gate(self):
        expected = report.scenarios(self.corpus, self.baseline)
        comparison = self.comparison()
        row = next(r for r in comparison["fixtures"] if r["id"] == "der-sequence")
        row["observed"]["core"] = {"result": "reject", "tree": None, "error": {"category": "invalid"}}
        # Bypass the gate to prove the report checks coverage independently.
        with mock.patch.object(report.gate, "validate", return_value=[]):
            with self.assertRaisesRegex(ValueError, "participant coverage differs"):
                report.execution(comparison, self.corpus, self.baseline, expected)

    def test_failed_build_writes_failed_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output, markdown = Path(directory) / "r.json", Path(directory) / "r.md"
            with mock.patch.object(report, "build", side_effect=ValueError("broken evidence")):
                code = report.main(["--output", str(output), "--report", str(markdown)])
            self.assertEqual(code, 1)
            self.assertIn("broken evidence", markdown.read_text(encoding="utf-8"))
            self.assertIn('"status": "failed"', output.read_text(encoding="utf-8"))

    def test_published_guide_states_the_computed_tables(self):
        text = GUIDE.read_text(encoding="utf-8")
        for name, lines in report.tables(report.build()).items():
            for line in lines[2:]:
                with self.subTest(table=name, line=line):
                    self.assertIn(line, text)


if __name__ == "__main__":
    unittest.main()
