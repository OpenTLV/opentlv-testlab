# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import check_rust_reference as reference, run_rust_differential as runner
from scripts import setup_rust_differential as setup


class RustDifferentialTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = {f["id"]: f for f in reference.load_json(reference.CORPUS)["fixtures"]}
        self.fixture = self.fixtures["der-sequence"]
        self.raw = {"result": "accept", "consumed": 8, "nodes": [
            {"offset": 0, "size": 8, "tag_size": 1, "value_offset": 2, "value_size": 6,
             "depth": 0, "number": "16", "class": 0, "constructed": True},
            {"offset": 2, "size": 3, "tag_size": 1, "value_offset": 4, "value_size": 1,
             "depth": 1, "number": "1", "class": 0, "constructed": False},
            {"offset": 5, "size": 3, "tag_size": 1, "value_offset": 7, "value_size": 1,
             "depth": 1, "number": "2", "class": 0, "constructed": False}]}

    def observation(self, name="core"):
        return runner.normalize(name, self.fixture, copy.deepcopy(self.raw))

    def test_library_ranges_project_complete_ordered_tree(self):
        self.assertEqual(self.observation()["tree"], self.fixture["expected"]["tree"])
        observed = {name: self.observation(name) for name in ("core", "der-parser")}
        self.assertEqual(runner.classify(self.fixture, observed), ("pass", [], []))
        self.assertNotEqual(observed["core"]["checks"], observed["der-parser"]["checks"])

    def test_indefinite_parent_excludes_own_eoc_and_preserves_child_eoc(self):
        wire = bytes.fromhex("30803080050000000000")
        nodes = [dict(self.raw["nodes"][0], size=10, value_size=6),
                 dict(self.raw["nodes"][0], offset=2, depth=1, size=6, value_offset=4, value_size=2),
                 dict(self.raw["nodes"][1], offset=4, depth=2, size=2, value_offset=6, value_size=0, number="5")]
        tree = runner.wire_tree(nodes, wire)
        self.assertEqual(tree["value_hex"], "308005000000")
        self.assertEqual(tree["children"][0]["value_hex"], "0500")

    def test_bad_ranges_missing_children_extra_nodes_and_invalid_types_fail(self):
        changes = [lambda r: r["nodes"].pop(), lambda r: r["nodes"].append(r["nodes"][1]),
                   lambda r: r["nodes"][1].update(offset=3),
                   lambda r: r["nodes"][1].update(depth=2),
                   lambda r: r["nodes"][1].update(value_size=5000),
                   lambda r: r["nodes"][0].update(constructed="true"),
                   lambda r: r.update(consumed=True), lambda r: r.update(extra="unexpected")]
        for change in changes:
            record = copy.deepcopy(self.raw)
            change(record)
            with self.subTest(record=record), self.assertRaises(ValueError):
                runner.normalize("core", self.fixture, record)

    def test_library_tag_disagreement_is_not_replaced_with_expected_tag(self):
        self.raw["nodes"][1]["number"] = "2"
        result = self.observation()
        self.assertEqual(result["tree"]["children"][0]["number"], "2")
        self.assertEqual(runner.classify(self.fixture, {"core": result})[0], "mismatch")

    def test_both_libraries_agreeing_with_each_other_can_still_mismatch(self):
        self.raw["nodes"][1]["number"] = "2"
        observed = {name: self.observation(name) for name in ("core", "der-parser")}
        outcome, differences, _ = runner.classify(self.fixture, observed)
        self.assertEqual(outcome, "mismatch")
        self.assertEqual(len(differences), 2)

    def test_declared_nonshared_cases_never_count_as_passes(self):
        for classification in ("unsupported", "inconclusive"):
            fixture = dict(self.fixture, classification=classification)
            self.assertEqual(runner.classify(fixture, {"core": self.observation()})[0], classification)

    def test_shared_capability_loss_fails_and_unknown_error_is_inconclusive(self):
        unsupported = runner.normalize("der-parser", self.fixture, {"result": "unsupported", "reason": "opaque"})
        self.assertEqual(runner.classify(self.fixture, {"der-parser": unsupported})[0], "mismatch")
        unknown = runner.normalize("der-parser", self.fixture, {"result": "reject", "error": {
            "category": "unknown", "source": "library", "stage": "unknown", "native_code": "Unmapped", "offset": None}})
        self.assertEqual(runner.classify(self.fixture, {"der-parser": unknown})[0], "inconclusive")

    def test_errors_preserve_native_identity_and_compare_categories(self):
        fixture = self.fixtures["der-truncated-identifier"]
        record = {"result": "reject", "error": {"category": "invalid", "source": "library",
                  "stage": "framing", "native_code": "Error(InvalidTag)", "offset": None}}
        normalized = runner.normalize("der-parser", fixture, record)
        self.assertEqual(normalized["error"], record["error"])
        self.assertEqual(runner.classify(fixture, {"der-parser": normalized})[0], "mismatch")
        record["error"]["offset"] = -1
        with self.assertRaises(ValueError):
            runner.normalize("der-parser", fixture, record)

    def test_denominator_excludes_unsupported_and_inconclusive(self):
        rows = [dict(self.fixture, outcome="pass"), dict(self.fixture, outcome="mismatch"),
                dict(self.fixture, classification="unsupported", outcome="unsupported")]
        coverage = runner.coverage(rows)["all"]
        self.assertEqual((coverage["executed"], coverage["shared"], coverage["shared_pass_percent"]), (3, 2, 50.0))

    def test_process_crash_timeout_stderr_and_malformed_json_are_run_failures(self):
        def process(command, **kwargs):
            kwargs["stdout"].write(b"not json")
            return subprocess.CompletedProcess(command, 0)
        for failure in (subprocess.CompletedProcess([], 2), process,
                        subprocess.TimeoutExpired("adapter", 5)):
            options = {"side_effect": failure} if callable(failure) or isinstance(failure, Exception) else {"return_value": failure}
            with self.subTest(failure=failure), mock.patch.object(runner.subprocess, "run", **options):
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    runner.run_adapter("core", self.fixture, Path("absent"))
        def noisy(command, **kwargs):
            kwargs["stderr"].write(b"unexpected")
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(runner.subprocess, "run", side_effect=noisy), self.assertRaises(ValueError):
            runner.run_adapter("core", self.fixture, Path("absent"))

    def test_failed_cli_overwrites_stale_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "report.json"
            output.write_text('{"status":"passed"}')
            status = runner.main(["--provenance", str(root / "missing.json"), "--output", str(output),
                                  "--report", str(root / "report.md")])
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(output.read_text())["status"], "failed")

    def test_unknown_selection_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(runner, "run_adapter") as run:
                self.assertEqual(runner.main(["--fixture", "unreviewed", "--output", str(root / "r.json"),
                                              "--report", str(root / "r.md")]), 1)
                run.assert_not_called()

    @unittest.skipUnless(os.name == "nt" or sys.platform.startswith("linux"), "supported memory-limit platforms")
    def test_real_memory_limit_prevents_large_child_allocation(self):
        command = [sys.executable, str(reference.ROOT / "scripts/rust_adapter_process.py"), sys.executable,
                   "-c", "try:\n x=bytearray(512*1024*1024)\nexcept MemoryError:\n print('bounded')"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "bounded")


class RustSetupTests(unittest.TestCase):
    def test_unsafe_and_duplicate_archive_members_are_rejected_before_extraction(self):
        for name, kind in (("../outside", tarfile.REGTYPE), ("root/../../outside", tarfile.REGTYPE),
                           ("root/link", tarfile.SYMTYPE), ("C:/outside", tarfile.REGTYPE),
                           ("root\\outside", tarfile.REGTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "source.tar.gz"
                with tarfile.open(archive, "w:gz") as stream:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    stream.addfile(member, io.BytesIO())
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    setup.extract_source(archive, root / "out", "root")
                self.assertFalse((root / "out").exists())

    def test_valid_archive_extracts_without_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                member = tarfile.TarInfo("root/file")
                member.size = 5
                stream.addfile(member, io.BytesIO(b"hello"))
            setup.extract_source(archive, root / "out", "root")
            self.assertEqual((root / "out/root/file").read_bytes(), b"hello")

    def test_corrupt_release_asset_fails_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "archive").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                setup.verify_assets(root, {"assets": {"archive": "0" * 64}})

    def test_failed_setup_invalidates_previous_selector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "provenance.json"
            output.write_text('{"status":"passed"}')
            with mock.patch.object(setup, "RUNS", root / "runs"), mock.patch.object(setup, "setup", side_effect=ValueError("probe")):
                self.assertEqual(setup.main(["--output", str(output)]), 1)
            self.assertEqual(json.loads(output.read_text())["status"], "failed")
            self.assertEqual(len(list((root / "runs").glob("*/failure.json"))), 1)

    def test_changed_implementation_binary_and_evidence_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "adapter"
            executable.write_bytes(b"original executable")
            receipt = {"schema": 1, "status": "passed", "implementation": setup.implementation_identity(),
                       "packages": setup.package_pins(),
                       "binding": {"core_selection": {"mode": "verified-source", "verified": True, "dirty": False,
                           **{k: v for k, v in setup.package_pins()["rust-binding"]["core_lock"].items()
                              if k in ("repository", "version", "commit", "release_tag")},
                           "locked_version": "0.8.0", "locked_commit": reference.load_json(setup.PIN)["commit"]}},
                       "binaries": {name: {"path": str(executable), "sha256": setup.digest(executable)}
                                    for name in setup.PARTICIPANTS},
                       "files": {str(executable): setup.digest(executable)}}
            path = root / "receipt.json"
            for change, message in ((lambda r: r.update(implementation={}), "implementation changed"),
                                    (lambda r: r["binaries"]["core"].update(sha256="bad"), "executable changed"),
                                    (lambda r: r["files"].update({str(executable): "bad"}), "evidence changed")):
                broken = copy.deepcopy(receipt)
                change(broken)
                path.write_text(json.dumps(broken))
                with self.assertRaisesRegex(ValueError, message):
                    setup.load_receipt(path)

    def test_ci_uses_verified_exact_external_cache_and_fresh_core(self):
        workflow = (reference.ROOT / ".github/workflows/fast.yml").read_text()
        job = workflow.split("  rust-differential:")[1].split("  capabilities:")[0]
        self.assertNotIn("restore-keys", job)
        self.assertNotIn("continue-on-error", job)
        self.assertIn("x86_64-unknown-linux-gnu-1.82.0", job)
        self.assertIn("scripts/check_rust_reference.py --verify-cache", job)
        self.assertIn("scripts/check_rust_differential.py", job)
        self.assertIn("run: python3 scripts/check_rust_regressions.py", job)
        self.assertIn("if: always()", job)
        self.assertNotIn("--core-assets", job)


if __name__ == "__main__":
    unittest.main()
