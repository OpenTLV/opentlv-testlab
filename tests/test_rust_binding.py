# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import copy
from pathlib import Path
import tempfile
import unittest

from scripts import setup_rust_binding as binding
from scripts import run_rust_differential as runner
from scripts import check_rust_regressions as gate
from scripts import check_rust_binding as audit


class PublishedRustBindingTests(unittest.TestCase):
    def setUp(self):
        self.pin = binding.reference.load_json(binding.PIN)

    def test_published_pin_matches_core_and_exact_registry_graph(self):
        binding.verify_pin(self.pin)

    def test_changed_core_source_features_checksum_and_revision_fail(self):
        for change in (
            lambda p: p["core_lock"].update(commit="0" * 40),
            lambda p: p["packages"][0].update(source="path+local"),
            lambda p: p["packages"][0].update(checksum="0" * 64),
            lambda p: p["packages"][0].update(features=["document"]),
            lambda p: p.update(version="0.3.0"),
        ):
            pin = copy.deepcopy(self.pin)
            change(pin)
            with self.assertRaises(ValueError):
                binding.verify_pin(pin)

    def test_local_dirty_or_mismatched_core_selection_cannot_be_release_evidence(self):
        selection = {"mode": "verified-source", "verified": True, "dirty": False,
                     **{k: self.pin["core_lock"][k] for k in ("version", "commit", "repository", "release_tag")},
                     "locked_version": self.pin["core_lock"]["version"],
                     "locked_commit": self.pin["core_lock"]["commit"]}
        binding.verify_selection(selection, self.pin)
        for change in ({"mode": "local-source"}, {"verified": False}, {"dirty": True},
                       {"commit": "0" * 40}, {"locked_commit": "0" * 40}, {"version": "0.9.0"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                binding.verify_selection({**selection, **change}, self.pin)

    def test_binding_error_retains_location_and_names_public_strict_api(self):
        fixture = {"id": "der-probe", "encoding": "der"}
        error = {"category": "invalid", "source": "library", "stage": "contents",
                 "native_code": "-15: Invalid value", "offset": 4}
        observed = runner.normalize("rust-binding", fixture, {"result": "reject", "error": error})
        self.assertEqual(observed["error"], error)
        self.assertIn("Strictness::Strict", observed["api"])
        self.assertIn("recursive-DER-framing-and-primitive-contents", observed["checks"])
        self.assertTrue(any("projected" in check for check in observed["checks"]))

    def test_failure_of_only_the_binding_is_a_shared_mismatch(self):
        fixture = {"classification": "shared", "expected": {"result": "reject", "error": "invalid"}}
        observed = {name: {"result": "reject", "error": {"category": "invalid"}}
                    for name in gate.setup.PARTICIPANTS}
        observed["rust-binding"] = {"result": "accept", "tree": {}}
        outcome, differences, _ = runner.classify(fixture, observed)
        self.assertEqual(outcome, "mismatch")
        self.assertEqual(differences, ["rust-binding: expected reject, observed accept"])

    def test_gap_audit_rejects_changed_evidence_and_unsubstantiated_resolution(self):
        gaps = binding.reference.load_json(audit.GAPS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core, vendor = root / "core", root / "vendor"
            raw = vendor / "opentlv-sys-0.2.2/src/lib.rs"
            raw.parent.mkdir(parents=True)
            raw.write_text("// no native declarations\n")
            for row in gaps["gaps"]:
                header = core / row["core_header"]["path"]
                header.parent.mkdir(parents=True, exist_ok=True)
                header.write_text("\n".join(row["native_anchors"]))
                row["core_header"]["sha256"] = audit.digest(header)
                for path in row["reviewed_sources"]:
                    source = vendor / path
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("// reviewed public facade\n")
                    row["reviewed_sources"][path] = audit.digest(source)
            self.assertEqual(len(audit.validate(gaps, core, vendor)), 3)
            for change in (lambda g: g["gaps"][0].update(status="resolved"),
                           lambda g: g["gaps"][0].update(tested_fix="untested"),
                           lambda g: g["gaps"][0]["core_header"].update(sha256="0" * 64)):
                broken = copy.deepcopy(gaps)
                change(broken)
                with self.assertRaises(ValueError):
                    audit.validate(broken, core, vendor)
            raw.write_text("pub fn tlv_ber_tag_number();")
            with self.assertRaisesRegex(ValueError, "native gap evidence changed"):
                audit.validate(gaps, core, vendor)


if __name__ == "__main__":
    unittest.main()
