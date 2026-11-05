# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import copy
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts import check_rust_reference as reference


class RustReferenceTests(unittest.TestCase):
    def setUp(self):
        self.pin = reference.load_json(reference.PIN)
        self.corpus = reference.load_json(reference.CORPUS)
        self.matrix = reference.load_json(reference.MATRIX)

    def test_committed_baseline(self):
        reference.verify_pin(self.pin)
        reference.verify_corpus(self.corpus, self.matrix)

    def test_lockfile_edge_or_checksum_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = copy.deepcopy(self.pin)
            pin.update(manifest="Cargo.toml", lockfile="Cargo.lock")
            (root / "Cargo.toml").write_bytes((reference.ROOT / self.pin["manifest"]).read_bytes())
            lock = (reference.ROOT / self.pin["lockfile"]).read_text()
            for changed in (lock.replace(' "nom",', ' "unknown",', 1),
                            lock.replace('checksum = "', 'checksum = "0', 1)):
                (root / "Cargo.lock").write_text(changed)
                with self.assertRaisesRegex(ValueError, "lockfile digest"):
                    reference.verify_pin(pin, root)

    def test_dependency_license_and_feature_inventory(self):
        for package in self.pin["packages"]:
            self.assertTrue(package["license"])
            self.assertEqual(len(package["checksum"]), 64)
        self.assertEqual([p["name"] for p in self.pin["packages"] if not p["notices"]], ["asn1-rs-impl"])
        pin = copy.deepcopy(self.pin)
        next(p for p in pin["packages"] if p["name"] == "der-parser")["features"].append("serialize")
        with self.assertRaisesRegex(ValueError, "unexpected reference features"):
            reference.verify_pin(pin)

    def test_manifest_override_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = copy.deepcopy(self.pin)
            pin.update(manifest="Cargo.toml", lockfile="Cargo.lock")
            (root / "Cargo.lock").write_bytes((reference.ROOT / self.pin["lockfile"]).read_bytes())
            manifest = (reference.ROOT / self.pin["manifest"]).read_text()
            (root / "Cargo.toml").write_text(manifest + '\n[patch.crates-io]\nder-parser = { path = "fork" }\n')
            with self.assertRaisesRegex(ValueError, "manifest digest"):
                reference.verify_pin(pin, root)

    def test_archive_and_extracted_source_corruption_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, source = root / "sample.crate", root / "source"
            source.mkdir()
            data = b"original source\n"
            with tarfile.open(archive, "w:gz") as stream:
                entry = tarfile.TarInfo("sample-1.0.0/lib.rs")
                entry.size = len(data)
                stream.addfile(entry, io.BytesIO(data))
            package = {"name": "sample", "version": "1.0.0", "checksum": hashlib.sha256(archive.read_bytes()).hexdigest(),
                       "notices": {}}
            path = source / "lib.rs"
            path.write_bytes(data)
            reference.verify_archive(archive, source, package)
            path.write_bytes(b"modified source")
            with self.assertRaisesRegex(ValueError, "source differs"):
                reference.verify_archive(archive, source, package)
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing source"):
                reference.verify_archive(archive, source, package)
            archive.write_bytes(b"broken archive")
            with self.assertRaisesRegex(ValueError, "archive digest mismatch"):
                reference.verify_archive(archive, source, package)

    def test_duplicate_ids_and_unreviewed_fixtures_fail_closed(self):
        self.corpus["fixtures"].append(copy.deepcopy(self.corpus["fixtures"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate fixture id"):
            reference.verify_corpus(self.corpus, self.matrix)
        self.corpus["fixtures"].pop()
        self.corpus["fixtures"][0]["review"] = "untriaged"
        with self.assertRaisesRegex(ValueError, "unreviewed"):
            reference.verify_corpus(self.corpus, self.matrix)

    def test_wrong_wire_tree_value_and_rejection_expectations_are_rejected(self):
        for field in ("wire", "tree", "value", "error"):
            corpus = copy.deepcopy(self.corpus)
            fixture = next(f for f in corpus["fixtures"] if f["expected"]["result"] ==
                           ("reject" if field == "error" else "accept"))
            if field == "wire":
                fixture["wire"] += "00"
            elif field == "tree":
                fixture["expected"]["tree"]["length"]["form"] = "indefinite"
            elif field == "value":
                fixture["expected"]["value"] = None
            else:
                fixture["expected"]["error"] = "limit"
            with self.subTest(field=field), self.assertRaises(ValueError):
                reference.verify_corpus(corpus, self.matrix)

    def test_indefinite_eoc_and_wire_order_are_preserved(self):
        fixture = next(f for f in self.corpus["fixtures"] if f["id"] == "ber-indefinite-sequence")
        tree = fixture["expected"]["tree"]
        self.assertEqual(tree["length"], {"form": "indefinite", "value": None, "encoded_hex": "80"})
        self.assertEqual([child["number"] for child in tree["children"]], ["1", "2"])
        self.assertEqual(tree["value_hex"], "0101ff020105")

    def test_capability_gaps_do_not_become_passes(self):
        fixtures = {f["id"]: f for f in self.corpus["fixtures"]}
        self.assertEqual(fixtures["der-nested-boolean-true-01"]["classification"], "inconclusive")
        self.assertEqual(fixtures["der-set-of-unsorted"]["classification"], "inconclusive")
        self.assertEqual(fixtures["ber-private-class-indefinite"]["classification"], "unsupported")
        self.assertEqual(fixtures["der-explicit-context"]["classification"], "unsupported")
        self.assertEqual(fixtures["der-private-class"]["classification"], "shared")
        self.assertTrue(all(row["rust_binding"]["status"] == "not-tested" for row in self.matrix["features"]))

    def test_documented_counts_match_the_corpus(self):
        fixtures = self.corpus["fixtures"]
        guide = (reference.ROOT / "docs/rust-reference.md").read_text(encoding="utf-8")
        ber = sum(f["encoding"] == "ber" for f in fixtures)
        self.assertIn(f"{len(fixtures)} fixtures: {ber} BER and {len(fixtures) - ber} DER", guide)
        counts = {name: sum(f["classification"] == name for f in fixtures) for name in reference.CLASSIFICATIONS}
        self.assertIn(f"{counts['shared']} shared, {counts['unsupported']} unsupported and "
                      f"{counts['inconclusive']} inconclusive", guide)


if __name__ == "__main__":
    unittest.main()
