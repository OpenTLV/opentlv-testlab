# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.check_asn1 import load_pin, verify_source


class SourcePinTests(unittest.TestCase):
    def test_committed_pin_has_required_provenance(self):
        pin = load_pin()
        self.assertEqual(pin["module"], "asn1")
        self.assertEqual(pin["license"], "MIT")
        self.assertIn("asn1/rfc5280.lua", pin["files"])

    def test_changed_or_missing_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            data = b"unmodified upstream bytes\n"
            pin = {"files": {"init.lua": hashlib.sha256(data).hexdigest()}}
            path = source / "init.lua"
            path.write_bytes(data)
            verify_source(source, pin)
            path.write_bytes(data + b"local patch")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_source(source, pin)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                verify_source(source, pin)

    def test_download_rejects_bad_digest_before_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            original = b"original source\n"
            path = source / "init.lua"
            path.write_bytes(original)
            pin = {"repository": "owner/repo", "commit": "a" * 40,
                   "files": {"init.lua": hashlib.sha256(original).hexdigest()}}
            with patch("scripts.check_asn1.urllib.request.urlopen",
                       return_value=io.BytesIO(b"changed remote bytes")):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    verify_source(source, pin, download=True)
            self.assertEqual(path.read_bytes(), original)

    def test_download_uses_commit_url_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            data = b"original\r\nsource\n"
            pin = {"repository": "owner/repo", "commit": "a" * 40,
                   "files": {"asn1/init.lua": hashlib.sha256(data).hexdigest()}}
            with patch("scripts.check_asn1.urllib.request.urlopen",
                       return_value=io.BytesIO(data)) as fetch:
                verify_source(source, pin, download=True)
                fetch.assert_called_once_with(
                    "https://raw.githubusercontent.com/owner/repo/" + "a" * 40
                    + "/asn1/init.lua", timeout=30)
            self.assertEqual((source / "asn1/init.lua").read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
