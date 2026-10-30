# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import setup_lua as setup


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ExternalCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dependency cache ")
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name)
        self.files = {"LICENSE": b"original license\n", "Makefile": b"install:\n",
                      "asn1/init.lua": b"return {}\n"}
        self.pin = {"version": "2.2.1", "commit": "a" * 40, "repository": "owner/repo",
                    "files": {k: sha(v) for k, v in self.files.items()}}
        self.configuration = {"installer_schema": 1, "lua": {"version": "Lua 5.2.4", "sha": "123"},
                              "platform": {"system": "Linux", "machine": "x86_64"},
                              "make": "GNU Make 4.3"}

    def fetch(self, url, timeout):
        self.assertEqual(timeout, 30)
        prefix = "https://raw.githubusercontent.com/owner/repo/" + "a" * 40 + "/"
        self.assertTrue(url.startswith(prefix))
        return io.BytesIO(self.files[url.removeprefix(prefix)])

    def make(self, command, *, cwd, env):
        self.assertEqual(command[:2], ["make", "install"])
        self.assertEqual(command[2], "ROOT_DIR=../stage")
        stage = (cwd / command[2].removeprefix("ROOT_DIR=")).resolve()
        for name in self.files:
            if name.endswith(".lua"):
                target = stage / setup.MODULE_DIR / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cwd / name, target)
        return ""

    def cold(self):
        with patch("scripts.check_asn1.urllib.request.urlopen", side_effect=self.fetch) as fetch, \
                patch.object(setup, "run", side_effect=self.make) as make:
            result = setup.external_setup(self.cache, self.pin, self.configuration, "make")
        self.assertEqual(fetch.call_count, len(self.files))
        self.assertEqual(make.call_count, 1)
        return result

    def test_cold_then_warm_uses_no_download_or_install(self):
        first = self.cold()
        self.assertFalse(first["cache_hit"])
        with patch("scripts.check_asn1.urllib.request.urlopen", side_effect=AssertionError("network")), \
                patch.object(setup, "run", side_effect=AssertionError("make")):
            second = setup.external_setup(self.cache, self.pin, self.configuration, "make", offline=True)
        self.assertTrue(second["cache_hit"])
        self.assertEqual(first["directory"], second["directory"])
        license_path = Path(second["directory"]) / "stage/usr/share/doc/lua-asn1/LICENSE"
        self.assertEqual(license_path.read_bytes(), self.files["LICENSE"])

    def test_offline_miss_does_not_download(self):
        with patch("scripts.check_asn1.urllib.request.urlopen") as fetch:
            with self.assertRaisesRegex(ValueError, "Offline cache miss"):
                setup.external_setup(self.cache, self.pin, self.configuration, "make", offline=True)
        fetch.assert_not_called()

    def test_partial_download_is_not_published(self):
        with patch("scripts.check_asn1.urllib.request.urlopen", side_effect=OSError("offline")):
            with self.assertRaises(OSError):
                setup.external_setup(self.cache, self.pin, self.configuration, "make")
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_failed_install_is_not_published(self):
        with patch("scripts.check_asn1.urllib.request.urlopen", side_effect=self.fetch), \
                patch.object(setup, "run", side_effect=ValueError("make failed")):
            with self.assertRaisesRegex(ValueError, "make failed"):
                setup.external_setup(self.cache, self.pin, self.configuration, "make")
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_corrupt_source_installed_file_license_or_receipt_fails_closed(self):
        entry = Path(self.cold()["directory"])
        for name in ["source/asn1/init.lua", "stage/usr/share/lua/common/asn1/init.lua",
                     "stage/usr/share/doc/lua-asn1/LICENSE", "installation.json"]:
            with self.subTest(name=name):
                path = entry / name
                original = path.read_bytes()
                path.write_bytes(b"{}")
                with patch("scripts.check_asn1.urllib.request.urlopen", side_effect=AssertionError("network")):
                    with self.assertRaises(ValueError):
                        setup.external_setup(self.cache, self.pin, self.configuration, "make")
                path.write_bytes(original)

    def test_missing_installed_module_is_not_cache_hit(self):
        entry = Path(self.cold()["directory"])
        (entry / "stage/usr/share/lua/common/asn1/init.lua").unlink()
        with self.assertRaises(FileNotFoundError):
            setup.external_setup(self.cache, self.pin, self.configuration, "make")

    def test_extra_shadow_module_is_rejected(self):
        entry = Path(self.cold()["directory"])
        (entry / "stage/usr/share/lua/common/asn1.lua").write_text("return {}")
        with self.assertRaisesRegex(ValueError, "Unexpected cache contents"):
            setup.external_setup(self.cache, self.pin, self.configuration, "make")

    def test_key_changes_with_version_pin_bytes_runtime_platform_or_configuration(self):
        original = setup.cache_key(self.pin, self.configuration)
        for key, value in [("version", "2.2.2"), ("commit", "b" * 40),
                           ("files", {"asn1/init.lua": "0" * 64})]:
            self.assertNotEqual(original, setup.cache_key({**self.pin, key: value}, self.configuration))
        for key, value in [("installer_schema", 2), ("lua", {"version": "Lua 5.2.3"}),
                           ("platform", {"system": "Linux", "machine": "aarch64"}),
                           ("platform", {"system": "Windows", "machine": "x86_64"}),
                           ("make", "GNU Make 4.4")]:
            self.assertNotEqual(original, setup.cache_key(self.pin, {**self.configuration, key: value}))
        self.assertEqual(original, setup.cache_key(dict(reversed(list(self.pin.items()))), self.configuration))


class FreshReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fresh release ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pin = copy.deepcopy(setup.load_release_pin())
        name = "opentlv-" + self.pin["rock_version"]
        self.payloads = {name + ".rockspec": b"rockspec\n", name + ".src.rock": b"rock bytes"}
        manifest = {"schema": 1, "request": {"repository": self.pin["repository"],
                    "tag": self.pin["tag"], "version": self.pin["version"],
                    "lua_sha": self.pin["commit"], "commit": self.pin["commit"],
                    "core_sha": self.pin["core_commit"]}, "quality": {"records": [{"release_rock": {
                    "rock": name + ".src.rock", "sha256": sha(self.payloads[name + ".src.rock"]),
                    "rockspec_sha256": sha(self.payloads[name + ".rockspec"]),
                    "commit": self.pin["commit"], "core_commit": self.pin["core_commit"],
                    "tag": self.pin["tag"]}}]}}
        self.payloads["release-manifest.json"] = json.dumps(manifest).encode()
        self.pin["assets"] = {name: sha(data) for name, data in self.payloads.items()}

    def fetch(self, url):
        self.assertTrue(url.startswith("https://github.com/OpenTLV/opentlv-lua/releases/download/v0.3.0/"))
        return self.payloads[url.rsplit("/", 1)[1]]

    def test_two_runs_fetch_every_asset_twice(self):
        with patch.object(setup, "fetch_bytes", side_effect=self.fetch) as fetch:
            first = setup.acquire_release(self.root / "run1", self.pin)
            second = setup.acquire_release(self.root / "run2", self.pin)
        self.assertEqual(fetch.call_count, 6)
        self.assertEqual(first, second)
        self.assertTrue(all(a["sha256"] == self.pin["assets"][a["name"]] for a in second))

    def test_reusing_download_directory_is_rejected(self):
        with patch.object(setup, "fetch_bytes", side_effect=self.fetch) as fetch:
            setup.acquire_release(self.root / "run", self.pin)
            with self.assertRaises(FileExistsError):
                setup.acquire_release(self.root / "run", self.pin)
        self.assertEqual(fetch.call_count, 3)

    def test_corrupted_asset_fails_before_installation(self):
        with patch.object(setup, "fetch_bytes", return_value=b"modified release"), \
                patch.object(setup, "run") as run:
            with self.assertRaisesRegex(ValueError, "Release SHA-256 mismatch"):
                setup.install_release(self.root, self.pin, "lua", "rocks", Path("/usr"))
        run.assert_not_called()

    def test_missing_asset_fails_without_local_fallback(self):
        with patch.object(setup, "fetch_bytes", side_effect=OSError("not found")):
            with self.assertRaises(OSError):
                setup.acquire_release(self.root / "run", self.pin)

    def test_manifest_identity_must_match_pin_even_with_valid_hash(self):
        manifest = json.loads(self.payloads["release-manifest.json"])
        manifest["request"]["commit"] = "b" * 40
        self.payloads["release-manifest.json"] = json.dumps(manifest).encode()
        self.pin["assets"]["release-manifest.json"] = sha(self.payloads["release-manifest.json"])
        with patch.object(setup, "fetch_bytes", side_effect=self.fetch):
            with self.assertRaisesRegex(ValueError, "manifest identity mismatch"):
                setup.acquire_release(self.root / "run", self.pin)

    def test_rock_provenance_must_match_manifest(self):
        manifest = json.loads(self.payloads["release-manifest.json"])
        manifest["quality"]["records"][0]["release_rock"]["core_commit"] = "b" * 40
        self.payloads["release-manifest.json"] = json.dumps(manifest).encode()
        self.pin["assets"]["release-manifest.json"] = sha(self.payloads["release-manifest.json"])
        with patch.object(setup, "fetch_bytes", side_effect=self.fetch):
            with self.assertRaisesRegex(ValueError, "rock provenance mismatch"):
                setup.acquire_release(self.root / "run", self.pin)


class SetupFailureTests(unittest.TestCase):
    def test_offline_cannot_skip_fresh_opentlv(self):
        with patch("sys.argv", ["setup_lua.py", "--offline"]), \
                patch.object(setup, "executable") as executable, redirect_stderr(io.StringIO()):
            self.assertEqual(setup.main(), 1)
        executable.assert_not_called()

    def test_failed_setup_retains_failed_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("sys.argv", ["setup_lua.py", "--runs-dir", temp]), \
                    patch.object(setup, "executable", return_value=Path("/usr/bin/lua5.2")), \
                    patch.object(setup, "context", return_value={"runtime": "test"}), \
                    patch.object(setup, "external_setup", side_effect=ValueError("corrupt cache")), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(setup.main(), 1)
            receipts = list(Path(temp).glob("*/provenance.json"))
            self.assertEqual(len(receipts), 1)
            report = json.loads(receipts[0].read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["error"], "corrupt cache")
            self.assertNotIn("opentlv", report)

    def test_lua_and_make_overrides_are_removed(self):
        with patch.dict("os.environ", {"LUA_INIT_5_2": "bad", "LUA_PATH_5_2": "bad",
                                      "LUA_CPATH": "bad", "LUAROCKS_CONFIG": "bad",
                                      "MAKEFILES": "bad", "PATH": "kept"}, clear=True):
            self.assertEqual(setup.clean_env(), {"PATH": "kept"})


if __name__ == "__main__":
    unittest.main()
