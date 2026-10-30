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
import zipfile

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
        self.name = "opentlv-" + self.pin["rock_version"]
        self.rockspec = b"rockspec\n"
        self.files = {self.name + ".rockspec": self.rockspec,
                      "opentlv-lua/lua/opentlv/init.lua": b"return require('opentlv._core')\n",
                      "opentlv-lua/LICENSE": b"license\n",
                      "opentlv-lua/cmake/Core.cmake": f"GIT_TAG {self.pin['core_commit']}\n".encode()}
        self.use_rock(self.files)
        self.core_output = f"-- OpenTLV version: 0.8.0 (0.8.0-0-{self.pin['core_commit'][:8]}, branch HEAD)"
        self.installed = dict(self.files)
        self.metadata = {"binding_version": self.pin["version"], "binding_revision": "",
                         "release_tag": self.pin["tag"], "dirty": False}
        self.commands = []

    def use_rock(self, files):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        self.rock = buffer.getvalue()
        self.pin["assets"] = {self.name + ".rockspec": sha(self.rockspec), self.name + ".src.rock": sha(self.rock)}

    def run_tool(self, command, *, cwd=None, env=None, log=None, timeout=60):
        command = [str(part) for part in command]
        self.commands.append(command)
        if "download" in command:
            (cwd / (self.name + ".src.rock")).write_bytes(self.rock)
        elif "install" in command:
            tree = Path(next(c for c in command if c.startswith("--tree=")).removeprefix("--tree="))
            metadata = tree / "lib/luarocks/rocks-5.2/opentlv" / self.pin["rock_version"]
            (metadata / "doc").mkdir(parents=True)
            (metadata / "doc/LICENSE").write_bytes(self.installed["opentlv-lua/LICENSE"])
            (metadata / "doc/LICENSE-Core").write_bytes(b"core license\n")
            (metadata / (self.name + ".rockspec")).write_bytes(self.installed[self.name + ".rockspec"])
            (metadata / "lua-version.json").write_text(json.dumps(self.metadata), encoding="utf-8")
            pure = tree / "share/lua/5.2/opentlv/init.lua"
            pure.parent.mkdir(parents=True)
            pure.write_bytes(self.installed["opentlv-lua/lua/opentlv/init.lua"])
            native = tree / "lib/lua/5.2/opentlv/_core.so"
            native.parent.mkdir(parents=True)
            native.write_bytes(b"native")
            return self.core_output
        return "tool 1.0"

    def install(self, name="run"):
        directory = self.root / name
        directory.mkdir()
        with patch.object(setup, "run", side_effect=self.run_tool):
            return setup.install_release(directory, self.pin, "lua", "rocks", Path("/usr"))

    def luarocks_actions(self):
        return [c[c.index("--only-server=https://luarocks.org") + 1] for c in self.commands
                if "--only-server=https://luarocks.org" in c]

    def test_committed_pin_selects_only_the_registry(self):
        pin = setup.load_release_pin()
        self.assertEqual(pin["server"], "https://luarocks.org")
        self.assertEqual(set(pin["assets"]), {self.name + ".rockspec", self.name + ".src.rock"})
        with patch.object(setup.json, "loads", return_value={**pin, "server": "https://github.com"}):
            with self.assertRaisesRegex(ValueError, "LuaRocks registry"):
                setup.load_release_pin()

    def test_every_run_downloads_and_installs_through_luarocks(self):
        first, second = self.install("run1"), self.install("run2")
        self.assertEqual(self.luarocks_actions(), ["download", "install"] * 2)
        install = next(c for c in self.commands if "install" in c)
        self.assertEqual(install[-3:], ["install", "opentlv", self.pin["rock_version"]])
        self.assertFalse(any(part.endswith(".src.rock") for c in self.commands for part in c))
        self.assertEqual(first["acquisition"], "fresh")
        self.assertEqual(second["source"], "https://luarocks.org")
        self.assertEqual(second["assets"], [{"name": self.name + ".src.rock", "sha256": sha(self.rock),
                                             "size": len(self.rock)}])
        self.assertEqual(second["core_commit"], self.pin["core_commit"])
        self.assertEqual(second["built_core_commit"], self.pin["core_commit"][:8])

    def test_private_config_has_one_server_and_a_new_cache(self):
        self.install()
        config = (self.root / "run/luarocks-config.lua").read_text(encoding="utf-8")
        self.assertIn('rocks_servers = {"https://luarocks.org"}', config)
        self.assertIn("luarocks-cache", config)
        self.assertNotIn("github", config)

    def test_reusing_download_directory_is_rejected(self):
        self.install()
        with patch.object(setup, "run", side_effect=self.run_tool) as run:
            with self.assertRaises(FileExistsError):
                setup.acquire_release(self.root / "run/downloads", self.pin, ["rocks"], {}, None)
        run.assert_not_called()

    def test_changed_registry_bytes_fail_before_installation(self):
        self.pin["assets"][self.name + ".src.rock"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Registry SHA-256 mismatch"):
            self.install()
        self.assertEqual(self.luarocks_actions(), ["download"])

    def test_failed_download_has_no_other_source(self):
        with patch.object(setup, "run", side_effect=ValueError("no results")) as run:
            (self.root / "run").mkdir()
            with self.assertRaisesRegex(ValueError, "no results"):
                setup.install_release(self.root / "run", self.pin, "lua", "rocks", Path("/usr"))
        self.assertEqual(run.call_count, 1)

    def test_download_without_the_source_rock_fails(self):
        def empty(command, *, cwd=None, env=None, log=None, timeout=60):
            return ""
        (self.root / "run").mkdir()
        with patch.object(setup, "run", side_effect=empty):
            with self.assertRaisesRegex(ValueError, "did not download"):
                setup.install_release(self.root / "run", self.pin, "lua", "rocks", Path("/usr"))

    def test_rock_contents_must_match_the_pin_before_installation(self):
        for name, data, message in [(self.name + ".rockspec", b"other\n", "different rockspec"),
                                    ("opentlv-lua/cmake/Core.cmake", b"GIT_TAG main\n", "different Core")]:
            with self.subTest(message=message):
                self.commands.clear()
                self.use_rock({**self.files, name: data})
                self.pin["assets"][self.name + ".rockspec"] = sha(self.rockspec)
                with self.assertRaisesRegex(ValueError, message):
                    self.install(message.replace(" ", "-"))
                self.assertEqual(self.luarocks_actions(), ["download"])

    def test_built_core_must_match_the_pin(self):
        for output in ("-- OpenTLV version: 0.8.0 (0.8.0-0-deadbeef, branch HEAD)", "no version line"):
            with self.subTest(output=output):
                self.core_output = output
                with self.assertRaisesRegex(ValueError, "different Core"):
                    self.install("core-" + str(len(output)))

    def test_installed_payload_must_match_the_verified_rock(self):
        for name, label in [("opentlv-lua/lua/opentlv/init.lua", "pure"), (self.name + ".rockspec", "spec"),
                            ("opentlv-lua/LICENSE", "license")]:
            with self.subTest(name=name):
                self.installed = {**self.files, name: b"changed\n"}
                with self.assertRaisesRegex(ValueError, "Installed payload differs"):
                    self.install(label)

    def test_installed_metadata_must_match_the_release(self):
        self.metadata["release_tag"] = "v9.9.9"
        with self.assertRaisesRegex(ValueError, "Installed version mismatch"):
            self.install()


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
