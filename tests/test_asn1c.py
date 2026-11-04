# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_asn1c, setup_asn1c as asn1c

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/asn1c-reference.md"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tarball(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class PinAndSchemaTests(unittest.TestCase):
    def test_committed_pin_selects_the_upstream_release(self):
        pin = asn1c.load_pin()
        self.assertEqual((pin["repository"], pin["tag"], pin["license"]), ("vlm/asn1c", "v0.9.29", "BSD-2-Clause"))
        self.assertEqual(pin["environment_version"], 929)
        for change in ({"repository": "mouse07410/asn1c"},
                       {"archive": {**pin["archive"], "url": "https://example.com/asn1c-0.9.29.tar.gz"}},
                       {"archive": {**pin["archive"], "sha256": "0" * 63}}, {"tag": "v0.9.28"}):
            with self.subTest(change=change), patch.object(asn1c.json, "loads", return_value={**pin, **change}):
                with self.assertRaises(ValueError):
                    asn1c.load_pin()

    def test_schema_is_one_versioned_module_of_c_identifiers(self):
        schema = asn1c.schema_identity()
        self.assertEqual(schema["module"], "TestLabReference-1")
        self.assertIn("HighTag200", schema["types"])
        self.assertTrue(all(re.fullmatch(r"[A-Z][A-Za-z0-9]*", name) for name in schema["types"]))
        # Generated files must not differ from asn1c runtime files only in case.
        runtime = {"boolean", "integer", "null", "bit_string", "octet_string", "ia5string", "object_identifier"}
        self.assertFalse(runtime & {name.lower() for name in schema["types"]})

    def test_renamed_module_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "TestLabReference-2.asn1"
            path.write_text(asn1c.SCHEMA.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "named after the file"):
                asn1c.schema_identity(path)


class CapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probes = asn1c.load_capabilities()["probes"]
        cls.types = asn1c.schema_identity()["types"]

    def invalid(self, probe, message):
        with self.assertRaisesRegex(ValueError, message):
            asn1c.validate_probe(probe, self.types)

    def probe(self, identifier):
        return copy.deepcopy(next(p for p in self.probes if p["id"] == identifier))

    def test_every_area_and_classification_is_characterized(self):
        pairs = {(p["area"], p["classification"]) for p in self.probes}
        for area in asn1c.AREAS:
            self.assertTrue(any(a == area for a, _ in pairs), area)
        self.assertTrue({c for _, c in pairs} == set(asn1c.CLASSIFICATIONS))
        self.assertIn(("cer", "unsupported"), pairs)
        self.assertIn(("der-decode", "not-comparable"), pairs)

    def test_every_schema_type_error_and_syntax_is_exercised(self):
        self.assertEqual({p["type"] for p in self.probes}, set(self.types))
        errors = {p["expected"]["decode"].get("error") for p in self.probes} - {None}
        self.assertEqual(errors, set(asn1c.ERRORS))
        self.assertEqual({p["decode"] for p in self.probes}, set(asn1c.DECODE_SYNTAXES))
        self.assertEqual({p["encode"] for p in self.probes}, set(asn1c.ENCODE_SYNTAXES))

    def test_each_case_is_distinct(self):
        cases = [(p["type"], p["decode"], p["encode"], bytes.fromhex(p["wire"])) for p in self.probes]
        self.assertEqual(len(cases), len(set(cases)))

    def test_integer_expectations_match_twos_complement(self):
        checked = 0
        for probe in self.probes:
            wire, decode = bytes.fromhex(probe["wire"]), probe["expected"]["decode"]
            if probe["type"] == "Number" and decode["status"] == "accepted" and len(wire) > 2 and wire[1] < 0x80:
                with self.subTest(probe=probe["id"]):
                    self.assertEqual(decode["value"]["value"], str(int.from_bytes(wire[2:], "big", signed=True)))
                checked += 1
        self.assertGreaterEqual(checked, 5)

    def test_supported_encodings_are_definite_and_minimal(self):
        def lengths(data):
            while data:
                position = 2 if data[0] & 0x1F != 0x1F else 3 + (data[1] >= 0x80)
                first = data[position - 1]
                self.assertNotEqual(first, 0x80, "indefinite length")
                if first > 0x80:
                    count = first & 0x7F
                    size = int.from_bytes(data[position:position + count], "big")
                    self.assertGreater(size, 127, "nonminimal long form")
                    position += count
                else:
                    size = first
                if data[0] & 0x20:
                    lengths(data[position:position + size])
                data = data[position + size:]
        for probe in self.probes:
            encode = probe["expected"].get("encode", {})
            if probe["classification"] == "supported" and encode.get("status") == "encoded":
                with self.subTest(probe=probe["id"]):
                    lengths(bytes.fromhex(encode["wire"]))

    def test_probe_shapes_are_strict(self):
        probe = self.probe("ber-sequence")
        self.invalid({**probe, "classification": "not-comparable"}, "reason")
        self.invalid({**probe, "reason": "explained away"}, "reason")
        self.invalid({**probe, "type": "Unknown"}, "Unknown schema type")
        self.invalid({**probe, "decode": "per"}, "transfer syntax")
        self.invalid({**probe, "area": "xer"}, "Area")
        wrong = self.probe("ber-sequence")
        wrong["expected"]["decode"]["consumed"] = 7
        self.invalid(wrong, "whole wire")
        no_encode = self.probe("ber-sequence")
        del no_encode["expected"]["encode"]
        self.invalid(no_encode, "Expected encode")
        rejected = self.probe("ber-wrong-tag")
        rejected["expected"]["decode"]["code"] = "RC_WMORE"
        self.invalid(rejected, "code matching")
        rejected = self.probe("ber-wrong-tag")
        rejected["expected"]["encode"] = {"status": "encoded", "wire": "00"}
        self.invalid(rejected, "Expected encode")
        empty = self.probe("ber-empty-input")
        empty["wire"] = "04"
        self.invalid(empty, "empty rejection")

    def test_capabilities_must_name_the_pins(self):
        data = json.loads(asn1c.CAPABILITIES.read_text(encoding="utf-8"))
        data["reference"]["asn1c"] = "0.9.28"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "capabilities.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different asn1c"):
                asn1c.load_capabilities(path)

    def test_guide_documents_every_probe(self):
        text = GUIDE.read_text(encoding="utf-8")
        for probe in self.probes:
            with self.subTest(probe=probe["id"]):
                self.assertIn(f"`{probe['id']}`", text)
        counts = {c: sum(p["classification"] == c for p in self.probes) for c in asn1c.CLASSIFICATIONS}
        self.assertIn(f"{len(self.probes)} probes: {counts['supported']} supported, {counts['unsupported']} "
                      f"unsupported and {counts['not-comparable']} not comparable", text)


class ReferenceCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="asn1c cache ")
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name)
        self.license = b"BSD-2-Clause license\n"
        self.use_archive({"asn1c-0.9.29/LICENSE": self.license, "asn1c-0.9.29/configure": b"#!/bin/sh\n"})
        self.configuration = {"installer_schema": 1, "compiler": {"version": "gcc 13"}, "make": {"version": "4.3"},
                              "platform": {"system": "Linux", "machine": "x86_64"}}
        self.commands = []

    def use_archive(self, members):
        self.archive = tarball(members)
        self.pin = {**asn1c.load_pin(), "license_sha256": sha(self.license),
                    "archive": {**asn1c.load_pin()["archive"], "size": len(self.archive), "sha256": sha(self.archive)}}

    def fetch(self, url, timeout):
        self.assertEqual(url, self.pin["archive"]["url"])
        return io.BytesIO(self.archive)

    def build(self, command, *, cwd=None, env=None, log=None, timeout=60):
        command = [str(part) for part in command]
        self.commands.append(command)
        self.assertNotIn("CFLAGS", env)
        if command[-1] == "install":
            prefix = Path(next(c for c in self.commands[0] if c.startswith("--prefix=")).removeprefix("--prefix="))
            for name in asn1c.REQUIRED_FILES:
                (prefix / name).parent.mkdir(parents=True, exist_ok=True)
                (prefix / name).write_text(name, encoding="utf-8")
        return ""

    def cold(self):
        with patch.object(asn1c.urllib.request, "urlopen", side_effect=self.fetch) as fetch, \
                patch.object(asn1c, "run", side_effect=self.build), patch.dict("os.environ", {"CFLAGS": "-O0"}):
            result = asn1c.external_setup(self.cache, self.pin, self.configuration, "cc", "make",
                                          log=self.cache / "build.log")
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(Path(self.commands[0][0]).name, "configure")
        self.assertEqual([c[1:] for c in self.commands[1:]], [[f"-j{asn1c.os.cpu_count() or 1}"], ["install"]])
        return result

    def test_cold_then_warm_needs_no_download_or_build(self):
        first = self.cold()
        self.assertFalse(first["cache_hit"])
        with patch.object(asn1c.urllib.request, "urlopen", side_effect=AssertionError("network")), \
                patch.object(asn1c, "run", side_effect=AssertionError("build")):
            second = asn1c.external_setup(self.cache, self.pin, self.configuration, "cc", "make",
                                          log=None, offline=True)
        self.assertTrue(second["cache_hit"])
        entry = Path(second["directory"])
        self.assertEqual((entry / "LICENSE").read_bytes(), self.license)
        self.assertEqual(second["skeletons"], str(entry / "prefix/share/asn1c"))

    def test_offline_miss_downloads_nothing(self):
        with patch.object(asn1c.urllib.request, "urlopen") as fetch:
            with self.assertRaisesRegex(ValueError, "Offline cache miss"):
                asn1c.external_setup(self.cache, self.pin, self.configuration, "cc", "make", log=None, offline=True)
        fetch.assert_not_called()

    def test_changed_archive_or_failed_build_is_not_published(self):
        with patch.object(asn1c.urllib.request, "urlopen", return_value=io.BytesIO(self.archive + b"x")):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                asn1c.external_setup(self.cache, self.pin, self.configuration, "cc", "make", log=None)
        with patch.object(asn1c.urllib.request, "urlopen", side_effect=self.fetch), \
                patch.object(asn1c, "run", side_effect=ValueError("make failed")):
            with self.assertRaisesRegex(ValueError, "make failed"):
                asn1c.external_setup(self.cache, self.pin, self.configuration, "cc", "make", log=None)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_unsafe_archive_is_rejected_before_extraction(self):
        for members, message in [({"asn1c-0.9.29/../escape": b"x"}, "Unsafe archive path"),
                                 ({"other/LICENSE": b"x"}, "Unsafe archive path"),
                                 ({"asn1c-0.9.29/link": None}, "not a file or directory")]:
            with self.subTest(message=message):
                self.use_archive(members)
                with patch.object(asn1c.urllib.request, "urlopen", side_effect=self.fetch):
                    with self.assertRaisesRegex(ValueError, message):
                        asn1c.external_setup(self.cache, self.pin, self.configuration, "cc", "make", log=None)

    def test_corrupt_or_extra_cache_contents_fail_closed(self):
        entry = Path(self.cold()["directory"])
        for name in ["prefix/bin/asn1c", "LICENSE", "source/asn1c-0.9.29.tar.gz", "installation.json"]:
            with self.subTest(name=name):
                path = entry / name
                original = path.read_bytes()
                path.write_bytes(b"{}")
                with self.assertRaises(ValueError):
                    asn1c.verify_install(entry, self.pin, self.configuration)
                path.write_bytes(original)
        (entry / "prefix/share/asn1c/shadow.c").write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Unexpected cache contents"):
            asn1c.verify_install(entry, self.pin, self.configuration)

    def test_key_changes_with_pin_compiler_platform_or_schema(self):
        original = asn1c.cache_key(self.pin, self.configuration)
        self.assertNotEqual(original, asn1c.cache_key({**self.pin, "commit": "b" * 40}, self.configuration))
        for key, value in [("installer_schema", 2), ("compiler", {"version": "clang 18"}),
                           ("platform", {"system": "Linux", "machine": "aarch64"}), ("make", {"version": "4.4"})]:
            self.assertNotEqual(original, asn1c.cache_key(self.pin, {**self.configuration, key: value}))
        self.assertTrue(original.startswith("asn1c-0.9.29-"))


class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.schema = asn1c.schema_identity()
        self.pin = asn1c.load_pin()

    def write_generated(self, types, cflags="-DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_PER_SUPPORT ", version="0.9.29"):
        generated = self.root / "generated"
        generated.mkdir()
        for name in types:
            (generated / f"{name}.c").write_text(f'/*\n * Generated by asn1c-{version} (http://lionet.info/asn1c)\n'
                                                 f' * From ASN.1 module "TestLabReference-1"\n */\n', encoding="utf-8")
        (generated / "INTEGER.c").write_text("/* runtime */\n", encoding="utf-8")
        listing = "\t\\\n".join(f"\tgenerated/{name}.c" for name in types)
        (generated / "Makefile.am.libasncodec").write_text(
            f"ASN_MODULE_SRCS=\t\\\n{listing}\n\nASN_MODULE_SRCS+=generated/INTEGER.c\nASN_MODULE_CFLAGS={cflags}\n",
            encoding="utf-8")
        return generated

    def test_sources_and_flags_come_from_the_generated_build_description(self):
        sources = asn1c.module_sources(self.write_generated(self.schema["types"]), self.schema, self.pin)
        self.assertEqual(sources[-1], "generated/INTEGER.c")
        self.assertEqual(len(sources), len(self.schema["types"]) + 1)

    def test_generated_output_must_match_the_schema_flags_and_compiler(self):
        for arguments, message in [((self.schema["types"][1:],), "differ from the schema"),
                                   ((self.schema["types"], "-DASN_DISABLE_PER_SUPPORT "), "codec flags"),
                                   ((self.schema["types"], "-DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_PER_SUPPORT ",
                                     "0.9.28"), "another asn1c")]:
            with self.subTest(message=message):
                generated = self.write_generated(*arguments)
                with self.assertRaisesRegex(ValueError, message):
                    asn1c.module_sources(generated, self.schema, self.pin)
                for path in generated.iterdir():
                    path.unlink()
                generated.rmdir()

    def test_nondeterministic_generation_fails(self):
        outputs = iter([{"a.c": "1"}, {"a.c": "2"}])
        with patch.object(asn1c, "generate", side_effect=lambda *args: next(outputs)):
            with self.assertRaisesRegex(ValueError, "different sources"):
                asn1c.generate_twice("asn1c", "skeletons", self.root, None)

    def test_generation_runs_in_identical_relative_layouts(self):
        commands = []

        def record(command, *, cwd=None, env=None, log=None, timeout=60):
            commands.append((command, cwd))
            (cwd / "generated/Flag.c").write_text("same", encoding="utf-8")
            return ""
        with patch.object(asn1c, "run", side_effect=record):
            files = asn1c.generate_twice("asn1c", "skeletons", self.root, None)
        self.assertEqual(files, {"Flag.c": sha(b"same")})
        self.assertEqual(commands[0][0], commands[1][0])
        self.assertEqual([c[1].name for c in commands], ["generation-1", "generation-2"])
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["generated"])
        self.assertEqual(commands[0][0][3:5], ["-D", "generated"])


class AdapterProcessTests(unittest.TestCase):
    def setUp(self):
        self.pin, self.schema = asn1c.load_pin(), asn1c.schema_identity()
        probes = asn1c.load_capabilities()["probes"]
        self.probes = [p for p in probes if p["id"] in ("ber-sequence", "ber-empty-input", "cer-decode")]
        self.identity = asn1c.adapter_identity(self.pin, self.schema)

    def record(self, probe, **changes):
        record = {"id": probe["id"], "type": probe["type"]}
        for key, value in copy.deepcopy(probe["expected"]).items():
            record[key] = {"syntax": probe[key], **value}
        record.update(changes)
        return record

    def complete(self, lines, returncode=0, stderr=""):
        stdout = "".join(json.dumps(line) + "\n" for line in lines)
        return subprocess.CompletedProcess(["adapter"], returncode, stdout, stderr)

    def audit(self, process):
        with patch.object(asn1c.subprocess, "run", return_value=process) as run, redirect_stdout(io.StringIO()):
            results = asn1c.audit("adapter", self.probes, self.pin, self.schema)
        return results, run

    def test_matching_results_pass_and_requests_are_one_line_each(self):
        results, run = self.audit(self.complete([self.identity, *map(self.record, self.probes)]))
        self.assertEqual([r["status"] for r in results], ["pass"] * 3)
        lines = run.call_args.kwargs["input"].splitlines()
        self.assertIn("ber-empty-input Octets ber der -", lines)
        self.assertIn("cer-decode Octets cer none 040141", lines)
        self.assertNotIn("CFLAGS", run.call_args.kwargs["env"])

    def test_detail_text_is_retained_but_never_compared(self):
        records = [self.record(p) for p in self.probes]
        records[1]["decode"]["detail"] = "diagnostic"
        results, _ = self.audit(self.complete([self.identity, *records]))
        self.assertEqual(results[1]["status"], "pass")
        self.assertEqual(results[1]["observed"]["decode"]["detail"], "diagnostic")

    def test_changed_behavior_is_reported(self):
        records = [self.record(p) for p in self.probes]
        records[0]["encode"]["wire"] = "3000"
        results, _ = self.audit(self.complete([self.identity, *records]))
        self.assertEqual([r["status"] for r in results], ["changed", "pass", "pass"])

    def test_crashes_timeouts_and_protocol_errors_are_run_failures(self):
        records = [self.record(p) for p in self.probes]
        cases = [(self.complete([self.identity, records[0]], -11, "segfault"), "failed \\(-11\\) at probe ber-empty-input"),
                 (self.complete([self.identity, records[0]]), "incomplete result set"),
                 (self.complete([{**self.identity, "version": "0.9.28"}, *records]), "different identity"),
                 (self.complete([self.identity, records[1], records[0], records[2]]), "out of order"),
                 (self.complete([self.identity, self.record(self.probes[0], decode={"syntax": "der"}),
                                 *records[1:]]), "another syntax")]
        for process, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.audit(process)
        timeout = subprocess.TimeoutExpired(["adapter"], 60, output=json.dumps(self.identity) + "\n")
        with patch.object(asn1c.subprocess, "run", side_effect=timeout):
            with self.assertRaisesRegex(ValueError, "timed out at probe ber-sequence"):
                asn1c.run_adapter("adapter", self.probes, self.identity)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Path(self.temp.name) / "run"
        (self.run / "generated").mkdir(parents=True)
        (self.run / "generated/Flag.c").write_text("generated", encoding="utf-8")
        adapter = self.run / "asn1c-adapter"
        adapter.write_bytes(b"binary")
        self.report = {"status": "passed", "completed_at": "2026-11-04T00:00:00", "configuration": {},
                       "external": {"pin": asn1c.load_pin(), "directory": str(self.run / "cache")},
                       "generation": {"schema": asn1c.schema_identity(), "files": {"Flag.c": sha(b"generated")}},
                       "adapter": {"path": str(adapter), "sha256": sha(b"binary"),
                                   "source_sha256": asn1c.digest(asn1c.ADAPTER_SOURCE)}}

    def load(self):
        path = self.run / "provenance.json"
        path.write_text(json.dumps(self.report), encoding="utf-8")
        with patch.object(check_asn1c, "verify_install"):
            return check_asn1c.load_receipt(path)

    def test_valid_receipt_loads(self):
        report, pin, schema = self.load()
        self.assertEqual(schema["module"], "TestLabReference-1")

    def test_changed_inputs_or_outputs_require_a_new_setup(self):
        changes = [(("generation", "schema", "sha256"), "0" * 64, "Schema changed"),
                   (("adapter", "source_sha256"), "0" * 64, "Adapter source changed"),
                   (("adapter", "sha256"), "0" * 64, "Adapter binary changed"),
                   (("generation", "files", "Flag.c"), "0" * 64, "Generated sources changed"),
                   (("external", "pin", "version"), "0.9.28", "different asn1c pin"),
                   (("status",), "failed", "not a passed")]
        for path, value, message in changes:
            with self.subTest(message=message):
                original = copy.deepcopy(self.report)
                target = self.report
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.load()
                self.report = original

    def test_command_fails_without_a_passed_setup(self):
        with patch("sys.argv", ["check_asn1c.py", "--runs-dir", self.temp.name]), redirect_stderr(io.StringIO()):
            self.assertEqual(check_asn1c.main(), 1)


class SetupFailureTests(unittest.TestCase):
    def test_failed_setup_retains_failed_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("sys.argv", ["setup_asn1c.py", "--runs-dir", temp]), \
                    patch.object(asn1c, "executable", return_value=Path("/usr/bin/cc")), \
                    patch.object(asn1c, "context", return_value={"compiler": "test"}), \
                    patch.object(asn1c, "external_setup", side_effect=ValueError("corrupt cache")), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(asn1c.main(), 1)
            report = json.loads(next(Path(temp).glob("*/provenance.json")).read_text(encoding="utf-8"))
            self.assertEqual((report["status"], report["error"]), ("failed", "corrupt cache"))
            self.assertNotIn("adapter", report)

    def test_compiler_overrides_are_removed(self):
        with patch.dict("os.environ", {"CC": "bad", "CFLAGS": "bad", "MAKEFLAGS": "bad", "PATH": "kept"}, clear=True):
            self.assertEqual(asn1c.build_env(), {"PATH": "kept", "LC_ALL": "C"})


if __name__ == "__main__":
    unittest.main()
