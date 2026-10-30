# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_differential as differential
from scripts.setup_lua import digest

ROOT = Path(__file__).resolve().parents[1]
OCTETS = {"type": "octet_string"}


def leaf(identifier, value):
    size = len(bytes.fromhex(value))
    return {"identifier": identifier, "length": size, "length_bytes": f"{size:02x}", "value": value}


def shared(fixture_id="octets", wire="04 01 41", schema=OCTETS, tree=None):
    return {"id": fixture_id, "operation": "decode", "wire": wire, "schema": schema,
            "classification": "shared",
            "expected": {"result": "accept", "tree": tree or leaf("04", "41")}}


def rejected_fixture(wire="04 02 41", framing="truncated"):
    return {"id": "rejected", "operation": "decode", "wire": wire, "schema": OCTETS,
            "classification": "shared", "expected": {"result": "reject", "framing": framing}}


def declared(classification="unsupported"):
    return {"id": "declared", "operation": "decode", "wire": "9f 1f 01 41", "schema": OCTETS,
            "classification": classification, "reason": "documented matrix reason"}


def accepted(tree=None, consumed=3, projected=False):
    observed = copy.deepcopy(tree or leaf("04", "41"))
    if projected:
        del observed["length_bytes"]
    return {"status": "accepted", "consumed": consumed, "tree": observed}


class EligibilityTests(unittest.TestCase):
    def test_shared_parser_preserves_every_comparable_field(self):
        tree = differential.parse_shared(bytes.fromhex("30 05 04 01 41 30 00"))
        self.assertEqual(tree, {"identifier": "30", "length": 5, "length_bytes": "05", "children": [
            leaf("04", "41"), {"identifier": "30", "length": 0, "length_bytes": "00", "children": []}]})

    def test_framing_errors_have_narrow_kinds(self):
        for wire, kind in [("", "empty"), ("04", "truncated"), ("04 02 41", "truncated"),
                           ("30 03 04 02 41", "truncated"), ("30 01 04", "truncated"),
                           ("04 00 04 00", "trailing"), ("04 00 ff", "trailing")]:
            with self.subTest(wire=wire), self.assertRaises(differential.FramingError) as caught:
                differential.parse_shared(bytes.fromhex(wire))
            self.assertEqual(caught.exception.kind, kind)

    def test_shapes_outside_the_shared_subset_are_not_eligible(self):
        for wire, message in [("9f 1f 01 41", "low tag"), ("ff", "low tag"), ("44 01 41", "universal or context"),
                              ("c4 01 41", "universal or context"), ("04 81 01 41", "short-form"),
                              ("04 80 00 00", "short-form"), ("30 80 00 00", "short-form"),
                              ("30 08 30 06 30 04 30 02 30 00", "nest at most")]:
            with self.subTest(wire=wire), self.assertRaisesRegex(ValueError, message) as caught:
                differential.parse_shared(bytes.fromhex(wire))
            self.assertNotIsInstance(caught.exception, differential.FramingError)

    def test_maximum_nesting_is_accepted(self):
        differential.parse_shared(bytes.fromhex("30 06 30 04 30 02 30 00"))


class CorpusValidationTests(unittest.TestCase):
    def invalid(self, fixture, message):
        with self.assertRaisesRegex(ValueError, message):
            differential.validate_fixture(fixture)

    def test_shared_fixture_needs_a_consistent_expectation(self):
        differential.validate_fixture(shared())
        differential.validate_fixture(rejected_fixture())
        self.invalid(shared(tree=leaf("04", "42")), "does not describe the wire")
        self.invalid(shared(wire="04 01"), "truncated framing")
        self.invalid(rejected_fixture("04 01 41"), "complete shared element")
        self.invalid(rejected_fixture("04 02 41", "trailing"), "not declared framing")
        self.invalid(rejected_fixture("04 02 41", "semantic"), "needs framing")
        fixture = shared()
        del fixture["expected"]
        self.invalid(fixture, "explicit expectation")

    def test_every_fixture_needs_valid_identity_and_schema(self):
        for changes, message in [({"id": "Bad Id"}, "kebab-case"), ({"operation": "encode"}, "decode"),
                                 ({"wire": "0"}, "non-hexadecimal|hex"), ({"wire": 4}, "hex string"),
                                 ({"wire": "00" * (differential.MAX_WIRE_BYTES + 1)}, "exceeds"),
                                 ({"schema": None}, "explicit ASN.1 schema"),
                                 ({"classification": "ignored"}, "Classification")]:
            with self.subTest(changes=changes):
                self.invalid({**shared(), **changes}, message)

    def test_shared_schema_cannot_use_unverified_constructs(self):
        for schema, message in [({"type": "null"}, "not shared"), ({"type": "octet_string", "tag": 31}, "0-30"),
                                ({"type": "octet_string", "tag": 4, "class": "application"}, "Unexpected"),
                                ({"type": "sequence"}, "needs fields"),
                                ({"type": "sequence", "fields": [{"name": "a"}]}, "name and schema"),
                                ({"type": "sequence_of"}, "needs an item"),
                                ({"type": "explicit", "inner": OCTETS}, "tag and inner")]:
            with self.subTest(schema=schema):
                self.invalid(shared(schema=schema), message)

    def test_shared_fixture_cannot_carry_a_reason_and_declared_needs_one(self):
        self.invalid({**shared(), "reason": "skip it"}, "explain away")
        fixture = declared()
        differential.validate_fixture(fixture)
        for changes in ({"reason": " "}, {"expected": {"result": "reject"}}):
            with self.subTest(changes=changes):
                self.invalid({**fixture, **changes}, "reason|no verdict")

    def test_corpus_rejects_empty_and_duplicate_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.json"
            for corpus, message in [({"schema": 2, "fixtures": [shared()]}, "schema 1"),
                                    ({"schema": 1, "fixtures": []}, "not be empty"),
                                    ({"schema": 1, "fixtures": [shared(), shared()]}, "unique")]:
                path.write_text(json.dumps(corpus), encoding="utf-8")
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    differential.load_corpus(path)

    def test_reproduction_metadata_must_match_the_pins_and_cover_every_fixture(self):
        packages = {"opentlv": differential.load_release_pin()["version"], "lua-asn1": differential.load_pin()["version"]}
        metadata = {"command": "run", "runtime": "Lua 5.2", "packages": packages}
        described = {**shared(), "category": "primitive", "description": "One octet"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.json"
            path.write_text(json.dumps({"schema": 1, "reproduction": metadata, "fixtures": [described]}), encoding="utf-8")
            self.assertEqual(differential.load_corpus(path)["reproduction"], metadata)
            for changed, fixture, message in [({"runtime": None}, described, None),
                                              ({"packages": {**packages, "lua-asn1": "0"}}, described, "different package versions"),
                                              ({}, shared(), "Category must be"),
                                              ({}, {**described, "category": "other"}, "Category must be"),
                                              ({}, {**described, "description": " "}, "Needs a description")]:
                candidate = {**metadata, **changed}
                if message is None:
                    del candidate["runtime"]
                    message = "command, runtime and packages"
                path.write_text(json.dumps({"schema": 1, "reproduction": candidate, "fixtures": [fixture]}), encoding="utf-8")
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    differential.load_corpus(path)

    def test_committed_seed_covers_every_declared_classification(self):
        fixtures = differential.load_corpus(differential.DEFAULT_FIXTURES)["fixtures"]
        for classification in differential.CLASSIFICATIONS:
            self.assertTrue(any(f["classification"] == classification for f in fixtures), classification)
        for result in ("accept", "reject"):
            self.assertTrue(any(f.get("expected", {}).get("result") == result for f in fixtures), result)
        schemas = json.dumps([f["schema"] for f in fixtures])
        for kind in (*differential.PRIMITIVES, "sequence", "sequence_of", "explicit"):
            self.assertIn(f'"{kind}"', schemas)

    def test_mismatch_probe_is_shared_so_it_reaches_a_verdict(self):
        fixtures = differential.load_corpus(ROOT / "tests/fixtures/differential_mismatch.json")["fixtures"]
        self.assertTrue(all(f["classification"] == "shared" for f in fixtures))


def tree_nodes(node, depth=1):
    yield node, depth
    for child in node.get("children", ()):
        yield from tree_nodes(child, depth + 1)


class BerCorpusTests(unittest.TestCase):
    """Coverage of the committed corpus; only Fast runs it through the real libraries."""

    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / "differential/fixtures/asn1-ber.json"
        cls.corpus = differential.load_corpus(cls.path)
        cls.fixtures = cls.corpus["fixtures"]
        cls.shared = [f for f in cls.fixtures if f["classification"] == "shared"]
        cls.trees = [f["expected"]["tree"] for f in cls.shared if f["expected"]["result"] == "accept"]
        cls.nodes = [item for tree in cls.trees for item in tree_nodes(tree)]

    def test_reproduction_command_runs_this_corpus(self):
        self.assertIn(self.path.relative_to(ROOT).as_posix(), self.corpus["reproduction"]["command"])

    def test_every_category_compares_something_and_declares_its_gaps(self):
        for category in differential.CATEGORIES:
            selected = [f["classification"] for f in self.fixtures if f["category"] == category]
            self.assertIn("shared", selected, category)
            self.assertGreater(len(set(selected)), 1, category)

    def test_every_shared_schema_and_framing_error_is_exercised(self):
        schemas = json.dumps([f["schema"] for f in self.shared])
        for kind in (*differential.PRIMITIVES, "sequence", "sequence_of", "explicit"):
            self.assertIn(f'"{kind}"', schemas)
        framing = {f["expected"].get("framing") for f in self.shared}
        self.assertLessEqual(set(differential.FRAMING_ERRORS), framing)

    def test_tag_length_and_depth_boundaries_are_reached(self):
        identifiers = {node["identifier"] for node, _ in self.nodes}
        self.assertLessEqual({"80", "9e", "a0", "be"}, identifiers)
        lengths = {node["length"] for node, _ in self.nodes}
        self.assertLessEqual({0, 1, 126, 127}, lengths)
        self.assertEqual(max(depth for _, depth in self.nodes), differential.MAX_SHARED_DEPTH)
        self.assertTrue(any(node["length"] == 127 and "children" in node for node, _ in self.nodes))

    def test_each_case_is_distinct(self):
        cases = [(bytes.fromhex(f["wire"]), json.dumps(f["schema"], sort_keys=True)) for f in self.fixtures]
        self.assertEqual(len(set(cases)), len(cases))

    def test_cited_probes_exist_in_the_capability_audit(self):
        audit = (ROOT / "tests/asn1_capabilities.lua").read_text(encoding="utf-8")
        cited = [m.group(1) for f in self.fixtures if (m := re.search(r"\(([a-z0-9-]+)\)$", f.get("reason", "")))]
        self.assertTrue(cited)
        for probe in cited:
            self.assertIn(f'"{probe}"', audit)


class ClassificationTests(unittest.TestCase):
    def outcome(self, fixture, opentlv, external):
        return differential.classify(fixture, {"opentlv": opentlv, "lua-asn1": external})

    def test_pass_requires_both_expectations(self):
        self.assertEqual(self.outcome(shared(), accepted(), accepted(projected=True)), ("pass", []))

    def test_rejection_detail_is_never_compared(self):
        self.assertEqual(self.outcome(rejected_fixture(),
                                      {"status": "rejected", "detail": "truncated input"},
                                      {"status": "rejected", "detail": "bad argument to band"}), ("pass", []))

    def test_each_kind_of_difference_is_a_mismatch(self):
        wrong_bytes = accepted(leaf("04", "42"))
        wrong_identifier = accepted(leaf("9e", "41"))
        wrong_length = accepted()
        wrong_length["tree"]["length"] = 2
        for name, observed, text in [("value", wrong_bytes, "root.value"), ("tag", wrong_identifier, "root.identifier"),
                                     ("length", wrong_length, "root.length"),
                                     ("consumed", accepted(consumed=2), "consumed 2 of 3"),
                                     ("reject", {"status": "rejected", "detail": "boom"}, "observed rejection: boom")]:
            with self.subTest(name=name):
                outcome, differences = self.outcome(shared(), accepted(), observed)
                self.assertEqual(outcome, "mismatch")
                self.assertIn(text, differences[0])

    def test_acceptance_of_a_declared_framing_error_is_a_mismatch(self):
        outcome, differences = self.outcome(rejected_fixture(), {"status": "rejected", "detail": "x"}, accepted())
        self.assertEqual(outcome, "mismatch")
        self.assertIn("lua-asn1: expected rejection", differences[0])

    def test_tree_shape_differences_are_found_at_depth(self):
        tree = {"identifier": "30", "length": 3, "length_bytes": "03", "children": [leaf("04", "41")]}
        fixture = shared(wire="30 03 04 01 41", tree=tree, schema={"type": "sequence_of", "item": OCTETS})
        deep = copy.deepcopy(tree)
        deep["children"][0]["value"] = "42"
        extra = copy.deepcopy(tree)
        extra["children"].append(leaf("04", "41"))
        flat = copy.deepcopy(tree)
        del flat["children"]
        for observed, text in [(deep, "root.0.value"), (extra, "expected 1 children, observed 2"),
                               (flat, "expected constructed")]:
            with self.subTest(text=text):
                outcome, differences = self.outcome(fixture, accepted(tree, 5), accepted(observed, 5))
                self.assertEqual(outcome, "mismatch")
                self.assertIn(text, differences[0])

    def test_projection_gap_does_not_hide_observed_length_bytes(self):
        wrong = accepted()
        wrong["tree"]["length_bytes"] = "8101"
        outcome, differences = self.outcome(shared(), wrong, accepted(projected=True))
        self.assertEqual(outcome, "mismatch")
        self.assertIn("opentlv root.length_bytes", differences[0])

    def test_declared_outcomes_never_become_pass_or_mismatch(self):
        for classification in ("unsupported", "inconclusive"):
            for observed in (accepted(), {"status": "rejected", "detail": "x"}, {"status": "unsupported"}):
                with self.subTest(classification=classification, observed=observed["status"]):
                    self.assertEqual(self.outcome(declared(classification), accepted(), observed), (classification, []))

    def test_adapter_unsupported_on_shared_fixture_is_a_run_failure(self):
        with self.assertRaisesRegex(ValueError, "is shared, but lua-asn1 reports: no type"):
            self.outcome(shared(), accepted(), {"status": "unsupported", "detail": "no type"})


FAKE_HOST = """
import json, os, sys
mode = {mode!r}
sys.stdin.read()
if mode == "startup":
    print("module not found", file=sys.stderr); sys.exit(1)
print(json.dumps({{"adapter": "fake", "module": "/fake.so", "version": "1.0", "runtime": "Lua 5.2",
                  "script": sys.argv[1],
                  "lua_env": sorted(k for k in os.environ if k.startswith(("LUA_", "LUAROCKS_"))),
                  "path": os.environ.get("LUA_PATH")}}), flush=True)
if mode == "garbage": print("not json")
if mode == "crash":
    print(json.dumps({{"id": "first", "status": "accepted", "tree": {{}}}}), flush=True)
    print("native failure", file=sys.stderr); sys.exit(139)
if mode == "hang":
    print(json.dumps({{"id": "first", "status": "accepted", "tree": {{}}}}), flush=True)
    import time; time.sleep(30)
if mode == "bad-id": print(json.dumps({{"id": "other", "status": "rejected"}}))
if mode == "bad-status": print(json.dumps({{"id": "first", "status": "error"}}))
if mode == "no-tree": print(json.dumps({{"id": "first", "status": "accepted"}}))
if mode == "ok":
    print(json.dumps({{"id": "first", "status": "rejected", "detail": "x"}}))
"""


class AdapterProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.adapter = {"script": Path("/adapter.lua"), "environment": {"LUA_PATH": "/only/?/init.lua"},
                        "module": "/fake.so", "version": "1.0"}
        self.requests = [{"id": "first", "wire": "0400"}]

    def run_host(self, mode, adapter=None, timeout=differential.ADAPTER_TIMEOUT):
        host = Path(self.temp.name) / "host.py"
        host.write_text(FAKE_HOST.format(mode=mode), encoding="utf-8")
        with patch.object(differential, "HOST", host), patch.object(differential, "ADAPTER_TIMEOUT", timeout), \
                patch.dict("os.environ", {"LUA_INIT": "os.exit(9)", "LUA_PATH_5_2": "/shadow/?.lua",
                                          "LUA_CPATH": "/shadow/?.so", "LUAROCKS_CONFIG": "/shadow"}):
            return differential.run_adapter("fake", adapter or self.adapter, sys.executable, self.requests)

    def test_success_returns_identity_and_records_with_clean_environment(self):
        identity, records = self.run_host("ok")
        self.assertEqual(records, [{"id": "first", "status": "rejected", "detail": "x"}])
        self.assertEqual(identity["lua_env"], ["LUA_PATH"])
        self.assertEqual(identity["path"], "/only/?/init.lua")

    def test_failures_are_run_failures_naming_the_fixture(self):
        self.requests.append({"id": "second", "wire": "0400"})
        with self.assertRaisesRegex(ValueError, r"fake failed \(139\) at fixture second: native failure"):
            self.run_host("crash")
        with self.assertRaisesRegex(ValueError, "fake timed out at fixture second"):
            self.run_host("hang", timeout=2)
        with self.assertRaisesRegex(ValueError, r"at fixture none \(adapter startup\): module not found"):
            self.run_host("startup")

    def test_protocol_errors_are_run_failures(self):
        for mode, message in [("garbage", "Expecting value|incomplete"), ("bad-id", "out of order"),
                              ("bad-status", "status error"), ("no-tree", "without a tree"),
                              ("silent", "incomplete result set")]:
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, message):
                self.run_host(mode)

    def test_wrong_library_identity_is_a_run_failure(self):
        for change, message in [({"module": "/other.so"}, "unexpected module"),
                                ({"version": "2.0"}, "unexpected version")]:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, message):
                self.run_host("ok", {**self.adapter, **change})

    def test_only_the_external_adapter_receives_the_schema(self):
        captured = {}

        def capture(name, adapter, lua, requests):
            captured[name] = requests
            return {"adapter": name}, [{"id": r["id"], "status": "rejected"} for r in requests]

        receipt = {"path": Path("run/provenance.json"), "lua": "lua", "runtime": "Lua 5.2.4", "platform": {},
                   "packages": {}, "adapters": {"opentlv": {"schema": False}, "lua-asn1": {"schema": True}}}
        with patch.object(differential, "run_adapter", side_effect=capture):
            report = differential.run_comparison([rejected_fixture("04 02 41")], receipt)
        self.assertEqual(captured["opentlv"], [{"id": "rejected", "wire": "040241"}])
        self.assertEqual(captured["lua-asn1"], [{"id": "rejected", "wire": "040241", "schema": OCTETS}])
        self.assertEqual(report["summary"]["pass"], 1)
        self.assertEqual(report["fixtures"][0]["wire"], "040241")

    def test_lua_literal_escapes_all_but_plain_text(self):
        self.assertEqual(differential.lua_literal({"a": [1, True, 'x"\n']}), '{["a"]={1,true,"x\\034\\010"}}')
        self.assertEqual(differential.lua_literal("é"), '"\\195\\169"')
        self.assertEqual(differential.lua_literal("]] os.exit()"), '"\\093\\093 os.exit\\040\\041"')
        with self.assertRaisesRegex(ValueError, "Cannot pass"):
            differential.lua_literal(None)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.tree = self.run_dir / "tree"
        self.module = self.tree / "share/lua/5.2/opentlv/init.lua"
        self.module.parent.mkdir(parents=True)
        self.module.write_bytes(b"return {}\n")
        self.lua = Path(self.temp.name) / "lua"
        self.lua.write_bytes(b"interpreter")
        self.pin = {"version": "2.2.1", "commit": "a" * 40}
        self.release = {"version": "0.3.0", "commit": "b" * 40}
        self.report = {
            "status": "passed", "completed_at": "2026-10-30T10:00:00+00:00", "lua_executable": str(self.lua),
            "configuration": {"lua": {"version": "Lua 5.2.4", "executable_sha256": digest(self.lua)},
                              "platform": {"system": "Linux"}},
            "external": {"pin": self.pin, "directory": str(Path(self.temp.name) / "cache"),
                         "module_directory": "/cache/modules"},
            "opentlv": {"pin": self.release, "acquisition": "fresh", "source": "https://luarocks.org",
                        "core_commit": "c" * 40,
                        "environment": {"LUA_PATH": "/tree/?/init.lua", "LUA_CPATH": "/tree/?.so"},
                        "installed_files": {str(self.module.relative_to(self.tree)): digest(self.module)}}}
        self.path = self.run_dir / "provenance.json"
        self.write()
        for name, value in [("load_pin", self.pin), ("load_release_pin", self.release)]:
            patcher = patch.object(differential, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(differential, "verify_install")
        self.verify_install = patcher.start()
        self.addCleanup(patcher.stop)

    def write(self):
        self.path.write_text(json.dumps(self.report), encoding="utf-8")

    def test_valid_receipt_isolates_each_library_path(self):
        receipt = differential.load_receipt(self.path)
        self.verify_install.assert_called_once()
        adapters = receipt["adapters"]
        self.assertEqual(adapters["opentlv"]["environment"], self.report["opentlv"]["environment"])
        self.assertFalse(adapters["opentlv"]["schema"])
        self.assertEqual(adapters["lua-asn1"]["environment"], {"LUA_PATH": "/cache/modules/?/init.lua", "LUA_CPATH": ""})
        self.assertEqual(adapters["lua-asn1"]["module"], "/cache/modules/asn1/init.lua")
        self.assertEqual(adapters["opentlv"]["module"], str(self.tree / "lib/lua/5.2/opentlv/_core.so"))
        self.assertEqual(receipt["packages"]["opentlv"]["acquisition"], "fresh")
        self.assertEqual(receipt["packages"]["opentlv"]["source"], "https://luarocks.org")

    def test_unusable_receipts_fail_closed(self):
        external_only = {k: v for k, v in self.report.items() if k != "opentlv"}
        for report, message in [({**self.report, "status": "failed"}, "not a complete passed"),
                                (external_only, "not a complete passed"),
                                ({**self.report, "external": {**self.report["external"], "pin": {}}}, "different dependency pins"),
                                ({**self.report, "opentlv": {**self.report["opentlv"], "pin": {}}}, "different dependency pins")]:
            self.path.write_text(json.dumps(report), encoding="utf-8")
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                differential.load_receipt(self.path)

    def test_changed_dependencies_fail_closed(self):
        self.module.write_bytes(b"return {patched=true}\n")
        with self.assertRaisesRegex(ValueError, "Installed OpenTLV file changed"):
            differential.load_receipt(self.path)
        self.module.write_bytes(b"return {}\n")
        shadow = self.tree / "share/lua/5.2/asn1.lua"
        shadow.write_bytes(b"return {}\n")
        with self.assertRaisesRegex(ValueError, "different inventory"):
            differential.load_receipt(self.path)
        shadow.unlink()
        self.lua.write_bytes(b"another interpreter")
        with self.assertRaisesRegex(ValueError, "interpreter changed"):
            differential.load_receipt(self.path)

    def test_corrupt_external_cache_fails_closed(self):
        self.verify_install.side_effect = ValueError("Installed file changed: asn1/init.lua")
        with self.assertRaisesRegex(ValueError, "Installed file changed"):
            differential.load_receipt(self.path)

    def test_newest_complete_receipt_is_selected(self):
        runs = Path(self.temp.name)
        for name, report in [("older", {"status": "passed", "completed_at": "2026-01-01", "opentlv": {}}),
                             ("external", {"status": "passed", "completed_at": "2027-01-01"}),
                             ("failed", {"status": "failed", "completed_at": "2027-01-01", "opentlv": {}})]:
            (runs / name).mkdir()
            (runs / name / "provenance.json").write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual(differential.newest_receipt(runs), self.path)
        with self.assertRaisesRegex(ValueError, "No complete passed setup"):
            differential.newest_receipt(runs / "older")


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.corpus = Path(self.temp.name) / "corpus.json"
        self.receipt = {"path": Path("provenance.json"), "lua": "lua", "runtime": "Lua 5.2.4", "platform": {},
                        "packages": {"opentlv": {"version": "0.3.0"}, "lua-asn1": {"version": "2.2.1"}},
                        "adapters": {"opentlv": {"schema": False}, "lua-asn1": {"schema": True}}}

    def command(self, fixtures, results, *extra):
        self.corpus.write_text(json.dumps({"schema": 1, "fixtures": fixtures}), encoding="utf-8")

        def adapter(name, _adapter, _lua, requests):
            return {"adapter": name}, [{"id": r["id"], **results[name][r["id"]]} for r in requests]

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(differential, "load_receipt", return_value=self.receipt), \
                patch.object(differential, "run_adapter", side_effect=adapter), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = differential.main(["--fixtures", str(self.corpus), "--provenance", "provenance.json", *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_command_reports_all_four_outcomes_and_exit_codes(self):
        fixtures = [shared("same"), shared("different"), {**declared("unsupported"), "id": "gap"},
                    {**declared("inconclusive"), "id": "unclear"}]
        rejected = {"status": "rejected", "detail": "x"}
        same, projected = accepted(), accepted(projected=True)
        results = {"opentlv": {"same": same, "different": same, "gap": same, "unclear": same},
                   "lua-asn1": {"same": projected, "different": accepted(leaf("04", "42"), projected=True),
                                "gap": rejected, "unclear": projected}}
        output = Path(self.temp.name) / "out/report.json"
        code, stdout, _ = self.command(fixtures, results, "--output", str(output))
        self.assertEqual(code, differential.MISMATCH_EXIT)
        self.assertIn("1 pass, 1 mismatch, 1 unsupported, 1 inconclusive", stdout)
        self.assertIn("root.value: expected '41', observed '42'", stdout)
        self.assertIn("unsupported  gap: documented matrix reason", stdout)
        report = json.loads(output.read_text(encoding="utf-8"))
        by_id = {f["id"]: f for f in report["fixtures"]}
        self.assertEqual(by_id["different"]["observed"]["opentlv"]["tree"], leaf("04", "41"))
        self.assertEqual(by_id["gap"]["observed"]["lua-asn1"]["status"], "rejected")
        self.assertEqual(by_id["gap"]["wire"], "9f1f0141")

    def test_report_retains_reproduction_metadata_and_checks_the_runtime(self):
        metadata = {"command": "run", "runtime": "Lua 5.2", "packages": {}}
        fixture = {**rejected_fixture(), "category": "truncated", "description": "Cut short"}
        rejected = {"status": "rejected", "detail": "x"}

        def adapter(_name, _adapter, _lua, requests):
            return {"runtime": "Lua 5.2"}, [{"id": r["id"], **rejected} for r in requests]

        with patch.object(differential, "run_adapter", side_effect=adapter):
            report = differential.run_comparison([fixture], self.receipt, metadata)
            self.assertEqual(report["reproduction"], metadata)
            self.assertEqual(report["fixtures"][0]["category"], "truncated")
            self.assertEqual(report["fixtures"][0]["description"], "Cut short")
            with self.assertRaisesRegex(ValueError, "verified on Lua 5.3, not Lua 5.2"):
                differential.run_comparison([fixture], self.receipt, {**metadata, "runtime": "Lua 5.3"})

    def test_clean_run_exits_zero_even_with_declared_gaps(self):
        results = {"opentlv": {"same": accepted(), "declared": accepted()},
                   "lua-asn1": {"same": accepted(projected=True), "declared": {"status": "unsupported"}}}
        self.assertEqual(self.command([shared("same"), declared()], results)[0], 0)

    def test_run_without_any_comparison_cannot_pass(self):
        results = {"opentlv": {"declared": accepted()}, "lua-asn1": {"declared": {"status": "unsupported"}}}
        code, _, stderr = self.command([declared()], results)
        self.assertEqual(code, 1)
        self.assertIn("No shared fixture was compared", stderr)

    def test_invalid_corpus_or_receipt_is_a_run_failure(self):
        self.corpus.write_text("{}", encoding="utf-8")
        with redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(differential.main(["--fixtures", str(self.corpus)]), 1)
        self.assertIn("Expected fixture schema 1", stderr.getvalue())
        with redirect_stderr(io.StringIO()) as stderr:
            code = differential.main(["--fixtures", str(differential.DEFAULT_FIXTURES),
                                      "--runs-dir", str(Path(self.temp.name) / "none")])
        self.assertEqual(code, 1)
        self.assertIn("No complete passed setup", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
