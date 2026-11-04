# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import check_report, run_der_differential as der

ROOT = Path(__file__).resolve().parents[1]
TRUE = {"kind": "boolean", "value": True}
FIVE = {"kind": "integer", "value": "5"}
PAIR = {"kind": "sequence", "fields": [{"name": "flag", "value": TRUE}, {"name": "count", "value": FIVE}]}


def canonical(fixture_id="pair", wire="30 06 01 01 ff 02 01 05", value=PAIR, type_name="Pair", limitations=None):
    fixture = {"id": fixture_id, "category": "constructed", "description": "A pair", "rule": "X.690 8.9",
               "type": type_name, "wire": wire, "expected": {"result": "canonical", "value": value}}
    if limitations:
        fixture["limitations"] = limitations
    return fixture


def rejection(fixture_id="long-form", wire="04 81 01 aa", error="invalid", type_name="Octets", limitations=None):
    fixture = {"id": fixture_id, "category": "noncanonical", "description": "Long form", "rule": "X.690 10.1",
               "type": type_name, "wire": wire, "expected": {"result": "reject", "error": error}}
    if limitations:
        fixture["limitations"] = limitations
    return fixture


def accepted(value=PAIR, wire="30060101ff020105"):
    return {"status": "accepted", "consumed": len(bytes.fromhex(wire)), "value": copy.deepcopy(value),
            "encode": {"status": "encoded", "wire": wire}}


def reference(value=PAIR, wire="30060101ff020105"):
    return {"decode": {"syntax": "der", "status": "accepted", "code": "RC_OK", "consumed": len(bytes.fromhex(wire)),
                       "value": copy.deepcopy(value)},
            "encode": {"syntax": "der", "status": "encoded", "wire": wire}}


def canonical_observed(value=PAIR, wire="30060101ff020105"):
    return {"opentlv": accepted(value, wire), "asn1c": reference(value, wire),
            "opentlv.encode": {"encode": {"status": "encoded", "wire": wire}},
            "interop.asn1c": reference(value, wire), "interop.opentlv": accepted(value, wire)}


class TypeDescriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.types = der.load_types()

    def test_descriptions_follow_the_schema_module_and_inline_references(self):
        self.assertEqual(list(self.types), der.asn1c.schema_identity()["types"])
        pairs = self.types["Nested"]["fields"][1]["type"]
        self.assertEqual(pairs["item"], self.types["Pair"])
        self.assertEqual(self.types["HighTag200"]["identifier"], "9f8148")

    def test_identifiers_must_be_minimal_and_match_the_form(self):
        for schema, message in [({"kind": "octet_string", "identifier": "9f801f"}, "minimal high-tag"),
                                ({"kind": "octet_string", "identifier": "9f1e"}, "low-tag form"),
                                ({"kind": "octet_string", "identifier": "0401"}, "trailing octets"),
                                ({"kind": "octet_string", "identifier": "24"}, "wrong form"),
                                ({"kind": "sequence", "identifier": "10", "fields": []}, "wrong form"),
                                ({"kind": "real", "identifier": "09"}, "Unknown kind")]:
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, message):
                der.resolve(schema, {})

    def test_components_need_distinct_tags_and_one_presence(self):
        integer = {"kind": "integer", "identifier": "02"}
        for fields, message in [([{"name": "a", "type": integer}, {"name": "b", "type": integer}], "distinct tags"),
                                ([{"name": "a", "type": integer, "optional": True, "default": FIVE}], "either"),
                                ([{"name": "a", "type": integer, "optional": False}], "either")]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                der.resolve({"kind": "sequence", "identifier": "30", "fields": fields}, {})

    def test_recursive_references_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "reference"):
            der.resolve({"ref": "Loop"}, {"Loop": {"ref": "Loop"}}, ("Loop",))

    def test_descriptions_must_list_the_schema_types_in_order(self):
        data = json.loads(der.TYPES.read_text(encoding="utf-8"))
        data["types"] = dict(reversed(list(data["types"].items())))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "types.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "in order"):
                der.load_types(path)


class IndependentEncoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.types = der.load_types()

    def encode(self, type_name, value):
        return der.der_encode(self.types[type_name], value).hex()

    def test_integers_use_minimal_twos_complement(self):
        for number, wire in [(0, "020100"), (127, "02017f"), (128, "02020080"), (-128, "020180"),
                             (-129, "0202ff7f"), (2 ** 63, "0209008000000000000000")]:
            with self.subTest(number=number):
                self.assertEqual(self.encode("Number", {"kind": "integer", "value": str(number)}), wire)

    def test_lengths_switch_to_the_shortest_long_form(self):
        for size, header in [(127, "047f"), (128, "048180"), (255, "0481ff"), (256, "04820100")]:
            with self.subTest(size=size):
                wire = self.encode("Octets", {"kind": "octet_string", "value": "00" * size})
                self.assertTrue(wire.startswith(header))

    def test_schema_rules_are_applied(self):
        default = {"kind": "sequence", "fields": [{"name": "flag", "value": {"kind": "boolean", "value": False}},
                                                  {"name": "count", "value": FIVE}]}
        self.assertEqual(self.encode("DefaultFlag", default), "3003020105")
        numbers = {"kind": "set_of", "items": [{"kind": "integer", "value": "256"}, {"kind": "integer", "value": "1"}]}
        self.assertEqual(self.encode("NumberSet", numbers), "310702010102020100")
        self.assertEqual(self.encode("Alternative", {"kind": "choice", "alternative": "number", "value": FIVE}),
                         "020105")
        self.assertEqual(self.encode("Explicit5", FIVE), "a503020105")
        self.assertEqual(self.encode("Identifier", {"kind": "object_identifier", "value": "2.999"}), "06028837")

    def test_values_that_have_no_der_encoding_are_rejected(self):
        for type_name, value, message in [
                ("Bits", {"kind": "bit_string", "unused_bits": 7, "value": "81"}, "not canonical"),
                ("Bits", {"kind": "bit_string", "unused_bits": 1, "value": ""}, "not canonical"),
                ("Text", {"kind": "ia5string", "value": "80"}, "below 0x80"),
                ("Identifier", {"kind": "object_identifier", "value": "1.40"}, "below 40"),
                ("Number", {"kind": "integer", "value": "05"}, "decimal string"),
                ("Pair", {"kind": "sequence", "fields": [{"name": "flag", "value": TRUE}]}, "Missing component"),
                ("Pair", {"kind": "sequence", "fields": list(reversed(PAIR["fields"]))}, "definition order"),
                ("Flag", FIVE, "does not match")]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.encode(type_name, value)

    def test_framing_reports_the_first_element(self):
        self.assertEqual(der.frame(bytes.fromhex("0101ff00")), 3)
        self.assertEqual(der.frame(bytes.fromhex("9f814801aa")), 5)
        self.assertIsNone(der.frame(bytes.fromhex("30800000")))
        for wire, kind in [("", "empty"), ("9f", "truncated"), ("9f81", "truncated"), ("04", "truncated"),
                           ("048201", "truncated"), ("0402aa", "truncated")]:
            with self.subTest(wire=wire), self.assertRaisesRegex(der.FramingError, kind):
                der.frame(bytes.fromhex(wire))


class CorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.types = der.load_types()
        cls.corpus = der.load_corpus(der.DEFAULT_FIXTURES, cls.types)

    def invalid(self, fixture, message):
        with self.assertRaisesRegex(ValueError, message):
            der.validate_fixture(fixture, self.types)

    def test_committed_corpus_covers_every_category_and_both_results(self):
        fixtures = self.corpus["fixtures"]
        self.assertEqual({f["category"] for f in fixtures}, set(der.CATEGORIES))
        self.assertEqual({f["expected"]["result"] for f in fixtures}, set(der.RESULTS))
        self.assertEqual({f["expected"]["error"] for f in fixtures if f["expected"]["result"] == "reject"},
                         set(der.ERRORS))
        self.assertEqual(self.corpus["reproduction"]["packages"], {"opentlv": "0.3.0", "asn1c": "0.9.29"})

    def test_every_limitation_cites_its_source(self):
        for fixture in self.corpus["fixtures"]:
            for key, reason in fixture.get("limitations", {}).items():
                with self.subTest(fixture=fixture["id"], key=key):
                    source = "capability probe " if key.startswith("asn1c") else ("der_schema.h", "asn1_codec.h",
                                                                                 "TestLab adapter")
                    self.assertTrue(any(word in reason for word in ([source] if isinstance(source, str) else
                                                                    source)))

    def test_cited_capability_probes_exist(self):
        probes = {probe["id"] for probe in der.asn1c.load_capabilities()["probes"]}
        for fixture in self.corpus["fixtures"]:
            for reason in fixture.get("limitations", {}).values():
                if "capability probe " in reason:
                    self.assertIn(reason.split("capability probe ")[1].rstrip(")"), probes)

    def test_canonical_wire_must_be_the_der_of_its_value(self):
        self.invalid(canonical(wire="30 06 01 01 01 02 01 05"), "not the DER encoding")
        self.invalid(canonical(wire="30 07 01 01 ff 02 02 00 05"), "not the DER encoding")
        self.invalid(canonical(value={"kind": "integer"}), "Invalid integer")

    def test_rejection_framing_must_match_the_wire(self):
        for fixture, message in [(rejection(wire="01 01", error="invalid"), "truncated root"),
                                 (rejection(wire="01 01 ff 00", error="invalid"), "contradicts"),
                                 (rejection(wire="01 01 ff", error="trailing"), "contradicts"),
                                 (rejection(wire="", error="truncated"), "empty root"),
                                 (rejection(error="unknown"), "one error")]:
            with self.subTest(message=message):
                self.invalid(fixture, message)

    def test_limitations_are_named_explained_and_leave_a_judge(self):
        for fixture, message in [
                (rejection(limitations={"lua.decode": "x"}), "Limitations name"),
                (rejection(limitations={"asn1c.decode": " "}), "needs a reason"),
                (rejection(limitations={"opentlv.encode": "x"}), "no encode check"),
                (rejection(limitations={"opentlv.decode": "x", "asn1c.decode": "y"}), "No library"),
                (canonical(limitations=dict.fromkeys(der.LIMITATIONS, "x")), "No library")]:
            with self.subTest(message=message):
                self.invalid(fixture, message)

    def test_fixture_fields_are_checked(self):
        for change, message in [({"id": "Pair"}, "kebab-case"), ({"category": "fuzz"}, "Category"),
                                ({"type": "Missing"}, "Unknown schema type"), ({"rule": ""}, "needs a rule"),
                                ({"extra": 1}, "unexpected or missing"), ({"wire": "00" * 4097}, "exceeds")]:
            with self.subTest(message=message):
                self.invalid({**canonical(), **change}, message)

    def test_reproduction_names_the_pinned_packages(self):
        metadata = copy.deepcopy(self.corpus["reproduction"])
        metadata["packages"]["asn1c"] = "0.9.28"
        with self.assertRaisesRegex(ValueError, "different package versions"):
            der.validate_reproduction(metadata)

    def test_static_denominators_count_judged_checks(self):
        counts = der.denominators([canonical(), rejection(limitations={"asn1c.decode": "x"}),
                                   canonical("other", limitations={"opentlv.encode": "x"})])
        self.assertEqual(counts["opentlv.decode"], {"applies": 3, "judged": 3})
        self.assertEqual(counts["asn1c.decode"], {"applies": 3, "judged": 2})
        self.assertEqual(counts["opentlv.round-trip"], {"applies": 2, "judged": 1})
        self.assertEqual(counts["interop.opentlv-to-asn1c"], {"applies": 2, "judged": 1})
        self.assertEqual(counts["interop.asn1c-to-opentlv"], {"applies": 2, "judged": 2})


class VerdictTests(unittest.TestCase):
    def test_asn1c_der_verdict_requires_the_canonical_re_encoding(self):
        record = reference(wire="0401aa")
        self.assertEqual(der.asn1c_verdict(record, "0401aa"), {"status": "accepted"})
        self.assertEqual(der.asn1c_verdict(record, "048101aa"),
                         {"status": "rejected", "error": "invalid", "native": "noncanonical", "canonical": "0401aa"})
        for native, normalized in [("malformed", "invalid"), ("constraint", "invalid"), ("truncated", "truncated"),
                                   ("trailing", "trailing"), ("empty", "empty")]:
            rejected = {"decode": {"status": "rejected", "error": native}}
            self.assertEqual(der.asn1c_verdict(rejected, "")["error"], normalized)
        failed = {**record, "encode": {"status": "failed"}}
        self.assertEqual(der.asn1c_verdict(failed, "0401aa")["status"], "undecided")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            der.asn1c_verdict({"decode": {"status": "unsupported"}}, "0401aa")

    def test_canonical_fixture_passes_every_check(self):
        outcome, checks = der.evaluate(canonical(), canonical_observed())
        self.assertEqual(outcome, "pass")
        self.assertEqual(list(checks), list(der.CHECKS["canonical"]))
        self.assertTrue(all(check["outcome"] == "pass" for check in checks.values()))

    def test_each_failing_check_is_reported(self):
        observed = canonical_observed()
        observed["opentlv"]["encode"]["wire"] = "30070101ff02020005"
        observed["opentlv.encode"]["encode"] = {"status": "failed", "detail": "callback"}
        observed["asn1c"]["decode"]["value"] = TRUE
        outcome, checks = der.evaluate(canonical(), observed)
        self.assertEqual(outcome, "mismatch")
        failed = {name for name, check in checks.items() if check["outcome"] == "fail"}
        self.assertEqual(failed, {"opentlv.round-trip", "opentlv.encode", "asn1c.decode"})
        self.assertIn("encoding failed", checks["opentlv.encode"]["difference"])

    def test_a_limitation_limits_every_check_that_uses_it(self):
        observed = canonical_observed()
        observed["opentlv.encode"]["encode"] = {"status": "unsupported", "detail": "out of range"}
        observed["opentlv"]["encode"] = {"status": "unsupported", "detail": "out of range"}
        del observed["interop.asn1c"]
        outcome, checks = der.evaluate(canonical(limitations={"opentlv.encode": "int64"}), observed)
        self.assertEqual(outcome, "pass")
        self.assertEqual({name for name, check in checks.items() if check["outcome"] == "limited"},
                         {"opentlv.round-trip", "opentlv.encode", "interop.opentlv-to-asn1c"})
        self.assertEqual(checks["opentlv.encode"]["limitations"], ["opentlv.encode"])

    def test_a_limitation_that_does_not_show_fails_the_run(self):
        with self.assertRaisesRegex(ValueError, "did not occur"):
            der.evaluate(canonical(limitations={"asn1c.decode": "x"}), canonical_observed())

    def test_missing_cross_input_is_not_run(self):
        observed = canonical_observed()
        observed["opentlv.encode"]["encode"] = {"status": "failed", "detail": "x"}
        del observed["interop.asn1c"]
        _, checks = der.evaluate(canonical(), observed)
        self.assertEqual(checks["interop.opentlv-to-asn1c"]["outcome"], "not-run")

    def test_rejections_must_come_from_the_library_with_the_expected_error(self):
        fixture = rejection()
        verdict = {"status": "rejected", "error": "invalid"}
        library = {"status": "rejected", "error": "invalid", "source": "opentlv"}
        self.assertEqual(der.evaluate(fixture, {"opentlv": library, "asn1c.verdict": verdict})[0], "pass")
        for change, message in [({"source": "adapter", "detail": "tag"}, "only the TestLab adapter"),
                                ({"error": "truncated"}, "OpenTLV error truncated"),
                                ({"status": "accepted"}, "OpenTLV accepted")]:
            with self.subTest(message=message):
                outcome, checks = der.evaluate(fixture, {"opentlv": {**library, **change}, "asn1c.verdict": verdict})
                self.assertEqual(outcome, "mismatch")
                self.assertIn(message, checks["opentlv.decode"]["difference"])
        outcome, checks = der.evaluate(fixture, {"opentlv": library, "asn1c.verdict": {"status": "accepted"}})
        self.assertIn("asn1c DER verdict accepted", checks["asn1c.decode"]["difference"])

    def test_adapter_records_are_validated(self):
        decode, encode = {"id": "x", "operation": "decode"}, {"id": "x/encode", "operation": "encode"}
        der.check_der_record("opentlv", decode, {"id": "x", **accepted()})
        der.check_der_record("opentlv", encode, {"id": "x/encode", "encode": {"status": "encoded", "wire": "00"}})
        for request, record, message in [
                (decode, {"status": "unsupported"}, "status unsupported"),
                (decode, {"status": "rejected", "error": "invalid", "source": "lua"}, "unknown rejection"),
                (decode, {"status": "accepted", "value": PAIR}, "did not re-encode"),
                (encode, {"id": "x/encode"}, "no encoding"),
                (encode, {"id": "x/encode", "encode": {"status": "maybe"}}, "unknown encode status")]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                der.check_der_record("opentlv", request, record)


class ComparisonTests(unittest.TestCase):
    """The comparison with stand-in adapters: requests, cross inputs and the report."""

    def setUp(self):
        self.types = der.load_types()
        self.receipts = {"paths": {"lua": "/lua/provenance.json", "asn1c": "/asn1c/provenance.json"},
                         "runtime": "Lua 5.2.4", "platform": {"system": "Linux"}, "compiler": "gcc 13",
                         "packages": {"opentlv": {"version": "0.3.0"},
                                      "asn1c": {"version": "0.9.29", "schema": "TestLabReference-1"}}}
        self.opentlv_requests, self.asn1c_requests = [], []

    def opentlv(self, _, requests, reproduction=None):
        self.opentlv_requests.append(requests)
        records = []
        for request in requests:
            if request["operation"] == "encode":
                records.append({"id": request["id"], "encode": {"status": "encoded", "wire": "30060101ff020105"}})
            elif request["wire"] == "048101aa":
                records.append({"id": request["id"], "status": "rejected", "error": "invalid", "source": "opentlv"})
            else:
                records.append({"id": request["id"], **accepted()})
        return records

    def asn1c(self, _, requests):
        self.asn1c_requests.append(requests)
        return [{"id": r["id"], "type": r["type"], **(reference() if r["type"] == "Pair" else
                                                       reference({"kind": "octet_string", "value": "aa"}, "0401aa"))}
                for r in requests]

    def compare(self, fixtures):
        with patch.object(der, "run_opentlv", side_effect=self.opentlv), \
                patch.object(der, "run_asn1c", side_effect=self.asn1c):
            return der.run_comparison(fixtures, self.types, self.receipts)

    def test_both_libraries_decode_encode_and_decode_each_other(self):
        report = self.compare([canonical(), rejection()])
        self.assertEqual(report["status"], "passed")
        first, cross = self.opentlv_requests
        self.assertEqual([(r["id"], r["operation"]) for r in first],
                         [("pair", "decode"), ("long-form", "decode"), ("pair/encode", "encode")])
        self.assertEqual(first[2]["value"], PAIR)
        self.assertEqual(first[0]["schema"], self.types["Pair"])
        self.assertEqual(cross, [{"id": "pair/from-asn1c", "operation": "decode", "wire": "30060101ff020105",
                                  "schema": self.types["Pair"]}])
        self.assertEqual([r["wire"] for r in self.asn1c_requests[0]], ["30060101ff020105", "048101aa"])
        self.assertEqual(self.asn1c_requests[1], [{"id": "pair", "type": "Pair", "wire": "30060101ff020105"}])
        self.assertEqual(report["summary"]["checks"]["opentlv.decode"],
                         {"pass": 2, "fail": 0, "limited": 0, "not-run": 0, "judged": 2})
        verdict = report["fixtures"][1]["observed"]["asn1c.verdict"]
        self.assertEqual(verdict["native"], "noncanonical")

    def test_reports_keep_matrix_coverage_and_reproduction(self):
        report = self.compare([canonical(), rejection(type_name="Octets", error="truncated")])
        origin = {"corpus": "differential/fixtures/der-canonical.json", "corpus_sha256": "abc",
                  "testlab": {"commit": "abc123", "modified": False}}
        der.add_reproduction(report, origin, [])
        self.assertEqual(report["status"], "mismatch")
        self.assertEqual(report["fixtures"][1]["reproduce"][-1],
                         "python3 scripts/run_der_differential.py --fixtures differential/fixtures/der-canonical.json "
                         "--fixture long-form")
        self.assertEqual(report["fixtures"][1]["reproduce"][:3], ["git checkout abc123", *der.SETUP_COMMANDS])
        text = der.render_report(report)
        for section in ("## Mismatches: possible defects", "## Coverage", "## Outcome matrix",
                        "| long-form | reject truncated | **FAIL** | — | — | **FAIL** |", "OpenTLV error invalid"):
            self.assertIn(section, text)

    def test_reports_list_declared_limitations_with_their_observation(self):
        fixture = rejection(wire="04 01 aa", limitations={"asn1c.decode": "asn1c reads it (capability probe x)"})
        report = self.compare([fixture])
        der.add_reproduction(report, {"corpus": "c.json", "corpus_sha256": "abc",
                                      "testlab": {"commit": None, "modified": True}}, [])
        text = der.render_report(report)
        self.assertEqual(report["fixtures"][0]["reproduce"][0], der.SETUP_COMMANDS[0])
        self.assertIn("## Declared limitations: not defects", text)
        self.assertIn("| long-form | `asn1c.decode` | asn1c DER verdict accepted | asn1c reads it", text)
        self.assertIn("uncommitted changes", text)


class CommandTests(unittest.TestCase):
    def run_main(self, outcome=None, error=None):
        report = {"schema": 1, "status": "passed", "fixtures": [],
                  "summary": {"fixtures": 1, "pass": 1, "mismatch": 0 if outcome != "mismatch" else 1}}
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(der, "load_receipts", side_effect=error, return_value={}), \
                patch.object(der.lua_runner, "newest_receipt", return_value=Path("/lua.json")), \
                patch.object(der.check_asn1c, "newest_receipt", return_value=Path("/asn1c.json")), \
                patch.object(der, "run_comparison", return_value=report), \
                patch.object(der, "print_report"), redirect_stderr(io.StringIO()) as stderr:
            output = Path(temp) / "report.json"
            status = der.main(["--fixture", "boolean-true", "--output", str(output)])
            return status, json.loads(output.read_text(encoding="utf-8")), stderr.getvalue()

    def test_exit_codes_separate_mismatches_from_run_failures(self):
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.run_main("mismatch")[0], der.MISMATCH_EXIT)
        status, report, stderr = self.run_main(error=ValueError("Receipt uses a different asn1c pin"))
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "failed")
        self.assertIn("different asn1c pin", stderr)
        self.assertEqual(report["reproduce"][-1].split()[-2:], ["--fixture", "boolean-true"])

    def test_unknown_fixture_is_a_run_failure(self):
        with redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()):
            self.assertEqual(der.main(["--fixture", "missing"]), 1)
        self.assertIn("Unknown fixture: missing", stderr.getvalue())

    def test_mismatch_probe_is_a_real_library_difference(self):
        probe = der.load_corpus(ROOT / "tests/fixtures/der_mismatch.json")["fixtures"]
        committed = {f["id"]: f for f in der.load_corpus(der.DEFAULT_FIXTURES)["fixtures"]}
        self.assertEqual(len(probe), 1)
        original = committed["default-omitted"]
        self.assertEqual((probe[0]["wire"], probe[0]["expected"]), (original["wire"], original["expected"]))
        self.assertNotIn("limitations", probe[0])
        self.assertEqual(original["limitations"].keys(), {"opentlv.encode"})

    def test_fast_runs_the_corpus_and_the_probe(self):
        text = (ROOT / ".github/workflows/fast.yml").read_text(encoding="utf-8")
        for command in ("scripts/run_der_differential.py", "tests/fixtures/der_mismatch.json",
                        "build/der-reports/mismatch-probe.json", "der-differential-reports"):
            self.assertIn(command, text)


class DerReportCheckTests(unittest.TestCase):
    def test_der_mismatch_is_rerun_with_both_receipts(self):
        result = {"id": "probe", "outcome": "mismatch", "wire": "3003020105", "type": "DefaultFlag",
                  "rule": "X.690 11.5", "expected": {"result": "canonical"}, "checks": {"opentlv.encode": {}},
                  "observed": {"opentlv": {}, "asn1c": {}, "opentlv.encode": {}},
                  "reproduce": [*der.SETUP_COMMANDS, "python3 scripts/run_der_differential.py --fixture probe"]}
        report = {"status": "mismatch", "runtime": "Lua 5.2.4", "fixtures": [result],
                  "provenance": {"lua": "/lua.json", "asn1c": "/asn1c.json"},
                  "packages": {"opentlv": {"version": "0.3.0"}, "asn1c": {"version": "0.9.29"}}}
        commands = []

        def fake_run(command, **_):
            commands.append(command)
            Path(command[command.index("--output") + 1]).write_text(json.dumps({"fixtures": [result]}),
                                                                   encoding="utf-8")
            return Mock(returncode=der.MISMATCH_EXIT)

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(check_report.subprocess, "run", side_effect=fake_run):
                self.assertEqual(check_report.check_report(path), 1)
            self.assertEqual(commands[0][4:8], ["--lua-provenance", "/lua.json", "--asn1c-provenance", "/asn1c.json"])
            result["reproduce"][-1] = "python3 scripts/run_differential.py --fixture probe"
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "another script"):
                check_report.check_report(path)


if __name__ == "__main__":
    unittest.main()
