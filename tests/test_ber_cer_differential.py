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

from scripts import check_report, run_ber_cer_differential as interop, x690

ROOT = Path(__file__).resolve().parents[1]
TRUE = {"kind": "boolean", "value": True}
FIVE = {"kind": "integer", "value": "5"}
PAIR = {"kind": "sequence", "fields": [{"name": "flag", "value": TRUE}, {"name": "count", "value": FIVE}]}
BER_PAIR = "30800101ff0201050000"
DER_PAIR = "30060101ff020105"
ISSUE = "https://github.com/OpenTLV/opentlv-lua/issues/99"


def fixture(fixture_id="pair", encoding="ber", wire="30 80 01 01 ff 02 01 05 00 00", expected=None,
            type_name="Pair", **declarations):
    entry = {"id": fixture_id, "encoding": encoding, "category": "indefinite-length", "description": "A pair",
             "rule": "X.690 8.9", "type": type_name, "wire": wire,
             "expected": expected or {"result": "accept" if encoding == "ber" else "canonical", "value": PAIR}}
    entry.update(declarations)
    return entry


def rejection(fixture_id="definite", encoding="cer", wire="30 06 01 01 ff 02 01 05", error="invalid", **declarations):
    return fixture(fixture_id, encoding, wire, {"result": "reject", "error": error}, **declarations)


def opentlv_accepted(value=PAIR, wire=BER_PAIR):
    return {"status": "accepted", "consumed": len(bytes.fromhex(wire)), "value": copy.deepcopy(value),
            "encode": {"status": "encoded", "wire": wire}}


def asn1c_record(value=PAIR, wire=DER_PAIR, encode=None):
    record = {"decode": {"syntax": "ber", "status": "accepted", "code": "RC_OK", "consumed": 10,
                         "value": copy.deepcopy(value)}}
    record["encode"] = encode or {"syntax": "der", "status": "encoded", "wire": wire}
    return record


def ber_observed(value=PAIR):
    return {"opentlv": opentlv_accepted(value, DER_PAIR), "asn1c": asn1c_record(value),
            "opentlv.encode": {"encode": {"status": "encoded", "wire": DER_PAIR}},
            "interop.asn1c": asn1c_record(value), "interop.opentlv": opentlv_accepted(value, DER_PAIR)}


def cer_observed(value=PAIR, wire=BER_PAIR):
    unsupported = {"syntax": "cer", "status": "unsupported"}
    return {"opentlv": opentlv_accepted(value, wire), "asn1c": asn1c_record(value, encode=unsupported),
            "opentlv.encode": {"encode": {"status": "encoded", "wire": wire}},
            "interop.asn1c": {"decode": asn1c_record(value)["decode"]}}


class ReferenceTests(unittest.TestCase):
    """The independent X.690 reference that every expectation and BER encoding is checked against."""

    @classmethod
    def setUpClass(cls):
        cls.types = interop.der.load_types()

    def decode(self, type_name, wire, rules="ber"):
        return x690.decode(self.types[type_name], bytes.fromhex(wire), rules)

    def error(self, type_name, wire, rules="ber"):
        with self.assertRaises(x690.Invalid) as raised:
            self.decode(type_name, wire, rules)
        return raised.exception.error

    def test_definite_and_indefinite_forms_give_one_value(self):
        for wire in (DER_PAIR, BER_PAIR, "3081060101ff020105", "30820006 0101ff 020105"):
            with self.subTest(wire=wire):
                self.assertEqual(self.decode("Pair", wire), PAIR)

    def test_constructed_strings_are_joined_and_segments_checked(self):
        self.assertEqual(self.decode("Octets", "24 80 24 80 04 01 41 00 00 04 01 42 00 00")["value"], "4142")
        self.assertEqual(self.decode("Text", "36 80 04 01 41 00 00")["value"], "41")
        self.assertEqual(self.decode("Implicit30", "be 03 04 01 41")["value"], "41")
        self.assertEqual(self.decode("Bits", "23 80 03 02 00 ff 03 02 04 f0 00 00"),
                         {"kind": "bit_string", "unused_bits": 4, "value": "fff0"})
        for type_name, wire in [("Text", "36 03 16 01 41"), ("Bits", "23 80 03 02 04 f0 03 02 00 ff 00 00"),
                                ("Number", "22 03 02 01 05")]:
            with self.subTest(wire=wire):
                self.assertEqual(self.error(type_name, wire), "invalid")

    def test_ber_alternatives_decode_to_the_logical_value(self):
        self.assertEqual(self.decode("Flag", "01 01 01"), TRUE)
        self.assertEqual(self.decode("Bits", "03 02 05 a1"), {"kind": "bit_string", "unused_bits": 5, "value": "a0"})
        self.assertEqual(self.decode("TaggedSet", "31 06 81 01 ff 80 01 05")["fields"][0]["name"], "first")

    def test_truncation_is_reported_only_without_a_bounding_definite_length(self):
        self.assertEqual(self.error("Pair", "30 80 01 01 ff 02 01 05"), "truncated")
        self.assertEqual(self.error("Pair", "30 80 01 01 ff 02 05 01"), "truncated")
        self.assertEqual(self.error("Pair", "30 03 02 05 01"), "invalid")
        self.assertEqual(self.error("Nested", "30 0d 04 01 41 30 80 30 06 01 01 ff 02 01 05"), "invalid")
        self.assertEqual(self.error("HighTag200", "9f 81"), "truncated")
        self.assertEqual(self.error("Octets", ""), "empty")
        self.assertEqual(self.error("Pair", BER_PAIR + "0000"), "trailing")

    def test_end_of_contents_and_identifier_rules(self):
        for type_name, wire in [("Octets", "00 00"), ("NumberList", "30 02 00 00"),
                                ("Pair", "30 80 01 01 ff 02 01 05 00 01 00 00 00"),
                                ("Pair", "30 80 01 01 ff 02 01 05 20 00"), ("Octets", "04 80 00 00"),
                                ("Octets", "04 ff"), ("HighTag31", "9f 80 1f 01 aa"), ("Implicit30", "9f 1e 01 aa")]:
            with self.subTest(wire=wire):
                self.assertEqual(self.error(type_name, wire), "invalid")

    def test_cer_adds_its_canonical_restrictions(self):
        long = "24 80 04 82 03 e8 " + "41 " * 1000 + "04 01 42 00 00"
        self.assertEqual(self.decode("Octets", long, "cer")["value"], "41" * 1000 + "42")
        for type_name, wire in [("Pair", DER_PAIR), ("Octets", "04 81 03 414243"), ("Flag", "01 01 01"),
                                ("Bits", "03 02 05 a1"), ("Octets", "24 80 04 01 41 00 00"),
                                ("Octets", "04 82 03 e9 " + "41 " * 1001),
                                ("DefaultFlag", "30 80 01 01 00 02 01 05 00 00"),
                                ("TaggedSet", "31 80 81 01 ff 80 01 05 00 00"),
                                ("NumberSet", "31 80 02 01 02 02 01 01 00 00")]:
            with self.subTest(wire=wire[:40]):
                self.assertEqual(self.error(type_name, wire, "cer"), "invalid")
                self.decode(type_name, wire)  # Each is still valid BER.

    def test_command_prints_the_value_or_the_rejection(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(x690.main(["Pair", "30 80 01 01 ff 02 01 05 00 00"]), 0)
            self.assertEqual(x690.main(["Pair", DER_PAIR, "--encoding", "cer"]), 1)
        accepted, rejected = map(json.loads, output.getvalue().splitlines())
        self.assertEqual(accepted, {"result": "accept", "value": PAIR})
        self.assertEqual((rejected["result"], rejected["error"]), ("reject", "invalid"))

    def test_cer_encoder_segments_at_1000_contents_octets(self):
        octets = self.types["Octets"]
        self.assertEqual(len(x690.cer_encode(octets, {"kind": "octet_string", "value": "41" * 1000})), 1004)
        segmented = x690.cer_encode(octets, {"kind": "octet_string", "value": "41" * 2000})
        self.assertEqual(segmented[:6].hex() + segmented[-2:].hex(), "2480048203e8" + "0000")
        self.assertEqual(segmented.count(bytes.fromhex("048203e8")), 2)
        bits = self.types["Bits"]
        self.assertEqual(x690.cer_encode(bits, {"kind": "bit_string", "unused_bits": 0, "value": "aa" * 999})[:5].hex(),
                         "038203e800")
        long_bits = x690.cer_encode(bits, {"kind": "bit_string", "unused_bits": 0, "value": "aa" * 1000})
        self.assertTrue(long_bits.endswith(bytes.fromhex("030200aa0000")))
        self.assertEqual(x690.cer_encode(self.types["NumberSet"], {"kind": "set_of", "items": [
            {"kind": "integer", "value": "256"}, FIVE]}).hex(), "3180020105020201000000")


class CorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.types = interop.der.load_types()
        cls.corpus = interop.load_corpus(interop.DEFAULT_FIXTURES, cls.types)
        cls.fixtures = cls.corpus["fixtures"]

    def invalid(self, entry, message):
        with self.assertRaisesRegex(ValueError, message):
            interop.validate_fixture(entry, self.types)

    def test_corpus_covers_every_category_encoding_result_and_error(self):
        self.assertEqual({f["category"] for f in self.fixtures}, set(interop.CATEGORIES))
        for encoding in interop.ENCODINGS:
            self.assertEqual({f["expected"]["result"] for f in self.fixtures if f["encoding"] == encoding},
                             set(interop.RESULTS[encoding]))
        self.assertEqual({f["expected"]["error"] for f in self.fixtures if f["expected"]["result"] == "reject"},
                         set(interop.ERRORS))
        self.assertEqual(self.corpus["reproduction"]["packages"], {"opentlv": "0.3.0", "asn1c": "0.9.29"})

    def test_every_declaration_cites_its_source(self):
        probes = {probe["id"] for probe in interop.der.asn1c.load_capabilities()["probes"]}
        for entry in self.fixtures:
            for key in ("limitations", "not_comparable"):
                for name, reason in entry.get(key, {}).items():
                    with self.subTest(fixture=entry["id"], name=name):
                        if name.startswith("asn1c"):
                            self.assertIn(reason.split("capability probe ")[1].rstrip(")"), probes)
                        else:
                            self.assertTrue(any(source in reason for source in (
                                "asn1_codec.h", "ber.h", "cer.h", "cer_validation.h", "TestLab adapter",
                                "schema layer")))

    def test_structural_classifications_cite_probes(self):
        probes = {probe["id"] for probe in interop.der.asn1c.load_capabilities()["probes"]}
        for reason in (interop.CER_ENCODE_LIMITATION, interop.CER_DECODE_NOT_COMPARABLE):
            self.assertIn(reason.split("capability probe ")[1].rstrip(")"), probes)

    def test_reused_fixtures_keep_their_origin_bytes(self):
        reused = [f for f in self.fixtures if "origin" in f]
        self.assertGreater(len(reused), 40)
        self.assertEqual({f["origin"].partition(":")[0] for f in reused}, set(interop.ORIGINS))
        self.invalid(fixture(wire="30 80 01 01 ff 02 01 05 00 00", origin="asn1-ber:boolean-false"), "differs")
        self.invalid(fixture(origin="seed:x"), "Origin must name")

    def test_expectations_must_agree_with_the_x690_reference(self):
        self.invalid(fixture(wire="30 80 01 01 ff 02 01 06 00 00"), "decodes")
        self.invalid(fixture(encoding="cer", wire=DER_PAIR), "not the CER encoding")
        self.invalid(rejection(wire=BER_PAIR), "decodes it as")
        self.invalid(rejection(wire="30 80 01 01 ff 02 01 05", error="invalid"), "reports truncated")
        self.invalid(fixture(encoding="ber", expected={"result": "canonical", "value": PAIR}), "expects: accept")

    def test_declarations_are_named_explained_and_leave_a_judge(self):
        for entry, message in [
                (rejection(limitations={"lua.decode": "x"}), "limitations name"),
                (rejection(not_comparable={"asn1c.decode": " "}), "needs a reason"),
                (rejection(limitations={"opentlv.encode": "x"}), "no encode check"),
                (rejection(encoding="ber", wire="02 02 00 01", type_name="Number",
                           limitations={"opentlv.decode": "x"}, not_comparable={"asn1c.decode": "y"}), "No library"),
                (fixture(limitations={"opentlv.decode": "x"}, not_comparable={"opentlv.decode": "y"}), "twice"),
                (fixture(encoding="cer", wire=BER_PAIR, limitations={"asn1c.encode": "x"}), "declared by the runner"),
                (rejection(not_comparable={"asn1c.decode": "x"}), "declared by the runner"),
                (fixture(confirmed={"opentlv.decode": "a known bug"}), "must link"),
                (fixture(confirmed={"opentlv.round-trip": ISSUE}), "confirmed name")]:
            with self.subTest(message=message):
                self.invalid(entry, message)
        interop.validate_fixture(fixture(confirmed={"opentlv.decode": ISSUE}), self.types)

    def test_fixture_fields_are_checked(self):
        for change, message in [({"id": "Pair"}, "kebab-case"), ({"category": "fuzz"}, "Category"),
                                ({"encoding": "der"}, "Encoding"), ({"type": "Missing"}, "Unknown schema type"),
                                ({"rule": ""}, "needs a rule"), ({"extra": 1}, "unexpected or missing"),
                                ({"wire": "00" * 4097}, "exceeds")]:
            with self.subTest(message=message):
                self.invalid({**fixture(), **change}, message)

    def test_reproduction_names_the_pinned_packages(self):
        metadata = copy.deepcopy(self.corpus["reproduction"])
        metadata["packages"]["opentlv"] = "0.2.0"
        with self.assertRaisesRegex(ValueError, "different package versions"):
            interop.validate_reproduction(metadata)

    def test_cer_rejections_of_valid_ber_are_not_comparable_for_asn1c(self):
        self.assertEqual(interop.declarations(rejection(), self.types)[1], {
            "asn1c.decode": interop.CER_DECODE_NOT_COMPARABLE})
        self.assertEqual(interop.declarations(rejection(wire="30 80 01 01 ff"), self.types)[1], {})
        self.assertEqual(interop.declarations(fixture(encoding="cer", wire=BER_PAIR), self.types)[0],
                         {"asn1c.encode": interop.CER_ENCODE_LIMITATION})

    def test_static_denominators_count_judged_checks(self):
        counts = interop.denominators([fixture(), rejection(), fixture("cer", "cer", BER_PAIR)], self.types)
        self.assertEqual(counts["ber"]["opentlv.encode"], {"applies": 1, "judged": 1})
        self.assertEqual(counts["cer"]["asn1c.decode"], {"applies": 2, "judged": 1})
        self.assertEqual(counts["cer"]["interop.asn1c-to-opentlv"], {"applies": 1, "judged": 0})
        self.assertEqual(counts["cer"]["opentlv.round-trip"], {"applies": 1, "judged": 1})


class VerdictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.types = interop.der.load_types()

    def evaluate(self, entry, observed):
        return interop.evaluate(entry, observed, self.types)

    def test_ber_encoders_are_judged_by_value_not_bytes(self):
        outcome, checks = self.evaluate(fixture(), ber_observed())
        self.assertEqual(outcome, "pass")
        self.assertEqual(list(checks), list(interop.CHECKS["accept"]))
        observed = ber_observed()
        observed["opentlv.encode"]["encode"]["wire"] = "3081060101ff020105"
        self.assertEqual(self.evaluate(fixture(), observed)[1]["opentlv.encode"]["outcome"], "pass")
        observed["opentlv.encode"]["encode"]["wire"] = "30060101ff020106"
        self.assertIn("has value", self.evaluate(fixture(), observed)[1]["opentlv.encode"]["difference"])
        observed["opentlv.encode"]["encode"]["wire"] = "30060101ff0201"
        self.assertIn("not BER of the value", self.evaluate(fixture(), observed)[1]["opentlv.encode"]["difference"])

    def test_set_of_values_compare_without_order(self):
        value = {"kind": "set_of", "items": [{"kind": "integer", "value": "2"}, {"kind": "integer", "value": "1"}]}
        reordered = {"kind": "set_of", "items": value["items"][::-1]}
        self.assertIsNone(interop.compare_value(value, reordered, "v"))
        self.assertIsNotNone(interop.compare_value({"kind": "sequence_of", "items": value["items"]},
                                                   {"kind": "sequence_of", "items": reordered["items"]}, "v"))

    def test_cer_reference_limitations_are_runner_declared_and_confirmed(self):
        entry = fixture(encoding="cer", wire=BER_PAIR)
        outcome, checks = self.evaluate(entry, cer_observed())
        self.assertEqual(outcome, "pass")
        self.assertEqual({n for n, c in checks.items() if c["outcome"] == "limitation"},
                         {"asn1c.encode", "interop.asn1c-to-opentlv"})
        observed = cer_observed()
        observed["asn1c"]["encode"] = {"syntax": "cer", "status": "encoded", "wire": BER_PAIR}
        with self.assertRaisesRegex(ValueError, "asn1c encoded CER"):
            self.evaluate(entry, observed)

    def test_valid_ber_cer_rejection_needs_asn1c_to_accept_it(self):
        observed = {"opentlv": {"status": "rejected", "error": "invalid", "source": "opentlv"},
                    "asn1c": asn1c_record()}
        outcome, checks = self.evaluate(rejection(), observed)
        self.assertEqual((outcome, checks["asn1c.decode"]["outcome"]), ("pass", "not-comparable"))
        observed["asn1c"] = {"decode": {"status": "rejected", "error": "malformed"}}
        with self.assertRaisesRegex(ValueError, "rejected valid BER"):
            self.evaluate(rejection(), observed)

    def test_rejections_must_come_from_the_library_with_the_expected_error(self):
        entry = rejection(encoding="ber", wire="30 80 01 01 ff", error="truncated")
        library = {"status": "rejected", "error": "truncated", "source": "opentlv"}
        reference = {"decode": {"status": "rejected", "error": "truncated"}}
        self.assertEqual(self.evaluate(entry, {"opentlv": library, "asn1c": reference})[0], "pass")
        for change, message in [({"source": "adapter", "detail": "tag"}, "only the TestLab adapter"),
                                ({"error": "invalid"}, "OpenTLV error invalid"), ({"status": "accepted"}, "accepted")]:
            with self.subTest(message=message):
                outcome, checks = self.evaluate(entry, {"opentlv": {**library, **change}, "asn1c": reference})
                self.assertEqual(outcome, "mismatch")
                self.assertIn(message, checks["opentlv.decode"]["difference"])
        reference = {"decode": {"status": "rejected", "error": "malformed"}}
        _, checks = self.evaluate(entry, {"opentlv": library, "asn1c": reference})
        self.assertIn("asn1c error invalid", checks["asn1c.decode"]["difference"])

    def test_a_declaration_that_does_not_show_fails_the_run(self):
        with self.assertRaisesRegex(ValueError, "did not occur"):
            self.evaluate(fixture(limitations={"asn1c.decode": "x"}), ber_observed())
        with self.assertRaisesRegex(ValueError, "no longer occurs"):
            self.evaluate(fixture(confirmed={"opentlv.decode": ISSUE}), ber_observed())

    def test_confirmed_mismatches_are_reported_without_failing(self):
        observed = ber_observed()
        observed["opentlv"]["status"] = "rejected"
        observed["opentlv"].update(error="invalid", source="opentlv")
        outcome, checks = self.evaluate(fixture(confirmed={"opentlv.decode": "Tracked in " + ISSUE}), observed)
        self.assertEqual(outcome, "confirmed")
        self.assertEqual(checks["opentlv.decode"]["issue"], ISSUE)
        self.assertEqual({c["outcome"] for n, c in checks.items() if n != "opentlv.decode"}, {"pass"})

    def test_limitation_and_not_comparable_keep_observations(self):
        observed = ber_observed()
        observed["opentlv.encode"]["encode"] = {"status": "unsupported", "detail": "out of range"}
        del observed["interop.asn1c"]
        _, checks = self.evaluate(fixture(limitations={"opentlv.encode": "int64"}), observed)
        self.assertEqual({n for n, c in checks.items() if c["outcome"] == "limitation"},
                         {"opentlv.encode", "interop.opentlv-to-asn1c"})
        observed = ber_observed()
        observed["asn1c"]["decode"]["value"] = TRUE
        _, checks = self.evaluate(fixture(not_comparable={"asn1c.decode": "probe"}), observed)
        self.assertEqual(checks["asn1c.decode"]["outcome"], "not-comparable")
        self.assertIn("asn1c value", checks["asn1c.decode"]["difference"])

    def test_missing_cross_input_is_inconclusive(self):
        observed = ber_observed()
        observed["opentlv.encode"]["encode"] = {"status": "failed", "detail": "x"}
        del observed["interop.asn1c"]
        _, checks = self.evaluate(fixture(), observed)
        self.assertEqual(checks["interop.opentlv-to-asn1c"]["outcome"], "inconclusive")
        self.assertEqual(checks["opentlv.encode"]["outcome"], "mismatch")


class ComparisonTests(unittest.TestCase):
    """The comparison with stand-in adapters: requests, cross inputs and the report."""

    def setUp(self):
        self.types = interop.der.load_types()
        self.receipts = {"paths": {"lua": "/lua/provenance.json", "asn1c": "/asn1c/provenance.json"},
                         "runtime": "Lua 5.2.4", "platform": {"system": "Linux"}, "compiler": "gcc 13",
                         "packages": {"opentlv": {"version": "0.3.0"},
                                      "asn1c": {"version": "0.9.29", "schema": "TestLabReference-1"}}}
        self.opentlv_requests, self.asn1c_requests = [], []

    def opentlv(self, _, requests, reproduction=None):
        self.opentlv_requests.append(requests)
        records = []
        for request in requests:
            wire = BER_PAIR if request["encoding"] == "cer" else DER_PAIR
            if request["operation"] == "encode":
                records.append({"id": request["id"], "encode": {"status": "encoded", "wire": wire}})
            elif request["wire"] == "30060101ff020105" and request["encoding"] == "cer":
                records.append({"id": request["id"], "status": "rejected", "error": "invalid", "source": "opentlv"})
            else:
                records.append({"id": request["id"], **opentlv_accepted(wire=wire)})
        return records

    def asn1c(self, _, requests):
        self.asn1c_requests.append(requests)
        records = []
        for request in requests:
            encode = {"none": None, "der": {"syntax": "der", "status": "encoded", "wire": DER_PAIR},
                      "cer": {"syntax": "cer", "status": "unsupported"}}[request["encode"]]
            record = {"id": request["id"], "type": request["type"], **asn1c_record()}
            if encode is None:
                del record["encode"]
            else:
                record["encode"] = encode
            records.append(record)
        return records

    def compare(self, fixtures):
        with patch.object(interop, "run_opentlv", side_effect=self.opentlv), \
                patch.object(interop, "run_asn1c", side_effect=self.asn1c):
            return interop.run_comparison(fixtures, self.types, self.receipts)

    def test_each_library_decodes_encodes_and_reads_the_other(self):
        report = self.compare([fixture(), fixture("cer-pair", "cer", BER_PAIR), rejection()])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["runner"], "run_ber_cer_differential.py")
        first, cross = self.opentlv_requests
        self.assertEqual([(r["id"], r["operation"], r["encoding"]) for r in first],
                         [("pair", "decode", "ber"), ("cer-pair", "decode", "cer"), ("definite", "decode", "cer"),
                          ("pair/encode", "encode", "ber"), ("cer-pair/encode", "encode", "cer")])
        # asn1c re-encodes only BER as DER, so only BER fixtures cross back to OpenTLV.
        self.assertEqual([(r["id"], r["encoding"], r["wire"]) for r in cross], [("pair/from-asn1c", "ber", DER_PAIR)])
        self.assertEqual([(r["id"], r["encode"]) for r in self.asn1c_requests[0]],
                         [("pair", "der"), ("cer-pair", "cer"), ("definite", "cer")])
        self.assertEqual([(r["id"], r["wire"], r["encode"]) for r in self.asn1c_requests[1]],
                         [("pair", DER_PAIR, "none"), ("cer-pair", BER_PAIR, "none")])
        summary = report["summary"]
        self.assertEqual(summary["encodings"], {"ber": {"accept": 1, "reject": 0},
                                                "cer": {"canonical": 1, "reject": 1}})
        self.assertEqual(summary["checks"]["cer"]["asn1c.decode"]["not-comparable"], 1)
        self.assertEqual(summary["outcomes"]["applies"], 6 + 7 + 2)
        self.assertEqual(summary["outcomes"]["judged"], 6 + 5 + 1)

    def test_reports_keep_findings_coverage_matrix_and_reproduction(self):
        report = self.compare([fixture(), rejection(encoding="ber", wire="30 80 01 01 ff", error="truncated")])
        origin = {"corpus": "differential/fixtures/ber-cer-interop.json", "corpus_sha256": "abc",
                  "testlab": {"commit": "abc123", "modified": False}}
        interop.add_reproduction(report, origin, [])
        self.assertEqual(report["status"], "mismatch")
        self.assertEqual(report["fixtures"][1]["reproduce"][-1],
                         "python3 scripts/run_ber_cer_differential.py --fixtures "
                         "differential/fixtures/ber-cer-interop.json --fixture definite")
        text = interop.render_report(report)
        for section in ("## Mismatches: possible defects", "## Coverage", "## Outcome matrix", "### BER",
                        "| definite | reject truncated | **MISMATCH** | — | **MISMATCH** |", "OpenTLV accepted it",
                        "| ber | `opentlv.decode` | 2 | 2 (100.0%) | 1 | 1 |"):
            self.assertIn(section, text)

    def test_reports_list_declarations_and_confirmed_bugs(self):
        report = self.compare([rejection(), rejection("other", wire="30 80 01 01 ff", error="truncated",
                                                      confirmed={"opentlv.decode": ISSUE},
                                                      not_comparable={"asn1c.decode": "x"})])
        interop.add_reproduction(report, {"corpus": "c.json", "corpus_sha256": "abc",
                                          "testlab": {"commit": None, "modified": True}}, [])
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["summary"]["confirmed"], 1)
        text = interop.render_report(report)
        self.assertIn("## Bugs: confirmed mismatches", text)
        self.assertIn(f"`opentlv.decode` ({ISSUE})", text)
        self.assertIn("## Limitations and not-comparable cases: not defects", text)
        self.assertIn("| definite | not comparable | `asn1c.decode` | asn1c accepted it |", text)
        self.assertIn("uncommitted changes", text)


class CommandTests(unittest.TestCase):
    def run_main(self, mismatch=0, error=None):
        report = {"schema": 1, "status": "passed", "fixtures": [], "summary": {"mismatch": mismatch}}
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(interop, "load_receipts", side_effect=error, return_value={}), \
                patch.object(interop.lua_runner, "newest_receipt", return_value=Path("/lua.json")), \
                patch.object(interop.check_asn1c, "newest_receipt", return_value=Path("/asn1c.json")), \
                patch.object(interop, "run_comparison", return_value=report), \
                patch.object(interop, "print_report"), redirect_stderr(io.StringIO()) as stderr:
            output = Path(temp) / "report.json"
            status = interop.main(["--fixture", "ber-null", "--output", str(output)])
            return status, json.loads(output.read_text(encoding="utf-8")), stderr.getvalue()

    def test_exit_codes_separate_mismatches_from_run_failures(self):
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.run_main(1)[0], interop.MISMATCH_EXIT)
        status, report, stderr = self.run_main(error=ValueError("Receipt uses a different asn1c pin"))
        self.assertEqual((status, report["status"], report["runner"]), (1, "failed", "run_ber_cer_differential.py"))
        self.assertIn("different asn1c pin", stderr)
        self.assertEqual(report["reproduce"][-1].split()[-2:], ["--fixture", "ber-null"])

    def test_unknown_fixture_is_a_run_failure(self):
        with redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()):
            self.assertEqual(interop.main(["--fixture", "missing"]), 1)
        self.assertIn("Unknown fixture: missing", stderr.getvalue())

    def test_mismatch_probe_is_a_real_library_difference(self):
        probe = interop.load_corpus(ROOT / "tests/fixtures/ber_cer_mismatch.json")["fixtures"]
        committed = {f["id"]: f for f in interop.load_corpus(interop.DEFAULT_FIXTURES)["fixtures"]}
        self.assertEqual(len(probe), 1)
        original = committed["ber-boolean-true-01"]
        self.assertEqual((probe[0]["wire"], probe[0]["expected"]), (original["wire"], original["expected"]))
        self.assertNotIn("limitations", probe[0])
        self.assertEqual(original["limitations"].keys(), {"opentlv.decode"})

    def test_fast_runs_the_corpus_and_the_probe(self):
        text = (ROOT / ".github/workflows/fast.yml").read_text(encoding="utf-8")
        for command in ("scripts/run_ber_cer_differential.py", "tests/fixtures/ber_cer_mismatch.json",
                        "build/ber-cer-reports/mismatch-probe.json", "ber-cer-differential-reports"):
            self.assertIn(command, text)


class ReportCheckTests(unittest.TestCase):
    def test_runner_is_chosen_by_name_when_packages_are_shared(self):
        self.assertEqual(check_report.runner_of({"packages": {"opentlv": {}, "asn1c": {}},
                                                 "runner": "run_ber_cer_differential.py"})[0],
                         "run_ber_cer_differential.py")
        self.assertEqual(check_report.runner_of({"packages": {"opentlv": {}, "asn1c": {}}})[0],
                         "run_der_differential.py")

    def test_mismatch_is_rerun_with_both_receipts(self):
        result = {"id": "probe", "outcome": "mismatch", "wire": "010101", "encoding": "ber", "type": "Flag",
                  "rule": "X.690 8.2.2", "expected": {"result": "accept"}, "checks": {"opentlv.decode": {}},
                  "observed": {"opentlv": {}, "asn1c": {}},
                  "reproduce": [*interop.SETUP_COMMANDS, "python3 scripts/run_ber_cer_differential.py --fixture probe"]}
        report = {"status": "mismatch", "runner": "run_ber_cer_differential.py", "runtime": "Lua 5.2.4",
                  "fixtures": [result], "provenance": {"lua": "/lua.json", "asn1c": "/asn1c.json"},
                  "packages": {"opentlv": {"version": "0.3.0"}, "asn1c": {"version": "0.9.29"}}}
        commands = []

        def fake_run(command, **_):
            commands.append(command)
            Path(command[command.index("--output") + 1]).write_text(json.dumps({"fixtures": [result]}),
                                                                   encoding="utf-8")
            return Mock(returncode=interop.MISMATCH_EXIT)

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(check_report.subprocess, "run", side_effect=fake_run):
                self.assertEqual(check_report.check_report(path), 1)
            self.assertEqual(commands[0][4:8], ["--lua-provenance", "/lua.json", "--asn1c-provenance", "/asn1c.json"])
            result["reproduce"][-1] = "python3 scripts/run_der_differential.py --fixture probe"
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "another script"):
                check_report.check_report(path)


if __name__ == "__main__":
    unittest.main()
