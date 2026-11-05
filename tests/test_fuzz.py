# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_ber_cer_differential as interop, run_der_differential as der, run_fuzz as fuzz
from scripts import setup_asn1c as asn1c, x690

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/differential-fuzzing.md"
TYPES = der.load_types()
TRUE = {"kind": "boolean", "value": True}
FIVE = {"kind": "integer", "value": "5"}
ASN1C_ERRORS = {"empty": "empty", "truncated": "truncated", "trailing": "trailing", "invalid": "malformed"}


def decode_case(type_name, wire, encoding, identifier="case"):
    return {"id": identifier, "strategy": "mutation", "index": 0, "type": type_name, "operation": "decode",
            "encoding": encoding, "wire": bytes.fromhex(wire).hex()}


def encode_case(type_name, value, encoding):
    return {"id": "case", "strategy": "value", "index": 0, "type": type_name, "operation": "encode",
            "encoding": encoding, "value": value}


def accepted(value, wire=None, source=None):
    record = {"status": "accepted", "value": value}
    if wire is not None:
        record["encode"] = {"status": "encoded", "wire": wire}
    return record


def rejected(error="invalid", source="opentlv"):
    return {"status": "rejected", "error": error, "source": source, "detail": "stand-in"}


def asn1c_record(value=None, error=None, wire=None):
    if error:
        return {"decode": {"syntax": "ber", "status": "rejected", "error": error}}
    return {"decode": {"syntax": "ber", "status": "accepted", "value": value},
            "encode": {"syntax": "der", "status": "encoded", "wire": wire}}


def judge(type_name, wire, encoding, opentlv=None, asn1c_result=None):
    return fuzz.judge_case(decode_case(type_name, wire, encoding), TYPES[type_name], opentlv, asn1c_result)[1]


# --- Stand-in libraries ------------------------------------------------------------------------

def canonical_or_der(schema, value, encoding):
    return fuzz.canonical_encode(schema, value, "der" if encoding == "ber" else encoding).hex()


def perfect_opentlv(context, requests, rules=None):
    """A decoder and encoder that implement X.690 exactly; `rules` replaces the rules it decodes with."""
    records = []
    for request in requests:
        schema, encoding = request["schema"], request["encoding"]
        if request["operation"] == "encode":
            records.append({"id": request["id"], "encode": {"status": "encoded",
                                                            "wire": canonical_or_der(schema, request["value"],
                                                                                     encoding)}})
            continue
        try:
            value = x690.decode(schema, bytes.fromhex(request["wire"]), (rules or {}).get(encoding, encoding))
        except x690.Invalid as error:
            records.append({"id": request["id"], "status": "rejected", "error": error.error, "source": "opentlv"})
            continue
        records.append({"id": request["id"], "status": "accepted", "value": value,
                        "encode": {"status": "encoded", "wire": canonical_or_der(schema, value, encoding)}})
    return records


def lenient_opentlv(context, requests):
    """A defect: DER is decoded with BER's length forms."""
    return perfect_opentlv(context, requests, {"der": x690.Rules("ber", True, True, True)})


def perfect_asn1c(context, requests):
    """A BER decoder with a DER encoder, as asn1c is, but without its deviations."""
    records = []
    for request in requests:
        try:
            value = x690.decode(TYPES[request["type"]], bytes.fromhex(request["wire"]), "ber")
        except x690.Invalid as error:
            records.append({"id": request["id"], **asn1c_record(error=ASN1C_ERRORS[error.error])})
            continue
        records.append({"id": request["id"], **asn1c_record(value, wire=der.der_encode(TYPES[request["type"]],
                                                                                        value).hex())})
    return records


def context(seed=1):
    return {"seed": seed, "types": TYPES, "receipts": None, "pool": fuzz.seed_pool(), "timeout": 5,
            "packages": {"opentlv": {"version": "0.3.0"}, "asn1c": {"version": "0.9.29"}}, "runtime": "Lua 5.2",
            "platform": {"system": "Linux"}, "compiler": "cc", "sanitizers": ["address", "undefined"],
            "provenance": {"lua": "lua.json", "asn1c": "asn1c.json"}, "testlab": {"commit": None, "modified": False},
            "seed_corpora": {}}


class ReferenceProfileTests(unittest.TestCase):
    """The DER profile and the partial profiles the fuzzer models OpenTLV Lua with."""

    def decode(self, type_name, wire, rules):
        return x690.decode(TYPES[type_name], bytes.fromhex(wire), rules)

    def error(self, type_name, wire, rules):
        with self.assertRaises(x690.Invalid) as raised:
            self.decode(type_name, wire, rules)
        return raised.exception

    def test_der_profile_agrees_with_every_der_fixture(self):
        for fixture in der.load_corpus(der.DEFAULT_FIXTURES)["fixtures"]:
            with self.subTest(fixture=fixture["id"]):
                expected = fixture["expected"]
                if expected["result"] == "canonical":
                    self.assertEqual(self.decode(fixture["type"], fixture["wire"], "der"), expected["value"])
                else:
                    self.assertEqual(self.error(fixture["type"], fixture["wire"], "der").error, expected["error"])

    def test_der_forbids_what_ber_allows(self):
        for type_name, wire in [("Pair", "30 80 01 01 ff 02 01 05 00 00"), ("Octets", "04 81 01 41"),
                                ("Octets", "24 03 04 01 41"), ("Flag", "01 01 01"), ("Bits", "03 02 04 f1"),
                                ("DefaultFlag", "30 06 01 01 00 02 01 05"), ("TaggedSet", "31 06 81 01 ff 80 01 05"),
                                ("NumberSet", "31 06 02 01 05 02 01 01")]:
            with self.subTest(wire=wire):
                self.assertEqual(self.error(type_name, wire, "der").error, "invalid")
                self.decode(type_name, wire, "ber")

    def test_partial_profiles_model_opentlv_lua(self):
        model = fuzz.OPENTLV_MODEL
        self.assertIn("11.1", self.error("Flag", "01 01 01", model["ber"]).detail)
        self.assertEqual(self.decode("Octets", "24 80 04 01 41 00 00", model["ber"])["value"], "41")
        cer_unsorted = "31 80 02 01 05 02 01 01 00 00"
        self.assertIn("11.6", self.error("NumberSet", cer_unsorted, "cer").detail)
        self.assertEqual(len(self.decode("NumberSet", cer_unsorted, model["cer"])["items"]), 2)
        self.assertEqual(self.error("Pair", "30 06 01 01 ff 02 01 05", model["cer"]).error, "invalid")
        self.assertEqual(len(self.decode("NumberSet", "31 06 02 01 05 02 01 01", model["der"])["items"]), 2)
        self.assertEqual(self.error("Octets", "04 81 01 41", model["der"]).error, "invalid")

    def test_object_identifier_errors_name_their_cause(self):
        self.assertIn("without contents", self.error("Identifier", "06 00", "ber").detail)
        self.assertIn("unterminated", self.error("Identifier", "06 02 2a 83", "ber").detail)

    def test_command_checks_der(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(x690.main(["Flag", "01 01 ff", "--encoding", "der"]), 0)
            self.assertEqual(x690.main(["Flag", "01 01 01", "--encoding", "der"]), 1)
        accepted_line, rejected_line = map(json.loads, output.getvalue().splitlines())
        self.assertEqual(accepted_line, {"result": "canonical", "value": TRUE})
        self.assertEqual(rejected_line["error"], "invalid")


class GenerationTests(unittest.TestCase):
    def test_rng_is_pinned_and_independent_of_python(self):
        rng = fuzz.Rng(1, "value", 0)
        self.assertEqual([rng.next() for _ in range(3)],
                         [8420925944675192703, 5348028085091327561, 138608486151878201])
        rng = fuzz.Rng(7, "mutation", 3)
        self.assertEqual([rng.below(10) for _ in range(10)], [5, 1, 2, 7, 6, 9, 0, 1, 2, 0])

    def test_cases_are_reproducible_alone(self):
        pool = fuzz.seed_pool()
        self.assertEqual(fuzz.value_cases(1, 12, TYPES), fuzz.value_cases(1, 12, TYPES))
        self.assertEqual(fuzz.mutation_case(1, 12, TYPES, pool), fuzz.mutation_case(1, 12, TYPES, pool))
        self.assertNotEqual(fuzz.value_cases(1, 12, TYPES), fuzz.value_cases(2, 12, TYPES))

    def test_generated_values_stay_in_the_intersection_and_decode_back(self):
        forms = set()
        for index in range(300):
            cases = fuzz.value_cases(5, index, TYPES)
            value = cases[0]["value"]
            schema = TYPES[cases[0]["type"]]
            self.assertFalse(fuzz.beyond_int64(value))
            self.assertTrue(all(max(arcs) <= fuzz.OID_ARC_MAX and len(arcs) <= 9 for arcs in fuzz.oid_arcs(value)))
            self.assertEqual({c["operation"] for c in cases}, {"encode", "decode"})
            self.assertEqual(len(cases), 3 + 9)
            for case in cases[3:]:
                wire = bytes.fromhex(case["wire"])
                self.assertLessEqual(len(wire), fuzz.MAX_WIRE)
                form = case["id"].rsplit("-decode-", 1)[1].split("-as-")[0]
                if form == case["encoding"] or case["encoding"] == "ber":
                    self.assertEqual(fuzz.logical(x690.decode(schema, wire, case["encoding"])),
                                     fuzz.logical(value))
                if form == "ber":
                    forms.add(wire != der.der_encode(schema, value))
        self.assertEqual(forms, {True, False})

    def test_ber_forms_cover_the_alternatives(self):
        rng, found = fuzz.Rng("forms"), set()
        for _ in range(400):
            name, value, encodings = fuzz.generate_value(TYPES, rng)
            wire = encodings["ber"]
            for element in fuzz.elements(wire):
                header = element.encoding[len(element.identifier)]
                found.add("indefinite" if header == 0x80 else "long" if header & 0x80 and
                          (header != 0x81 or element.encoding[len(element.identifier) + 1] < 0x80) else None)
                if element.constructed and element.identifier[0] & 0x1F in (3, 4):
                    found.add("segmented")
        self.assertLessEqual({"indefinite", "long", "segmented"}, found)

    def test_canonical_serialization_reproduces_the_seed(self):
        for type_name, wire, encoding in [("Nested", "30 0d 04 01 41 30 08 30 06 01 01 ff 02 01 05", "der"),
                                          ("Pair", "30 80 01 01 ff 02 01 05 00 00", "cer")]:
            data = bytes.fromhex(wire)
            self.assertEqual(fuzz.serialize(x690.parse(data, "ber"), encoding, {}), data)

    def test_mutations_are_bounded_and_named(self):
        pool, operations = fuzz.seed_pool(), set()
        for index in range(400):
            case = fuzz.mutation_case(3, index, TYPES, pool)
            self.assertLessEqual(len(case["wire"]) // 2, fuzz.MAX_WIRE)
            self.assertIn(case["type"], TYPES)
            operations.update(case["mutations"])
        self.assertLessEqual({"tree:contents", "tree:form", "tree:segment", "flip", "truncate", "indefinite"},
                             operations)

    def test_literal_encoding_keeps_defaults_and_order(self):
        default = {"kind": "sequence", "fields": [{"name": "flag", "value": {"kind": "boolean", "value": False}},
                                                  {"name": "count", "value": FIVE}]}
        self.assertEqual(der.der_encode(TYPES["DefaultFlag"], default).hex(), "3003020105")
        self.assertEqual(fuzz.literal_encode(TYPES["DefaultFlag"], default, "der", False).hex(), "3006010100020105")
        items = {"kind": "set_of", "items": [FIVE, {"kind": "integer", "value": "1"}]}
        self.assertEqual(fuzz.literal_encode(TYPES["NumberSet"], items, "cer", False).hex(), "3180020105020101" "0000")
        self.assertEqual(fuzz.literal_encode(TYPES["NumberSet"], items, "cer", True).hex(), "3180020101020105" "0000")


class OpenTLVJudgementTests(unittest.TestCase):
    def outcome(self, checks, name="opentlv.decode"):
        return checks[name]["outcome"], checks[name].get("rule")

    def test_agreement_passes_and_round_trips(self):
        checks = judge("Pair", "30 06 01 01 ff 02 01 05", "der", accepted(
            {"kind": "sequence", "fields": [{"name": "flag", "value": TRUE}, {"name": "count", "value": FIVE}]},
            "30060101ff020105"))
        self.assertEqual(self.outcome(checks), ("pass", None))
        self.assertEqual(self.outcome(checks, "opentlv.round-trip"), ("pass", None))

    def test_documented_limitations_are_explained(self):
        cases = [("Flag", "01 01 01", "ber", rejected(), "opentlv-contents"),
                 ("NumberSet", "31 80 02 01 05 02 01 01 00 00", "cer",
                  accepted({"kind": "set_of", "items": [FIVE, {"kind": "integer", "value": "1"}]}), "opentlv-schema"),
                 ("Octets", "24 80 04 01 41 00 00", "cer", accepted({"kind": "octet_string", "value": "41"}),
                  "opentlv-strings"),
                 ("Number", "02 09 01 00 00 00 00 00 00 00 00", "ber", rejected(), "opentlv-int64"),
                 ("Identifier", "06 21 2a" + " 01" * 32, "ber", rejected(), "opentlv-oid"),
                 ("Pair", "30 03 02 01 05", "ber", rejected(source="adapter"), "opentlv-adapter"),
                 ("Pair", "30 80 01 01 ff 02 01 05", "ber", rejected("invalid"), "error-category"),
                 ("Pair", "30 06 01 01 ff 02 01 05 00", "ber",
                  {"status": "error", "detail": "attempt to index a nil value"}, None)]
        for type_name, wire, encoding, verdict, rule in cases:
            with self.subTest(wire=wire):
                outcome, found = self.outcome(judge(type_name, wire, encoding, verdict))
                if rule is None:
                    self.assertEqual(outcome, "crash")
                else:
                    self.assertEqual(found, rule)
                    self.assertEqual(outcome, fuzz.EXPLANATIONS[rule][0])

    def test_unexplained_differences_are_findings(self):
        long_form = judge("Octets", "04 81 01 41", "der", accepted({"kind": "octet_string", "value": "41"}))
        self.assertEqual(self.outcome(long_form), ("canonical-mismatch", None))
        invalid_ber = judge("Number", "02 02 00 05", "ber", accepted(FIVE))
        self.assertEqual(self.outcome(invalid_ber), ("semantic-mismatch", None))
        valid_rejected = judge("Number", "02 01 05", "cer", rejected())
        self.assertEqual(self.outcome(valid_rejected), ("semantic-mismatch", None))
        by_adapter = judge("Number", "02 01 05", "ber", rejected(source="adapter"))
        self.assertIn("only the TestLab adapter", by_adapter["opentlv.decode"]["difference"])
        other_value = judge("Number", "02 01 05", "ber", accepted({"kind": "integer", "value": "6"}))
        self.assertEqual(self.outcome(other_value), ("semantic-mismatch", None))
        crash = judge("Number", "02 01 05", "ber", {"status": "sanitizer", "detail": "heap-buffer-overflow"})
        self.assertEqual(self.outcome(crash), ("sanitizer", None))

    def test_depth_limit_is_a_limitation_only_for_rejected_input(self):
        deep = "30 80" * 40 + "00 00" * 40
        error = {"status": "error", "detail": "opentlv: resource limit exceeded (LIMIT)"}
        self.assertEqual(self.outcome(judge("Pair", deep, "ber", error)), ("limitation", "opentlv-depth"))

    def test_encoders_are_judged_by_bytes_or_value(self):
        schema = TYPES["DefaultFlag"]
        value = {"kind": "sequence", "fields": [{"name": "flag", "value": {"kind": "boolean", "value": False}},
                                                {"name": "count", "value": FIVE}]}
        judged = [fuzz.judge_encoding(schema, value, encoding, {"status": "encoded", "wire": wire}, "OpenTLV")
                  for encoding, wire in [("der", "3003020105"), ("der", "3006010100020105"), ("der", "308103020105"),
                                         ("der", "3003020106"), ("ber", "3080020105" "0000"),
                                         ("cer", "3080010100020105" "0000")]]
        self.assertEqual([j["outcome"] for j in judged], ["pass", "limitation", "canonical-mismatch",
                                                          "semantic-mismatch", "pass", "limitation"])
        self.assertEqual(judged[1]["rule"], "opentlv-writer")
        big = {"kind": "integer", "value": str(2 ** 64)}
        self.assertEqual(fuzz.judge_encoding(TYPES["Number"], big, "der", {"status": "unsupported"}, "OpenTLV")["rule"],
                         "opentlv-int64")
        self.assertEqual(fuzz.judge_encoding(TYPES["Number"], big, "der", {"status": "unsupported"}, "asn1c")["outcome"],
                         "semantic-mismatch")

    def test_round_trip_must_return_canonical_input(self):
        checks = judge("Number", "02 01 05", "der", accepted(FIVE, "020106"))
        self.assertEqual(self.outcome(checks, "opentlv.round-trip"), ("semantic-mismatch", None))
        checks = judge("Number", "02 01 05", "ber", accepted(FIVE, "02810105"))
        self.assertEqual(self.outcome(checks, "opentlv.round-trip"), ("pass", None))


class Asn1cJudgementTests(unittest.TestCase):
    def outcome(self, type_name, wire, encoding, record):
        result = judge(type_name, wire, encoding, asn1c_result=record)["asn1c.decode"]
        return result["outcome"], result.get("rule")

    def test_probe_explanations_need_the_probed_shape(self):
        cases = [("Number", "02 00", "ber", asn1c_record({"kind": "integer", "value": None}, wire="0200"),
                  "asn1c:ber-integer-empty"),
                 ("Text", "36 80 04 01 41 00 00", "ber", asn1c_record(error="malformed"),
                  fuzz.SEGMENT_LIMITATION),
                 ("Explicit5", "a5 80 02 01 05 00 00", "ber", asn1c_record(error="malformed"),
                  fuzz.EXPLICIT_LIMITATION),
                 ("Octets", "24 80 04 01 41 00 00", "cer", asn1c_record({"kind": "octet_string", "value": "41"},
                                                                        wire="040141"), "asn1c-cer"),
                 ("Identifier", "06 06 2a 90 80 80 80 00", "ber",
                  asn1c_record({"kind": "object_identifier", "value": "1.2.0"}, wire="06062a9080808000"),
                  "asn1c:ber-oid-arc-above-32-bits"),
                 ("Text", "36 03 16 01 41", "ber", asn1c_record({"kind": "ia5string", "value": "41"}, wire="160141"),
                  "asn1c:ber-constructed-segment-own-tag"),
                 ("Bits", "23 80 00 00", "ber", asn1c_record(error="constraint"), fuzz.EMPTY_BITS_LIMITATION),
                 ("Bits", "23 06 03 02 00 ff 03 00", "ber",
                  asn1c_record({"kind": "bit_string", "unused_bits": 0, "value": "ff"}, wire="030200ff"),
                  "asn1c:ber-bit-string-segment-no-initial-octet")]
        for type_name, wire, encoding, record, rule in cases:
            with self.subTest(rule=rule):
                self.assertEqual(self.outcome(type_name, wire, encoding, record), (fuzz.EXPLANATIONS[rule][0], rule))

    def test_other_differences_are_findings(self):
        self.assertEqual(self.outcome("Octets", "24 80 04 01 41 00 00", "ber", asn1c_record(error="malformed")),
                         ("semantic-mismatch", None))
        self.assertEqual(self.outcome("Text", "36 03 02 01 41", "ber", asn1c_record({"kind": "ia5string",
                                                                                      "value": "41"}, wire="160141")),
                         ("semantic-mismatch", None))
        reencoded = asn1c_record({"kind": "octet_string", "value": "41"}, wire="04810141")
        self.assertEqual(self.outcome("Octets", "04 81 01 41", "der", reencoded), ("canonical-mismatch", None))
        undecided = {"decode": {"status": "accepted", "value": FIVE}, "encode": {"status": "failed"}}
        self.assertEqual(self.outcome("Number", "02 01 05", "der", undecided), ("inconclusive", "asn1c-reencoding"))

    def test_round_trip_reads_the_der_reencoding(self):
        record = asn1c_record({"kind": "octet_string", "value": "41"}, wire="04810141")
        checks = judge("Octets", "24 80 04 01 41 00 00", "ber", asn1c_result=record)
        self.assertEqual(checks["asn1c.round-trip"]["outcome"], "canonical-mismatch")

    def test_every_cited_probe_exists_with_its_classification(self):
        probes = {p["id"]: p["classification"] for p in asn1c.load_capabilities()["probes"]}
        expected = {"not-comparable": "not-comparable", "limitation": "unsupported"}
        for rule, (outcome, reason) in fuzz.EXPLANATIONS.items():
            for probe in re.findall(r"capability probes? ([\w-]+(?:, [\w-]+)*)", reason):
                for name in probe.split(", "):
                    with self.subTest(rule=rule, probe=name):
                        self.assertIn(name, probes)
                        if rule.startswith("asn1c:"):
                            self.assertEqual(probes[name], expected[outcome])


class ProcessTests(unittest.TestCase):
    def run_script(self, code, ids=("a", "b"), timeout=20):
        command = [sys.executable, "-c", code]
        return fuzz.run_once(command, dict(os.environ), "", list(ids), lambda identity: None, timeout)

    def test_records_and_anomalies_are_parsed(self):
        lines = 'print("{}"); print(\'{"id": "a"}\'); print(\'{"id": "b"}\')'
        records, anomaly = self.run_script(lines)
        self.assertEqual(([r["id"] for r in records], anomaly), (["a", "b"], None))
        records, anomaly = self.run_script('import sys; print("{}"); print(\'{"id": "a"}\'); sys.exit(139)')
        self.assertEqual((len(records), anomaly["status"]), (1, "crash"))
        code = ('import sys; print("{}"); print(\'{"id": "a"}\'); print(\'{"id": "b"}\'); '
                'sys.stderr.write("==7==ERROR: LeakSanitizer: detected memory leaks\\n"); sys.exit(1)')
        records, anomaly = self.run_script(code)
        self.assertEqual((len(records), anomaly["status"], anomaly["detail"]),
                         (2, "sanitizer", "ERROR: LeakSanitizer: detected memory leaks"))
        records, anomaly = self.run_script('import time; print("{}", flush=True); time.sleep(10)', timeout=1)
        self.assertEqual((records, anomaly["status"]), ([], "timeout"))

    def test_isolation_attributes_each_anomaly_to_one_request(self):
        requests = [{"id": str(i)} for i in range(8)]
        calls = []

        def run(batch):
            calls.append([r["id"] for r in batch])
            ids = [r["id"] for r in batch]
            if "3" in ids:  # A crash stops the process at request 3.
                done = ids.index("3")
                return [{"id": i} for i in ids[:done]], {"status": "crash", "detail": "signal 11"}
            if "6" in ids:  # A leak is reported only after the last result.
                return [{"id": i} for i in ids], {"status": "sanitizer", "detail": "leak"}
            return [{"id": i} for i in ids], None
        results = fuzz.isolate(run, requests)
        self.assertEqual([r.get("status") for r in results],
                         [None, None, None, "crash", None, None, "sanitizer", None])
        self.assertEqual(calls[0], [str(i) for i in range(8)])
        self.assertIn(["3"], calls)

    def test_sanitizer_reports_lose_volatile_details(self):
        stderr = "==4242==ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer: " \
                 "heap-buffer-overflow /home/user/x/generated/ber_decoder.c:123:4 in ber_check_tags\n"
        self.assertEqual(fuzz.sanitizer_report(stderr),
                         "SUMMARY: AddressSanitizer: heap-buffer-overflow ber_decoder.c in ber_check_tags")
        self.assertIsNone(fuzz.sanitizer_report("asn1c adapter: wire is not lowercase hex"))


class MinimizationTests(unittest.TestCase):
    def fake_evaluate(self, predicate):
        def evaluate(context, cases, libraries=("opentlv", "asn1c")):
            results = []
            for case in cases:
                found = predicate(case)
                checks = {"opentlv.decode": {"outcome": "semantic-mismatch" if found else "pass",
                                             "difference": "stand-in"}}
                views = {"x690": {"status": "rejected", "detail": "stand-in"}} if case["operation"] == "decode" \
                    else None
                results.append({"views": views, "checks": checks, "observed": {}})
            return results
        return evaluate

    def test_bytes_shrink_to_what_keeps_the_bucket(self):
        case = decode_case("Octets", "30 80 aa bb cc 01 01 01 dd ee 00 00", "ber")
        key = fuzz.bucket(case, "opentlv.decode", {"outcome": "semantic-mismatch"},
                          {"x690": {"status": "rejected", "detail": "stand-in"}})
        with patch.object(fuzz, "evaluate", self.fake_evaluate(lambda c: "010101" in c["wire"])):
            self.assertEqual(fuzz.shrink_bytes({}, case, "opentlv.decode", key, 48)["wire"], "010101")

    def test_values_shrink_while_the_finding_remains(self):
        value = {"kind": "sequence_of", "items": [{"kind": "integer", "value": str(n)} for n in (7, 300, -9, 42)]}
        case = encode_case("NumberList", value, "der")
        key = fuzz.bucket(case, "opentlv.decode", {"outcome": "semantic-mismatch"}, None)
        found = lambda c: any(item["value"] == "300" for item in c["value"]["items"])  # noqa: E731
        with patch.object(fuzz, "evaluate", self.fake_evaluate(found)):
            shrunk = fuzz.shrink_value({"types": TYPES}, case, "opentlv.decode", key, 48)
        self.assertEqual(shrunk["value"], {"kind": "sequence_of", "items": [{"kind": "integer", "value": "300"}]})

    def test_fixture_drafts_join_the_corpus_of_their_encoding(self):
        draft = fuzz.fixture_draft("abc", decode_case("Flag", "01 01 01", "der"),
                                   fuzz.reference_views(TYPES["Flag"], decode_case("Flag", "01 01 01", "der")), TYPES)
        self.assertEqual((draft["valid"], draft["corpus"]), (True, "differential/fixtures/der-canonical.json"))
        self.assertEqual(draft["fixture"]["expected"], {"result": "reject", "error": "invalid"})
        draft = fuzz.fixture_draft("abc", encode_case("Flag", TRUE, "cer"), None, TYPES)
        self.assertEqual((draft["valid"], draft["fixture"]["encoding"], draft["fixture"]["wire"]),
                         (True, "cer", "0101ff"))
        interop.validate_fixture(draft["fixture"], TYPES)


class RunTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        environment = patch.dict(os.environ, {"GITHUB_ACTIONS": "false"})
        environment.start()
        self.addCleanup(environment.stop)

    def main(self, *arguments, opentlv=perfect_opentlv):
        output = io.StringIO()
        with patch.object(fuzz, "load_context", lambda args: context(args.seed)), \
                patch.object(fuzz, "run_opentlv", opentlv), patch.object(fuzz, "run_asn1c", perfect_asn1c), \
                redirect_stdout(output), redirect_stderr(output):
            return fuzz.main(list(arguments)), output.getvalue()

    def test_a_correct_implementation_gives_no_finding_and_repeats_exactly(self):
        for name in ("one", "two"):
            status, _ = self.main("--iterations", "40", "--batch-size", "15", "--output-dir", str(self.directory / name))
            self.assertEqual(status, 0)
        one, two = ((self.directory / name / "summary.json").read_text(encoding="utf-8") for name in ("one", "two"))
        self.assertEqual(one, two)
        summary = json.loads(one)
        self.assertEqual((summary["status"], summary["findings"], summary["cases"]),
                         ("passed", [], {"value": 40 * 12, "mutation": 40}))
        self.assertTrue(all(e["outcome"] in ("limitation", "not-comparable", "inconclusive")
                            for e in summary["explained"]))
        self.assertIn("Local and private", (self.directory / "one/summary.md").read_text(encoding="utf-8"))

    def test_a_defect_gives_minimized_replayable_findings(self):
        status, output = self.main("--iterations", "30", "--strategy", "value", "--output-dir",
                                   str(self.directory / "run"), opentlv=lenient_opentlv)
        self.assertEqual(status, fuzz.FINDING_EXIT)
        summary = json.loads((self.directory / "run/summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["findings"])
        self.assertTrue(all(f["outcome"] == "canonical-mismatch" and f["check"] == "opentlv.decode"
                            for f in summary["findings"]))
        path = next((self.directory / "run/findings").glob("*.json"))
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((record["triage"], record["minimized"]["stable"]), ("untriaged", True))
        self.assertLessEqual(len(record["minimized"]["case"]["wire"]), len(record["first"]["case"]["wire"]))
        self.assertTrue(record["minimized"]["confirm"].startswith("python3 scripts/x690.py "))
        self.assertTrue(record["fixture_draft"]["valid"])
        self.assertIn("--start", record["first"]["reproduce"][-1])
        self.assertEqual(self.main("--replay", str(path), opentlv=lenient_opentlv)[0], fuzz.FINDING_EXIT)
        self.assertEqual(self.main("--replay", str(path))[0], 0)

    def test_output_never_lands_in_the_tracked_tree(self):
        status, output = self.main("--output-dir", str(ROOT / "differential/fuzz"))
        self.assertEqual(status, 1)
        self.assertIn("tracked tree", output)
        (self.directory / "used").mkdir()
        (self.directory / "used/x").write_text("", encoding="utf-8")
        self.assertEqual(self.main("--output-dir", str(self.directory / "used"))[0], 1)

    def test_public_ci_is_refused(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            status, output = self.main("--output-dir", str(self.directory / "ci"))
        self.assertEqual(status, 1)
        self.assertIn("public CI", output)

    def test_one_case_reruns_alone(self):
        self.main("--iterations", "8", "--strategy", "mutation", "--output-dir", str(self.directory / "all"))
        self.main("--start", "5", "--iterations", "1", "--strategy", "mutation", "--output-dir",
                  str(self.directory / "one"))
        one = json.loads((self.directory / "one/summary.json").read_text(encoding="utf-8"))
        self.assertEqual(one["cases"], {"mutation": 1})


class SanitizerBuildTests(unittest.TestCase):
    def test_sanitize_compiles_and_links_every_object_with_the_sanitizers(self):
        commands = []

        def run(command, **_):
            commands.append([str(part) for part in command])
            if "-o" in command and command[command.index("-o") + 1] == "asn1c-adapter":
                (directory / "asn1c-adapter").write_bytes(b"")
            return ""
        with tempfile.TemporaryDirectory() as name, patch.object(asn1c, "run", run):
            directory = Path(name)
            schema = asn1c.schema_identity()
            built = asn1c.compile_adapter(directory, "cc", ["generated/A.c"], schema, asn1c.load_pin(),
                                          directory / "build.log", sanitize=True)
        self.assertEqual(built["sanitizers"], ["address", "undefined"])
        self.assertTrue(all("-fsanitize=address,undefined" in c and "-fno-sanitize=nonnull-attribute" in c
                            for c in commands))
        self.assertEqual(len(commands), 3)


class DocumentationTests(unittest.TestCase):
    def test_guide_documents_every_rule_check_and_outcome(self):
        text = GUIDE.read_text(encoding="utf-8")
        for name in [*fuzz.EXPLANATIONS, *fuzz.CHECKS, *fuzz.OUTCOMES, *fuzz.STRATEGIES]:
            with self.subTest(name=name):
                self.assertIn(f"`{name}`", text)


if __name__ == "__main__":
    unittest.main()
