#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Differential fuzzing of OpenTLV Lua BER, DER and CER against asn1c, judged by the X.690 reference.

Two strategies share one evaluation. `value` generates typed values, encodes them with OpenTLV
and the reference, and has both libraries decode the reference's DER, CER and BER forms.
`mutation` mutates committed and generated encodings and feeds the same bytes to both libraries.
Every check is judged against `x690.py`, never against the other library. A difference that a
documented limitation or capability probe explains is classified as such; any other is a finding,
which is minimized, rechecked against X.690 and kept with everything needed to reproduce it.

Exploratory inputs and findings stay local: see docs/differential-fuzzing.md.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

if __package__:
    from . import check_asn1c, run_ber_cer_differential as interop, run_der_differential as der
    from . import run_differential as lua_runner, setup_asn1c as asn1c, x690
    from .check_asn1 import ROOT
    from .setup_lua import clean_env, digest, require
else:
    import check_asn1c
    import run_ber_cer_differential as interop
    import run_der_differential as der
    import run_differential as lua_runner
    import setup_asn1c as asn1c
    import x690
    from check_asn1 import ROOT
    from setup_lua import clean_env, digest, require

RUNNER = "run_fuzz.py"
ENCODINGS = ("ber", "der", "cer")
STRATEGIES = ("value", "mutation")
CHECKS = ("opentlv.decode", "opentlv.round-trip", "opentlv.encode", "asn1c.decode", "asn1c.round-trip")
OUTCOMES = ("pass", "semantic-mismatch", "canonical-mismatch", "crash", "sanitizer", "limitation", "not-comparable",
            "inconclusive")
# Untriaged outcomes: each is minimized, rechecked against X.690 and kept as a finding.
FINDINGS = ("semantic-mismatch", "canonical-mismatch", "crash", "sanitizer")
ANOMALIES = ("crash", "timeout", "sanitizer")
FINDING_EXIT = 3
MAX_WIRE = asn1c.MAX_WIRE_BYTES
INT64 = (-2 ** 63, 2 ** 63 - 1)
OID_ARC_MAX = 2 ** 32 - 1
SEED_CORPORA = (der.DEFAULT_FIXTURES, interop.DEFAULT_FIXTURES)
SETUP_COMMANDS = ["python3 scripts/setup_lua.py --lua lua5.2", "python3 scripts/setup_asn1c.py --sanitize"]
DEFAULT_OUTPUT = ROOT / "build/fuzz"
SANITIZER_ENV = {"ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:symbolize=1",
                 "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}
SANITIZER_MARKS = ("ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "runtime error:")

# What OpenTLV Lua implements of X.690: its Formats check framing and its codecs apply the
# canonical contents rules to every encoding, but no schema layer or cer_validation.h is bound.
OPENTLV_MODEL = {"ber": x690.Rules("ber", True, False, False), "cer": x690.Rules("cer", True, False, False),
                 "der": x690.Rules("der", True, False, False)}
GROUPS = {"contents": "opentlv-contents", "strings": "opentlv-strings", "schema": "opentlv-schema"}

# Each explanation is a documented limitation or an asn1c capability probe; nothing else explains.
EXPLANATIONS = {
    "opentlv-int64": ("limitation", "asn1.integer represents int64_t only (Core asn1_codec.h), so the Lua codec "
                                    "rejects longer INTEGER values on decoding and encoding"),
    "opentlv-oid": ("limitation", "asn1.oid holds at most TLV_ASN1_OID_MAX_ARCS (32) arcs, each fitting uint64_t, "
                                  "and rejects longer OBJECT IDENTIFIER values (Core asn1_codec.h)"),
    "opentlv-contents": ("limitation", "the asn1.* codecs apply the canonical contents rules of X.690 11.1 and "
                                       "11.2.1 to BER as well, as Core's asn1_codec.h documents"),
    "opentlv-strings": ("limitation", "OpenTLV Lua binds Core's CER Format but not cer_validation.h, so CER string "
                                      "segmentation (X.690 9.2) is not checked"),
    "opentlv-schema": ("limitation", "OpenTLV Lua binds no ASN.1 schema layer, so SET and SET OF order and DEFAULT "
                                     "omission (X.690 9.3, 10.3, 11.5, 11.6) are not checked"),
    "opentlv-writer": ("limitation", "the Lua Tree Writer writes the value as given: it omits no DEFAULT value, and "
                                     "der_schema.h and tlv_cer_write_segmented_string() are not bound"),
    "opentlv-adapter": ("limitation", "OpenTLV Lua binds no ASN.1 schema layer, so only the TestLab adapter rejects "
                                      "schema violations; its rejection is not an OpenTLV verdict"),
    "opentlv-depth": ("limitation", "the adapters traverse at most 32 levels, OpenTLV's default depth"),
    "asn1c-cer": ("not-comparable", "asn1c decodes CER with its BER decoder, which accepts this valid BER form "
                                    "(capability probe cer-form-as-ber)"),
    "asn1c:ber-oid-arc-above-32-bits": ("not-comparable", "asn1c reduces OBJECT IDENTIFIER arcs above 2^32-1 "
                                                          "modulo 2^32 (capability probe ber-oid-arc-above-32-bits)"),
    "error-category": ("inconclusive", "both reject, but with another normalized error; with several defects the "
                                       "error depends on which one a decoder meets first"),
    "asn1c-reencoding": ("inconclusive", "asn1c decoded the input but could not re-encode it as DER"),
}
# asn1c accepts what X.690 forbids: the reference's reason for rejecting -> capability probe.
ASN1C_ACCEPTS = (
    ("INTEGER without contents", "ber-integer-empty"),
    ("INTEGER not in its fewest octets", "ber-integer-nonminimal"),
    ("BOOLEAN contents are one octet", "ber-boolean-empty, ber-boolean-two-octets"),
    ("BIT STRING without its initial octet", "ber-bit-string-no-initial-octet"),
    ("BIT STRING segment without its initial octet", "ber-bit-string-segment-no-initial-octet"),
    ("subidentifier with a leading 80 octet", "ber-oid-leading-80"),
    ("unterminated last subidentifier", "ber-oid-incomplete-subidentifier"),
    ("tag number with a leading zero septet", "ber-high-tag-leading-zero"),
    ("high-tag-number form for a tag number below 31", "ber-high-tag-form-for-low-number"),
    ("unused bits in a segment other than the last", "ber-bit-string-segment-unused"),
    ("indefinite length on a primitive value", "ber-primitive-indefinite"),
    ("segment with identifier", "ber-constructed-segment-own-tag"),
)
for _, probes in ASN1C_ACCEPTS:
    EXPLANATIONS["asn1c:" + probes.split(", ")[0]] = ("not-comparable", f"asn1c accepts this X.690 violation "
                                                                        f"(capability probe {probes})")
SEGMENT_LIMITATION = "asn1c:ber-constructed-ia5-octet-segments"
EXPLICIT_LIMITATION = "asn1c:ber-explicit-indefinite-primitive"
EMPTY_BITS_LIMITATION = "asn1c:ber-bit-string-constructed-empty"
EXPLANATIONS[EMPTY_BITS_LIMITATION] = (
    "limitation", "asn1c's constraint check rejects an empty BIT STRING in constructed form (capability probe "
                  "ber-bit-string-constructed-empty)")
EXPLANATIONS[SEGMENT_LIMITATION] = (
    "limitation", "asn1c rejects the OCTET STRING segments X.690 prescribes for IA5String and implicitly tagged "
                  "strings (capability probes ber-constructed-ia5-octet-segments, "
                  "ber-constructed-implicit-octet-segments)")
EXPLANATIONS[EXPLICIT_LIMITATION] = (
    "limitation", "asn1c rejects an indefinite length on an explicit tag around a primitive type (capability probe "
                  "ber-explicit-indefinite-primitive)")


# --- Deterministic randomness ------------------------------------------------------------------

class Rng:
    """SplitMix64 seeded from the case: the same seed, strategy and index give the same case on
    every Python version and platform, so any case can be rerun alone."""

    MASK = (1 << 64) - 1

    def __init__(self, *seed):
        self.state = int.from_bytes(hashlib.sha256(json.dumps(seed).encode()).digest()[:8], "big")

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & self.MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.MASK
        return z ^ (z >> 31)

    def below(self, bound):
        limit = (1 << 64) - (1 << 64) % bound
        while (value := self.next()) >= limit:
            pass
        return value % bound

    def between(self, low, high):
        return low + self.below(high - low + 1)

    def chance(self, percent):
        return self.below(100) < percent

    def choice(self, items):
        return items[self.below(len(items))]

    def octets(self, count, limit=256):
        return bytes(self.below(limit) for _ in range(count))

    def shuffle(self, items):
        for i in range(len(items) - 1, 0, -1):
            j = self.below(i + 1)
            items[i], items[j] = items[j], items[i]
        return items


# --- Logical values ----------------------------------------------------------------------------

INTEGERS = (0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, 32768, -32769, 2 ** 31 - 1, 2 ** 31, -2 ** 31,
            2 ** 53, 2 ** 53 + 1, -2 ** 53 - 1, 2 ** 63 - 1, -2 ** 63)
ARCS = (0, 1, 39, 40, 127, 128, 16383, 16384, 2 ** 21 - 1, 2 ** 28, OID_ARC_MAX)


def string_length(rng):
    """Mostly short, then the length-octet and 1000-octet segmentation boundaries."""
    roll = rng.below(100)
    if roll < 70:
        return rng.below(17)
    if roll < 85:
        return rng.between(120, 135)
    if roll < 93:
        return rng.between(250, 260)
    if roll < 98:
        return rng.between(995, 1005)
    return rng.between(1995, 2005)


def oid_arc(rng, limit=OID_ARC_MAX):
    return min(rng.choice(ARCS) if rng.chance(30) else rng.below(1 << rng.between(1, 32)), limit)


def generate(schema, rng):
    """A random value of the type, inside the common supported subset (docs/differential-fuzzing.md)."""
    kind = schema["kind"]
    if kind == "choice":
        alternative = rng.choice(schema["alternatives"])
        return {"kind": "choice", "alternative": alternative["name"], "value": generate(alternative["type"], rng)}
    if kind == "explicit":
        return generate(schema["inner"], rng)
    if kind == "boolean":
        return {"kind": kind, "value": rng.chance(50)}
    if kind == "integer":
        if rng.chance(40):
            number = rng.choice(INTEGERS)
        else:
            bits = rng.below(64)
            number = rng.below(1 << bits) if bits else 0
            number = -number - 1 if rng.chance(50) else number
        return {"kind": kind, "value": str(number)}
    if kind == "null":
        return {"kind": kind}
    if kind == "object_identifier":
        first = rng.below(3)
        second = rng.below(40) if first < 2 else oid_arc(rng, OID_ARC_MAX - 80)
        arcs = [first, second] + [oid_arc(rng) for _ in range(rng.below(7))]
        return {"kind": kind, "value": ".".join(map(str, arcs))}
    if kind in ("octet_string", "ia5string"):
        return {"kind": kind, "value": rng.octets(string_length(rng), 128 if kind == "ia5string" else 256).hex()}
    if kind == "bit_string":
        data = bytearray(rng.octets(string_length(rng)))
        unused = rng.below(8) if data else 0
        if data:
            data[-1] &= 0xFF << unused & 0xFF
        return {"kind": kind, "unused_bits": unused, "value": data.hex()}
    if kind in ("sequence", "set"):
        fields = []
        for field in schema["fields"]:
            if "default" in field:
                value = field["default"] if rng.chance(40) else generate(field["type"], rng)
            elif field.get("optional") and rng.chance(40):
                continue
            else:
                value = generate(field["type"], rng)
            fields.append({"name": field["name"], "value": value})
        return {"kind": kind, "fields": fields}
    count = rng.below(6) if rng.chance(85) else rng.between(6, 20)
    return {"kind": kind, "items": [generate(schema["item"], rng) for _ in range(count)]}


def walk_values(value):
    yield value
    for field in value.get("fields", ()):
        yield from walk_values(field["value"])
    for item in value.get("items", ()):
        yield from walk_values(item)
    if value.get("kind") == "choice":
        yield from walk_values(value["value"])


def beyond_int64(value):
    return any(v.get("kind") == "integer" and v.get("value") is not None and
               not INT64[0] <= int(v["value"]) <= INT64[1] for v in walk_values(value))


def oid_arcs(value):
    return [list(map(int, v["value"].split("."))) for v in walk_values(value)
            if v.get("kind") == "object_identifier" and v.get("value")]


def beyond_opentlv_oid(value):
    """More arcs than TLV_ASN1_OID_MAX_ARCS, or one that does not fit uint64_t."""
    return any(len(arcs) > 32 or max(arcs) >= 2 ** 64 for arcs in oid_arcs(value))


def logical(value):
    return interop.logical(value)


# --- Encoders ----------------------------------------------------------------------------------

def ber_length(size, rng):
    """Short, long or padded long form (8.1.3.4, 8.1.3.5): all valid BER."""
    if size < 0x80 and rng.chance(70):
        return bytes([size])
    octets = size.to_bytes(max((size.bit_length() + 7) // 8, 1), "big")
    if rng.chance(30):
        octets = b"\x00" * rng.between(1, 2) + octets
    return bytes([0x80 | len(octets)]) + octets


def ber_constructed(identifier, contents, rng):
    if rng.chance(50):
        return identifier + b"\x80" + contents + b"\x00\x00"
    return identifier + ber_length(len(contents), rng) + contents


def split(data, rng, keep_last):
    """Random cut points; the last part is never empty when keep_last is set."""
    cuts = sorted({rng.below(len(data) + 1) for _ in range(rng.between(0, 3))})
    parts, start = [], 0
    for cut in cuts + [len(data)]:
        parts.append(data[start:cut])
        start = cut
    if keep_last and not parts[-1] and len(parts) > 1:
        parts = parts[:-2] + [parts[-2]]
    return parts


def ber_string(kind, identifier, contents, rng):
    """A constructed string of primitive segments, sometimes nested (8.6.4, 8.7.3, 8.23.5)."""
    tag = x690.SEGMENT_IDENTIFIERS[kind]
    if kind == "bit_string":
        unused, data = contents[:1], contents[1:]
        chunks = split(data, rng, keep_last=unused != b"\x00")
        segments = [tag + ber_length(len(c) + 1, rng) + b"\x00" + c for c in chunks[:-1]]
        segments.append(tag + ber_length(len(chunks[-1]) + 1, rng) + unused + chunks[-1])
    else:
        segments = [tag + ber_length(len(c), rng) + c for c in split(contents, rng, keep_last=False)]
    if len(segments) > 1 and rng.chance(20):
        cut = rng.between(1, len(segments) - 1)
        segments = [ber_constructed(bytes([tag[0] | 0x20]), b"".join(segments[:cut]), rng)] + segments[cut:]
    constructed = bytes([identifier[0] | 0x20]) + identifier[1:]
    return ber_constructed(constructed, b"".join(segments), rng)


def ber_encode(schema, value, rng):
    """One random valid BER encoding: alternative lengths, constructed strings, TRUE other than ff,
    set padding bits, an encoded DEFAULT and any SET or SET OF order."""
    kind = schema["kind"]
    if kind == "choice":
        alternative = next(a for a in schema["alternatives"] if a["name"] == value["alternative"])
        return ber_encode(alternative["type"], value["value"], rng)
    identifier = bytes.fromhex(schema["identifier"])
    if kind in der.LEAVES:
        contents = der.leaf_contents(kind, value)
        if kind == "boolean" and value["value"] and rng.chance(15):
            contents = bytes([rng.between(1, 254)])
        if kind == "bit_string" and value["unused_bits"] and len(contents) > 1 and rng.chance(15):
            contents = contents[:-1] + bytes([contents[-1] | rng.below(1 << value["unused_bits"])])
        if kind in x690.STRINGS and rng.chance(30):
            return ber_string(kind, identifier, contents, rng)
        return identifier + ber_length(len(contents), rng) + contents
    if kind == "explicit":
        return ber_constructed(identifier, ber_encode(schema["inner"], value, rng), rng)
    if kind in ("sequence", "set"):
        given = {field["name"]: field["value"] for field in value["fields"]}
        parts = [ber_encode(f["type"], given[f["name"]], rng) for f in schema["fields"]
                 if f["name"] in given and (given[f["name"]] != f.get("default") or rng.chance(20))]
    else:
        parts = [ber_encode(schema["item"], item, rng) for item in value["items"]]
    if kind in ("set", "set_of") and rng.chance(50):
        rng.shuffle(parts)
    return ber_constructed(identifier, b"".join(parts), rng)


def literal_encode(schema, value, framing, sort_items):
    """What a writer without a schema layer produces: the components given, in their order, and
    every string in primitive form; definite lengths, or indefinite constructed ones for CER."""
    kind = schema["kind"]
    if kind == "choice":
        alternative = next(a for a in schema["alternatives"] if a["name"] == value["alternative"])
        return literal_encode(alternative["type"], value["value"], framing, sort_items)
    if kind in der.LEAVES:
        return der.tlv(schema["identifier"], der.leaf_contents(kind, value))
    if kind == "explicit":
        parts = [literal_encode(schema["inner"], value, framing, sort_items)]
    elif kind in ("sequence", "set"):
        given = {field["name"]: field["value"] for field in value["fields"]}
        parts = [literal_encode(f["type"], given[f["name"]], framing, sort_items)
                 for f in schema["fields"] if f["name"] in given]
    else:
        parts = [literal_encode(schema["item"], item, framing, sort_items) for item in value["items"]]
        if kind == "set_of" and sort_items:
            width = max(map(len, parts), default=0)
            parts.sort(key=lambda part: der.set_of_key(part, width))
    if framing == "cer":
        return bytes.fromhex(schema["identifier"]) + b"\x80" + b"".join(parts) + b"\x00\x00"
    return der.tlv(schema["identifier"], b"".join(parts))


def canonical_encode(schema, value, encoding):
    return x690.cer_encode(schema, value) if encoding == "cer" else der.der_encode(schema, value)


# --- Cases -------------------------------------------------------------------------------------

def value_encodings(schema, value, rng):
    """DER, CER and one random BER form, each checked by the reference; None if one is too long."""
    encodings = {"der": der.der_encode(schema, value), "cer": x690.cer_encode(schema, value)}
    for _ in range(4):
        encodings["ber"] = ber_encode(schema, value, rng)
        if len(encodings["ber"]) <= MAX_WIRE:
            break
    else:
        encodings["ber"] = encodings["der"]
    if max(map(len, encodings.values())) > MAX_WIRE:
        return None
    for encoding, wire in encodings.items():
        if logical(x690.decode(schema, wire, encoding)) != logical(value):
            raise AssertionError(f"Generated {encoding} {wire.hex()} does not decode to its value")
    return encodings


def generate_value(types, rng):
    """A type, a value of it and its encodings; values whose encodings exceed the adapters' limit are redrawn."""
    while True:
        name = rng.choice(list(types))
        value = generate(types[name], rng)
        encodings = value_encodings(types[name], value, rng)
        if encodings:
            return name, value, encodings


def value_cases(seed, index, types):
    """Encode one value with each encoding, and decode the reference's DER, CER and BER forms with
    every encoding: as BER they must give the value, and as DER or CER only a canonical form may."""
    rng = Rng(seed, "value", index)
    name, value, encodings = generate_value(types, rng)
    base = {"strategy": "value", "index": index, "type": name}
    cases = [{**base, "id": f"value-{index}-encode-{e}", "operation": "encode", "encoding": e, "value": value}
             for e in ENCODINGS]
    for form in ENCODINGS:
        for encoding in ENCODINGS:
            label = form if form == encoding else f"{form}-as-{encoding}"
            cases.append({**base, "id": f"value-{index}-decode-{label}", "operation": "decode",
                          "encoding": encoding, "wire": encodings[form].hex()})
    return cases


def seed_pool():
    """Every committed DER, BER and CER fixture, accepted or rejected, in corpus order."""
    pool = []
    for path in SEED_CORPORA:
        for fixture in json.loads(path.read_text(encoding="utf-8"))["fixtures"]:
            pool.append({"origin": f"{path.stem}:{fixture['id']}", "type": fixture["type"],
                         "encoding": fixture.get("encoding", "der"), "wire": bytes.fromhex(fixture["wire"])})
    return pool


def scan(data):
    """Best-effort TLV elements of possibly invalid bytes: (start, length octet, contents end, constructed)."""
    found = []

    def walk(position, end, depth):
        while position < end and depth < 8 and len(found) < 64:
            start = position
            if data[position] == 0 and position + 1 < end and data[position + 1] == 0:
                position += 2
                continue
            constructed = bool(data[position] & 0x20)
            if data[position] & 0x1F == 0x1F:
                position += 1
                while position < end and data[position] & 0x80:
                    position += 1
            position += 1
            if position >= end:
                return
            length_at, first = position, data[position]
            position += 1
            if first == 0x80:
                found.append((start, length_at, None, constructed))
                if constructed:
                    walk(position, end, depth + 1)
                return
            if first & 0x80:
                count = first & 0x7F
                if position + count > end:
                    return
                length = int.from_bytes(data[position:position + count], "big")
                position += count
            else:
                length = first
            stop = min(position + length, end)
            found.append((start, length_at, stop, constructed))
            if constructed:
                walk(position, stop, depth + 1)
            position = stop

    walk(0, len(data), 0)
    return found


INTERESTING_OCTETS = (0x00, 0x01, 0x1F, 0x20, 0x3F, 0x7F, 0x80, 0x81, 0x82, 0x84, 0x9F, 0xA0, 0xFF)


def length_octets(size):
    return der.der_length(size)


def mutate_once(data, rng, pool, tags):
    """One mutation: byte-level edits, or edits of a TLV element found by scan()."""
    elements = scan(data)
    operations = ["flip", "set", "insert", "delete", "truncate", "append", "duplicate", "splice"]
    if elements:
        operations += ["length", "long-form", "indefinite", "constructed", "tag", "drop-element",
                       "repeat-element"] * 2
    operation = rng.choice(operations)
    data = bytearray(data)
    if operation in ("length", "long-form", "indefinite", "constructed", "tag", "drop-element", "repeat-element"):
        start, length_at, stop, constructed = rng.choice(elements)
        header_end = length_at + 1 + (data[length_at] & 0x7F if data[length_at] & 0x80 and data[length_at] != 0x80
                                      else 0)
        size = None if stop is None else stop - header_end
        stop = len(data) if stop is None else stop
        if operation == "constructed":
            data[start] ^= 0x20
        elif operation == "tag":
            data[start:length_at] = rng.choice((bytes([rng.choice(INTERESTING_OCTETS)]), bytes([rng.below(256)]),
                                                b"\x9f" + bytes([rng.between(0x80, 0x81), rng.below(0x80)]),
                                                bytes.fromhex(rng.choice(tags))))
        elif operation == "drop-element":
            del data[start:stop]
        elif operation == "repeat-element":
            data[stop:stop] = data[start:stop]
        elif size is None:
            data[length_at:length_at + 1] = length_octets(rng.below(len(data) + 2))
        elif operation == "length":
            data[length_at:header_end] = length_octets(max(size + rng.choice((-2, -1, 1, 2, 127)), 0))
        elif operation == "long-form":
            data[length_at:header_end] = bytes([0x81 + rng.below(2)]) + b"\x00" * rng.below(2) + bytes([size & 0xFF])
        else:
            data[stop:stop] = b"\x00\x00"
            data[length_at:header_end] = b"\x80"
        return bytes(data), operation
    position = rng.below(len(data) + 1)
    if operation == "flip" and data:
        data[min(position, len(data) - 1)] ^= 1 << rng.below(8)
    elif operation == "set" and data:
        data[min(position, len(data) - 1)] = rng.choice(INTERESTING_OCTETS)
    elif operation == "insert":
        data[position:position] = bytes([rng.choice(INTERESTING_OCTETS) if rng.chance(50) else rng.below(256)])
    elif operation == "delete":
        del data[position:position + rng.between(1, 4)]
    elif operation == "truncate":
        del data[position:]
    elif operation == "append":
        data += rng.choice((b"\x00\x00", b"\x00", bytes([rng.below(256)])))
    elif operation == "duplicate" and data:
        end = rng.between(position, min(len(data), position + 16))
        data[end:end] = data[position:end]
    elif operation == "splice":
        donor = rng.choice(pool)["wire"]
        cut = rng.below(len(donor) + 1)
        data[position:] = donor[cut:]
    return bytes(data), operation


TREE_OPERATIONS = ("contents", "retag", "form", "drop-child", "duplicate-child", "swap-children", "segment",
                   "end-of-contents")


def serialize(element, encoding, forms):
    """An element tree in the encoding's canonical length forms, except where `forms` overrides one."""
    body = b"".join(serialize(child, encoding, forms) for child in element.children) if element.constructed \
        else element.contents
    form = forms.get(id(element)) or ("indefinite" if encoding == "cer" and element.constructed else "minimal")
    if form == "indefinite":
        return element.identifier + b"\x80" + body + b"\x00\x00"
    length = der.der_length(len(body))
    if form == "long":
        length = bytes([0x81]) + bytes([len(body)]) if len(body) < 0x100 else length
    elif form == "padded":
        length = bytes([0x80 | len(length) + (len(length) == 1)]) + b"\x00" + \
            (length if len(length) == 1 else length[1:])
    return element.identifier + length + body


def mutate_tree(root, rng, tags, forms):
    """One edit of a parsed element; serialize() recomputes every length around it."""
    nodes, stack = [], [root]
    while stack:
        nodes.append(stack.pop())
        stack.extend(reversed(nodes[-1].children))
    target = rng.choice(nodes)
    operations = ["retag", "form"] + (["drop-child", "duplicate-child", "swap-children", "end-of-contents"]
                                      if target.constructed and target.children else []) + \
        (["contents", "contents", "segment"] if not target.constructed else [])
    operation = rng.choice(operations)
    if operation == "contents":
        data = bytearray(target.contents)
        edit = rng.below(4) if data else 2
        if edit == 2:
            data.insert(rng.below(len(data) + 1), rng.choice(INTERESTING_OCTETS))
        else:
            position = rng.below(len(data))
            if edit == 0:
                data[position] ^= 1 << rng.below(8)
            elif edit == 1:
                data[position] = rng.choice(INTERESTING_OCTETS)
            else:
                del data[position]
        target.contents = bytes(data)
    elif operation == "retag":
        target.identifier = bytes.fromhex(rng.choice(tags))
        if rng.chance(30):
            target.identifier = bytes([target.identifier[0] ^ 0x20]) + target.identifier[1:]
    elif operation == "form":
        forms[id(target)] = rng.choice(("long", "padded", "indefinite", "minimal"))
    elif operation == "drop-child":
        del target.children[rng.below(len(target.children))]
    elif operation == "duplicate-child":
        position = rng.below(len(target.children))
        target.children.insert(position, target.children[position])
    elif operation == "swap-children":
        first, second = rng.below(len(target.children)), rng.below(len(target.children))
        target.children[first], target.children[second] = target.children[second], target.children[first]
    elif operation == "end-of-contents":
        target.children.insert(rng.below(len(target.children) + 1), x690.Element(b"\x00", False, b"", [], b""))
    else:
        bits = target.identifier[0] & 0x1F == 0x03
        data, parts = target.contents, []
        if bits and data:
            for chunk in split(data[1:], rng, keep_last=data[0] != 0):
                parts.append(b"\x00" + chunk)
            parts[-1] = data[:1] + parts[-1][1:]
        else:
            parts = split(data, rng, keep_last=False)
        segment = b"\x03" if bits else b"\x04"
        target.children = [x690.Element(segment, False, part, [], b"") for part in parts]
        target.identifier = bytes([target.identifier[0] | 0x20]) + target.identifier[1:]
        target.constructed = True
    return operation


def mutation_case(seed, index, types, pool):
    """Seed bytes from a committed fixture or a generated value, mutated one to three times, then
    sometimes read with another encoding or type. A seed that is valid BER is usually edited as a
    tree, which keeps its framing; otherwise its bytes are edited."""
    rng = Rng(seed, "mutation", index)
    tags = sorted({i for schema in types.values() for i in schema_identifiers(schema)})
    if rng.chance(60):
        source = rng.choice(pool)
        name, wire, encoding, origin = source["type"], source["wire"], source["encoding"], source["origin"]
    else:
        name, value, encodings = generate_value(types, rng)
        encoding = rng.choice(ENCODINGS)
        wire, origin = encodings[encoding], f"generated:{encoding}"
    count = 1 if rng.chance(50) else 2 if rng.chance(70) else 3
    operations = []
    try:
        root = x690.parse(wire, "ber") if rng.chance(65) else None
    except x690.Invalid:
        root = None
    if root is not None:
        forms = {}
        operations = ["tree:" + mutate_tree(root, rng, tags, forms) for _ in range(count)]
        wire = serialize(root, encoding, forms)
    else:
        for _ in range(count):
            wire, operation = mutate_once(wire, rng, pool, tags)
            operations.append(operation)
    if rng.chance(30):
        encoding = rng.choice(ENCODINGS)
    if rng.chance(15):
        name = rng.choice(list(types))
    return {"id": f"mutation-{index}", "strategy": "mutation", "index": index, "type": name, "operation": "decode",
            "encoding": encoding, "wire": wire[:MAX_WIRE].hex(), "seed_origin": origin, "mutations": operations}


def schema_identifiers(schema, kinds=None):
    """Identifiers in the type, optionally only of the given kinds."""
    found = set()
    if "identifier" in schema and (kinds is None or schema["kind"] in kinds):
        found.add(schema["identifier"])
    for nested in [*(f["type"] for f in schema.get("fields", ())), *(a["type"] for a in schema.get("alternatives", ())),
                   *(schema[key] for key in ("item", "inner") if key in schema)]:
        found |= schema_identifiers(nested, kinds)
    return found


# --- Reference ---------------------------------------------------------------------------------

def reference(schema, wire, rules):
    try:
        return {"status": "accepted", "value": x690.decode(schema, wire, rules)}
    except x690.Invalid as error:
        return {"status": "rejected", "error": error.error, "detail": error.detail}


def reference_views(schema, case):
    """The X.690 verdict, the BER verdict and the verdict of OpenTLV Lua's own rule profile."""
    wire = bytes.fromhex(case["wire"])
    full = reference(schema, wire, case["encoding"])
    ber = full if case["encoding"] == "ber" else reference(schema, wire, "ber")
    return {"x690": full, "ber": ber, "opentlv-model": reference(schema, wire, OPENTLV_MODEL[case["encoding"]])}


# --- Adapters ----------------------------------------------------------------------------------

def sanitizer_report(stderr):
    """The sanitizer's summary without paths, line numbers or addresses, or None."""
    if not any(mark in stderr for mark in SANITIZER_MARKS):
        return None
    lines = stderr.splitlines()
    line = next((l for l in lines if l.startswith("SUMMARY:")), None) or \
        next(l for l in lines if any(mark in l for mark in SANITIZER_MARKS))
    return normalize_detail(line)


def normalize_detail(text):
    """Diagnostic text without what changes between runs: paths, addresses, line numbers and process ids."""
    text = re.sub(r"==\d+==", "", text)
    text = re.sub(r"(/[\w.+-]+)+/", "", text)
    text = re.sub(r"0x[0-9a-f]+", "ADDRESS", text)
    return re.sub(r":\d+(:\d+)?", "", text).strip()[:300]


def run_once(command, env, payload, ids, identity_check, timeout):
    """One adapter process: complete records, and the anomaly that stopped it, if any."""
    try:
        result = subprocess.run(command, input=payload, env=env, cwd=ROOT, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout)
        stdout, stderr, code, timed_out = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr = (part.decode("utf-8", "replace") if isinstance(part, bytes) else part or ""
                          for part in (error.stdout, error.stderr))
        code, timed_out = None, True
    lines = stdout.splitlines()
    require(lines, f"{command[0]} gave no identity: {stderr[-2000:]}")
    identity_check(json.loads(lines[0]))
    records = []
    for line, identifier in zip(lines[1:], ids):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            break
        require(record.get("id") == identifier, f"{command[0]} returned results out of order")
        records.append(record)
    report = sanitizer_report(stderr)
    if report:
        anomaly = {"status": "sanitizer", "detail": report}
    elif timed_out:
        anomaly = {"status": "timeout", "detail": f"no result within {timeout} s"}
    elif code != 0 or len(records) < len(ids):
        signal = f"signal {-code}" if code is not None and code < 0 else f"exit {code}"
        anomaly = {"status": "crash", "detail": normalize_detail(f"{signal}: {stderr.strip()[-300:]}")}
    else:
        return records, None
    anomaly["stderr"] = stderr[-4000:]
    return records, anomaly


def isolate(run, requests):
    """One record per request. A crash, hang or sanitizer report is attributed to the request it
    stopped at, which reruns alone; a report after the last result splits the batch in halves."""
    results = [None] * len(requests)
    pending = [list(range(len(requests)))]
    while pending:
        group = pending.pop(0)
        records, anomaly = run([requests[i] for i in group])
        for i, record in zip(group, records):
            results[i] = record
        if anomaly is None:
            continue
        if len(group) == 1:
            results[group[0]] = {**anomaly, "id": requests[group[0]]["id"]}
        elif len(records) < len(group):
            rest = group[len(records) + 1:]
            pending[:0] = [[group[len(records)]]] + ([rest] if rest else [])
        else:
            half = len(group) // 2
            pending[:0] = [group[:half], group[half:]]
    return results


def lua_identity(adapter):
    def check(identity):
        require(identity.get("adapter") == "opentlv" and identity.get("module") == adapter["module"] and
                identity.get("version") == adapter["version"], f"OpenTLV adapter reported {identity}")
    return check


def run_opentlv(context, requests):
    """OpenTLV's DER adapter for DER requests and its BER/CER adapter for the rest."""
    adapter, lua = context["receipts"]["opentlv"], context["receipts"]["lua"]["lua"]
    environment = clean_env()
    environment.update(adapter["environment"])
    results = [None] * len(requests)
    for script, encodings in ((der.DER_ADAPTER, ("der",)), (interop.ADAPTER, ("ber", "cer"))):
        chosen = [i for i, request in enumerate(requests) if request["encoding"] in encodings]
        if not chosen:
            continue
        command = [str(lua), str(lua_runner.HOST), str(script), "--isolate"]

        def run(batch, command=command):
            return run_once(command, environment, "return " + lua_runner.lua_literal(batch), [r["id"] for r in batch],
                            lua_identity(adapter), context["timeout"])
        for i, record in zip(chosen, isolate(run, [requests[i] for i in chosen])):
            results[i] = record
    return results


def run_asn1c(context, requests):
    """asn1c decodes everything with its BER decoder and re-encodes it as DER."""
    if not requests:
        return []
    receipt = context["receipts"]["asn1c"]
    environment = {**asn1c.build_env(), **SANITIZER_ENV}

    def check(identity):
        require(identity == receipt["identity"], f"asn1c adapter reported {identity}")

    def run(batch):
        lines = "".join(f"{r['id']} {r['type']} ber der {r['wire'] or '-'}\n" for r in batch)
        return run_once([receipt["path"]], environment, lines, [r["id"] for r in batch], check, context["timeout"])
    return isolate(run, requests)


# --- Verdicts ----------------------------------------------------------------------------------

def opentlv_verdict(record):
    if record.get("status") in ANOMALIES + ("error",):
        return record
    return {key: record[key] for key in ("status", "value", "error", "source", "detail") if key in record}


def asn1c_verdict(record, encoding, wire):
    if record.get("status") in ANOMALIES:
        return record
    decode = record["decode"]
    if encoding == "der":
        verdict = der.asn1c_verdict(record, wire)
        if verdict["status"] == "accepted":
            verdict["value"] = decode["value"]
        return verdict
    if decode["status"] == "accepted":
        return {"status": "accepted", "value": decode["value"]}
    return {"status": "rejected", "error": der.ASN1C_ERRORS[decode["error"]], "native": decode["error"]}


def difference(expected, verdict):
    """How a verdict differs from the reference in acceptance or value; None if it does not."""
    if expected["status"] == "accepted":
        if verdict["status"] != "accepted":
            return f"rejected it ({verdict.get('error')}{', ' + verdict['source'] if 'source' in verdict else ''})"
        if logical(verdict["value"]) != logical(expected["value"]):
            return "decoded another value"
        return None
    return "accepted it" if verdict["status"] == "accepted" else None


def mismatch_kind(case, views, verdict):
    """Canonical when a decoder accepts as DER or CER bytes that are only valid BER of the value;
    any other difference is semantic."""
    full, ber = views["x690"], views["ber"]
    if case["encoding"] != "ber" and full["status"] == "rejected" and ber["status"] == "accepted" and \
            verdict["status"] == "accepted" and logical(verdict["value"]) == logical(ber["value"]):
        return "canonical-mismatch"
    return "semantic-mismatch"


def explained(rule, text):
    outcome, reason = EXPLANATIONS[rule]
    return {"outcome": outcome, "rule": rule, "reason": reason, "difference": text}


def anomaly_result(verdict):
    outcome = "sanitizer" if verdict["status"] == "sanitizer" else "crash"
    return {"outcome": outcome, "difference": f"{verdict['status']}: {verdict['detail']}"}


def explain_model(schema, wire, encoding, full, verdict):
    """The rule groups OpenTLV Lua lacks that explain its verdict, or None."""
    model = OPENTLV_MODEL[encoding]
    full_rules = x690.PROFILES[encoding]
    groups = [g for g in GROUPS if getattr(model, g) != getattr(full_rules, g)]
    explaining = [g for g in groups if reference(schema, wire, model._replace(**{g: getattr(full_rules, g)}))["status"]
                  == full["status"]]
    return GROUPS[(explaining or groups)[0]] if groups else None


def judge_opentlv_decode(case, schema, views, verdict):
    full = views["x690"]
    if verdict["status"] in ANOMALIES:
        return anomaly_result(verdict)
    if verdict["status"] == "error":
        if full["status"] == "rejected" and re.search(r"depth|deeper|LIMIT", verdict["detail"], re.I):
            return explained("opentlv-depth", verdict["detail"])
        return {"outcome": "crash", "difference": f"error: {verdict['detail']}"}
    text = difference(full, verdict)
    if text is None:
        if full["status"] == "rejected":
            if verdict.get("source") == "adapter":
                return explained("opentlv-adapter", verdict.get("detail"))
            if verdict["error"] != full["error"]:
                return explained("error-category", f"OpenTLV {verdict['error']}, X.690 {full['error']}")
        return {"outcome": "pass"}
    if full["status"] == "accepted" and verdict["status"] == "rejected" and verdict.get("source") == "opentlv":
        if beyond_int64(full["value"]):
            return explained("opentlv-int64", text)
        if beyond_opentlv_oid(full["value"]):
            return explained("opentlv-oid", text)
    model = views["opentlv-model"]
    adapter_only = verdict["status"] == "rejected" and verdict.get("source") == "adapter"
    if difference(model, verdict) is None and not (adapter_only and model["status"] == "accepted"):
        rule = explain_model(schema, bytes.fromhex(case["wire"]), case["encoding"], full, verdict)
        if rule:
            return explained(rule, text)
    if adapter_only and full["status"] == "accepted":
        text += "; only the TestLab adapter rejected it"
    return {"outcome": mismatch_kind(case, views, verdict), "difference": text}


def judge_encoding(schema, value, encoding, produced, who):
    """An encoding of a value: canonical bytes for DER and CER, any BER the reference reads as the value."""
    if produced is None or produced.get("status") != "encoded":
        status = (produced or {}).get("status", "missing")
        if who == "OpenTLV" and status == "unsupported" and beyond_int64(value):
            return explained("opentlv-int64", f"{who} encoding unsupported")
        return {"outcome": "semantic-mismatch", "difference": f"{who} encoding {status}: "
                                                               f"{(produced or {}).get('detail')}"}
    wire = bytes.fromhex(produced["wire"])
    if encoding != "ber" and wire == canonical_encode(schema, value, encoding):
        return {"outcome": "pass"}
    read = reference(schema, wire, "ber")
    if read["status"] != "accepted" or logical(read["value"]) != logical(value):
        what = read.get("detail") or "another value"
        return {"outcome": "semantic-mismatch", "difference": f"{who} wrote {produced['wire']}, read as {what}"}
    if encoding == "ber":
        return {"outcome": "pass"}
    if who == "OpenTLV" and wire in {literal_encode(schema, value, encoding, sort) for sort in (False, True)}:
        return explained("opentlv-writer", f"{who} wrote {produced['wire']}")
    return {"outcome": "canonical-mismatch",
            "difference": f"{who} wrote {produced['wire']}, not {canonical_encode(schema, value, encoding).hex()}"}


def judge_asn1c_decode(case, schema, views, verdict):
    full, ber = views["x690"], views["ber"]
    if verdict["status"] in ANOMALIES:
        return anomaly_result(verdict)
    if verdict["status"] == "undecided":
        return explained("asn1c-reencoding", verdict.get("detail"))
    text = difference(full, verdict)
    if text is None:
        if full["status"] == "rejected" and verdict["error"] != full["error"]:
            return explained("error-category", f"asn1c {verdict['error']}, X.690 {full['error']}")
        return {"outcome": "pass"}
    if case["encoding"] == "cer" and full["status"] == "rejected" and ber["status"] == "accepted" and \
            difference(ber, verdict) is None:
        return explained("asn1c-cer", text)
    if verdict["status"] == "accepted" and ber["status"] == "rejected":
        for reason, probes in ASN1C_ACCEPTS:
            if reason in ber["detail"] and (probes != "ber-constructed-segment-own-tag" or own_tag_segment(
                    schema, ber["detail"])):
                return explained("asn1c:" + probes.split(", ")[0], text)
    if verdict["status"] == "rejected" and full["status"] == "accepted":
        wire = bytes.fromhex(case["wire"])
        if segmented_without_own_tag(schema, wire):
            return explained(SEGMENT_LIMITATION, text)
        if indefinite_explicit(schema, wire):
            return explained(EXPLICIT_LIMITATION, text)
        if empty_constructed_bits(schema, wire, full["value"]):
            return explained(EMPTY_BITS_LIMITATION, text)
    if verdict["status"] == "accepted" and full["status"] == "accepted" and \
            any(max(arcs) > OID_ARC_MAX for arcs in oid_arcs(full["value"])):
        return explained("asn1c:ber-oid-arc-above-32-bits", text)
    return {"outcome": mismatch_kind(case, views, verdict), "difference": text}


def own_tag_segment(schema, detail):
    """A segment that repeats the string type's own identifier, which asn1c accepts."""
    match = re.search(r"segment with identifier ([0-9a-f]+)", detail)
    own = {bytes([bytes.fromhex(i)[0] & 0xDF]).hex() + i[2:] for i in schema_identifiers(schema, x690.STRINGS)}
    return bool(match) and bytes([bytes.fromhex(match.group(1))[0] & 0xDF]).hex() + match.group(1)[2:] in own


def elements(wire):
    try:
        root = x690.parse(wire, "ber")
    except x690.Invalid:
        return []
    found, stack = [], [root]
    while stack:
        element = stack.pop()
        found.append(element)
        stack.extend(element.children)
    return found


def segmented_without_own_tag(schema, wire):
    """A constructed IA5String or implicitly tagged string: X.690 segments it with OCTET STRINGs."""
    strings = {i for i in schema_identifiers(schema, x690.STRINGS) if i not in ("03", "04")}
    return any(e.constructed and x690.primitive_identifier(e.identifier).hex() in strings for e in elements(wire))


def empty_constructed_bits(schema, wire, value):
    """An empty BIT STRING value read from a constructed BIT STRING."""
    bits = schema_identifiers(schema, ("bit_string",))
    return any(v.get("kind") == "bit_string" and not v["value"] for v in walk_values(value)) and \
        any(e.constructed and x690.primitive_identifier(e.identifier).hex() in bits for e in elements(wire))


def indefinite_explicit(schema, wire):
    explicit = schema_identifiers(schema, ("explicit",))
    return any(e.identifier.hex() in explicit and e.encoding[len(e.identifier)] == 0x80 for e in elements(wire))


def judge_asn1c_round_trip(schema, views, record):
    """asn1c's DER re-encoding of what it decoded must be the DER of the value."""
    return judge_encoding(schema, views["x690"]["value"], "der", record.get("encode"), "asn1c")


def judge_case(case, schema, opentlv, asn1c_record):
    """Every check of one case that its observations make applicable."""
    checks = {}
    if case["operation"] == "encode":
        if opentlv is not None:
            if opentlv.get("status") in ANOMALIES:
                checks["opentlv.encode"] = anomaly_result(opentlv)
            elif opentlv.get("status") == "error":
                checks["opentlv.encode"] = {"outcome": "crash", "difference": f"error: {opentlv['detail']}"}
            else:
                checks["opentlv.encode"] = judge_encoding(schema, case["value"], case["encoding"], opentlv["encode"],
                                                          "OpenTLV")
        return None, checks
    views = reference_views(schema, case)
    full = views["x690"]
    if opentlv is not None:
        verdict = opentlv_verdict(opentlv)
        checks["opentlv.decode"] = judge_opentlv_decode(case, schema, views, verdict)
        if full["status"] == "accepted" and verdict["status"] == "accepted" and difference(full, verdict) is None:
            checks["opentlv.round-trip"] = round_trip(case, schema, full["value"], opentlv.get("encode"))
    if asn1c_record is not None:
        verdict = asn1c_verdict(asn1c_record, case["encoding"], case["wire"])
        checks["asn1c.decode"] = judge_asn1c_decode(case, schema, views, verdict)
        if case["encoding"] != "der" and full["status"] == "accepted" and verdict["status"] == "accepted" and \
                difference(full, verdict) is None:
            checks["asn1c.round-trip"] = judge_asn1c_round_trip(schema, views, asn1c_record)
    return views, checks


def round_trip(case, schema, value, produced):
    """OpenTLV re-encodes what it decoded: DER and CER must give the input back, BER the value."""
    result = judge_encoding(schema, value, case["encoding"], produced, "OpenTLV")
    if result["outcome"] == "pass" and case["encoding"] != "ber" and produced["wire"] != case["wire"]:
        return {"outcome": "canonical-mismatch", "difference": f"re-encoded {produced['wire']}"}
    return result


def evaluate(context, cases, libraries=("opentlv", "asn1c")):
    """Observe and judge cases; only the named libraries run."""
    types = context["types"]
    opentlv = run_opentlv(context, [lua_request(case, types) for case in cases]) if "opentlv" in libraries \
        else [None] * len(cases)
    decodes = [i for i, case in enumerate(cases) if case["operation"] == "decode"]
    asn1c_records = [None] * len(cases)
    if "asn1c" in libraries:
        observed = run_asn1c(context, [{"id": cases[i]["id"], "type": cases[i]["type"], "wire": cases[i]["wire"]}
                                       for i in decodes])
        for i, record in zip(decodes, observed):
            asn1c_records[i] = record
    results = []
    for case, mine, theirs in zip(cases, opentlv, asn1c_records):
        views, checks = judge_case(case, types[case["type"]], mine, theirs)
        results.append({"views": views, "checks": checks, "observed": {"opentlv": mine, "asn1c": theirs}})
    return results


def lua_request(case, types):
    request = {"id": case["id"], "operation": case["operation"], "encoding": case["encoding"],
               "schema": types[case["type"]]}
    if case["operation"] == "encode":
        request["value"] = case["value"]
    else:
        request["wire"] = case["wire"]
    return request


# --- Findings ----------------------------------------------------------------------------------

def bucket(case, check, result, views):
    """Findings that likely share a cause share a bucket; only its first case is minimized."""
    reference_status = views["x690"]["status"] if views else "value"
    reason = re.sub(r"\b[0-9a-f]*\d[0-9a-f]*\b", "N", views["x690"].get("detail", "")) if views else ""
    detail = re.sub(r"(?<!code )\b\d+\b", "N", normalize_detail(result.get("difference", ""))) \
        if result["outcome"] in ("crash", "sanitizer") else ""
    key = [check, case["encoding"], result["outcome"], result.get("rule", ""), reference_status, reason, detail]
    if result["outcome"] not in ("crash", "sanitizer"):
        key.append(case["type"])
    return tuple(key)


def finding_id(key):
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()[:12]


def first_kept(context, cases, check, key):
    """The first candidate whose finding stays in the bucket; only the library of the check runs."""
    verdicts = evaluate(context, cases, (check.split(".")[0],))
    return next((c for c, r in zip(cases, verdicts) if check in r["checks"] and
                 bucket(c, check, r["checks"][check], r["views"]) == key), None)


def shrink_bytes(context, case, check, key, rounds):
    """Delta debugging over the bytes: drop chunks while the finding keeps its bucket."""
    data = bytes.fromhex(case["wire"])
    chunk = max(len(data) // 2, 1)
    while data and rounds > 0:
        candidates = list(dict.fromkeys(data[:i] + data[i + chunk:] for i in range(0, len(data), chunk)))
        cases = [{**case, "id": f"{case['id']}-min{i}", "wire": c.hex()} for i, c in enumerate(candidates)]
        rounds -= 1
        kept = first_kept(context, cases, check, key)
        if kept:
            data = bytes.fromhex(kept["wire"])
            chunk = min(chunk, max(len(data) // 2, 1))
        elif chunk == 1:
            break
        else:
            chunk //= 2
    return {**case, "wire": data.hex()}


def smaller_values(schema, value):
    """Each value one simplification away: a removed item or optional field, or a simpler leaf."""
    kind = schema["kind"]
    if kind == "choice":
        alternative = next(a for a in schema["alternatives"] if a["name"] == value["alternative"])
        return [{**value, "value": v} for v in smaller_values(alternative["type"], value["value"])]
    if kind == "explicit":
        return smaller_values(schema["inner"], value)
    if kind in ("sequence", "set"):
        found, fields = [], value["fields"]
        for i, field in enumerate(fields):
            definition = next(f for f in schema["fields"] if f["name"] == field["name"])
            if definition.get("optional"):
                found.append({**value, "fields": fields[:i] + fields[i + 1:]})
            found += [{**value, "fields": fields[:i] + [{"name": field["name"], "value": v}] + fields[i + 1:]}
                      for v in smaller_values(definition["type"], field["value"])]
        return found
    if kind in ("sequence_of", "set_of"):
        items = value["items"]
        found = [{**value, "items": items[:i] + items[i + 1:]} for i in range(len(items))]
        for i, item in enumerate(items):
            found += [{**value, "items": items[:i] + [v] + items[i + 1:]} for v in smaller_values(schema["item"], item)]
        return found
    if kind == "integer":
        number = int(value["value"])
        return [{**value, "value": str(n)} for n in dict.fromkeys((0, number // 2)) if n != number]
    if kind == "object_identifier":
        arcs = value["value"].split(".")
        return [{**value, "value": ".".join(arcs[:-1])}] if len(arcs) > 2 else []
    if kind in ("octet_string", "ia5string"):
        data = value["value"]
        return [{**value, "value": data[:len(data) // 4 * 2]}] if data else []
    if kind == "bit_string" and value["value"]:
        return [{"kind": kind, "unused_bits": 0, "value": value["value"][:len(value["value"]) // 4 * 2]}]
    if kind == "boolean" and value["value"]:
        return [{**value, "value": False}]
    return []


def shrink_value(context, case, check, key, rounds):
    """Simplify the value while the encoding finding keeps its bucket."""
    schema = context["types"][case["type"]]
    while rounds > 0:
        candidates = []
        for value in smaller_values(schema, case["value"])[:64]:
            try:
                if len(canonical_encode(schema, value, "der")) <= MAX_WIRE:
                    candidates.append(value)
            except ValueError:
                continue
        if not candidates:
            break
        rounds -= 1
        cases = [{**case, "id": f"{case['id']}-min{i}", "value": v} for i, v in enumerate(candidates)]
        kept = first_kept(context, cases, check, key)
        if not kept:
            break
        case = {**case, "value": kept["value"]}
    return case


def confirm_command(case):
    return shlex.join(["python3", "scripts/x690.py", case["type"], case["wire"], "--encoding", case["encoding"]])


def fixture_draft(identifier, case, views, types):
    """The finding as an entry of the committed corpus for its encoding, for review after triage."""
    schema = types[case["type"]]
    if case["operation"] == "encode":
        wire = canonical_encode(schema, case["value"], case["encoding"])
        expected = {"result": "accept" if case["encoding"] == "ber" else "canonical", "value": case["value"]}
        rule = "X.690 " + {"ber": "8", "der": "10, 11", "cer": "9, 11"}[case["encoding"]]
    else:
        wire, full = bytes.fromhex(case["wire"]), views["x690"]
        if full["status"] == "accepted":
            expected = {"result": "accept" if case["encoding"] == "ber" else "canonical", "value": full["value"]}
            rule = "X.690 " + {"ber": "8", "der": "10, 11", "cer": "9, 11"}[case["encoding"]]
        else:
            expected = {"result": "reject", "error": full["error"]}
            clauses = re.findall(r"\(([\d., ]+)\)", full["detail"])
            rule = "X.690 " + (clauses[-1] if clauses else "8.1") + ": " + full["detail"]
    leaf = schema["kind"] in der.LEAVES
    draft = {"id": f"fuzz-{identifier}", "category": "malformed" if expected["result"] == "reject" else
             "primitive" if leaf else "constructed",
             "description": f"Fuzz finding {identifier}: describe the case before committing it",
             "rule": rule, "type": case["type"], "wire": wire.hex(), "expected": expected}
    try:
        if case["encoding"] == "der":
            der.validate_fixture(draft, types)
            corpus = der.DEFAULT_FIXTURES
        else:
            draft = {"id": draft["id"], "encoding": case["encoding"], **{k: v for k, v in draft.items() if k != "id"}}
            interop.validate_fixture(draft, types)
            corpus = interop.DEFAULT_FIXTURES
        problem = None
    except ValueError as error:
        corpus, problem = None, str(error)
    return {"corpus": corpus.relative_to(ROOT).as_posix() if corpus else None, "valid": problem is None,
            "problem": problem, "fixture": draft}


def case_command(context, case):
    command = ["python3", "scripts/" + RUNNER, "--seed", str(context["seed"]), "--strategy", case["strategy"],
               "--start", str(case["index"]), "--iterations", "1"]
    return shlex.join(command)


def minimize_finding(context, key, entry, rounds):
    """Minimize the first case of a bucket, then recheck it against X.690 with both libraries."""
    case, check = entry["case"], entry["check"]
    if rounds:
        shrink = shrink_bytes if case["operation"] == "decode" else shrink_value
        case = shrink(context, {**case, "id": case["id"] + "-min"}, check, key, rounds)
    result = evaluate(context, [case])[0]
    found = result["checks"].get(check)
    return case, result, found is not None and bucket(case, check, found, result["views"]) == key


def shown_path(path):
    return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)


def write_finding(context, directory, key, entry, rounds):
    identifier = finding_id(key)
    path = directory / f"{identifier}.json"
    minimized, result, stable = minimize_finding(context, key, entry, rounds)
    first = entry["case"]
    record = {
        "schema": 1, "runner": RUNNER, "id": identifier, "triage": "untriaged",
        "check": entry["check"], "library": entry["check"].split(".")[0], "encoding": first["encoding"],
        "type": first["type"], "outcome": entry["result"]["outcome"], "occurrences": entry["count"],
        "first": {"case": first, "result": entry["result"], "observed": entry["observed"], "views": entry["views"],
                  "reproduce": reproduction(context, case_command(context, first))},
        "minimized": {"case": minimized, "result": result["checks"].get(entry["check"]), "stable": stable,
                      "checks": result["checks"], "observed": result["observed"], "views": result["views"],
                      "minimization_rounds": rounds},
        "seed": context["seed"], "packages": context["packages"], "runtime": context["runtime"],
        "platform": context["platform"], "compiler": context["compiler"], "sanitizers": context["sanitizers"],
        "testlab": context["testlab"], "provenance": context["provenance"],
        "replay": reproduction(context, shlex.join(["python3", "scripts/" + RUNNER, "--replay", shown_path(path)])),
    }
    if minimized["operation"] == "decode":
        record["minimized"]["confirm"] = confirm_command(minimized)
    record["fixture_draft"] = fixture_draft(identifier, minimized, result["views"], context["types"])
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def reproduction(context, command):
    commit = context["testlab"]["commit"]
    return ([f"git checkout {commit}"] if commit else []) + SETUP_COMMANDS + [command]


# --- Runs --------------------------------------------------------------------------------------

def cases_for(context, strategy, indices):
    if strategy == "value":
        return [case for index in indices for case in value_cases(context["seed"], index, context["types"])]
    return [mutation_case(context["seed"], index, context["types"], context["pool"]) for index in indices]


def tally(summary, buckets, case, judged):
    summary["cases"][case["strategy"]] = summary["cases"].get(case["strategy"], 0) + 1
    views = judged["views"]
    if views:
        status = views["x690"]["status"]
        reference_counts = summary["reference"].setdefault(case["encoding"], {"accepted": 0, "rejected": 0})
        reference_counts[status] += 1
    summary["types"][case["type"]] = summary["types"].get(case["type"], 0) + 1
    for operation in case.get("mutations", ()):
        summary["mutations"][operation] = summary["mutations"].get(operation, 0) + 1
    for check, result in judged["checks"].items():
        counts = summary["checks"].setdefault(check, {}).setdefault(case["encoding"], dict.fromkeys(OUTCOMES, 0))
        counts[result["outcome"]] += 1
        if result["outcome"] == "pass":
            continue
        if result["outcome"] in FINDINGS:
            key = bucket(case, check, result, views)
            entry = buckets.setdefault(key, {"case": case, "check": check, "result": result, "views": views,
                                             "observed": judged["observed"], "count": 0})
            entry["count"] += 1
        else:
            key = (check, case["encoding"], result["outcome"], result["rule"])
            entry = summary["explained"].setdefault(key, {"check": check, "encoding": case["encoding"],
                                                           "outcome": result["outcome"], "rule": result["rule"],
                                                           "reason": result["reason"], "count": 0,
                                                           "example": {"case": case["id"], "type": case["type"],
                                                                       "difference": result["difference"]}})
            entry["count"] += 1


def run_fuzz(context, args):
    summary = {"cases": {}, "reference": {}, "types": {}, "mutations": {}, "checks": {}, "explained": {}}
    buckets = {}
    for strategy in args.strategy:
        for start in range(args.start, args.start + args.iterations, args.batch_size):
            indices = range(start, min(start + args.batch_size, args.start + args.iterations))
            cases = cases_for(context, strategy, indices)
            for case, judged in zip(cases, evaluate(context, cases)):
                tally(summary, buckets, case, judged)
            print(f"{strategy}: {indices.stop - args.start} of {args.iterations} done, {len(buckets)} findings",
                  flush=True)
    findings = []
    for number, (key, entry) in enumerate(buckets.items()):
        rounds = args.minimize_rounds if number < args.max_findings else 0
        record = write_finding(context, args.output_dir / "findings", key, entry, rounds)
        minimized = record["minimized"]["case"]
        findings.append({name: record[name] for name in ("id", "check", "encoding", "type", "outcome", "occurrences")} |
                        {"minimized": minimized["wire"] if minimized["operation"] == "decode" else minimized["value"],
                         "stable": record["minimized"]["stable"],
                         "reference": (record["minimized"]["views"] or {}).get("x690")})
    summary["explained"] = sorted(summary["explained"].values(), key=lambda e: (e["check"], e["encoding"], e["rule"]))
    summary["checks"] = {name: dict(sorted(e.items())) for name, e in sorted(summary["checks"].items())}
    for key in ("types", "mutations"):
        summary[key] = dict(sorted(summary[key].items()))
    return {"schema": 1, "runner": RUNNER, "status": "findings" if findings else "passed",
            "seed": context["seed"], "strategies": list(args.strategy), "start": args.start,
            "iterations": args.iterations, "packages": context["packages"], "runtime": context["runtime"],
            "platform": context["platform"], "compiler": context["compiler"], "sanitizers": context["sanitizers"],
            "testlab": context["testlab"], "seed_corpora": context["seed_corpora"], **summary, "findings": findings}


def replay(context, path):
    """Rerun a finding's minimized case; it reproduces when the check keeps its outcome."""
    record = json.loads(path.read_text(encoding="utf-8"))
    require(record.get("runner") == RUNNER and record.get("schema") == 1, f"{path} is not a fuzz finding")
    case, check = record["minimized"]["case"], record["check"]
    result = evaluate(context, [case])[0]
    found = result["checks"].get(check)
    print(json.dumps({"id": record["id"], "check": check, "expected": record["minimized"]["result"],
                      "observed": found}, indent=2, sort_keys=True))
    return found is not None and found["outcome"] == record["outcome"]


# --- Reports -----------------------------------------------------------------------------------

def render_summary(summary):
    testlab = summary["testlab"]
    lines = ["# Differential fuzzing summary", "", "Local and private: exploratory inputs and findings stay out of "
             "public issues, CI and artifacts until triage.", "",
             f"- Status: {summary['status']}", f"- Seed: {summary['seed']}; strategies: "
             f"{', '.join(summary['strategies'])}; cases {summary['start']} to "
             f"{summary['start'] + summary['iterations'] - 1} of each",
             f"- TestLab commit: `{testlab['commit'] or 'unknown'}`" +
             (" with uncommitted changes" if testlab["modified"] else ""),
             f"- Runtime: {summary['runtime']}; compiler: {summary['compiler']}; sanitizers: "
             f"{', '.join(summary['sanitizers']) or 'none'}"]
    for name, package in summary["packages"].items():
        lines.append(f"- {name}: " + ", ".join(f"{key} {value}" for key, value in sorted(package.items())))
    lines += ["", "## Findings: untriaged", ""]
    if summary["findings"]:
        lines += ["| Finding | Check | Encoding | Type | Outcome | Occurrences | Minimized |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
        for f in summary["findings"]:
            shown = f["minimized"] if isinstance(f["minimized"], str) else "value"
            lines.append(f"| `{f['id']}` | `{f['check']}` | {f['encoding']} | `{f['type']}` | {f['outcome']} | "
                         f"{f['occurrences']} | `{shown[:64] or '(empty)'}` |")
    else:
        lines.append("None.")
    lines += ["", "## Checks", "", "| Check | Encoding | " + " | ".join(OUTCOMES) + " |",
              "|" + " --- |" * (len(OUTCOMES) + 2)]
    for check, encodings in summary["checks"].items():
        for encoding, counts in encodings.items():
            lines.append(f"| `{check}` | {encoding} | " + " | ".join(str(counts[o]) for o in OUTCOMES) + " |")
    lines += ["", "## Explained differences", "", "| Check | Encoding | Outcome | Rule | Count | Example |",
              "| --- | --- | --- | --- | --- | --- |"]
    for e in summary["explained"]:
        lines.append(f"| `{e['check']}` | {e['encoding']} | {e['outcome']} | `{e['rule']}` | {e['count']} | "
                     f"{e['example']['case']} |")
    lines += ["", "## Input coverage", "",
              "Reference verdicts per encoding: " + "; ".join(f"{encoding} {c['accepted']} accepted, {c['rejected']} "
                                                              f"rejected" for encoding, c in
                                                              sorted(summary["reference"].items())) + ".",
              "", "Cases per type: " + ", ".join(f"`{name}` {count}" for name, count in summary["types"].items()) + "."]
    if summary["mutations"]:
        lines += ["", "Mutations: " + ", ".join(f"{name} {count}" for name, count in summary["mutations"].items()) + "."]
    return "\n".join(lines) + "\n"


def print_summary(summary):
    print(f"Seed {summary['seed']}: " + ", ".join(f"{count} {strategy} cases" for strategy, count in
                                                   summary["cases"].items()))
    totals = dict.fromkeys(OUTCOMES, 0)
    for encodings in summary["checks"].values():
        for counts in encodings.values():
            for outcome, count in counts.items():
                totals[outcome] += count
    print("Checks: " + ", ".join(f"{count} {outcome}" for outcome, count in totals.items()))
    for finding in summary["findings"]:
        print(f"finding {finding['id']}: {finding['check']} {finding['encoding']} {finding['type']} "
              f"{finding['outcome']} ({finding['occurrences']} cases)")
    print(f"{len(summary['findings'])} untriaged findings")


# --- Setup -------------------------------------------------------------------------------------

def check_output_directory(path):
    """Findings must never land in the tracked tree, where they could be committed."""
    resolved = path.resolve()
    require(not resolved.is_relative_to(ROOT) or resolved.is_relative_to(ROOT / "build"),
            f"{path} is in the tracked tree; keep fuzz output under build/ or outside the repository")
    require(not resolved.exists() or not any(resolved.iterdir()), f"{path} must be new or empty")
    return resolved


def load_context(args):
    lua_path = (args.lua_provenance or lua_runner.newest_receipt(args.lua_runs_dir)).resolve()
    asn1c_path = (args.asn1c_provenance or check_asn1c.newest_receipt(args.asn1c_runs_dir)).resolve()
    receipts = der.load_receipts(lua_path, asn1c_path)
    report = json.loads(asn1c_path.read_text(encoding="utf-8"))
    types = der.load_types()
    return {"seed": args.seed, "types": types, "receipts": receipts, "pool": seed_pool(), "timeout": args.timeout,
            "packages": receipts["packages"], "runtime": receipts["runtime"], "platform": receipts["platform"],
            "compiler": receipts["compiler"], "sanitizers": report["adapter"].get("sanitizers", []),
            "provenance": receipts["paths"], "testlab": lua_runner.testlab_revision(),
            "seed_corpora": {p.relative_to(ROOT).as_posix(): digest(p) for p in SEED_CORPORA}}


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seed", type=int, default=1, help="Every case derives from it; default 1")
    parser.add_argument("--strategy", action="append", choices=STRATEGIES,
                        help="Run only this strategy; repeat for both (the default)")
    parser.add_argument("--iterations", type=int, default=500, help="Cases per strategy; default 500")
    parser.add_argument("--start", type=int, default=0, help="First case index, to rerun one case")
    parser.add_argument("--batch-size", type=int, default=200, help="Cases per adapter process; default 200")
    parser.add_argument("--timeout", type=int, default=120, help="Seconds per adapter process; default 120")
    parser.add_argument("--max-findings", type=int, default=50, help="Findings to minimize; others are kept as found")
    parser.add_argument("--minimize-rounds", type=int, default=48, help="Evaluation rounds per minimization")
    parser.add_argument("--output-dir", type=Path, help="New or empty; default build/fuzz/seed-SEED")
    parser.add_argument("--replay", type=Path, metavar="FINDING", help="Rerun a finding's minimized case")
    parser.add_argument("--lua-runs-dir", type=Path, default=ROOT / "build/dependency-runs")
    parser.add_argument("--lua-provenance", type=Path, help="Lua setup receipt; default is the newest complete one")
    parser.add_argument("--asn1c-runs-dir", type=Path, default=asn1c.SANITIZED_RUNS,
                        help="Default build/asn1c-sanitized-runs, from setup_asn1c.py --sanitize")
    parser.add_argument("--asn1c-provenance", type=Path, help="asn1c setup receipt; default is the newest passed one")
    parser.add_argument("--private-ci", action="store_true",
                        help="Allow a CI run, confirming that its logs and artifacts are private")
    args = parser.parse_args(arguments)
    args.strategy = args.strategy or list(STRATEGIES)
    for name in ("iterations", "batch_size", "timeout", "max_findings", "minimize_rounds", "start"):
        if getattr(args, name) < (0 if name in ("max_findings", "minimize_rounds", "start") else 1):
            parser.error(f"--{name.replace('_', '-')} is out of range")
    try:
        require(os.environ.get("GITHUB_ACTIONS") != "true" or args.private_ci,
                "Exploratory fuzzing stays out of public CI: its logs and artifacts would publish untriaged inputs "
                "(docs/differential-fuzzing.md#disclosure-policy)")
        if not args.replay:
            args.output_dir = check_output_directory(args.output_dir or DEFAULT_OUTPUT / f"seed-{args.seed}")
        context = load_context(args)
        if not context["sanitizers"]:
            print("Warning: the asn1c adapter has no sanitizers; run scripts/setup_asn1c.py --sanitize",
                  file=sys.stderr)
        if args.replay:
            return FINDING_EXIT if replay(context, args.replay) else 0
        summary = run_fuzz(context, args)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                                                      encoding="utf-8")
        (args.output_dir / "summary.md").write_text(render_summary(summary), encoding="utf-8")
        print_summary(summary)
        print(f"Summary: {args.output_dir / 'summary.md'}")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Differential fuzzing failed: {error}", file=sys.stderr)
        return 1
    return FINDING_EXIT if summary["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
