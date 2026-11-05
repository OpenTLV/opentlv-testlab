#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

"""Independent ITU-T X.690 BER and CER reference for hand-written fixtures.

`decode()` reads BER or CER into the typed values of the asn1c adapter, or raises `Invalid`
with a normalized error; `cer_encode()` writes the CER encoding of a typed value. Neither
shares code with OpenTLV or asn1c. A fixture that disagrees with them is a fixture error, and
an encoder whose output they read as another value fails its check.
"""

import argparse
import json
import sys

if __package__:
    from .run_der_differential import LEAVES, der_length, identifier_number, leaf_contents, load_types, set_of_key
else:
    from run_der_differential import LEAVES, der_length, identifier_number, leaf_contents, load_types, set_of_key

RULES = ("ber", "cer")
STRINGS = ("bit_string", "octet_string", "ia5string")
# A restricted character string is encoded as an implicitly tagged OCTET STRING (8.23.5),
# so its segments are OCTET STRING encodings.
SEGMENT_IDENTIFIERS = {"bit_string": b"\x03", "octet_string": b"\x04", "ia5string": b"\x04"}
SEGMENT_OCTETS = 1000  # X.690 9.2
MAX_DEPTH = 32


class Invalid(ValueError):
    """Input that is not a valid encoding: `error` is empty, truncated, trailing or invalid."""

    def __init__(self, error, detail):
        super().__init__(f"{error}: {detail}")
        self.error = error
        self.detail = detail


class Element:
    def __init__(self, identifier, constructed, contents, children, encoding):
        self.identifier, self.constructed = identifier, constructed
        self.contents, self.children, self.encoding = contents, children, encoding


def missing(open_end, detail):
    """A missing octet truncates the input only while no definite length bounds the element."""
    raise Invalid("truncated" if open_end else "invalid", detail)


def parse_identifier(data, position, end, open_end):
    if position >= end:
        missing(open_end, "missing identifier")
    first = data[position]
    position += 1
    number = first & 0x1F
    if number == 0x1F:
        if position < end and data[position] == 0x80:
            raise Invalid("invalid", "tag number with a leading zero septet (8.1.2.4.2)")
        number = 0
        while True:
            if position >= end:
                missing(open_end, "unterminated tag number")
            octet = data[position]
            position += 1
            number = number << 7 | octet & 0x7F
            if not octet & 0x80:
                break
        if number < 31:
            raise Invalid("invalid", "high-tag-number form for a tag number below 31 (8.1.2.2)")
    if first & 0xC0 == 0 and number == 0:
        raise Invalid("invalid", "end-of-contents outside an indefinite-length value (8.1.5)")
    return bool(first & 0x20), position


def parse_element(data, position, end, open_end, rules, depth):
    """One element from `position`; `end` is the input end or the enclosing definite length."""
    if depth > MAX_DEPTH:
        raise Invalid("invalid", f"nested deeper than {MAX_DEPTH} levels")
    start = position
    constructed, position = parse_identifier(data, position, end, open_end)
    identifier = data[start:position]
    if position >= end:
        missing(open_end, "missing length")
    first = data[position]
    position += 1
    children, contents = [], None
    if first == 0x80:
        if not constructed:
            raise Invalid("invalid", "indefinite length on a primitive value (8.1.3.2)")
        while True:
            if position >= end:
                missing(open_end, "missing end-of-contents")
            if data[position] == 0:
                if position + 1 >= end:
                    missing(open_end, "truncated end-of-contents")
                if data[position + 1] != 0:
                    raise Invalid("invalid", "end-of-contents with a nonzero length (8.1.5)")
                position += 2
                break
            child, position = parse_element(data, position, end, open_end, rules, depth + 1)
            children.append(child)
    else:
        if first == 0xFF:
            raise Invalid("invalid", "reserved length octet ff (8.1.3.5)")
        if rules == "cer" and constructed:
            raise Invalid("invalid", "definite length on a constructed value (9.1)")
        length = first
        if first & 0x80:
            count = first & 0x7F
            if position + count > end:
                missing(open_end, "missing length octets")
            octets = data[position:position + count]
            position += count
            length = int.from_bytes(octets, "big")
            if rules == "cer" and (length < 0x80 or octets[0] == 0):
                raise Invalid("invalid", "length not in its fewest octets (9.1)")
        if position + length > end:
            missing(open_end, "value past the end of its container")
        stop = position + length
        if constructed:
            while position < stop:
                child, position = parse_element(data, position, stop, False, rules, depth + 1)
                children.append(child)
        else:
            contents = data[position:stop]
        position = stop
    return Element(identifier, constructed, contents, children, data[start:position]), position


def parse(data, rules):
    if not data:
        raise Invalid("empty", "no input")
    element, end = parse_element(data, 0, len(data), True, rules, 0)
    if end != len(data):
        raise Invalid("trailing", f"{len(data) - end} octets after the value")
    return element


# --- Typed values ------------------------------------------------------------------------------

def primitive_identifier(identifier):
    return bytes([identifier[0] & ~0x20]) + identifier[1:]


def matches(schema, element):
    if schema["kind"] == "choice":
        return any(matches(alternative["type"], element) for alternative in schema["alternatives"])
    identifier = element.identifier
    if schema["kind"] in STRINGS and element.constructed:
        identifier = primitive_identifier(identifier)
    return identifier.hex() == schema["identifier"]


def segments(kind, element, rules):
    """Contents octets of each primitive segment of a constructed string (8.6.4, 8.7.3)."""
    found = []
    for child in element.children:
        if primitive_identifier(child.identifier) != SEGMENT_IDENTIFIERS[kind]:
            raise Invalid("invalid", f"segment with identifier {child.identifier.hex()} (8.6.4, 8.7.3)")
        if child.constructed:
            if rules == "cer":
                raise Invalid("invalid", "constructed segment (9.2)")
            found += segments(kind, child, rules)
        else:
            found.append(child.contents)
    return found


def string_contents(kind, element, rules):
    """The contents of a string in either form, as one primitive encoding would hold them."""
    if not element.constructed:
        if rules == "cer" and len(element.contents) > SEGMENT_OCTETS:
            raise Invalid("invalid", f"primitive string of more than {SEGMENT_OCTETS} octets (9.2)")
        return element.contents
    parts = segments(kind, element, rules)
    if rules == "cer":
        if sum(map(len, parts)) - (len(parts) - 1) * (kind == "bit_string") <= SEGMENT_OCTETS:
            raise Invalid("invalid", f"constructed string of at most {SEGMENT_OCTETS} octets (9.2)")
        if any(len(part) != SEGMENT_OCTETS for part in parts[:-1]) or not parts[-1]:
            raise Invalid("invalid", f"segment that is not {SEGMENT_OCTETS} octets (9.2)")
    if kind != "bit_string":
        return b"".join(parts)
    if not parts:
        return b"\x00"
    for part in parts:
        if not part:
            raise Invalid("invalid", "BIT STRING segment without its initial octet (8.6.2)")
    if any(part[0] for part in parts[:-1]):
        raise Invalid("invalid", "unused bits in a segment other than the last (8.6.4)")
    return parts[-1][:1] + b"".join(part[1:] for part in parts)


def leaf_value(kind, contents, rules):
    if kind == "boolean":
        if len(contents) != 1:
            raise Invalid("invalid", "BOOLEAN contents are one octet (8.2.1)")
        if rules == "cer" and contents[0] not in (0x00, 0xFF):
            raise Invalid("invalid", "CER TRUE is ff (11.1)")
        return {"kind": kind, "value": contents[0] != 0}
    if kind == "integer":
        if not contents:
            raise Invalid("invalid", "INTEGER without contents (8.3.1)")
        if len(contents) > 1 and (contents[0], contents[1] & 0x80) in ((0x00, 0), (0xFF, 0x80)):
            raise Invalid("invalid", "INTEGER not in its fewest octets (8.3.2)")
        return {"kind": kind, "value": str(int.from_bytes(contents, "big", signed=True))}
    if kind == "null":
        if contents:
            raise Invalid("invalid", "NULL has no contents (8.8.2)")
        return {"kind": kind}
    if kind == "object_identifier":
        if not contents or contents[-1] & 0x80:
            raise Invalid("invalid", "OBJECT IDENTIFIER needs complete subidentifiers (8.19.2)")
        arcs, value, first = [], 0, True
        for octet in contents:
            if first and octet == 0x80:
                raise Invalid("invalid", "subidentifier with a leading 80 octet (8.19.2)")
            value, first = value << 7 | octet & 0x7F, not octet & 0x80
            if first:
                arcs.append(value)
                value = 0
        head = min(arcs[0] // 40, 2)
        return {"kind": kind, "value": ".".join(map(str, [head, arcs[0] - 40 * head, *arcs[1:]]))}
    if kind == "bit_string":
        if not contents:
            raise Invalid("invalid", "BIT STRING without its initial octet (8.6.2)")
        unused, data = contents[0], bytearray(contents[1:])
        if unused > 7 or (unused and not data):
            raise Invalid("invalid", "invalid number of unused bits (8.6.2.2, 8.6.2.3)")
        if data and data[-1] & ((1 << unused) - 1):
            if rules == "cer":
                raise Invalid("invalid", "CER unused bits are zero (11.2.1)")
            data[-1] &= 0xFF << unused & 0xFF  # The sender's choice; not part of the value (8.6.2.3).
        return {"kind": kind, "unused_bits": unused, "value": data.hex()}
    if kind == "ia5string" and any(octet >= 0x80 for octet in contents):
        raise Invalid("invalid", "IA5String octet above 7f")
    return {"kind": kind, "value": contents.hex()}


def check_default(field, value, rules):
    if rules == "cer" and "default" in field and value == field["default"]:
        raise Invalid("invalid", f"component {field['name']} encodes its DEFAULT value (11.5)")


def fields_value(schema, found, rules, depth):
    fields = []
    for field in schema["fields"]:
        if field["name"] in found:
            value = value_of(field["type"], found[field["name"]], rules, depth + 1)
            check_default(field, value, rules)
            fields.append({"name": field["name"], "value": value})
        elif "default" in field:
            fields.append({"name": field["name"], "value": field["default"]})
        elif not field.get("optional"):
            raise Invalid("invalid", f"missing component {field['name']}")
    return fields


def sequence_value(schema, element, rules, depth):
    children, found, index = element.children, {}, 0
    for field in schema["fields"]:
        if index < len(children) and matches(field["type"], children[index]):
            found[field["name"]] = children[index]
            index += 1
    if index < len(children):
        raise Invalid("invalid", f"unexpected component {children[index].identifier.hex()}")
    return {"kind": "sequence", "fields": fields_value(schema, found, rules, depth)}


def set_value(schema, element, rules, depth):
    found, order = {}, []
    for child in element.children:
        field = next((f for f in schema["fields"] if matches(f["type"], child)), None)
        if field is None:
            raise Invalid("invalid", f"unexpected component {child.identifier.hex()}")
        if field["name"] in found:
            raise Invalid("invalid", f"repeated component {field['name']}")
        found[field["name"]] = child
        order.append(identifier_number(child.identifier.hex()))
    if rules == "cer" and order != sorted(order):
        raise Invalid("invalid", "SET components out of tag order (9.3)")
    return {"kind": "set", "fields": fields_value(schema, found, rules, depth)}


def value_of(schema, element, rules, depth=0):
    kind = schema["kind"]
    if kind == "choice":
        for alternative in schema["alternatives"]:
            if matches(alternative["type"], element):
                return {"kind": "choice", "alternative": alternative["name"],
                        "value": value_of(alternative["type"], element, rules, depth + 1)}
        raise Invalid("invalid", f"no alternative has identifier {element.identifier.hex()}")
    if not matches(schema, element):
        raise Invalid("invalid", f"expected identifier {schema['identifier']}, found {element.identifier.hex()}")
    if kind in LEAVES:
        if element.constructed and kind not in STRINGS:
            raise Invalid("invalid", f"{kind} in constructed form (8.2.1, 8.3.1, 8.8.1, 8.19.1)")
        contents = string_contents(kind, element, rules) if kind in STRINGS else element.contents
        return leaf_value(kind, contents, rules)
    if kind == "explicit":
        if len(element.children) != 1:
            raise Invalid("invalid", "an explicit tag holds exactly one value (8.14.2)")
        return value_of(schema["inner"], element.children[0], rules, depth + 1)
    if kind == "sequence":
        return sequence_value(schema, element, rules, depth)
    if kind == "set":
        return set_value(schema, element, rules, depth)
    items = [value_of(schema["item"], child, rules, depth + 1) for child in element.children]
    if kind == "set_of" and rules == "cer":
        encodings = [child.encoding for child in element.children]
        width = max(map(len, encodings), default=0)
        if encodings != sorted(encodings, key=lambda encoding: set_of_key(encoding, width)):
            raise Invalid("invalid", "SET OF components out of order (11.6)")
    return {"kind": kind, "items": items}


def decode(schema, data, rules):
    """The typed value of `data` under BER or CER; `Invalid` names why it has none."""
    return value_of(schema, parse(data, rules), rules)


# --- CER encoder -------------------------------------------------------------------------------

def indefinite(identifier, contents):
    return bytes.fromhex(identifier) + b"\x80" + contents + b"\x00\x00"


def string_encoding(kind, identifier, contents):
    """Primitive up to 1000 contents octets, otherwise 1000-octet primitive segments (9.2)."""
    if len(contents) <= SEGMENT_OCTETS:
        return bytes.fromhex(identifier) + der_length(len(contents)) + contents
    tag = SEGMENT_IDENTIFIERS[kind]
    constructed = bytes([bytes.fromhex(identifier)[0] | 0x20]).hex() + identifier[2:]
    if kind == "bit_string":
        step, data = SEGMENT_OCTETS - 1, contents[1:]
        chunks = [data[i:i + step] for i in range(0, len(data), step)]
        parts = [b"\x00" + chunk for chunk in chunks[:-1]] + [contents[:1] + chunks[-1]]
    else:
        parts = [contents[i:i + SEGMENT_OCTETS] for i in range(0, len(contents), SEGMENT_OCTETS)]
    return indefinite(constructed, b"".join(tag + der_length(len(part)) + part for part in parts))


def cer_encode(schema, value):
    kind = schema["kind"]
    if kind == "choice":
        alternative = next((a for a in schema["alternatives"] if a["name"] == value.get("alternative")), None)
        if value.get("kind") != "choice" or alternative is None:
            raise ValueError("Value is not an alternative of the CHOICE")
        return cer_encode(alternative["type"], value["value"])
    if kind == "explicit":
        return indefinite(schema["identifier"], cer_encode(schema["inner"], value))
    if value.get("kind") != kind:
        raise ValueError(f"Value of kind {value.get('kind')} does not match {kind}")
    if kind in LEAVES:
        return string_encoding(kind, schema["identifier"], leaf_contents(kind, value))
    if kind in ("sequence", "set"):
        names = [field["name"] for field in value["fields"]]
        if names != [field["name"] for field in schema["fields"] if field["name"] in names]:
            raise ValueError(f"{kind} fields out of definition order")
        given = {field["name"]: field["value"] for field in value["fields"]}
        parts = []
        for field in schema["fields"]:
            if field["name"] not in given:
                if not field.get("optional") and "default" not in field:
                    raise ValueError(f"Missing component {field['name']}")
            elif given[field["name"]] != field.get("default"):  # CER omits a DEFAULT value (11.5).
                parts.append((identifier_number(field["type"]["identifier"]),
                              cer_encode(field["type"], given[field["name"]])))
        if kind == "set":
            parts.sort(key=lambda part: part[0])  # Tag order (9.3).
        return indefinite(schema["identifier"], b"".join(part for _, part in parts))
    encodings = [cer_encode(schema["item"], item) for item in value["items"]]
    if kind == "set_of":
        width = max(map(len, encodings), default=0)
        encodings.sort(key=lambda encoding: set_of_key(encoding, width))  # Ascending encodings (11.6).
    return indefinite(schema["identifier"], b"".join(encodings))


def main(arguments=None):
    parser = argparse.ArgumentParser(description="Decode hex with the X.690 reference, as a fixture expects it")
    parser.add_argument("type", help="Schema type of TestLabReference-1")
    parser.add_argument("wire", nargs="?", default="", help="Hex octets; spaces are allowed")
    parser.add_argument("--encoding", choices=RULES, default="ber")
    args = parser.parse_args(arguments)
    types = load_types()
    if args.type not in types:
        parser.error(f"unknown type {args.type}; choose one of {', '.join(types)}")
    try:
        value = decode(types[args.type], bytes.fromhex(args.wire), args.encoding)
    except Invalid as error:
        print(json.dumps({"result": "reject", "error": error.error, "detail": error.detail}))
        return 1
    result = "accept" if args.encoding == "ber" else "canonical"
    if args.encoding == "cer" and cer_encode(types[args.type], value) != bytes.fromhex(args.wire):
        raise AssertionError("A CER decoding must re-encode to its input")
    print(json.dumps({"result": result, "value": value}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
