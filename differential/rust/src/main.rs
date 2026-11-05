// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

use der_parser::ber::{parse_ber_recursive, BerObject, BerObjectContent, Length};
use der_parser::der::parse_der_recursive;
use der_parser::error::BerError;
use der_parser::nom::Err;

fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// Recover slices only after the library has accepted this object. Tree shape,
// numeric tag, class, P/C and definite content lengths come from the library.
fn nodes(
    object: &BerObject,
    wire: &[u8],
    start: usize,
    depth: usize,
    output: &mut Vec<String>,
) -> Result<usize, &'static str> {
    if depth > 16 || output.len() == 256 {
        return Err("policy: traversal budget exceeded");
    }
    let header = &object.header;
    let mut tag_size = 1;
    if wire[start] & 31 == 31 {
        while wire[start + tag_size] & 128 != 0 {
            tag_size += 1;
        }
        tag_size += 1;
    }
    let first = wire[start + tag_size];
    let length_size = 1 + if first > 128 {
        (first & 127) as usize
    } else {
        0
    };
    let value_offset = start + tag_size + length_size;
    let index = output.len();
    output.push(String::new());
    let mut end = value_offset;
    if header.constructed() {
        match &object.content {
            BerObjectContent::Sequence(children) | BerObjectContent::Set(children) => {
                for child in children {
                    end += nodes(child, wire, end, depth + 1, output)?;
                }
            }
            _ => return Err("generic parser exposes opaque constructed contents"),
        }
    }
    let (value_size, trailer) = match header.length() {
        Length::Definite(length) => (length, 0),
        Length::Indefinite => (end - value_offset, 2),
    };
    if header.constructed() && end != value_offset + value_size {
        return Err("generic parser did not traverse the complete contents");
    }
    let size = value_offset - start + value_size + trailer;
    assert!(start + size <= wire.len());
    output[index] = format!(
        "{{\"offset\":{start},\"size\":{size},\"tag_size\":{tag_size},\"value_offset\":{value_offset},\"value_size\":{value_size},\"depth\":{depth},\"number\":\"{}\",\"class\":{},\"constructed\":{}}}",
        header.tag().0, header.class() as u8, header.constructed()
    );
    Ok(size)
}

fn reject(category: &str, source: &str, stage: &str, native: Option<String>) {
    println!(
        "{{\"result\":\"reject\",\"error\":{{\"category\":\"{category}\",\"source\":\"{source}\",\"stage\":\"{stage}\",\"native_code\":{},\"offset\":null}}}}",
        native.map_or("null".into(), |s| quoted(&s))
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[1].as_str(), "ber" | "der") {
        std::process::exit(2);
    }
    let hex = args[2].as_bytes();
    if hex.len() % 2 != 0 || hex.len() > 8192 || !hex.iter().all(u8::is_ascii_hexdigit) {
        std::process::exit(2);
    }
    let wire: Vec<u8> = args[2]
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    if wire.is_empty() {
        reject("empty", "adapter", "policy", None);
        return;
    }
    // Recursion fuel is deliberately separate from normalized constructed depth.
    let parsed = if args[1] == "der" {
        parse_der_recursive(&wire, 32)
    } else {
        parse_ber_recursive(&wire, 32)
    };
    match parsed {
        Ok((rest, object)) => {
            if !rest.is_empty() {
                reject("trailing", "adapter", "policy", None);
                return;
            }
            let mut output = Vec::new();
            match nodes(&object, &wire, 0, 0, &mut output) {
                Ok(consumed) => {
                    assert_eq!(consumed, wire.len());
                    println!(
                        "{{\"result\":\"accept\",\"consumed\":{consumed},\"nodes\":[{}]}}",
                        output.join(",")
                    );
                }
                Err(reason) if reason.starts_with("policy:") => {
                    reject("limit", "policy", "policy", None)
                }
                Err(reason) => println!(
                    "{{\"result\":\"unsupported\",\"reason\":{}}}",
                    quoted(reason)
                ),
            }
        }
        Err(error) => {
            if matches!(
                &error,
                Err::Error(BerError::Unsupported) | Err::Failure(BerError::Unsupported)
            ) {
                println!(
                    "{{\"result\":\"unsupported\",\"reason\":\"library Error(Unsupported)\"}}"
                );
                return;
            }
            let (category, stage) = match &error {
                Err::Incomplete(_) => ("truncated", "framing"),
                Err::Error(e) | Err::Failure(e) => match e {
                    // This is an incomplete child inside a successfully delimited
                    // parent (SequenceIterator wraps nom::Incomplete as Error).
                    BerError::Incomplete(_) => ("invalid", "framing"),
                    BerError::InvalidTag
                    | BerError::InvalidLength
                    | BerError::IndefiniteLengthUnexpected
                    | BerError::ConstructExpected
                    | BerError::ConstructUnexpected => ("invalid", "framing"),
                    BerError::DerConstraintFailed(_) => ("invalid", "canonicality"),
                    BerError::BerValueError
                    | BerError::InvalidValue { .. }
                    | BerError::StringInvalidCharset => ("invalid", "contents"),
                    BerError::BerMaxDepth => ("limit", "policy"),
                    _ => ("unknown", "unknown"),
                },
            };
            reject(category, "library", stage, Some(format!("{error:?}")));
        }
    }
}
