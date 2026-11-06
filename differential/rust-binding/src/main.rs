// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

#![forbid(unsafe_code)]

use opentlv::{Error, Format, FormatRef, Limits, Strictness};

#[derive(Debug)]
struct Failure {
    category: &'static str,
    source: &'static str,
    stage: &'static str,
    native: Option<Error>,
    offset: Option<usize>,
}

fn policy(category: &'static str) -> Failure {
    Failure {
        category,
        source: "adapter",
        stage: "policy",
        native: None,
        offset: None,
    }
}

fn failure(error: Error, bounded: bool, offset: Option<usize>) -> Failure {
    if error == Error::OutOfMemory {
        std::process::exit(2);
    }
    let (category, stage) = match error {
        Error::Truncated => (if bounded { "invalid" } else { "truncated" }, "framing"),
        Error::InvalidTag | Error::InvalidTagSize | Error::InvalidLength => ("invalid", "framing"),
        Error::InvalidValue => ("invalid", "contents"),
        Error::Limit => ("limit", "policy"),
        _ => ("unknown", "unknown"),
    };
    Failure {
        category,
        stage,
        source: "library",
        native: Some(error),
        offset,
    }
}

// Tag::as_bytes exposes the accepted identifier. Decimal/class/P-C projection
// is adapter presentation, NOT evidence of a public tlv_ber_tag_number wrapper.
fn tag_number(tag: &[u8]) -> u64 {
    if tag[0] & 31 != 31 {
        return u64::from(tag[0] & 31);
    }
    tag[1..].iter().fold(0u64, |n, b| {
        n.checked_mul(128)
            .and_then(|n| n.checked_add(u64::from(b & 127)))
            .expect("accepted tag exceeds normalized numeric domain")
    })
}

fn walk(
    format: Format,
    data: &[u8],
    start: usize,
    depth: usize,
    nodes: &mut Vec<String>,
) -> Result<usize, Failure> {
    if depth > 16 || nodes.len() == 256 {
        let mut error = policy("limit");
        error.source = "policy";
        return Err(error);
    }
    let decoded = FormatRef::from(format)
        .decode(data)
        .map_err(|e| failure(e.error, depth != 0, e.offset.map(|n| start + n)))?;
    let layout = decoded.layout();
    let value = decoded.element.value();
    let tag = decoded.element.tag().as_bytes();
    let value_start = layout.value.expect("BER/DER value range").start;
    let size = decoded.encoded().len();
    let constructed = tag[0] & 32 != 0;
    nodes.push(format!(
        "{{\"offset\":{start},\"size\":{size},\"tag_size\":{},\"value_offset\":{},\"value_size\":{},\"depth\":{depth},\"number\":\"{}\",\"class\":{},\"constructed\":{constructed}}}",
        tag.len(), start + value_start, value.len(), tag_number(tag), tag[0] >> 6
    ));
    if constructed {
        let mut position = 0;
        while position < value.len() {
            let used = walk(
                format,
                &value[position..],
                start + value_start + position,
                depth + 1,
                nodes,
            )?;
            assert!(used > 0 && used <= value.len() - position);
            position += used;
        }
    }
    Ok(size)
}

fn observe(format: Format, wire: &[u8]) -> Result<Vec<String>, Failure> {
    if wire.is_empty() {
        return Err(policy("empty"));
    }
    if format == Format::Der {
        let limits = Limits {
            max_depth: 16,
            max_input_size: 4096,
            max_value_size: 4096,
            max_elements: 256,
        };
        format
            .read(wire, &limits, Strictness::Strict)
            .map_err(|e| failure(e.error, false, e.location.offset()))?;
    }
    let mut nodes = Vec::new();
    let consumed = walk(format, wire, 0, 0, &mut nodes)?;
    if consumed != wire.len() {
        return Err(policy("trailing"));
    }
    Ok(nodes)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--version" {
        println!("{}", opentlv::version());
        return;
    }
    if args.len() != 3 || !matches!(args[1].as_str(), "ber" | "der") {
        std::process::exit(2);
    }
    let hex = args[2].as_bytes();
    if hex.len() % 2 != 0 || hex.len() > 8192 || !hex.iter().all(u8::is_ascii_hexdigit) {
        std::process::exit(2);
    }
    let wire: Vec<u8> = hex
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    match observe(
        if args[1] == "der" {
            Format::Der
        } else {
            Format::Ber
        },
        &wire,
    ) {
        Ok(nodes) => println!(
            "{{\"result\":\"accept\",\"consumed\":{},\"nodes\":[{}]}}",
            wire.len(),
            nodes.join(",")
        ),
        Err(e) => {
            // Native Core error descriptions contain printable ASCII, no quotes/backslashes.
            let native = e
                .native
                .map_or("null".into(), |n| format!("\"{}: {n}\"", n.code()));
            let offset = e.offset.map_or("null".into(), |n| n.to_string());
            println!("{{\"result\":\"reject\",\"error\":{{\"category\":\"{}\",\"source\":\"{}\",\"stage\":\"{}\",\"native_code\":{native},\"offset\":{offset}}}}}", e.category, e.source, e.stage);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentlv::{Element, Tag};

    #[test]
    fn public_framing_preserves_indefinite_and_non_universal_children() {
        let wire = [0xe1, 0x80, 0x04, 1, 0x61, 0, 0];
        let nodes = observe(Format::Ber, &wire).unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes[0].contains("\"class\":3"));
        let decoded = FormatRef::from(Format::Ber).decode(&wire).unwrap();
        assert_eq!(decoded.encoded(), wire);
        assert_eq!(decoded.raw_length(), [0x80]);
        assert_eq!(decoded.layout().trailer, Some(5..7));
        assert_eq!(decoded.element.value(), [4, 1, 0x61]);
    }

    #[test]
    fn strict_der_rejects_root_and_nested_noncanonical_values() {
        for wire in [
            &[1, 1, 1][..],
            &[0x30, 3, 1, 1, 1],
            &[2, 2, 0, 1],
            &[0x30, 0x80, 0, 0],
        ] {
            assert_eq!(observe(Format::Der, wire).unwrap_err().category, "invalid");
        }
        assert!(observe(Format::Der, &[0x30, 3, 1, 1, 0xff]).is_ok());
        assert!(observe(Format::Ber, &[1, 1, 1]).is_ok());
    }

    #[test]
    fn public_errors_and_single_root_policy_stay_separate() {
        assert_eq!(observe(Format::Ber, &[]).unwrap_err().source, "adapter");
        assert_eq!(
            observe(Format::Ber, &[5, 0, 5, 0]).unwrap_err().category,
            "trailing"
        );
        let truncated = observe(Format::Ber, &[4, 2, 1]).unwrap_err();
        assert_eq!(truncated.native, Some(Error::Truncated));
        assert_eq!(truncated.category, "truncated");
        assert_eq!(
            observe(Format::Ber, &[0x30, 2, 4, 1]).unwrap_err().category,
            "invalid"
        );
    }

    #[test]
    fn public_encode_round_trip_and_limits() {
        let tag = Tag::from_bytes(&[2]);
        let element = Element::new(tag.clone(), &[5]);
        let ber = FormatRef::from(Format::Ber);
        let wire = ber.encode(&element).unwrap();
        assert_eq!(wire, [2, 1, 5]);
        assert_eq!(ber.decode(&wire).unwrap().element, element);
        let mut limits = Format::Der.default_limits().unwrap();
        let mut output = [0; 8];
        assert_eq!(
            Format::Der
                .write(&tag, &[5], &limits, Strictness::Strict, &mut output)
                .unwrap(),
            3
        );
        assert_eq!(&output[..3], &wire);
        limits.max_elements = 0;
        assert_eq!(
            Format::Der
                .read(&wire, &limits, Strictness::Strict)
                .unwrap_err()
                .error,
            Error::Limit
        );
    }
}
