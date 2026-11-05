// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

//! Pinned reference capability observations. The executable never uses fixture expectations.

#[cfg(test)]
mod tests {
    use der_parser::ber::{parse_ber_recursive, BerObjectContent, Class, Length};
    use der_parser::der::parse_der_recursive;
    use der_parser::{parse_ber, parse_der};

    #[test]
    fn generic_parser_accepts_reviewed_nonminimal_headers() {
        // These are divergences from the independent X.690 fixtures, not new
        // expectations or exclusions in the shared differential denominator.
        assert!(parse_ber(&[0x9f, 0x80, 0x1f, 1, 0xaa]).is_ok());
        for wire in [
            &[4, 0x81, 1, 0xaa][..],
            &[4, 0x82, 0, 1, 0xaa],
            &[0x9f, 0x1e, 1, 0xaa],
        ] {
            assert!(parse_der(wire).is_ok());
        }
    }

    #[test]
    fn incomplete_high_tags_use_invalid_tag_not_incomplete() {
        use der_parser::error::BerError;
        use der_parser::nom::Err;
        assert_eq!(
            parse_ber(&[0x9f, 0x81]),
            Err(Err::Error(BerError::InvalidTag))
        );
        assert_eq!(parse_der(&[0x9f]), Err(Err::Error(BerError::InvalidTag)));
    }

    #[test]
    fn canonical_integer_is_accepted_in_both_modes() {
        for parse in [parse_ber, parse_der] {
            let (rest, object) = parse(&[2, 1, 42]).expect("canonical INTEGER");
            assert!(rest.is_empty());
            assert_eq!(object.as_u32().unwrap(), 42);
        }
    }

    #[test]
    fn ber_indefinite_sequence_preserves_length_and_children() {
        let wire = [0x30, 0x80, 2, 1, 42, 0, 0];
        let (rest, object) = parse_ber(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(object.header.length(), Length::Indefinite);
        assert_eq!(object.as_sequence().unwrap().len(), 1);
        assert_eq!(object[0].as_u32().unwrap(), 42);
        assert!(parse_der(&wire).is_err());
    }

    #[test]
    fn der_checks_root_boolean_and_integer_contents() {
        for wire in [&[1, 1, 1][..], &[2, 2, 0, 1]] {
            assert!(parse_ber(wire).is_ok());
            assert!(parse_der(wire).is_err());
        }
    }

    #[test]
    fn der_generic_recursion_does_not_validate_nested_boolean() {
        // src/der/parser.rs delegates SEQUENCE contents to BER recursion.
        // This observation is not a claim that these bytes are canonical DER.
        let wire = [0x30, 3, 1, 1, 1];
        assert!(parse_der(&wire).is_ok());
        assert!(parse_der(&wire[2..]).is_err());
    }

    #[test]
    fn non_universal_constructed_contents_are_opaque() {
        let (_, object) = parse_der(&[0xa0, 3, 2, 1, 1]).unwrap();
        assert_eq!(object.header.class(), Class::ContextSpecific);
        assert!(object.header.is_constructed());
        assert!(matches!(object.content, BerObjectContent::Unknown(_)));
    }

    #[test]
    fn high_tag_and_non_universal_classes_are_preserved() {
        for (first, class) in [
            (0x5f, Class::Application),
            (0x9f, Class::ContextSpecific),
            (0xdf, Class::Private),
        ] {
            let wire = [first, 0x81, 0x48, 1, 0x41];
            let (rest, object) = parse_ber(&wire).unwrap();
            assert!(rest.is_empty());
            assert_eq!(object.header.class(), class);
            assert_eq!(object.header.tag().0, 200);
        }
    }

    #[test]
    fn remainder_is_not_a_library_rejection() {
        for parse in [parse_ber, parse_der] {
            let (rest, _) = parse(&[5, 0, 5, 0]).unwrap();
            assert_eq!(rest, &[5, 0]);
        }
    }

    #[test]
    fn schema_order_is_not_checked_by_generic_der() {
        assert!(parse_der(&[0x31, 6, 2, 1, 2, 2, 1, 1]).is_ok());
    }

    #[test]
    fn constructed_octet_strings_are_not_reassembled_by_ber() {
        let (_, object) = parse_ber(&[0x24, 3, 4, 1, 0x41]).unwrap();
        assert!(object.header.is_constructed());
        assert_eq!(object.as_slice().unwrap(), &[4, 1, 0x41]);
    }

    #[test]
    fn truncated_input_and_explicit_recursion_budget_fail() {
        for parse in [parse_ber, parse_der] {
            assert!(parse(&[]).is_err());
            assert!(parse(&[2, 2, 1]).is_err());
        }
        for parse in [parse_ber_recursive, parse_der_recursive] {
            assert!(parse(&[0x30, 2, 0x30, 0], 1).is_err());
            assert!(parse(&[0x30, 2, 0x30, 0], 4).is_ok());
        }
    }
}
