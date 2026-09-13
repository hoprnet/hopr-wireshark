//! Parsers for the libp2p framing that sits between TCP and the HOPR packet stream.
//!
//! These are pure functions over byte slices with no Wireshark types in sight, so they can be
//! unit-tested directly. Each returns [`Incomplete`] rather than an error when the input is merely
//! short, which is what the dissector turns into a request for more TCP segments.

pub mod multistream;
pub mod plaintext;
pub mod yamux;

/// Outcome of parsing one unit out of a byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed<T> {
    /// A complete unit, and how many bytes it consumed.
    Done { value: T, consumed: usize },
    /// Not enough bytes yet.
    ///
    /// `needed` is the total size of the unit when that is already known from a length field, or
    /// `None` when even that much has not arrived.
    Incomplete { needed: Option<usize> },
    /// The bytes are not a valid unit of this kind, with a reason to show the user.
    Invalid(&'static str),
}

/// Reads an unsigned LEB128 varint, the length prefix libp2p uses throughout.
///
/// Capped at five bytes / 32 bits, matching the `unsigned-varint` spec's `u32` profile that
/// multistream-select and the plaintext handshake are defined against. A longer encoding is a
/// framing error rather than a big number, and saying so early stops a desync from being read as
/// a multi-gigabyte length.
pub fn uvarint(bytes: &[u8]) -> Parsed<u32> {
    let mut value: u64 = 0;
    for (i, b) in bytes.iter().take(5).enumerate() {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            if value > u64::from(u32::MAX) {
                return Parsed::Invalid("varint exceeds 32 bits");
            }
            // Only the first byte of a varint may be zero; anything else is a non-minimal
            // encoding, which libp2p's decoder rejects too.
            if i > 0 && *b == 0 {
                return Parsed::Invalid("non-minimal varint encoding");
            }
            return Parsed::Done {
                value: value as u32,
                consumed: i + 1,
            };
        }
    }
    if bytes.len() < 5 {
        Parsed::Incomplete { needed: None }
    } else {
        Parsed::Invalid("varint longer than five bytes")
    }
}

/// Reads a varint-length-prefixed byte string.
///
/// Both multistream-select messages and the plaintext handshake's protobuf are framed this way,
/// which is why the dissector can walk the pre-multiplexer part of the stream without yet knowing
/// which of the two it is looking at.
pub fn length_prefixed(bytes: &[u8], max_len: usize) -> Parsed<&[u8]> {
    let (len, header) = match uvarint(bytes) {
        Parsed::Done { value, consumed } => (value as usize, consumed),
        Parsed::Incomplete { needed } => return Parsed::Incomplete { needed },
        Parsed::Invalid(why) => return Parsed::Invalid(why),
    };

    if len > max_len {
        return Parsed::Invalid("length prefix implausibly large for this protocol");
    }

    let total = header + len;
    if bytes.len() < total {
        return Parsed::Incomplete { needed: Some(total) };
    }

    Parsed::Done {
        value: &bytes[header..total],
        consumed: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uvarint_should_read_single_byte_values() {
        assert_eq!(uvarint(&[0x00]), Parsed::Done { value: 0, consumed: 1 });
        assert_eq!(
            uvarint(&[0x7f]),
            Parsed::Done {
                value: 127,
                consumed: 1
            }
        );
    }

    #[test]
    fn uvarint_should_read_multi_byte_values() {
        assert_eq!(
            uvarint(&[0x80, 0x01]),
            Parsed::Done {
                value: 128,
                consumed: 2
            }
        );
        assert_eq!(
            uvarint(&[0xff, 0xff, 0xff, 0xff, 0x0f]),
            Parsed::Done {
                value: u32::MAX,
                consumed: 5
            }
        );
    }

    #[test]
    fn uvarint_should_report_a_truncated_encoding_as_incomplete() {
        assert_eq!(uvarint(&[]), Parsed::Incomplete { needed: None });
        assert_eq!(uvarint(&[0x80]), Parsed::Incomplete { needed: None });
    }

    #[test]
    fn uvarint_should_reject_encodings_that_cannot_be_valid() {
        // Six continuation bytes: past the u32 profile's ceiling.
        assert!(matches!(uvarint(&[0x80; 6]), Parsed::Invalid(_)));
        // Overflows 32 bits even though it is five bytes.
        assert!(matches!(uvarint(&[0xff, 0xff, 0xff, 0xff, 0x7f]), Parsed::Invalid(_)));
        // 0x80 0x00 encodes zero in two bytes; libp2p's decoder rejects it, so must this.
        assert!(matches!(uvarint(&[0x80, 0x00]), Parsed::Invalid(_)));
    }

    #[test]
    fn length_prefixed_should_split_header_from_body() {
        assert_eq!(
            length_prefixed(b"\x03abcdef", 100),
            Parsed::Done {
                value: b"abc".as_slice(),
                consumed: 4
            }
        );
    }

    #[test]
    fn length_prefixed_should_report_the_full_size_it_is_waiting_for() {
        assert_eq!(
            length_prefixed(b"\x10abc", 100),
            Parsed::Incomplete { needed: Some(17) },
            "a known length must be reported so the caller can ask for exactly that much"
        );
    }

    #[test]
    fn length_prefixed_should_reject_a_length_beyond_the_protocol_maximum() {
        assert!(
            matches!(length_prefixed(b"\xff\xff\x03", 100), Parsed::Invalid(_)),
            "a desynchronised stream must not be read as a huge frame"
        );
    }
}
