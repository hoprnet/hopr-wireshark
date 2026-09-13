//! multistream-select 1.0, the protocol negotiation libp2p runs before every other protocol.
//!
//! A message is a varint-length-prefixed line ending in `\n`. Both sides open with
//! `/multistream/1.0.0`; the dialer then proposes a protocol and the listener either echoes it
//! (accepted) or answers `na` (not available). The same exchange happens three times on a HOPR
//! connection: once on the raw TCP stream to pick the security protocol, once on the secured
//! stream to pick the multiplexer, and once inside every multiplexed substream to pick the
//! application protocol.

use crate::wire::{Parsed, length_prefixed};

/// The longest message worth accepting.
///
/// Protocol names are short; a length prefix far beyond that means the parser has lost the frame
/// boundary, and reading it as a real length would swallow the rest of the stream.
const MAX_MESSAGE: usize = 1024;

/// The header both sides send first.
pub const MULTISTREAM_HEADER: &str = "/multistream/1.0.0";

/// The listener's rejection of a proposed protocol.
pub const NOT_AVAILABLE: &str = "na";

/// One negotiation message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The line, without its trailing newline.
    pub text: String,
}

impl Message {
    /// Whether this is the opening `/multistream/1.0.0` header rather than a protocol name.
    pub fn is_header(&self) -> bool {
        self.text == MULTISTREAM_HEADER
    }

    /// Whether this is the listener saying it does not speak the proposed protocol.
    pub fn is_rejection(&self) -> bool {
        self.text == NOT_AVAILABLE
    }

    /// Whether this names a protocol, as opposed to being a header or a rejection.
    pub fn is_protocol(&self) -> bool {
        !self.is_header() && !self.is_rejection() && self.text.starts_with('/')
    }
}

/// Reads one negotiation message.
pub fn message(bytes: &[u8]) -> Parsed<Message> {
    match length_prefixed(bytes, MAX_MESSAGE) {
        Parsed::Done { value, consumed } => {
            let Some((b'\n', line)) = value.split_last() else {
                return Parsed::Invalid("multistream-select message does not end in a newline");
            };
            match std::str::from_utf8(line) {
                Ok(text) => Parsed::Done {
                    value: Message { text: text.to_string() },
                    consumed,
                },
                Err(_) => Parsed::Invalid("multistream-select message is not valid UTF-8"),
            }
        }
        Parsed::Incomplete { needed } => Parsed::Incomplete { needed },
        Parsed::Invalid(why) => Parsed::Invalid(why),
    }
}

/// Whether `bytes` plausibly starts a multistream-select message.
///
/// Used to tell a negotiation message from the plaintext handshake's protobuf, which shares the
/// same length prefix. A protobuf `Exchange` starts with a field tag (`0x0a` for field 1), never
/// with `/` or `n`, so looking at the first body byte separates the two without guessing.
pub fn looks_like_message(bytes: &[u8]) -> bool {
    match length_prefixed(bytes, MAX_MESSAGE) {
        Parsed::Done { value, .. } => value.last() == Some(&b'\n') && matches!(value.first(), Some(b'/' | b'n')),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_read_the_opening_header() {
        let mut buf = vec![MULTISTREAM_HEADER.len() as u8 + 1];
        buf.extend_from_slice(MULTISTREAM_HEADER.as_bytes());
        buf.push(b'\n');

        let Parsed::Done { value, consumed } = message(&buf) else {
            panic!("a complete header message must parse");
        };
        assert_eq!(value.text, MULTISTREAM_HEADER);
        assert_eq!(consumed, buf.len());
        assert!(value.is_header());
        assert!(!value.is_protocol());
    }

    #[test]
    fn should_read_a_protocol_proposal() {
        let buf = b"\x10/hopr/mix/1.2.0\n";
        let Parsed::Done { value, .. } = message(buf) else {
            panic!("a complete protocol message must parse");
        };
        assert_eq!(value.text, "/hopr/mix/1.2.0");
        assert!(value.is_protocol());
    }

    #[test]
    fn should_read_a_rejection() {
        let Parsed::Done { value, .. } = message(b"\x03na\n") else {
            panic!("a complete rejection must parse");
        };
        assert!(value.is_rejection());
        assert!(!value.is_protocol());
    }

    #[test]
    fn should_reject_a_message_without_a_newline() {
        assert!(matches!(message(b"\x03abc"), Parsed::Invalid(_)));
    }

    #[test]
    fn should_report_a_split_message_as_incomplete() {
        assert_eq!(message(b"\x10/hopr"), Parsed::Incomplete { needed: Some(17) });
    }

    #[test]
    fn should_distinguish_negotiation_from_the_plaintext_handshake() {
        assert!(looks_like_message(b"\x03na\n"));
        assert!(looks_like_message(b"\x10/hopr/mix/1.2.0\n"));
        // A protobuf `Exchange`: field 1, wire type 2, then a length.
        assert!(!looks_like_message(b"\x04\x0a\x02\xab\xcd"));
    }
}
