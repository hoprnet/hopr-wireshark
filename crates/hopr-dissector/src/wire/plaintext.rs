//! The `/plaintext/2.0.0` handshake.
//!
//! Each side sends one varint-length-prefixed protobuf message and then stops framing entirely —
//! everything after it is the raw multiplexer stream. The message is:
//!
//! ```text
//! message Exchange {
//!   optional bytes id     = 1;  // the sender's peer id, in its binary form
//!   optional bytes pubkey = 2;  // a protobuf-encoded PublicKey
//! }
//!
//! message PublicKey {
//!   required KeyType Type = 1;  // Ed25519 = 1
//!   required bytes   Data = 2;  // for Ed25519, the raw 32-byte key
//! }
//! ```
//!
//! This is the single most useful thing the dissector reads off the wire: it names the node at
//! each end of the connection, so every packet on it can be attributed to a sender and decrypted
//! with the right receiver's key, without the user having to map ports to nodes by hand.

use crate::wire::{Parsed, length_prefixed};

/// Generous ceiling for an `Exchange`: a peer id and a 32-byte key with protobuf overhead come to
/// well under a hundred bytes. rust-libp2p's own decoder caps the message at 100.
const MAX_EXCHANGE: usize = 256;

/// libp2p's `KeyType` for Ed25519, the only one a HOPR node uses.
const KEY_TYPE_ED25519: u64 = 1;

/// What the handshake revealed about one side of the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// The peer id, exactly as it appeared on the wire.
    pub peer_id: Vec<u8>,
    /// The raw public key, for an Ed25519 key. `None` for any other key type, which a HOPR node
    /// never sends but another libp2p peer on the same port might.
    pub ed25519_key: Option<[u8; 32]>,
}

/// Reads one `Exchange` message.
pub fn exchange(bytes: &[u8]) -> Parsed<Exchange> {
    let (body, consumed) = match length_prefixed(bytes, MAX_EXCHANGE) {
        Parsed::Done { value, consumed } => (value, consumed),
        Parsed::Incomplete { needed } => return Parsed::Incomplete { needed },
        Parsed::Invalid(why) => return Parsed::Invalid(why),
    };

    let mut peer_id = Vec::new();
    let mut pubkey = Vec::new();

    for field in protobuf_fields(body) {
        match field {
            Ok((1, Value::Bytes(b))) => peer_id = b.to_vec(),
            Ok((2, Value::Bytes(b))) => pubkey = b.to_vec(),
            // Unknown fields are skipped rather than rejected: protobuf is designed for that, and
            // a future libp2p adding one should not break the dissection of the two we read.
            Ok(_) => {}
            Err(why) => return Parsed::Invalid(why),
        }
    }

    Parsed::Done {
        value: Exchange {
            peer_id,
            ed25519_key: parse_public_key(&pubkey),
        },
        consumed,
    }
}

/// Extracts the raw key from a protobuf-encoded libp2p `PublicKey`, if it is an Ed25519 one.
fn parse_public_key(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut key_type = None;
    let mut data: Option<&[u8]> = None;

    for field in protobuf_fields(bytes) {
        match field.ok()? {
            (1, Value::Varint(v)) => key_type = Some(v),
            (2, Value::Bytes(b)) => data = Some(b),
            _ => {}
        }
    }

    (key_type? == KEY_TYPE_ED25519).then_some(())?;
    data?.try_into().ok()
}

/// A protobuf field value, in the two encodings these messages use.
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// Walks the fields of a protobuf message.
///
/// A deliberately minimal reader: these two messages have four fields between them and are
/// produced by one implementation, so pulling in a protobuf crate (and a build step to generate
/// code from a `.proto`) would cost more than it saves. Groups (wire type 3/4) are long removed
/// from the language and are reported as errors rather than skipped.
fn protobuf_fields(mut bytes: &[u8]) -> impl Iterator<Item = Result<(u64, Value<'_>), &'static str>> {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }

        let (tag, n) = match varint64(bytes) {
            Some(v) => v,
            None => return Some(Err("truncated protobuf field tag")),
        };
        bytes = &bytes[n..];

        let field = tag >> 3;
        let value = match tag & 0x07 {
            0 => match varint64(bytes) {
                Some((v, n)) => {
                    bytes = &bytes[n..];
                    Value::Varint(v)
                }
                None => return Some(Err("truncated protobuf varint")),
            },
            2 => match varint64(bytes) {
                Some((len, n)) => {
                    let start = n;
                    let end = match start.checked_add(len as usize) {
                        Some(end) if end <= bytes.len() => end,
                        _ => return Some(Err("protobuf length-delimited field runs past the message")),
                    };
                    let slice = &bytes[start..end];
                    bytes = &bytes[end..];
                    Value::Bytes(slice)
                }
                None => return Some(Err("truncated protobuf length prefix")),
            },
            1 => {
                if bytes.len() < 8 {
                    return Some(Err("truncated protobuf 64-bit field"));
                }
                bytes = &bytes[8..];
                Value::Varint(0)
            }
            5 => {
                if bytes.len() < 4 {
                    return Some(Err("truncated protobuf 32-bit field"));
                }
                bytes = &bytes[4..];
                Value::Varint(0)
            }
            _ => return Some(Err("unsupported protobuf wire type")),
        };

        Some(Ok((field, value)))
    })
}

/// Reads a protobuf varint, returning its value and width.
fn varint64(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, b) in bytes.iter().take(10).enumerate() {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the `Exchange` rust-libp2p sends: field 1 = peer id, field 2 = encoded PublicKey.
    fn encode_exchange(peer_id: &[u8], key: Option<&[u8; 32]>) -> Vec<u8> {
        let mut pubkey = Vec::new();
        if let Some(key) = key {
            pubkey.extend_from_slice(&[0x08, KEY_TYPE_ED25519 as u8]); // field 1, varint
            pubkey.push(0x12); // field 2, length-delimited
            pubkey.push(key.len() as u8);
            pubkey.extend_from_slice(key);
        }

        let mut body = Vec::new();
        body.push(0x0a); // field 1, length-delimited
        body.push(peer_id.len() as u8);
        body.extend_from_slice(peer_id);
        if !pubkey.is_empty() {
            body.push(0x12); // field 2, length-delimited
            body.push(pubkey.len() as u8);
            body.extend_from_slice(&pubkey);
        }

        let mut out = vec![body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn should_read_a_peer_id_and_ed25519_key() {
        let key = [7u8; 32];
        let buf = encode_exchange(b"\x00\x24\x08\x01\x12\x20peer", Some(&key));

        let Parsed::Done { value, consumed } = exchange(&buf) else {
            panic!("a complete exchange must parse");
        };
        assert_eq!(consumed, buf.len());
        assert_eq!(value.peer_id, b"\x00\x24\x08\x01\x12\x20peer");
        assert_eq!(value.ed25519_key, Some(key));
    }

    #[test]
    fn should_report_a_split_exchange_as_incomplete() {
        let buf = encode_exchange(b"peer", Some(&[7u8; 32]));
        assert!(matches!(exchange(&buf[..buf.len() - 5]), Parsed::Incomplete { .. }));
    }

    #[test]
    fn should_ignore_a_key_that_is_not_ed25519() {
        // Key type 2 (RSA): the peer id still reads, the key does not.
        let mut pubkey = vec![0x08, 0x02, 0x12, 0x04];
        pubkey.extend_from_slice(b"abcd");
        let mut body = vec![0x0a, 0x04];
        body.extend_from_slice(b"peer");
        body.push(0x12);
        body.push(pubkey.len() as u8);
        body.extend_from_slice(&pubkey);
        let mut buf = vec![body.len() as u8];
        buf.extend_from_slice(&body);

        let Parsed::Done { value, .. } = exchange(&buf) else {
            panic!("an exchange with a non-Ed25519 key must still parse");
        };
        assert_eq!(value.peer_id, b"peer");
        assert_eq!(value.ed25519_key, None);
    }

    #[test]
    fn should_skip_an_unknown_field() {
        // Field 5, varint — something a future libp2p might add.
        let mut body = vec![0x28, 0x2a, 0x0a, 0x04];
        body.extend_from_slice(b"peer");
        let mut buf = vec![body.len() as u8];
        buf.extend_from_slice(&body);

        let Parsed::Done { value, .. } = exchange(&buf) else {
            panic!("an unknown field must not fail the parse");
        };
        assert_eq!(value.peer_id, b"peer");
    }

    #[test]
    fn should_reject_a_field_that_runs_past_the_message() {
        let buf = [0x03, 0x0a, 0x40, 0x00];
        assert!(matches!(exchange(&buf), Parsed::Invalid(_)));
    }
}
