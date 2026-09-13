//! Encoders for the libp2p framing, used to build a capture the dissector can be pointed at.
//!
//! These are the inverse of the parsers in `crate::wire`, written independently rather than by
//! reusing them: a test whose encoder and decoder share a mistake proves nothing.

use hopr_lib::api::types::crypto::prelude::OffchainPublicKey;

/// Encodes an unsigned LEB128 varint.
pub fn uvarint(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Encodes a varint-length-prefixed byte string.
pub fn length_prefixed(body: &[u8]) -> Vec<u8> {
    let mut out = uvarint(body.len() as u32);
    out.extend_from_slice(body);
    out
}

/// Encodes a multistream-select message.
pub fn multistream(text: &str) -> Vec<u8> {
    let mut body = text.as_bytes().to_vec();
    body.push(b'\n');
    length_prefixed(&body)
}

/// Encodes the `/plaintext/2.0.0` exchange a node sends for `key`.
pub fn plaintext_exchange(key: &OffchainPublicKey) -> Vec<u8> {
    let peer_id = hopr_lib::api::PeerId::from(key).to_bytes();

    // libp2p `PublicKey`: field 1 = KeyType (Ed25519 = 1), field 2 = the raw key.
    let raw = ed25519_bytes(key);
    let mut pubkey = vec![0x08, 0x01, 0x12, raw.len() as u8];
    pubkey.extend_from_slice(&raw);

    // `Exchange`: field 1 = peer id, field 2 = the encoded public key.
    let mut body = vec![0x0a, peer_id.len() as u8];
    body.extend_from_slice(&peer_id);
    body.push(0x12);
    body.push(pubkey.len() as u8);
    body.extend_from_slice(&pubkey);

    length_prefixed(&body)
}

/// The raw Ed25519 key bytes behind an `OffchainPublicKey`.
///
/// Taken out of the peer id rather than from the key directly: `OffchainPublicKey` stores the
/// Montgomery form it does Sphinx arithmetic in, and the wire wants the Edwards form — which is
/// exactly what the peer id's multihash already contains.
fn ed25519_bytes(key: &OffchainPublicKey) -> Vec<u8> {
    let peer_id = hopr_lib::api::PeerId::from(key);
    let bytes = peer_id.to_bytes();
    // Identity multihash: code 0x00, length, then the protobuf-encoded PublicKey whose last 32
    // bytes are the key itself.
    bytes[bytes.len() - 32..].to_vec()
}

/// Encodes a yamux frame.
pub fn yamux(frame_type: u8, flags: u16, stream_id: u32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, frame_type];
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// yamux frame types and flags the capture builder uses.
pub const DATA: u8 = 0;
pub const SYN: u16 = 0x0001;

/// The complete pre-multiplexer half of a connection: negotiation, identity exchange, and the
/// multiplexer's negotiation.
pub fn connection_preamble(key: &OffchainPublicKey) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(multistream("/multistream/1.0.0"));
    out.extend(multistream("/plaintext/2.0.0"));
    out.extend(plaintext_exchange(key));
    out.extend(multistream("/multistream/1.0.0"));
    out.extend(multistream("/yamux/1.0.0"));
    out
}

/// A yamux `Data` frame opening a substream and negotiating `protocol` on it.
pub fn open_substream(stream_id: u32, protocol: &str) -> Vec<u8> {
    let mut body = multistream("/multistream/1.0.0");
    body.extend(multistream(protocol));
    yamux(DATA, SYN, stream_id, &body)
}
