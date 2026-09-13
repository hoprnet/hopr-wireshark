//! yamux, the stream multiplexer a HOPR connection runs over the plaintext transport.
//!
//! Every frame is a fixed 12-byte header, big-endian throughout:
//!
//! ```text
//! 0       1       2               4                               8                              12
//! +-------+-------+---------------+-------------------------------+-------------------------------+
//! |version| type  |     flags     |           stream id           |             length            |
//! +-------+-------+---------------+-------------------------------+-------------------------------+
//! ```
//!
//! Only `Data` frames have a body; for the others `length` carries a value whose meaning depends
//! on the type (a window delta, a ping token, a termination code).

use crate::wire::Parsed;

/// Size of a yamux frame header.
pub const HEADER_LEN: usize = 12;

/// The version every current implementation writes.
pub const VERSION: u8 = 0;

/// Largest `Data` body the dissector will wait for.
///
/// yamux's default receive window is 256 KiB and a sender may not exceed it, so anything past
/// that is a lost frame boundary rather than a large write. Bounding it stops a desync from
/// parking the dissector on a multi-gigabyte reassembly.
pub const MAX_BODY: u32 = 1 << 20;

/// Frame types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FrameType {
    /// Carries substream payload.
    Data,
    /// Adjusts the receiver's flow-control window.
    WindowUpdate,
    /// Round-trip probe / keep-alive.
    Ping,
    /// Terminates the whole session.
    GoAway,
    /// Something this dissector does not know about.
    Unknown(u8),
}

impl FrameType {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => FrameType::Data,
            1 => FrameType::WindowUpdate,
            2 => FrameType::Ping,
            3 => FrameType::GoAway,
            other => FrameType::Unknown(other),
        }
    }

    /// Name for display.
    pub fn name(self) -> &'static str {
        match self {
            FrameType::Data => "Data",
            FrameType::WindowUpdate => "Window Update",
            FrameType::Ping => "Ping",
            FrameType::GoAway => "Go Away",
            FrameType::Unknown(_) => "Unknown",
        }
    }
}

/// Frame flags, as a bit set.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Flags(pub u16);

impl Flags {
    /// Opens a new substream.
    pub const SYN: u16 = 0x0001;
    /// Acknowledges a substream open.
    pub const ACK: u16 = 0x0002;
    /// Half-closes the substream.
    pub const FIN: u16 = 0x0004;
    /// Resets the substream.
    pub const RST: u16 = 0x0008;

    /// Names of the flags that are set, in wire order.
    pub fn names(self) -> Vec<&'static str> {
        [
            (Self::SYN, "SYN"),
            (Self::ACK, "ACK"),
            (Self::FIN, "FIN"),
            (Self::RST, "RST"),
        ]
        .into_iter()
        .filter(|(bit, _)| self.0 & bit != 0)
        .map(|(_, name)| name)
        .collect()
    }

    /// Whether this frame opens a substream.
    pub fn is_syn(self) -> bool {
        self.0 & Self::SYN != 0
    }

    /// Whether this frame ends a substream in either of the two ways it can.
    pub fn closes_stream(self) -> bool {
        self.0 & (Self::FIN | Self::RST) != 0
    }
}

/// A parsed frame header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: Flags,
    pub stream_id: u32,
    /// Body length for `Data`; a type-specific value otherwise.
    pub length: u32,
}

impl Header {
    /// Number of body bytes that follow this header.
    pub fn body_len(&self) -> usize {
        match self.frame_type {
            FrameType::Data => self.length as usize,
            _ => 0,
        }
    }

    /// Total size of the frame on the wire.
    pub fn frame_len(&self) -> usize {
        HEADER_LEN + self.body_len()
    }
}

/// Reads a frame header, checking that its body length is plausible.
///
/// The body itself is not required to be present: the caller decides whether to wait for it or to
/// treat the frame as spanning more segments.
pub fn header(bytes: &[u8]) -> Parsed<Header> {
    if bytes.len() < HEADER_LEN {
        return Parsed::Incomplete {
            needed: Some(HEADER_LEN),
        };
    }

    let version = bytes[0];
    if version != VERSION {
        return Parsed::Invalid("unsupported yamux version");
    }

    let frame_type = FrameType::from_raw(bytes[1]);
    if let FrameType::Unknown(_) = frame_type {
        return Parsed::Invalid("unknown yamux frame type");
    }

    let length = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if frame_type == FrameType::Data && length > MAX_BODY {
        return Parsed::Invalid("yamux data frame larger than the protocol's window allows");
    }

    Parsed::Done {
        value: Header {
            version,
            frame_type,
            flags: Flags(u16::from_be_bytes([bytes[2], bytes[3]])),
            stream_id: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            length,
        },
        consumed: HEADER_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u16, stream: u32, len: u32) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = VERSION;
        out[1] = kind;
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        out[4..8].copy_from_slice(&stream.to_be_bytes());
        out[8..12].copy_from_slice(&len.to_be_bytes());
        out
    }

    #[test]
    fn should_read_a_data_frame_header() {
        let Parsed::Done { value, consumed } = header(&frame(0, Flags::SYN, 3, 1461)) else {
            panic!("a well-formed header must parse");
        };
        assert_eq!(consumed, HEADER_LEN);
        assert_eq!(value.frame_type, FrameType::Data);
        assert_eq!(value.stream_id, 3);
        assert_eq!(value.length, 1461);
        assert_eq!(value.body_len(), 1461);
        assert_eq!(value.frame_len(), HEADER_LEN + 1461);
        assert!(value.flags.is_syn());
        assert_eq!(value.flags.names(), vec!["SYN"]);
    }

    #[test]
    fn non_data_frames_should_have_no_body() {
        for kind in [1u8, 2, 3] {
            let Parsed::Done { value, .. } = header(&frame(kind, 0, 0, 262144)) else {
                panic!("a well-formed header must parse");
            };
            assert_eq!(
                value.body_len(),
                0,
                "for {:?} the length field is not a body length",
                value.frame_type
            );
            assert_eq!(value.frame_len(), HEADER_LEN);
        }
    }

    #[test]
    fn should_report_a_split_header_as_incomplete() {
        assert_eq!(
            header(&frame(0, 0, 1, 10)[..5]),
            Parsed::Incomplete {
                needed: Some(HEADER_LEN)
            }
        );
    }

    #[test]
    fn should_reject_headers_that_cannot_be_yamux() {
        let mut bad_version = frame(0, 0, 1, 10);
        bad_version[0] = 9;
        assert!(matches!(header(&bad_version), Parsed::Invalid(_)));

        assert!(matches!(header(&frame(42, 0, 1, 10)), Parsed::Invalid(_)));
        assert!(matches!(header(&frame(0, 0, 1, MAX_BODY + 1)), Parsed::Invalid(_)));
    }

    #[test]
    fn should_list_every_flag_that_is_set() {
        assert_eq!(Flags(Flags::SYN | Flags::FIN).names(), vec!["SYN", "FIN"]);
        assert!(Flags(Flags::RST).closes_stream());
        assert!(Flags(Flags::FIN).closes_stream());
        assert!(!Flags(Flags::ACK).closes_stream());
    }
}
