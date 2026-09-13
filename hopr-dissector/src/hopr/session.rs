//! The Session protocol, on reserved tag 2 — segmentation, retransmission and acknowledgement of
//! an application byte stream carried over the mixnet.
//!
//! A message is `version(1) type(1) length(2)` followed by one of three bodies. The header is
//! read here because it is four fixed bytes; each body is handed to the node's own decoder, so
//! the segment header layout and the retransmission bitmap cannot drift away from the
//! implementation that produces them.

use epan::{Encoding, Pinfo, Tree, Tvb};
use hopr_protocol_app::v1::ApplicationData;
use hopr_protocol_session::{FrameAcknowledgements, Segment, SegmentRequest};

use crate::fields::Fields;

/// Capacity the Session protocol is instantiated at.
///
/// The Session runs directly on top of `ApplicationData`, so one Session message is at most one
/// application payload. This is the same constant `hopr-transport-session` derives `SESSION_MTU`
/// from; using anything else here would make the dissector disagree with the sender about how
/// many entries fit in a retransmission request or an acknowledgement.
const CAPACITY: usize = ApplicationData::PAYLOAD_SIZE;

/// Version byte, discriminant, and a `u16` body length.
const HEADER_LEN: usize = 4;

/// Header inside a `Segment` body: frame id, sequence index, sequence flags.
const SEGMENT_HEADER_LEN: usize = 6;

/// The only version this dissector knows.
const VERSION: u8 = 1;

/// Message discriminants.
const SEGMENT: u8 = 0;
const REQUEST: u8 = 1;
const ACKNOWLEDGE: u8 = 2;

/// Dissects a Session protocol message, returning a short description for the Info column.
pub fn dissect(f: &Fields, data: &[u8], tvb: Tvb<'_>, pinfo: &mut Pinfo<'_>, tree: Tree<'_>) -> String {
    let (item, sub) = tree.add_subtree(f.subtrees.session, tvb, 0, data.len(), "Session Protocol");

    if data.len() < HEADER_LEN {
        item.expert(pinfo, f.experts.malformed, "Session message is shorter than its header");
        return "truncated".into();
    }

    sub.add(f.session.version, tvb, 0, 1, Encoding::BigEndian);
    sub.add(f.session.kind, tvb, 1, 1, Encoding::BigEndian);
    sub.add(f.session.length, tvb, 2, 2, Encoding::BigEndian);

    if data[0] != VERSION {
        item.expert(
            pinfo,
            f.experts.malformed,
            &format!("unsupported Session version {} (expected {VERSION})", data[0]),
        );
        return format!("version {}", data[0]);
    }

    let declared = u16::from_be_bytes([data[2], data[3]]) as usize;
    let Some(body) = data.get(HEADER_LEN..HEADER_LEN + declared) else {
        item.expert(
            pinfo,
            f.experts.malformed,
            &format!(
                "Session message declares a {declared}-byte body but only {} bytes follow the header",
                data.len() - HEADER_LEN
            ),
        );
        return "truncated body".into();
    };
    let at = HEADER_LEN;

    let summary = match data[1] {
        SEGMENT => match Segment::try_from(body) {
            Ok(segment) => {
                sub.add(f.session.frame_id, tvb, at, 4, Encoding::BigEndian);
                sub.add(f.session.seq_idx, tvb, at + 4, 1, Encoding::BigEndian);
                sub.add_uint(f.session.seq_len, tvb, at + 5, 1, segment.seq_flags.seq_len() as u32);
                sub.add_bool(f.session.terminating, tvb, at + 5, 1, segment.is_terminating());

                let payload_at = at + SEGMENT_HEADER_LEN;
                if segment.data.is_empty() {
                    // A terminating segment carries no data: it exists to say the stream ended.
                    sub.add_bytes(f.session.payload, tvb, payload_at, 0, &[])
                        .set_text("Segment Payload: <empty>");
                } else {
                    sub.add(
                        f.session.payload,
                        tvb,
                        payload_at,
                        segment.data.len(),
                        Encoding::NotApplicable,
                    );
                }

                format!(
                    "Segment {} ({}/{}{})",
                    segment.frame_id,
                    segment.seq_idx as u16 + 1,
                    segment.seq_flags.seq_len(),
                    if segment.is_terminating() { ", terminating" } else { "" }
                )
            }
            Err(error) => {
                item.expert(pinfo, f.experts.malformed, &format!("cannot decode segment: {error}"));
                "undecodable segment".into()
            }
        },
        REQUEST => match SegmentRequest::<CAPACITY>::try_from(body) {
            Ok(request) => {
                let mut count = 0;
                for segment_id in request {
                    sub.add_uint(f.session.requested_frame, tvb, at, declared, segment_id.0)
                        .set_text(&format!(
                            "Requested Segment: frame {}, index {}",
                            segment_id.0, segment_id.1
                        ));
                    sub.add_uint(f.session.requested_index, tvb, at, declared, segment_id.1 as u32);
                    count += 1;
                }
                format!("SegmentRequest ({count} segments)")
            }
            Err(error) => {
                item.expert(
                    pinfo,
                    f.experts.malformed,
                    &format!("cannot decode segment request: {error}"),
                );
                "undecodable request".into()
            }
        },
        ACKNOWLEDGE => match FrameAcknowledgements::<CAPACITY>::try_from(body) {
            Ok(acks) => {
                let mut count = 0;
                for frame_id in acks {
                    sub.add_uint(f.session.acked_frame, tvb, at, declared, frame_id);
                    count += 1;
                }
                format!("FrameAcknowledgements ({count} frames)")
            }
            Err(error) => {
                item.expert(
                    pinfo,
                    f.experts.malformed,
                    &format!("cannot decode frame acknowledgements: {error}"),
                );
                "undecodable acknowledgements".into()
            }
        },
        other => {
            item.expert(
                pinfo,
                f.experts.malformed,
                &format!("unknown Session message type {other}"),
            );
            format!("type {other}")
        }
    };

    item.append(&format!(": {summary}"));
    summary
}
