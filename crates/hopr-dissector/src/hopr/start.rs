//! The Session Start protocol, on reserved tag 1 — how a Session is negotiated.
//!
//! The wire header is fixed (`version(1) type(1) length(2)`), but each message body mixes
//! fixed-width fields with CBOR regions whose shape depends on the message. Rather than
//! re-implement that, the body is handed to `HoprStartProtocol::decode` — the node's own decoder,
//! instantiated with the node's own types — and the tree is built from what it returns. A change
//! to the message set therefore fails this dissector's build instead of silently mis-reading
//! Sessions.

use epan::{Encoding, Pinfo, Tree, Tvb};
use hopr_lib::exports::transport::session::HoprStartProtocol;
use hopr_protocol_app::v1::Tag;
use hopr_protocol_start::StartProtocol;

use crate::fields::Fields;

/// Version byte, discriminant, and a `u16` body length.
const HEADER_LEN: usize = 4;

/// The only version this dissector knows.
const VERSION: u8 = 1;

/// Dissects a Start protocol message, returning a short description for the Info column.
pub fn dissect(f: &Fields, tag: Tag, data: &[u8], tvb: Tvb<'_>, pinfo: &mut Pinfo<'_>, tree: Tree<'_>) -> String {
    let (item, sub) = tree.add_subtree(f.subtrees.start, tvb, 0, data.len(), "Session Start Protocol");

    if data.len() < HEADER_LEN {
        item.expert(pinfo, f.experts.malformed, "Start message is shorter than its header");
        return "truncated".into();
    }

    sub.add(f.start.version, tvb, 0, 1, Encoding::BigEndian);
    sub.add(f.start.kind, tvb, 1, 1, Encoding::BigEndian);
    sub.add(f.start.length, tvb, 2, 2, Encoding::BigEndian);

    if data[0] != VERSION {
        item.expert(
            pinfo,
            f.experts.malformed,
            &format!("unsupported Start version {} (expected {VERSION})", data[0]),
        );
        return format!("version {}", data[0]);
    }

    let message = match HoprStartProtocol::decode(tag, data) {
        Ok(message) => message,
        Err(error) => {
            item.expert(
                pinfo,
                f.experts.malformed,
                &format!("cannot decode Start message: {error}"),
            );
            return format!("undecodable type {}", data[1]);
        }
    };

    let body = HEADER_LEN;
    let body_len = data.len() - HEADER_LEN;

    let summary = match &message {
        StartProtocol::StartSession(init) => {
            sub.add_uint64(f.start.challenge, tvb, body, 8, init.challenge);
            sub.add_str(f.start.target, tvb, body, body_len, &format!("{:?}", init.target));
            sub.add_str(
                f.start.capabilities,
                tvb,
                body,
                body_len,
                &format!("{:?}", init.capabilities),
            );
            format!("StartSession challenge {}", init.challenge)
        }
        StartProtocol::SessionEstablished(est) => {
            sub.add_uint64(f.start.challenge, tvb, body, 8, est.orig_challenge);
            sub.add_str(f.start.session_id, tvb, body, body_len, est.session_id.as_ref());
            format!("SessionEstablished {}", est.session_id)
        }
        StartProtocol::SessionError(err) => {
            sub.add_str(f.start.error_reason, tvb, body, body_len, &format!("{:?}", err.reason));
            sub.add_str(
                f.start.session_id,
                tvb,
                body,
                body_len,
                &format!("{:?}", err.identifier),
            );
            format!("SessionError {:?}", err.reason)
        }
        StartProtocol::KeepAlive(ka) => {
            sub.add_str(f.start.session_id, tvb, body, body_len, ka.session_id.as_ref());
            format!("KeepAlive {}", ka.session_id)
        }
        StartProtocol::SsaCommit(commit) => {
            sub.add_str(f.start.session_id, tvb, body, body_len, commit.session_id.as_ref());
            sub.add_uint(f.start.ssa_index, tvb, body, body_len, commit.ssa_index.into());
            sub.add_uint(
                f.start.ssa_commitments,
                tvb,
                body,
                body_len,
                commit.coefficient_commitments.len() as u32,
            );
            format!(
                "SsaCommit ssa {} ({} commitments)",
                u32::from(commit.ssa_index),
                commit.coefficient_commitments.len()
            )
        }
        StartProtocol::SsaRequest(request) => {
            sub.add_str(f.start.session_id, tvb, body, body_len, request.session_id.as_ref());
            format!("SsaRequest {}", request.session_id)
        }
    };

    // The node's own `Debug` rendering, so that anything the fields above do not break out —
    // PIX parameters, capability sets, target details — is still readable in the tree rather
    // than only as bytes.
    sub.add_str(f.start.summary, tvb, body, body_len, &format!("{message:?}"));

    item.append(&format!(": {summary}"));
    summary
}
