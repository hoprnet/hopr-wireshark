//! The probe protocol, on reserved tag 0.
//!
//! Two message shapes, both a version byte and a discriminant followed by a fixed body:
//!
//! ```text
//! Probe     (1): version(1) type(1) direction(1) nonce(32)
//! Telemetry (0): version(1) type(1) id(8) path(40) timestamp(16)
//! ```
//!
//! A `Pong` echoes the nonce of the `Ping` it answers, which is what makes a round trip
//! identifiable in a capture.
//!
//! Unlike the layers above, this one is parsed here rather than through the node's own decoder:
//! `hopr_transport_probe`'s message type is crate-internal, and the format is two fixed-width
//! bodies. The sizes below come from the constants that define them.

use epan::{Encoding, Pinfo, Tree, Tvb};

use crate::fields::Fields;

/// The only version this dissector knows.
const VERSION: u8 = 1;

/// Version byte plus discriminant.
const HEADER_LEN: usize = 2;

/// Size of a probe nonce.
const NONCE_LEN: usize = 32;

/// Direction byte plus nonce.
const PROBE_BODY: usize = 1 + NONCE_LEN;

/// Telemetry id, path and timestamp.
const TELEMETRY_ID_LEN: usize = 8;
const TELEMETRY_PATH_LEN: usize = 40;
const TELEMETRY_TS_LEN: usize = 16;
const TELEMETRY_BODY: usize = TELEMETRY_ID_LEN + TELEMETRY_PATH_LEN + TELEMETRY_TS_LEN;

/// Message discriminants.
const TELEMETRY: u8 = 0;
const PROBE: u8 = 1;

/// Neighbour probe directions.
const PING: u8 = 0;
const PONG: u8 = 1;

/// Dissects a probe message, returning a short description for the Info column.
pub fn dissect(f: &Fields, data: &[u8], tvb: Tvb<'_>, pinfo: &mut Pinfo<'_>, tree: Tree<'_>) -> String {
    let (item, sub) = tree.add_subtree(f.subtrees.probe, tvb, 0, data.len(), "Probe Protocol");

    if data.len() < HEADER_LEN {
        item.expert(pinfo, f.experts.malformed, "probe message is shorter than its header");
        return "truncated".into();
    }

    sub.add(f.probe.version, tvb, 0, 1, Encoding::BigEndian);
    if data[0] != VERSION {
        item.expert(
            pinfo,
            f.experts.malformed,
            &format!("unsupported probe version {} (expected {VERSION})", data[0]),
        );
        return format!("version {}", data[0]);
    }

    sub.add(f.probe.kind, tvb, 1, 1, Encoding::BigEndian);
    let body = &data[HEADER_LEN..];

    match data[1] {
        PROBE if body.len() == PROBE_BODY => {
            sub.add(f.probe.neighbor_kind, tvb, HEADER_LEN, 1, Encoding::BigEndian);
            sub.add(f.probe.nonce, tvb, HEADER_LEN + 1, NONCE_LEN, Encoding::NotApplicable);

            let direction = match body[0] {
                PING => "Ping",
                PONG => "Pong",
                other => {
                    item.expert(
                        pinfo,
                        f.experts.malformed,
                        &format!("unknown neighbour probe direction {other}"),
                    );
                    "Unknown"
                }
            };
            let nonce = hex::encode(&body[1..1 + 6.min(NONCE_LEN)]);
            item.append(&format!(": {direction}"));
            format!("{direction} {nonce}…")
        }
        TELEMETRY if body.len() == TELEMETRY_BODY => {
            let mut at = HEADER_LEN;
            sub.add(f.probe.telemetry_id, tvb, at, TELEMETRY_ID_LEN, Encoding::NotApplicable);
            at += TELEMETRY_ID_LEN;
            sub.add(
                f.probe.telemetry_path,
                tvb,
                at,
                TELEMETRY_PATH_LEN,
                Encoding::NotApplicable,
            );
            at += TELEMETRY_PATH_LEN;
            sub.add(
                f.probe.telemetry_timestamp,
                tvb,
                at,
                TELEMETRY_TS_LEN,
                Encoding::NotApplicable,
            );

            item.append(": Telemetry");
            format!("Telemetry {}", hex::encode(&body[..TELEMETRY_ID_LEN]))
        }
        kind @ (PROBE | TELEMETRY) => {
            let expected = if kind == PROBE { PROBE_BODY } else { TELEMETRY_BODY };
            item.expert(
                pinfo,
                f.experts.malformed,
                &format!("probe body is {} bytes, expected {expected}", body.len()),
            );
            "malformed".into()
        }
        other => {
            item.expert(
                pinfo,
                f.experts.malformed,
                &format!("unknown probe message type {other}"),
            );
            format!("type {other}")
        }
    }
}
