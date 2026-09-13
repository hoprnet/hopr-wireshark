//! Walking a connection's byte stream and turning it into a packet detail tree.
//!
//! # Shape of the work
//!
//! Dissection happens in two walks over the same bytes:
//!
//! * [`layout`] is pure. Given the parse phase at the start of a frame and the bytes in front of
//!   it, it says where every framing unit begins and ends. Running it again on a later visit
//!   produces the same answer, which is what lets TCP desegmentation be re-requested correctly.
//! * [`content`] runs once per frame, on its first visit, and does everything stateful:
//!   accumulating substream bytes, decrypting packets, remembering SURBs, learning key
//!   identifiers. What it produced is recorded and replayed afterwards.
//!
//! Keeping the second out of the first is what makes the dissection the user sees identical
//! whether they are watching a live capture scroll past or clicking a packet an hour later.

use epan::{
    Conversation, Encoding, Pinfo, Tree, Tvb,
    conv::Direction,
    tree::{DESEGMENT_ONE_MORE_SEGMENT, TreeItem},
};
use hopr_crypto_packet::HoprSurb;
use hopr_lib::api::types::{internal::prelude::Ticket, primitive::prelude::BytesEncodable};

use crate::{
    fields::Fields,
    hopr::{self, Decoded, META_PACKET_SIZE, PACKET_SIZE, app, ticket},
    keys::short_key,
    state::{DissectorState, FrameRecord, PacketUnit, Phase, Unit, with_state},
    wire::{Parsed, multistream, plaintext, yamux},
};

/// Protocol prefix of the substream HOPR packets travel on.
///
/// Matched by prefix rather than in full: the version moves with the wire format (`1.1.0`,
/// `1.2.0`, …) and a dissector that only recognised one of them would go blind on a cluster
/// running another, for no gain — the packet framing is what it actually depends on, and that is
/// the same across versions.
const MIX_PROTOCOL_PREFIX: &str = "/hopr/mix/";

/// One framing unit found in a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Element {
    /// A varint-length-prefixed message from the pre-multiplexer part of the stream.
    Handshake {
        offset: usize,
        /// Total size including the length prefix.
        len: usize,
        /// Where the body starts, relative to the frame.
        body: usize,
        kind: HandshakeKind,
    },
    /// A yamux frame.
    Yamux {
        offset: usize,
        header: yamux::Header,
        /// Where the body starts, relative to the frame. Equal to `offset + HEADER_LEN`.
        body: usize,
    },
    /// The frame ends part-way through a unit.
    Incomplete {
        offset: usize,
        /// Total size of the unit, when its length field has already arrived.
        needed: Option<usize>,
    },
    /// The bytes stopped being parseable.
    Desync { offset: usize, reason: &'static str },
}

/// What a pre-multiplexer message turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeKind {
    /// A multistream-select header, proposal or rejection.
    Multistream(multistream::Message),
    /// The `/plaintext/2.0.0` peer-identity exchange.
    Exchange(Box<plaintext::Exchange>),
}

/// Walks `bytes` from the given phase, returning the units it contains.
///
/// Pure: the same inputs always give the same output, including the trailing [`Element::Incomplete`]
/// that tells the caller how much more to ask TCP for.
pub fn layout(mut phase: Phase, mut exchange_seen: bool, bytes: &[u8]) -> Vec<Element> {
    let mut out = Vec::new();
    let mut at = 0;

    loop {
        if at >= bytes.len() {
            return out;
        }
        let rest = &bytes[at..];

        match phase {
            Phase::Desynchronised => {
                out.push(Element::Desync {
                    offset: at,
                    reason: "stream is no longer parseable",
                });
                return out;
            }
            Phase::Handshake => {
                // multistream-select messages and the plaintext exchange share a varint length
                // prefix, so which one this is can only be told from the body.
                let is_multistream = multistream::looks_like_message(rest);
                let parsed = if is_multistream {
                    match multistream::message(rest) {
                        Parsed::Done { value, consumed } => Parsed::Done {
                            value: (HandshakeKind::Multistream(value), consumed),
                            consumed,
                        },
                        Parsed::Incomplete { needed } => Parsed::Incomplete { needed },
                        Parsed::Invalid(why) => Parsed::Invalid(why),
                    }
                } else {
                    match plaintext::exchange(rest) {
                        Parsed::Done { value, consumed } => Parsed::Done {
                            value: (HandshakeKind::Exchange(Box::new(value)), consumed),
                            consumed,
                        },
                        Parsed::Incomplete { needed } => Parsed::Incomplete { needed },
                        Parsed::Invalid(why) => Parsed::Invalid(why),
                    }
                };

                match parsed {
                    Parsed::Done {
                        value: (kind, consumed),
                        ..
                    } => {
                        // The body starts after the varint, whose width is the difference between
                        // the message and its payload.
                        let prefix = prefix_len(rest, consumed);

                        // The exchange ends the security upgrade; the multiplexer is negotiated
                        // after it, and the stream becomes yamux frames once that is accepted.
                        let advance_to_yamux = match &kind {
                            HandshakeKind::Exchange(_) => {
                                exchange_seen = true;
                                false
                            }
                            HandshakeKind::Multistream(m) => exchange_seen && m.is_protocol(),
                        };

                        out.push(Element::Handshake {
                            offset: at,
                            len: consumed,
                            body: at + prefix,
                            kind,
                        });
                        at += consumed;

                        if advance_to_yamux {
                            phase = Phase::Yamux;
                        }
                    }
                    Parsed::Incomplete { needed } => {
                        out.push(Element::Incomplete { offset: at, needed });
                        return out;
                    }
                    Parsed::Invalid(reason) => {
                        out.push(Element::Desync { offset: at, reason });
                        return out;
                    }
                }
            }
            Phase::Yamux => match yamux::header(rest) {
                Parsed::Done { value, .. } => {
                    let total = value.frame_len();
                    if rest.len() < total {
                        out.push(Element::Incomplete {
                            offset: at,
                            needed: Some(total),
                        });
                        return out;
                    }
                    out.push(Element::Yamux {
                        offset: at,
                        header: value,
                        body: at + yamux::HEADER_LEN,
                    });
                    at += total;
                }
                Parsed::Incomplete { needed } => {
                    out.push(Element::Incomplete { offset: at, needed });
                    return out;
                }
                Parsed::Invalid(reason) => {
                    out.push(Element::Desync { offset: at, reason });
                    return out;
                }
            },
        }
    }
}

/// Width of the varint length prefix of a message that occupied `consumed` bytes.
fn prefix_len(bytes: &[u8], consumed: usize) -> usize {
    match crate::wire::uvarint(bytes) {
        Parsed::Done { value, consumed: n } => {
            debug_assert_eq!(n + value as usize, consumed);
            n
        }
        // Unreachable for a message that parsed, but a wrong prefix width would only misplace a
        // highlight, so there is no reason to panic over it.
        _ => 1,
    }
}

/// Runs the stateful half of dissection for one frame and records what it produced.
fn content(
    state: &mut DissectorState,
    conv: Conversation,
    dir: Direction,
    bytes: &[u8],
    elements: &[Element],
    decrypt: bool,
) -> FrameRecord {
    let mut record = FrameRecord::default();

    for element in elements {
        match element {
            Element::Handshake { kind, .. } => match kind {
                HandshakeKind::Exchange(exchange) => {
                    // The handshake is the only thing on the wire that names the nodes, and it
                    // names them for the whole connection: everything decrypted later depends on
                    // this one message.
                    if let Some(node) = state.registry.by_peer_id(&exchange.peer_id) {
                        let public = node.public;
                        state.set_sender(conv, dir, public);
                    }
                    state.stream(conv, dir).exchange_seen = true;
                }
                HandshakeKind::Multistream(message) => {
                    let stream = state.stream(conv, dir);
                    if stream.exchange_seen && message.is_protocol() {
                        stream.phase = Phase::Yamux;
                    }
                }
            },
            Element::Yamux { header, body, .. } => {
                state.stream(conv, dir).phase = Phase::Yamux;

                if header.frame_type != yamux::FrameType::Data {
                    if header.flags.closes_stream() {
                        state.stream(conv, dir).substreams.remove(&header.stream_id);
                    }
                    continue;
                }

                let body_bytes = &bytes[*body..*body + header.body_len()];
                substream_content(state, conv, dir, header.stream_id, body_bytes, &mut record, decrypt);

                if header.flags.closes_stream() {
                    state.stream(conv, dir).substreams.remove(&header.stream_id);
                }
            }
            Element::Desync { .. } => {
                state.stream(conv, dir).phase = Phase::Desynchronised;
            }
            // An incomplete unit is re-delivered in full once TCP has more of it, so nothing is
            // consumed here — doing so would count those bytes twice.
            Element::Incomplete { .. } => {}
        }
    }

    record
}

/// Folds one yamux `Data` body into its substream and extracts whatever completed.
fn substream_content(
    state: &mut DissectorState,
    conv: Conversation,
    dir: Direction,
    stream_id: u32,
    body: &[u8],
    record: &mut FrameRecord,
    decrypt: bool,
) {
    // The substream's own bytes, taken out of the stream state so the registry and trackers can
    // be borrowed alongside it while packets are decoded.
    let (mut pending, mut protocol) = {
        let sub = state.stream(conv, dir).substreams.entry(stream_id).or_default();
        (std::mem::take(&mut sub.pending), sub.protocol.clone())
    };
    pending.extend_from_slice(body);

    // Before a protocol is agreed, a substream carries multistream-select messages.
    while protocol.is_none() {
        match multistream::message(&pending) {
            Parsed::Done { value, consumed } => {
                pending.drain(..consumed);
                if value.is_protocol() {
                    // Both sides send the name; whichever is seen first on this direction fixes
                    // it, and they agree by construction.
                    protocol = Some(value.text.clone());
                    record.units.push(Unit::Negotiated {
                        stream_id,
                        protocol: value.text,
                    });
                }
            }
            _ => break,
        }
    }

    if let Some(name) = protocol.clone() {
        if name.starts_with(MIX_PROTOCOL_PREFIX) {
            while pending.len() >= PACKET_SIZE {
                let raw: Vec<u8> = pending.drain(..PACKET_SIZE).collect();
                let decoded = if decrypt {
                    decode_packet(state, conv, dir, &raw)
                } else {
                    Err("decryption is turned off in the protocol preferences".to_string())
                };
                record.units.push(Unit::Packet(Box::new(PacketUnit {
                    stream_id,
                    raw,
                    decoded,
                })));
            }
        } else if !pending.is_empty() {
            record.units.push(Unit::Opaque {
                stream_id,
                protocol: name,
                len: pending.len(),
            });
            pending.clear();
        }
    }

    let sub = state.stream(conv, dir).substreams.entry(stream_id).or_default();
    sub.pending = pending;
    sub.protocol = protocol;
}

/// Decrypts one packet and folds what it reveals back into the dissector's state.
fn decode_packet(
    state: &mut DissectorState,
    conv: Conversation,
    dir: Direction,
    raw: &[u8],
) -> Result<Decoded, String> {
    if state.registry.is_empty() {
        return Err(match &state.key_error {
            Some(error) => error.clone(),
            None => "no node key file configured".to_string(),
        });
    }

    let sender = state
        .sender(conv, dir)
        .ok_or("the sending node is unknown: no /plaintext/2.0.0 handshake was captured")?;
    let receiver_key = state
        .receiver(conv, dir)
        .ok_or("the receiving node is unknown: no /plaintext/2.0.0 handshake was captured")?;

    // A packet arriving at a node it was relayed to is what binds the key identifier the previous
    // hop named it by. Done before decoding, so a chain of relays resolves in one pass.
    if raw.len() >= META_PACKET_SIZE {
        state.learner.observe_arrival(&raw[..META_PACKET_SIZE], &receiver_key);
    }

    // Split the borrows: decoding needs the registry and the learner shared, and the SURB tracker
    // mutable.
    let DissectorState {
        registry,
        learner,
        surbs,
        ..
    } = state;

    let receiver = registry
        .by_public(&receiver_key)
        .ok_or_else(|| format!("no key configured for {}", short_key(&receiver_key)))?;

    let decoded = hopr::decode(raw, &sender, receiver, registry, learner, surbs)?;

    // A relayed packet names its next hop by an identifier that may not be known yet; remembering
    // the packet it will travel on is what lets the next link's arrival resolve it.
    if let Decoded::Forwarded(fwd) = &decoded
        && let Some(id) = fwd.next_hop_id
    {
        state.learner.expect_forward(&fwd.outgoing_meta_packet, id);
    }

    Ok(decoded)
}

/// Dissects one TCP payload.
///
/// Returns the number of bytes accounted for, which is all of them: anything not consumed by a
/// complete unit is left to TCP's desegmentation rather than to another dissector.
pub fn dissect_tcp(f: &Fields, tvb: Tvb<'_>, pinfo: &mut Pinfo<'_>, tree: Tree<'_>) -> usize {
    let conv = Conversation::of(pinfo);
    let dir = Direction::of(pinfo);
    let frame = pinfo.frame_number();
    let key = (conv, dir, frame);
    let visited = pinfo.visited();

    let Some(bytes) = tvb.bytes(0, tvb.captured_len()) else {
        return 0;
    };

    let (phase, exchange_seen, decrypt) = with_state(|state| {
        state.ensure_keys(f.prefs.key_file.get().as_deref());
        let (phase, exchange_seen) = state.phase_for_frame(key, visited);
        (phase, exchange_seen, f.prefs.decrypt.get())
    });

    let elements = layout(phase, exchange_seen, &bytes);

    if !visited {
        with_state(|state| {
            let record = content(state, conv, dir, &bytes, &elements, decrypt);
            state.record(key, record);
        });
    }

    pinfo.set_protocol("HOPR");
    pinfo.clear_info();

    // One borrow for the whole render. Taking a fresh one per layer reads more naturally but
    // panics the moment two of them overlap, which is exactly what a nested tree does.
    with_state(|state| render(f, state, &elements, &bytes, tvb, pinfo, tree, key));

    // Asking for more data after the tree is built, so the part of the frame that *is* complete
    // is shown even when the rest of it is still in flight.
    if let Some(Element::Incomplete { offset, needed }) = elements.last() {
        let more = needed
            .and_then(|n| n.checked_sub(bytes.len() - offset))
            .map(|n| n as u32)
            .unwrap_or(DESEGMENT_ONE_MORE_SEGMENT);
        pinfo.request_more_data(*offset, more);
    }

    tvb.captured_len()
}

/// Builds the detail tree for one frame.
#[allow(clippy::too_many_arguments)]
fn render(
    f: &Fields,
    state: &mut DissectorState,
    elements: &[Element],
    bytes: &[u8],
    tvb: Tvb<'_>,
    pinfo: &mut Pinfo<'_>,
    tree: Tree<'_>,
    key: (Conversation, Direction, u32),
) {
    let (_, root) = tree.add_subtree(f.subtrees.libp2p, tvb, 0, bytes.len(), "HOPR libp2p Framing");

    // Units are consumed in the order the content pass produced them, which is the order this
    // walk meets the substreams that produced them.
    let mut next_unit = 0;

    for element in elements {
        match element {
            Element::Handshake {
                offset,
                len,
                body,
                kind,
            } => {
                render_handshake(f, state, kind, tvb, *offset, *len, *body, pinfo, root);
            }
            Element::Yamux { offset, header, body } => {
                render_yamux(
                    f,
                    state,
                    header,
                    tvb,
                    *offset,
                    *body,
                    pinfo,
                    root,
                    key,
                    &mut next_unit,
                    bytes,
                );
            }
            Element::Incomplete { offset, needed } => {
                let len = bytes.len() - offset;
                let (item, _) = root.add_subtree(
                    f.subtrees.libp2p,
                    tvb,
                    *offset,
                    len,
                    &match needed {
                        Some(n) => format!("Incomplete unit: {len} of {n} bytes, waiting for more segments"),
                        None => format!("Incomplete unit: {len} bytes, waiting for more segments"),
                    },
                );
                let _ = item;
            }
            Element::Desync { offset, reason } => {
                let (item, _) = root.add_subtree(
                    f.subtrees.libp2p,
                    tvb,
                    *offset,
                    bytes.len() - offset,
                    "Unparseable stream data",
                );
                item.expert(pinfo, f.experts.malformed, reason);
                pinfo.append_info("desynchronised");
            }
        }
    }
}

/// Draws one pre-multiplexer message.
#[allow(clippy::too_many_arguments)]
fn render_handshake(
    f: &Fields,
    state: &DissectorState,
    kind: &HandshakeKind,
    tvb: Tvb<'_>,
    offset: usize,
    len: usize,
    body: usize,
    pinfo: &mut Pinfo<'_>,
    tree: Tree<'_>,
) {
    match kind {
        HandshakeKind::Multistream(message) => {
            let (item, sub) = tree.add_subtree(
                f.subtrees.handshake,
                tvb,
                offset,
                len,
                &format!("multistream-select: {}", message.text),
            );
            let _ = item;
            sub.add_uint(
                f.libp2p.ms_length,
                tvb,
                offset,
                body - offset,
                (len - (body - offset)) as u32,
            );
            sub.add_str(f.libp2p.ms_message, tvb, body, len - (body - offset), &message.text);
            pinfo.append_info(&format!("select {}", message.text));
        }
        HandshakeKind::Exchange(exchange) => {
            let (item, sub) = tree.add_subtree(f.subtrees.handshake, tvb, offset, len, "plaintext/2.0.0 exchange");

            sub.add_bytes(f.libp2p.pt_peer_id, tvb, body, len - (body - offset), &exchange.peer_id);
            if let Some(key) = &exchange.ed25519_key {
                sub.add_bytes(f.libp2p.pt_pubkey, tvb, body, len - (body - offset), key);
            }

            let label = state
                .registry
                .by_peer_id(&exchange.peer_id)
                .map(|node| node.name.clone());

            match label {
                Some(name) => {
                    sub.add_str(f.libp2p.pt_node, tvb, body, len - (body - offset), &name);
                    item.append(&format!(": {name}"));
                    pinfo.append_info(&format!("identified as {name}"));
                }
                None => {
                    item.expert(
                        pinfo,
                        f.experts.unknown_peer,
                        "this peer id is not one of the configured nodes; packets it sends cannot be attributed",
                    );
                    pinfo.append_info("plaintext exchange (unknown peer)");
                }
            }
        }
    }
}

/// Draws one yamux frame, and whatever completed inside it.
#[allow(clippy::too_many_arguments)]
fn render_yamux(
    f: &Fields,
    state: &DissectorState,
    header: &yamux::Header,
    tvb: Tvb<'_>,
    offset: usize,
    body: usize,
    pinfo: &mut Pinfo<'_>,
    tree: Tree<'_>,
    key: (Conversation, Direction, u32),
    next_unit: &mut usize,
    bytes: &[u8],
) {
    let flags = header.flags.names();
    let (item, sub) = tree.add_subtree(
        f.subtrees.yamux,
        tvb,
        offset,
        header.frame_len(),
        &format!(
            "yamux {} stream {}{}{}",
            header.frame_type.name(),
            header.stream_id,
            if flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", flags.join(","))
            },
            if header.frame_type == yamux::FrameType::Data {
                format!(", {} bytes", header.length)
            } else {
                String::new()
            }
        ),
    );
    let _ = item;

    sub.add(f.libp2p.yx_version, tvb, offset, 1, Encoding::BigEndian);
    sub.add(f.libp2p.yx_type, tvb, offset + 1, 1, Encoding::BigEndian);

    let flags_item = sub.add(f.libp2p.yx_flags, tvb, offset + 2, 2, Encoding::BigEndian);
    if !flags.is_empty() {
        let flag_tree = flags_item
            .append(&format!(" ({})", flags.join(", ")))
            .subtree(f.subtrees.yamux_flags);
        for field in [
            f.libp2p.yx_flag_syn,
            f.libp2p.yx_flag_ack,
            f.libp2p.yx_flag_fin,
            f.libp2p.yx_flag_rst,
        ] {
            flag_tree.add(field, tvb, offset + 2, 2, Encoding::BigEndian);
        }
    }

    sub.add(f.libp2p.yx_stream, tvb, offset + 4, 4, Encoding::BigEndian);
    sub.add(f.libp2p.yx_length, tvb, offset + 8, 4, Encoding::BigEndian);

    if header.frame_type != yamux::FrameType::Data {
        return;
    }

    // Units that completed inside this body, in the order the content pass produced them.
    let body_len = header.body_len();
    let units_before = *next_unit;
    {
        let Some(record) = state.recorded(&key) else {
            return;
        };
        while *next_unit < record.units.len() {
            let unit = &record.units[*next_unit];
            let unit_stream = match unit {
                Unit::Negotiated { stream_id, .. } => *stream_id,
                Unit::Packet(p) => p.stream_id,
                Unit::Opaque { stream_id, .. } => *stream_id,
            };
            if unit_stream != header.stream_id {
                break;
            }
            *next_unit += 1;

            match unit {
                Unit::Negotiated { protocol, .. } => {
                    sub.add_str(f.libp2p.yx_protocol, tvb, body, body_len, protocol);
                    pinfo.append_info(&format!("stream {} = {protocol}", header.stream_id));
                }
                Unit::Opaque { protocol, len, .. } => {
                    let (item, _) = sub.add_subtree(
                        f.subtrees.libp2p,
                        tvb,
                        body,
                        body_len,
                        &format!("{protocol}: {len} bytes (not decoded)"),
                    );
                    let _ = item;
                }
                Unit::Packet(packet) => {
                    // A packet whose bytes all sit in this frame is highlighted where they are;
                    // one that spans frames is shown as its own reassembled buffer instead.
                    // `then` rather than `then_some`: the latter evaluates its argument even
                    // when the condition is false, and the subtraction underflows for a frame
                    // shorter than a packet — which is every frame of a packet that spans several.
                    let contiguous = (body_len >= PACKET_SIZE
                        && bytes.len() >= body + body_len
                        && bytes[body + body_len - PACKET_SIZE..body + body_len] == packet.raw[..])
                        .then(|| body + body_len - PACKET_SIZE);

                    render_packet(f, state, packet, contiguous, tvb, pinfo, sub);
                }
            }
        }
    }

    // A frame carrying part of a packet completes nothing, and would otherwise leave the summary
    // column blank — which reads as "the dissector had nothing to say" rather than "this is the
    // middle of something". Saying so makes a packet split across frames visible in the list.
    if *next_unit == units_before {
        pinfo.append_info(&format!("stream {}, {body_len} bytes (continued)", header.stream_id));
    }
}

/// Draws one HOPR packet.
fn render_packet(
    f: &Fields,
    state: &DissectorState,
    packet: &PacketUnit,
    contiguous_at: Option<usize>,
    tvb: Tvb<'_>,
    pinfo: &mut Pinfo<'_>,
    tree: Tree<'_>,
) {
    // Where the packet's bytes live for the purpose of highlighting. When it spans frames there
    // is no single range to point at, so the reassembled bytes become their own data source and
    // offsets are taken into that instead.
    let (packet_tvb, at) = match contiguous_at {
        Some(offset) => (tvb, offset),
        None => (pinfo.add_data_source(tvb, "Reassembled HOPR Packet", &packet.raw), 0),
    };

    let kind = packet.decoded.as_ref().map(Decoded::kind).unwrap_or("Undecrypted");
    let (item, sub) = tree.add_subtree(
        f.subtrees.hopr,
        packet_tvb,
        at,
        PACKET_SIZE,
        &format!("HOPR Packet ({kind})"),
    );

    let decoded = match &packet.decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            sub.add(f.hopr.raw_packet, packet_tvb, at, PACKET_SIZE, Encoding::NotApplicable);
            sub.add_str(f.hopr.decrypt_error, packet_tvb, at, PACKET_SIZE, error);
            let expert = if state.registry.is_empty() {
                f.experts.no_keys
            } else {
                f.experts.decrypt_failed
            };
            item.expert(pinfo, expert, error);
            pinfo.append_info("HOPR packet (undecrypted)");
            return;
        }
    };

    sub.add_str(f.hopr.kind, packet_tvb, at, PACKET_SIZE, kind);
    sub.add_bytes(f.hopr.packet_tag, packet_tvb, at, PACKET_SIZE, decoded.packet_tag());

    match decoded {
        Decoded::Final(final_packet) => render_final(f, final_packet, packet_tvb, at, pinfo, sub, item),
        Decoded::Forwarded(fwd) => render_forwarded(f, state, fwd, packet_tvb, at, pinfo, sub, item),
        Decoded::Acknowledgements(acks) => {
            sub.add_uint(f.hopr.ack_count, packet_tvb, at, PACKET_SIZE, acks.count as u32);
            let (_, ack_tree) = sub.add_subtree(
                f.subtrees.acks,
                packet_tvb,
                at,
                PACKET_SIZE,
                &format!("Acknowledgements ({})", acks.acks.len()),
            );
            for ack in &acks.acks {
                ack_tree.add_bytes(f.hopr.ack, packet_tvb, at, PACKET_SIZE, ack);
            }
            item.append(&format!(": {} acknowledgements", acks.acks.len()));
            pinfo.append_info(&format!("{} acks", acks.acks.len()));
        }
    }
}

/// Draws a packet that reached its destination, and the application data inside it.
fn render_final(
    f: &Fields,
    packet: &hopr::FinalPacket,
    tvb: Tvb<'_>,
    at: usize,
    pinfo: &mut Pinfo<'_>,
    tree: Tree<'_>,
    item: TreeItem<'_>,
) {
    tree.add_bytes(f.hopr.pseudonym, tvb, at, PACKET_SIZE, packet.sender.as_ref());
    tree.add_bool(f.hopr.is_reply, tvb, at, PACKET_SIZE, packet.is_reply);
    tree.add_bytes(f.hopr.ack_key, tvb, at, PACKET_SIZE, packet.ack_key.as_ref());

    let signals = hopr::signal_names(packet.signals);
    tree.add_uint(f.hopr.signals, tvb, at, PACKET_SIZE, *packet.signals.as_ref() as u32);
    if !signals.is_empty() {
        let (_, signal_tree) = tree.add_subtree(
            f.subtrees.signals,
            tvb,
            at,
            PACKET_SIZE,
            &format!("Signals: {}", signals.join(", ")),
        );
        for name in &signals {
            signal_tree.add_str(f.hopr.signal_name, tvb, at, PACKET_SIZE, name);
        }
    }

    if !packet.surbs.is_empty() {
        tree.add_uint(f.hopr.surb_count, tvb, at, PACKET_SIZE, packet.surbs.len() as u32);
        let (_, surb_tree) = tree.add_subtree(
            f.subtrees.surbs,
            tvb,
            at,
            PACKET_SIZE,
            &format!("SURBs ({})", packet.surbs.len()),
        );
        for (id, surb) in &packet.surbs {
            render_surb(f, id, surb, tvb, at, surb_tree);
        }
    }

    // The decrypted payload gets its own tab in the bytes pane, so the user can read what the
    // sender wrote next to the ciphertext that carried it.
    let payload_tvb = pinfo.add_data_source(tvb, "Decrypted HOPR Payload", &packet.plain_text);
    let summary = app::dissect(f, &packet.plain_text, payload_tvb, pinfo, tree);

    item.append(&format!(": {summary}"));
    pinfo.append_info(&summary);
}

/// Draws one SURB.
fn render_surb(f: &Fields, id: &[u8], surb: &HoprSurb, tvb: Tvb<'_>, at: usize, tree: Tree<'_>) {
    let (_, sub) = tree.add_subtree(
        f.subtrees.surb,
        tvb,
        at,
        PACKET_SIZE,
        &format!("SURB {}", hex::encode(id)),
    );
    sub.add_bytes(f.hopr.surb_id, tvb, at, PACKET_SIZE, id);
    sub.add_uint(
        f.hopr.surb_first_relayer,
        tvb,
        at,
        PACKET_SIZE,
        u32::from_be_bytes(surb.first_relayer.as_ref().try_into().unwrap_or([0, 0, 0, 0])),
    );
}

/// Draws a packet passing through, and the ticket that paid for it.
#[allow(clippy::too_many_arguments)]
fn render_forwarded(
    f: &Fields,
    state: &DissectorState,
    packet: &hopr::ForwardedPacket,
    tvb: Tvb<'_>,
    at: usize,
    pinfo: &mut Pinfo<'_>,
    tree: Tree<'_>,
    item: TreeItem<'_>,
) {
    tree.add_uint(f.hopr.path_pos, tvb, at, PACKET_SIZE, packet.path_pos as u32);
    tree.add_bytes(f.hopr.ack_key, tvb, at, PACKET_SIZE, packet.ack_key.as_ref());
    tree.add_bytes(
        f.hopr.ack_challenge,
        tvb,
        at,
        PACKET_SIZE,
        packet.ack_challenge.as_ref(),
    );

    let next_hop = match packet.next_hop_id {
        Some(id) => {
            let raw = u32::from_be_bytes(id.as_ref().try_into().unwrap_or([0, 0, 0, 0]));
            tree.add_uint(f.hopr.next_hop_id, tvb, at, PACKET_SIZE, raw);

            match state.learner.resolve(&id).map(|key| state.registry.label(&key)) {
                Some(name) => {
                    tree.add_str(f.hopr.next_hop, tvb, at, PACKET_SIZE, &name);
                    name
                }
                None => {
                    tree.add_str(f.hopr.next_hop, tvb, at, PACKET_SIZE, "<unknown>").expert(
                        pinfo,
                        f.experts.key_id_unknown,
                        "the node this key identifier names has not been seen receiving a packet yet; \
                             it usually resolves once more of the capture has been read",
                    );
                    format!("key id {raw}")
                }
            }
        }
        None => "<unknown>".to_string(),
    };

    // The ticket is the one part of a relayed packet that was never encrypted, so its bytes can
    // be pointed at directly — they sit in the packet's tail.
    ticket::dissect(f, &packet.ticket, tvb, at + PACKET_SIZE - Ticket::SIZE, pinfo, tree);

    item.append(&format!(": to {next_hop}, {} hops left", packet.path_pos));
    pinfo.append_info(&format!("relay to {next_hop}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A varint-length-prefixed multistream-select message.
    fn ms(text: &str) -> Vec<u8> {
        let mut out = vec![(text.len() + 1) as u8];
        out.extend_from_slice(text.as_bytes());
        out.push(b'\n');
        out
    }

    /// A minimal plaintext `Exchange` carrying `peer_id`.
    fn exchange(peer_id: &[u8]) -> Vec<u8> {
        let mut body = vec![0x0a, peer_id.len() as u8];
        body.extend_from_slice(peer_id);
        let mut out = vec![body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    fn yamux_frame(stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8, 0, 0, 0];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn should_walk_a_whole_connection_setup() {
        let mut stream = Vec::new();
        stream.extend(ms(multistream::MULTISTREAM_HEADER));
        stream.extend(ms("/plaintext/2.0.0"));
        stream.extend(exchange(b"peer-one"));
        stream.extend(ms(multistream::MULTISTREAM_HEADER));
        stream.extend(ms("/yamux/1.0.0"));
        stream.extend(yamux_frame(1, b"hello"));

        let elements = layout(Phase::Handshake, false, &stream);

        assert_eq!(elements.len(), 6, "five handshake messages then one yamux frame");
        assert!(matches!(
            &elements[2],
            Element::Handshake {
                kind: HandshakeKind::Exchange(_),
                ..
            }
        ));
        assert!(
            matches!(&elements[5], Element::Yamux { header, .. } if header.stream_id == 1),
            "the stream must switch to yamux once the multiplexer is accepted"
        );
    }

    #[test]
    fn should_not_switch_to_yamux_before_the_exchange() {
        // The security protocol is accepted before the handshake runs; treating that acceptance
        // as the multiplexer's would read the exchange as a yamux frame.
        let mut stream = Vec::new();
        stream.extend(ms(multistream::MULTISTREAM_HEADER));
        stream.extend(ms("/plaintext/2.0.0"));
        stream.extend(exchange(b"peer-one"));

        let elements = layout(Phase::Handshake, false, &stream);
        assert!(matches!(
            &elements[2],
            Element::Handshake {
                kind: HandshakeKind::Exchange(_),
                ..
            }
        ));
    }

    #[test]
    fn should_report_how_much_more_is_needed_for_a_split_yamux_frame() {
        let frame = yamux_frame(3, &[0u8; 100]);
        let elements = layout(Phase::Yamux, true, &frame[..40]);

        assert_eq!(
            elements.last(),
            Some(&Element::Incomplete {
                offset: 0,
                needed: Some(yamux::HEADER_LEN + 100)
            })
        );
    }

    #[test]
    fn should_stop_at_the_first_unparseable_byte() {
        let mut stream = yamux_frame(1, b"ok");
        stream.extend_from_slice(&[9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);

        let elements = layout(Phase::Yamux, true, &stream);

        assert_eq!(elements.len(), 2);
        assert!(matches!(elements[0], Element::Yamux { .. }));
        assert!(
            matches!(elements[1], Element::Desync { .. }),
            "a bad version byte ends the walk rather than resynchronising by guesswork"
        );
    }

    #[test]
    fn a_desynchronised_stream_should_stay_desynchronised() {
        let elements = layout(Phase::Desynchronised, true, &yamux_frame(1, b"ok"));
        assert!(matches!(elements.as_slice(), [Element::Desync { offset: 0, .. }]));
    }

    #[test]
    fn walking_the_same_bytes_twice_should_give_the_same_answer() {
        let mut stream = Vec::new();
        stream.extend(ms(multistream::MULTISTREAM_HEADER));
        stream.extend(ms("/plaintext/2.0.0"));
        stream.extend(exchange(b"peer-one"));

        // This is what makes a revisit safe to draw from the framing walk alone.
        assert_eq!(
            layout(Phase::Handshake, false, &stream),
            layout(Phase::Handshake, false, &stream)
        );
    }
}
