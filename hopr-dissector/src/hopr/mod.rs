//! Decryption of a HOPR packet, and dissection of everything the plaintext turns out to contain.
//!
//! # Where the keys come from, and why that is enough
//!
//! A HOPR packet on the wire is addressed to exactly one node — the one at the far end of the TCP
//! connection it is travelling on, which the `/plaintext/2.0.0` handshake named. Holding that
//! node's packet key is all it takes to peel one layer: the same operation a relay performs.
//! Doing it on every link of the cluster in turn is what lets a dissector follow a packet that no
//! single node can follow.
//!
//! Replies are the one case that needs more than a key. A packet sent on a SURB is decrypted by
//! its recipient with an opener that was never on the wire; the dissector reconstructs that
//! opener from the SURB it saw delivered earlier, using the return path's private keys. See
//! [`surbs`] and `hopr_crypto_packet::sphinx::reply_opener_from_surb`.

pub mod app;
pub mod probe;
pub mod session;
pub mod start;
pub mod surbs;
pub mod ticket;

use hopr_crypto_packet::{
    HoprKeyIdent, HoprSurb,
    prelude::{HoprPacket, HoprSurbId, PacketSignal, PacketSignals},
};
use hopr_lib::api::types::{
    crypto::prelude::{HalfKey, HalfKeyChallenge, OffchainPublicKey},
    internal::prelude::{HoprPseudonym, Ticket},
    primitive::prelude::{BytesEncodable, BytesRepresentable},
};

use crate::keys::{KeyIdLearner, NodeRegistry, Resolver};

/// Size of a HOPR packet on the wire.
///
/// Fixed: the `mix` protocol's codec reads exactly this many bytes per packet and adds no framing
/// of its own, which is what makes a substream of concatenated packets parseable at all.
pub const PACKET_SIZE: usize = HoprPacket::SIZE;

/// Size of the Sphinx meta-packet, the part of a packet that survives a hop unchanged.
pub const META_PACKET_SIZE: usize = PACKET_SIZE - Ticket::SIZE;

/// Size of one acknowledgement inside an acknowledgement packet.
pub const ACK_SIZE: usize = hopr_lib::api::types::internal::prelude::Acknowledgement::SIZE;

/// What one HOPR packet turned out to be.
pub enum Decoded {
    /// Addressed to the receiving node: carries an application payload.
    Final(Box<FinalPacket>),
    /// Passing through the receiving node on its way somewhere else.
    Forwarded(Box<ForwardedPacket>),
    /// Addressed to the receiving node, carrying acknowledgements rather than a payload.
    Acknowledgements(Box<AckPacket>),
}

impl Decoded {
    /// One-word name for the summary column.
    pub fn kind(&self) -> &'static str {
        match self {
            Decoded::Final(_) => "Final",
            Decoded::Forwarded(_) => "Forwarded",
            Decoded::Acknowledgements(_) => "Ack",
        }
    }

    /// The packet's replay-detection tag.
    pub fn packet_tag(&self) -> &[u8] {
        match self {
            Decoded::Final(p) => &p.packet_tag,
            Decoded::Forwarded(p) => &p.packet_tag,
            Decoded::Acknowledgements(p) => &p.packet_tag,
        }
    }
}

/// A packet whose final destination is the node that received it.
pub struct FinalPacket {
    pub packet_tag: Vec<u8>,
    /// Pseudonym the sender chose for itself. The nearest thing to a sender identity a final hop
    /// ever sees — the real sender is exactly what the mixnet hides.
    pub sender: HoprPseudonym,
    /// Acknowledgement key owed to the previous hop.
    pub ack_key: HalfKey,
    /// The decrypted payload, an `ApplicationData` encoding.
    pub plain_text: Vec<u8>,
    /// SURBs the sender attached for replies, paired with the ids they will be used under.
    pub surbs: Vec<(HoprSurbId, HoprSurb)>,
    /// Signals the sender raised, chiefly about running low on SURBs.
    pub signals: PacketSignals,
    /// Whether this packet arrived on one of the receiver's own SURBs, i.e. it is a reply.
    pub is_reply: bool,
}

/// A packet the receiving node will pass on.
pub struct ForwardedPacket {
    pub packet_tag: Vec<u8>,
    /// The key identifier naming the next hop, as it appeared in the header.
    ///
    /// Kept as the identifier rather than a resolved key so that a name the dissector had not
    /// learned yet when the frame was first parsed still resolves when the frame is looked at
    /// again. See [`crate::keys::KeyIdLearner`].
    pub next_hop_id: Option<HoprKeyIdent>,
    /// Position in the path, counting down towards the destination.
    pub path_pos: u8,
    /// Acknowledgement key owed to the previous hop.
    pub ack_key: HalfKey,
    /// Challenge the next hop's acknowledgement must answer.
    pub ack_challenge: HalfKeyChallenge,
    /// The ticket this relay was paid with.
    pub ticket: Ticket,
    /// The Sphinx meta-packet that will travel on, for recognising it at the next hop.
    pub outgoing_meta_packet: Vec<u8>,
}

/// A packet carrying acknowledgements of earlier packets.
pub struct AckPacket {
    pub packet_tag: Vec<u8>,
    /// How many acknowledgements the packet claims to carry.
    pub count: u16,
    /// The acknowledgements themselves, each [`ACK_SIZE`] bytes.
    pub acks: Vec<Vec<u8>>,
}

/// Names of the signals set in `signals`, most specific first.
///
/// The signals are not independent bits: `OutOfSurbs` is `SurbDistress` plus one, so a packet
/// announcing that the sender has run out also satisfies the test for "running low". Listing both
/// would be literally true and misleading — the sender raised one signal, not two — so a signal
/// whose bits are wholly covered by an already-listed one is left out.
pub fn signal_names(signals: PacketSignals) -> Vec<&'static str> {
    // Ordered widest-first, so the specific signal is the one that survives.
    const ORDERED: &[(PacketSignal, &str)] = &[
        (PacketSignal::OutOfSurbs, "OutOfSurbs"),
        (PacketSignal::SurbDistress, "SurbDistress"),
    ];

    let mut covered = 0u8;
    let mut out = Vec::new();
    for (signal, name) in ORDERED {
        // The bits have to come from the flag set rather than from `*signal as u8`: `flagset`
        // generates the enum without its discriminants, keeping the values only in the
        // `From<PacketSignal>` impl, so the cast would yield the variant's ordinal instead.
        let bits = *PacketSignals::from(*signal).as_ref();
        if signals.contains(*signal) && bits & !covered != 0 {
            covered |= bits;
            out.push(*name);
        }
    }
    out
}

/// Decrypts one HOPR packet.
///
/// `receiver` is the node the packet was addressed to — the far end of the connection it was seen
/// on — and `sender` the node that sent it. Both come from the transport layer, not from the
/// packet, because a Sphinx packet names neither.
pub fn decode(
    raw: &[u8],
    sender: &OffchainPublicKey,
    receiver: &crate::keys::Node,
    registry: &NodeRegistry,
    learner: &KeyIdLearner,
    surbs: &mut surbs::SurbTracker,
) -> Result<Decoded, String> {
    if raw.len() != PACKET_SIZE {
        return Err(format!("packet is {} bytes, expected {PACKET_SIZE}", raw.len()));
    }

    let resolver = Resolver::new(registry, learner);

    // Which SURB, if any, this packet came back on. Only the opener lookup knows, and by the time
    // the decoded packet exists the sender id it was keyed by is gone — so it is captured here.
    let replied_on = std::cell::Cell::new(false);

    let packet = HoprPacket::from_incoming(raw, &receiver.keypair, *sender, &resolver, |sender_id| {
        let opener = surbs.opener_for(sender_id, registry, learner);
        replied_on.set(opener.is_some());
        opener
    })
    .map_err(|e| e.to_string())?;

    match packet {
        HoprPacket::Final(incoming) => {
            let packet_tag = incoming.packet_tag.to_vec();

            match incoming.ack_key {
                // No acknowledgement is owed exactly when the payload *is* acknowledgements: the
                // sender set `no_ack` because acknowledging an acknowledgement would not end.
                None => Ok(Decoded::Acknowledgements(Box::new(parse_acks(
                    packet_tag,
                    &incoming.plain_text,
                )?))),
                Some(ack_key) => {
                    // Remember the SURBs before the packet is consumed: a reply arriving later
                    // can only be read with an opener rebuilt from one of them.
                    surbs.remember(incoming.sender, &incoming.surbs);

                    Ok(Decoded::Final(Box::new(FinalPacket {
                        packet_tag,
                        sender: incoming.sender,
                        ack_key,
                        plain_text: incoming.plain_text.into_vec(),
                        surbs: incoming.surbs,
                        signals: incoming.signals,
                        is_reply: replied_on.get(),
                    })))
                }
            }
        }
        HoprPacket::Forwarded(fwd) => {
            let outgoing_meta_packet = fwd.outgoing.packet.as_ref().to_vec();
            // Exactly one identifier is looked up while decoding a relayed packet: the next hop's.
            let next_hop_id = resolver.asked().first().copied();

            Ok(Decoded::Forwarded(Box::new(ForwardedPacket {
                packet_tag: fwd.packet_tag.to_vec(),
                next_hop_id,
                path_pos: fwd.path_pos,
                ack_key: fwd.ack_key,
                ack_challenge: fwd.outgoing.ack_challenge,
                ticket: fwd.outgoing.ticket,
                outgoing_meta_packet,
            })))
        }
        // `from_incoming` never produces this: it is the variant a *sender* constructs.
        HoprPacket::Outgoing(_) => Err("decoding produced an outgoing packet, which cannot happen here".into()),
    }
}

/// Splits an acknowledgement packet's payload into its acknowledgements.
fn parse_acks(packet_tag: Vec<u8>, plain_text: &[u8]) -> Result<AckPacket, String> {
    let count_bytes: [u8; 2] = plain_text
        .get(..2)
        .and_then(|b| b.try_into().ok())
        .ok_or("acknowledgement packet is too short to hold a count")?;
    let count = u16::from_be_bytes(count_bytes);

    let body = plain_text
        .get(2..2 + count as usize * ACK_SIZE)
        .ok_or_else(|| format!("acknowledgement packet claims {count} acknowledgements but is too short"))?;

    Ok(AckPacket {
        packet_tag,
        count,
        acks: body.chunks_exact(ACK_SIZE).map(<[u8]>::to_vec).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_names_should_not_report_distress_twice_for_out_of_surbs() {
        assert_eq!(signal_names(PacketSignals::default()), Vec::<&str>::new());
        assert_eq!(signal_names(PacketSignal::SurbDistress.into()), vec!["SurbDistress"]);
        assert_eq!(
            signal_names(PacketSignal::OutOfSurbs.into()),
            vec!["OutOfSurbs"],
            "OutOfSurbs subsumes SurbDistress's bit and must not also be reported as distress"
        );
    }

    #[test]
    fn should_split_an_acknowledgement_payload() -> anyhow::Result<()> {
        let mut payload = 2u16.to_be_bytes().to_vec();
        payload.extend(std::iter::repeat_n(0xaa, ACK_SIZE));
        payload.extend(std::iter::repeat_n(0xbb, ACK_SIZE));

        let acks = parse_acks(vec![0; 16], &payload).map_err(anyhow::Error::msg)?;

        assert_eq!(acks.count, 2);
        assert_eq!(acks.acks.len(), 2);
        assert!(acks.acks[0].iter().all(|b| *b == 0xaa));
        assert!(acks.acks[1].iter().all(|b| *b == 0xbb));
        Ok(())
    }

    #[test]
    fn should_reject_an_acknowledgement_payload_that_is_shorter_than_its_count() {
        let mut payload = 5u16.to_be_bytes().to_vec();
        payload.extend(std::iter::repeat_n(0, ACK_SIZE));

        assert!(
            parse_acks(vec![0; 16], &payload).is_err(),
            "a count past the end of the payload must not be read as truncated data"
        );
    }

    #[test]
    fn should_reject_an_acknowledgement_payload_with_no_count() {
        assert!(parse_acks(vec![0; 16], &[0x01]).is_err());
    }

    #[test]
    fn decoding_should_reject_a_packet_of_the_wrong_size() {
        use hopr_lib::api::types::crypto::prelude::{Keypair, OffchainKeypair};

        let registry = NodeRegistry::default();
        let learner = KeyIdLearner::default();
        let mut surbs = surbs::SurbTracker::default();
        let receiver = crate::keys::Node {
            name: "n".into(),
            public: *OffchainKeypair::random().public(),
            keypair: OffchainKeypair::random(),
            peer_id: Vec::new(),
        };
        let sender = *OffchainKeypair::random().public();

        assert!(
            decode(&[0u8; 10], &sender, &receiver, &registry, &learner, &mut surbs).is_err(),
            "a short buffer must be reported rather than fed to the Sphinx decoder"
        );
    }
}
