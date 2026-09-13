//! A miniature HOPR cluster, and real packets sent across it.
//!
//! Packets are built with `hopr-crypto-packet` itself rather than with fixtures: a capture made
//! of hand-written bytes would only prove the dissector agrees with the test's idea of the wire
//! format, which is the thing under test.

use bimap::BiHashMap;
use hopr_crypto_packet::{
    HoprKeyIdent, HoprSurb,
    prelude::{HoprPacket, HoprSenderId, HoprSurbId, PacketRouting, PacketSignals},
    sphinx::prelude::SimpleBiMapper,
};
use hopr_lib::api::types::{
    crypto::prelude::{ChainKeypair, Hash, Keypair, OffchainKeypair, OffchainPublicKey},
    internal::prelude::{HoprPseudonym, TicketBuilder, TransportPath, WinningProbability},
    primitive::prelude::{BytesEncodable, KeyIdent, U256},
};

/// One node: the two keypairs it runs with, and the identifier the chain gave it.
pub struct Node {
    pub name: String,
    pub packet_key: OffchainKeypair,
    pub chain_key: ChainKeypair,
    pub key_id: HoprKeyIdent,
}

impl Node {
    pub fn public(&self) -> OffchainPublicKey {
        *self.packet_key.public()
    }
}

/// A cluster of nodes that can send packets to each other.
pub struct Cluster {
    pub nodes: Vec<Node>,
    mapper: SimpleBiMapper<hopr_crypto_packet::HoprSphinxSuite, hopr_crypto_packet::HoprSphinxHeaderSpec>,
}

impl Cluster {
    /// Builds `count` nodes with key identifiers `0..count`.
    pub fn new(count: usize) -> Self {
        let nodes: Vec<Node> = (0..count)
            .map(|i| Node {
                name: format!("node{i}"),
                packet_key: OffchainKeypair::random(),
                chain_key: ChainKeypair::random(),
                key_id: KeyIdent::from(i as u32),
            })
            .collect();

        let mapper = nodes
            .iter()
            .map(|n| (n.key_id, n.public()))
            .collect::<BiHashMap<_, _>>()
            .into();

        Self { nodes, mapper }
    }

    /// The TOML the dissector's `hopr.key_file` preference points at.
    ///
    /// Deliberately gives only the packet keys, with no key identifiers: resolving those from the
    /// traffic is part of what the dissector is being tested on.
    pub fn key_file(&self) -> String {
        let mut out = String::new();
        for node in &self.nodes {
            out.push_str("[[node]]\n");
            out.push_str(&format!("name = \"{}\"\n", node.name));
            out.push_str(&format!(
                "packet_key = \"{}\"\n\n",
                hex::encode(node.packet_key.secret().as_ref())
            ));
        }
        out
    }

    /// Builds a packet from `nodes[0]` along `path`, optionally attaching a return path.
    ///
    /// Returns the wire bytes of the packet as it leaves the sender, and the openers the sender
    /// keeps — which the dissector is expected to reconstruct from the SURBs alone.
    pub fn send(
        &self,
        pseudonym: &HoprPseudonym,
        path: &[usize],
        return_path: Option<&[usize]>,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let forward_path = TransportPath::new(path.iter().map(|i| self.nodes[*i].public()))?;
        let return_paths = match return_path {
            Some(hops) => vec![TransportPath::new(hops.iter().map(|i| self.nodes[*i].public()))?],
            None => vec![],
        };

        let ticket = ticket_for(&self.nodes[path[0]], path.len());
        let ssa_gen = hopr_protocol_pix::SsaShareGenerator::new(Default::default());

        let (packet, _openers) = HoprPacket::into_outgoing(
            payload,
            pseudonym,
            PacketRouting::ForwardPath {
                forward_path,
                return_paths,
                generation: 0,
            },
            &self.nodes[0].chain_key,
            ticket,
            &self.mapper,
            &Hash::default(),
            &ssa_gen,
            PacketSignals::default(),
        )?;

        wire_bytes(packet)
    }

    /// Builds a reply packet that travels back along `surb`'s return path.
    pub fn reply(
        &self,
        sender: usize,
        sender_id: HoprSenderId,
        surb: HoprSurb,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let hops = surb.additional_data_receiver.proof_of_relay_values().chain_length() as usize;
        let ticket = ticket_for(&self.nodes[sender], hops);
        let ssa_gen = hopr_protocol_pix::SsaShareGenerator::new(Default::default());

        let (packet, _) = HoprPacket::into_outgoing(
            payload,
            &sender_id.pseudonym(),
            PacketRouting::<TransportPath>::Surb(sender_id, surb),
            &self.nodes[sender].chain_key,
            ticket,
            &self.mapper,
            &Hash::default(),
            &ssa_gen,
            PacketSignals::default(),
        )?;

        wire_bytes(packet)
    }

    /// Decodes `raw` at `node`, the way that node would.
    ///
    /// The test uses this to take the SURBs out of a delivered packet so it can build a reply —
    /// the same thing an exit node does, and the only way to get a SURB that is really on the
    /// wire rather than one the test kept a copy of.
    pub fn receive(&self, node: usize, previous_hop: usize, raw: &[u8]) -> anyhow::Result<HoprPacket> {
        Ok(HoprPacket::from_incoming(
            raw,
            &self.nodes[node].packet_key,
            self.nodes[previous_hop].public(),
            &self.mapper,
            |_| None,
        )?)
    }

    /// Relays `raw` at `node`, producing the bytes that node sends on to the next hop.
    ///
    /// The Sphinx meta-packet travels unchanged; the ticket does not, because each relay is paid
    /// by the one before it. Replacing it is what makes this a real forward rather than a replay,
    /// and it is also what the dissector's key-identifier learning has to see through: it
    /// recognises the packet at the next hop by the meta-packet alone.
    pub fn relay(&self, node: usize, previous_hop: usize, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        let HoprPacket::Forwarded(mut fwd) = self.receive(node, previous_hop, raw)? else {
            anyhow::bail!("the packet is not one this node relays");
        };

        // `path_pos` counts hops remaining, so the ticket the next hop is owed is worth that much.
        fwd.outgoing.ticket = ticket_for(&self.nodes[node], fwd.path_pos as usize + 1)
            .eth_challenge(fwd.next_challenge)
            .build_signed(&self.nodes[node].chain_key, &Hash::default())?
            .leak();

        let mut bytes = fwd.outgoing.packet.as_ref().to_vec();
        bytes.extend_from_slice(&fwd.outgoing.ticket.into_boxed());
        Ok(bytes)
    }

    /// The sender id a reply on the SURB at `index` of a delivered packet will carry.
    pub fn sender_id(pseudonym: &HoprPseudonym, surb_id: HoprSurbId) -> HoprSenderId {
        HoprSenderId::from_pseudonym_and_id(pseudonym, surb_id)
    }
}

/// Serialises a freshly built packet the way the transport puts it on the wire.
///
/// `HoprPacket` has no public encoder — a node hands the parts to its codec rather than asking
/// the packet to serialise itself — so the two parts are concatenated here: the Sphinx
/// meta-packet, then the ticket that pays the first hop.
fn wire_bytes(packet: HoprPacket) -> anyhow::Result<Vec<u8>> {
    let HoprPacket::Outgoing(out) = packet else {
        anyhow::bail!("a freshly built packet is always outgoing");
    };

    let mut bytes = out.packet.as_ref().to_vec();
    bytes.extend_from_slice(&out.ticket.into_boxed());
    anyhow::ensure!(
        bytes.len() == HoprPacket::SIZE,
        "encoded packet is {} bytes, expected {}",
        bytes.len(),
        HoprPacket::SIZE
    );
    Ok(bytes)
}

/// A ticket good enough to pass the relay's structural checks.
///
/// The dissector never validates a ticket against a channel — it has no chain — so the values
/// only have to be well formed and signed.
fn ticket_for(next_hop: &Node, path_len: usize) -> TicketBuilder {
    let price_per_packet: U256 = 10_000_000_000_000_000u128.into();

    if path_len > 1 {
        TicketBuilder::default()
            .counterparty(next_hop.chain_key.public().to_address())
            .amount(price_per_packet * U256::from(path_len as u64 - 1))
            .index(1)
            .win_prob(WinningProbability::ALWAYS)
            .channel_epoch(1)
            .eth_challenge(Default::default())
    } else {
        TicketBuilder::zero_hop().counterparty(next_hop.chain_key.public().to_address())
    }
}
