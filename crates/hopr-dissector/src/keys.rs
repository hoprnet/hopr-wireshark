//! The cluster's node keys, and the key-identifier mapping that decryption needs.
//!
//! # What has to be supplied and what is worked out
//!
//! The only input is a packet (offchain) private key per node — either directly, or as the
//! encrypted identity file the node runs with. Everything else the dissector needs is derived or
//! observed:
//!
//! * which node is at each end of a TCP connection comes from the `/plaintext/2.0.0` handshake;
//! * a node's four-byte **key identifier**, which packet headers name the next hop by, is
//!   assigned by the chain — a counter over key bindings, so it cannot be derived from the key.
//!   Rather than make the user transcribe it, the dissector learns it from the traffic: see
//!   [`KeyIdLearner`].

use std::{collections::HashMap, path::Path};

use hopr_crypto_packet::{HoprKeyIdent, HoprSphinxHeaderSpec, HoprSphinxSuite, ProtocolKeyIdMapper};
use hopr_lib::api::types::{
    crypto::prelude::{Keypair, OffchainKeypair, OffchainPublicKey},
    primitive::prelude::KeyIdMapping,
};
use hopr_lib::{HoprKeys, IdentityRetrievalModes};
use serde::Deserialize;

/// Everything known about one node of the cluster.
pub struct Node {
    /// Label shown in the tree. Defaults to a short form of the public key.
    pub name: String,
    /// The node's packet key. Decrypts every packet addressed to it, at any hop.
    pub keypair: OffchainKeypair,
    /// The node's public key.
    pub public: OffchainPublicKey,
    /// The node's libp2p peer id, in the binary form the plaintext handshake carries.
    pub peer_id: Vec<u8>,
}

impl Node {
    fn new(name: Option<String>, keypair: OffchainKeypair) -> Self {
        let public = *keypair.public();
        let peer_id = hopr_lib::api::PeerId::from(&public).to_bytes();
        Self {
            name: name.unwrap_or_else(|| short_key(&public)),
            keypair,
            public,
            peer_id,
        }
    }
}

/// A short, readable form of a public key, for labels.
pub fn short_key(key: &OffchainPublicKey) -> String {
    let bytes = key.as_ref();
    format!(
        "{}…{}",
        hex::encode(&bytes[..3]),
        hex::encode(&bytes[bytes.len() - 3..])
    )
}

/// The cluster's nodes, indexed by the things the dissector looks them up by.
#[derive(Default)]
pub struct NodeRegistry {
    nodes: Vec<Node>,
    by_public: HashMap<OffchainPublicKey, usize>,
    by_peer_id: HashMap<Vec<u8>, usize>,
    /// Key identifiers taken from the configuration file, if any were given.
    configured_ids: HashMap<HoprKeyIdent, usize>,
}

impl NodeRegistry {
    /// Number of nodes loaded.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether no keys were loaded, in which case nothing can be decrypted.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Every node, in the order they were configured.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Looks a node up by its public key.
    pub fn by_public(&self, key: &OffchainPublicKey) -> Option<&Node> {
        self.by_public.get(key).map(|i| &self.nodes[*i])
    }

    /// Looks a node up by the binary peer id seen in a plaintext handshake.
    pub fn by_peer_id(&self, peer_id: &[u8]) -> Option<&Node> {
        self.by_peer_id.get(peer_id).map(|i| &self.nodes[*i])
    }

    /// The label for a public key, or a short hex form when the key is not one of ours.
    pub fn label(&self, key: &OffchainPublicKey) -> String {
        self.by_public(key)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| short_key(key))
    }

    fn push(&mut self, node: Node, key_id: Option<u32>) {
        let idx = self.nodes.len();
        self.by_public.insert(node.public, idx);
        self.by_peer_id.insert(node.peer_id.clone(), idx);
        if let Some(id) = key_id {
            self.configured_ids.insert(HoprKeyIdent::from(id), idx);
        }
        self.nodes.push(node);
    }

    /// Loads a registry from a TOML configuration file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let config: Config = toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
        config.into_registry(path)
    }
}

/// The `[[node]]` entries of the key file.
#[derive(Deserialize)]
struct Config {
    /// Load every `*.id` in this directory, using `identity_password`.
    ///
    /// A convenience for a local cluster, whose identities all sit in one directory under one
    /// password. Relative paths resolve against the key file's own directory.
    identity_dir: Option<String>,
    /// Password for the identity files found through `identity_dir`.
    identity_password: Option<String>,
    #[serde(default, rename = "node")]
    nodes: Vec<NodeConfig>,
}

/// One `[[node]]` entry.
#[derive(Deserialize)]
struct NodeConfig {
    /// Label for this node in the dissection. Defaults to a short form of its public key.
    name: Option<String>,
    /// The packet key as hex, with or without a `0x` prefix.
    packet_key: Option<String>,
    /// An encrypted identity file to take the packet key from.
    identity_file: Option<String>,
    /// Password for `identity_file`. Falls back to the file-level `identity_password`.
    password: Option<String>,
    /// The node's on-chain key identifier, when known. Learned from traffic when omitted.
    key_id: Option<u32>,
}

impl Config {
    fn into_registry(self, config_path: &Path) -> Result<NodeRegistry, String> {
        let base = config_path.parent().unwrap_or(Path::new("."));
        let mut registry = NodeRegistry::default();

        if let Some(dir) = &self.identity_dir {
            let password = self.identity_password.as_deref().ok_or(
                "`identity_dir` needs `identity_password`: identity files are encrypted and cannot be read without it",
            )?;
            let dir = base.join(dir);
            let mut entries: Vec<_> = std::fs::read_dir(&dir)
                .map_err(|e| format!("cannot list {}: {e}", dir.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|e| e == "id"))
                .collect();
            // Sorted so the order — and therefore the default labels — do not depend on the
            // filesystem's directory order.
            entries.sort();

            for path in entries {
                let name = path.file_stem().map(|s| s.to_string_lossy().into_owned());
                let keypair = load_identity(&path, password)?;
                registry.push(Node::new(name, keypair), None);
            }
        }

        for node in self.nodes {
            let keypair = match (&node.packet_key, &node.identity_file) {
                (Some(hex_key), None) => parse_packet_key(hex_key)?,
                (None, Some(file)) => {
                    let password = node
                        .password
                        .as_deref()
                        .or(self.identity_password.as_deref())
                        .ok_or_else(|| format!("`identity_file` {file} needs a `password`"))?;
                    load_identity(&base.join(file), password)?
                }
                (Some(_), Some(_)) => {
                    return Err("a node entry gives both `packet_key` and `identity_file`; use one".into());
                }
                (None, None) => return Err("a node entry gives neither `packet_key` nor `identity_file`".into()),
            };
            registry.push(Node::new(node.name, keypair), node.key_id);
        }

        if registry.is_empty() {
            return Err(format!("{} defines no nodes", config_path.display()));
        }

        Ok(registry)
    }
}

/// Parses a hex packet key.
fn parse_packet_key(text: &str) -> Result<OffchainKeypair, String> {
    let bytes = hex::decode(text.trim().trim_start_matches("0x"))
        .map_err(|e| format!("`packet_key` is not valid hexadecimal: {e}"))?;
    OffchainKeypair::from_secret(&bytes).map_err(|e| format!("`packet_key` is not a valid packet key: {e}"))
}

/// Reads the packet key out of an encrypted identity file.
fn load_identity(path: &Path, password: &str) -> Result<OffchainKeypair, String> {
    // `IdentityRetrievalModes::FromFile` *creates* an identity when the path does not exist,
    // which would be a surprising thing for a read-only tool to do to a mistyped path.
    if !path.exists() {
        return Err(format!("identity file {} does not exist", path.display()));
    }

    let keys = HoprKeys::try_from(IdentityRetrievalModes::FromFile {
        password,
        id_path: &path.to_string_lossy(),
    })
    .map_err(|e| format!("cannot read identity file {}: {e}", path.display()))?;

    Ok(keys.packet_key)
}

/// Resolves the four-byte key identifiers that packet headers name the next hop by.
///
/// # Why this has to learn
///
/// A key identifier is the index at which a node's key binding was added on chain, so nothing
/// about it can be computed from the key itself — only read from the chain, or observed.
/// Observing it is what this does, and it needs no chain access:
///
/// 1. A relay's decode asks for the key identifier of the next hop. If it is not yet known, the
///    identifier is remembered together with a fingerprint of the packet the relay will send on.
/// 2. That packet then appears on a connection whose far end the `/plaintext/2.0.0` handshake
///    already named. Matching the fingerprint binds the identifier to that node.
///
/// The fingerprint is over the Sphinx meta-packet only, because a relay replaces the ticket that
/// follows it — the meta-packet is the part that travels unchanged from one hop to the next.
///
/// Until an identifier is bound, decoding still succeeds: [`Resolver`] answers with a placeholder
/// so that the Sphinx transformation, which does not depend on the answer, can complete. The
/// dissection records the raw identifier rather than the placeholder, so a name that was unknown
/// on the first pass over a capture appears on the second.
#[derive(Default)]
pub struct KeyIdLearner {
    known: HashMap<HoprKeyIdent, OffchainPublicKey>,
    /// Fingerprint of a relayed meta-packet, to the identifier of the node it is going to.
    pending: HashMap<u64, HoprKeyIdent>,
}

impl KeyIdLearner {
    /// Seeds the identifiers that were given in the key file.
    pub fn with_configured(registry: &NodeRegistry) -> Self {
        Self {
            known: registry
                .configured_ids
                .iter()
                .map(|(id, idx)| (*id, registry.nodes[*idx].public))
                .collect(),
            pending: HashMap::new(),
        }
    }

    /// The public key an identifier stands for, if it is known yet.
    pub fn resolve(&self, id: &HoprKeyIdent) -> Option<OffchainPublicKey> {
        self.known.get(id).copied()
    }

    /// Records that a relay will forward `meta_packet` to whoever `id` names.
    pub fn expect_forward(&mut self, meta_packet: &[u8], id: HoprKeyIdent) {
        if self.known.contains_key(&id) {
            return;
        }
        self.pending.insert(fingerprint(meta_packet), id);
    }

    /// Records that `meta_packet` was seen travelling to `receiver`, binding any identifier that
    /// was waiting on it. Returns the identifier if one was learned.
    pub fn observe_arrival(&mut self, meta_packet: &[u8], receiver: &OffchainPublicKey) -> Option<HoprKeyIdent> {
        let id = self.pending.remove(&fingerprint(meta_packet))?;
        self.known.insert(id, *receiver);
        Some(id)
    }

    /// Number of identifiers resolved so far.
    pub fn learned(&self) -> usize {
        self.known.len()
    }
}

/// Hash of a meta-packet, used to recognise it again at the next hop.
///
/// A collision would mislabel one hop of one packet in a debugging view, so a keyed cryptographic
/// hash would buy nothing here that the default hasher does not already provide.
fn fingerprint(meta_packet: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    meta_packet.hash(&mut hasher);
    hasher.finish()
}

/// The [`KeyIdMapping`] handed to the Sphinx decoder for one packet.
///
/// Answers from what [`KeyIdLearner`] knows, and records what it was asked so the caller can
/// recover the identifier behind a placeholder answer. Single-use: one instance per decode.
pub struct Resolver<'a> {
    registry: &'a NodeRegistry,
    learner: &'a KeyIdLearner,
    asked: std::cell::RefCell<Vec<HoprKeyIdent>>,
}

impl<'a> Resolver<'a> {
    /// Creates a resolver for one decode.
    pub fn new(registry: &'a NodeRegistry, learner: &'a KeyIdLearner) -> Self {
        Self {
            registry,
            learner,
            asked: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// The identifiers the decode asked about, in the order it asked.
    ///
    /// For a relayed packet this is exactly one: the next hop.
    pub fn asked(&self) -> Vec<HoprKeyIdent> {
        self.asked.borrow().clone()
    }
}

impl KeyIdMapping<HoprKeyIdent, OffchainPublicKey> for Resolver<'_> {
    fn map_key_to_id(&self, key: &OffchainPublicKey) -> Option<HoprKeyIdent> {
        self.learner.known.iter().find(|(_, k)| *k == key).map(|(id, _)| *id)
    }

    fn map_id_to_public(&self, id: &HoprKeyIdent) -> Option<OffchainPublicKey> {
        self.asked.borrow_mut().push(*id);
        self.learner.resolve(id).or_else(|| {
            // A placeholder, not a guess: the Sphinx transformation does not consume the next
            // hop's key, so answering lets the decode finish and produce the relayed packet whose
            // arrival is what binds this identifier for good. The caller reads the identifier out
            // of `asked` and never displays the placeholder.
            self.registry.nodes.first().map(|n| n.public)
        })
    }
}

/// `Resolver` satisfies the decoder's bound through the blanket impl on `KeyIdMapping`.
const _: fn() = || {
    fn assert_mapper<T: ProtocolKeyIdMapper<HoprSphinxSuite, HoprSphinxHeaderSpec>>() {}
    assert_mapper::<Resolver<'_>>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_of(n: usize) -> NodeRegistry {
        let mut registry = NodeRegistry::default();
        for i in 0..n {
            registry.push(Node::new(Some(format!("node{i}")), OffchainKeypair::random()), None);
        }
        registry
    }

    #[test]
    fn should_index_nodes_by_public_key_and_peer_id() {
        let registry = registry_of(3);
        let node = &registry.nodes()[1];

        assert_eq!(registry.by_public(&node.public).map(|n| &n.name), Some(&node.name));
        assert_eq!(registry.by_peer_id(&node.peer_id).map(|n| &n.name), Some(&node.name));
        assert!(registry.by_peer_id(b"not a peer id").is_none());
    }

    #[test]
    fn should_label_an_unknown_key_by_its_hex_prefix() {
        let registry = registry_of(1);
        let stranger = *OffchainKeypair::random().public();

        assert_eq!(registry.label(&stranger), short_key(&stranger));
        assert_eq!(registry.label(&registry.nodes()[0].public), "node0");
    }

    #[test]
    fn learner_should_bind_an_identifier_when_the_packet_reaches_the_next_hop() {
        let registry = registry_of(2);
        let next_hop = registry.nodes()[1].public;
        let id = HoprKeyIdent::from(7u32);
        let meta_packet = b"the sphinx meta packet bytes";

        let mut learner = KeyIdLearner::default();
        assert_eq!(learner.resolve(&id), None);

        learner.expect_forward(meta_packet, id);
        assert_eq!(
            learner.observe_arrival(meta_packet, &next_hop),
            Some(id),
            "the same meta packet arriving at a known node binds the identifier"
        );
        assert_eq!(learner.resolve(&id), Some(next_hop));
    }

    #[test]
    fn learner_should_ignore_a_packet_it_was_not_waiting_for() {
        let registry = registry_of(2);
        let mut learner = KeyIdLearner::default();

        assert_eq!(
            learner.observe_arrival(b"never forwarded", &registry.nodes()[0].public),
            None
        );
        assert_eq!(learner.learned(), 0);
    }

    #[test]
    fn resolver_should_record_what_it_was_asked_and_still_answer() {
        let registry = registry_of(2);
        let learner = KeyIdLearner::default();
        let resolver = Resolver::new(&registry, &learner);
        let id = HoprKeyIdent::from(42u32);

        assert!(
            resolver.map_id_to_public(&id).is_some(),
            "an unknown identifier must still get an answer, so the decode can finish"
        );
        assert_eq!(resolver.asked(), vec![id]);
    }

    #[test]
    fn resolver_should_answer_a_learned_identifier_with_the_real_key() {
        let registry = registry_of(2);
        let expected = registry.nodes()[1].public;
        let id = HoprKeyIdent::from(3u32);

        let mut learner = KeyIdLearner::default();
        learner.expect_forward(b"packet", id);
        learner.observe_arrival(b"packet", &expected);

        let resolver = Resolver::new(&registry, &learner);
        assert_eq!(resolver.map_id_to_public(&id), Some(expected));
        assert_eq!(resolver.map_key_to_id(&expected), Some(id));
    }
}
