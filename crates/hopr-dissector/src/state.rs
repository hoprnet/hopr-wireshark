//! State the dissector carries across packets, and the discipline that keeps it consistent.
//!
//! # Why the state lives here rather than in epan
//!
//! epan offers `conversation_add_proto_data` for exactly this, but it stores a `void *` that has
//! to come from a `wmem` pool — an awkward home for Rust values with destructors. Instead only the
//! *identity* of a conversation is taken from epan, and everything hanging off it lives in a
//! process-wide map. Dissection is single-threaded, so a `RefCell` is all the synchronisation
//! needed, and Wireshark's init routine clears the map when a new capture file is opened.
//!
//! # The two-pass problem
//!
//! Wireshark dissects every packet at least twice: once while reading the file or capturing, and
//! again whenever the user selects it. A dissector that advances stream state on every call would
//! double-count, and one that advanced it only on the first call would draw nothing the second
//! time. The split here is:
//!
//! * **Framing** is recomputed on every visit. It is a pure function of the parse phase at the
//!   start of the frame and the bytes in front of it, so it produces the same answer every time —
//!   which also means TCP's desegmentation requests are re-issued correctly on later passes.
//! * **Content** — the bytes accumulated per substream, the SURBs seen, the key identifiers
//!   learned — advances only on the first visit, and what it produced is recorded per frame and
//!   replayed afterwards.
//!
//! The only thing that has to be remembered to make the framing reproducible is the phase at the
//! start of each frame, which is one byte.

use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
};

use epan::conv::{Conversation, Direction};
use hopr_lib::api::types::crypto::prelude::OffchainPublicKey;

use crate::{
    hopr::{Decoded, surbs::SurbTracker},
    keys::{KeyIdLearner, NodeRegistry},
};

/// Where in a connection's byte stream the parser is.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum Phase {
    /// Varint-length-prefixed messages: multistream-select negotiation and the plaintext
    /// handshake, which share a framing and so are read by one loop.
    #[default]
    Handshake,
    /// yamux frames.
    Yamux,
    /// The stream stopped making sense and parsing it further would only produce noise.
    Desynchronised,
}

/// Parse state for one direction of one connection.
#[derive(Default)]
pub struct StreamState {
    /// Phase after everything seen so far.
    pub phase: Phase,
    /// Whether the plaintext `Exchange` has been seen. Until it has, a length-prefixed message
    /// that is not multistream-select must be the handshake; afterwards the next accepted
    /// protocol is the multiplexer, and the stream moves on to yamux frames.
    pub exchange_seen: bool,
    /// Per-substream state, keyed by yamux stream id.
    pub substreams: HashMap<u32, Substream>,
}

/// State of one yamux substream.
#[derive(Default)]
pub struct Substream {
    /// The application protocol negotiated on it, once negotiation finishes.
    pub protocol: Option<String>,
    /// Substream bytes not yet forming a complete unit of that protocol.
    ///
    /// A yamux frame boundary has nothing to do with a HOPR packet boundary, so a packet
    /// routinely spans several frames and occasionally shares one.
    pub pending: Vec<u8>,
}

/// What one frame's content pass produced, replayed on later visits.
#[derive(Default)]
pub struct FrameRecord {
    /// Units completed in this frame, in the order they completed.
    pub units: Vec<Unit>,
}

/// One thing that completed within a frame.
pub enum Unit {
    /// A protocol was negotiated on a substream.
    Negotiated { stream_id: u32, protocol: String },
    /// A HOPR packet finished arriving.
    Packet(Box<PacketUnit>),
    /// Substream bytes on a protocol this dissector does not decode.
    Opaque {
        stream_id: u32,
        protocol: String,
        len: usize,
    },
}

/// A complete HOPR packet and what decrypting it produced.
pub struct PacketUnit {
    /// The yamux substream it arrived on.
    pub stream_id: u32,
    /// The packet exactly as it appeared on the wire.
    ///
    /// Kept even when the packet sits whole inside one frame: the renderer compares it against
    /// the frame's bytes to decide whether the tree can point at them, and falls back to showing
    /// this as a reassembled data source when it cannot.
    pub raw: Vec<u8>,
    /// The decryption result, or why there is none.
    pub decoded: Result<Decoded, String>,
}

/// Everything the dissector knows about the capture currently open.
#[derive(Default)]
pub struct DissectorState {
    /// The cluster's keys, and the error from the last attempt to load them.
    pub registry: NodeRegistry,
    pub key_file: Option<PathBuf>,
    pub key_error: Option<String>,

    pub learner: KeyIdLearner,
    pub surbs: SurbTracker,

    streams: HashMap<(Conversation, Direction), StreamState>,
    /// Phase at the start of each frame, so the framing pass reproduces itself on later visits.
    phase_at_frame: HashMap<(Conversation, Direction, u32), (Phase, bool)>,
    records: HashMap<(Conversation, Direction, u32), FrameRecord>,
    /// The node sending in each direction, from the plaintext handshake.
    senders: HashMap<(Conversation, Direction), OffchainPublicKey>,
}

impl DissectorState {
    /// Drops everything tied to the capture file, keeping the loaded keys.
    ///
    /// Called from Wireshark's init routine, which runs when a file is opened or a capture starts.
    /// The keys survive because they come from a preference, not from the capture.
    pub fn reset_for_new_capture(&mut self) {
        self.learner = KeyIdLearner::with_configured(&self.registry);
        self.surbs = SurbTracker::default();
        self.streams.clear();
        self.phase_at_frame.clear();
        self.records.clear();
        self.senders.clear();
    }

    /// Reloads the node keys if the configured path has changed.
    ///
    /// Returns whether anything changed, so the caller can reset derived state.
    pub fn ensure_keys(&mut self, path: Option<&Path>) -> bool {
        if path == self.key_file.as_deref() {
            return false;
        }

        self.key_file = path.map(Path::to_path_buf);
        match path {
            None => {
                self.registry = NodeRegistry::default();
                self.key_error = None;
            }
            Some(path) => match NodeRegistry::load(path) {
                Ok(registry) => {
                    self.registry = registry;
                    self.key_error = None;
                }
                Err(error) => {
                    self.registry = NodeRegistry::default();
                    self.key_error = Some(error);
                }
            },
        }
        self.learner = KeyIdLearner::with_configured(&self.registry);
        true
    }

    /// The phase to start a frame's framing pass from.
    ///
    /// On a frame's first visit this is the current phase, which is also recorded; on later visits
    /// it is whatever was recorded then.
    pub fn phase_for_frame(&mut self, key: (Conversation, Direction, u32), visited: bool) -> (Phase, bool) {
        if visited && let Some(state) = self.phase_at_frame.get(&key) {
            return *state;
        }
        let stream = self.streams.entry((key.0, key.1)).or_default();
        let state = (stream.phase, stream.exchange_seen);
        self.phase_at_frame.insert(key, state);
        state
    }

    /// The mutable stream state for a direction.
    pub fn stream(&mut self, conv: Conversation, dir: Direction) -> &mut StreamState {
        self.streams.entry((conv, dir)).or_default()
    }

    /// Records which node sends in a direction, as learned from the plaintext handshake.
    pub fn set_sender(&mut self, conv: Conversation, dir: Direction, key: OffchainPublicKey) {
        self.senders.insert((conv, dir), key);
    }

    /// The node sending in a direction, if the handshake has been seen.
    pub fn sender(&self, conv: Conversation, dir: Direction) -> Option<OffchainPublicKey> {
        self.senders.get(&(conv, dir)).copied()
    }

    /// The node receiving in a direction: the one sending in the other.
    pub fn receiver(&self, conv: Conversation, dir: Direction) -> Option<OffchainPublicKey> {
        self.senders.get(&(conv, opposite(dir))).copied()
    }

    /// Stores what a frame's content pass produced.
    pub fn record(&mut self, key: (Conversation, Direction, u32), record: FrameRecord) {
        self.records.insert(key, record);
    }

    /// What a frame's content pass produced, if it has run.
    pub fn recorded(&self, key: &(Conversation, Direction, u32)) -> Option<&FrameRecord> {
        self.records.get(key)
    }
}

/// The other direction of a conversation.
pub fn opposite(dir: Direction) -> Direction {
    match dir {
        Direction::Forward => Direction::Reverse,
        Direction::Reverse => Direction::Forward,
    }
}

thread_local! {
    /// The dissector's state.
    ///
    /// Thread-local rather than a global with a lock because epan dissects on one thread; making
    /// that assumption explicit is better than a mutex that would never be contended and would
    /// hide the day the assumption stops holding.
    static STATE: RefCell<DissectorState> = RefCell::new(DissectorState::default());
}

/// Runs `f` with the dissector's state.
pub fn with_state<T>(f: impl FnOnce(&mut DissectorState) -> T) -> T {
    STATE.with(|state| f(&mut state.borrow_mut()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_reload_keys_only_when_the_path_changes() {
        let mut state = DissectorState::default();

        assert!(!state.ensure_keys(None), "no path to no path is not a change");

        let missing = PathBuf::from("/nonexistent/hopr-keys.toml");
        assert!(state.ensure_keys(Some(&missing)), "a new path is a change");
        assert!(state.key_error.is_some(), "a path that cannot be read must be reported");
        assert!(
            !state.ensure_keys(Some(&missing)),
            "the same path again is not a change"
        );

        assert!(state.ensure_keys(None), "clearing the path is a change");
        assert!(state.key_error.is_none());
    }

    #[test]
    fn should_replay_the_recorded_phase_on_a_revisit() {
        let mut state = DissectorState::default();
        let conv = Conversation::of_raw_for_test(1);
        let key = (conv, Direction::Forward, 7);

        assert_eq!(state.phase_for_frame(key, false), (Phase::Handshake, false));

        // The stream moves on, as it would once the handshake completes.
        let stream = state.stream(conv, Direction::Forward);
        stream.phase = Phase::Yamux;
        stream.exchange_seen = true;

        assert_eq!(
            state.phase_for_frame(key, true),
            (Phase::Handshake, false),
            "revisiting frame 7 must parse it the way it was parsed the first time"
        );
        assert_eq!(
            state.phase_for_frame((conv, Direction::Forward, 8), false),
            (Phase::Yamux, true),
            "a frame seen for the first time starts from where the stream actually is"
        );
    }

    #[test]
    fn receiver_should_be_the_sender_of_the_other_direction() {
        use hopr_lib::api::types::crypto::prelude::{Keypair, OffchainKeypair};

        let mut state = DissectorState::default();
        let conv = Conversation::of_raw_for_test(2);
        let a = *OffchainKeypair::random().public();
        let b = *OffchainKeypair::random().public();

        state.set_sender(conv, Direction::Forward, a);
        state.set_sender(conv, Direction::Reverse, b);

        assert_eq!(state.sender(conv, Direction::Forward), Some(a));
        assert_eq!(state.receiver(conv, Direction::Forward), Some(b));
        assert_eq!(state.receiver(conv, Direction::Reverse), Some(a));
    }
}
