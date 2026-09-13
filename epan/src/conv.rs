//! Conversation identity.
//!
//! epan's own `conversation_add_proto_data` stores a `void *` that has to be allocated from a
//! `wmem` pool, which is an awkward home for Rust state. This wrapper takes only the *identity*
//! of a conversation from epan and leaves the state itself on the Rust side, keyed by that
//! identity — see the dissector's `state` module. Dissection is single-threaded, so a plain map
//! guarded by a `RefCell` is enough.

use crate::{sys, tree::Pinfo};

/// Identity of the transport-layer conversation a packet belongs to.
///
/// Stable for as long as a capture file is open, and distinct for each TCP connection, which is
/// exactly the scope a libp2p connection's parse state needs. It is *not* stable across files:
/// state keyed by it must be dropped when Wireshark loads a new one.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Conversation(usize);

impl Conversation {
    /// The conversation this packet belongs to, creating it if this is the first packet seen.
    pub fn of(pinfo: &mut Pinfo<'_>) -> Self {
        // SAFETY: `pinfo` is valid for the dissector call. `find_or_create_conversation` never
        // returns null — it allocates when there is no match.
        let conv = unsafe { sys::find_or_create_conversation(pinfo.as_raw()) };
        Self(conv as usize)
    }

    /// A distinct identity with no conversation behind it, for tests of state keyed by one.
    ///
    /// Not `cfg(test)`: the dissector's own tests are in a different crate and need it too, and a
    /// value that names no conversation is harmless — nothing here dereferences the identity.
    pub fn of_raw_for_test(id: usize) -> Self {
        Self(id)
    }
}

/// Which side of a conversation a packet is travelling on.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// From the endpoint that opened the conversation.
    Forward,
    /// Towards the endpoint that opened the conversation.
    Reverse,
}

impl Direction {
    /// Classifies a packet by comparing its ports.
    ///
    /// A TCP stream has two independent byte streams and each needs its own parse state, so every
    /// lookup is keyed by direction as well as conversation. The comparison is arbitrary but
    /// consistent: which of the two is "forward" does not matter as long as a given direction
    /// always lands on the same answer.
    pub fn of(pinfo: &Pinfo<'_>) -> Self {
        if pinfo.src_port() > pinfo.dst_port() {
            Direction::Forward
        } else {
            Direction::Reverse
        }
    }
}
