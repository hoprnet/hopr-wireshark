//! Tracking SURBs so that reply traffic can be read.
//!
//! # The problem
//!
//! Roughly half a Session's traffic travels on SURBs: the entry node mints them, attaches them to
//! forward packets, and the exit node uses them to send data back. A reply's payload is decrypted
//! with a `ReplyOpener` that its sender kept in memory and never transmitted, so a capture of the
//! wire contains everything needed to route a reply and nothing needed to read one.
//!
//! # What this does about it
//!
//! The opener is recoverable by anyone holding the private keys of the nodes on the return path,
//! because the per-hop shared secrets it is made of are exactly what those nodes derive when the
//! reply passes through them. So:
//!
//! 1. Every SURB seen arriving in a decrypted packet is remembered, keyed by the sender id the
//!    reply will carry — `pseudonym || surb_id`.
//! 2. When a reply does arrive, the SURB for its sender id is looked up and turned into an opener
//!    by walking the return path.
//!
//! Step 2 is deferred rather than done at step 1 on purpose: the walk needs every hop's key
//! identifier resolved, and identifiers are learned from traffic that may not have been seen yet
//! when the SURB was first observed. By the time a reply arrives, the forward path it answers has
//! been seen, so the identifiers are known.

use std::collections::HashMap;

use hopr_crypto_packet::{
    HoprSurb,
    prelude::{HoprSenderId, HoprSurbId, ReplyOpener},
};
use hopr_lib::api::types::internal::prelude::HoprPseudonym;

use crate::keys::{KeyIdLearner, NodeRegistry};

/// Remembers delivered SURBs and turns them into reply openers on demand.
#[derive(Default)]
pub struct SurbTracker {
    surbs: HashMap<HoprSenderId, HoprSurb>,
    /// Openers already reconstructed. A SURB is single-use, but Wireshark dissects a packet more
    /// than once, so the same opener is asked for again on every pass.
    openers: HashMap<HoprSenderId, ReplyOpener>,
    /// Sender ids whose walk failed, so a reply that cannot be opened is not retried on every
    /// pass over the capture.
    failed: HashMap<HoprSenderId, String>,
}

impl SurbTracker {
    /// Records the SURBs a final packet delivered.
    pub fn remember(&mut self, sender: HoprPseudonym, surbs: &[(HoprSurbId, HoprSurb)]) {
        for (id, surb) in surbs {
            let sender_id = HoprSenderId::from_pseudonym_and_id(&sender, *id);
            // A SURB is not overwritten once seen: Wireshark re-dissects the same frame, and the
            // second delivery of the same SURB must not disturb an opener already built from it.
            self.surbs.entry(sender_id).or_insert_with(|| surb.clone());
        }
    }

    /// The opener for a reply carrying `sender_id`, building it on first use.
    ///
    /// `None` when the SURB was never seen — a capture that started mid-Session — or when the
    /// return path runs through a node whose key was not supplied.
    pub fn opener_for(
        &mut self,
        sender_id: &HoprSenderId,
        registry: &NodeRegistry,
        learner: &KeyIdLearner,
    ) -> Option<ReplyOpener> {
        if let Some(opener) = self.openers.get(sender_id) {
            return Some(opener.clone());
        }
        if self.failed.contains_key(sender_id) {
            return None;
        }

        let surb = self.surbs.get(sender_id)?;

        match hopr_crypto_packet::sphinx::prelude::reply_opener_from_surb(surb, |id| {
            // A key identifier that has already been observed resolves to exactly one node.
            // One that has not is answered with every node in the cluster: the header's
            // authentication tag identifies which of them the identifier names, so this resolves
            // the hop rather than guessing at it. That matters here more than anywhere else — a
            // return path's first hop is often a node no packet has been *relayed to* yet, so
            // waiting for the identifier to be learned would leave the first replies of a
            // Session unreadable.
            match learner.resolve(id).and_then(|public| registry.by_public(&public)) {
                Some(node) => vec![&node.keypair],
                None => registry.nodes().iter().map(|node| &node.keypair).collect(),
            }
        }) {
            Ok(opener) => {
                self.openers.insert(*sender_id, opener.clone());
                Some(opener)
            }
            Err(error) => {
                self.failed.insert(*sender_id, error.to_string());
                None
            }
        }
    }

    /// Why the opener for `sender_id` could not be built, if it was tried and failed.
    pub fn failure(&self, sender_id: &HoprSenderId) -> Option<&str> {
        self.failed.get(sender_id).map(String::as_str)
    }

    /// How many SURBs are being tracked.
    pub fn tracked(&self) -> usize {
        self.surbs.len()
    }

    /// How many reply openers have been reconstructed.
    pub fn opened(&self) -> usize {
        self.openers.len()
    }
}

#[cfg(test)]
mod tests {
    use hopr_lib::api::types::crypto_random::Randomizable;

    use super::*;

    #[test]
    fn should_not_rebuild_an_opener_for_a_surb_it_has_never_seen() {
        let mut tracker = SurbTracker::default();
        let registry = NodeRegistry::default();
        let learner = KeyIdLearner::default();
        let sender_id = HoprSenderId::new(&HoprPseudonym::random());

        assert!(tracker.opener_for(&sender_id, &registry, &learner).is_none());
        assert_eq!(tracker.tracked(), 0);
        assert_eq!(tracker.opened(), 0);
    }
}
