//! The ticket a relay is paid with, which travels in the tail of every relayed packet.

use epan::{Pinfo, Tree, Tvb};
use hopr_lib::api::types::{internal::prelude::Ticket, primitive::prelude::BytesEncodable};

use crate::fields::Fields;

/// Adds a ticket to the tree.
///
/// `offset` locates the ticket inside `tvb`, which for a relayed packet is the wire packet itself:
/// unlike everything above it, the ticket is not encrypted, so the tree can point at the real
/// bytes rather than at a decrypted copy.
pub fn dissect(f: &Fields, ticket: &Ticket, tvb: Tvb<'_>, offset: usize, _pinfo: &mut Pinfo<'_>, tree: Tree<'_>) {
    let (item, sub) = tree.add_subtree(
        f.subtrees.ticket,
        tvb,
        offset,
        Ticket::SIZE,
        &format!(
            "Ticket: #{}, {} to {}",
            ticket.index, ticket.amount, ticket.counterparty
        ),
    );
    let _ = item;

    sub.add_str(
        f.hopr.ticket_counterparty,
        tvb,
        offset,
        20,
        &ticket.counterparty.to_string(),
    );
    sub.add_str(
        f.hopr.ticket_amount,
        tvb,
        offset,
        Ticket::SIZE,
        &ticket.amount.to_string(),
    );
    sub.add_uint64(f.hopr.ticket_index, tvb, offset, Ticket::SIZE, ticket.index);
    sub.add_uint(
        f.hopr.ticket_channel_epoch,
        tvb,
        offset,
        Ticket::SIZE,
        ticket.channel_epoch,
    );
    sub.add_str(
        f.hopr.ticket_win_prob,
        tvb,
        offset,
        Ticket::SIZE,
        &format!("{}", ticket.win_prob()),
    );
    sub.add_bytes(
        f.hopr.ticket_challenge,
        tvb,
        offset,
        Ticket::SIZE,
        ticket.challenge.as_ref(),
    );

    match &ticket.signature {
        Some(signature) => {
            sub.add_bytes(f.hopr.ticket_signature, tvb, offset, Ticket::SIZE, signature.as_ref());
        }
        None => {
            // A ticket always carries a signature on the wire; an unsigned one here means the
            // trailing bytes did not parse as one, which is worth showing rather than omitting.
            sub.add_str(f.hopr.ticket_signature, tvb, offset, Ticket::SIZE, "<unsigned>");
        }
    }
}
