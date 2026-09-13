//! A Wireshark dissector for the HOPR mixnet protocol stack.
//!
//! # What it dissects
//!
//! Live or captured TCP traffic between HOPR nodes, from the libp2p framing up through the
//! application protocols:
//!
//! ```text
//! TCP
//!  └─ multistream-select        protocol negotiation
//!      └─ /plaintext/2.0.0      peer identity exchange — names the node at each end
//!          └─ yamux             stream multiplexing
//!              └─ /hopr/mix/*   fixed-size HOPR packets
//!                  └─ Sphinx    decrypted with the receiving node's packet key
//!                      ├─ ticket, acknowledgements, SURBs
//!                      └─ ApplicationData
//!                          ├─ Probe
//!                          ├─ Session Start
//!                          └─ Session
//! ```
//!
//! # What it needs
//!
//! * **Nodes built with `hopr-transport-p2p`'s `insecure-plaintext` feature.** A production node
//!   negotiates `noise`, whose session keys are ephemeral and never leave the process; a capture
//!   of one is unreadable even to someone holding every node's packet key. The feature swaps that
//!   one layer for `/plaintext/2.0.0` and changes nothing else — the HOPR encryption this
//!   dissector is *about* is untouched.
//! * **The cluster's packet keys**, in a file named by the `hopr.key_file` preference. Everything
//!   else — which node is at each end of a connection, which node a key identifier names — is
//!   read off the wire or learned from the traffic.
//!
//! Without keys the libp2p framing is still dissected and HOPR packets are shown as ciphertext,
//! which is enough to see a Session's shape without being able to read it.

pub mod dissect;
pub mod fields;
pub mod hopr;
pub mod keys;
pub mod state;
pub mod wire;

use std::sync::OnceLock;

use epan::{Pinfo, Tree, Tvb, ffi_guard, sys};

epan::declare_plugin!(version = "0.1.0", protoinfo = protoinfo, handoff = handoff);

/// Everything registered with epan, built once during `protoinfo`.
///
/// A `OnceLock` rather than a plain `static mut`: registration and dissection happen on the same
/// thread, but the lock states the "written once, then only read" contract in the type rather
/// than in a comment.
static FIELDS: OnceLock<fields::Fields> = OnceLock::new();

/// The registered protocols and fields.
///
/// # Panics
/// If called before registration, which cannot happen: epan calls `protoinfo` before any
/// dissection, and nothing else reaches this.
fn fields() -> &'static fields::Fields {
    FIELDS.get().expect("fields are registered before any dissection")
}

/// Registers protocols, fields, subtrees, expert infos and preferences.
fn protoinfo() {
    let _ = FIELDS.set(fields::Fields::register());

    // SAFETY: both are plain callback registrations on the registration thread.
    unsafe {
        sys::register_init_routine(Some(init_capture));
        sys::register_cleanup_routine(Some(cleanup_capture));
    }
}

/// Attaches the dissector to TCP.
fn handoff() {
    let f = fields();

    // SAFETY: the strings are `'static` C literals, and the handle is created for a protocol
    // registered in the phase before this one.
    unsafe {
        let handle = sys::create_dissector_handle(Some(dissect_tcp), f.proto_hopr.id());
        HANDLE.set(handle as usize).ok();

        // Attached heuristically rather than by port: a local cluster's nodes pick their ports
        // from configuration, and requiring the user to list them is both a chore and a way to
        // miss traffic. The heuristic looks for libp2p's opening bytes, which are specific
        // enough that a false positive would have to be a stream that begins by announcing
        // multistream-select.
        sys::heur_dissector_add(
            c"tcp".as_ptr(),
            Some(heuristic),
            c"HOPR over libp2p".as_ptr(),
            c"hopr_tcp".as_ptr(),
            f.proto_hopr.id(),
            sys::HEURISTIC_ENABLE,
        );
    }
}

/// The dissector handle, kept so the heuristic can pin it to a conversation.
static HANDLE: OnceLock<usize> = OnceLock::new();

/// The opening bytes of a libp2p connection: the length-prefixed multistream-select header.
const LIBP2P_OPENING: &[u8] = b"\x13/multistream/1.0.0\n";

/// Decides whether a TCP stream is libp2p.
///
/// # Safety
/// Called by epan with a valid tvb, `packet_info` and tree.
unsafe extern "C" fn heuristic(
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    _data: *mut std::ffi::c_void,
) -> bool {
    ffi_guard("heuristic", false, || {
        // SAFETY: the pointers are valid for this call, which is what the wrappers borrow for.
        let tvb_safe = unsafe { Tvb::from_raw(tvb) };
        let mut pinfo_safe = unsafe { Pinfo::from_raw(pinfo) };

        let Some(opening) = tvb_safe.bytes(0, LIBP2P_OPENING.len()) else {
            return false;
        };
        if opening != LIBP2P_OPENING {
            return false;
        }

        // Pinning the dissector to the conversation means later packets skip the heuristic —
        // which they must, since only the first bytes of the stream carry the signature.
        if let Some(handle) = HANDLE.get() {
            // SAFETY: `handle` was produced by `create_dissector_handle` during handoff.
            unsafe {
                let conv = sys::find_or_create_conversation(pinfo);
                sys::conversation_set_dissector(conv, *handle as sys::dissector_handle_t);
            }
        }

        // SAFETY: as above.
        let tree_safe = unsafe { Tree::from_raw(tree, &fields().registered) };
        dissect::dissect_tcp(fields(), tvb_safe, &mut pinfo_safe, tree_safe);
        true
    })
}

/// Dissects one TCP payload.
///
/// # Safety
/// Called by epan with a valid tvb, `packet_info` and tree.
unsafe extern "C" fn dissect_tcp(
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    _data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    ffi_guard("dissect_tcp", 0, || {
        // SAFETY: the pointers are valid for this call.
        let tvb_safe = unsafe { Tvb::from_raw(tvb) };
        let mut pinfo_safe = unsafe { Pinfo::from_raw(pinfo) };
        let tree_safe = unsafe { Tree::from_raw(tree, &fields().registered) };

        dissect::dissect_tcp(fields(), tvb_safe, &mut pinfo_safe, tree_safe) as std::ffi::c_int
    })
}

/// Drops per-capture state when a file is opened or a capture starts.
///
/// # Safety
/// Called by epan between captures, on the dissection thread.
unsafe extern "C" fn init_capture() {
    ffi_guard("init_capture", (), || {
        state::with_state(|state| state.reset_for_new_capture());
    });
}

/// Drops per-capture state when a capture is closed.
///
/// # Safety
/// As [`init_capture`].
unsafe extern "C" fn cleanup_capture() {
    ffi_guard("cleanup_capture", (), || {
        state::with_state(|state| state.reset_for_new_capture());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_heuristic_signature_should_be_the_libp2p_opening_message() {
        // 0x13 is 19: the length of "/multistream/1.0.0\n". A signature whose prefix disagreed
        // with its body would never match a real stream.
        assert_eq!(LIBP2P_OPENING[0] as usize, LIBP2P_OPENING.len() - 1);
        assert_eq!(&LIBP2P_OPENING[1..], b"/multistream/1.0.0\n");
    }
}
