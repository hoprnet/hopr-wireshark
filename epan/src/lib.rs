//! A safe-enough wrapper over the parts of Wireshark's `epan` API that a dissector plugin needs.
//!
//! This is not a general binding to libwireshark. It covers protocol and field registration, the
//! detail-tree and column APIs, `tvbuff` access, conversations, expert info and preferences —
//! roughly the surface a `packet-*.c` dissector uses — and nothing else.
//!
//! # Lifetime and ownership model
//!
//! Two kinds of pointer come out of epan, and they are treated differently:
//!
//! * **Per-dissection pointers** (`tvbuff_t`, `proto_tree`, `packet_info`) are valid only for the
//!   duration of one dissector call. [`Tvb`], [`Tree`] and [`Pinfo`] borrow them with a lifetime
//!   that cannot outlive the call, so none can be stashed in the dissector's own state.
//! * **Registration pointers** (field names, protocol names, the `hf_register_info` array itself)
//!   must stay valid for the life of the process, because epan keeps them without copying.
//!   [`Registry`] leaks them deliberately; registration happens once at startup, so the total is
//!   fixed and small.
//!
//! # Panics
//!
//! Unwinding across the C boundary is undefined behaviour. Every `extern "C"` entry point the
//! plugin exposes must therefore go through [`ffi_guard`], which catches a panic, reports it once
//! per process, and returns a neutral value.

pub mod conv;
pub mod plugin;
pub mod prefs;
pub mod proto;
pub mod tree;
pub mod tvb;

use std::{
    ffi::{CStr, CString},
    sync::atomic::{AtomicBool, Ordering},
};

pub use conv::Conversation;
pub use epan_sys as sys;
pub use prefs::Prefs;
pub use proto::{Encoding, ExpertId, ExpertInfo, FieldId, FieldKind, FieldSpec, Protocol, Registry, SubtreeId};
pub use tree::{Pinfo, Tree, TreeItem};
pub use tvb::Tvb;

/// Runs `f`, turning a panic into `fallback` instead of unwinding into C.
///
/// The first panic is reported on stderr with its payload; later ones are silent, because a
/// dissector that panics tends to panic on every packet and a per-packet message would bury the
/// capture. Wireshark keeps running and the affected packets simply dissect as far as they got.
pub fn ffi_guard<T>(what: &str, fallback: T, f: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    static REPORTED: AtomicBool = AtomicBool::new(false);

    match std::panic::catch_unwind(f) {
        Ok(v) => v,
        Err(payload) => {
            if !REPORTED.swap(true, Ordering::Relaxed) {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                eprintln!(
                    "hopr-wireshark: panic in {what}: {msg}\n\
                     Dissection of the affected packets is incomplete; further panics are not \
                     reported. Please file this against the hopr-wireshark repository."
                );
            }
            fallback
        }
    }
}

/// Leaks `s` as a NUL-terminated C string that lives for the rest of the process.
///
/// epan stores the pointers it is given during registration without copying, so anything handed
/// to it has to outlive every dissection. Registration runs once, so the leak is bounded by the
/// number of registered fields.
///
/// # Panics
/// If `s` contains an interior NUL byte.
pub(crate) fn leak_cstring(s: &str) -> &'static CStr {
    let owned = CString::new(s).unwrap_or_else(|_| panic!("registration string {s:?} contains an interior NUL"));
    Box::leak(owned.into_boxed_c_str())
}
