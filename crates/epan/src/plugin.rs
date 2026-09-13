//! The symbols Wireshark's plugin loader looks for.
//!
//! On loading a shared object from its plugin directory, Wireshark reads `plugin_version`,
//! `plugin_want_major` and `plugin_want_minor`, and refuses the plugin outright unless the two
//! version numbers equal its own. It then calls `plugin_register`, and `plugin_describe` if
//! present. [`declare_plugin!`] emits all five.
//!
//! # Why `plugin_register` does not register anything
//!
//! `plugin_register` only hands epan a [`proto_plugin`](crate::sys::proto_plugin) — a pair of
//! callbacks — via `proto_register_plugin`. epan calls the first during `proto_init` and the
//! second once every protocol in the process has registered. Doing the work directly in
//! `plugin_register` looks equivalent and is not: the loader may run it more than once in a
//! process (`tshark -G` scans plugins before `epan_init` does), and the second
//! `proto_register_protocol` with the same name aborts Wireshark with "Duplicate protocol name".
//! Recording callbacks is idempotent, so the two-phase form is the only safe one.
//!
//! The split also exists for a reason a single phase cannot express: a handoff has to look up
//! dissectors *other* protocols register (`"tcp.port"`, the `"data"` dissector), which do not
//! exist until every protocol's first phase has run.

/// Emits the loader symbols for an `epan` dissector plugin.
///
/// `$version` is the plugin's own version string, shown in Help → About → Plugins.
/// `$protoinfo` registers protocols, fields, subtrees, expert infos and preferences.
/// `$handoff` attaches the dissector to the tables it should be reached through, and looks up any
/// dissectors it wants to call. Both are `fn()`, both run once, and a panic in either is caught
/// rather than unwound into C.
///
/// The Wireshark version the plugin declares compatibility with is not a parameter: it comes from
/// the headers `epan-sys` was built against, so a plugin can only ever claim the version it was
/// actually compiled for.
///
/// # Example
///
/// ```ignore
/// epan::declare_plugin!(version = "0.1.0", protoinfo = register_protoinfo, handoff = register_handoff);
/// ```
#[macro_export]
macro_rules! declare_plugin {
    (version = $version:expr, protoinfo = $protoinfo:path, handoff = $handoff:path $(,)?) => {
        /// Plugin version string, read by the loader and shown in Help → About → Plugins.
        #[unsafe(no_mangle)]
        pub static plugin_version: [::std::ffi::c_char; { $version.len() + 1 }] = {
            let bytes = $version.as_bytes();
            let mut out = [0 as ::std::ffi::c_char; { $version.len() + 1 }];
            let mut i = 0;
            while i < bytes.len() {
                out[i] = bytes[i] as ::std::ffi::c_char;
                i += 1;
            }
            out
        };

        /// Wireshark major version this plugin was built for. The loader rejects a mismatch.
        #[unsafe(no_mangle)]
        pub static plugin_want_major: ::std::ffi::c_int = $crate::sys::WIRESHARK_VERSION_MAJOR;

        /// Wireshark minor version this plugin was built for. The loader rejects a mismatch.
        #[unsafe(no_mangle)]
        pub static plugin_want_minor: ::std::ffi::c_int = $crate::sys::WIRESHARK_VERSION_MINOR;

        /// Registers protocols, fields, subtrees, expert infos and preferences.
        ///
        /// # Safety
        /// Called by epan during `proto_init`, on the registration thread.
        unsafe extern "C" fn __hopr_register_protoinfo() {
            $crate::ffi_guard("register_protoinfo", (), || $protoinfo());
        }

        /// Attaches the dissector to the tables it is reached through.
        ///
        /// # Safety
        /// Called by epan after every protocol has registered, on the registration thread.
        unsafe extern "C" fn __hopr_register_handoff() {
            $crate::ffi_guard("register_handoff", (), || $handoff());
        }

        /// Hands epan the two registration callbacks.
        ///
        /// # Safety
        /// Called by Wireshark's plugin loader, possibly more than once per process; recording
        /// the same callbacks again is harmless.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn plugin_register() {
            static PLUGIN: $crate::sys::proto_plugin = $crate::sys::proto_plugin {
                register_protoinfo: Some(__hopr_register_protoinfo),
                register_handoff: Some(__hopr_register_handoff),
            };
            // SAFETY: `PLUGIN` is `'static`, which is what epan requires — it keeps the pointer
            // and calls through it later.
            unsafe { $crate::sys::proto_register_plugin(&PLUGIN) };
        }

        /// Tells the loader what kind of plugin this is, for Help → About → Plugins.
        ///
        /// # Safety
        /// Called by Wireshark on the registration thread.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn plugin_describe() -> u32 {
            $crate::sys::WS_PLUGIN_DESC_DISSECTOR
        }
    };
}
