//! Generates the `epan` bindings and records what Wireshark version they were generated against.
//!
//! Wireshark's plugin loader refuses any plugin whose `plugin_want_major`/`plugin_want_minor` do
//! not equal its own, so the version discovered here is not merely informational: it is baked into
//! the plugin as `WIRESHARK_VERSION_{MAJOR,MINOR}` and decides which Wireshark will load the
//! result. Build against the Wireshark you intend to run.

use std::{io::Write, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=WIRESHARK_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=WIRESHARK_LIB_DIR");

    let lib = probe_wireshark();

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(lib.include_paths.iter().map(|p| format!("-I{}", p.display())))
        // Wireshark's headers are C; `-fparse-all-comments` keeps the doc comments, which is
        // what makes the generated bindings navigable in an editor.
        .clang_arg("-fparse-all-comments")
        .generate_comments(true)
        // Only the epan/wsutil surface. Without this the glib and libc worlds come along and
        // collide with the `libc` crate's own definitions.
        .allowlist_function(
            "(proto|tvb|col|conversation|expert|dissector|register|create|call|prefs|uat|tcp|epan|find|ws|heur|wmem)_.*",
        )
        .allowlist_function("proto_tree_.*")
        .allowlist_function("proto_item_.*")
        .allowlist_function("proto_register_.*")
        // Per-packet and per-conversation scratch storage, and the "Decrypted ..." data-source
        // tabs. Named individually because their prefixes (`p_`, `add_`) are too generic to
        // allowlist wholesale.
        .allowlist_function("p_(add|get|remove)_proto_data")
        .allowlist_function("add_new_data_source")
        .allowlist_function("val_to_str.*")
        .allowlist_function("g_(free|malloc|strdup|str_equal|str_hash)")
        .allowlist_type("(proto|tvb|packet|column|conversation|expert|dissector|header_field|hf|value_string|ei|uat|prefs|module)_.*")
        .allowlist_type("(proto_item|proto_tree|tvbuff_t|packet_info|dissector_handle_t|address)")
        // `field_display_e` carries the BASE_*/SEP_* display constants, which are enum variants
        // rather than `#define`s and so are not reachable through `allowlist_var`.
        .allowlist_type("(field_display_e|ftenum|wmem_allocator_t|heuristic_dissector_flags_e)")
        // `WIRESHARK_VERSION_*` is deliberately *not* allowlisted: `ws_version.h` defines it
        // unsigned, while the loader compares `plugin_want_{major,minor}` as `int`. `version.rs`
        // below re-emits the same numbers with the type the loader expects.
        .allowlist_var("(FT|BASE|ENC|WS_PLUGIN|COL|PI|SEP|NO_ADDR|NO_PORT|HFILL)_.*")
        // `hf_register_info` embeds a `header_field_info` whose trailing members are filled by
        // the HFILL macro; deriving Default lets Rust spell that out once.
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .prepend_enum_name(false)
        .layout_tests(false)
        // glib types (gchar, gint, ...) are in the C namespace; map the fixed-width ones onto
        // Rust's so the generated signatures read naturally.
        .size_t_is_usize(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate epan bindings");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write epan bindings");

    let (major, minor, micro) = wireshark_version(&lib);

    // Consumed by `src/lib.rs` to emit the loader's version gate.
    let mut f = std::fs::File::create(out_dir.join("version.rs")).expect("failed to create version.rs");
    writeln!(f, "/// Wireshark major version these bindings were generated against.").unwrap();
    writeln!(f, "pub const WIRESHARK_VERSION_MAJOR: i32 = {major};").unwrap();
    writeln!(f, "/// Wireshark minor version these bindings were generated against.").unwrap();
    writeln!(f, "pub const WIRESHARK_VERSION_MINOR: i32 = {minor};").unwrap();
    writeln!(f, "/// Full Wireshark version string these bindings were generated against.").unwrap();
    writeln!(f, "pub const WIRESHARK_VERSION: &str = \"{major}.{minor}.{micro}\";").unwrap();

    // Let downstream crates (and `just install`) find the right plugin directory without
    // re-deriving the version.
    println!("cargo:version_major={major}");
    println!("cargo:version_minor={minor}");
    println!("cargo:version={major}.{minor}.{micro}");
}

/// Finds Wireshark's headers and libraries.
///
/// `pkg-config` is the normal path (the `wireshark.pc` shipped by every distribution's
/// `wireshark-dev`/`wireshark-devel` package, and by the `dev` output in this repo's flake).
/// `WIRESHARK_INCLUDE_DIR`/`WIRESHARK_LIB_DIR` override it for a Wireshark built from source
/// that was never installed.
fn probe_wireshark() -> pkg_config::Library {
    if let (Ok(include), Ok(libdir)) = (
        std::env::var("WIRESHARK_INCLUDE_DIR"),
        std::env::var("WIRESHARK_LIB_DIR"),
    ) {
        println!("cargo:rustc-link-search=native={libdir}");
        println!("cargo:rustc-link-lib=dylib=wireshark");
        println!("cargo:rustc-link-lib=dylib=wsutil");

        // `pkg_config::Library` has no public constructor, so the manual path re-enters
        // pkg-config with the override applied rather than hand-rolling a parallel type.
        unsafe { std::env::set_var("PKG_CONFIG_PATH", format!("{libdir}/pkgconfig")) };
        return pkg_config::Config::new()
            .cargo_metadata(false)
            .probe("wireshark")
            .unwrap_or_else(|_| panic!("WIRESHARK_INCLUDE_DIR={include} is set but no wireshark.pc was found under {libdir}/pkgconfig"));
    }

    pkg_config::Config::new().probe("wireshark").unwrap_or_else(|e| {
        panic!(
            "could not locate Wireshark's development files: {e}\n\
             Install the wireshark development package (wireshark-dev / wireshark-devel), enter\n\
             this repository's `nix develop` shell, or set WIRESHARK_INCLUDE_DIR and\n\
             WIRESHARK_LIB_DIR to a Wireshark build tree."
        )
    })
}

/// Reads the Wireshark version from `ws_version.h`.
///
/// `wireshark.pc`'s `Version:` field carries the same number, but `pkg-config` reports it as a
/// string that has historically included suffixes (`4.2.0rc1`), while the loader compares the
/// integers from this header. Reading the header is what the plugin is actually gated on.
fn wireshark_version(lib: &pkg_config::Library) -> (i32, i32, i32) {
    let header = lib
        .include_paths
        .iter()
        .map(|p| p.join("ws_version.h"))
        .find(|p| p.exists())
        .unwrap_or_else(|| {
            panic!(
                "ws_version.h not found in any of the Wireshark include paths: {:?}",
                lib.include_paths
            )
        });
    println!("cargo:rerun-if-changed={}", header.display());

    let text = std::fs::read_to_string(&header).unwrap_or_else(|e| panic!("cannot read {}: {e}", header.display()));

    let field = |name: &str| -> i32 {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("#define {name} ")))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("{name} not found in {}", header.display()))
    };

    (
        field("WIRESHARK_VERSION_MAJOR"),
        field("WIRESHARK_VERSION_MINOR"),
        field("WIRESHARK_VERSION_MICRO"),
    )
}
