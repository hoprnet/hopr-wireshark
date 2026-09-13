{
  description = "Wireshark dissector for live HOPR mixnet traffic";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # The dissector is an `epan` plugin: a shared object loaded into the Wireshark
        # process. Wireshark refuses any plugin whose `plugin_want_major`/`plugin_want_minor`
        # do not match its own, so the Wireshark used to build must be the Wireshark used to
        # run. `wireshark-cli` carries `tshark` plus the `dev` output with `epan/` headers;
        # the GUI (`pkgs.wireshark`) is the same libraries with a Qt frontend, so a plugin
        # built here loads into both as long as the versions agree.
        wireshark = pkgs.wireshark-cli;

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          rustPlatform.bindgenHook # sets LIBCLANG_PATH / BINDGEN_EXTRA_CLANG_ARGS
        ];

        buildInputs = with pkgs; [
          wireshark
          wireshark.dev
          glib
          glib.dev
          libpcap
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs buildInputs;

          packages = with pkgs; [ wireshark-cli cargo-nextest ];

          # `epan-sys/build.rs` reads these. The plugin directory is version-scoped
          # (`plugins/<major>.<minor>/epan`), and `just install` needs the same numbers.
          shellHook = ''
            export HOPR_WIRESHARK_VERSION="${wireshark.version}"
            export WIRESHARK_PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins/${pkgs.lib.versions.majorMinor wireshark.version}/epan"
            echo "hopr-wireshark dev shell — Wireshark ${wireshark.version}"
            echo "  plugin install dir: $WIRESHARK_PLUGIN_DIR"
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
