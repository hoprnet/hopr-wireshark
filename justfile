# Recipes for building, testing and installing the dissector.
#
# Everything here assumes the `nix develop` shell, which is what pins the Wireshark the plugin is
# built against. Running them outside it works only if a matching wireshark-dev is on the system.

_default:
    @just --list

# Build the plugin.
build profile="release":
    cargo build --profile {{ if profile == "debug" { "dev" } else { profile } }}

# Run every test, including the end-to-end run through tshark.
test:
    cargo test --all-targets

# Lint and format-check.
check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings

# Format.
fmt:
    cargo fmt

# Install the plugin into Wireshark's personal plugin directory.
#
# The directory is version-scoped, and Wireshark refuses a plugin built for another version, so
# `WIRESHARK_PLUGIN_DIR` comes from the dev shell rather than being spelled out here.
install profile="release": (build profile)
    #!/usr/bin/env bash
    set -euo pipefail
    : "${WIRESHARK_PLUGIN_DIR:?run this inside 'nix develop'}"
    mkdir -p "$WIRESHARK_PLUGIN_DIR"
    src="target/{{ if profile == "debug" { "debug" } else { profile } }}/libhopr.so"
    [[ -f "$src" ]] || src="target/{{ if profile == "debug" { "debug" } else { profile } }}/libhopr.dylib"
    cp "$src" "$WIRESHARK_PLUGIN_DIR/hopr.so"
    echo "installed $src -> $WIRESHARK_PLUGIN_DIR/hopr.so"
    tshark -G plugins | grep -i hopr

# Remove the installed plugin.
uninstall:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${WIRESHARK_PLUGIN_DIR:?run this inside 'nix develop'}"
    rm -f "$WIRESHARK_PLUGIN_DIR/hopr.so"
    echo "removed $WIRESHARK_PLUGIN_DIR/hopr.so"

# Capture a local cluster's traffic into a file, then open it with the dissector.
#
# `iface` is usually loopback, since a local cluster's nodes talk to each other over it. Capturing
# needs the privileges your system requires for packet capture.
capture keys iface="lo" out="/tmp/hopr.pcapng":
    dumpcap -i {{ iface }} -w {{ out }} -f "tcp"
    tshark -r {{ out }} -o hopr.key_file:{{ keys }}

# Watch a local cluster live. Ctrl-C to stop.
live keys iface="lo":
    tshark -i {{ iface }} -f tcp -o hopr.key_file:{{ keys }}
