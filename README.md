# hopr-wireshark

A Wireshark dissector for the HOPR mixnet protocol stack, written in Rust against the node's own
protocol crates. It decrypts HOPR packets captured from a local cluster and dissects everything
inside them — tickets, acknowledgements, SURBs, and the Probe, Session Start and Session protocols
above them.

```text
TCP
 └─ multistream-select        protocol negotiation
     └─ /plaintext/2.0.0      peer identity exchange — names the node at each end
         └─ yamux             stream multiplexing
             └─ /hopr/mix/*   fixed-size HOPR packets
                 └─ Sphinx    decrypted with the receiving node's packet key
                     ├─ ticket, acknowledgements, SURBs
                     └─ ApplicationData
                         ├─ Probe
                         ├─ Session Start
                         └─ Session
```

The summary column reads like this, for a capture of a three-node cluster:

```text
4  127.0.0.1 → 127.0.0.2  HOPR  select /multistream/1.0.0, select /plaintext/2.0.0, identified as node0, …
6  127.0.0.1 → 127.0.0.2  HOPR  stream 1 = /hopr/mix/1.2.0
7  127.0.0.1 → 127.0.0.2  HOPR  Session: Segment 42 (1/1)
11 127.0.0.1 → 127.0.0.2  HOPR  relay to node2
13 127.0.0.2 → 127.0.0.1  HOPR  Session: Segment 43 (1/1)
20 127.0.0.1 → 127.0.0.2  HOPR  Probe: Ping abababababab…
```

## Why this needs a special node build

HOPR's onion encryption is the thing worth looking at, and it sits *underneath* the transport's.
A production node negotiates `noise` over TCP, whose session keys are ephemeral and never leave
the process — so a capture of one is uniformly random bytes even to someone holding every node's
packet key.

`hopr-transport-p2p`'s `insecure-plaintext` feature swaps that one layer for `/plaintext/2.0.0`,
which performs the peer-identity exchange and then hands the raw stream to the multiplexer. The
HOPR encryption this dissector is about is untouched; only the layer that was hiding it is gone.

**A node built that way exchanges every packet in a form any on-path observer can read.** It is
for a local cluster on loopback and nothing else. The feature is off by default, cannot be
combined with QUIC (which has no unencrypted mode), and the node logs a warning on every start.

## Building

The plugin is loaded into the Wireshark process, and Wireshark refuses any plugin whose declared
major/minor version differs from its own. The Wireshark you build against must therefore be the
Wireshark you run. The flake pins one:

```console
$ nix develop
$ just build
$ just install
```

`just install` puts the shared object in Wireshark's personal plugin directory for that version
and prints the entry Wireshark now reports for it.

Outside Nix, install your distribution's `wireshark-dev` / `wireshark-devel` package and build
normally; `epan-sys` finds the headers through `pkg-config`, or through
`WIRESHARK_INCLUDE_DIR` and `WIRESHARK_LIB_DIR` if you point them at a build tree.

The HOPR protocol crates come from a local `hoprnet` checkout, through the `[patch.crates-io]`
block at the bottom of `Cargo.toml`. It expects `../hoprnet-3`; change the paths if yours is
somewhere else. They are not taken from crates.io because the dissector depends on unreleased
work — the `insecure-plaintext` transport feature and the SURB reply-opener reconstruction.

## Using it

1. Build the cluster's nodes with the `insecure-plaintext` feature, leaving `transport-quic` out:

   ```console
   $ cargo build --release -p hoprd --no-default-features \
       --features runtime-tokio,session-server,strategy-pix-test,insecure-plaintext
   ```

   Run them with `HOPRD_NAT=true`. That is not about NAT here — it is the switch that makes a
   node announce `/ip4/.../tcp/<port>`. Without it the announced address is QUIC, which nothing
   in this build listens on: `hopr-utils-session` pulls `hopr-lib` with default features, so
   `transport-announce-quic` cannot be turned off from hoprd.
2. Write a key file listing the cluster's packet keys — see `keys.example.toml`.
3. Point Wireshark at it: **Edit → Preferences → Protocols → HOPR → Node key file**, or
   `-o hopr.key_file:/path/to/keys.toml` on the command line.
4. Capture on the interface the nodes talk over. For a cluster on one machine that is loopback.

```console
$ just live keys.toml lo          # watch it go past
$ just capture keys.toml lo       # capture to a file, then dissect it
```

Without a key file the libp2p framing is still dissected and HOPR packets are shown as
ciphertext — enough to see a Session's shape without being able to read it.

### Useful display filters

| Filter | Shows |
| --- | --- |
| `hopr` | every HOPR packet |
| `hopr.type == "Forwarded"` | packets being relayed |
| `hopr.next_hop == "node2"` | packets on their way to a particular node |
| `hopr.is_reply == 1` | traffic that came back on a SURB |
| `hopr_session.frame_id == 42` | the segments of one Session frame |
| `hopr_start` | Session negotiation |
| `hopr.decrypt_error` | packets the dissector could not read, and why |

## What it works out for itself

Only the packet keys are configured. Three things that would otherwise have to be supplied are
derived from the traffic:

**Which node is at each end of a connection** comes from the `/plaintext/2.0.0` exchange, which
carries each side's peer id. That is what says whose key decrypts a packet, and it is why the
dissector never has to guess.

**Key identifiers.** A packet header names its next hop by a four-byte identifier the chain
assigned, which cannot be derived from a key. Rather than make you transcribe it, the dissector
remembers a fingerprint of each relayed packet and binds the identifier when that packet turns up
on the connection to its next hop. An identifier not yet bound shows as `<unknown>` on the first
pass over a capture and resolves on the second — which is the pass the GUI does when you click a
packet.

**Reply openers.** Roughly half a Session's traffic travels on SURBs, and a reply is decrypted
with an opener its sender kept in memory and never transmitted. The dissector rebuilds it from
the SURB it saw delivered, by walking the return path with the keys of the nodes on it. Where the
identifier of a hop is not yet known, every key is offered and the header's authentication tag
decides which one fits — so the hop is identified rather than guessed at.

## How it is put together

| Crate | What it is |
| --- | --- |
| `crates/epan-sys` | `bindgen` bindings to `libwireshark`, generated against whichever Wireshark is found at build time |
| `crates/epan` | a safe wrapper over the registration, tree, tvbuff, conversation and preference surface a dissector uses |
| `crates/hopr-dissector` | the plugin: libp2p framing, HOPR decryption, and the protocols above it |

The protocol layers are decoded with the node's own crates — `ApplicationData`,
`HoprStartProtocol`, `Segment`, `HoprPacket` — rather than with a re-implementation of the wire
format. A protocol change that would silently break a hand-written copy breaks this build
instead.

`cargo test` includes an end-to-end run: it builds real packets with `hopr-crypto-packet`, wraps
them in libp2p framing and a synthetic TCP capture, runs the built plugin inside `tshark`, and
checks the fields that come out. It covers a relayed packet across two connections, a reply on a
SURB, and a packet split across both yamux frames and TCP segments.

## Limitations

* **TCP only.** QUIC encrypts inside the transport with TLS 1.3 and has no plaintext mode, so a
  node reachable over QUIC produces a capture nothing can read. The two features are mutually
  exclusive at compile time for that reason.
* **One Wireshark version per build.** See *Building*.
* **A capture that starts mid-Session** misses the `/plaintext/2.0.0` handshake that names the
  connection's endpoints, and its packets cannot be attributed. Start the capture before the
  nodes connect.
* **PIX `SsaCommit` and `SsaRequest` bodies** are summarised rather than broken out field by
  field; the commitment counts and session id are filterable, the group elements are not.

## Licence

GPL-3.0-only, matching the HOPR sources it builds on.
