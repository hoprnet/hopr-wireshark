//! Runs the built plugin inside a real `tshark` against a capture of real HOPR packets.
//!
//! Everything below the assertions is genuine: the packets are built by `hopr-crypto-packet`, the
//! framing by an encoder written independently of the dissector's parser, and the dissection by
//! the same shared object Wireshark would load. What the test checks is the only thing that
//! matters about a dissector — that the fields a user filters on come out with the right values.
//!
//! The test is skipped, loudly, when `tshark` is not on `PATH` or the plugin has not been built
//! for the `tshark` that is. Both are true outside this repository's `nix develop` shell, and
//! neither is a failure of the code under test.

mod support;

use hopr_crypto_packet::prelude::HoprPacket;
use hopr_lib::api::types::crypto_random::Randomizable;
use hopr_lib::api::types::internal::prelude::HoprPseudonym;
use hopr_protocol_app::v1::{ApplicationData, ReservedTag};
use support::{
    cluster::Cluster,
    libp2p::{self, DATA},
    pcap::{Dir, TcpCapture},
};

/// Fields pulled out of one `tshark` row.
type Row = Vec<String>;

/// Builds a capture, runs `tshark` over it, and returns the requested fields per packet.
///
/// `name` scopes the working directory. Tests in one binary share a process and run in parallel,
/// so a directory keyed only by the process id would have them overwriting each other's captures
/// — which reads as a baffling dissection bug rather than as the collision it is. The directory
/// is left behind on purpose: when an assertion fails, the capture that failed it is the first
/// thing worth looking at.
fn run_tshark(name: &str, capture: &[u8], key_file: &str, fields: &[&str]) -> Option<Vec<Row>> {
    run_tshark_passes(name, capture, key_file, fields, 1)
}

/// As [`run_tshark`], but with `passes` set to 2 to make `tshark` dissect the file twice.
///
/// Two passes are what the Wireshark GUI does — it dissects while reading and again when a packet
/// is selected — and some of what the dissector reports is only knowable on the second one. A key
/// identifier naming a next hop, for instance, is bound when the packet is seen *arriving* there,
/// which is a later frame than the one being labelled.
fn run_tshark_passes(name: &str, capture: &[u8], key_file: &str, fields: &[&str], passes: u8) -> Option<Vec<Row>> {
    let dir = std::env::temp_dir().join(format!("hopr-dissector-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp directory is creatable");
    eprintln!("capture for {name}: {}", dir.display());

    let pcap_path = dir.join("capture.pcap");
    let keys_path = dir.join("keys.toml");
    std::fs::write(&pcap_path, capture).expect("capture is writable");
    std::fs::write(&keys_path, key_file).expect("key file is writable");

    let plugin_dir = install_plugin(&dir)?;

    let mut command = std::process::Command::new("tshark");
    command
        .env("WIRESHARK_PLUGIN_DIR", &plugin_dir)
        .arg("-r")
        .arg(&pcap_path)
        .arg("-o")
        .arg(format!("hopr.key_file:{}", keys_path.display()))
        .arg("-T")
        .arg("fields");
    if passes > 1 {
        command.arg("-2");
    }
    for field in fields {
        command.arg("-e").arg(field);
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skipping: cannot run tshark ({error})");
            return None;
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "tshark failed: {stderr}\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    // A plugin built for another Wireshark is rejected with a message and no dissection, which
    // would otherwise show up as a puzzling empty result.
    assert!(
        !stderr.contains("not compatible"),
        "the plugin was rejected by this tshark: {stderr}"
    );

    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.split('\t').map(str::to_string).collect())
            .collect(),
    )
}

/// Copies the built plugin into the version-scoped layout `WIRESHARK_PLUGIN_DIR` expects.
fn install_plugin(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    // `tests/` runs from `target/<profile>/deps`, and the cdylib sits one level up.
    let built = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .join(if cfg!(target_os = "macos") {
            "libhopr.dylib"
        } else {
            "libhopr.so"
        });

    if !built.exists() {
        eprintln!("skipping: {} has not been built", built.display());
        return None;
    }

    let version = epan::sys::WIRESHARK_VERSION;
    let (major_minor, _) = version.rsplit_once('.').unwrap_or((version, ""));
    let plugin_dir = dir.join("plugins");
    let target = plugin_dir.join(major_minor).join("epan");
    std::fs::create_dir_all(&target).ok()?;
    std::fs::copy(&built, target.join("hopr.so")).ok()?;

    Some(plugin_dir)
}

/// Application payload carried by the forward packet: a Session segment.
fn session_segment(frame_id: u32, payload: &[u8]) -> Vec<u8> {
    // version(1) type(1=Segment... 0) length(2) | frame_id(4) seq_idx(1) seq_flags(1) | payload
    let mut body = frame_id.to_be_bytes().to_vec();
    body.push(0); // sequence index
    body.push(1); // one segment in the sequence, not terminating
    body.extend_from_slice(payload);

    let mut message = vec![1u8, 0];
    message.extend_from_slice(&(body.len() as u16).to_be_bytes());
    message.extend_from_slice(&body);

    ApplicationData::new(ReservedTag::Session, message)
        .expect("a small Session message fits in a packet")
        .to_bytes()
        .to_vec()
}

/// A neighbour probe, as the probe protocol encodes one.
fn probe_ping(nonce: u8) -> Vec<u8> {
    let mut message = vec![1u8, 1, 0];
    message.extend(std::iter::repeat_n(nonce, 32));

    ApplicationData::new(ReservedTag::Ping, message)
        .expect("a probe fits in a packet")
        .to_bytes()
        .to_vec()
}

#[test]
fn should_decrypt_and_dissect_a_cluster_capture() -> anyhow::Result<()> {
    // node0 sends, node1 relays or receives, node2 is the far end of a relayed path.
    let cluster = Cluster::new(3);
    let pseudonym = HoprPseudonym::random();

    // Destined for node1, carrying a Session segment and a return path back to node0.
    let direct = cluster.send(&pseudonym, &[1], Some(&[0]), &session_segment(42, b"hello session"))?;
    // Passing through node1 on its way to node2.
    let relayed = cluster.send(&pseudonym, &[1, 2], None, &probe_ping(0xab))?;

    // The reply node1 sends on the SURB it just received. Taking the SURB out of the delivered
    // packet rather than from the sender's own copy is what makes this a real round trip.
    let HoprPacket::Final(delivered) = cluster.receive(1, 0, &direct)? else {
        anyhow::bail!("the direct packet must be final at node1");
    };
    let (surb_id, surb) = delivered
        .surbs
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the direct packet must carry a SURB"))?;
    let reply = cluster.reply(
        1,
        Cluster::sender_id(&delivered.sender, surb_id),
        surb,
        &session_segment(43, b"hello back"),
    )?;

    let mut capture = TcpCapture::new(45001, 45002);

    // node0 → node1, and node1's half of the handshake.
    capture.send(Dir::AtoB, &libp2p::connection_preamble(&cluster.nodes[0].public()));
    capture.send(Dir::BtoA, &libp2p::connection_preamble(&cluster.nodes[1].public()));

    capture.send(Dir::AtoB, &libp2p::open_substream(1, "/hopr/mix/1.2.0"));
    capture.send(Dir::AtoB, &libp2p::yamux(DATA, 0, 1, &direct));

    // Split across TCP segments *and* across yamux frames, so both reassembly paths are
    // exercised rather than only the happy one.
    let (head, tail) = relayed.split_at(700);
    capture.send(Dir::AtoB, &libp2p::yamux(DATA, 0, 1, head));
    capture.send_split(Dir::AtoB, &libp2p::yamux(DATA, 0, 1, tail), 300);

    // node1 → node0: the reply travels back on the same connection, in the other direction.
    capture.send(Dir::BtoA, &libp2p::open_substream(2, "/hopr/mix/1.2.0"));
    capture.send(Dir::BtoA, &libp2p::yamux(DATA, 0, 2, &reply));

    // The second hop, on its own connection. Nothing in the first connection says which node the
    // relayed packet's next-hop identifier names; seeing the packet arrive here is what binds it.
    let onward = cluster.relay(1, 0, &relayed)?;
    let mut second = TcpCapture::new(45005, 45006);
    second.send(Dir::AtoB, &libp2p::connection_preamble(&cluster.nodes[1].public()));
    second.send(Dir::BtoA, &libp2p::connection_preamble(&cluster.nodes[2].public()));
    second.send(Dir::AtoB, &libp2p::open_substream(1, "/hopr/mix/1.2.0"));
    second.send(Dir::AtoB, &libp2p::yamux(DATA, 0, 1, &onward));

    // Both connections in one file, in the order they happened.
    let mut both = capture.finish();
    both.extend_from_slice(&second.finish()[24..]);

    let Some(rows) = run_tshark_passes(
        "cluster",
        &both,
        &cluster.key_file(),
        &[
            "frame.number",
            "hopr.type",
            "hopr_libp2p.plaintext.node",
            "hopr_app.reserved_tag",
            "hopr_session.frame_id",
            "hopr_probe.probe.nonce",
            "hopr.next_hop",
            "hopr.is_reply",
            "hopr.decrypt_error",
        ],
        2,
    ) else {
        return Ok(());
    };

    let all = |index: usize| -> Vec<String> {
        rows.iter()
            .filter_map(|row| row.get(index))
            .filter(|value| !value.is_empty())
            .cloned()
            .collect()
    };

    assert!(
        all(8).is_empty(),
        "no packet should have failed to decrypt, but some did: {:?}",
        all(8)
    );

    assert_eq!(
        all(2),
        vec!["node0", "node1", "node1", "node2"],
        "the plaintext handshake must name the node at each end of both connections"
    );

    assert_eq!(
        all(1),
        vec!["Final", "Forwarded", "Final", "Final"],
        "the direct packet is final at node1, the relayed one passes through it, the reply is \
         final at node0, and the relayed packet is final at node2"
    );

    assert_eq!(
        all(6),
        vec!["node2"],
        "the relayed packet's next hop must resolve to a node name, which means the key \
         identifier was learned from the traffic rather than configured"
    );

    assert_eq!(
        all(4),
        vec!["42", "43"],
        "both Session segments must be decoded, including the reply — which is only readable if \
         the reply opener was reconstructed from the SURB"
    );

    assert_eq!(
        all(5).first().map(String::as_str),
        Some("abababababababababababababababababababababababababababababababab"),
        "the probe payload is only readable at node2, the packet's destination, and only from a \
         packet that was reassembled across yamux frames and TCP segments to get there"
    );

    assert_eq!(
        all(7),
        vec!["False", "True", "False"],
        "of the three packets that reached a destination, exactly the middle one came back on a \
         SURB — which is only knowable by having opened it"
    );

    Ok(())
}

#[test]
fn should_dissect_the_framing_without_keys() -> anyhow::Result<()> {
    let cluster = Cluster::new(2);
    let pseudonym = HoprPseudonym::random();
    let packet = cluster.send(&pseudonym, &[1], None, &probe_ping(0x11))?;

    let mut capture = TcpCapture::new(45003, 45004);
    capture.send(Dir::AtoB, &libp2p::connection_preamble(&cluster.nodes[0].public()));
    capture.send(Dir::BtoA, &libp2p::connection_preamble(&cluster.nodes[1].public()));
    capture.send(Dir::AtoB, &libp2p::open_substream(1, "/hopr/mix/1.2.0"));
    capture.send(Dir::AtoB, &libp2p::yamux(DATA, 0, 1, &packet));

    // An empty key file is a configuration a user will hit — the preference set before the keys
    // exist — and it must degrade to framing-only rather than to nothing.
    let Some(rows) = run_tshark(
        "no-keys",
        &capture.finish(),
        "",
        &[
            "hopr_libp2p.yamux.stream_id",
            "hopr.decrypt_error",
            "hopr_libp2p.yamux.protocol",
        ],
    ) else {
        return Ok(());
    };

    let protocols: Vec<_> = rows.iter().filter_map(|r| r.get(2)).filter(|v| !v.is_empty()).collect();
    assert_eq!(
        protocols,
        vec!["/hopr/mix/1.2.0"],
        "the substream's protocol must still be dissected without any keys"
    );

    let errors: Vec<_> = rows.iter().filter_map(|r| r.get(1)).filter(|v| !v.is_empty()).collect();
    assert_eq!(
        errors.len(),
        1,
        "the packet must be reported as undecryptable, not dropped"
    );
    Ok(())
}
