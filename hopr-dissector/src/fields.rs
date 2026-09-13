//! Everything the dissector registers with Wireshark: protocols, fields, subtrees, expert infos.
//!
//! One [`Fields`] value is built during registration and then only read, so it is handed around
//! as a shared reference for the life of the process.
//!
//! The six protocols are registered separately rather than as one, so that each layer gets its
//! own row in the detail pane, its own entry in the protocol hierarchy statistics, and its own
//! display-filter prefix — `hopr_session.frame_id == 42` reads better, and filters faster, than a
//! single flat namespace would.

use epan::{
    ExpertId, ExpertInfo, FieldId, FieldKind, FieldSpec, Prefs, Protocol, Registry, SubtreeId,
    prefs::{BoolPref, FilenamePref},
    proto::Registered,
    sys,
};

/// Registered ids for one protocol layer, plus the preferences attached to the root one.
pub struct Fields {
    pub registered: Registered,
    pub libp2p: Libp2pFields,
    pub hopr: HoprFields,
    pub app: AppFields,
    pub probe: ProbeFields,
    pub start: StartFields,
    pub session: SessionFields,
    pub experts: Experts,
    pub subtrees: Subtrees,
    pub prefs: DissectorPrefs,
    /// The protocol shown in the Protocol column and used for the topmost tree item.
    pub proto_libp2p: Protocol,
    pub proto_hopr: Protocol,
    pub proto_app: Protocol,
    pub proto_probe: Protocol,
    pub proto_start: Protocol,
    pub proto_session: Protocol,
}

/// Preferences the user can set under Edit → Preferences → Protocols → HOPR.
pub struct DissectorPrefs {
    pub key_file: FilenamePref,
    pub decrypt: BoolPref,
}

/// The libp2p framing between TCP and the HOPR packet stream.
pub struct Libp2pFields {
    pub ms_message: FieldId,
    pub ms_length: FieldId,
    pub pt_peer_id: FieldId,
    pub pt_pubkey: FieldId,
    pub pt_node: FieldId,
    pub yx_version: FieldId,
    pub yx_type: FieldId,
    pub yx_flags: FieldId,
    pub yx_flag_syn: FieldId,
    pub yx_flag_ack: FieldId,
    pub yx_flag_fin: FieldId,
    pub yx_flag_rst: FieldId,
    pub yx_stream: FieldId,
    pub yx_length: FieldId,
    pub yx_protocol: FieldId,
}

/// The HOPR packet layer.
pub struct HoprFields {
    pub kind: FieldId,
    pub sender_node: FieldId,
    pub receiver_node: FieldId,
    pub packet_tag: FieldId,
    pub next_hop: FieldId,
    pub next_hop_id: FieldId,
    pub path_pos: FieldId,
    pub ack_key: FieldId,
    pub ack_challenge: FieldId,
    pub pseudonym: FieldId,
    pub is_reply: FieldId,
    pub surb_count: FieldId,
    pub surb_id: FieldId,
    pub surb_first_relayer: FieldId,
    pub signals: FieldId,
    pub signal_name: FieldId,
    pub ack_count: FieldId,
    pub ack: FieldId,
    pub ticket_counterparty: FieldId,
    pub ticket_channel_epoch: FieldId,
    pub ticket_index: FieldId,
    pub ticket_amount: FieldId,
    pub ticket_win_prob: FieldId,
    pub ticket_challenge: FieldId,
    pub ticket_signature: FieldId,
    pub decrypt_error: FieldId,
    pub raw_packet: FieldId,
}

/// `ApplicationData`: the tag-plus-payload envelope every final packet carries.
pub struct AppFields {
    pub tag: FieldId,
    pub tag_name: FieldId,
    pub payload: FieldId,
    pub payload_len: FieldId,
}

/// The probe protocol, on reserved tag 0.
pub struct ProbeFields {
    pub version: FieldId,
    pub kind: FieldId,
    pub neighbor_kind: FieldId,
    pub nonce: FieldId,
    pub telemetry_id: FieldId,
    pub telemetry_path: FieldId,
    pub telemetry_timestamp: FieldId,
}

/// The Session Start protocol, on reserved tag 1.
pub struct StartFields {
    pub version: FieldId,
    pub kind: FieldId,
    pub length: FieldId,
    pub challenge: FieldId,
    pub session_id: FieldId,
    pub target: FieldId,
    pub capabilities: FieldId,
    pub error_reason: FieldId,
    pub ssa_index: FieldId,
    pub ssa_commitments: FieldId,
    pub summary: FieldId,
}

/// The Session protocol, on reserved tag 2.
pub struct SessionFields {
    pub version: FieldId,
    pub kind: FieldId,
    pub length: FieldId,
    pub frame_id: FieldId,
    pub seq_idx: FieldId,
    pub seq_len: FieldId,
    pub terminating: FieldId,
    pub payload: FieldId,
    pub requested_frame: FieldId,
    pub requested_index: FieldId,
    pub acked_frame: FieldId,
}

/// Conditions worth flagging in the Expert Information dialog.
pub struct Experts {
    pub decrypt_failed: ExpertId,
    pub no_keys: ExpertId,
    pub unknown_peer: ExpertId,
    pub malformed: ExpertId,
    pub reply_unopened: ExpertId,
    pub key_id_unknown: ExpertId,
}

/// Expandable nodes.
pub struct Subtrees {
    pub libp2p: SubtreeId,
    pub yamux: SubtreeId,
    pub yamux_flags: SubtreeId,
    pub handshake: SubtreeId,
    pub hopr: SubtreeId,
    pub ticket: SubtreeId,
    pub surbs: SubtreeId,
    pub surb: SubtreeId,
    pub acks: SubtreeId,
    pub app: SubtreeId,
    pub probe: SubtreeId,
    pub start: SubtreeId,
    pub session: SubtreeId,
    pub signals: SubtreeId,
}

/// yamux frame type labels.
const YAMUX_TYPES: &[(u32, &str)] = &[(0, "Data"), (1, "Window Update"), (2, "Ping"), (3, "Go Away")];

/// Reserved application tags.
const RESERVED_TAGS: &[(u32, &str)] = &[(0, "Probe"), (1, "Start"), (2, "Session"), (15, "Undefined")];

/// Probe message discriminants.
const PROBE_TYPES: &[(u32, &str)] = &[(0, "Telemetry"), (1, "Probe")];

/// Neighbour probe directions.
const PROBE_NEIGHBOR_TYPES: &[(u32, &str)] = &[(0, "Ping"), (1, "Pong")];

/// Start protocol message discriminants.
///
/// Order follows the `StartProtocol` enum; a message the dissector does not know about is shown by
/// number rather than guessed at.
const START_TYPES: &[(u32, &str)] = &[
    (0, "StartSession"),
    (1, "SessionEstablished"),
    (2, "SsaCommit"),
    (3, "SsaRequest"),
    (4, "SessionError"),
    (5, "KeepAlive"),
];

/// Session protocol message discriminants.
const SESSION_TYPES: &[(u32, &str)] = &[(0, "Segment"), (1, "SegmentRequest"), (2, "FrameAcknowledgements")];

impl Fields {
    /// Registers every protocol, field, subtree, expert info and preference.
    ///
    /// Called once, from the plugin's `protoinfo` phase.
    pub fn register() -> Self {
        let proto_libp2p = Protocol::register("HOPR libp2p Framing", "HOPR-libp2p", "hopr_libp2p");
        let proto_hopr = Protocol::register("HOPR Protocol", "HOPR", "hopr");
        let proto_app = Protocol::register("HOPR Application Data", "HOPR-App", "hopr_app");
        let proto_probe = Protocol::register("HOPR Probe Protocol", "HOPR-Probe", "hopr_probe");
        let proto_start = Protocol::register("HOPR Session Start Protocol", "HOPR-Start", "hopr_start");
        let proto_session = Protocol::register("HOPR Session Protocol", "HOPR-Session", "hopr_session");

        // Fields are registered against the root protocol because epan resolves a field's owning
        // protocol from the `hf` array it arrives in, not from its name. Registering all of them
        // together keeps one array and one `Registered` to carry around; the display-filter
        // prefixes still put each field under its own protocol for the user.
        let mut reg = Registry::new(proto_hopr);

        let libp2p = Libp2pFields {
            ms_message: reg.field(&FieldSpec::new(
                "Protocol",
                "hopr_libp2p.multistream.protocol",
                FieldKind::String,
                "A multistream-select protocol name, header or rejection",
            )),
            ms_length: reg.field(&FieldSpec::new(
                "Message Length",
                "hopr_libp2p.multistream.length",
                FieldKind::UintDec { width: 4 },
                "Length of the multistream-select message, from its varint prefix",
            )),
            pt_peer_id: reg.field(&FieldSpec::new(
                "Peer ID",
                "hopr_libp2p.plaintext.peer_id",
                FieldKind::BytesColon,
                "The peer id the sender claims, from the /plaintext/2.0.0 exchange",
            )),
            pt_pubkey: reg.field(&FieldSpec::new(
                "Public Key",
                "hopr_libp2p.plaintext.pubkey",
                FieldKind::BytesColon,
                "The sender's Ed25519 public key, from the /plaintext/2.0.0 exchange",
            )),
            pt_node: reg.field(&FieldSpec::new(
                "Node",
                "hopr_libp2p.plaintext.node",
                FieldKind::String,
                "Which configured node this peer id belongs to",
            )),
            yx_version: reg.field(&FieldSpec::new(
                "Version",
                "hopr_libp2p.yamux.version",
                FieldKind::UintDec { width: 1 },
                "",
            )),
            yx_type: reg.field(&FieldSpec::enumerated(
                "Type",
                "hopr_libp2p.yamux.type",
                FieldKind::UintHex { width: 1 },
                "",
                YAMUX_TYPES,
            )),
            yx_flags: reg.field(&FieldSpec::new(
                "Flags",
                "hopr_libp2p.yamux.flags",
                FieldKind::UintHex { width: 2 },
                "",
            )),
            yx_flag_syn: reg.field(&FieldSpec::new(
                "SYN",
                "hopr_libp2p.yamux.flags.syn",
                FieldKind::Flag { width: 2, mask: 0x0001 },
                "Opens a substream",
            )),
            yx_flag_ack: reg.field(&FieldSpec::new(
                "ACK",
                "hopr_libp2p.yamux.flags.ack",
                FieldKind::Flag { width: 2, mask: 0x0002 },
                "Acknowledges a substream open",
            )),
            yx_flag_fin: reg.field(&FieldSpec::new(
                "FIN",
                "hopr_libp2p.yamux.flags.fin",
                FieldKind::Flag { width: 2, mask: 0x0004 },
                "Half-closes the substream",
            )),
            yx_flag_rst: reg.field(&FieldSpec::new(
                "RST",
                "hopr_libp2p.yamux.flags.rst",
                FieldKind::Flag { width: 2, mask: 0x0008 },
                "Resets the substream",
            )),
            yx_stream: reg.field(&FieldSpec::new(
                "Stream ID",
                "hopr_libp2p.yamux.stream_id",
                FieldKind::UintDec { width: 4 },
                "",
            )),
            yx_length: reg.field(&FieldSpec::new(
                "Length",
                "hopr_libp2p.yamux.length",
                FieldKind::UintDec { width: 4 },
                "Body length for a Data frame; a type-specific value otherwise",
            )),
            yx_protocol: reg.field(&FieldSpec::new(
                "Substream Protocol",
                "hopr_libp2p.yamux.protocol",
                FieldKind::String,
                "The application protocol negotiated on this substream",
            )),
        };

        let hopr = HoprFields {
            kind: reg.field(&FieldSpec::new(
                "Packet Type",
                "hopr.type",
                FieldKind::String,
                "Whether the receiving node is this packet's destination, a relay, or the target of \
                 an acknowledgement batch",
            )),
            sender_node: reg.field(&FieldSpec::new(
                "Previous Hop",
                "hopr.previous_hop",
                FieldKind::String,
                "The node that sent this packet, from the connection's plaintext handshake",
            )),
            receiver_node: reg.field(&FieldSpec::new(
                "Receiving Node",
                "hopr.receiver",
                FieldKind::String,
                "The node this packet was addressed to, and whose key decrypted it",
            )),
            packet_tag: reg.field(&FieldSpec::new(
                "Packet Tag",
                "hopr.packet_tag",
                FieldKind::Bytes,
                "Replay-detection tag derived from the packet's shared secret",
            )),
            next_hop: reg.field(&FieldSpec::new(
                "Next Hop",
                "hopr.next_hop",
                FieldKind::String,
                "The node this packet will be relayed to",
            )),
            next_hop_id: reg.field(&FieldSpec::new(
                "Next Hop Key ID",
                "hopr.next_hop_key_id",
                FieldKind::UintDecHex { width: 4 },
                "On-chain key identifier naming the next hop, as carried in the header",
            )),
            path_pos: reg.field(&FieldSpec::new(
                "Path Position",
                "hopr.path_pos",
                FieldKind::UintDec { width: 1 },
                "Hops remaining to the destination",
            )),
            ack_key: reg.field(&FieldSpec::new(
                "Acknowledgement Key Share",
                "hopr.ack_key",
                FieldKind::Bytes,
                "Half-key this node owes the previous hop as proof of relay",
            )),
            ack_challenge: reg.field(&FieldSpec::new(
                "Acknowledgement Challenge",
                "hopr.ack_challenge",
                FieldKind::Bytes,
                "Challenge the next hop's acknowledgement must answer",
            )),
            pseudonym: reg.field(&FieldSpec::new(
                "Sender Pseudonym",
                "hopr.pseudonym",
                FieldKind::Bytes,
                "The sender's chosen pseudonym — the only sender identity a destination sees",
            )),
            is_reply: reg.field(&FieldSpec::new(
                "Is Reply",
                "hopr.is_reply",
                FieldKind::Flag { width: 1, mask: 0x01 },
                "Whether this packet arrived on one of the receiver's own SURBs",
            )),
            surb_count: reg.field(&FieldSpec::new(
                "SURB Count",
                "hopr.surb_count",
                FieldKind::UintDec { width: 4 },
                "How many single-use reply blocks this packet delivered",
            )),
            surb_id: reg.field(&FieldSpec::new(
                "SURB ID",
                "hopr.surb.id",
                FieldKind::Bytes,
                "Identifier a reply on this SURB will carry",
            )),
            surb_first_relayer: reg.field(&FieldSpec::new(
                "First Relayer",
                "hopr.surb.first_relayer",
                FieldKind::UintDecHex { width: 4 },
                "Key identifier of the first hop on this SURB's return path",
            )),
            signals: reg.field(&FieldSpec::new(
                "Packet Signals",
                "hopr.signals",
                FieldKind::UintHex { width: 1 },
                "",
            )),
            signal_name: reg.field(&FieldSpec::new("Signal", "hopr.signal", FieldKind::String, "")),
            ack_count: reg.field(&FieldSpec::new(
                "Acknowledgement Count",
                "hopr.ack_count",
                FieldKind::UintDec { width: 2 },
                "",
            )),
            ack: reg.field(&FieldSpec::new("Acknowledgement", "hopr.ack", FieldKind::Bytes, "")),
            ticket_counterparty: reg.field(&FieldSpec::new(
                "Counterparty",
                "hopr.ticket.counterparty",
                FieldKind::String,
                "Chain address the ticket is payable to — the relay being paid",
            )),
            ticket_channel_epoch: reg.field(&FieldSpec::new(
                "Channel Epoch",
                "hopr.ticket.channel_epoch",
                FieldKind::UintDec { width: 4 },
                "",
            )),
            ticket_index: reg.field(&FieldSpec::new(
                "Index",
                "hopr.ticket.index",
                FieldKind::UintDec { width: 8 },
                "",
            )),
            ticket_amount: reg.field(&FieldSpec::new("Amount", "hopr.ticket.amount", FieldKind::String, "")),
            ticket_win_prob: reg.field(&FieldSpec::new(
                "Winning Probability",
                "hopr.ticket.win_prob",
                FieldKind::String,
                "",
            )),
            ticket_challenge: reg.field(&FieldSpec::new(
                "Challenge",
                "hopr.ticket.challenge",
                FieldKind::Bytes,
                "",
            )),
            ticket_signature: reg.field(&FieldSpec::new(
                "Signature",
                "hopr.ticket.signature",
                FieldKind::Bytes,
                "",
            )),
            decrypt_error: reg.field(&FieldSpec::new(
                "Decryption Error",
                "hopr.decrypt_error",
                FieldKind::String,
                "Why this packet could not be decrypted",
            )),
            raw_packet: reg.field(&FieldSpec::new(
                "Encrypted Packet",
                "hopr.raw",
                FieldKind::Bytes,
                "The HOPR packet as it appears on the wire",
            )),
        };

        let app = AppFields {
            tag: reg.field(&FieldSpec::new(
                "Tag",
                "hopr_app.tag",
                FieldKind::UintDecHex { width: 8 },
                "Application-layer protocol identifier",
            )),
            tag_name: reg.field(&FieldSpec::enumerated(
                "Reserved Tag",
                "hopr_app.reserved_tag",
                FieldKind::UintDec { width: 4 },
                "Which built-in protocol a reserved tag names",
                RESERVED_TAGS,
            )),
            payload: reg.field(&FieldSpec::new("Payload", "hopr_app.payload", FieldKind::Bytes, "")),
            payload_len: reg.field(&FieldSpec::new(
                "Payload Length",
                "hopr_app.payload_len",
                FieldKind::UintDec { width: 4 },
                "",
            )),
        };

        let probe = ProbeFields {
            version: reg.field(&FieldSpec::new(
                "Version",
                "hopr_probe.version",
                FieldKind::UintDec { width: 1 },
                "",
            )),
            kind: reg.field(&FieldSpec::enumerated(
                "Type",
                "hopr_probe.type",
                FieldKind::UintHex { width: 1 },
                "",
                PROBE_TYPES,
            )),
            neighbor_kind: reg.field(&FieldSpec::enumerated(
                "Probe Type",
                "hopr_probe.probe.type",
                FieldKind::UintHex { width: 1 },
                "",
                PROBE_NEIGHBOR_TYPES,
            )),
            nonce: reg.field(&FieldSpec::new(
                "Nonce",
                "hopr_probe.probe.nonce",
                FieldKind::Bytes,
                "A Pong echoes the nonce of the Ping it answers",
            )),
            telemetry_id: reg.field(&FieldSpec::new(
                "Telemetry ID",
                "hopr_probe.telemetry.id",
                FieldKind::Bytes,
                "",
            )),
            telemetry_path: reg.field(&FieldSpec::new(
                "Telemetry Path",
                "hopr_probe.telemetry.path",
                FieldKind::Bytes,
                "",
            )),
            telemetry_timestamp: reg.field(&FieldSpec::new(
                "Telemetry Timestamp",
                "hopr_probe.telemetry.timestamp",
                FieldKind::Bytes,
                "",
            )),
        };

        let start = StartFields {
            version: reg.field(&FieldSpec::new(
                "Version",
                "hopr_start.version",
                FieldKind::UintDec { width: 1 },
                "",
            )),
            kind: reg.field(&FieldSpec::enumerated(
                "Type",
                "hopr_start.type",
                FieldKind::UintHex { width: 1 },
                "",
                START_TYPES,
            )),
            length: reg.field(&FieldSpec::new(
                "Body Length",
                "hopr_start.length",
                FieldKind::UintDec { width: 2 },
                "",
            )),
            challenge: reg.field(&FieldSpec::new(
                "Challenge",
                "hopr_start.challenge",
                FieldKind::UintDecHex { width: 8 },
                "Ties a session response to the request that asked for it",
            )),
            session_id: reg.field(&FieldSpec::new(
                "Session ID",
                "hopr_start.session_id",
                FieldKind::String,
                "",
            )),
            target: reg.field(&FieldSpec::new(
                "Target",
                "hopr_start.target",
                FieldKind::String,
                "What the session asks the exit node to connect it to",
            )),
            capabilities: reg.field(&FieldSpec::new(
                "Capabilities",
                "hopr_start.capabilities",
                FieldKind::String,
                "",
            )),
            error_reason: reg.field(&FieldSpec::new(
                "Error Reason",
                "hopr_start.error_reason",
                FieldKind::String,
                "",
            )),
            ssa_index: reg.field(&FieldSpec::new(
                "SSA Index",
                "hopr_start.ssa_index",
                FieldKind::UintDec { width: 4 },
                "Which session stealth address this PIX message commits to",
            )),
            ssa_commitments: reg.field(&FieldSpec::new(
                "Coefficient Commitments",
                "hopr_start.ssa_commitments",
                FieldKind::UintDec { width: 4 },
                "How many polynomial coefficient commitments this message carries",
            )),
            summary: reg.field(&FieldSpec::new(
                "Message",
                "hopr_start.summary",
                FieldKind::String,
                "The decoded message, as the node's own types render it",
            )),
        };

        let session = SessionFields {
            version: reg.field(&FieldSpec::new(
                "Version",
                "hopr_session.version",
                FieldKind::UintDec { width: 1 },
                "",
            )),
            kind: reg.field(&FieldSpec::enumerated(
                "Type",
                "hopr_session.type",
                FieldKind::UintHex { width: 1 },
                "",
                SESSION_TYPES,
            )),
            length: reg.field(&FieldSpec::new(
                "Body Length",
                "hopr_session.length",
                FieldKind::UintDec { width: 2 },
                "",
            )),
            frame_id: reg.field(&FieldSpec::new(
                "Frame ID",
                "hopr_session.frame_id",
                FieldKind::UintDec { width: 4 },
                "Which application frame this segment belongs to",
            )),
            seq_idx: reg.field(&FieldSpec::new(
                "Sequence Index",
                "hopr_session.seq_idx",
                FieldKind::UintDec { width: 1 },
                "Position of this segment within its frame",
            )),
            seq_len: reg.field(&FieldSpec::new(
                "Sequence Length",
                "hopr_session.seq_len",
                FieldKind::UintDec { width: 1 },
                "How many segments the frame was split into",
            )),
            terminating: reg.field(&FieldSpec::new(
                "Terminating",
                "hopr_session.terminating",
                FieldKind::Flag { width: 1, mask: 0x80 },
                "Whether this segment closes the session",
            )),
            payload: reg.field(&FieldSpec::new(
                "Segment Payload",
                "hopr_session.payload",
                FieldKind::Bytes,
                "",
            )),
            requested_frame: reg.field(&FieldSpec::new(
                "Requested Frame",
                "hopr_session.request.frame_id",
                FieldKind::UintDec { width: 4 },
                "",
            )),
            requested_index: reg.field(&FieldSpec::new(
                "Requested Segment Index",
                "hopr_session.request.seq_idx",
                FieldKind::UintDec { width: 1 },
                "Position within its frame of a segment being asked for again",
            )),
            acked_frame: reg.field(&FieldSpec::new(
                "Acknowledged Frame",
                "hopr_session.ack.frame_id",
                FieldKind::UintDec { width: 4 },
                "",
            )),
        };

        let experts = Experts {
            decrypt_failed: reg.expert(&ExpertInfo {
                abbrev: "hopr.decrypt_failed",
                summary: "HOPR packet could not be decrypted",
                group: sys::PI_PROTOCOL,
                severity: sys::PI_WARN,
            }),
            no_keys: reg.expert(&ExpertInfo {
                abbrev: "hopr.no_keys",
                summary: "No node keys configured; HOPR packets cannot be decrypted",
                group: sys::PI_PROTOCOL,
                severity: sys::PI_NOTE,
            }),
            unknown_peer: reg.expert(&ExpertInfo {
                abbrev: "hopr.unknown_peer",
                summary: "Connection endpoint is not one of the configured nodes",
                group: sys::PI_PROTOCOL,
                severity: sys::PI_NOTE,
            }),
            malformed: reg.expert(&ExpertInfo {
                abbrev: "hopr.malformed",
                summary: "Malformed HOPR message",
                group: sys::PI_MALFORMED,
                severity: sys::PI_ERROR,
            }),
            reply_unopened: reg.expert(&ExpertInfo {
                abbrev: "hopr.reply_unopened",
                summary: "Reply payload not readable: the SURB it came back on was never seen",
                group: sys::PI_PROTOCOL,
                severity: sys::PI_NOTE,
            }),
            key_id_unknown: reg.expert(&ExpertInfo {
                abbrev: "hopr.key_id_unknown",
                summary: "Next hop's key identifier has not been observed yet",
                group: sys::PI_PROTOCOL,
                severity: sys::PI_COMMENT,
            }),
        };

        let subtrees = Subtrees {
            libp2p: reg.subtree(),
            yamux: reg.subtree(),
            yamux_flags: reg.subtree(),
            handshake: reg.subtree(),
            hopr: reg.subtree(),
            ticket: reg.subtree(),
            surbs: reg.subtree(),
            surb: reg.subtree(),
            acks: reg.subtree(),
            app: reg.subtree(),
            probe: reg.subtree(),
            start: reg.subtree(),
            session: reg.subtree(),
            signals: reg.subtree(),
        };

        let registered = reg.finish();

        let prefs_module = Prefs::register(proto_hopr, None);
        let prefs = DissectorPrefs {
            key_file: prefs_module.filename(
                "key_file",
                "Node key file",
                "TOML file listing the packet keys of the cluster's nodes. Without it the libp2p \
                 framing is still dissected, but HOPR packets stay encrypted. See the project's \
                 README for the format.",
            ),
            decrypt: prefs_module.boolean(
                "decrypt",
                "Decrypt HOPR packets",
                "Decrypt HOPR packets with the configured node keys. Turn off to see the transport \
                 framing alone.",
                true,
            ),
        };

        Self {
            registered,
            libp2p,
            hopr,
            app,
            probe,
            start,
            session,
            experts,
            subtrees,
            prefs,
            proto_libp2p,
            proto_hopr,
            proto_app,
            proto_probe,
            proto_start,
            proto_session,
        }
    }
}
