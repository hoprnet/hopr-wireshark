//! Writing a classic `pcap` file containing a TCP conversation.
//!
//! Hand-rolled rather than taken from a crate: the format is a 24-byte file header and a 16-byte
//! record header, and the test needs exact control over sequence numbers and segment boundaries
//! anyway — which is the whole point of feeding a dissector a synthetic capture.

/// LINKTYPE_ETHERNET.
const LINKTYPE_ETHERNET: u32 = 1;

/// One direction of a TCP conversation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Client to server.
    AtoB,
    /// Server to client.
    BtoA,
}

/// Builds a capture of one TCP conversation between two endpoints.
pub struct TcpCapture {
    records: Vec<Vec<u8>>,
    seq_a: u32,
    seq_b: u32,
    port_a: u16,
    port_b: u16,
    timestamp_us: u64,
}

impl TcpCapture {
    /// Starts a capture, emitting the three-way handshake.
    pub fn new(port_a: u16, port_b: u16) -> Self {
        let mut capture = Self {
            records: Vec::new(),
            seq_a: 1000,
            seq_b: 2000,
            port_a,
            port_b,
            timestamp_us: 1_700_000_000_000_000,
        };

        // Without a handshake Wireshark still tracks the conversation, but starting mid-stream
        // makes it guess at sequence bases, and a test should not depend on the guess.
        capture.segment(Dir::AtoB, &[], 0x02); // SYN
        capture.seq_a += 1;
        capture.segment(Dir::BtoA, &[], 0x12); // SYN, ACK
        capture.seq_b += 1;
        capture.segment(Dir::AtoB, &[], 0x10); // ACK

        capture
    }

    /// Appends `payload` as one TCP segment in `dir`.
    pub fn send(&mut self, dir: Dir, payload: &[u8]) {
        self.segment(dir, payload, 0x18); // PSH, ACK
        match dir {
            Dir::AtoB => self.seq_a += payload.len() as u32,
            Dir::BtoA => self.seq_b += payload.len() as u32,
        }
    }

    /// Appends `payload` split into segments of at most `mtu` bytes.
    ///
    /// Used to put a unit across a segment boundary on purpose, which is what exercises the
    /// dissector's desegmentation.
    pub fn send_split(&mut self, dir: Dir, payload: &[u8], mtu: usize) {
        for chunk in payload.chunks(mtu.max(1)) {
            self.send(dir, chunk);
        }
    }

    /// Serialises the capture.
    pub fn finish(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // pcap file header: magic, version 2.4, no timezone correction, no snaplen limit.
        out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&262144u32.to_le_bytes());
        out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

        for record in &self.records {
            out.extend_from_slice(record);
        }
        out
    }

    /// Emits one segment with the given TCP flags.
    fn segment(&mut self, dir: Dir, payload: &[u8], flags: u8) {
        let (src_port, dst_port, seq, ack) = match dir {
            Dir::AtoB => (self.port_a, self.port_b, self.seq_a, self.seq_b),
            Dir::BtoA => (self.port_b, self.port_a, self.seq_b, self.seq_a),
        };
        let (src_ip, dst_ip) = match dir {
            Dir::AtoB => ([127, 0, 0, 1], [127, 0, 0, 2]),
            Dir::BtoA => ([127, 0, 0, 2], [127, 0, 0, 1]),
        };

        let mut frame = Vec::new();

        // Ethernet: two locally administered addresses and an IPv4 ethertype.
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        let tcp_len = 20 + payload.len();

        // IPv4: no options, so IHL is 5.
        frame.push(0x45);
        frame.push(0);
        frame.extend_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
        frame.push(64); // TTL
        frame.push(6); // TCP
        // Left zero: Wireshark does not validate IPv4 checksums by default, and a wrong one
        // would only add noise to the test's output.
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);

        // TCP: no options, so the data offset is 5 words.
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ack.to_be_bytes());
        frame.push(0x50);
        frame.push(flags);
        frame.extend_from_slice(&65535u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes()); // checksum, as above
        frame.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        frame.extend_from_slice(payload);

        // Record header: timestamp, captured length, original length.
        let mut record = Vec::new();
        record.extend_from_slice(&((self.timestamp_us / 1_000_000) as u32).to_le_bytes());
        record.extend_from_slice(&((self.timestamp_us % 1_000_000) as u32).to_le_bytes());
        record.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        record.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        record.extend_from_slice(&frame);

        self.timestamp_us += 1_000;
        self.records.push(record);
    }
}
