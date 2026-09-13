//! placeholder
epan::declare_plugin!(version = "0.1.0", protoinfo = protoinfo, handoff = handoff);

fn protoinfo() {
    let proto = epan::Protocol::register("HOPR Protocol", "HOPR", "hopr");
    let _ = proto;
}

fn handoff() {}
