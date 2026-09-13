//! `ApplicationData`: the eight-byte tag and payload that every final packet's plaintext is.
//!
//! The tag decides which protocol the payload belongs to. Tags below
//! [`ReservedTag::UPPER_BOUND`] are reserved for HOPR's own protocols and are handed to the
//! matching dissector here; everything above is an application's own traffic, which the dissector
//! shows as bytes because only the application knows what they mean.

use epan::{Encoding, Pinfo, Tree, Tvb};
use hopr_protocol_app::v1::{ApplicationData, ReservedTag, Tag};

use crate::{
    fields::Fields,
    hopr::{probe, session, start},
};

/// Dissects an `ApplicationData` encoding and whatever protocol its tag names.
///
/// `data` is the decrypted payload and `tvb` a data source over exactly those bytes, so offsets
/// into one are offsets into the other.
///
/// Returns a short description for the Info column.
pub fn dissect(f: &Fields, data: &[u8], tvb: Tvb<'_>, pinfo: &mut Pinfo<'_>, tree: Tree<'_>) -> String {
    let app = match ApplicationData::try_from(data) {
        Ok(app) => app,
        Err(error) => {
            let (item, _) = tree.add_subtree(f.subtrees.app, tvb, 0, data.len(), "Application Data");
            item.expert(pinfo, f.experts.malformed, &format!("not an ApplicationData: {error}"));
            return "malformed application data".into();
        }
    };

    let tag = app.application_tag;
    let reserved = reserved_tag(tag);
    let label = reserved.map(name_of).unwrap_or("Application");

    let (_, sub) = tree.add_subtree(
        f.subtrees.app,
        tvb,
        0,
        data.len(),
        &format!(
            "Application Data: {label}, tag {}, {} bytes",
            tag.as_u64(),
            app.plain_text.len()
        ),
    );

    sub.add_uint64(f.app.tag, tvb, 0, Tag::SIZE, tag.as_u64());
    if let Some(reserved) = reserved {
        sub.add_uint(f.app.tag_name, tvb, 0, Tag::SIZE, reserved as u32);
    }
    sub.add_uint(f.app.payload_len, tvb, 0, Tag::SIZE, app.plain_text.len() as u32);

    let payload = &data[Tag::SIZE..];
    let Some(payload_tvb) = tvb.subset(Tag::SIZE, payload.len()) else {
        return format!("{label} (payload not captured)");
    };

    match reserved {
        Some(ReservedTag::Ping) => format!("Probe: {}", probe::dissect(f, payload, payload_tvb, pinfo, sub)),
        Some(ReservedTag::SessionStart) => {
            format!("Start: {}", start::dissect(f, tag, payload, payload_tvb, pinfo, sub))
        }
        Some(ReservedTag::Session) => format!("Session: {}", session::dissect(f, payload, payload_tvb, pinfo, sub)),
        // `Undefined` is the catch-all inside the reserved range: a tag that names no protocol,
        // so there is nothing further to decode.
        Some(ReservedTag::Undefined) | None => {
            sub.add(f.app.payload, payload_tvb, 0, payload.len(), Encoding::NotApplicable);
            format!("{label} tag {}, {} bytes", tag.as_u64(), payload.len())
        }
    }
}

/// The reserved protocol a tag names, if it is in the reserved range.
fn reserved_tag(tag: Tag) -> Option<ReservedTag> {
    match tag {
        Tag::Reserved(0) => Some(ReservedTag::Ping),
        Tag::Reserved(1) => Some(ReservedTag::SessionStart),
        Tag::Reserved(2) => Some(ReservedTag::Session),
        Tag::Reserved(15) => Some(ReservedTag::Undefined),
        // A reserved value with no protocol behind it yet. Treated as opaque rather than
        // guessed at, so a tag added upstream shows up as unknown instead of mis-decoded.
        Tag::Reserved(_) | Tag::Application(_) => None,
    }
}

/// Display name of a reserved tag.
fn name_of(tag: ReservedTag) -> &'static str {
    match tag {
        ReservedTag::Ping => "Probe",
        ReservedTag::SessionStart => "Start",
        ReservedTag::Session => "Session",
        ReservedTag::Undefined => "Undefined",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_recognise_every_reserved_tag_the_protocol_defines() {
        assert!(matches!(reserved_tag(Tag::Reserved(0)), Some(ReservedTag::Ping)));
        assert!(matches!(
            reserved_tag(Tag::Reserved(1)),
            Some(ReservedTag::SessionStart)
        ));
        assert!(matches!(reserved_tag(Tag::Reserved(2)), Some(ReservedTag::Session)));
        assert!(matches!(reserved_tag(Tag::Reserved(15)), Some(ReservedTag::Undefined)));
    }

    #[test]
    fn should_treat_an_unassigned_reserved_tag_as_unknown() {
        assert!(
            reserved_tag(Tag::Reserved(7)).is_none(),
            "a reserved value with no protocol behind it must not be decoded as one"
        );
    }

    #[test]
    fn should_treat_application_tags_as_opaque() {
        assert!(reserved_tag(Tag::Application(16)).is_none());
        assert!(reserved_tag(Tag::Application(1_000_000)).is_none());
    }
}
