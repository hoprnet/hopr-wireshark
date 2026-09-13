//! Protocol, field, subtree and expert-info registration.
//!
//! Everything here runs once, from the plugin's `plugin_register` entry point. epan keeps the
//! pointers it is handed without copying them, so all of it is deliberately leaked (see
//! [`crate::leak_cstring`]); the total is bounded by the number of registered fields.

use std::ffi::c_int;

use crate::{leak_cstring, sys};

/// Handle to a registered field, used to place values in the detail tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FieldId(pub(crate) c_int);

/// Handle to a registered subtree (`ett_`), used to make an item expandable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SubtreeId(pub(crate) c_int);

/// Handle to a registered expert info, used to flag a problem on an item.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExpertId(pub(crate) usize);

/// Handle to a registered protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Protocol(pub(crate) c_int);

impl Protocol {
    /// Registers a protocol.
    ///
    /// `filter_name` is the prefix every one of the protocol's fields must use, and the name a
    /// user types in the display filter bar.
    pub fn register(name: &str, short_name: &str, filter_name: &str) -> Self {
        // SAFETY: the three strings are leaked, so they outlive epan's use of them, and
        // registration happens on the single thread that calls `plugin_register`.
        Self(unsafe {
            sys::proto_register_protocol(
                leak_cstring(name).as_ptr(),
                leak_cstring(short_name).as_ptr(),
                leak_cstring(filter_name).as_ptr(),
            )
        })
    }

    /// The protocol's numeric id, as epan knows it.
    pub fn id(self) -> c_int {
        self.0
    }
}

/// What a field holds and how it is displayed.
///
/// A deliberately small subset: the types this dissector's fields actually use. `FT_`/`BASE_`
/// combinations that epan rejects at registration (it aborts the process) are unrepresentable
/// here — for instance there is no way to ask for a decimal byte array.
#[derive(Copy, Clone, Debug)]
pub enum FieldKind {
    /// A label with no value of its own; the item's text carries the meaning.
    None,
    /// The protocol itself — the root item of a protocol's subtree.
    Protocol,
    /// A byte string, shown as hex.
    Bytes,
    /// A byte string, shown as colon-separated hex. Reads better for keys and identifiers.
    BytesColon,
    /// A UTF-8 string.
    String,
    /// An unsigned integer of `width` bytes (1, 2, 3, 4 or 8), shown in decimal.
    UintDec { width: u8 },
    /// An unsigned integer of `width` bytes, shown in hex.
    UintHex { width: u8 },
    /// An unsigned integer of `width` bytes, shown in decimal with the hex in parentheses.
    UintDecHex { width: u8 },
    /// A boolean occupying `width` bytes, true when `mask` is set.
    Flag { width: u8, mask: u64 },
}

impl FieldKind {
    fn ftype(self) -> sys::ftenum {
        fn uint(width: u8) -> sys::ftenum {
            match width {
                1 => sys::FT_UINT8,
                2 => sys::FT_UINT16,
                3 => sys::FT_UINT24,
                4 => sys::FT_UINT32,
                8 => sys::FT_UINT64,
                other => panic!("unsupported integer field width {other}; epan has no FT_UINT for it"),
            }
        }
        match self {
            FieldKind::None => sys::FT_NONE,
            FieldKind::Protocol => sys::FT_PROTOCOL,
            FieldKind::Bytes | FieldKind::BytesColon => sys::FT_BYTES,
            FieldKind::String => sys::FT_STRING,
            FieldKind::UintDec { width } | FieldKind::UintHex { width } | FieldKind::UintDecHex { width } => {
                uint(width)
            }
            FieldKind::Flag { width, .. } => {
                // For FT_BOOLEAN, `display` is the field's bit width rather than a BASE_, so the
                // width has to be a legal one even though no FT_UINT is involved.
                let _ = uint(width);
                sys::FT_BOOLEAN
            }
        }
    }

    fn display(self) -> c_int {
        match self {
            FieldKind::None | FieldKind::Protocol | FieldKind::Bytes | FieldKind::String => sys::BASE_NONE as c_int,
            FieldKind::BytesColon => sys::SEP_COLON as c_int,
            FieldKind::UintDec { .. } => sys::BASE_DEC as c_int,
            FieldKind::UintHex { .. } => sys::BASE_HEX as c_int,
            FieldKind::UintDecHex { .. } => sys::BASE_DEC_HEX as c_int,
            FieldKind::Flag { width, .. } => (width as c_int) * 8,
        }
    }

    fn bitmask(self) -> u64 {
        match self {
            FieldKind::Flag { mask, .. } => mask,
            _ => 0,
        }
    }
}

/// A field to register: its display name, filter name, type and description.
pub struct FieldSpec {
    /// Shown in the detail pane, e.g. `"Packet Tag"`.
    pub name: &'static str,
    /// Display-filter name. Must start with the protocol's filter name, e.g. `"hopr.packet_tag"`.
    pub abbrev: &'static str,
    /// Type and display base.
    pub kind: FieldKind,
    /// Tooltip / `-G fields` description. Empty for none.
    pub blurb: &'static str,
    /// Optional enum labels, as `(value, label)` pairs. Rendered as `label (value)`.
    pub values: &'static [(u32, &'static str)],
}

impl FieldSpec {
    /// A field with no enum labels.
    pub const fn new(name: &'static str, abbrev: &'static str, kind: FieldKind, blurb: &'static str) -> Self {
        Self {
            name,
            abbrev,
            kind,
            blurb,
            values: &[],
        }
    }

    /// A field whose numeric value has known labels.
    pub const fn enumerated(
        name: &'static str,
        abbrev: &'static str,
        kind: FieldKind,
        blurb: &'static str,
        values: &'static [(u32, &'static str)],
    ) -> Self {
        Self {
            name,
            abbrev,
            kind,
            blurb,
            values,
        }
    }
}

/// An expert info to register: a condition worth flagging in the "Expert Information" dialog.
pub struct ExpertInfo {
    /// Filter name, e.g. `"hopr.decrypt_failed"`.
    pub abbrev: &'static str,
    /// One-line summary shown in the expert list.
    pub summary: &'static str,
    /// Which group it belongs to (`PI_MALFORMED`, `PI_PROTOCOL`, ...).
    pub group: u32,
    /// How bad it is (`PI_ERROR`, `PI_WARN`, `PI_NOTE`, `PI_COMMENT`).
    pub severity: u32,
}

/// Collects fields, subtrees and expert infos, then hands them to epan in one go.
///
/// epan requires the `hf_register_info` array to stay alive for the life of the process and
/// writes each field's assigned id back into it, so the array is built here, leaked, and the ids
/// read out afterwards.
// The `Box`es below are not redundant indirection: each `hf_register_info`/`ei_register_info`
// holds a raw pointer *into* these vectors, taken while the vector is still growing. Storing the
// values inline would invalidate every pointer already handed out on the next reallocation.
#[allow(clippy::vec_box)]
pub struct Registry {
    proto: Protocol,
    hf: Vec<sys::hf_register_info>,
    /// Boxed so the `*mut c_int` epan writes through stays put while the vector grows.
    field_ids: Vec<Box<c_int>>,
    ett: Vec<Box<c_int>>,
    ei: Vec<sys::ei_register_info>,
    ei_ids: Vec<Box<sys::expert_field>>,
}

impl Registry {
    /// Starts collecting registrations for `proto`.
    pub fn new(proto: Protocol) -> Self {
        Self {
            proto,
            hf: Vec::new(),
            field_ids: Vec::new(),
            ett: Vec::new(),
            ei: Vec::new(),
            ei_ids: Vec::new(),
        }
    }

    /// Adds a field, returning the handle used to place it in a tree.
    ///
    /// The handle is not usable until [`Registry::finish`] has run, because epan assigns the id
    /// during registration. Since registration completes before any packet is dissected, that
    /// distinction never shows up at a call site.
    pub fn field(&mut self, spec: &FieldSpec) -> FieldId {
        debug_assert!(
            spec.abbrev.contains('.'),
            "field abbrev {:?} must be prefixed with the protocol's filter name",
            spec.abbrev
        );

        let mut id = Box::new(-1_i32);
        let id_ptr: *mut c_int = &mut *id;
        self.field_ids.push(id);

        let strings = if spec.values.is_empty() {
            std::ptr::null()
        } else {
            value_string_array(spec.values) as *const std::ffi::c_void
        };

        self.hf.push(sys::hf_register_info {
            p_id: id_ptr,
            hfinfo: sys::header_field_info {
                name: leak_cstring(spec.name).as_ptr(),
                abbrev: leak_cstring(spec.abbrev).as_ptr(),
                type_: spec.kind.ftype(),
                display: spec.kind.display(),
                strings,
                bitmask: spec.kind.bitmask(),
                blurb: if spec.blurb.is_empty() {
                    std::ptr::null()
                } else {
                    leak_cstring(spec.blurb).as_ptr()
                },
                // The HFILL macro's contents. epan fills these in.
                id: -1,
                parent: 0,
                ref_type: sys::HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        });

        // The id is read back in `finish`; until then this handle's value is a placeholder.
        FieldId(self.field_ids.len() as c_int - 1)
    }

    /// Adds a subtree index.
    pub fn subtree(&mut self) -> SubtreeId {
        self.ett.push(Box::new(-1));
        SubtreeId(self.ett.len() as c_int - 1)
    }

    /// Adds an expert info.
    pub fn expert(&mut self, info: &ExpertInfo) -> ExpertId {
        let mut field = Box::new(sys::expert_field { ei: -1, hf: -1 });
        let field_ptr: *mut sys::expert_field = &mut *field;
        self.ei_ids.push(field);

        self.ei.push(sys::ei_register_info {
            ids: field_ptr,
            eiinfo: sys::expert_field_info {
                name: leak_cstring(info.abbrev).as_ptr(),
                group: info.group as c_int,
                severity: info.severity as c_int,
                summary: leak_cstring(info.summary).as_ptr(),
                // The EXPFILL macro's contents.
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: unsafe { std::mem::zeroed() },
            },
        });

        ExpertId(self.ei_ids.len() - 1)
    }

    /// Hands everything collected to epan and returns the resolved handles.
    ///
    /// Must be called from `plugin_register`, before any dissection.
    pub fn finish(self) -> Registered {
        let Registry {
            proto,
            hf,
            field_ids,
            ett,
            ei,
            ei_ids,
        } = self;

        // epan keeps the arrays; leaking is the documented contract, not an oversight.
        let hf = Box::leak(hf.into_boxed_slice());
        let field_ids = Box::leak(field_ids.into_boxed_slice());
        let ett = Box::leak(ett.into_boxed_slice());
        let ei = Box::leak(ei.into_boxed_slice());
        let ei_ids = Box::leak(ei_ids.into_boxed_slice());

        // SAFETY: every pointer below outlives the process, the counts match the arrays, and
        // this runs on the registration thread before any dissection.
        unsafe {
            if !hf.is_empty() {
                sys::proto_register_field_array(proto.0, hf.as_mut_ptr(), hf.len() as c_int);
            }
            if !ett.is_empty() {
                let ptrs: Vec<*mut c_int> = ett.iter_mut().map(|b| &mut **b as *mut c_int).collect();
                let ptrs = Box::leak(ptrs.into_boxed_slice());
                sys::proto_register_subtree_array(ptrs.as_ptr(), ptrs.len() as c_int);
            }
            if !ei.is_empty() {
                let module = sys::expert_register_protocol(proto.0);
                sys::expert_register_field_array(module, ei.as_mut_ptr(), ei.len() as c_int);
            }
        }

        Registered {
            proto,
            fields: field_ids.iter().map(|b| **b).collect(),
            subtrees: ett.iter().map(|b| **b).collect(),
            experts: ei_ids.iter().map(|b| **b).collect(),
        }
    }
}

/// The ids epan assigned, resolved from the handles [`Registry`] returned.
pub struct Registered {
    proto: Protocol,
    fields: Vec<c_int>,
    subtrees: Vec<c_int>,
    experts: Vec<sys::expert_field>,
}

impl Registered {
    /// The protocol these registrations belong to.
    pub fn protocol(&self) -> Protocol {
        self.proto
    }

    /// Resolves a field handle to the id epan assigned.
    pub fn field(&self, id: FieldId) -> c_int {
        self.fields[id.0 as usize]
    }

    /// Resolves a subtree handle to the id epan assigned.
    pub fn subtree(&self, id: SubtreeId) -> c_int {
        self.subtrees[id.0 as usize]
    }

    /// Resolves an expert handle to the record epan assigned.
    pub(crate) fn expert(&self, id: ExpertId) -> sys::expert_field {
        self.experts[id.0]
    }
}

/// Byte-order and representation hint for [`crate::Tree::add`].
#[derive(Copy, Clone, Debug)]
pub enum Encoding {
    /// Multi-byte integers are big-endian. HOPR and libp2p are big-endian throughout.
    BigEndian,
    /// Multi-byte integers are little-endian.
    LittleEndian,
    /// Not applicable — byte arrays, strings and label-only fields.
    NotApplicable,
    /// A UTF-8 string of the item's length.
    Utf8,
}

impl Encoding {
    pub(crate) fn raw(self) -> std::ffi::c_uint {
        match self {
            Encoding::BigEndian | Encoding::NotApplicable => sys::ENC_BIG_ENDIAN,
            Encoding::LittleEndian => sys::ENC_LITTLE_ENDIAN,
            Encoding::Utf8 => sys::ENC_UTF_8,
        }
    }
}

/// Builds the NUL-terminated `value_string` array epan expects for an enumerated field.
fn value_string_array(values: &'static [(u32, &'static str)]) -> *const sys::value_string {
    let mut out: Vec<sys::value_string> = values
        .iter()
        .map(|(v, label)| sys::value_string {
            value: *v,
            strptr: leak_cstring(label).as_ptr(),
        })
        .collect();
    // epan walks the array until it finds a null `strptr`.
    out.push(sys::value_string {
        value: 0,
        strptr: std::ptr::null(),
    });
    Box::leak(out.into_boxed_slice()).as_ptr()
}
