//! The detail tree, the summary columns, and the per-packet metadata around them.

use std::ffi::{CString, c_int};

use crate::{
    Tvb, leak_cstring,
    proto::{Encoding, ExpertId, FieldId, Registered, SubtreeId},
    sys,
};

/// A node in the packet detail tree.
///
/// May be null: Wireshark skips building the tree when nothing will read it (the common case
/// while scanning a large file), and every method here is a no-op in that state. That is why the
/// type is `Copy` and infallible rather than an `Option` every call site would have to unwrap.
#[derive(Copy, Clone)]
pub struct Tree<'a> {
    raw: *mut sys::proto_tree,
    reg: &'a Registered,
}

/// A single item in the tree, as returned by the `add*` methods.
#[derive(Copy, Clone)]
pub struct TreeItem<'a> {
    raw: *mut sys::proto_item,
    reg: &'a Registered,
}

impl<'a> Tree<'a> {
    /// Wraps a raw `proto_tree` for the duration of a dissector call.
    ///
    /// # Safety
    /// `raw` must be null or a valid `proto_tree` that outlives `'a`.
    pub unsafe fn from_raw(raw: *mut sys::proto_tree, reg: &'a Registered) -> Self {
        Self { raw, reg }
    }

    /// Whether Wireshark is actually building a tree for this packet.
    ///
    /// Worth checking before computing something expensive purely for display; the `add*` methods
    /// already handle the null case themselves.
    pub fn is_visible(self) -> bool {
        !self.raw.is_null()
    }

    /// Adds `len` bytes at `offset` as `field`, letting epan format the value.
    pub fn add(self, field: FieldId, tvb: Tvb<'_>, offset: usize, len: usize, enc: Encoding) -> TreeItem<'a> {
        if self.raw.is_null() {
            return TreeItem::null(self.reg);
        }
        // SAFETY: `raw` is a valid tree, `tvb` a valid buffer, and `field` an id epan assigned.
        // Out-of-range offsets are epan's to report (it marks the item malformed).
        let item = unsafe {
            sys::proto_tree_add_item(
                self.raw,
                self.reg.field(field),
                tvb.as_raw(),
                offset as c_int,
                len as c_int,
                enc.raw(),
            )
        };
        TreeItem {
            raw: item,
            reg: self.reg,
        }
    }

    /// Adds a byte array that is not a verbatim slice of `tvb` — a decrypted value, say — while
    /// still anchoring it to the `offset..offset + len` bytes it came from.
    ///
    /// `len` is only how much of the buffer the item highlights; the value's own length decides
    /// how many bytes are read from it. `proto_tree_add_bytes` conflates the two and would read
    /// `len` bytes out of `value`, which for anything decrypted — where the highlight covers the
    /// whole ciphertext and the value is a field inside it — reads off the end of the allocation.
    pub fn add_bytes(self, field: FieldId, tvb: Tvb<'_>, offset: usize, len: usize, value: &[u8]) -> TreeItem<'a> {
        if self.raw.is_null() {
            return TreeItem::null(self.reg);
        }
        // SAFETY: `value` is read for exactly `value.len()` bytes during the call and not retained.
        let item = unsafe {
            sys::proto_tree_add_bytes_with_length(
                self.raw,
                self.reg.field(field),
                tvb.as_raw(),
                offset as c_int,
                len as c_int,
                value.as_ptr(),
                value.len() as c_int,
            )
        };
        TreeItem {
            raw: item,
            reg: self.reg,
        }
    }

    /// Adds a string value anchored to `offset..offset + len`.
    pub fn add_str(self, field: FieldId, tvb: Tvb<'_>, offset: usize, len: usize, value: &str) -> TreeItem<'a> {
        if self.raw.is_null() {
            return TreeItem::null(self.reg);
        }
        let value = CString::new(value).unwrap_or_else(|_| c"<string contains NUL>".into());
        // SAFETY: `value` lives until the end of the statement; epan copies it.
        let item = unsafe {
            sys::proto_tree_add_string(
                self.raw,
                self.reg.field(field),
                tvb.as_raw(),
                offset as c_int,
                len as c_int,
                value.as_ptr(),
            )
        };
        TreeItem {
            raw: item,
            reg: self.reg,
        }
    }

    /// Adds an integer value anchored to `offset..offset + len`.
    pub fn add_uint(self, field: FieldId, tvb: Tvb<'_>, offset: usize, len: usize, value: u32) -> TreeItem<'a> {
        if self.raw.is_null() {
            return TreeItem::null(self.reg);
        }
        // SAFETY: as `add`.
        let item = unsafe {
            sys::proto_tree_add_uint(
                self.raw,
                self.reg.field(field),
                tvb.as_raw(),
                offset as c_int,
                len as c_int,
                value,
            )
        };
        TreeItem {
            raw: item,
            reg: self.reg,
        }
    }

    /// Adds a 64-bit integer value anchored to `offset..offset + len`.
    ///
    /// Separate from [`Tree::add_uint`] because epan's two setters are not interchangeable: the
    /// 32-bit one rejects a field wider than `FT_UINT32` with a "dissector bug" expert info
    /// rather than truncating.
    pub fn add_uint64(self, field: FieldId, tvb: Tvb<'_>, offset: usize, len: usize, value: u64) -> TreeItem<'a> {
        if self.raw.is_null() {
            return TreeItem::null(self.reg);
        }
        // SAFETY: as `add`.
        let item = unsafe {
            sys::proto_tree_add_uint64(
                self.raw,
                self.reg.field(field),
                tvb.as_raw(),
                offset as c_int,
                len as c_int,
                value,
            )
        };
        TreeItem {
            raw: item,
            reg: self.reg,
        }
    }

    /// Adds a boolean value anchored to `offset..offset + len`.
    pub fn add_bool(self, field: FieldId, tvb: Tvb<'_>, offset: usize, len: usize, value: bool) -> TreeItem<'a> {
        if self.raw.is_null() {
            return TreeItem::null(self.reg);
        }
        // SAFETY: as `add`.
        let item = unsafe {
            sys::proto_tree_add_boolean(
                self.raw,
                self.reg.field(field),
                tvb.as_raw(),
                offset as c_int,
                len as c_int,
                value as u64,
            )
        };
        TreeItem {
            raw: item,
            reg: self.reg,
        }
    }

    /// Adds a label-only expandable node and returns the subtree under it.
    pub fn add_subtree(
        self,
        ett: SubtreeId,
        tvb: Tvb<'_>,
        offset: usize,
        len: usize,
        label: &str,
    ) -> (TreeItem<'a>, Tree<'a>) {
        if self.raw.is_null() {
            return (TreeItem::null(self.reg), self);
        }
        let label = CString::new(label).unwrap_or_else(|_| c"<label contains NUL>".into());
        let mut item: *mut sys::proto_item = std::ptr::null_mut();
        // SAFETY: `label` lives until the end of the statement; epan copies it. `item` receives
        // the created node.
        let sub = unsafe {
            sys::proto_tree_add_subtree(
                self.raw,
                tvb.as_raw(),
                offset as c_int,
                len as c_int,
                self.reg.subtree(ett),
                &mut item,
                label.as_ptr(),
            )
        };
        (
            TreeItem {
                raw: item,
                reg: self.reg,
            },
            Tree {
                raw: sub,
                reg: self.reg,
            },
        )
    }
}

impl<'a> TreeItem<'a> {
    fn null(reg: &'a Registered) -> Self {
        Self {
            raw: std::ptr::null_mut(),
            reg,
        }
    }

    /// Makes this item expandable and returns the subtree under it.
    pub fn subtree(self, ett: SubtreeId) -> Tree<'a> {
        if self.raw.is_null() {
            return Tree {
                raw: std::ptr::null_mut(),
                reg: self.reg,
            };
        }
        // SAFETY: `raw` is a valid item and `ett` an index epan assigned.
        let sub = unsafe { sys::proto_item_add_subtree(self.raw, self.reg.subtree(ett)) };
        Tree {
            raw: sub,
            reg: self.reg,
        }
    }

    /// Appends text to the item's label.
    pub fn append(self, text: &str) -> Self {
        if self.raw.is_null() {
            return self;
        }
        let text = CString::new(text).unwrap_or_else(|_| c"<text contains NUL>".into());
        // SAFETY: the format string is the literal `%s`, so exactly one `char *` argument is
        // consumed and `text` cannot be interpreted as a format itself.
        unsafe { sys::proto_item_append_text(self.raw, c"%s".as_ptr(), text.as_ptr()) };
        self
    }

    /// Replaces the item's label.
    pub fn set_text(self, text: &str) -> Self {
        if self.raw.is_null() {
            return self;
        }
        let text = CString::new(text).unwrap_or_else(|_| c"<text contains NUL>".into());
        // SAFETY: as `append`.
        unsafe { sys::proto_item_set_text(self.raw, c"%s".as_ptr(), text.as_ptr()) };
        self
    }

    /// Sets how many bytes the item covers, for a length only known after parsing.
    pub fn set_len(self, len: usize) -> Self {
        if !self.raw.is_null() {
            // SAFETY: `raw` is a valid item.
            unsafe { sys::proto_item_set_len(self.raw, len as c_int) };
        }
        self
    }

    /// Flags a problem on this item, so it shows up in Expert Information.
    pub fn expert(self, pinfo: &mut Pinfo<'_>, id: ExpertId, detail: &str) -> Self {
        let mut field = self.reg.expert(id);
        let detail = CString::new(detail).unwrap_or_else(|_| c"<detail contains NUL>".into());
        // SAFETY: `pinfo` is valid for the call, `field` is a copy of a registered record (epan
        // reads the ids out of it), and the format string is the literal `%s`. A null `raw` is
        // explicitly allowed here — epan attaches the info to the current tree instead.
        unsafe {
            sys::expert_add_info_format(pinfo.raw, self.raw, &mut field, c"%s".as_ptr(), detail.as_ptr());
        }
        self
    }
}

/// Per-packet metadata: the summary columns, the addresses, and the desegmentation request.
pub struct Pinfo<'a> {
    pub(crate) raw: *mut sys::packet_info,
    _marker: std::marker::PhantomData<&'a ()>,
}

/// Asks TCP for one more segment, whatever its size.
pub const DESEGMENT_ONE_MORE_SEGMENT: u32 = 0x0fffffff;

impl<'a> Pinfo<'a> {
    /// Wraps a raw `packet_info` for the duration of a dissector call.
    ///
    /// # Safety
    /// `raw` must be a valid `packet_info` that outlives `'a`.
    pub unsafe fn from_raw(raw: *mut sys::packet_info) -> Self {
        Self {
            raw,
            _marker: std::marker::PhantomData,
        }
    }

    /// The raw pointer, for the few epan calls this wrapper does not cover.
    pub fn as_raw(&mut self) -> *mut sys::packet_info {
        self.raw
    }

    /// This packet's number in the capture, as shown in the "No." column.
    pub fn frame_number(&self) -> u32 {
        // SAFETY: `raw` is valid for `'a`.
        unsafe { (*self.raw).num }
    }

    /// Whether this packet has been dissected before.
    ///
    /// Wireshark dissects each packet at least twice — once while reading the file, again when
    /// the user selects it — so any state a dissector accumulates must be built on the first
    /// visit only, and replayed on later ones. Getting this wrong is the classic way a stateful
    /// dissector shows different results depending on what the user clicked.
    pub fn visited(&self) -> bool {
        // SAFETY: `raw` is valid and `fd` is non-null for any packet under dissection.
        unsafe { (*(*self.raw).fd).visited() != 0 }
    }

    /// Source port of the current transport-layer conversation.
    pub fn src_port(&self) -> u32 {
        // SAFETY: `raw` is valid for `'a`.
        unsafe { (*self.raw).srcport }
    }

    /// Destination port of the current transport-layer conversation.
    pub fn dst_port(&self) -> u32 {
        // SAFETY: `raw` is valid for `'a`.
        unsafe { (*self.raw).destport }
    }

    /// Sets the Protocol column.
    pub fn set_protocol(&mut self, name: &'static str) {
        // SAFETY: `cinfo` may be null (no columns wanted); epan's `col_*` tolerate that. The
        // string is leaked, so it outlives epan's use of it.
        unsafe {
            sys::col_set_str(
                (*self.raw).cinfo,
                sys::COL_PROTOCOL as c_int,
                leak_cstring(name).as_ptr(),
            )
        };
    }

    /// Empties the Info column.
    pub fn clear_info(&mut self) {
        // SAFETY: as `set_protocol`.
        unsafe { sys::col_clear((*self.raw).cinfo, sys::COL_INFO as c_int) };
    }

    /// Appends to the Info column, inserting `", "` if it is not empty.
    pub fn append_info(&mut self, text: &str) {
        let text = CString::new(text).unwrap_or_else(|_| c"<info contains NUL>".into());
        // SAFETY: epan copies the strings during the call.
        unsafe { sys::col_append_sep_str((*self.raw).cinfo, sys::COL_INFO as c_int, c", ".as_ptr(), text.as_ptr()) };
    }

    /// Tells TCP that dissection needs more bytes than this segment carries.
    ///
    /// `offset` is where in the current buffer the incomplete unit starts; `len` is how many more
    /// bytes are needed, or [`DESEGMENT_ONE_MORE_SEGMENT`] when that is not yet known. TCP will
    /// call the dissector again with a buffer that starts at `offset` and carries more data.
    ///
    /// Has no effect unless TCP offered desegmentation for this packet (`can_desegment`), which
    /// it does not when the user has turned TCP reassembly off — in that case the dissector must
    /// cope with the truncated unit, which here means skipping it.
    pub fn request_more_data(&mut self, offset: usize, len: u32) -> bool {
        // SAFETY: `raw` is valid for `'a`; these are plain fields of the struct.
        unsafe {
            if (*self.raw).can_desegment == 0 {
                return false;
            }
            (*self.raw).desegment_offset = offset as c_int;
            (*self.raw).desegment_len = len;
            true
        }
    }

    /// Registers `data` as a named buffer the user can inspect in the bytes pane, and returns a
    /// tvb over it.
    ///
    /// Used for anything that is not a verbatim slice of the wire: the decrypted HOPR payload
    /// shows up as its own "Decrypted ..." tab next to the raw frame.
    pub fn add_data_source<'t>(&mut self, parent: Tvb<'t>, name: &str, data: &[u8]) -> Tvb<'t> {
        let name = CString::new(name).unwrap_or_else(|_| c"<name contains NUL>".into());
        // SAFETY: `tvb_new_child_real_data` copies nothing, so `data` would have to outlive the
        // tvb — which is why the bytes are copied into epan-managed memory first, by handing the
        // pointer to a tvb that is immediately tied to `parent`'s lifetime through
        // `add_new_data_source`. epan takes ownership of the copy via the child relationship.
        unsafe {
            let copy = sys::wmem_alloc(sys::wmem_file_scope(), data.len()) as *mut u8;
            std::ptr::copy_nonoverlapping(data.as_ptr(), copy, data.len());
            let child = sys::tvb_new_child_real_data(parent.as_raw(), copy, data.len() as u32, data.len() as c_int);
            sys::add_new_data_source(self.raw, child, name.as_ptr());
            Tvb::from_raw(child)
        }
    }
}
