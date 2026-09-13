//! Access to a `tvbuff_t` — the byte buffer a dissector is handed.

use std::ffi::c_int;

use crate::sys;

/// A borrowed view of the bytes under dissection.
///
/// Valid only for the dissector call that produced it; the lifetime enforces that. A tvb may be
/// shorter than the packet claims to be (a truncated capture), which is why "captured" and
/// "reported" lengths are separate: reading past the captured length throws a C-level exception
/// inside epan, so this type only ever reads within it.
#[derive(Copy, Clone)]
pub struct Tvb<'a> {
    pub(crate) raw: *mut sys::tvbuff_t,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> Tvb<'a> {
    /// Wraps a raw `tvbuff_t` for the duration of a dissector call.
    ///
    /// # Safety
    /// `raw` must be a valid `tvbuff_t` that outlives `'a`.
    pub unsafe fn from_raw(raw: *mut sys::tvbuff_t) -> Self {
        Self {
            raw,
            _marker: std::marker::PhantomData,
        }
    }

    /// The raw pointer, for the few epan calls this wrapper does not cover.
    pub fn as_raw(self) -> *mut sys::tvbuff_t {
        self.raw
    }

    /// Number of bytes actually present in the capture.
    pub fn captured_len(self) -> usize {
        // SAFETY: `raw` is valid for `'a`.
        unsafe { sys::tvb_captured_length(self.raw) as usize }
    }

    /// Number of bytes the packet claims to carry, which may exceed [`Tvb::captured_len`].
    pub fn reported_len(self) -> usize {
        // SAFETY: `raw` is valid for `'a`.
        unsafe { sys::tvb_reported_length(self.raw) as usize }
    }

    /// Whether `len` bytes are really present at `offset`.
    pub fn has(self, offset: usize, len: usize) -> bool {
        offset.checked_add(len).is_some_and(|end| end <= self.captured_len())
    }

    /// Copies `len` bytes from `offset`, or `None` if they were not captured.
    pub fn bytes(self, offset: usize, len: usize) -> Option<Vec<u8>> {
        if !self.has(offset, len) {
            return None;
        }
        let mut out = vec![0u8; len];
        // SAFETY: the bounds check above guarantees `offset..offset + len` is captured, and
        // `out` has room for exactly `len` bytes.
        unsafe {
            sys::tvb_memcpy(
                self.raw,
                out.as_mut_ptr() as *mut std::ffi::c_void,
                offset as c_int,
                len,
            );
        }
        Some(out)
    }

    /// Reads one byte, or `None` if it was not captured.
    pub fn u8(self, offset: usize) -> Option<u8> {
        self.has(offset, 1)
            .then(|| unsafe { sys::tvb_get_uint8(self.raw, offset as c_int) })
    }

    /// Reads a big-endian `u16`, or `None` if the bytes were not captured.
    pub fn u16_be(self, offset: usize) -> Option<u16> {
        self.has(offset, 2)
            .then(|| unsafe { sys::tvb_get_ntohs(self.raw, offset as c_int) })
    }

    /// Reads a big-endian `u32`, or `None` if the bytes were not captured.
    pub fn u32_be(self, offset: usize) -> Option<u32> {
        self.has(offset, 4)
            .then(|| unsafe { sys::tvb_get_ntohl(self.raw, offset as c_int) })
    }

    /// A view of `len` bytes starting at `offset`, for handing to another dissector.
    pub fn subset(self, offset: usize, len: usize) -> Option<Tvb<'a>> {
        self.has(offset, len).then(|| {
            // SAFETY: bounds checked; the child tvb borrows from `self` and shares its lifetime.
            unsafe { Tvb::from_raw(sys::tvb_new_subset_length(self.raw, offset as c_int, len as c_int)) }
        })
    }
}
