//! Protocol preferences, as they appear under Edit → Preferences → Protocols.

use std::{
    ffi::{CStr, c_char},
    path::PathBuf,
};

use crate::{leak_cstring, proto::Protocol, sys};

/// A protocol's preferences module.
pub struct Prefs {
    module: *mut sys::module_t,
}

impl Prefs {
    /// Creates the preferences module for `proto`.
    ///
    /// `apply` runs whenever the user changes any of this protocol's preferences — the place to
    /// reload anything derived from them.
    pub fn register(proto: Protocol, apply: Option<unsafe extern "C" fn()>) -> Self {
        // SAFETY: called once from `plugin_register`, on the registration thread.
        Self {
            module: unsafe { sys::prefs_register_protocol(proto.id(), apply) },
        }
    }

    /// Adds a file-path preference, returning a handle that reads its current value.
    ///
    /// The storage is leaked because epan writes the user's choice through the pointer for as
    /// long as the process runs.
    pub fn filename(&self, name: &str, title: &str, description: &str) -> FilenamePref {
        let storage: &'static mut *const c_char = Box::leak(Box::new(std::ptr::null()));
        let ptr: *mut *const c_char = storage;

        // SAFETY: all three strings are leaked and `ptr` points at leaked storage, so every
        // pointer epan retains outlives the process.
        unsafe {
            sys::prefs_register_filename_preference(
                self.module,
                leak_cstring(name).as_ptr(),
                leak_cstring(title).as_ptr(),
                leak_cstring(description).as_ptr(),
                ptr,
                false,
            );
        }

        FilenamePref { storage: ptr }
    }

    /// Adds a boolean preference, returning a handle that reads its current value.
    pub fn boolean(&self, name: &str, title: &str, description: &str, default: bool) -> BoolPref {
        let storage: &'static mut bool = Box::leak(Box::new(default));
        let ptr: *mut bool = storage;

        // SAFETY: as `filename`.
        unsafe {
            sys::prefs_register_bool_preference(
                self.module,
                leak_cstring(name).as_ptr(),
                leak_cstring(title).as_ptr(),
                leak_cstring(description).as_ptr(),
                ptr,
            );
        }

        BoolPref { storage: ptr }
    }
}

/// Reads the current value of a file-path preference.
#[derive(Copy, Clone)]
pub struct FilenamePref {
    storage: *mut *const c_char,
}

// SAFETY: `storage` points at leaked, immovable storage that epan owns for the life of the
// process; this handle only reads through it. epan writes the value on the same thread that
// dissects, so a read here never races a write. The marker traits exist because the handle is
// held in a process-wide registration struct, not because it is used from another thread.
unsafe impl Send for FilenamePref {}
unsafe impl Sync for FilenamePref {}

impl FilenamePref {
    /// The path the user configured, or `None` while the preference is unset.
    pub fn get(self) -> Option<PathBuf> {
        // SAFETY: `storage` points at leaked storage epan owns for the process lifetime; the
        // string it holds is epan's and is read, not retained.
        unsafe {
            let raw = *self.storage;
            if raw.is_null() {
                return None;
            }
            let s = CStr::from_ptr(raw).to_string_lossy();
            (!s.is_empty()).then(|| PathBuf::from(s.as_ref()))
        }
    }
}

/// Reads the current value of a boolean preference.
#[derive(Copy, Clone)]
pub struct BoolPref {
    storage: *mut bool,
}

// SAFETY: as [`FilenamePref`].
unsafe impl Send for BoolPref {}
unsafe impl Sync for BoolPref {}

impl BoolPref {
    /// The value the user configured.
    pub fn get(self) -> bool {
        // SAFETY: as `FilenamePref::get`.
        unsafe { *self.storage }
    }
}
