use alloc::vec::Vec;
use wdk_sys::UNICODE_STRING;
use alloc::string::String;
/// A wrapper around a `Vec<u16>` representing a Unicode string.
#[derive(Default)]
pub struct OwnedUnicodeString {
    /// The internal buffer holding the wide (UTF-16) string, including the null terminator.
    buffer: Vec<u16>,
    /// A marker to indicate that this struct cannot be moved once pinned.
    /// This ensures that the memory address of the buffer remains valid for the lifetime of the
    /// `UNICODE_STRING`.
    _phantompinned: core::marker::PhantomPinned,
}

impl OwnedUnicodeString {
    /// Converts the `OwnedUnicodeString` into a `UNICODE_STRING` that can be used in kernel APIs.
    ///
    /// # Returns
    ///
    /// * A `UNICODE_STRING` pointing to the wide string stored in `buffer`.
    pub fn to_unicode(&self) -> UNICODE_STRING {
        // The length is the size of the string in bytes, excluding the null terminator.
        // MaximumLength includes the null terminator.
        UNICODE_STRING {
            Length: ((self.buffer.len() * size_of::<u16>()) - 2) as u16,
            MaximumLength: (self.buffer.len() * size_of::<u16>()) as u16,
            Buffer: self.buffer.as_ptr() as *mut u16,
        }
    }
    pub fn to_string_lossy(&self) -> String {
        // Create a slice without the null terminator, if present.
        let utf16_slice = if let Some((&last, elems)) = self.buffer.split_last() {
            if last == 0 {
                elems
            } else {
                self.buffer.as_slice()
            }
        } else {
            self.buffer.as_slice()
        };
        String::from_utf16_lossy(utf16_slice)
    }
}

/// Converts a Rust `&str` to an `OwnedUnicodeString`.
///
/// # Arguments
///
/// * `str` - A reference to the Rust string slice to be converted.
///
/// # Returns
///
/// * A structure containing the wide (UTF-16) representation of the input string.
pub fn str_to_unicode(str: &str) -> OwnedUnicodeString {
    // Convert the rust string to a wide string
    let mut wide_string: Vec<u16> = str.encode_utf16().collect();

    // Null terminate the string
    wide_string.push(0);

    OwnedUnicodeString {
        buffer: wide_string,
        _phantompinned: core::marker::PhantomPinned,
    }
}
