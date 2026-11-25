#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

/// A reference to a slice of bytes in a [`NameArena`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NameRef {
    /// Byte offset within the arena.
    pub off: u32,
    /// Byte length of the name.
    pub len: u16,
}

/// Compact byte arena storing file and directory names in WTF-8 encoding.
///
/// WTF-8 preserves unpaired UTF-16 surrogates without loss, which is required
/// because Windows filenames may contain arbitrary 16-bit code units.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct NameArena {
    data: Vec<u8>,
}

impl NameArena {
    /// Creates an empty `NameArena`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty `NameArena` with the specified byte capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Creates a `NameArena` from pre-populated WTF-8 byte data.
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns the raw underlying WTF-8 byte buffer of the arena.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Appends a UTF-16 slice (converting unpaired surrogates to 3-byte WTF-8 sequences)
    /// and returns a [`NameRef`] to the stored name.
    pub fn push_utf16(&mut self, slice: &[u16]) -> NameRef {
        let off_usize = self.data.len();
        assert!(
            off_usize <= u32::MAX as usize,
            "NameArena byte length exceeded u32::MAX"
        );
        let off = off_usize as u32;

        for item in char::decode_utf16(slice.iter().copied()) {
            match item {
                Ok(c) => {
                    let mut buf = [0u8; 4];
                    let s = c.encode_utf8(&mut buf);
                    self.data.extend_from_slice(s.as_bytes());
                }
                Err(e) => {
                    let s = e.unpaired_surrogate();
                    let b0 = (0xE0 | (s >> 12)) as u8;
                    let b1 = (0x80 | ((s >> 6) & 0x3F)) as u8;
                    let b2 = (0x80 | (s & 0x3F)) as u8;
                    self.data.extend_from_slice(&[b0, b1, b2]);
                }
            }
        }

        let diff = self.data.len() - off_usize;
        let len = if diff > u16::MAX as usize {
            self.data.truncate(off_usize + u16::MAX as usize);
            u16::MAX
        } else {
            diff as u16
        };
        NameRef { off, len }
    }

    /// Appends a standard UTF-8 `&str` and returns a [`NameRef`].
    pub fn push_str(&mut self, s: &str) -> NameRef {
        self.push_wtf8(s.as_bytes())
    }

    /// Appends raw WTF-8 bytes and returns a [`NameRef`].
    pub fn push_wtf8(&mut self, b: &[u8]) -> NameRef {
        let off_usize = self.data.len();
        assert!(
            off_usize <= u32::MAX as usize,
            "NameArena byte length exceeded u32::MAX"
        );
        let off = off_usize as u32;
        let push_len = b.len().min(u16::MAX as usize);
        self.data.extend_from_slice(&b[..push_len]);
        NameRef {
            off,
            len: push_len as u16,
        }
    }

    /// Returns the raw WTF-8 byte slice corresponding to the given [`NameRef`].
    pub fn bytes(&self, r: NameRef) -> &[u8] {
        let start = r.off as usize;
        let end = start.saturating_add(r.len as usize);
        self.data.get(start..end).unwrap_or(&[])
    }

    /// Appends all bytes from `other` into `self`, returning the base offset to add to `other`'s `NameRef`s.
    pub fn append(&mut self, other: &NameArena) -> u32 {
        let base_usize = self.data.len();
        assert!(
            base_usize <= u32::MAX as usize,
            "NameArena byte length exceeded u32::MAX"
        );
        self.data.extend_from_slice(&other.data);
        base_usize as u32
    }

    /// Returns the number of bytes allocated on the heap by this arena.
    pub fn heap_bytes(&self) -> usize {
        self.data.capacity() * std::mem::size_of::<u8>()
    }

    /// Shrinks the capacity of the internal buffer as much as possible.
    pub fn shrink_to_fit(&mut self) {
        self.data.shrink_to_fit();
    }
}

/// Converts a WTF-8 byte slice to a Windows [`OsString`].
///
/// Unpaired surrogates encoded as 3-byte sequences are reconstructed into their original 16-bit code units.
pub fn wtf8_to_os_string(b: &[u8]) -> OsString {
    let mut wide = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let b0 = b[i];
        if b0 < 0x80 {
            wide.push(b0 as u16);
            i += 1;
        } else if (b0 & 0xE0) == 0xC0 {
            if i + 1 < b.len() && (b[i + 1] & 0xC0) == 0x80 {
                let b1 = b[i + 1];
                let cp = (((b0 & 0x1F) as u16) << 6) | ((b1 & 0x3F) as u16);
                wide.push(cp);
                i += 2;
            } else {
                wide.push(b0 as u16);
                i += 1;
            }
        } else if (b0 & 0xF0) == 0xE0 {
            if i + 2 < b.len() && (b[i + 1] & 0xC0) == 0x80 && (b[i + 2] & 0xC0) == 0x80 {
                let b1 = b[i + 1];
                let b2 = b[i + 2];
                let cp = (((b0 & 0x0F) as u16) << 12)
                    | (((b1 & 0x3F) as u16) << 6)
                    | ((b2 & 0x3F) as u16);
                wide.push(cp);
                i += 3;
            } else {
                wide.push(b0 as u16);
                i += 1;
            }
        } else if (b0 & 0xF8) == 0xF0 {
            if i + 3 < b.len()
                && (b[i + 1] & 0xC0) == 0x80
                && (b[i + 2] & 0xC0) == 0x80
                && (b[i + 3] & 0xC0) == 0x80
            {
                let b1 = b[i + 1];
                let b2 = b[i + 2];
                let b3 = b[i + 3];
                let cp = (((b0 & 0x07) as u32) << 18)
                    | (((b1 & 0x3F) as u32) << 12)
                    | (((b2 & 0x3F) as u32) << 6)
                    | ((b3 & 0x3F) as u32);
                if (0x10000..=0x10FFFF).contains(&cp) {
                    let cp_sub = cp - 0x10000;
                    wide.push((0xD800 + (cp_sub >> 10)) as u16);
                    wide.push((0xDC00 + (cp_sub & 0x3FF)) as u16);
                } else {
                    wide.push(0xFFFD);
                }
                i += 4;
            } else {
                wide.push(b0 as u16);
                i += 1;
            }
        } else {
            wide.push(b0 as u16);
            i += 1;
        }
    }
    OsString::from_wide(&wide)
}

/// Converts a WTF-8 byte slice to a UTF-8 string lossily.
///
/// If the slice is valid UTF-8, returns [`Cow::Borrowed`].
/// Any unpaired surrogates or invalid byte sequences are replaced with U+FFFD.
pub fn wtf8_to_string_lossy(b: &[u8]) -> Cow<'_, str> {
    if let Ok(s) = std::str::from_utf8(b) {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let b0 = b[i];
        if b0 < 0x80 {
            out.push(b0 as char);
            i += 1;
        } else if (b0 & 0xE0) == 0xC0 {
            if i + 1 < b.len() && (b[i + 1] & 0xC0) == 0x80 {
                let b1 = b[i + 1];
                let cp = (((b0 & 0x1F) as u32) << 6) | ((b1 & 0x3F) as u32);
                if let Some(c) = char::from_u32(cp) {
                    out.push(c);
                } else {
                    out.push('\u{FFFD}');
                }
                i += 2;
            } else {
                out.push('\u{FFFD}');
                i += 1;
            }
        } else if (b0 & 0xF0) == 0xE0 {
            if i + 2 < b.len() && (b[i + 1] & 0xC0) == 0x80 && (b[i + 2] & 0xC0) == 0x80 {
                let b1 = b[i + 1];
                let b2 = b[i + 2];
                let cp = (((b0 & 0x0F) as u32) << 12)
                    | (((b1 & 0x3F) as u32) << 6)
                    | ((b2 & 0x3F) as u32);
                if (0xD800..=0xDFFF).contains(&cp) {
                    out.push('\u{FFFD}');
                } else if let Some(c) = char::from_u32(cp) {
                    out.push(c);
                } else {
                    out.push('\u{FFFD}');
                }
                i += 3;
            } else {
                out.push('\u{FFFD}');
                i += 1;
            }
        } else if (b0 & 0xF8) == 0xF0 {
            if i + 3 < b.len()
                && (b[i + 1] & 0xC0) == 0x80
                && (b[i + 2] & 0xC0) == 0x80
                && (b[i + 3] & 0xC0) == 0x80
            {
                let b1 = b[i + 1];
                let b2 = b[i + 2];
                let b3 = b[i + 3];
                let cp = (((b0 & 0x07) as u32) << 18)
                    | (((b1 & 0x3F) as u32) << 12)
                    | (((b2 & 0x3F) as u32) << 6)
                    | ((b3 & 0x3F) as u32);
                if let Some(c) = char::from_u32(cp) {
                    out.push(c);
                } else {
                    out.push('\u{FFFD}');
                }
                i += 4;
            } else {
                out.push('\u{FFFD}');
                i += 1;
            }
        } else {
            out.push('\u{FFFD}');
            i += 1;
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[test]
    fn wtf8_roundtrips_unpaired_surrogate() {
        let w: Vec<u16> = vec![0x61, 0xD800, 0x62];
        let mut a = NameArena::default();
        let r = a.push_utf16(&w);
        assert_eq!(wtf8_to_os_string(a.bytes(r)), OsString::from_wide(&w));
    }

    #[test]
    fn wtf8_surrogate_pair_is_plain_utf8() {
        let w: Vec<u16> = "a😀".encode_utf16().collect();
        let mut a = NameArena::default();
        let r = a.push_utf16(&w);
        assert_eq!(std::str::from_utf8(a.bytes(r)).unwrap(), "a😀");
    }

    #[test]
    fn append_rebases() {
        let mut a = NameArena::default();
        a.push_str("x");
        let mut b = NameArena::default();
        let r = b.push_str("yz");
        let base = a.append(&b);
        assert_eq!(
            a.bytes(NameRef {
                off: r.off + base,
                len: r.len
            }),
            b"yz"
        );
    }

    #[test]
    fn wtf8_lossy_conversion() {
        // Plain UTF-8 should be borrowed
        let s = "hello world";
        let res = wtf8_to_string_lossy(s.as_bytes());
        assert!(matches!(res, Cow::Borrowed(_)));
        assert_eq!(res, "hello world");

        // Unpaired surrogate should be replaced with U+FFFD
        let w: Vec<u16> = vec![0x61, 0xD800, 0x62];
        let mut a = NameArena::default();
        let r = a.push_utf16(&w);
        let lossy = wtf8_to_string_lossy(a.bytes(r));
        assert!(matches!(lossy, Cow::Owned(_)));
        assert_eq!(lossy, "a\u{FFFD}b");
    }

    #[test]
    fn arena_capacity_and_shrink() {
        let mut a = NameArena::with_capacity(1024);
        assert!(a.heap_bytes() >= 1024);
        a.push_str("test");
        a.shrink_to_fit();
        assert!(a.heap_bytes() >= 4);
    }
}
