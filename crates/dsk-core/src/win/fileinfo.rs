//! Version-resource reader (P9.7): `ProductName` / `FileDescription` / `ProductVersion` of an
//! executable. `GetFileVersionInfoW` maps the file as data; no code from it runs.

#![allow(unsafe_code)]

use std::path::Path;

use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::core::PCWSTR;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Product strings from an executable's version resource.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProductInfo {
    pub product_name: Option<String>,
    pub file_description: Option<String>,
    pub product_version: Option<String>,
    pub company: Option<String>,
}

fn query_string(block: &[u8], lang_cp: &str, key: &str) -> Option<String> {
    let sub = to_wide(&format!(r"\StringFileInfo\{lang_cp}\{key}"));
    let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `block` holds the whole version resource returned by GetFileVersionInfoW; the
    // returned pointer points inside it and `len` counts UTF-16 units.
    let ok = unsafe {
        VerQueryValueW(
            block.as_ptr() as *const core::ffi::c_void,
            PCWSTR(sub.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };
    if !ok.as_bool() || ptr.is_null() || len == 0 {
        return None;
    }
    let start = ptr as usize;
    let base = block.as_ptr() as usize;
    let units = len as usize;
    if start < base || start + units * 2 > base + block.len() {
        return None;
    }
    let off = start - base;
    let words: Vec<u16> = block[off..off + units * 2]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&w| w != 0)
        .collect();
    let s = String::from_utf16_lossy(&words).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Reads product strings. `None` when the file has no version resource.
pub fn product_info(path: &Path) -> Option<ProductInfo> {
    let wide = to_wide(&path.to_string_lossy());
    // SAFETY: `wide` is NUL-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if size == 0 || size > 4 * 1024 * 1024 {
        return None;
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is `size` bytes long, as GetFileVersionInfoSizeW requested.
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(wide.as_ptr()),
            None,
            size,
            block.as_mut_ptr() as *mut core::ffi::c_void,
        )
    }
    .ok()?;

    // First translation, then the common English/Unicode fallbacks.
    let mut candidates: Vec<String> = Vec::new();
    let trans = to_wide(r"\VarFileInfo\Translation");
    let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: Query into the owned block; the result is bounds-checked below.
    let ok = unsafe {
        VerQueryValueW(
            block.as_ptr() as *const core::ffi::c_void,
            PCWSTR(trans.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };
    let base = block.as_ptr() as usize;
    if ok.as_bool() && !ptr.is_null() && len >= 4 {
        let off = (ptr as usize).wrapping_sub(base);
        if let Some(b) = block.get(off..off + 4) {
            let lang = u16::from_le_bytes([b[0], b[1]]);
            let cp = u16::from_le_bytes([b[2], b[3]]);
            candidates.push(format!("{lang:04x}{cp:04x}"));
        }
    }
    candidates.extend([
        "040904b0".to_string(),
        "040904e4".to_string(),
        "000004b0".to_string(),
    ]);

    for lc in &candidates {
        let info = ProductInfo {
            product_name: query_string(&block, lc, "ProductName"),
            file_description: query_string(&block, lc, "FileDescription"),
            product_version: query_string(&block, lc, "ProductVersion"),
            company: query_string(&block, lc, "CompanyName"),
        };
        if info.product_name.is_some() || info.file_description.is_some() {
            return Some(info);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_notepad_and_rejects_non_pe() {
        let notepad = crate::win::volume::system32_dir().join("notepad.exe");
        let info = product_info(&notepad).expect("notepad has a version resource");
        assert!(
            info.product_name
                .as_deref()
                .unwrap_or_default()
                .contains("Windows")
                || info.file_description.is_some()
        );
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("setup.exe");
        std::fs::write(&fake, b"MZ not really").unwrap();
        assert_eq!(product_info(&fake), None);
    }
}
