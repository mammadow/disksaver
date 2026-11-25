use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{FSCTL_SET_COMPRESSION, FSCTL_SET_SPARSE};

/// Deterministic SplitMix64 PRNG.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

/// Sets the sparse flag on an open file handle using `FSCTL_SET_SPARSE`.
pub fn set_sparse(file: &File) -> Result<(), Box<dyn std::error::Error>> {
    let handle = HANDLE(file.as_raw_handle());
    let mut bytes_returned = 0u32;
    unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_SPARSE,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )?;
    }
    Ok(())
}

/// Sets LZNT1 compression on an open file handle using `FSCTL_SET_COMPRESSION`.
pub fn set_compressed(file: &File) -> Result<(), Box<dyn std::error::Error>> {
    let handle = HANDLE(file.as_raw_handle());
    let mut format: u16 = 1; // COMPRESSION_FORMAT_DEFAULT / LZNT1
    let mut bytes_returned = 0u32;
    unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_COMPRESSION,
            Some(&mut format as *mut u16 as *const c_void),
            std::mem::size_of::<u16>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )?;
    }
    Ok(())
}

/// Creates a directory junction (`mklink /J`) pointing `link` to `target`.
pub fn make_junction(link: &Path, target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()?;
    if !status.success() {
        return Err(format!("mklink /J failed with exit code {:?}", status.code()).into());
    }
    Ok(())
}

/// Compresses a file using LZX algorithm via `compact.exe /c /exe:lzx`.
pub fn compact_lzx(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("compact.exe")
        .args(["/c", "/exe:lzx"])
        .arg(path)
        .status()?;
    if !status.success() {
        eprintln!(
            "Warning: compact.exe /c /exe:lzx returned exit code {:?}",
            status.code()
        );
    }
    Ok(())
}

/// Populates the test fixture according to the specification.
pub fn populate_fixture(root: &Path, many_count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = SplitMix64::new(42);

    // 1. plain\f0000..f0999 (1–64 KiB each)
    let plain_dir = root.join("plain");
    std::fs::create_dir_all(&plain_dir)?;
    for i in 0..1000 {
        let size = 1024 + (rng.next_u64() % (65536 - 1024 + 1)) as usize;
        let file_path = plain_dir.join(format!("f{:04}", i));
        let mut buf = vec![0u8; size];
        for chunk in buf.chunks_mut(8) {
            let val = rng.next_u64().to_le_bytes();
            let to_copy = chunk.len().min(8);
            chunk.copy_from_slice(&val[..to_copy]);
        }
        std::fs::write(&file_path, &buf)?;
    }

    // 2. many\e00000..e{many_count - 1} (empty files)
    let many_dir = root.join("many");
    std::fs::create_dir_all(&many_dir)?;
    for i in 0..many_count {
        let file_path = many_dir.join(format!("e{:05}", i));
        File::create(&file_path)?;
    }

    // 3. links\target.bin (1 MiB) + links\l000..l199 (200 hard links)
    let links_dir = root.join("links");
    std::fs::create_dir_all(&links_dir)?;
    let target_path = links_dir.join("target.bin");
    {
        let mut f = File::create(&target_path)?;
        let chunk = vec![0xAAu8; 64 * 1024];
        for _ in 0..16 {
            f.write_all(&chunk)?;
        }
    }
    for i in 0..200 {
        let link_path = links_dir.join(format!("l{:03}", i));
        std::fs::hard_link(&target_path, &link_path)?;
    }

    // 4. ads\host.txt (10 B) + ads\host.txt:big (2 MiB)
    let ads_dir = root.join("ads");
    std::fs::create_dir_all(&ads_dir)?;
    let host_path = ads_dir.join("host.txt");
    std::fs::write(&host_path, b"0123456789")?;
    let stream_path = format!("{}:big", host_path.display());
    {
        let mut sf = File::create(&stream_path)?;
        let chunk = vec![0xBBu8; 64 * 1024];
        for _ in 0..32 {
            sf.write_all(&chunk)?;
        }
    }

    // 5. sparse\s.bin (1 GiB logical, nothing written)
    let sparse_dir = root.join("sparse");
    std::fs::create_dir_all(&sparse_dir)?;
    let sparse_path = sparse_dir.join("s.bin");
    {
        let sf = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&sparse_path)?;
        set_sparse(&sf)?;
        sf.set_len(1 << 30)?; // 1 GiB
    }

    // 6. lznt1\z.bin (8 MiB zeros, FSCTL_SET_COMPRESSION)
    let lznt1_dir = root.join("lznt1");
    std::fs::create_dir_all(&lznt1_dir)?;
    let lznt1_path = lznt1_dir.join("z.bin");
    {
        let mut zf = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lznt1_path)?;
        set_compressed(&zf)?;
        let zeros = vec![0u8; 64 * 1024];
        for _ in 0..128 {
            zf.write_all(&zeros)?;
        }
        zf.sync_all()?;
    }

    // 7. wof\data.txt (8 MiB repetitive text, compact.exe /c /exe:lzx)
    let wof_dir = root.join("wof");
    std::fs::create_dir_all(&wof_dir)?;
    let wof_path = wof_dir.join("data.txt");
    {
        let mut wf = File::create(&wof_path)?;
        let text_block =
            b"The quick brown fox jumps over the lazy dog. Repetitive line for WOF compression.\n";
        let mut written = 0usize;
        let target_size = 8 * 1024 * 1024;
        while written < target_size {
            let to_write = (target_size - written).min(text_block.len());
            wf.write_all(&text_block[..to_write])?;
            written += to_write;
        }
    }
    compact_lzx(&wof_path)?;

    // 8. junction -> plain (mklink /J)
    let junction_path = root.join("junction");
    if !junction_path.exists() {
        make_junction(&junction_path, &plain_dir)?;
    }

    // 9. deep\... (> 400 characters using \\?\ long-path prefixing)
    let deep_dir = root.join("deep");
    std::fs::create_dir_all(&deep_dir)?;
    let abs_deep = std::path::absolute(&deep_dir)?;
    let os_wide: Vec<u16> = abs_deep.as_os_str().encode_wide().collect();
    let prefix_long = [0x005Cu16, 0x005C, 0x003F, 0x005C]; // \\?\
    let long_deep = if os_wide.starts_with(&prefix_long) {
        abs_deep
    } else {
        let mut p = OsString::from(r"\\?\");
        p.push(abs_deep.as_os_str());
        PathBuf::from(p)
    };
    let mut curr_deep = long_deep;
    for i in 0..10 {
        curr_deep = curr_deep.join(format!(
            "long_nested_component_{:02}_abcdefghijklmnopqrstuvwxyz",
            i
        ));
        std::fs::create_dir_all(&curr_deep)?;
    }
    let deep_file = curr_deep.join("deep_file.txt");
    std::fs::write(&deep_file, b"deep nested file content")?;

    // 10. names\ file [0x61, 0xD800, 0x62] (unpaired surrogate)
    let names_dir = root.join("names");
    std::fs::create_dir_all(&names_dir)?;
    let surrogate_name = OsString::from_wide(&[0x0061, 0xD800, 0x0062]);
    let surrogate_file = names_dir.join(surrogate_name);
    std::fs::write(&surrogate_file, b"unpaired surrogate content")?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dsk-fixture <root-path> [many-count]");
        std::process::exit(1);
    }
    let root = Path::new(&args[1]);
    let many_count = if args.len() >= 3 {
        args[2].parse::<usize>()?
    } else {
        50_000
    };
    println!(
        "Populating fixture at {} (many_count = {})...",
        root.display(),
        many_count
    );
    populate_fixture(root, many_count)?;
    println!("Fixture populated successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsk_core::index::{NodeFlags, ROOT};
    use dsk_core::scan::{ScanMethod, ScanOptions, scan_volume};
    use std::sync::atomic::AtomicBool;
    use tempfile::TempDir;

    #[test]
    fn small_fixture_manifest_and_dir_scan() {
        // Create tempdir on C: (NTFS) for junction and ADS support
        let local_temp =
            std::env::var_os("LOCALAPPDATA").map(|p| std::path::PathBuf::from(p).join("Temp"));
        let tmp = local_temp
            .as_deref()
            .and_then(|p| TempDir::new_in(p).ok())
            .or_else(|| TempDir::new_in(std::env::temp_dir()).ok())
            .unwrap_or_else(|| TempDir::new().unwrap());
        let root = tmp.path();

        // Populate with small many_count (10 files) so test runs in milliseconds
        populate_fixture(root, 10).expect("populate_fixture should succeed");

        // Verify key files exist on disk
        assert!(root.join("plain").join("f0000").exists());
        assert!(root.join("many").join("e00009").exists());
        assert!(root.join("links").join("target.bin").exists());
        assert!(root.join("links").join("l000").exists());
        assert!(root.join("ads").join("host.txt").exists());
        assert!(root.join("sparse").join("s.bin").exists());
        assert!(root.join("lznt1").join("z.bin").exists());
        assert!(root.join("wof").join("data.txt").exists());
        assert!(root.join("junction").exists());

        // Scan via dsk-core Directory scanner
        let rep = scan_volume(
            root,
            &ScanOptions {
                method: ScanMethod::Dir,
                threads: Some(2),
                use_cache: false,
            },
            &|_| {},
            &AtomicBool::new(false),
        )
        .expect("scan_volume in Dir mode should succeed");

        let ix = &rep.index;
        assert_eq!(rep.method_used, ScanMethod::Dir);
        assert!(ix.file_count(ROOT) >= 1000 + 10 + 201);

        // Verify junction is flagged as REPARSE
        let j_node = ix
            .children(ROOT)
            .find(|&c| ix.name(c) == "junction")
            .expect("junction node should exist in index");
        assert!(ix.flags(j_node).contains(NodeFlags::REPARSE));

        // Verify hard links deduplication in links folder
        let links_node = ix
            .children(ROOT)
            .find(|&c| ix.name(c) == "links")
            .expect("links node should exist in index");
        let non_dup = ix
            .children(links_node)
            .filter(|&c| !ix.flags(c).contains(NodeFlags::DIR))
            .filter(|&c| !ix.flags(c).contains(NodeFlags::DUP_LINK))
            .count();
        assert_eq!(non_dup, 1);
    }
}
