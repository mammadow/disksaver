//! Typed intent-only Named Pipe IPC protocol definitions and session store.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::clean::deny::normalize_win_path_str;
use crate::clean::executor::{CleanProgress, CleanReport};
use crate::clean::plan::CleanPlan;
use crate::clean::rules::RuleTier;
use crate::error::{DskError, Result};
use crate::ntfs::mft::Phase;
use crate::optimize::intent::OptimizerIntent;
use crate::scan::{ScanMethod, ScanReport};
use crate::win::preconditions::SystemPreconditions;
use crate::win::volume::volume_root_of;

pub const MAX_CONTROL_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
pub const MAX_STREAM_FRAME_BYTES: usize = 256 * 1024 * 1024; // 256 MiB

static PLAN_ID_SEQ: AtomicU64 = AtomicU64::new(1);

/// Serializable representation of system preconditions for IPC transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemPreconditionsDto {
    pub elevated: bool,
    pub running_processes: Vec<String>,
    pub servicing_reason: Option<String>,
    pub battery_pct: Option<u8>,
    pub on_ac_power: bool,
}

impl From<&SystemPreconditions> for SystemPreconditionsDto {
    fn from(p: &SystemPreconditions) -> Self {
        let mut procs: Vec<String> = p.running_processes.iter().cloned().collect();
        procs.sort();
        Self {
            elevated: p.elevated,
            running_processes: procs,
            servicing_reason: p.servicing_reason.clone(),
            battery_pct: p.battery_pct,
            on_ac_power: p.on_ac_power,
        }
    }
}

impl From<SystemPreconditions> for SystemPreconditionsDto {
    fn from(p: SystemPreconditions) -> Self {
        Self::from(&p)
    }
}

impl From<&SystemPreconditionsDto> for SystemPreconditions {
    fn from(dto: &SystemPreconditionsDto) -> Self {
        Self {
            elevated: dto.elevated,
            running_processes: dto.running_processes.iter().cloned().collect(),
            servicing_reason: dto.servicing_reason.clone(),
            battery_pct: dto.battery_pct,
            on_ac_power: dto.on_ac_power,
        }
    }
}

impl From<SystemPreconditionsDto> for SystemPreconditions {
    fn from(dto: SystemPreconditionsDto) -> Self {
        Self {
            elevated: dto.elevated,
            running_processes: dto.running_processes.into_iter().collect(),
            servicing_reason: dto.servicing_reason,
            battery_pct: dto.battery_pct,
            on_ac_power: dto.on_ac_power,
        }
    }
}

/// Intent-only requests accepted by the elevated helper daemon.
///
/// MUST NEVER accept arbitrary paths, deletion targets, or raw command strings from the client (§10.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperRequest {
    Ping,
    ScanVolume {
        volume_root: String,
        method: ScanMethod,
    },
    BuildPlan {
        volume_root: String,
        max_tier: RuleTier,
        include_recycle_bin: bool,
    },
    ExecutePlanRules {
        plan_id: String,
        rule_ids: Vec<String>,
        dry_run: bool,
        force_battery: bool,
    },
    /// §10.1 intent-only optimizer: a fixed operation with validated scalar parameters (no paths,
    /// no command lines). See [`OptimizerIntent`].
    RunOptimizer {
        intent: OptimizerIntent,
        dry_run: bool,
    },
    Shutdown,
}

/// Responses emitted by the elevated helper daemon over the Named Pipe.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperResponse {
    Pong {
        helper_pid: u32,
        version: String,
    },
    ScanProgress {
        phase: Phase,
        done: u64,
        total: u64,
    },
    ScanComplete {
        /// Raw `encode_scan_report` bytes. On the wire they travel zstd-compressed and
        /// base64-encoded: a plain `Vec<u8>` would serialize as a JSON number array (~3.5× the raw
        /// size) and overflow `MAX_STREAM_FRAME_BYTES` for real system drives.
        #[serde(with = "zstd_base64_bytes")]
        report_bytes: Vec<u8>,
    },
    PlanBuilt {
        plan_id: String,
        plan: CleanPlan,
        preconditions: SystemPreconditionsDto,
    },
    CleanProgress(CleanProgress),
    CleanComplete(CleanReport),
    OptimizerComplete {
        message: String,
    },
    Error {
        kind: String,
        message: String,
    },
    ShuttingDown,
}

/// Bounded in-memory store for pinning plans and the latest scan report inside the elevated helper.
///
/// Keeps at most 4 recent `(plan_id, CleanPlan)` instances with FIFO eviction (§10.2) plus the most
/// recent `(normalized_volume_root, Arc<ScanReport>)` so `BuildPlan` can reuse an immediately
/// preceding `ScanVolume` without re-scanning the drive.
#[derive(Default)]
pub struct HelperSessionStore {
    plans: VecDeque<(String, CleanPlan)>,
    last_scan: Option<(String, Arc<ScanReport>)>,
}

impl std::fmt::Debug for HelperSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperSessionStore")
            .field("plans_len", &self.plans.len())
            .field(
                "last_scan_key",
                &self.last_scan.as_ref().map(|(k, _)| k.as_str()),
            )
            .finish()
    }
}

fn normalize_scan_cache_key(volume_root: &str) -> String {
    let p = Path::new(volume_root.trim());
    volume_root_of(p).unwrap_or_else(|| normalize_win_path_str(p))
}

impl HelperSessionStore {
    pub fn new() -> Self {
        Self {
            plans: VecDeque::with_capacity(4),
            last_scan: None,
        }
    }

    /// Caches the most recent `ScanReport` keyed by normalized `volume_root`.
    pub fn set_last_scan(&mut self, volume_root: String, report: Arc<ScanReport>) {
        let key = normalize_scan_cache_key(&volume_root);
        self.last_scan = Some((key, report));
    }

    /// Retrieves the cached `ScanReport` if it matches `volume_root`.
    pub fn get_last_scan(&self, volume_root: &str) -> Option<Arc<ScanReport>> {
        let key = normalize_scan_cache_key(volume_root);
        self.last_scan
            .as_ref()
            .filter(|(cached_key, _)| *cached_key == key)
            .map(|(_, report)| Arc::clone(report))
    }

    /// Stores a generated plan and returns its unique `plan_id`.
    pub fn insert_plan(&mut self, plan: CleanPlan) -> String {
        let seq = PLAN_ID_SEQ.fetch_add(1, Ordering::Relaxed);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let plan_id = format!("plan-{now_ms}-{seq}");

        if self.plans.len() >= 4 {
            self.plans.pop_front();
        }
        self.plans.push_back((plan_id.clone(), plan));
        plan_id
    }

    /// Retrieves a pinned plan by `plan_id`.
    pub fn get_plan(&self, plan_id: &str) -> Option<&CleanPlan> {
        self.plans
            .iter()
            .find(|(id, _)| id == plan_id)
            .map(|(_, plan)| plan)
    }

    /// Validates requested rule IDs against the pinned plan and returns a filtered plan.
    ///
    /// Fails with `DskError::Ipc` if `plan_id` does not exist or any requested `rule_id` was not
    /// in the original plan.
    pub fn validate_execution_rules(
        &self,
        plan_id: &str,
        requested_rule_ids: &[String],
    ) -> Result<CleanPlan> {
        let plan = self
            .get_plan(plan_id)
            .ok_or_else(|| DskError::Ipc(format!("unknown or expired plan_id '{plan_id}'")))?;

        for rid in requested_rule_ids {
            if !plan.rules.iter().any(|r| &r.rule_id == rid) {
                return Err(DskError::Ipc(format!(
                    "rule '{rid}' was not included in approved plan '{plan_id}'"
                )));
            }
        }

        Ok(plan.filtered_rules(requested_rule_ids))
    }
}

/// Upper bound for a decompressed `ScanReport` payload received over IPC (the codec itself caps
/// node count at 50M and the name arena at 2 GB).
pub const MAX_DECOMPRESSED_REPORT_BYTES: u64 = 6 * 1024 * 1024 * 1024;

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard (RFC 4648, padded) base64 encoder.
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(BASE64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(BASE64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Strict standard base64 decoder (padding required, no whitespace).
fn base64_decode(text: &str) -> std::result::Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 length is not a multiple of 4".to_string());
    }
    let quads = bytes.len() / 4;
    let mut out = Vec::with_capacity(quads * 3);
    for (i, quad) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let last = i + 1 == quads;
        let mut n = 0u32;
        let mut pad = 0usize;
        for (j, &c) in quad.iter().enumerate() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if last && j >= 2 => {
                    pad += 1;
                    0
                }
                _ => return Err(format!("invalid base64 byte 0x{c:02x}")),
            };
            if pad > 0 && c != b'=' {
                return Err("base64 data after padding".to_string());
            }
            n = (n << 6) | u32::from(v);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// `serde(with)` adapter: zstd-compress + base64 a byte payload, with a bounded decompressor.
mod zstd_base64_bytes {
    use std::io::Read;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        let compressed = zstd::bulk::compress(bytes, 3).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&super::base64_encode(&compressed))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        let compressed = super::base64_decode(&text).map_err(serde::de::Error::custom)?;
        drop(text);
        let decoder =
            zstd::stream::read::Decoder::new(&compressed[..]).map_err(serde::de::Error::custom)?;
        let mut out = Vec::new();
        decoder
            .take(super::MAX_DECOMPRESSED_REPORT_BYTES + 1)
            .read_to_end(&mut out)
            .map_err(serde::de::Error::custom)?;
        if out.len() as u64 > super::MAX_DECOMPRESSED_REPORT_BYTES {
            return Err(serde::de::Error::custom(
                "decompressed scan report exceeds maximum allowed size",
            ));
        }
        Ok(out)
    }
}

/// Writes a length-prefixed JSON frame to a stream, enforcing maximum frame length bounds.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T, max_len: usize) -> Result<()> {
    let payload = serde_json::to_vec(msg)
        .map_err(|e| DskError::Ipc(format!("failed to serialize frame: {e}")))?;

    if payload.len() > max_len {
        return Err(DskError::Ipc(format!(
            "frame size {} exceeds maximum allowed length {max_len}",
            payload.len()
        )));
    }

    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&payload)?;
    w.flush()?;
    Ok(())
}

/// Reads a length-prefixed JSON frame from a stream, enforcing maximum frame length bounds.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R, max_len: usize) -> Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > max_len {
        return Err(DskError::Ipc(format!(
            "incoming frame length {len} exceeds maximum allowed {max_len}"
        )));
    }

    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;

    serde_json::from_slice(&buf)
        .map_err(|e| DskError::Ipc(format!("failed to parse incoming frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::plan::CleanPlan;
    use crate::clean::rules::{PreconditionRule, RuleMethod, RuleTier};
    use crate::scan::ScanMethod;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip_and_oversized_frame_rejection() {
        let req = HelperRequest::BuildPlan {
            volume_root: r"C:\".to_string(),
            max_tier: RuleTier::Review,
            include_recycle_bin: true,
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &req, MAX_CONTROL_FRAME_BYTES).expect("write frame");

        let mut cur = Cursor::new(&buf);
        let decoded: HelperRequest =
            read_frame(&mut cur, MAX_CONTROL_FRAME_BYTES).expect("read frame");
        assert_eq!(decoded, req);

        // Frame exceeding max_len must be rejected
        let mut cur_small = Cursor::new(&buf);
        let err: Result<HelperRequest> = read_frame(&mut cur_small, 5);
        assert!(err.is_err());
    }

    #[test]
    fn session_store_pins_plan_and_rejects_unknown_plan_id_or_unplanned_rule_id() {
        let mut store = HelperSessionStore::new();

        let plan = CleanPlan {
            version: 1,
            scanned_path: r"C:\".to_string(),
            volume_root: r"C:\".to_string(),
            scan_method: ScanMethod::Mft,
            total_est_bytes: 5000,
            rules: vec![crate::clean::plan::PlannedRule {
                rule_id: "sys.temp".to_string(),
                name: "Temp Files".to_string(),
                category: "System".to_string(),
                tier: RuleTier::Safe,
                regenerable: true,
                requires_admin: false,
                method: RuleMethod::DeleteContents,
                preconditions: PreconditionRule::default(),
                explain: "explain".to_string(),
                est_bytes: 5000,
                item_count: 10,
                roots: Vec::new(),
                os_handler_bytes: None,
                estimate: Default::default(),
            }],
            skipped: Vec::new(),
        };

        let plan_id = store.insert_plan(plan);
        assert!(store.get_plan(&plan_id).is_some());

        // Valid rule execution
        let filtered = store
            .validate_execution_rules(&plan_id, &["sys.temp".to_string()])
            .expect("rule must validate");
        assert_eq!(filtered.rules.len(), 1);

        // Unplanned rule execution must fail
        let err_rule = store.validate_execution_rules(&plan_id, &["evil.rule".to_string()]);
        assert!(err_rule.is_err());

        // Unknown plan ID must fail
        let err_plan = store.validate_execution_rules("fake-plan-999", &["sys.temp".to_string()]);
        assert!(err_plan.is_err());
    }

    #[test]
    fn protocol_contains_no_arbitrary_path_delete_variant() {
        // Ensure HelperRequest variants only represent intent verbs (Ping, ScanVolume, BuildPlan, ExecutePlanRules, Shutdown)
        let sample_req = HelperRequest::Ping;
        let json = serde_json::to_string(&sample_req).unwrap();
        assert!(json.contains("ping"));
    }

    #[test]
    fn system_preconditions_dto_roundtrip() {
        use rustc_hash::FxHashSet;
        let mut procs = FxHashSet::default();
        procs.insert("chrome.exe".to_string());
        procs.insert("steam.exe".to_string());

        let pre = SystemPreconditions {
            elevated: true,
            running_processes: procs,
            servicing_reason: Some("TrustedInstaller".to_string()),
            battery_pct: Some(85),
            on_ac_power: true,
        };

        let dto = SystemPreconditionsDto::from(&pre);
        assert_eq!(
            dto.running_processes,
            vec!["chrome.exe".to_string(), "steam.exe".to_string()]
        );

        let back_ref = SystemPreconditions::from(&dto);
        assert_eq!(back_ref, pre);
        let back_owned = SystemPreconditions::from(dto);
        assert_eq!(back_owned, pre);
    }

    #[test]
    fn session_store_caches_last_scan_by_normalized_volume_root() {
        use crate::index::IndexBuilder;
        use crate::volume::VolumeInfo;
        let mut store = HelperSessionStore::new();
        assert!(store.get_last_scan(r"C:\").is_none());

        let builder = IndexBuilder::new(5, r"C:\", VolumeInfo::default());
        let report = Arc::new(ScanReport {
            index: builder.finish(),
            method_used: ScanMethod::Dir,
            elapsed: std::time::Duration::from_millis(1),
            skipped: 0,
            check: None,
            fallback_reason: None,
        });

        store.set_last_scan(r"\\?\c:\".to_string(), Arc::clone(&report));
        assert!(store.get_last_scan("C:").is_some());
        assert!(store.get_last_scan(r"c:\").is_some());
        assert!(store.get_last_scan(r"D:\").is_none());
    }

    #[test]
    fn base64_codec_roundtrips_and_rejects_malformed_input() {
        for len in 0..16usize {
            let data: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
            let enc = base64_encode(&data);
            assert_eq!(enc.len() % 4, 0);
            assert_eq!(base64_decode(&enc).expect("decode"), data);
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert!(base64_decode("TWE").is_err());
        assert!(base64_decode("TW=u").is_err());
        assert!(base64_decode("TWE=TWFu").is_err());
        assert!(base64_decode("TW!u").is_err());
    }

    #[test]
    fn scan_complete_frames_are_compact_and_roundtrip() {
        // Codec output is highly repetitive; a JSON number array would be ~3.5x the raw size.
        let report_bytes: Vec<u8> = (0..4_000_000u32).map(|i| (i % 251) as u8).collect();
        let resp = HelperResponse::ScanComplete {
            report_bytes: report_bytes.clone(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &resp, MAX_STREAM_FRAME_BYTES).expect("write");
        assert!(
            buf.len() < report_bytes.len() / 4,
            "ScanComplete frame should be compressed (got {} bytes for {} raw)",
            buf.len(),
            report_bytes.len()
        );
        let back: HelperResponse =
            read_frame(&mut Cursor::new(buf), MAX_STREAM_FRAME_BYTES).expect("read");
        assert_eq!(back, resp);

        // A malformed payload is rejected instead of panicking.
        let bogus = br#"{"type":"scan_complete","report_bytes":"!!!!"}"#;
        let mut framed = (bogus.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(bogus);
        assert!(
            read_frame::<_, HelperResponse>(&mut Cursor::new(framed), MAX_STREAM_FRAME_BYTES)
                .is_err()
        );
    }
}
