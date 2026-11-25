#![forbid(unsafe_code)]

//! Local AI model store and LLM/diffusion weight detector (§9.2).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};

use crate::clean::deny::{DenyContext, is_denied_path};
use crate::index::{Index, NodeFlags, NodeId, ROOT};
use crate::time::filetime_to_min2000;

/// Known AI model storage ecosystems.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AiModelStoreKind {
    HuggingFace,
    Ollama,
    LmStudio,
    PyTorchHub,
    StableDiffusion,
    StandaloneWeights,
}

impl AiModelStoreKind {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::HuggingFace => "Hugging Face Cache",
            Self::Ollama => "Ollama Models",
            Self::LmStudio => "LM Studio Models",
            Self::PyTorchHub => "PyTorch Hub Cache",
            Self::StableDiffusion => "Stable Diffusion / ComfyUI",
            Self::StandaloneWeights => "Standalone Model Weights",
        }
    }
}

/// Discovered AI model folder or large standalone weight file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiModelCandidate {
    pub kind: AiModelStoreKind,
    pub model_name: String,
    pub path: PathBuf,
    pub allocated_bytes: u64,
    pub file_count: u64,
    pub days_since_access: u32,
}

/// Report returned by [`scan_ai_models`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiModelsReport {
    pub models: Vec<AiModelCandidate>,
    pub total_allocated_bytes: u64,
}

const STANDALONE_MODEL_EXTENSIONS: &[&str] =
    &["gguf", "safetensors", "onnx", "ckpt", "pt", "pth", "mlx"];

fn match_model_store_dir(path_lower: &str, dir_name_lower: &str) -> Option<AiModelStoreKind> {
    if (path_lower.ends_with(r"\huggingface\hub")
        || path_lower.ends_with(r"\huggingface\transformers"))
        || (dir_name_lower.starts_with("models--") && path_lower.contains(r"\huggingface\hub\"))
    {
        return Some(AiModelStoreKind::HuggingFace);
    }
    if path_lower.ends_with(r"\.ollama\models") || path_lower.ends_with(r"\ollama\models") {
        return Some(AiModelStoreKind::Ollama);
    }
    // LM Studio: legacy `~\.cache\lm-studio\models` and the current `~\.lmstudio\models`.
    if path_lower.ends_with(r"\lm-studio\models")
        || path_lower.ends_with(r"\lmstudio\models")
        || path_lower.ends_with(r"\.lmstudio\models")
    {
        return Some(AiModelStoreKind::LmStudio);
    }
    if path_lower.ends_with(r"\.cache\torch\hub") || path_lower.ends_with(r"\torch\hub") {
        return Some(AiModelStoreKind::PyTorchHub);
    }
    if path_lower.ends_with(r"\models\stable-diffusion")
        || path_lower.ends_with(r"\comfyui\models\checkpoints")
        || path_lower.ends_with(r"\comfyui\models\loras")
    {
        return Some(AiModelStoreKind::StableDiffusion);
    }
    None
}

fn measure_model_subtree(index: &Index, root: NodeId, now_mins: u32) -> (u64, u64, u32) {
    let mut stack = vec![root];
    let mut seen_fids: FxHashSet<u64> = FxHashSet::default();
    let mut alloc_bytes = 0u64;
    let mut file_count = 0u64;
    let mut newest_touch = 0u32;

    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if flags.contains(NodeFlags::DIR) {
            if node != root && flags.contains(NodeFlags::REPARSE) {
                continue;
            }
            stack.extend(index.children(node));
            continue;
        }
        if flags.contains(NodeFlags::SYSTEM) {
            continue;
        }
        file_count += 1;
        newest_touch = newest_touch
            .max(index.atime_min(node))
            .max(index.mtime_min(node));

        let fid = index.file_id(node);
        if fid != 0 && flags.contains(NodeFlags::HARDLINK) && !seen_fids.insert(fid) {
            continue;
        }
        alloc_bytes = alloc_bytes.saturating_add(index.allocated(node));
    }

    let days_since_access = if newest_touch == 0 {
        0
    } else {
        now_mins.saturating_sub(newest_touch) / 1440
    };
    (alloc_bytes, file_count, days_since_access)
}

/// Scans an [`Index`] for AI/ML framework model stores and large standalone weight files (§9.2).
pub fn scan_ai_models(index: &Index, min_bytes: u64) -> AiModelsReport {
    let deny_ctx = DenyContext::default();
    let now_ft = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| 116_444_736_000_000_000u64.saturating_add(d.as_secs().saturating_mul(10_000_000)))
        .unwrap_or(0);
    let now_mins = filetime_to_min2000(now_ft);

    let mut models = Vec::new();
    let mut stack = vec![ROOT];
    let mut covered_stores: Vec<NodeId> = Vec::new();

    while let Some(node) = stack.pop() {
        let flags = index.flags(node);
        if node != ROOT
            && flags.intersects(NodeFlags::REPARSE | NodeFlags::SYSTEM | NodeFlags::ORPHANS)
        {
            continue;
        }

        if flags.contains(NodeFlags::DIR) {
            let full_path = index.path(node);
            if node != ROOT {
                let path_lower = full_path.to_string_lossy().to_ascii_lowercase();
                let name_lower = index.name(node).to_ascii_lowercase();
                if let Some(kind) = match_model_store_dir(&path_lower, &name_lower) {
                    // For HuggingFace hub root with individual `models--org--model` children, prefer
                    // enumerating individual model folders when present so users can remove one model cleanly.
                    if kind == AiModelStoreKind::HuggingFace
                        && path_lower.ends_with(r"\huggingface\hub")
                    {
                        let model_dirs: Vec<NodeId> = index
                            .children(node)
                            .filter(|&c| {
                                index.flags(c).contains(NodeFlags::DIR)
                                    && index.name(c).to_ascii_lowercase().starts_with("models--")
                            })
                            .collect();
                        if !model_dirs.is_empty() {
                            stack.extend(model_dirs);
                            continue;
                        }
                    }

                    if is_denied_path(&full_path, &deny_ctx).is_none() {
                        let (alloc, files, days) = measure_model_subtree(index, node, now_mins);
                        if alloc >= min_bytes {
                            let model_name = index
                                .name(node)
                                .trim_start_matches("models--")
                                .replace("--", "/");
                            models.push(AiModelCandidate {
                                kind,
                                model_name,
                                path: full_path,
                                allocated_bytes: alloc,
                                file_count: files,
                                days_since_access: days,
                            });
                            covered_stores.push(node);
                        }
                    }
                    continue;
                }
            }
            stack.extend(index.children(node));
        } else {
            let name_lower = index.name(node).to_ascii_lowercase();
            let is_weight_ext = name_lower
                .rfind('.')
                .map(|dot| STANDALONE_MODEL_EXTENSIONS.contains(&&name_lower[dot + 1..]))
                .unwrap_or(false);
            if !is_weight_ext || flags.contains(NodeFlags::CLOUD) {
                continue;
            }
            let alloc = index.allocated(node);
            if alloc < min_bytes {
                continue;
            }
            let full_path = index.path(node);
            if is_denied_path(&full_path, &deny_ctx).is_some() {
                continue;
            }
            let touch = index.atime_min(node).max(index.mtime_min(node));
            let days = if touch == 0 {
                0
            } else {
                now_mins.saturating_sub(touch) / 1440
            };
            models.push(AiModelCandidate {
                kind: AiModelStoreKind::StandaloneWeights,
                model_name: index.name(node).into_owned(),
                path: full_path,
                allocated_bytes: alloc,
                file_count: 1,
                days_since_access: days,
            });
        }
    }

    let _ = covered_stores;
    models.sort_by_key(|m| std::cmp::Reverse(m.allocated_bytes));
    let total_allocated_bytes = models
        .iter()
        .map(|m| m.allocated_bytes)
        .fold(0u64, u64::saturating_add);

    AiModelsReport {
        models,
        total_allocated_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{EntryBatch, IndexBuilder, NameArena, RawEntry};
    use crate::volume::VolumeInfo;

    #[test]
    fn lm_studio_current_and_legacy_model_dirs_are_recognized() {
        for p in [
            r"c:\users\u\.lmstudio\models",
            r"c:\users\u\.cache\lm-studio\models",
        ] {
            assert_eq!(
                match_model_store_dir(p, "models"),
                Some(AiModelStoreKind::LmStudio),
                "{p}"
            );
        }
        assert_eq!(match_model_store_dir(r"c:\work\models", "models"), None);
    }

    #[test]
    fn scans_huggingface_ollama_lmstudio_and_standalone_weights() {
        let mut names = NameArena::new();
        let n_root = names.push_str("C:");
        let n_users = names.push_str("Users");
        let n_alice = names.push_str("Alice");
        let n_cache = names.push_str(".cache");
        let n_hf = names.push_str("huggingface");
        let n_hub = names.push_str("hub");
        let n_llama = names.push_str("models--meta-llama--Llama-3");
        let n_st = names.push_str("model.safetensors");
        let n_ollama = names.push_str(".ollama");
        let n_om = names.push_str("models");
        let n_blob = names.push_str("sha256-abc");
        let n_lms = names.push_str("lm-studio");
        let n_lm_m = names.push_str("models");
        let n_gguf = names.push_str("qwen.gguf");
        let n_downloads = names.push_str("Downloads");
        let n_lone = names.push_str("mistral-7b.gguf");

        let batch = EntryBatch {
            entries: vec![
                RawEntry {
                    key: 5,
                    parent_key: 5,
                    name: n_root,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 5,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 10,
                    parent_key: 5,
                    name: n_users,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 10,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 11,
                    parent_key: 10,
                    name: n_alice,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 11,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 12,
                    parent_key: 11,
                    name: n_cache,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 12,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 13,
                    parent_key: 12,
                    name: n_hf,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 13,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 14,
                    parent_key: 13,
                    name: n_hub,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 14,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 15,
                    parent_key: 14,
                    name: n_llama,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 15,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 16,
                    parent_key: 15,
                    name: n_st,
                    flags: NodeFlags::empty(),
                    logical: 4_000_000_000,
                    allocated: 4_000_000_000,
                    mtime: 0,
                    atime: 0,
                    file_id: 16,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 17,
                    parent_key: 11,
                    name: n_ollama,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 17,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 18,
                    parent_key: 17,
                    name: n_om,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 18,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 19,
                    parent_key: 18,
                    name: n_blob,
                    flags: NodeFlags::empty(),
                    logical: 2_000_000_000,
                    allocated: 2_000_000_000,
                    mtime: 0,
                    atime: 0,
                    file_id: 19,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 20,
                    parent_key: 12,
                    name: n_lms,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 20,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 21,
                    parent_key: 20,
                    name: n_lm_m,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 21,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 22,
                    parent_key: 21,
                    name: n_gguf,
                    flags: NodeFlags::empty(),
                    logical: 1_500_000_000,
                    allocated: 1_500_000_000,
                    mtime: 0,
                    atime: 0,
                    file_id: 22,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 23,
                    parent_key: 11,
                    name: n_downloads,
                    flags: NodeFlags::DIR,
                    logical: 0,
                    allocated: 0,
                    mtime: 0,
                    atime: 0,
                    file_id: 23,
                    reparse_tag: 0,
                },
                RawEntry {
                    key: 24,
                    parent_key: 23,
                    name: n_lone,
                    flags: NodeFlags::empty(),
                    logical: 500_000_000,
                    allocated: 500_000_000,
                    mtime: 0,
                    atime: 0,
                    file_id: 24,
                    reparse_tag: 0,
                },
            ],
            names,
        };

        let mut b = IndexBuilder::new(
            5,
            r"C:\",
            VolumeInfo {
                root: r"C:\".to_string(),
                ..Default::default()
            },
        );
        b.push_batch(batch);
        let index = b.finish();

        let report = scan_ai_models(&index, 100_000_000);
        assert_eq!(report.models.len(), 4);
        assert_eq!(report.total_allocated_bytes, 8_000_000_000);
        assert_eq!(report.models[0].kind, AiModelStoreKind::HuggingFace);
        assert_eq!(report.models[0].model_name, "meta-llama/Llama-3");
        assert!(
            report
                .models
                .iter()
                .any(|m| m.kind == AiModelStoreKind::Ollama)
        );
        assert!(
            report
                .models
                .iter()
                .any(|m| m.kind == AiModelStoreKind::LmStudio)
        );
        assert!(
            report
                .models
                .iter()
                .any(|m| m.kind == AiModelStoreKind::StandaloneWeights)
        );
    }
}
