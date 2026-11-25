//! Pure parser and retention planner for Windows Driver Store (`pnputil.exe`) packages.

#![forbid(unsafe_code)]

use rustc_hash::{FxHashMap, FxHashSet};

/// Metadata parsed for an individual driver package from `pnputil /enum-drivers`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverPackageInfo {
    pub published_name: String,
    pub original_name: String,
    pub provider_name: String,
    pub class_name: String,
    pub driver_date: String,
    pub driver_version: String,
    pub raw_version_str: String,
}

/// Validates that an INF file name strictly conforms to the expected `oem<digits>.inf` format (§10.7).
pub fn validate_oem_inf_name(name: &str) -> bool {
    let s = name.to_ascii_lowercase();
    if !s.starts_with("oem") || !s.ends_with(".inf") {
        return false;
    }
    let num_part = &s[3..s.len() - 4];
    !num_part.is_empty() && num_part.chars().all(|c| c.is_ascii_digit())
}

/// Parses the output of `pnputil /enum-drivers` into structured driver packages.
pub fn parse_pnputil_drivers(stdout: &str) -> Vec<DriverPackageInfo> {
    let mut packages = Vec::new();

    let mut published_name = String::new();
    let mut original_name = String::new();
    let mut provider_name = String::new();
    let mut class_name = String::new();
    let mut driver_date = String::new();
    let mut driver_version = String::new();
    let mut raw_version_str = String::new();

    let flush_pkg = |packages: &mut Vec<DriverPackageInfo>,
                     pub_name: &mut String,
                     orig_name: &mut String,
                     prov_name: &mut String,
                     cls_name: &mut String,
                     date: &mut String,
                     ver: &mut String,
                     raw_ver: &mut String| {
        if !pub_name.is_empty() {
            packages.push(DriverPackageInfo {
                published_name: std::mem::take(pub_name),
                original_name: std::mem::take(orig_name),
                provider_name: std::mem::take(prov_name),
                class_name: std::mem::take(cls_name),
                driver_date: std::mem::take(date),
                driver_version: std::mem::take(ver),
                raw_version_str: std::mem::take(raw_ver),
            });
        }
    };

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((key, val)) = trimmed.split_once(':') {
            let key_norm = key.trim().to_ascii_lowercase();
            let val_clean = val.trim();

            match key_norm.as_str() {
                "published name" => {
                    flush_pkg(
                        &mut packages,
                        &mut published_name,
                        &mut original_name,
                        &mut provider_name,
                        &mut class_name,
                        &mut driver_date,
                        &mut driver_version,
                        &mut raw_version_str,
                    );
                    published_name = val_clean.to_string();
                }
                "original name" => {
                    original_name = val_clean.to_string();
                }
                "provider name" => {
                    provider_name = val_clean.to_string();
                }
                "class name" => {
                    class_name = val_clean.to_string();
                }
                "driver version" => {
                    raw_version_str = val_clean.to_string();
                    let parts: Vec<&str> = val_clean.split_whitespace().collect();
                    if parts.len() >= 2 {
                        driver_date = parts[0].to_string();
                        driver_version = parts[1].to_string();
                    } else {
                        driver_version = val_clean.to_string();
                    }
                }
                _ => {}
            }
        }
    }

    flush_pkg(
        &mut packages,
        &mut published_name,
        &mut original_name,
        &mut provider_name,
        &mut class_name,
        &mut driver_date,
        &mut driver_version,
        &mut raw_version_str,
    );

    packages
}

/// Parses the output of `pnputil /enum-devices /drivers` to identify currently bound OEM INF names.
pub fn parse_pnputil_bound_infs(stdout: &str) -> FxHashSet<String> {
    let mut bound = FxHashSet::default();

    for line in stdout.lines() {
        let trimmed = line.trim();
        let Some((key, val)) = trimmed.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("driver name") {
            let inf = val.trim().to_ascii_lowercase();
            if validate_oem_inf_name(&inf) {
                bound.insert(inf);
            }
        }
    }

    bound
}

/// Decodes the five predefined XML entities used by `pnputil /format xml`.
fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Returns the text content of the first `<tag>…</tag>` element in `block` (no attributes).
fn xml_child_text(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    Some(xml_unescape(block[start..end].trim()))
}

/// Returns the value of `attr="…"` inside an element's start tag.
fn xml_attr(start_tag: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = start_tag.find(&needle)? + needle.len();
    let end = start_tag[start..].find('"')? + start;
    Some(xml_unescape(&start_tag[start..end]))
}

/// True when `stdout` is the XML document produced by `pnputil … /format xml` (Windows 11 builds
/// that support it). Element names are not localized, unlike the text output's field labels.
pub fn is_pnputil_xml(stdout: &str) -> bool {
    stdout.contains("<PnpUtil")
}

/// Parses `pnputil /enum-drivers /format xml` into structured driver packages.
pub fn parse_pnputil_drivers_xml(xml: &str) -> Vec<DriverPackageInfo> {
    let mut packages = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<Driver ") {
        let after = &rest[pos..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let start_tag = &after[..tag_end];
        let Some(block_end) = after.find("</Driver>") else {
            break;
        };
        let block = &after[tag_end + 1..block_end];
        rest = &after[block_end + "</Driver>".len()..];

        let Some(published_name) = xml_attr(start_tag, "DriverName") else {
            continue;
        };
        let raw_version_str = xml_child_text(block, "DriverVersion").unwrap_or_default();
        let parts: Vec<&str> = raw_version_str.split_whitespace().collect();
        let (driver_date, driver_version) = if parts.len() >= 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (String::new(), raw_version_str.clone())
        };
        packages.push(DriverPackageInfo {
            published_name,
            original_name: xml_child_text(block, "OriginalName").unwrap_or_default(),
            provider_name: xml_child_text(block, "ProviderName").unwrap_or_default(),
            class_name: xml_child_text(block, "ClassName").unwrap_or_default(),
            driver_date,
            driver_version,
            raw_version_str,
        });
    }
    packages
}

/// Parses `pnputil /enum-devices /drivers /format xml` into the set of OEM INFs referenced by any
/// device: the installed `<DriverName>` *and* every `<DriverName DriverName="…">` matching driver
/// (conservative: anything a device could fall back to is treated as bound).
pub fn parse_pnputil_bound_infs_xml(xml: &str) -> FxHashSet<String> {
    let mut bound = FxHashSet::default();
    let mut rest = xml;
    while let Some(pos) = rest.find("<DriverName") {
        let after = &rest[pos + "<DriverName".len()..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let start_tag = &after[..tag_end];
        if let Some(attr) = xml_attr(start_tag, "DriverName") {
            let inf = attr.trim().to_ascii_lowercase();
            if validate_oem_inf_name(&inf) {
                bound.insert(inf);
            }
        } else if start_tag.trim().is_empty() {
            let body = &after[tag_end + 1..];
            if let Some(close) = body.find("</DriverName>") {
                let inf = xml_unescape(body[..close].trim()).to_ascii_lowercase();
                if validate_oem_inf_name(&inf) {
                    bound.insert(inf);
                }
            }
        }
        rest = &after[tag_end..];
    }
    bound
}

/// Parses driver packages from either pnputil output format.
pub fn parse_pnputil_drivers_any(stdout: &str) -> Vec<DriverPackageInfo> {
    if is_pnputil_xml(stdout) {
        parse_pnputil_drivers_xml(stdout)
    } else {
        parse_pnputil_drivers(stdout)
    }
}

/// Parses bound OEM INFs from either pnputil output format.
pub fn parse_pnputil_bound_infs_any(stdout: &str) -> FxHashSet<String> {
    if is_pnputil_xml(stdout) {
        parse_pnputil_bound_infs_xml(stdout)
    } else {
        parse_pnputil_bound_infs(stdout)
    }
}

/// pnputil's `MM/DD/YYYY` driver date as a sortable `(year, month, day)`; unparseable dates sort
/// lowest.
fn parse_driver_date(d: &str) -> (u32, u32, u32) {
    let mut it = d.split('/').map(|p| p.trim().parse::<u32>().unwrap_or(0));
    let (m, day, y) = (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    );
    (y, m, day)
}

fn parse_version_quad(v: &str) -> (u32, u32, u32, u32) {
    let mut parts = [0u32; 4];
    for (i, seg) in v.split('.').take(4).enumerate() {
        if let Ok(n) = seg.parse::<u32>() {
            parts[i] = n;
        }
    }
    (parts[0], parts[1], parts[2], parts[3])
}

/// Selects superseded driver packages that can be pruned safely.
///
/// Retention policy (§10.7):
/// 1. NEVER prune any package currently bound to an active device (`bound_infs`).
/// 2. For each driver family `(provider, class, original_name)`, always retain the newest version
///    and at least one previous version for rollback.
/// 3. Returns only older superseded unbound packages whose names match `oem<digits>.inf`.
pub fn select_prunable_drivers(
    packages: &[DriverPackageInfo],
    bound_infs: &FxHashSet<String>,
) -> Vec<DriverPackageInfo> {
    let mut groups: FxHashMap<(String, String, String), Vec<DriverPackageInfo>> =
        FxHashMap::default();

    for pkg in packages {
        // Fail closed per family: a package whose family fields did not parse (partial or
        // localized output) would otherwise be lumped into one ("", "", "") family where every
        // unrelated driver looks superseded.
        if pkg.provider_name.trim().is_empty()
            || pkg.class_name.trim().is_empty()
            || pkg.original_name.trim().is_empty()
        {
            continue;
        }
        let key = (
            pkg.provider_name.to_ascii_lowercase(),
            pkg.class_name.to_ascii_lowercase(),
            pkg.original_name.to_ascii_lowercase(),
        );
        groups.entry(key).or_default().push(pkg.clone());
    }

    let mut prunable = Vec::new();

    for (_, mut group) in groups {
        // Sort packages descending by parsed 4-part version, then by date string
        group.sort_by(|a, b| {
            let va = parse_version_quad(&a.driver_version);
            let vb = parse_version_quad(&b.driver_version);
            vb.cmp(&va).then_with(|| {
                parse_driver_date(&b.driver_date).cmp(&parse_driver_date(&a.driver_date))
            })
        });

        let mut unbound_kept = 0usize;

        for pkg in group {
            let norm_name = pkg.published_name.to_ascii_lowercase();

            // 1. Bound packages are always kept
            if bound_infs.contains(&norm_name) {
                continue;
            }

            // 2. Keep newest unbound version + 1 previous fallback version (2 total unbound retained)
            if unbound_kept < 2 {
                unbound_kept += 1;
                continue;
            }

            // 3. Candidate for pruning: validate oemNN.inf format before marking prunable
            if validate_oem_inf_name(&pkg.published_name) {
                prunable.push(pkg);
            }
        }
    }

    prunable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driverstore_rejects_non_oem_inf_names() {
        assert!(validate_oem_inf_name("oem1.inf"));
        assert!(validate_oem_inf_name("OEM42.INF"));
        assert!(validate_oem_inf_name("oem1234.inf"));

        assert!(!validate_oem_inf_name("oem.inf"));
        assert!(!validate_oem_inf_name("oem12.sys"));
        assert!(!validate_oem_inf_name("oem12.inf.bak"));
        assert!(!validate_oem_inf_name("../oem12.inf"));
        assert!(!validate_oem_inf_name("something_oem1.inf"));
    }

    #[test]
    fn driverstore_xml_parsers_match_text_semantics() {
        let drivers_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<PnpUtil Version="10.0.26300" Command="/enum-drivers /format xml">
    <Driver DriverName="oem10.inf">
        <OriginalName>nv_dispi.inf</OriginalName>
        <ProviderName>NVIDIA</ProviderName>
        <ClassName>Display</ClassName>
        <DriverVersion>01/01/2023 30.0.1.100</DriverVersion>
    </Driver>
    <Driver DriverName="oem11.inf">
        <OriginalName>nv_dispi.inf</OriginalName>
        <ProviderName>NVIDIA</ProviderName>
        <ClassName>Display</ClassName>
        <DriverVersion>06/01/2023 30.0.1.200</DriverVersion>
    </Driver>
    <Driver DriverName="oem12.inf">
        <OriginalName>nv_dispi.inf</OriginalName>
        <ProviderName>A &amp; B Corp</ProviderName>
        <ClassName>Display</ClassName>
        <DriverVersion>01/01/2024 31.0.1.300</DriverVersion>
    </Driver>
</PnpUtil>"#;
        assert!(is_pnputil_xml(drivers_xml));
        let pkgs = parse_pnputil_drivers_any(drivers_xml);
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].published_name, "oem10.inf");
        assert_eq!(pkgs[0].driver_version, "30.0.1.100");
        assert_eq!(pkgs[0].driver_date, "01/01/2023");
        assert_eq!(pkgs[2].provider_name, "A & B Corp");

        let devices_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<PnpUtil Version="10.0.26300" Command="/enum-devices /drivers /format xml">
    <Device InstanceId="PCI\VEN_10DE&amp;DEV_1">
        <DriverName>oem42.inf</DriverName>
        <MatchingDrivers>
            <DriverName DriverName="oem41.inf">
                <ProviderName>NVIDIA</ProviderName>
            </DriverName>
            <DriverName DriverName="display.inf">
                <ProviderName>Microsoft</ProviderName>
            </DriverName>
        </MatchingDrivers>
    </Device>
</PnpUtil>"#;
        let bound = parse_pnputil_bound_infs_any(devices_xml);
        assert!(bound.contains("oem42.inf"));
        assert!(bound.contains("oem41.inf"));
        assert!(!bound.contains("display.inf"));
        assert_eq!(bound.len(), 2);

        // Text output still goes through the legacy parser.
        assert!(!is_pnputil_xml("Published Name: oem1.inf"));
        assert_eq!(
            parse_pnputil_drivers_any("Published Name: oem1.inf").len(),
            1
        );
    }

    #[test]
    fn driverstore_never_prunes_packages_with_unparsed_family_fields() {
        // Partially localized output: published names parse, family labels do not.
        let packages: Vec<DriverPackageInfo> = (1..=6)
            .map(|n| DriverPackageInfo {
                published_name: format!("oem{n}.inf"),
                original_name: String::new(),
                provider_name: String::new(),
                class_name: String::new(),
                driver_date: String::new(),
                driver_version: format!("1.0.0.{n}"),
                raw_version_str: String::new(),
            })
            .collect();
        assert!(select_prunable_drivers(&packages, &FxHashSet::default()).is_empty());
    }

    #[test]
    fn driverstore_date_tiebreak_orders_by_year_not_string() {
        // Same version: "12/31/2023" > "01/15/2024" as strings, but 2024 is newer.
        let mk = |name: &str, date: &str| DriverPackageInfo {
            published_name: name.to_string(),
            original_name: "x.inf".to_string(),
            provider_name: "P".to_string(),
            class_name: "C".to_string(),
            driver_date: date.to_string(),
            driver_version: "1.0.0.0".to_string(),
            raw_version_str: String::new(),
        };
        let packages = vec![
            mk("oem1.inf", "12/01/2022"),
            mk("oem2.inf", "12/31/2023"),
            mk("oem3.inf", "01/15/2024"),
        ];
        let prunable = select_prunable_drivers(&packages, &FxHashSet::default());
        assert_eq!(prunable.len(), 1);
        assert_eq!(prunable[0].published_name, "oem1.inf");
    }

    #[test]
    fn driverstore_parser_retains_bound_and_newest_plus_one_per_family() {
        let stdout_drivers = r#"
Published Name:     oem10.inf
Original Name:      nv_dispi.inf
Provider Name:      NVIDIA
Class Name:         Display
Driver Version:     01/01/2023 30.0.1.100

Published Name:     oem11.inf
Original Name:      nv_dispi.inf
Provider Name:      NVIDIA
Class Name:         Display
Driver Version:     06/01/2023 30.0.1.200

Published Name:     oem12.inf
Original Name:      nv_dispi.inf
Provider Name:      NVIDIA
Class Name:         Display
Driver Version:     01/01/2024 31.0.1.300

Published Name:     oem13.inf
Original Name:      nv_dispi.inf
Provider Name:      NVIDIA
Class Name:         Display
Driver Version:     06/01/2024 31.0.1.400
"#;

        let packages = parse_pnputil_drivers(stdout_drivers);
        assert_eq!(packages.len(), 4);

        // Assume oem13.inf is bound to the current graphics card
        let mut bound = FxHashSet::default();
        bound.insert("oem13.inf".to_string());

        let prunable = select_prunable_drivers(&packages, &bound);

        // oem13 is bound -> kept
        // oem12 is unbound newest -> kept
        // oem11 is unbound second newest -> kept
        // oem10 is unbound third -> prunable!
        assert_eq!(prunable.len(), 1);
        assert_eq!(prunable[0].published_name, "oem10.inf");
    }
}
