//! Structural PE triage: import hash, Rich header, overlay, packing traits and
//! kernel-driver identification. Everything here reads header fields and a few
//! bounded byte ranges; nothing scans the whole image.

use goblin::pe::PE;
use hexlora_core::*;
use md5::{Digest, Md5};

const SECTION_EXECUTE: u32 = 0x2000_0000;
const SECTION_WRITE: u32 = 0x8000_0000;
/// The Rich header sits between the DOS stub and the PE signature.
const MAX_RICH_SEARCH_BYTES: usize = 4096;
const MAX_RICH_RECORDS: usize = 256;
const MAX_LISTED_RICH_RECORDS: usize = 32;

/// Section names written by well-known packers and protectors.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    (".enigma1", "Enigma Protector"),
    (".enigma2", "Enigma Protector"),
    (".petite", "Petite"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    ("PEC2", "PECompact"),
    ("pec1", "PECompact"),
    (".perplex", "Perplex"),
    (".yP", "Y0da Protector"),
    (".y0da", "Y0da Protector"),
    ("pebundle", "PEBundle"),
    (".svkp", "SVK Protector"),
    (".boom", "The Boomerang List Builder"),
    (".taz", "PESpin"),
    ("BitArts", "Crunch"),
    (".neolit", "NeoLite"),
    (".packed", "RLPack"),
    (".RLPack", "RLPack"),
    (".shrink1", "Shrinker"),
    ("WWPACK", "WWPack"),
    (".ndata", "Nullsoft installer"),
];

/// Kernel components whose presence in the import table identifies the driver
/// model, most specific first.
const DRIVER_MODELS: &[(&str, &str)] = &[
    ("wdfldr.sys", "KMDF (Kernel-Mode Driver Framework)"),
    ("fltmgr.sys", "File system minifilter"),
    ("ndis.sys", "NDIS network driver"),
    ("fwpkclnt.sys", "Windows Filtering Platform callout"),
    ("storport.sys", "Storport miniport"),
    ("scsiport.sys", "SCSI miniport"),
    ("ks.sys", "Kernel streaming"),
    ("portcls.sys", "Audio port class"),
    ("usbd.sys", "USB client"),
    ("hidclass.sys", "HID minidriver"),
    ("dxgkrnl.sys", "Display miniport"),
    ("videoprt.sys", "Video miniport"),
    ("win32k.sys", "Win32k kernel-mode display driver"),
    ("netio.sys", "Kernel network I/O"),
];

pub(crate) fn enrich(pe: &PE<'_>, bytes: &[u8], a: &mut BinaryAnalysis) {
    import_hash(pe, a);
    rich_header(pe, bytes, a);
    overlay(pe, bytes, a);
    section_traits(pe, a);
    driver_identity(pe, a);
}

/// The names pefile-compatible import hashing drops from a library name.
fn imphash_library(dll: &str) -> String {
    let lower = dll.to_ascii_lowercase();
    for extension in [".dll", ".ocx", ".sys"] {
        if let Some(stem) = lower.strip_suffix(extension) {
            return stem.to_string();
        }
    }
    lower
}

fn import_hash(pe: &PE<'_>, a: &mut BinaryAnalysis) {
    if pe.imports.is_empty() {
        return;
    }
    let mut hasher = Md5::new();
    // The reference implementation resolves ordinal-only imports from these
    // libraries through a built-in name table. Without that table the hash
    // would be computed over different text, so it is reported as not
    // comparable instead of silently disagreeing with other tools.
    let mut needs_ordinal_table = false;
    for (index, import) in pe.imports.iter().enumerate() {
        let library = imphash_library(import.dll);
        let by_ordinal = import.rva == 0 && import.name.starts_with("ORDINAL ");
        let function = if by_ordinal {
            if matches!(library.as_str(), "ws2_32" | "wsock32" | "oleaut32") {
                needs_ordinal_table = true;
            }
            format!("ord{}", import.ordinal)
        } else {
            import.name.to_ascii_lowercase()
        };
        if index > 0 {
            hasher.update(b",");
        }
        hasher.update(library.as_bytes());
        hasher.update(b".");
        hasher.update(function.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    if needs_ordinal_table {
        a.metadata.insert(
            "Import hash (ordinal names unresolved)".into(),
            format!("{digest} — not comparable with imphash from other tools"),
        );
    } else {
        a.metadata.insert("Import hash (imphash)".into(), digest);
    }
}

struct RichRecord {
    product: u16,
    build: u16,
    count: u32,
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

/// Decodes the linker's undocumented Rich header: a list of the compiler and
/// linker builds that produced the objects in the image, XOR-masked with a key
/// stored right after the `Rich` marker.
fn parse_rich_header(bytes: &[u8], pe_pointer: usize) -> Option<(u32, Vec<RichRecord>, String)> {
    let limit = pe_pointer.min(bytes.len()).min(MAX_RICH_SEARCH_BYTES);
    let stub = bytes.get(..limit)?;
    let rich = stub.windows(4).rposition(|window| window == b"Rich")?;
    let key = read_u32(bytes, rich + 4)?;
    // Walk back in 4-byte steps to the masked `DanS` marker.
    let mut start = None;
    let mut cursor = rich;
    while cursor >= 4 {
        cursor -= 4;
        if read_u32(bytes, cursor)? ^ key == u32::from_le_bytes(*b"DanS") {
            start = Some(cursor);
            break;
        }
    }
    let start = start?;
    let mut clear = Vec::with_capacity(rich - start);
    let mut offset = start;
    while offset < rich {
        clear.extend_from_slice(&(read_u32(bytes, offset)? ^ key).to_le_bytes());
        offset += 4;
    }
    // `DanS` and three padding words precede the records.
    let mut records = Vec::new();
    for record in clear
        .get(16..)?
        .as_chunks::<8>()
        .0
        .iter()
        .take(MAX_RICH_RECORDS)
    {
        let id = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
        let count = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);
        records.push(RichRecord {
            product: (id >> 16) as u16,
            build: (id & 0xffff) as u16,
            count,
        });
    }
    Some((key, records, hex::encode(Md5::digest(&clear))))
}

fn rich_header(pe: &PE<'_>, bytes: &[u8], a: &mut BinaryAnalysis) {
    let pe_pointer = pe.header.dos_header.pe_pointer as usize;
    let Some((key, records, hash)) = parse_rich_header(bytes, pe_pointer) else {
        return;
    };
    a.metadata.insert(
        "Rich header".into(),
        format!("{} tool records", records.len()),
    );
    a.metadata
        .insert("Rich header key".into(), format!("0x{key:08x}"));
    a.metadata.insert("Rich header hash".into(), hash);
    for (index, record) in records.iter().take(MAX_LISTED_RICH_RECORDS).enumerate() {
        a.metadata.insert(
            format!("Rich tool {index}"),
            format!(
                "product {} · build {} · {} objects",
                record.product, record.build, record.count
            ),
        );
    }
}

fn overlay(pe: &PE<'_>, bytes: &[u8], a: &mut BinaryAnalysis) {
    let file_size = bytes.len() as u64;
    let sections_end = pe
        .sections
        .iter()
        .filter(|section| section.size_of_raw_data > 0)
        .map(|section| section.pointer_to_raw_data as u64 + section.size_of_raw_data as u64)
        .max()
        .unwrap_or(0)
        .max(
            pe.header
                .optional_header
                .map(|optional| optional.windows_fields.size_of_headers as u64)
                .unwrap_or(0),
        );
    if sections_end == 0 || sections_end >= file_size {
        return;
    }
    // The Authenticode certificate table is appended after the sections by
    // design; only bytes outside it count as overlay.
    let certificates = pe
        .header
        .optional_header
        .and_then(|optional| optional.data_directories.get_certificate_table().copied())
        .map(|directory| {
            let start = directory.virtual_address as u64;
            (start, start.saturating_add(directory.size as u64))
        })
        .filter(|(start, end)| *start >= sections_end && *end <= file_size && start < end);
    let (overlay_offset, overlay_size) = match certificates {
        Some((start, end)) => {
            let before = start - sections_end;
            let after = file_size - end;
            // Padding up to the 8-byte certificate alignment is not an overlay.
            if before > 8 {
                (sections_end, before + after)
            } else if after > 0 {
                (end, after)
            } else {
                return;
            }
        }
        None => (sections_end, file_size - sections_end),
    };
    if overlay_size == 0 {
        return;
    }
    a.metadata
        .insert("Overlay offset".into(), format!("0x{overlay_offset:x}"));
    a.metadata
        .insert("Overlay size".into(), overlay_size.to_string());
    let share = overlay_size as f64 / file_size as f64;
    a.findings.push(
        Finding::new(
            Severity::Info,
            FindingCategory::Packing,
            "Data appended after the PE image",
            "Bytes follow the last section and are not part of the mapped image. Installers and self-extracting archives store payloads this way; so do some droppers.",
        )
        .with_rule("pe.overlay")
        .with_confidence(Confidence::High)
        .with_evidence_at(
            "Overlay",
            format!("{overlay_size} bytes ({:.1}% of the file)", share * 100.0),
            overlay_offset,
        ),
    );
}

fn section_name(section: &goblin::pe::section_table::SectionTable) -> String {
    section.name().unwrap_or("<invalid>").to_string()
}

fn section_traits(pe: &PE<'_>, a: &mut BinaryAnalysis) {
    let mut packers: Vec<(&str, String)> = Vec::new();
    for section in &pe.sections {
        let name = section_name(section);
        if let Some((_, packer)) = PACKER_SECTIONS
            .iter()
            .find(|(marker, _)| name.eq_ignore_ascii_case(marker))
            && !packers.iter().any(|(known, _)| known == packer)
        {
            packers.push((packer, name.clone()));
        }
        if section.characteristics & SECTION_EXECUTE != 0
            && section.size_of_raw_data == 0
            && section.virtual_size > 0
        {
            a.findings.push(
                Finding::new(
                    Severity::Low,
                    FindingCategory::Packing,
                    format!("Executable section with no file data: {name}"),
                    "The section is executable and occupies memory but stores nothing in the file, so its code must be written at run time. Unpacking stubs use this layout.",
                )
                .with_rule("pe.empty-executable-section")
                .with_confidence(Confidence::Medium)
                .with_evidence_at(
                    "Virtual size",
                    format!("{} bytes", section.virtual_size),
                    section.pointer_to_raw_data as u64,
                ),
            );
        }
    }
    if !packers.is_empty() {
        let names: Vec<&str> = packers.iter().map(|(packer, _)| *packer).collect();
        a.metadata
            .insert("Packer section markers".into(), names.join(", "));
        let mut finding = Finding::new(
            Severity::Low,
            FindingCategory::Packing,
            format!("Packer section names: {}", names.join(", ")),
            "Section names match a known packer or protector. Names are trivially renamed, so this is a lead rather than an identification.",
        )
        .with_rule("pe.packer-section-names")
        .with_confidence(Confidence::Medium);
        for (packer, section) in &packers {
            finding = finding.with_evidence(*packer, section.clone());
        }
        a.findings.push(finding);
    }

    let entry = pe.entry;
    if entry != 0 && !pe.sections.is_empty() {
        let containing = pe.sections.iter().enumerate().find(|(_, section)| {
            let size = section.virtual_size.max(section.size_of_raw_data);
            entry >= section.virtual_address
                && (entry as u64) < section.virtual_address as u64 + size as u64
        });
        match containing {
            None => a.findings.push(
                Finding::new(
                    Severity::Medium,
                    FindingCategory::Packing,
                    "Entry point outside every section",
                    "The entry point does not fall inside any section. Loaders tolerate this only in unusual, hand-built images.",
                )
                .with_rule("pe.entry-outside-sections")
                .with_confidence(Confidence::High)
                .with_evidence("Entry point RVA", format!("0x{entry:x}")),
            ),
            Some((index, section)) => {
                let name = section_name(section);
                if section.characteristics & SECTION_EXECUTE == 0 {
                    a.findings.push(
                        Finding::new(
                            Severity::Medium,
                            FindingCategory::Packing,
                            format!("Entry point in non-executable section: {name}"),
                            "The entry point lies in a section that is not marked executable.",
                        )
                        .with_rule("pe.entry-not-executable")
                        .with_confidence(Confidence::High)
                        .with_evidence("Entry point RVA", format!("0x{entry:x}")),
                    );
                } else if section.characteristics & SECTION_WRITE != 0 {
                    a.findings.push(
                        Finding::new(
                            Severity::Low,
                            FindingCategory::Packing,
                            format!("Entry point in writable section: {name}"),
                            "Execution starts in a section that is also writable, which is how self-modifying unpacking stubs are laid out.",
                        )
                        .with_rule("pe.entry-in-writable-section")
                        .with_confidence(Confidence::Medium)
                        .with_evidence("Entry point RVA", format!("0x{entry:x}")),
                    );
                } else if index > 0 && index + 1 == pe.sections.len() && pe.sections.len() > 2 {
                    a.findings.push(
                        Finding::new(
                            Severity::Info,
                            FindingCategory::Packing,
                            format!("Entry point in the last section: {name}"),
                            "Compilers place the entry point in the first code section. An entry point in the last section often means code was appended after linking.",
                        )
                        .with_rule("pe.entry-in-last-section")
                        .with_confidence(Confidence::Low)
                        .with_evidence("Entry point RVA", format!("0x{entry:x}")),
                    );
                }
            }
        }
    }

    // A native image with a handful of imports that are all loader helpers
    // resolves its real imports at run time.
    let resolver_only = !pe.imports.is_empty()
        && pe.imports.len() <= 6
        && pe.imports.iter().any(|import| {
            matches!(
                import.name.as_ref(),
                "GetProcAddress" | "LdrGetProcedureAddress"
            )
        })
        && pe.imports.iter().any(|import| {
            matches!(
                import.name.as_ref(),
                "LoadLibraryA"
                    | "LoadLibraryW"
                    | "LoadLibraryExA"
                    | "LoadLibraryExW"
                    | "LdrLoadDll"
            )
        });
    if resolver_only && pe.clr_data.is_none() {
        a.findings.push(
            Finding::new(
                Severity::Low,
                FindingCategory::Packing,
                "Import table contains only loader helpers",
                "The image imports little beyond LoadLibrary and GetProcAddress, so the functions it really uses are resolved at run time and are not visible statically.",
            )
            .with_rule("pe.resolver-only-imports")
            .with_confidence(Confidence::Medium)
            .with_evidence("Imported functions", pe.imports.len().to_string()),
        );
    }
}

fn driver_identity(pe: &PE<'_>, a: &mut BinaryAnalysis) {
    let native_subsystem = pe
        .header
        .optional_header
        .is_some_and(|optional| optional.windows_fields.subsystem == 1);
    let libraries: Vec<String> = pe
        .libraries
        .iter()
        .map(|library| library.to_ascii_lowercase())
        .collect();
    let imports_kernel = libraries.iter().any(|library| {
        matches!(
            library.as_str(),
            "ntoskrnl.exe" | "hal.dll" | "wdfldr.sys" | "ndis.sys" | "fltmgr.sys"
        )
    });
    if !imports_kernel {
        return;
    }
    a.metadata.insert("Kernel driver".into(), "Yes".into());
    let model = DRIVER_MODELS
        .iter()
        .find(|(library, _)| libraries.iter().any(|imported| imported == library))
        .map(|(_, model)| *model)
        .unwrap_or("WDM (Windows Driver Model)");
    a.metadata.insert("Driver model".into(), model.into());
    if !native_subsystem {
        a.metadata.insert(
            "Driver subsystem".into(),
            "Not marked native despite kernel imports".into(),
        );
    }
    let kernel_imports = pe
        .imports
        .iter()
        .filter(|import| {
            matches!(
                import.dll.to_ascii_lowercase().as_str(),
                "ntoskrnl.exe" | "hal.dll"
            )
        })
        .count();
    a.metadata
        .insert("Kernel imports".into(), kernel_imports.to_string());
    let creates_device = pe.imports.iter().any(|import| {
        matches!(
            import.name.as_ref(),
            "IoCreateDevice" | "IoCreateDeviceSecure" | "WdmlibIoCreateDeviceSecure"
        )
    });
    let links_device = pe.imports.iter().any(|import| {
        matches!(
            import.name.as_ref(),
            "IoCreateSymbolicLink" | "IoCreateUnprotectedSymbolicLink"
        )
    });
    a.metadata.insert(
        "Driver device interface".into(),
        match (creates_device, links_device) {
            (true, true) => "Creates a device and a user-visible symbolic link",
            (true, false) => "Creates a device without a symbolic link",
            (false, _) if model.starts_with("KMDF") => "Managed by the framework",
            (false, _) => "No device creation import",
        }
        .into(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imphash_library_drops_only_loadable_extensions() {
        assert_eq!(imphash_library("KERNEL32.dll"), "kernel32");
        assert_eq!(imphash_library("ntoskrnl.exe"), "ntoskrnl.exe");
        assert_eq!(imphash_library("FLTMGR.SYS"), "fltmgr");
        assert_eq!(imphash_library("comctl32.OCX"), "comctl32");
    }

    #[test]
    fn rich_header_decodes_masked_records_and_rejects_noise() {
        let key = 0x1234_5678u32;
        let mut image = vec![0u8; 0x80];
        image[..2].copy_from_slice(b"MZ");
        let clear: [u32; 6] = [
            u32::from_le_bytes(*b"DanS"),
            0,
            0,
            0,
            (0x0104 << 16) | 0x7809,
            12,
        ];
        for word in clear {
            image.extend_from_slice(&(word ^ key).to_le_bytes());
        }
        image.extend_from_slice(b"Rich");
        image.extend_from_slice(&key.to_le_bytes());
        image.resize(0x100, 0);
        let (decoded_key, records, hash) =
            parse_rich_header(&image, 0x100).expect("rich header decodes");
        assert_eq!(decoded_key, key);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].product, 0x0104);
        assert_eq!(records[0].build, 0x7809);
        assert_eq!(records[0].count, 12);
        assert_eq!(hash.len(), 32);

        assert!(parse_rich_header(&[0u8; 0x200], 0x100).is_none());
        // A marker with no matching `DanS` must not loop or panic.
        let mut orphan = vec![0xffu8; 0x100];
        orphan[0x90..0x94].copy_from_slice(b"Rich");
        assert!(parse_rich_header(&orphan, 0x100).is_none());
        assert!(parse_rich_header(b"Rich", 4).is_none());
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/binaries")
                .join(name),
        )
        .expect("read PE fixture")
    }

    fn rules(analysis: &BinaryAnalysis) -> Vec<&str> {
        analysis
            .findings
            .iter()
            .filter_map(|finding| finding.rule_id.as_deref())
            .collect()
    }

    #[test]
    fn clean_executable_gets_an_import_hash_and_no_packing_findings() {
        let analysis = crate::analyze_binary(&fixture("fixture-x64.exe")).expect("analyze PE");
        // md5 of "kernel32.createremotethread,kernel32.exitprocess,
        // kernel32.getstdhandle,kernel32.openprocess,kernel32.virtualallocex,
        // kernel32.writefile,kernel32.writeprocessmemory", the text the
        // reference imphash algorithm hashes for this import table.
        assert_eq!(
            analysis
                .metadata
                .get("Import hash (imphash)")
                .map(String::as_str),
            Some("445e41ce919b3b7add0a68ebcd2b653c")
        );
        assert!(analysis.metadata.contains_key("PDB GUID"));
        assert!(!analysis.metadata.contains_key("Kernel driver"));
        assert!(!analysis.metadata.contains_key("Overlay size"));
        assert!(rules(&analysis).is_empty(), "{:?}", analysis.findings);
    }

    #[test]
    fn driver_is_identified_from_its_kernel_imports() {
        let analysis =
            crate::analyze_binary(&fixture("fixture-driver.sys")).expect("analyze driver");
        let metadata = |key: &str| analysis.metadata.get(key).map(String::as_str);
        assert_eq!(metadata("Kernel driver"), Some("Yes"));
        assert_eq!(metadata("Driver model"), Some("WDM (Windows Driver Model)"));
        assert_eq!(metadata("Kernel imports"), Some("4"));
        assert_eq!(
            metadata("Driver device interface"),
            Some("Creates a device and a user-visible symbolic link")
        );
        assert!(!analysis.metadata.contains_key("Driver subsystem"));
    }

    #[test]
    fn appended_data_is_reported_as_an_overlay() {
        let mut image = fixture("fixture-x64.exe");
        let original = image.len();
        image.extend_from_slice(&[0x41; 4096]);
        let analysis = crate::analyze_binary(&image).expect("analyze PE with overlay");
        assert_eq!(
            analysis.metadata.get("Overlay offset").map(String::as_str),
            Some(format!("0x{original:x}").as_str())
        );
        assert_eq!(
            analysis.metadata.get("Overlay size").map(String::as_str),
            Some("4096")
        );
        let finding = analysis
            .findings
            .iter()
            .find(|finding| finding.rule_id.as_deref() == Some("pe.overlay"))
            .expect("overlay finding");
        assert_eq!(finding.category, FindingCategory::Packing);
        assert_eq!(finding.evidence[0].offset, Some(original as u64));
    }

    /// Rewrites one field of the section header named `section`.
    fn patch_section(image: &mut [u8], section: &[u8], field: usize, value: &[u8]) {
        let mut name = [0u8; 8];
        name[..section.len()].copy_from_slice(section);
        let header = image
            .windows(8)
            .position(|window| window == name)
            .expect("section header");
        image[header + field..header + field + value.len()].copy_from_slice(value);
    }

    #[test]
    fn packer_traits_are_recognized_in_a_modified_image() {
        // Rename `.text` to a UPX section name.
        let mut renamed = fixture("fixture-x64.exe");
        patch_section(&mut renamed, b".text", 0, b"UPX0\0\0\0\0");
        let analysis = crate::analyze_binary(&renamed).expect("analyze renamed PE");
        assert!(rules(&analysis).contains(&"pe.packer-section-names"));
        assert_eq!(
            analysis
                .metadata
                .get("Packer section markers")
                .map(String::as_str),
            Some("UPX")
        );

        // Make the code section writable: execution starts in writable memory.
        let mut writable = fixture("fixture-x64.exe");
        patch_section(&mut writable, b".text", 36, &0xe000_0020u32.to_le_bytes());
        let analysis = crate::analyze_binary(&writable).expect("analyze writable PE");
        assert!(rules(&analysis).contains(&"pe.entry-in-writable-section"));

        // Clear the execute bit: the entry point is in data.
        let mut data = fixture("fixture-x64.exe");
        patch_section(&mut data, b".text", 36, &0x4000_0040u32.to_le_bytes());
        let analysis = crate::analyze_binary(&data).expect("analyze non-executable PE");
        assert!(rules(&analysis).contains(&"pe.entry-not-executable"));

        // Drop the code section's file data while keeping it in memory.
        let mut empty = fixture("fixture-x64.exe");
        patch_section(&mut empty, b".text", 16, &0u32.to_le_bytes());
        let analysis = crate::analyze_binary(&empty).expect("analyze hollow PE");
        assert!(rules(&analysis).contains(&"pe.empty-executable-section"));
    }
}
