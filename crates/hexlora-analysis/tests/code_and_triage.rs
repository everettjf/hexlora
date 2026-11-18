//! Triage, pattern rules, and code listings through the analysis layer, using
//! the checked-in binary fixtures.

use hexlora_analysis::{
    CancellationToken, CodeView, Limits, analyze_node, apply_capability_strings, enrich_triage,
    open_artifact, scan_capability_strings,
};
use hexlora_core::{ArtifactNode, Confidence, FindingCategory, HexloraError};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/binaries")
}

fn open(name: &str) -> ArtifactNode {
    open_artifact(&fixtures().join(name), &CancellationToken::default()).expect("open fixture")
}

#[test]
fn triage_adds_capabilities_without_touching_plain_analysis() {
    let node = open("fixture-x64.exe");
    let mut analysis = analyze_node(&node).expect("analyze").expect("binary");
    // Discovery-time analysis stays cheap: no capabilities until asked.
    assert!(analysis.capabilities.is_empty());
    enrich_triage(&mut analysis);
    let ids: Vec<&str> = analysis
        .capabilities
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(ids, ["injection.remote-thread"]);
    let finding = analysis
        .findings
        .iter()
        .find(|finding| finding.category == FindingCategory::Capability)
        .expect("capability finding");
    assert_eq!(
        finding.rule_id.as_deref(),
        Some("capability.injection.remote-thread")
    );
    assert_eq!(finding.confidence, Some(Confidence::High));
    assert_eq!(finding.evidence.len(), 4);
}

#[test]
fn string_scan_feeds_capability_rules_and_can_be_cancelled() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut image = std::fs::read(fixtures().join("fixture-driver.sys")).expect("read driver");
    // The marker straddles the reader's 1 MiB chunk boundary.
    image.resize(1024 * 1024 - 10, 0);
    image.extend(
        "\\Device\\PhysicalMemory"
            .bytes()
            .flat_map(|byte| [byte, 0]),
    );
    let path = directory.path().join("driver.sys");
    std::fs::write(&path, &image).expect("write driver copy");
    let node = open_artifact(&path, &CancellationToken::default()).expect("open driver copy");
    let mut analysis = analyze_node(&node).expect("analyze").expect("binary");
    enrich_triage(&mut analysis);
    let mapping = |analysis: &hexlora_core::BinaryAnalysis| {
        analysis
            .capabilities
            .iter()
            .find(|c| c.id == "driver.physical-memory-mapping")
            .map(|c| (c.confidence, c.evidence.len()))
    };
    assert_eq!(mapping(&analysis), Some((Confidence::Medium, 1)));

    let strings =
        scan_capability_strings(&node, &CancellationToken::default()).expect("string scan");
    apply_capability_strings(&mut analysis, &strings);
    assert_eq!(mapping(&analysis), Some((Confidence::High, 2)));

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    assert!(matches!(
        scan_capability_strings(&node, &cancelled),
        Err(HexloraError::Cancelled)
    ));
}

#[cfg(feature = "yara")]
#[test]
fn yara_rules_scan_files_and_archive_members_alike() {
    use hexlora_analysis::{YaraRules, yara_findings, yara_scan_node};
    use std::io::Write;
    let directory = tempfile::tempdir().expect("temporary directory");
    let rules_path = directory.path().join("demo.yar");
    std::fs::write(
        &rules_path,
        "rule fixture_message { strings: $a = \"hexlora fixture\" condition: $a }",
    )
    .expect("write rules");
    let rules = YaraRules::load(&rules_path).expect("compile rules");
    let cancel = CancellationToken::default();

    let node = open("fixture-x64.exe");
    let matches = yara_scan_node(&node, &rules, &cancel).expect("scan file");
    assert_eq!(matches.len(), 1);
    assert_eq!(
        yara_findings(&matches)[0].category,
        FindingCategory::Pattern
    );

    // The same bytes inside a ZIP are scanned without extraction to disk.
    let archive_path = directory.path().join("bundle.zip");
    let mut archive = zip::ZipWriter::new(std::fs::File::create(&archive_path).expect("zip"));
    archive
        .start_file("bin/app.exe", zip::write::SimpleFileOptions::default())
        .expect("zip member");
    archive
        .write_all(&std::fs::read(fixtures().join("fixture-x64.exe")).expect("read"))
        .expect("write member");
    archive
        .start_file("notes.txt", zip::write::SimpleFileOptions::default())
        .expect("zip member");
    archive.write_all(b"nothing here").expect("write member");
    archive.finish().expect("finish zip");
    let artifact = open_artifact(&archive_path, &cancel).expect("open zip");
    let mut hits = Vec::new();
    for member in artifact.files() {
        if !yara_scan_node(member, &rules, &cancel)
            .expect("scan member")
            .is_empty()
        {
            hits.push(member.name.clone());
        }
    }
    assert_eq!(hits, ["app.exe"]);
}

#[test]
fn code_view_lists_code_with_names_and_source_lines_from_a_companion_pdb() {
    let node = open("fixture-x64.exe");
    let view =
        CodeView::open(&node, None, None, &CancellationToken::default()).expect("open code view");
    assert!(view.symbol_error.is_none(), "{:?}", view.symbol_error);
    let summary = view
        .symbol_summary()
        .expect("PDB was found beside the image");
    assert_eq!(summary.format, hexlora_analysis::SymbolFormat::Pdb);
    assert!(summary.functions >= 5);

    let listing = view
        .listing_at("fixture_start", Limits::default())
        .expect("list entry by its PDB name");
    assert_eq!(listing.function.as_deref(), Some("fixture_start"));
    let comments: Vec<&str> = listing
        .lines
        .iter()
        .filter_map(|line| line.comment.as_deref())
        .collect();
    assert_eq!(
        comments,
        [
            "write_message",
            "inject",
            "add_numbers",
            "KERNEL32.dll!ExitProcess"
        ]
    );
    assert!(listing.lines.iter().all(|line| {
        line.source_file
            .as_deref()
            .is_some_and(|file| file.ends_with("fixture.c"))
            && line.source_line.is_some_and(|number| number > 0)
    }));
    let text = listing.to_text();
    assert!(text.starts_with("fixture_start:\n"), "{text}");
    assert!(text.contains("; write_message"), "{text}");
    assert!(text.contains("fixture.c:"), "{text}");
    assert!(text.trim_end().ends_with("; end of function"), "{text}");
    // A listing address maps back to the file for the hex view.
    let first = listing.lines.first().expect("first line");
    let offset = view.file_offset(first.address).expect("file offset") as usize;
    let bytes = std::fs::read(fixtures().join("fixture-x64.exe")).expect("read");
    assert_eq!(
        hex_of(&bytes[offset..offset + first.bytes.len() / 2]),
        first.bytes
    );
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn code_view_reports_unusable_symbols_without_failing_the_listing() {
    let node = open("fixture-driver.sys");
    let wrong = fixtures().join("fixture.c");
    let view = CodeView::open(&node, None, Some(&wrong), &CancellationToken::default())
        .expect("code view opens without symbols");
    assert!(view.symbols.is_none());
    assert!(
        view.symbol_error
            .as_deref()
            .is_some_and(|error| error.contains("no PDB or DWARF")),
        "{:?}",
        view.symbol_error
    );
    assert!(view.listing_at("entry", Limits::default()).is_ok());
    assert!(
        view.listing_at("not_a_function", Limits::default())
            .is_err()
    );

    // A file that is not a binary cannot be opened for disassembly.
    let source = open("fixture.c");
    assert!(CodeView::open(&source, None, None, &CancellationToken::default()).is_err());
    let cancelled = CancellationToken::default();
    cancelled.cancel();
    assert!(matches!(
        CodeView::open(&node, None, None, &cancelled),
        Err(HexloraError::Cancelled)
    ));
}

#[test]
fn universal_binary_slices_open_independently() {
    let node = open("fixture-universal.dylib");
    let analysis = analyze_node(&node).expect("analyze").expect("binary");
    assert_eq!(analysis.slice_analyses.len(), 2);
    let mut architectures = Vec::new();
    for slice in 0..2 {
        let view = CodeView::open(&node, Some(slice), None, &CancellationToken::default())
            .expect("open slice");
        architectures.push(view.program.architecture.label());
        assert!(view.listing_at("exported_entry", Limits::default()).is_ok());
    }
    architectures.sort_unstable();
    assert_eq!(architectures, ["arm64", "x86_64"]);
}
