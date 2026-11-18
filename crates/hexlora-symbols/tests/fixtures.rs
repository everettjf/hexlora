//! Debug information read from the checked-in binary fixtures.

use hexlora_symbols::{LoadOptions, SymbolFormat, find_companion, load};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/binaries")
        .join(name)
}

fn options<'a>(explicit: Option<&'a std::path::Path>) -> LoadOptions<'a> {
    LoadOptions {
        explicit,
        architecture: None,
        should_stop: &|| false,
    }
}

#[test]
fn pdb_beside_a_pe_is_found_matched_and_read() {
    let image_path = fixture("fixture-x64.exe");
    let image = std::fs::read(&image_path).expect("read PE fixture");
    assert_eq!(
        find_companion(&image_path, &image).as_deref(),
        Some(fixture("fixture-x64.pdb").as_path())
    );
    let symbols = load(Some(&image_path), &image, &options(None))
        .expect("PDB loads")
        .expect("PDB is found");
    assert_eq!(symbols.format, SymbolFormat::Pdb);
    assert!(symbols.relative_addresses);
    let identity = symbols.identity.as_deref().expect("PDB identity");
    assert!(
        identity.len() == 36 + ", age 1".len() && identity.ends_with(", age 1"),
        "{identity}"
    );
    let names: Vec<&str> = symbols.functions.iter().map(|f| f.name.as_str()).collect();
    for expected in [
        "add_numbers",
        "write_message",
        "inject",
        "exported_entry",
        "fixture_start",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    let add = symbols
        .functions
        .iter()
        .find(|function| function.name == "add_numbers")
        .expect("add_numbers");
    assert_eq!(add.address, 0x1000);
    assert!(add.size.is_some_and(|size| size > 0));
    assert_eq!(
        symbols.function_at(add.address).map(|f| f.name.as_str()),
        Some("add_numbers")
    );
    let (file, line) = symbols.line_at(add.address).expect("line for add_numbers");
    assert!(file.ends_with("fixture.c"), "{file}");
    assert!(line > 0);
    assert!(symbols.summary().line_records > 4);
}

#[test]
fn pdb_for_another_image_is_refused() {
    let driver = std::fs::read(fixture("fixture-driver.sys")).expect("read driver fixture");
    // The driver was linked without a PDB, so it has no identity to contradict.
    let pdb = fixture("fixture-x64.pdb");
    assert!(load(None, &driver, &options(Some(&pdb))).is_ok());

    // An image that names a different PDB must not accept this one.
    let mut image = std::fs::read(fixture("fixture-x64.exe")).expect("read PE fixture");
    // The CodeView record is `RSDS`, then the 16-byte GUID.
    let position = image
        .windows(4)
        .position(|window| window == b"RSDS")
        .expect("CodeView record in the image")
        + 4;
    image[position] ^= 0xff;
    let error = load(None, &image, &options(Some(&pdb))).expect_err("mismatched PDB is refused");
    assert!(error.to_string().contains("different image"), "{error}");
}

#[test]
fn embedded_dwarf_gives_functions_and_lines_for_both_architectures() {
    for name in ["fixture-x86_64.elf", "fixture-aarch64.elf"] {
        let path = fixture(name);
        let image = std::fs::read(&path).expect("read ELF fixture");
        let symbols = load(Some(&path), &image, &options(None))
            .expect("DWARF loads")
            .unwrap_or_else(|| panic!("{name} has DWARF"));
        assert_eq!(symbols.format, SymbolFormat::Dwarf);
        assert!(!symbols.relative_addresses);
        assert_eq!(symbols.compile_units, 1);
        let names: Vec<&str> = symbols.functions.iter().map(|f| f.name.as_str()).collect();
        for expected in ["add_numbers", "message_text", "exported_entry", "_start"] {
            assert!(
                names.contains(&expected),
                "{name}: {expected} missing from {names:?}"
            );
        }
        let function = symbols
            .functions
            .iter()
            .find(|function| function.name == "message_text")
            .expect("message_text");
        assert!(function.size.is_some_and(|size| size > 0));
        let (file, line) = symbols
            .line_at(function.address)
            .unwrap_or_else(|| panic!("{name}: line for message_text"));
        assert!(file.ends_with("fixture.c"), "{file}");
        assert!(line > 0);
    }
}

#[test]
fn cancelled_loads_stop_and_truncated_files_do_not_panic() {
    let path = fixture("fixture-x86_64.elf");
    let image = std::fs::read(&path).expect("read ELF fixture");
    let cancelled = LoadOptions {
        explicit: None,
        architecture: None,
        should_stop: &|| true,
    };
    assert!(load(Some(&path), &image, &cancelled).is_err());

    let pdb = std::fs::read(fixture("fixture-x64.pdb")).expect("read PDB fixture");
    let directory = tempfile::tempdir().expect("temporary directory");
    for (index, length) in [64usize, 4096, 8192, pdb.len() / 2, pdb.len() - 1]
        .into_iter()
        .enumerate()
    {
        let truncated = directory.path().join(format!("truncated-{index}.pdb"));
        std::fs::write(&truncated, &pdb[..length]).expect("write truncated PDB");
        let _ = load(None, b"MZ", &options(Some(&truncated)));
    }
    for length in [16usize, 64, 512, image.len() / 2, image.len() - 1] {
        let _ = load(None, &image[..length], &options(None));
    }
    // Every byte flipped in turn across the debug sections must not panic.
    let mut damaged = image.clone();
    for offset in (0..damaged.len()).step_by(7) {
        damaged[offset] ^= 0xa5;
        let _ = load(None, &damaged, &options(None));
        damaged[offset] ^= 0xa5;
    }
}

#[test]
fn damaged_pdbs_are_rejected_or_partly_read_but_never_fatal() {
    // The PDB reader indexes with values from the file and can panic on a
    // damaged one; loading must turn that into an error, not a crash.
    let image = std::fs::read(fixture("fixture-x64.exe")).expect("read PE fixture");
    let pdb = std::fs::read(fixture("fixture-x64.pdb")).expect("read PDB fixture");
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("damaged.pdb");
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut loaded, mut refused) = (0usize, 0usize);
    for _ in 0..400 {
        let mut damaged = pdb.clone();
        for _ in 0..1 + next() % 6 {
            let at = (next() % damaged.len() as u64) as usize;
            let value = [0u32, 1, 0x7fff_ffff, u32::MAX][(next() % 4) as usize];
            let end = (at + 4).min(damaged.len());
            damaged[at..end].copy_from_slice(&value.to_le_bytes()[..end - at]);
        }
        std::fs::write(&path, &damaged).expect("write damaged PDB");
        match load(None, &image, &options(Some(&path))) {
            Ok(_) => loaded += 1,
            Err(_) => refused += 1,
        }
    }
    // Most single-word changes land in padding or unused streams.
    assert!(
        loaded > 0 && refused > 0,
        "loaded {loaded}, refused {refused}"
    );
}
