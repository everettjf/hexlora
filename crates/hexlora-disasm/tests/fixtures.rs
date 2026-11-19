//! Function discovery and listings for the checked-in binary fixtures.

use hexlora_disasm::{Architecture, EndReason, FlowKind, FunctionSource, Limits, Listing, Program};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/binaries")
            .join(name),
    )
    .expect("read fixture")
}

fn listing(program: &Program, bytes: &[u8], target: &str) -> Listing {
    let address = program
        .resolve(target)
        .unwrap_or_else(|| panic!("{target} resolves"));
    program
        .disassemble(bytes, address, Limits::default())
        .unwrap_or_else(|error| panic!("{target} disassembles: {error}"))
}

fn comments(listing: &Listing) -> Vec<&str> {
    listing
        .instructions
        .iter()
        .filter_map(|instruction| instruction.comment.as_deref())
        .collect()
}

#[test]
fn pe_functions_come_from_entry_exports_and_unwind_data() {
    let bytes = fixture("fixture-x64.exe");
    let program = Program::discover(&bytes, None).expect("discover PE");
    assert_eq!(program.architecture, Architecture::X86_64);
    assert!(program.relative_tables);
    assert_eq!(program.image_base, 0x1_4000_0000);
    let entry = program.entry.expect("entry point");
    let sources: Vec<FunctionSource> = program.functions.iter().map(|f| f.source).collect();
    assert!(sources.contains(&FunctionSource::Entry));
    assert!(sources.contains(&FunctionSource::Export));
    assert!(sources.contains(&FunctionSource::Unwind));
    let exported = program
        .functions
        .iter()
        .find(|function| function.name.as_deref() == Some("exported_entry"))
        .expect("export is a function");
    assert_eq!(program.resolve("exported_entry"), Some(exported.address));
    assert_eq!(program.resolve("entry"), Some(entry));
    // An RVA and a full virtual address name the same place.
    assert_eq!(
        program.resolve(&format!("0x{:x}", entry - program.image_base)),
        Some(entry)
    );
    assert_eq!(program.resolve(&format!("0x{entry:x}")), Some(entry));
    // Addresses from the file's own tables are RVAs; data and unmapped
    // addresses are not code under any reading.
    assert_eq!(
        program.code_address_from_table(entry - program.image_base),
        Some(entry)
    );
    assert_eq!(program.code_address_from_table(0), None);
    assert_eq!(program.code_address_from_table(0x2000), None);
    assert_eq!(program.resolve("no_such_function"), None);
    assert_eq!(program.resolve("0xdeadbeef00"), None);
}

#[test]
fn pe_listing_names_imports_strings_and_call_targets() {
    let bytes = fixture("fixture-x64.exe");
    let mut program = Program::discover(&bytes, None).expect("discover PE");
    let entry = listing(&program, &bytes, "entry");
    assert_eq!(entry.end, EndReason::FunctionEnd);
    let last = entry.instructions.last().expect("entry has instructions");
    assert_eq!(last.flow, FlowKind::Jump);
    assert_eq!(last.comment.as_deref(), Some("KERNEL32.dll!ExitProcess"));
    let calls: Vec<_> = entry
        .instructions
        .iter()
        .filter(|instruction| instruction.flow == FlowKind::Call)
        .collect();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|call| call.target.is_some()));
    // Unnamed call targets still get a stable label.
    assert!(calls.iter().all(|call| {
        call.comment
            .as_deref()
            .is_some_and(|c| c.starts_with("sub_"))
    }));

    // Names from debug information replace the synthesized ones.
    let inject = calls[1].target.expect("second call target");
    program.add_debug_functions(
        [("inject".to_string(), inject - program.image_base, Some(144))],
        true,
    );
    let entry = listing(&program, &bytes, "entry");
    assert!(comments(&entry).contains(&"inject"));
    let inject = listing(&program, &bytes, "inject");
    assert_eq!(inject.function.as_deref(), Some("inject"));
    let found = comments(&inject);
    for import in [
        "KERNEL32.dll!OpenProcess",
        "KERNEL32.dll!VirtualAllocEx",
        "KERNEL32.dll!WriteProcessMemory",
        "KERNEL32.dll!CreateRemoteThread",
    ] {
        assert!(found.contains(&import), "{import} missing from {found:?}");
    }
    assert!(found.contains(&"\"hexlora fixture\\n\""), "{found:?}");
    assert_eq!(
        inject.instructions.last().map(|i| i.flow),
        Some(FlowKind::Return)
    );
    // Every instruction's bytes are where the listing says they are.
    for instruction in &inject.instructions {
        let offset = program
            .file_offset(instruction.address)
            .expect("file offset") as usize;
        assert_eq!(
            &bytes[offset..offset + instruction.bytes.len()],
            &instruction.bytes[..]
        );
    }
}

#[test]
fn driver_entry_shows_kernel_imports() {
    let bytes = fixture("fixture-driver.sys");
    let program = Program::discover(&bytes, None).expect("discover driver");
    let found_listing = listing(&program, &bytes, "entry");
    let found = comments(&found_listing);
    for import in [
        "ntoskrnl.exe!IoCreateDevice",
        "ntoskrnl.exe!ZwOpenProcess",
        "ntoskrnl.exe!IoCreateSymbolicLink",
    ] {
        assert!(found.contains(&import), "{import} missing from {found:?}");
    }
    // `map_region` sets up arguments before its tail call, so it is a
    // function, not an import stub.
    assert!(
        !found.iter().any(|comment| comment.contains("(stub)")),
        "{found:?}"
    );
}

#[test]
fn elf_listings_cover_x86_64_and_arm64() {
    for (name, architecture) in [
        ("fixture-x86_64.elf", Architecture::X86_64),
        ("fixture-aarch64.elf", Architecture::Arm64),
    ] {
        let bytes = fixture(name);
        let program = Program::discover(&bytes, None).expect("discover ELF");
        assert_eq!(program.architecture, architecture, "{name}");
        assert!(!program.relative_tables);
        let exported = listing(&program, &bytes, "exported_entry");
        assert_eq!(exported.end, EndReason::FunctionEnd, "{name}");
        let last = exported.instructions.last().expect("instructions");
        assert_eq!(last.flow, FlowKind::Jump, "{name}");
        assert_eq!(last.comment.as_deref(), Some("add_numbers"), "{name}");
        assert_eq!(last.target, program.resolve("add_numbers"), "{name}");
        let text = listing(&program, &bytes, "message_text");
        assert!(
            comments(&text).contains(&"\"hexlora fixture\\n\""),
            "{name}: {:?}",
            text.instructions
        );
        // A self-loop is a jump inside the function and needs no label, but
        // it must not run the listing past the function.
        let start = listing(&program, &bytes, "_start");
        assert!(start.instructions.len() <= 4, "{name}");
    }
}

#[test]
fn universal_macho_slices_name_stubs_through_the_indirect_symbol_table() {
    let bytes = fixture("fixture-universal.dylib");
    let mut seen = Vec::new();
    for slice in 0..2 {
        let program = Program::discover(&bytes, Some(slice)).expect("discover slice");
        seen.push(program.architecture);
        let stubs: Vec<&str> = program
            .functions
            .iter()
            .filter(|function| function.source == FunctionSource::Stub)
            .filter_map(|function| function.name.as_deref())
            .collect();
        assert_eq!(stubs, ["_malloc", "_puts"], "slice {slice}");
        // Names resolve with or without the Mach-O underscore.
        let write = listing(&program, &bytes, "write_message");
        assert_eq!(write.function.as_deref(), Some("_write_message"));
        let found = comments(&write);
        assert!(found.contains(&"_puts"), "slice {slice}: {found:?}");
        assert!(found.contains(&"_malloc"), "slice {slice}: {found:?}");
        assert!(
            found.contains(&"\"hexlora fixture\\n\""),
            "slice {slice}: {found:?}"
        );
        let stub = listing(&program, &bytes, "_puts");
        assert!(comments(&stub).contains(&"_puts"), "slice {slice}");
    }
    seen.sort_by_key(|architecture| architecture.label());
    assert_eq!(seen, [Architecture::Arm64, Architecture::X86_64]);
    assert!(Program::discover(&bytes, Some(9)).is_err());
}

#[test]
fn listings_respect_the_instruction_limit_and_reject_data_addresses() {
    let bytes = fixture("fixture-x64.exe");
    let program = Program::discover(&bytes, None).expect("discover PE");
    let entry = program.entry.expect("entry");
    let limited = program
        .disassemble(
            &bytes,
            entry,
            Limits {
                max_instructions: 3,
            },
        )
        .expect("limited listing");
    assert_eq!(limited.instructions.len(), 3);
    assert_eq!(limited.end, EndReason::InstructionLimit);
    // Zero is raised to one rather than producing an empty listing.
    let one = program
        .disassemble(
            &bytes,
            entry,
            Limits {
                max_instructions: 0,
            },
        )
        .expect("one instruction");
    assert_eq!(one.instructions.len(), 1);

    // Code after a function of unknown size is not attributed to it.
    let export = program.resolve("exported_entry").expect("export");
    let inside = program
        .disassemble(&bytes, export + 5, Limits::default())
        .expect("listing from inside the export");
    assert_eq!(inside.function, None);
    let whole = program
        .disassemble(&bytes, export, Limits::default())
        .expect("listing from the export");
    assert_eq!(whole.function.as_deref(), Some("exported_entry"));

    let data = program
        .regions
        .iter()
        .find(|region| !region.executable)
        .expect("data region")
        .address;
    assert!(
        program
            .disassemble(&bytes, data, Limits::default())
            .is_err()
    );
    assert!(
        program
            .disassemble(&bytes, 0x10, Limits::default())
            .is_err()
    );
    assert!(
        program
            .disassemble(&bytes, u64::MAX, Limits::default())
            .is_err()
    );
}

#[test]
fn the_running_test_binary_disassembles_from_many_functions() {
    let Ok(path) = std::env::current_exe() else {
        return;
    };
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    // Hosts with an unsupported architecture or format are skipped.
    let Ok(program) = Program::discover(&bytes, None) else {
        return;
    };
    assert!(program.functions.len() > 100, "{}", program.functions.len());
    // The default listing starts here, so a wrong entry address breaks `disasm`
    // on every executable of that format.
    let entry = program.entry.expect("an executable has an entry point");
    assert!(program.is_code(entry), "entry 0x{entry:x} is not code");
    assert!(
        !listing(&program, &bytes, "entry").instructions.is_empty(),
        "the entry point disassembles"
    );
    let mut calls_named = 0usize;
    for function in program
        .functions
        .iter()
        .step_by(program.functions.len() / 200 + 1)
    {
        let listing = program
            .disassemble(
                &bytes,
                function.address,
                Limits {
                    max_instructions: 400,
                },
            )
            .expect("function disassembles");
        assert!(!listing.instructions.is_empty());
        if let Some(size) = function.size {
            let end = listing.instructions.last().map(|i| i.address).unwrap_or(0);
            assert!(end < function.address + size, "{}", function.display_name());
        }
        calls_named += listing
            .instructions
            .iter()
            .filter(|i| i.flow == FlowKind::Call && i.comment.is_some())
            .count();
    }
    assert!(calls_named > 0, "no call target in a real binary was named");
}

#[test]
fn damaged_images_never_panic() {
    for name in [
        "fixture-x64.exe",
        "fixture-driver.sys",
        "fixture-x86_64.elf",
        "fixture-aarch64.elf",
        "fixture-universal.dylib",
    ] {
        let original = fixture(name);
        for length in [0, 1, 64, 512, original.len() / 2, original.len() - 1] {
            let _ = Program::discover(&original[..length], None);
        }
        let mut damaged = original.clone();
        let step = (damaged.len() / 1500).max(1);
        for offset in (0..damaged.len().min(0x3000)).step_by(step) {
            for flip in [0xffu8, 0x80, 0x01] {
                damaged[offset] ^= flip;
                for slice in [None, Some(1)] {
                    if let Ok(program) = Program::discover(&damaged, slice) {
                        for function in program.functions.iter().take(16) {
                            let _ = program.disassemble(
                                &damaged,
                                function.address,
                                Limits {
                                    max_instructions: 64,
                                },
                            );
                        }
                        if let Some(entry) = program.entry {
                            let _ = program.disassemble(&damaged, entry, Limits::default());
                        }
                    }
                }
                damaged[offset] ^= flip;
            }
        }
    }
    // Random bytes handed to each decoder directly.
    let bytes = fixture("fixture-x64.exe");
    let mut noise = bytes.clone();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for byte in noise.iter_mut().skip(0x400).take(0x200) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    let program = Program::discover(&noise, None).expect("headers are intact");
    for function in &program.functions {
        let _ = program.disassemble(&noise, function.address, Limits::default());
    }
}
