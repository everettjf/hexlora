//! Image layout and function-start discovery for PE, ELF, and Mach-O.

use crate::{Architecture, FunctionSet, FunctionSource, Program, Region};
use goblin::Object;
use hexlora_core::{HexloraError, Result};
use std::collections::HashMap;

/// Entries read from any one table (symbols, unwind records, relocations).
const MAX_TABLE_ENTRIES: usize = 2_000_000;

fn unsupported(what: impl std::fmt::Display) -> HexloraError {
    HexloraError::Malformed(format!("disassembly is not available for {what}"))
}

pub(crate) fn discover(bytes: &[u8], slice: Option<usize>) -> Result<Program> {
    match Object::parse(bytes).map_err(|error| HexloraError::Malformed(error.to_string()))? {
        Object::PE(pe) => discover_pe(&pe),
        Object::Elf(elf) => discover_elf(&elf),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => discover_macho(&macho, bytes, 0),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            let index = slice.unwrap_or(0);
            let arch = fat
                .iter_arches()
                .nth(index)
                .and_then(|arch| arch.ok())
                .ok_or_else(|| unsupported(format!("architecture slice {index}")))?;
            let start = arch.offset as usize;
            let end = start.saturating_add(arch.size as usize);
            let data = bytes
                .get(start..end)
                .ok_or_else(|| unsupported("a slice that extends past the file"))?;
            let macho = goblin::mach::MachO::parse(data, 0)
                .map_err(|error| HexloraError::Malformed(error.to_string()))?;
            discover_macho(&macho, data, arch.offset as u64)
        }
        _ => Err(unsupported("this file format")),
    }
}

// ---- PE -----------------------------------------------------------------

const PE_SECTION_EXECUTE: u32 = 0x2000_0000;

fn discover_pe(pe: &goblin::pe::PE<'_>) -> Result<Program> {
    let machine = pe.header.coff_header.machine;
    let architecture = match machine {
        0x014c => Architecture::X86,
        0x8664 => Architecture::X86_64,
        0xaa64 => Architecture::Arm64,
        other => return Err(unsupported(format!("PE machine type 0x{other:04x}"))),
    };
    let base = pe.image_base;
    let regions = pe
        .sections
        .iter()
        .map(|section| {
            let size = section.virtual_size.max(section.size_of_raw_data) as u64;
            let file_size = if section.virtual_size == 0 {
                section.size_of_raw_data
            } else {
                section.size_of_raw_data.min(section.virtual_size)
            } as u64;
            Region {
                name: section.name().unwrap_or("<invalid>").to_string(),
                address: base.wrapping_add(section.virtual_address as u64),
                size,
                file_offset: section.pointer_to_raw_data as u64,
                file_size,
                executable: section.characteristics & PE_SECTION_EXECUTE != 0,
            }
        })
        .collect();

    let mut functions = FunctionSet::default();
    let entry = (pe.entry != 0).then(|| base.wrapping_add(pe.entry as u64));
    if let Some(entry) = entry {
        functions.add(entry, None, None, FunctionSource::Entry);
    }
    for export in pe.exports.iter().take(MAX_TABLE_ENTRIES) {
        if export.reexport.is_none() && export.rva != 0 {
            functions.add(
                base.wrapping_add(export.rva as u64),
                None,
                export.name.map(str::to_string),
                FunctionSource::Export,
            );
        }
    }
    if let Some(tls) = &pe.tls_data {
        // TLS callbacks are stored as virtual addresses.
        for callback in tls.callbacks.iter().take(4096) {
            functions.add(*callback, None, None, FunctionSource::TlsCallback);
        }
    }
    if let Some(exception) = &pe.exception_data {
        match architecture {
            Architecture::X86_64 => {
                for function in exception.functions().take(MAX_TABLE_ENTRIES).flatten() {
                    if function.begin_address == 0 {
                        continue;
                    }
                    functions.add(
                        base.wrapping_add(function.begin_address as u64),
                        function
                            .end_address
                            .checked_sub(function.begin_address)
                            .map(u64::from),
                        None,
                        FunctionSource::Unwind,
                    );
                }
            }
            Architecture::Arm64 => {
                for function in exception
                    .functions_arm64()
                    .take(MAX_TABLE_ENTRIES)
                    .flatten()
                {
                    if function.begin_address != 0 {
                        functions.add(
                            base.wrapping_add(function.begin_address as u64),
                            None,
                            None,
                            FunctionSource::Unwind,
                        );
                    }
                }
            }
            Architecture::X86 => {}
        }
    }
    let mut slots = HashMap::new();
    for import in pe.imports.iter().take(MAX_TABLE_ENTRIES) {
        // `offset` is the RVA of this import's address-table entry.
        slots.insert(
            base.wrapping_add(import.offset as u64),
            format!("{}!{}", import.dll, import.name),
        );
    }
    Ok(Program::assemble(
        architecture,
        base,
        true,
        entry,
        regions,
        functions,
        slots,
    ))
}

// ---- ELF ----------------------------------------------------------------

fn discover_elf(elf: &goblin::elf::Elf<'_>) -> Result<Program> {
    use goblin::elf::{
        header::{EM_386, EM_AARCH64, EM_X86_64, ET_REL},
        program_header::{PF_X, PT_LOAD},
        section_header::{SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS},
        sym::{STT_FUNC, STT_GNU_IFUNC},
    };
    let architecture = match elf.header.e_machine {
        EM_386 => Architecture::X86,
        EM_X86_64 => Architecture::X86_64,
        EM_AARCH64 => Architecture::Arm64,
        other => return Err(unsupported(format!("ELF machine type {other}"))),
    };
    if !elf.little_endian {
        return Err(unsupported("big-endian ELF files"));
    }
    if elf.header.e_type == ET_REL {
        // Section addresses in an object file are all zero until it is linked.
        return Err(unsupported("relocatable object files"));
    }
    let mut regions: Vec<Region> = elf
        .section_headers
        .iter()
        .filter(|header| header.sh_flags & SHF_ALLOC as u64 != 0 && header.sh_addr != 0)
        .map(|header| Region {
            name: elf
                .shdr_strtab
                .get_at(header.sh_name)
                .unwrap_or("<unnamed>")
                .to_string(),
            address: header.sh_addr,
            size: header.sh_size,
            file_offset: header.sh_offset,
            file_size: if header.sh_type == SHT_NOBITS {
                0
            } else {
                header.sh_size
            },
            executable: header.sh_flags & SHF_EXECINSTR as u64 != 0,
        })
        .collect();
    if regions.is_empty() {
        // Section headers are optional; fall back to the loadable segments.
        regions = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
            .enumerate()
            .map(|(index, header)| Region {
                name: format!("LOAD{index}"),
                address: header.p_vaddr,
                size: header.p_memsz,
                file_offset: header.p_offset,
                file_size: header.p_filesz.min(header.p_memsz),
                executable: header.p_flags & PF_X != 0,
            })
            .collect();
    }

    let mut functions = FunctionSet::default();
    let entry = (elf.entry != 0).then_some(elf.entry);
    if let Some(entry) = entry {
        functions.add(entry, None, None, FunctionSource::Entry);
    }
    for (symbols, strings) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
        for symbol in symbols.iter().take(MAX_TABLE_ENTRIES) {
            if !matches!(symbol.st_type(), STT_FUNC | STT_GNU_IFUNC)
                || symbol.st_value == 0
                || symbol.st_shndx == 0
            {
                continue;
            }
            functions.add(
                symbol.st_value,
                Some(symbol.st_size),
                strings.get_at(symbol.st_name).map(str::to_string),
                FunctionSource::Symbol,
            );
        }
    }
    // GOT entries filled by the dynamic linker: slot address → symbol.
    let (jump_slot, glob_dat) = match architecture {
        Architecture::Arm64 => (1026, 1025),
        Architecture::X86 | Architecture::X86_64 => (7, 6),
    };
    let mut slots = HashMap::new();
    for relocation in elf
        .pltrelocs
        .iter()
        .chain(elf.dynrelas.iter())
        .chain(elf.dynrels.iter())
        .take(MAX_TABLE_ENTRIES)
    {
        if relocation.r_type != jump_slot && relocation.r_type != glob_dat {
            continue;
        }
        if let Some(name) = elf
            .dynsyms
            .get(relocation.r_sym)
            .and_then(|symbol| elf.dynstrtab.get_at(symbol.st_name))
            .filter(|name| !name.is_empty())
        {
            slots.insert(relocation.r_offset, name.to_string());
        }
    }
    Ok(Program::assemble(
        architecture,
        0,
        false,
        entry,
        regions,
        functions,
        slots,
    ))
}

// ---- Mach-O -------------------------------------------------------------

const S_ZEROFILL: u32 = 0x1;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_SYMBOL_STUBS: u32 = 0x8;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

/// Reads function start addresses from `LC_FUNCTION_STARTS`: ULEB128 deltas
/// beginning at the `__TEXT` segment's address.
fn function_starts(data: &[u8], text_address: u64, functions: &mut FunctionSet) {
    let mut address = text_address;
    let mut cursor = 0usize;
    let mut count = 0usize;
    while cursor < data.len() && count < MAX_TABLE_ENTRIES {
        let mut delta = 0u64;
        let mut shift = 0u32;
        loop {
            let Some(byte) = data.get(cursor) else {
                return;
            };
            cursor += 1;
            if shift < 64 {
                delta |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        if delta == 0 {
            return;
        }
        address = address.wrapping_add(delta);
        functions.add(address, None, None, FunctionSource::FunctionStarts);
        count += 1;
    }
}

fn discover_macho(macho: &goblin::mach::MachO<'_>, data: &[u8], file_base: u64) -> Result<Program> {
    use goblin::mach::{constants::cputype, load_command::CommandVariant};
    let architecture = match macho.header.cputype {
        cputype::CPU_TYPE_X86 => Architecture::X86,
        cputype::CPU_TYPE_X86_64 => Architecture::X86_64,
        cputype::CPU_TYPE_ARM64 => Architecture::Arm64,
        other => return Err(unsupported(format!("Mach-O CPU type 0x{other:x}"))),
    };
    if !macho.little_endian {
        return Err(unsupported("big-endian Mach-O files"));
    }
    if macho.header.filetype == goblin::mach::header::MH_OBJECT {
        return Err(unsupported("relocatable object files"));
    }

    struct Table {
        kind: u32,
        address: u64,
        size: u64,
        /// First index into the indirect symbol table.
        first_indirect: u32,
        /// Bytes per stub, for stub sections.
        stub_size: u32,
    }
    let mut regions = Vec::new();
    let mut tables = Vec::new();
    let mut text_address = None;
    let mut indirect_table = None;
    let mut function_starts_range = None;
    let mut segment_index = 0usize;
    for command in &macho.load_commands {
        match &command.command {
            CommandVariant::Dysymtab(dysymtab) => {
                indirect_table = Some((dysymtab.indirectsymoff, dysymtab.nindirectsyms));
            }
            CommandVariant::FunctionStarts(linkedit) => {
                function_starts_range = Some((linkedit.dataoff, linkedit.datasize));
            }
            CommandVariant::Segment32(_) | CommandVariant::Segment64(_) => {
                let is_64 = matches!(command.command, CommandVariant::Segment64(_));
                let Some(segment) = macho.segments.get(segment_index) else {
                    continue;
                };
                segment_index += 1;
                let segment_name = segment.name().unwrap_or("<invalid>").to_string();
                if segment_name == "__TEXT" {
                    text_address = Some(segment.vmaddr);
                }
                let Ok(sections) = segment.sections() else {
                    continue;
                };
                // goblin does not expose the reserved fields that tie stub and
                // pointer sections to the indirect symbol table, so they are
                // read from the raw section headers.
                let (header_size, section_size, reserved_at) =
                    if is_64 { (72, 80, 68) } else { (56, 68, 56) };
                for (index, (section, _)) in sections.iter().enumerate() {
                    let kind = section.flags & 0xff;
                    let zero_fill =
                        matches!(kind, S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL);
                    regions.push(Region {
                        name: format!("{segment_name},{}", section.name().unwrap_or("<invalid>")),
                        address: section.addr,
                        size: section.size,
                        file_offset: file_base + section.offset as u64,
                        file_size: if zero_fill { 0 } else { section.size },
                        executable: section.flags
                            & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
                            != 0,
                    });
                    if matches!(
                        kind,
                        S_SYMBOL_STUBS | S_LAZY_SYMBOL_POINTERS | S_NON_LAZY_SYMBOL_POINTERS
                    ) {
                        let raw = command.offset + header_size + index * section_size + reserved_at;
                        if let (Some(first_indirect), Some(stub_size)) =
                            (read_u32(data, raw), read_u32(data, raw + 4))
                        {
                            tables.push(Table {
                                kind,
                                address: section.addr,
                                size: section.size,
                                first_indirect,
                                stub_size,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let mut functions = FunctionSet::default();
    // `LC_MAIN` gives a file offset from the start of `__TEXT`; the older
    // `LC_UNIXTHREAD` gives the address itself.
    let entry = (macho.entry != 0).then(|| {
        if macho.old_style_entry {
            macho.entry
        } else {
            text_address.unwrap_or(0).wrapping_add(macho.entry)
        }
    });
    if let Some(entry) = entry {
        functions.add(entry, None, None, FunctionSource::Entry);
    }
    if let Some(symbols) = &macho.symbols {
        for (name, symbol) in symbols.iter().take(MAX_TABLE_ENTRIES).flatten() {
            if symbol.n_type & N_STAB != 0
                || symbol.n_type & N_TYPE != N_SECT
                || symbol.n_value == 0
            {
                continue;
            }
            functions.add(
                symbol.n_value,
                None,
                Some(name.to_string()),
                FunctionSource::Symbol,
            );
        }
    }
    if let (Some((offset, size)), Some(text_address)) = (function_starts_range, text_address)
        && let Some(table) =
            data.get(offset as usize..(offset as usize).saturating_add(size as usize))
    {
        function_starts(table, text_address, &mut functions);
    }

    // Stubs and pointer slots are named through the indirect symbol table,
    // which works for both classic and chained-fixup binaries.
    let mut slots = HashMap::new();
    if let (Some((indirect_offset, indirect_count)), Some(symbols)) =
        (indirect_table, &macho.symbols)
    {
        let pointer_size: u64 = if macho.is_64 { 8 } else { 4 };
        for table in &tables {
            let entry_size = if table.kind == S_SYMBOL_STUBS {
                table.stub_size as u64
            } else {
                pointer_size
            };
            if entry_size == 0 {
                continue;
            }
            let count = (table.size / entry_size).min(MAX_TABLE_ENTRIES as u64);
            for index in 0..count {
                let indirect = table.first_indirect as u64 + index;
                if indirect >= indirect_count as u64 {
                    break;
                }
                let Some(symbol_index) =
                    read_u32(data, indirect_offset as usize + indirect as usize * 4)
                else {
                    break;
                };
                if symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                    continue;
                }
                let Ok((name, _)) = symbols.get(symbol_index as usize) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                let address = table.address + index * entry_size;
                if table.kind == S_SYMBOL_STUBS {
                    functions.add(
                        address,
                        Some(entry_size),
                        Some(name.to_string()),
                        FunctionSource::Stub,
                    );
                } else {
                    slots.insert(address, name.to_string());
                }
            }
        }
    }
    Ok(Program::assemble(
        architecture,
        0,
        false,
        entry,
        regions,
        functions,
        slots,
    ))
}
