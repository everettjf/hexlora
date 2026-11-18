//! Function and line information from DWARF in an ELF or Mach-O file.

use crate::{DebugSymbols, LoadOptions, SymbolFormat};
use gimli::{AttributeValue, EndianSlice, RunTimeEndian};
use goblin::Object;
use hexlora_core::{HexloraError, Result};
use std::{borrow::Cow, collections::HashMap, io::Read, path::Path};

/// Total bytes compressed debug sections may expand to.
const MAX_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const SHF_COMPRESSED: u64 = 0x800;
const ELFCOMPRESS_ZLIB: u32 = 1;

type Slice<'a> = EndianSlice<'a, RunTimeEndian>;
type Sections<'a> = HashMap<String, Cow<'a, [u8]>>;

struct DebugObject<'a> {
    sections: Sections<'a>,
    endian: RunTimeEndian,
    identity: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn inflate(data: &[u8], expected: u64, budget: &mut u64) -> Option<Vec<u8>> {
    if expected > *budget {
        return None;
    }
    let mut output = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .take(expected)
        .read_to_end(&mut output)
        .ok()?;
    if output.len() as u64 != expected {
        return None;
    }
    *budget -= expected;
    Some(output)
}

fn elf_sections<'a>(elf: &goblin::elf::Elf<'a>, bytes: &'a [u8]) -> Option<DebugObject<'a>> {
    use goblin::elf::{header::ET_REL, note::NT_GNU_BUILD_ID, section_header::SHT_NOBITS};
    // Relocatable objects need their relocations applied before their DWARF
    // addresses mean anything.
    if elf.header.e_type == ET_REL {
        return None;
    }
    let mut sections = Sections::new();
    let mut budget = MAX_DECOMPRESSED_BYTES;
    for header in &elf.section_headers {
        let Some(name) = elf.shdr_strtab.get_at(header.sh_name) else {
            continue;
        };
        if !name.starts_with(".debug_") || header.sh_type == SHT_NOBITS {
            continue;
        }
        let start = usize::try_from(header.sh_offset).ok()?;
        let end = start.checked_add(usize::try_from(header.sh_size).ok()?)?;
        let Some(data) = bytes.get(start..end) else {
            continue;
        };
        let data: Cow<'a, [u8]> = if header.sh_flags & SHF_COMPRESSED != 0 {
            let (kind, size, payload) = if elf.is_64 {
                let head = data.get(..24)?;
                (
                    u32::from_le_bytes(head[0..4].try_into().ok()?),
                    u64::from_le_bytes(head[8..16].try_into().ok()?),
                    &data[24..],
                )
            } else {
                let head = data.get(..12)?;
                (
                    u32::from_le_bytes(head[0..4].try_into().ok()?),
                    u32::from_le_bytes(head[4..8].try_into().ok()?) as u64,
                    &data[12..],
                )
            };
            // Only little-endian zlib sections are expanded; anything else is
            // treated as absent rather than misread.
            if !elf.little_endian || kind != ELFCOMPRESS_ZLIB {
                continue;
            }
            match inflate(payload, size, &mut budget) {
                Some(expanded) => Cow::Owned(expanded),
                None => continue,
            }
        } else {
            Cow::Borrowed(data)
        };
        sections.insert(name.to_string(), data);
    }
    let identity = elf
        .iter_note_sections(bytes, None)
        .into_iter()
        .flatten()
        .chain(elf.iter_note_headers(bytes).into_iter().flatten())
        .flatten()
        .find(|note| note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID)
        .map(|note| hex(note.desc));
    Some(DebugObject {
        sections,
        endian: if elf.little_endian {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        },
        identity,
    })
}

fn macho_sections<'a>(macho: &goblin::mach::MachO<'a>) -> DebugObject<'a> {
    let mut sections = Sections::new();
    for segment in &macho.segments {
        let Ok(parsed) = segment.sections() else {
            continue;
        };
        for (section, data) in parsed {
            let (Ok(segment_name), Ok(name)) = (section.segname(), section.name()) else {
                continue;
            };
            // `__debug_info` in Mach-O is `.debug_info` in DWARF's own naming.
            if segment_name == "__DWARF"
                && let Some(rest) = name.strip_prefix("__")
            {
                sections.insert(format!(".{rest}"), Cow::Borrowed(data));
            }
        }
    }
    let identity = macho.load_commands.iter().find_map(|command| {
        if let goblin::mach::load_command::CommandVariant::Uuid(uuid) = &command.command {
            Some(hex(&uuid.uuid))
        } else {
            None
        }
    });
    DebugObject {
        sections,
        endian: if macho.little_endian {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        },
        identity,
    }
}

fn macho_architecture(cputype: u32) -> &'static str {
    match cputype {
        0x0100_000c => "arm64",
        0x0200_000c => "arm64_32",
        0x0100_0007 => "x86_64",
        7 => "x86",
        12 => "arm",
        _ => "",
    }
}

fn debug_object<'a>(bytes: &'a [u8], architecture: Option<&str>) -> Option<DebugObject<'a>> {
    match Object::parse(bytes).ok()? {
        Object::Elf(elf) => elf_sections(&elf, bytes),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => Some(macho_sections(&macho)),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            let arches = fat.arches().ok()?;
            let wanted = architecture.map(|name| name.to_ascii_lowercase());
            let index = wanted
                .as_deref()
                .and_then(|wanted| {
                    arches.iter().position(|arch| {
                        let name = macho_architecture(arch.cputype);
                        !name.is_empty() && (wanted == name || wanted.starts_with(name))
                    })
                })
                .unwrap_or(0);
            match fat.get(index).ok()? {
                goblin::mach::SingleArch::MachO(macho) => Some(macho_sections(&macho)),
                goblin::mach::SingleArch::Archive(_) => None,
            }
        }
        _ => None,
    }
}

/// The UUID or build ID of an image, for matching a companion symbol file.
pub(crate) fn image_identity(image: &[u8], architecture: Option<&str>) -> Option<String> {
    debug_object(image, architecture)?.identity
}

fn section_name(id: gimli::SectionId) -> String {
    // Mach-O section names are limited to 16 bytes, so `__debug_str_offsets`
    // is stored truncated.
    id.name().to_string()
}

fn lookup<'a>(sections: &'a Sections<'_>, id: gimli::SectionId) -> &'a [u8] {
    let name = section_name(id);
    if let Some(data) = sections.get(&name) {
        return data;
    }
    // Mach-O truncation: `.debug_str_offsets` → `.debug_str_offs`.
    if name.len() > 15
        && let Some(data) = sections.get(&name[..15])
    {
        return data;
    }
    &[]
}

fn text<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    value: AttributeValue<Slice<'a>>,
) -> Option<String> {
    let slice = dwarf.attr_string(unit, value).ok()?;
    Some(String::from_utf8_lossy(slice.slice()).into_owned())
}

/// The name of a function entry: its linkage name if it has one, else its
/// source name, following one reference to a declaration or abstract instance.
fn entry_name<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>>,
    follow: bool,
) -> Option<String> {
    for attribute in [
        gimli::DW_AT_linkage_name,
        gimli::DW_AT_MIPS_linkage_name,
        gimli::DW_AT_name,
    ] {
        if let Some(value) = entry.attr_value(attribute)
            && let Some(name) = text(dwarf, unit, value)
            && !name.is_empty()
        {
            return Some(name);
        }
    }
    if !follow {
        return None;
    }
    for attribute in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
        if let Some(AttributeValue::UnitRef(offset)) = entry.attr_value(attribute)
            && let Ok(target) = unit.entry(offset)
            && let Some(name) = entry_name(dwarf, unit, &target, false)
        {
            return Some(name);
        }
    }
    None
}

pub(crate) fn load(
    path: &Path,
    bytes: &[u8],
    options: &LoadOptions<'_>,
) -> Result<Option<DebugSymbols>> {
    let Some(object) = debug_object(bytes, options.architecture) else {
        return Ok(None);
    };
    if lookup(&object.sections, gimli::SectionId::DebugInfo).is_empty() {
        return Ok(None);
    }
    let endian = object.endian;
    let dwarf = gimli::Dwarf::load(|id| -> std::result::Result<Slice<'_>, gimli::Error> {
        Ok(EndianSlice::new(lookup(&object.sections, id), endian))
    })
    .map_err(|error| HexloraError::Malformed(format!("DWARF in {}: {error}", path.display())))?;

    let mut symbols = DebugSymbols::new(SymbolFormat::Dwarf, path);
    symbols.identity = object.identity.clone();
    let mut file_cache = HashMap::new();
    let mut headers = dwarf.units();
    // A damaged unit ends the walk but keeps what was read so far.
    while let Ok(Some(header)) = headers.next() {
        if (options.should_stop)() {
            return Err(HexloraError::Cancelled);
        }
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        symbols.compile_units += 1;
        read_functions(&dwarf, &unit, &mut symbols);
        read_lines(&dwarf, &unit, &mut symbols, &mut file_cache);
        if symbols.truncated {
            break;
        }
    }
    symbols.finish();
    Ok(Some(symbols))
}

fn read_functions<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    symbols: &mut DebugSymbols,
) {
    let mut entries = unit.entries();
    while let Ok(Some(entry)) = entries.next_dfs() {
        if entry.tag() != gimli::DW_TAG_subprogram {
            continue;
        }
        let Some(low) = entry
            .attr_value(gimli::DW_AT_low_pc)
            .and_then(|value| dwarf.attr_address(unit, value).ok().flatten())
        else {
            continue;
        };
        // Address zero is what a linker leaves behind for discarded functions.
        if low == 0 {
            continue;
        }
        let size = match entry.attr_value(gimli::DW_AT_high_pc) {
            Some(AttributeValue::Udata(size)) => Some(size),
            Some(value) => dwarf
                .attr_address(unit, value)
                .ok()
                .flatten()
                .and_then(|high| high.checked_sub(low)),
            None => None,
        };
        if let Some(name) = entry_name(dwarf, unit, entry, true) {
            symbols.push_function(name, low, size);
        }
        if symbols.truncated {
            return;
        }
    }
}

fn read_lines<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    symbols: &mut DebugSymbols,
    file_cache: &mut HashMap<String, u32>,
) {
    let Some(program) = unit.line_program.clone() else {
        return;
    };
    // File index within this unit → interned file.
    let mut unit_files: HashMap<u64, u32> = HashMap::new();
    let mut rows = program.rows();
    while let Ok(Some((header, row))) = rows.next_row() {
        if row.end_sequence() {
            symbols.push_line(row.address(), 0, 0);
            continue;
        }
        let Some(line) = row.line() else {
            continue;
        };
        // A sequence starting at zero belongs to code the linker discarded.
        if row.address() == 0 {
            continue;
        }
        let index = row.file_index();
        let file = match unit_files.get(&index) {
            Some(file) => *file,
            None => {
                let name = header
                    .file(index)
                    .map(|file| {
                        let name = text(dwarf, unit, file.path_name()).unwrap_or_default();
                        let directory = file
                            .directory(header)
                            .and_then(|directory| text(dwarf, unit, directory))
                            .unwrap_or_default();
                        if directory.is_empty() || name.starts_with('/') {
                            name
                        } else {
                            format!("{directory}/{name}")
                        }
                    })
                    .unwrap_or_default();
                let file = symbols.intern_file(file_cache, name);
                unit_files.insert(index, file);
                file
            }
        };
        symbols.push_line(
            row.address(),
            file,
            u32::try_from(line.get()).unwrap_or(u32::MAX),
        );
        if symbols.truncated {
            return;
        }
    }
}
