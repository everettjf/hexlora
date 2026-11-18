//! Function and line information from a Microsoft PDB.

use crate::{DebugSymbols, LoadOptions, SymbolFormat};
use hexlora_core::{HexloraError, Result};
use pdb2::{FallibleIterator, PDB, SymbolData};
use std::{collections::HashMap, io::Cursor, path::Path};

/// The CodeView record a PE image carries to name its PDB.
pub(crate) struct ImageIdentity {
    pub guid: String,
    pub age: u32,
    pub file_name: String,
}

/// Formats a GUID stored in its on-disk mixed-endian layout the way the `uuid`
/// crate prints the same value.
fn format_guid(bytes: [u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

pub(crate) fn image_identity(image: &[u8]) -> Option<ImageIdentity> {
    if !image.starts_with(b"MZ") {
        return None;
    }
    let pe = goblin::pe::PE::parse(image).ok()?;
    let codeview = pe.debug_data?.codeview_pdb70_debug_info?;
    let file_name = codeview
        .filename
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    Some(ImageIdentity {
        guid: format_guid(codeview.signature),
        age: codeview.age,
        file_name: String::from_utf8_lossy(file_name).into_owned(),
    })
}

fn malformed(path: &Path, error: impl std::fmt::Display) -> HexloraError {
    HexloraError::Malformed(format!("PDB {}: {error}", path.display()))
}

pub(crate) fn load(
    path: &Path,
    bytes: memmap2::Mmap,
    image: &[u8],
    options: &LoadOptions<'_>,
) -> Result<DebugSymbols> {
    let mut pdb = PDB::open(Cursor::new(bytes)).map_err(|error| malformed(path, error))?;
    let information = pdb
        .pdb_information()
        .map_err(|error| malformed(path, error))?;
    let guid = information.guid.to_string();
    if let Some(expected) = image_identity(image)
        && expected.guid != guid
    {
        return Err(HexloraError::Malformed(format!(
            "{} was built from a different image (the image expects PDB {}, age {}; this PDB is {guid})",
            path.display(),
            expected.guid,
            expected.age
        )));
    }
    let mut symbols = DebugSymbols::new(SymbolFormat::Pdb, path);
    symbols.identity = Some(format!("{guid}, age {}", information.age));

    let address_map = pdb.address_map().map_err(|error| malformed(path, error))?;
    let string_table = pdb.string_table().ok();
    let debug_information = pdb
        .debug_information()
        .map_err(|error| malformed(path, error))?;
    let mut file_cache = HashMap::new();
    let mut modules = debug_information
        .modules()
        .map_err(|error| malformed(path, error))?;
    // A damaged module stream ends the walk but keeps what was read so far.
    while let Ok(Some(module)) = modules.next() {
        if (options.should_stop)() {
            return Err(HexloraError::Cancelled);
        }
        let Ok(Some(module_info)) = pdb.module_info(&module) else {
            continue;
        };
        symbols.compile_units += 1;
        let program = module_info.line_program().ok();
        let Ok(mut records) = module_info.symbols() else {
            continue;
        };
        while let Ok(Some(record)) = records.next() {
            let Ok(SymbolData::Procedure(procedure)) = record.parse() else {
                continue;
            };
            let Some(rva) = procedure.offset.to_rva(&address_map) else {
                continue;
            };
            let start = rva.0 as u64;
            symbols.push_function(
                procedure.name.to_string().into_owned(),
                start,
                Some(procedure.len as u64),
            );
            let (Some(program), Some(string_table)) = (&program, &string_table) else {
                continue;
            };
            let mut lines = program.lines_for_symbol(procedure.offset);
            while let Ok(Some(line)) = lines.next() {
                let Some(line_rva) = line.offset.to_rva(&address_map) else {
                    continue;
                };
                let Ok(file) = program.get_file_info(line.file_index) else {
                    continue;
                };
                let Ok(name) = file.name.to_string_lossy(string_table) else {
                    continue;
                };
                let file = symbols.intern_file(&mut file_cache, name.into_owned());
                symbols.push_line(line_rva.0 as u64, file, line.line_start);
            }
            symbols.push_line(start + procedure.len as u64, 0, 0);
            if symbols.truncated {
                break;
            }
        }
        if symbols.truncated {
            break;
        }
    }
    // Public symbols name functions that have no procedure record, such as
    // those from objects built without debug information.
    if let Ok(globals) = pdb.global_symbols() {
        let mut records = globals.iter();
        while let Ok(Some(record)) = records.next() {
            if let Ok(SymbolData::Public(public)) = record.parse()
                && public.function
                && let Some(rva) = public.offset.to_rva(&address_map)
            {
                symbols.push_function(public.name.to_string().into_owned(), rva.0 as u64, None);
            }
        }
    }
    symbols.finish();
    Ok(symbols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_prints_like_the_uuid_crate() {
        let bytes = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(format_guid(bytes), "00112233-4455-6677-8899-aabbccddeeff");
    }
}
