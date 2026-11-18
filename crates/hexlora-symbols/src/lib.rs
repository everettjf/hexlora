//! Function names and source lines from local debug information.
//!
//! Reads a PDB the user supplies or that sits next to a PE image, and DWARF
//! embedded in an ELF or Mach-O file or in a companion `.dSYM`/`.debug` file.
//! Nothing is downloaded: there is no symbol-server client here. A symbol file
//! is used only when its identity matches the image it is offered for.

use hexlora_core::{HexloraError, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

mod dwarf;
mod pdb;

/// Most functions kept from one symbol file.
pub const MAX_FUNCTIONS: usize = 500_000;
/// Most address-to-line records kept from one symbol file.
pub const MAX_LINES: usize = 2_000_000;
/// Largest symbol file opened.
pub const MAX_SYMBOL_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// A line record further than this before an address does not describe it.
const MAX_LINE_DISTANCE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolFormat {
    Pdb,
    Dwarf,
}

impl SymbolFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pdb => "PDB",
            Self::Dwarf => "DWARF",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionSymbol {
    /// The linkage name when the debug information has one, otherwise the
    /// source-level name. Linkage names may be mangled.
    pub name: String,
    pub address: u64,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LineRecord {
    address: u64,
    file: u32,
    /// Zero marks the end of a sequence: no line applies from here on.
    line: u32,
}

/// Debug information for one image.
#[derive(Debug, Clone)]
pub struct DebugSymbols {
    pub format: SymbolFormat,
    /// The file the information was read from.
    pub path: PathBuf,
    /// GUID and age for a PDB; UUID or build ID for DWARF, when present.
    pub identity: Option<String>,
    /// Whether addresses are relative to the image base (PDB) or absolute
    /// virtual addresses (DWARF).
    pub relative_addresses: bool,
    /// Sorted by address, one entry per address.
    pub functions: Vec<FunctionSymbol>,
    pub compile_units: usize,
    /// Set when a limit cut the function or line list short.
    pub truncated: bool,
    files: Vec<String>,
    lines: Vec<LineRecord>,
}

/// What a report says about loaded debug information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebugSymbolSummary {
    pub format: SymbolFormat,
    pub path: PathBuf,
    pub identity: Option<String>,
    pub functions: usize,
    pub line_records: usize,
    pub source_files: usize,
    pub compile_units: usize,
    pub truncated: bool,
}

impl DebugSymbols {
    fn new(format: SymbolFormat, path: &Path) -> Self {
        Self {
            format,
            path: path.to_path_buf(),
            identity: None,
            relative_addresses: format == SymbolFormat::Pdb,
            functions: Vec::new(),
            compile_units: 0,
            truncated: false,
            files: Vec::new(),
            lines: Vec::new(),
        }
    }

    fn push_function(&mut self, name: String, address: u64, size: Option<u64>) {
        if self.functions.len() >= MAX_FUNCTIONS {
            self.truncated = true;
            return;
        }
        self.functions.push(FunctionSymbol {
            name,
            address,
            size,
        });
    }

    fn intern_file(
        &mut self,
        cache: &mut std::collections::HashMap<String, u32>,
        name: String,
    ) -> u32 {
        if let Some(index) = cache.get(&name) {
            return *index;
        }
        let index = self.files.len() as u32;
        self.files.push(name.clone());
        cache.insert(name, index);
        index
    }

    fn push_line(&mut self, address: u64, file: u32, line: u32) {
        if self.lines.len() >= MAX_LINES {
            self.truncated = true;
            return;
        }
        self.lines.push(LineRecord {
            address,
            file,
            line,
        });
    }

    fn finish(&mut self) {
        // Prefer the entry with a known size when two describe one address.
        self.functions
            .sort_by(|a, b| a.address.cmp(&b.address).then(b.size.cmp(&a.size)));
        self.functions.dedup_by_key(|function| function.address);
        // A real line wins over an end-of-sequence marker at the same address.
        self.lines
            .sort_by(|a, b| a.address.cmp(&b.address).then(b.line.cmp(&a.line)));
        self.lines.dedup_by_key(|line| line.address);
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn source_file_count(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.lines.is_empty()
    }

    /// The function whose known extent contains `address`, or that starts
    /// exactly there when its size is unknown.
    pub fn function_at(&self, address: u64) -> Option<&FunctionSymbol> {
        let index = self
            .functions
            .partition_point(|function| function.address <= address);
        let function = self.functions.get(index.checked_sub(1)?)?;
        match function.size {
            Some(size) => (address - function.address < size.max(1)).then_some(function),
            None => (function.address == address).then_some(function),
        }
    }

    /// The source file and line that produced the code at `address`.
    pub fn line_at(&self, address: u64) -> Option<(&str, u32)> {
        let index = self.lines.partition_point(|line| line.address <= address);
        let record = self.lines.get(index.checked_sub(1)?)?;
        if record.line == 0 || address - record.address > MAX_LINE_DISTANCE {
            return None;
        }
        Some((self.files.get(record.file as usize)?.as_str(), record.line))
    }

    pub fn summary(&self) -> DebugSymbolSummary {
        DebugSymbolSummary {
            format: self.format,
            path: self.path.clone(),
            identity: self.identity.clone(),
            functions: self.functions.len(),
            line_records: self.lines.len(),
            source_files: self.files.len(),
            compile_units: self.compile_units,
            truncated: self.truncated,
        }
    }
}

fn io_error(path: &Path, source: std::io::Error) -> HexloraError {
    HexloraError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn is_pdb(prefix: &[u8]) -> bool {
    prefix.starts_with(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS")
}

/// A `.dSYM` bundle keeps its DWARF in `Contents/Resources/DWARF/<name>`.
fn resolve_dsym(path: &Path) -> PathBuf {
    if !path.is_dir() {
        return path.to_path_buf();
    }
    let dwarf = path.join("Contents/Resources/DWARF");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&dwarf)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|candidate| candidate.is_file())
                .collect()
        })
        .unwrap_or_default();
    candidates.sort();
    candidates.into_iter().next().unwrap_or(dwarf)
}

/// Looks next to an image for the symbol file its build would have produced.
/// Only the image's own directory (and, for a bundle executable, the bundle's
/// directory) is consulted.
pub fn find_companion(image_path: &Path, image: &[u8]) -> Option<PathBuf> {
    let directory = image_path.parent()?;
    let file_name = image_path.file_name()?.to_str()?;
    if let Some(identity) = pdb::image_identity(image) {
        let recorded = identity
            .file_name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default();
        let stem = image_path.file_stem()?.to_str()?;
        for name in [recorded.to_string(), format!("{stem}.pdb")] {
            if name.is_empty() {
                continue;
            }
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        return None;
    }
    let mut candidates = vec![
        directory.join(format!("{file_name}.dSYM")),
        directory.join(format!("{file_name}.debug")),
    ];
    // `Foo.app/Contents/MacOS/Foo` ↔ `Foo.app.dSYM` beside the bundle.
    for ancestor in image_path.ancestors().skip(1).take(4) {
        let is_bundle = ancestor.extension().is_some_and(|extension| {
            ["app", "framework", "appex", "bundle", "plugin", "xpc"]
                .iter()
                .any(|known| extension.eq_ignore_ascii_case(known))
        });
        if let (true, Some(name), Some(parent)) = (
            is_bundle,
            ancestor.file_name().and_then(|name| name.to_str()),
            ancestor.parent(),
        ) {
            candidates.push(parent.join(format!("{name}.dSYM")));
        }
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.exists())
        .map(|candidate| resolve_dsym(&candidate))
        .filter(|candidate| candidate.is_file())
}

/// Options for loading debug information.
pub struct LoadOptions<'a> {
    /// A symbol file the user chose. Without one, DWARF embedded in the image
    /// is used, then a companion file beside it.
    pub explicit: Option<&'a Path>,
    /// Preferred architecture inside a universal Mach-O (`arm64`, `x86_64`).
    pub architecture: Option<&'a str>,
    /// Polled during long loads; returning true abandons the load.
    pub should_stop: &'a (dyn Fn() -> bool + Sync),
}

fn read_symbol_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.len() > MAX_SYMBOL_FILE_BYTES {
        return Err(HexloraError::Limit(format!(
            "symbol file {} exceeds {MAX_SYMBOL_FILE_BYTES} bytes",
            path.display()
        )));
    }
    std::fs::read(path).map_err(|source| io_error(path, source))
}

/// Loads debug information for an image.
///
/// `image_path` is where the image lives on disk, when it does; it is used to
/// find companion files and is reported as the source of embedded DWARF.
/// Returns `Ok(None)` when no debug information is available, and an error
/// when a symbol file was found but is unreadable or belongs to another build.
pub fn load(
    image_path: Option<&Path>,
    image: &[u8],
    options: &LoadOptions<'_>,
) -> Result<Option<DebugSymbols>> {
    let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        load_inner(image_path, image, options)
    }));
    guarded.unwrap_or_else(|_| {
        Err(HexloraError::Malformed(
            "debug information could not be parsed".into(),
        ))
    })
}

fn load_inner(
    image_path: Option<&Path>,
    image: &[u8],
    options: &LoadOptions<'_>,
) -> Result<Option<DebugSymbols>> {
    let embedded_path = image_path.unwrap_or(Path::new("<image>"));
    let load_file = |path: &Path| -> Result<Option<DebugSymbols>> {
        let path = resolve_dsym(path);
        let bytes = read_symbol_file(&path)?;
        if is_pdb(&bytes) {
            return pdb::load(&path, bytes, image, options).map(Some);
        }
        let expected = dwarf::image_identity(image, options.architecture);
        let symbols = dwarf::load(&path, &bytes, options)?;
        if let (Some(expected), Some(symbols)) = (&expected, &symbols)
            && let Some(found) = &symbols.identity
            && found != expected
        {
            return Err(HexloraError::Malformed(format!(
                "{} was built from a different image (expected {expected}, found {found})",
                path.display()
            )));
        }
        Ok(symbols)
    };
    if let Some(explicit) = options.explicit {
        return match load_file(explicit)? {
            Some(symbols) => Ok(Some(symbols)),
            None => Err(HexloraError::Malformed(format!(
                "{} contains no PDB or DWARF debug information",
                explicit.display()
            ))),
        };
    }
    if let Some(symbols) = dwarf::load(embedded_path, image, options)? {
        return Ok(Some(symbols));
    }
    match image_path.and_then(|path| find_companion(path, image)) {
        Some(companion) => load_file(&companion),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbols() -> DebugSymbols {
        let mut symbols = DebugSymbols::new(SymbolFormat::Dwarf, Path::new("demo"));
        let mut cache = std::collections::HashMap::new();
        let main = symbols.intern_file(&mut cache, "main.c".into());
        let again = symbols.intern_file(&mut cache, "main.c".into());
        assert_eq!(main, again);
        symbols.push_function("sized".into(), 0x1000, Some(0x20));
        symbols.push_function("unsized".into(), 0x2000, None);
        symbols.push_function("duplicate".into(), 0x1000, None);
        symbols.push_line(0x1000, main, 10);
        symbols.push_line(0x1008, main, 11);
        symbols.push_line(0x1020, main, 0);
        symbols.push_line(0x1020, main, 0);
        symbols.finish();
        symbols
    }

    #[test]
    fn function_lookup_respects_known_extents() {
        let symbols = symbols();
        assert_eq!(symbols.functions.len(), 2);
        assert_eq!(
            symbols.function_at(0x1000).map(|f| f.name.as_str()),
            Some("sized")
        );
        assert_eq!(
            symbols.function_at(0x101f).map(|f| f.name.as_str()),
            Some("sized")
        );
        assert!(symbols.function_at(0x1020).is_none());
        assert!(symbols.function_at(0xfff).is_none());
        assert_eq!(
            symbols.function_at(0x2000).map(|f| f.name.as_str()),
            Some("unsized")
        );
        assert!(symbols.function_at(0x2001).is_none());
    }

    #[test]
    fn line_lookup_stops_at_sequence_ends_and_far_addresses() {
        let symbols = symbols();
        assert_eq!(symbols.line_at(0x1000), Some(("main.c", 10)));
        assert_eq!(symbols.line_at(0x1007), Some(("main.c", 10)));
        assert_eq!(symbols.line_at(0x100f), Some(("main.c", 11)));
        assert_eq!(symbols.line_at(0x1020), None);
        assert_eq!(symbols.line_at(0x5000), None);
        assert_eq!(symbols.line_at(0x10), None);
        assert_eq!(symbols.summary().line_records, 3);
    }

    #[test]
    fn garbage_inputs_yield_no_symbols_or_a_clean_error() {
        let never = || false;
        let options = LoadOptions {
            explicit: None,
            architecture: None,
            should_stop: &never,
        };
        for image in [&b""[..], b"MZ", b"\x7fELF", &[0xffu8; 4096][..]] {
            assert!(matches!(load(None, image, &options), Ok(None)));
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let bogus = directory.path().join("bogus.pdb");
        std::fs::write(&bogus, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0garbage").expect("write");
        let options = LoadOptions {
            explicit: Some(&bogus),
            architecture: None,
            should_stop: &never,
        };
        assert!(load(None, b"MZ", &options).is_err());
        let text = directory.path().join("notes.txt");
        std::fs::write(&text, b"not debug information").expect("write");
        let options = LoadOptions {
            explicit: Some(&text),
            architecture: None,
            should_stop: &never,
        };
        assert!(load(None, b"MZ", &options).is_err());
    }
}
