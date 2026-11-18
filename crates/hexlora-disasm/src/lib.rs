//! Bounded, read-only disassembly preview for PE, ELF, and Mach-O images.
//!
//! This is a linear disassembler with function discovery from the facts a file
//! states about itself: its entry point, exports, symbol tables, unwind data,
//! and stub tables. It names call targets and referenced strings. It does not
//! recover control flow graphs, follow indirect jumps, or decompile; those
//! belong to the dedicated tools Hexlora hands off to.
//!
//! The image is never loaded or executed. Every listing is capped by an
//! instruction and byte budget, and discovery is capped by a function count.

use hexlora_core::{HexloraError, Result};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

mod arm64;
mod image;
mod x86;

/// Most functions kept by discovery.
pub const MAX_FUNCTIONS: usize = 1_000_000;
/// Hard ceiling on one listing, whatever the caller asks for.
pub const MAX_LISTING_INSTRUCTIONS: usize = 50_000;
pub const DEFAULT_LISTING_INSTRUCTIONS: usize = 2_000;
/// Longest string shown beside an instruction that references it.
const MAX_STRING_PREVIEW: usize = 80;
const MIN_STRING_PREVIEW: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86,
    X86_64,
    Arm64,
}

impl Architecture {
    pub fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
        }
    }
}

/// A mapped range of the image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Region {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    /// Bytes of the range present in the file; the rest is zero-filled.
    pub file_size: u64,
    pub executable: bool,
}

impl Region {
    fn contains(&self, address: u64) -> bool {
        address >= self.address && address - self.address < self.size
    }
}

/// How a function start was found. Ordered from most to least authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionSource {
    Entry,
    Export,
    Symbol,
    DebugInfo,
    TlsCallback,
    Stub,
    Unwind,
    FunctionStarts,
}

impl FunctionSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Entry => "Entry point",
            Self::Export => "Export",
            Self::Symbol => "Symbol",
            Self::DebugInfo => "Debug info",
            Self::TlsCallback => "TLS callback",
            Self::Stub => "Import stub",
            Self::Unwind => "Unwind data",
            Self::FunctionStarts => "Function starts",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    pub address: u64,
    pub size: Option<u64>,
    /// The name as the file spells it, possibly mangled.
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub source: FunctionSource,
}

impl Function {
    /// A readable name: demangled, raw, or synthesized from the address.
    pub fn display_name(&self) -> String {
        match (&self.demangled, &self.name, self.source) {
            (Some(name), _, _) => name.clone(),
            (None, Some(name), _) => name.clone(),
            (None, None, FunctionSource::Entry) => "entry".into(),
            (None, None, FunctionSource::TlsCallback) => format!("tls_callback_{:x}", self.address),
            (None, None, _) => format!("sub_{:x}", self.address),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    /// Execution continues with the next instruction.
    Next,
    Call,
    Jump,
    ConditionalJump,
    Return,
    /// A breakpoint, trap, or undefined instruction.
    Trap,
    /// Bytes that do not decode as an instruction.
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub flow: FlowKind,
    /// Direct branch or call destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    /// What the instruction refers to: a function, an import, or a string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The function's known or inferred end was reached.
    FunctionEnd,
    /// The next known function begins here.
    NextFunction,
    InstructionLimit,
    /// The mapped, file-backed bytes ran out.
    EndOfData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listing {
    pub start: u64,
    /// The function the listing starts in, when one is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    pub instructions: Vec<Instruction>,
    pub end: EndReason,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_instructions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_instructions: DEFAULT_LISTING_INSTRUCTIONS,
        }
    }
}

/// The disassembler's view of one image: where code and data are mapped and
/// which function starts are known. It holds no file bytes; pass the same
/// bytes it was discovered from to `disassemble`.
#[derive(Debug, Clone)]
pub struct Program {
    pub architecture: Architecture,
    /// The preferred load address of a PE image; zero for other formats.
    pub image_base: u64,
    /// Whether the file's own tables (and Hexlora's other views) give
    /// addresses relative to `image_base`. True for PE.
    pub relative_tables: bool,
    pub entry: Option<u64>,
    pub regions: Vec<Region>,
    /// Sorted by address, one per address.
    pub functions: Vec<Function>,
    pub functions_truncated: bool,
    /// Pointer slot (IAT, GOT, lazy pointer) → imported name.
    slots: HashMap<u64, String>,
}

/// Collects function starts, keeping the most authoritative description of each.
#[derive(Default)]
pub(crate) struct FunctionSet {
    functions: BTreeMap<u64, Function>,
    truncated: bool,
}

impl FunctionSet {
    pub(crate) fn add(
        &mut self,
        address: u64,
        size: Option<u64>,
        name: Option<String>,
        source: FunctionSource,
    ) {
        let name = name.filter(|name| !name.is_empty());
        let size = size.filter(|size| *size > 0);
        if let Some(existing) = self.functions.get_mut(&address) {
            if existing.name.is_none() {
                existing.name = name;
            }
            if existing.size.is_none() {
                existing.size = size;
            }
            existing.source = existing.source.min(source);
            return;
        }
        if self.functions.len() >= MAX_FUNCTIONS {
            self.truncated = true;
            return;
        }
        self.functions.insert(
            address,
            Function {
                address,
                size,
                name,
                demangled: None,
                source,
            },
        );
    }
}

impl Program {
    /// Reads the layout and known function starts of an image.
    ///
    /// `slice` selects an architecture inside a universal Mach-O; it is ignored
    /// for other formats.
    pub fn discover(bytes: &[u8], slice: Option<usize>) -> Result<Self> {
        std::panic::catch_unwind(|| image::discover(bytes, slice)).unwrap_or_else(|_| {
            Err(HexloraError::Malformed(
                "image layout could not be read for disassembly".into(),
            ))
        })
    }

    pub(crate) fn assemble(
        architecture: Architecture,
        image_base: u64,
        relative_tables: bool,
        entry: Option<u64>,
        mut regions: Vec<Region>,
        functions: FunctionSet,
        slots: HashMap<u64, String>,
    ) -> Self {
        regions.retain(|region| region.size > 0);
        regions.sort_by_key(|region| region.address);
        let mut program = Self {
            architecture,
            image_base,
            relative_tables,
            entry,
            regions,
            functions: Vec::new(),
            functions_truncated: functions.truncated,
            slots,
        };
        // A function start outside executable bytes is a data symbol or a
        // corrupt table entry.
        program.functions = functions
            .functions
            .into_values()
            .filter(|function| program.is_code(function.address))
            .collect();
        program
    }

    /// Adds functions from debug information. `relative` says whether the
    /// addresses are relative to the image base.
    pub fn add_debug_functions(
        &mut self,
        functions: impl IntoIterator<Item = (String, u64, Option<u64>)>,
        relative: bool,
    ) {
        let mut set = FunctionSet {
            functions: std::mem::take(&mut self.functions)
                .into_iter()
                .map(|function| (function.address, function))
                .collect(),
            truncated: self.functions_truncated,
        };
        for (name, address, size) in functions {
            let address = if relative {
                self.image_base.wrapping_add(address)
            } else {
                address
            };
            if self.is_code(address) {
                set.add(address, size, Some(name), FunctionSource::DebugInfo);
            }
        }
        self.functions_truncated = set.truncated;
        self.functions = set.functions.into_values().collect();
    }

    /// Fills in readable names using `demangle`, for at most `limit` functions.
    pub fn demangle_with(&mut self, limit: usize, demangle: impl Fn(&str) -> Option<String>) {
        let mut rewritten = 0usize;
        for function in &mut self.functions {
            if rewritten >= limit {
                break;
            }
            if function.demangled.is_none()
                && let Some(name) = &function.name
                && let Some(demangled) = demangle(name)
            {
                function.demangled = Some(demangled);
                rewritten += 1;
            }
        }
    }

    pub fn region_at(&self, address: u64) -> Option<&Region> {
        let index = self
            .regions
            .partition_point(|region| region.address <= address);
        // Regions can overlap in malformed files; look back a few entries.
        self.regions[..index]
            .iter()
            .rev()
            .take(8)
            .find(|region| region.contains(address))
    }

    pub fn is_code(&self, address: u64) -> bool {
        self.region_at(address)
            .is_some_and(|region| region.executable && address - region.address < region.file_size)
    }

    /// The file-backed bytes mapped at `address`, at most `length` of them.
    pub fn bytes_at<'a>(&self, bytes: &'a [u8], address: u64, length: usize) -> Option<&'a [u8]> {
        let region = self.region_at(address)?;
        let delta = address - region.address;
        if delta >= region.file_size {
            return None;
        }
        let available = usize::try_from(region.file_size - delta).ok()?.min(length);
        let start = usize::try_from(region.file_offset.checked_add(delta)?).ok()?;
        let end = start.checked_add(available)?.min(bytes.len());
        bytes.get(start..end).filter(|slice| !slice.is_empty())
    }

    /// The file offset holding the byte mapped at `address`.
    pub fn file_offset(&self, address: u64) -> Option<u64> {
        let region = self.region_at(address)?;
        let delta = address - region.address;
        (delta < region.file_size).then(|| region.file_offset + delta)
    }

    fn function_index_at_or_before(&self, address: u64) -> Option<usize> {
        self.functions
            .partition_point(|function| function.address <= address)
            .checked_sub(1)
    }

    /// The function containing `address`. A function of unknown size is taken
    /// to run until the next known function in the same region.
    pub fn function_containing(&self, address: u64) -> Option<&Function> {
        let index = self.function_index_at_or_before(address)?;
        let function = &self.functions[index];
        match function.size {
            Some(size) => (address - function.address < size).then_some(function),
            None => {
                let region = self.region_at(function.address)?;
                region.contains(address).then_some(function)
            }
        }
    }

    fn next_function_after(&self, address: u64) -> Option<u64> {
        let index = self
            .functions
            .partition_point(|function| function.address <= address);
        self.functions.get(index).map(|function| function.address)
    }

    /// The name of the import a pointer slot is bound to.
    pub fn import_at(&self, slot: u64) -> Option<&str> {
        self.slots.get(&slot).map(String::as_str)
    }

    /// Converts an address from the file's own tables (an RVA for PE) to the
    /// virtual address listings use.
    pub fn table_address(&self, address: u64) -> u64 {
        if self.relative_tables {
            self.image_base.wrapping_add(address)
        } else {
            address
        }
    }

    /// Resolves what a user typed to an address: `entry`, a hexadecimal
    /// address (an RVA is accepted for PE), or a function name.
    pub fn resolve(&self, target: &str) -> Option<u64> {
        let target = target.trim();
        if target.eq_ignore_ascii_case("entry") {
            return self.entry;
        }
        let digits = target
            .strip_prefix("0x")
            .or_else(|| target.strip_prefix("0X"));
        if let Some(address) = digits.and_then(|digits| u64::from_str_radix(digits, 16).ok()) {
            if self.region_at(address).is_some() {
                return Some(address);
            }
            let rebased = self.table_address(address);
            return self.region_at(rebased).is_some().then_some(rebased);
        }
        let matches = |function: &&Function| {
            function.name.as_deref() == Some(target)
                || function.demangled.as_deref() == Some(target)
        };
        self.functions
            .iter()
            .find(matches)
            .or_else(|| {
                // Mach-O spells C symbols with a leading underscore.
                let underscored = format!("_{target}");
                self.functions
                    .iter()
                    .find(|function| function.name.as_deref() == Some(underscored.as_str()))
            })
            .map(|function| function.address)
    }

    /// A short label for an address: a function name, with an offset when the
    /// address is inside rather than at the start of it.
    pub fn label(&self, address: u64) -> Option<String> {
        let function = self.function_containing(address)?;
        // Only named functions make useful labels for interior addresses.
        if address == function.address {
            return Some(function.display_name());
        }
        (function.name.is_some() && function.size.is_some()).then(|| {
            format!(
                "{}+0x{:x}",
                function.display_name(),
                address - function.address
            )
        })
    }

    /// A quoted preview of a NUL-terminated ASCII or UTF-16LE string stored
    /// at `address`.
    pub fn string_at(&self, bytes: &[u8], address: u64) -> Option<String> {
        let data = self.bytes_at(bytes, address, MAX_STRING_PREVIEW * 2 + 2)?;
        let printable = |byte: u8| (0x20..0x7f).contains(&byte) || byte == b'\t';
        let escape = |text: String| {
            text.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\t', "\\t")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
        };
        let ascii: Vec<u8> = data
            .iter()
            .copied()
            .take_while(|byte| printable(*byte) || matches!(byte, b'\n' | b'\r'))
            .take(MAX_STRING_PREVIEW)
            .collect();
        let terminated = data.get(ascii.len()) == Some(&0) || ascii.len() == MAX_STRING_PREVIEW;
        if ascii.len() >= MIN_STRING_PREVIEW && terminated {
            let text = String::from_utf8_lossy(&ascii).into_owned();
            return Some(format!("\"{}\"", escape(text)));
        }
        let wide: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit < 0x7f && printable(*unit as u8))
            .take(MAX_STRING_PREVIEW)
            .collect();
        let terminated = data
            .get(wide.len() * 2..wide.len() * 2 + 2)
            .is_some_and(|pair| pair == [0, 0])
            || wide.len() == MAX_STRING_PREVIEW;
        if wide.len() >= MIN_STRING_PREVIEW && terminated {
            return Some(format!("L\"{}\"", escape(String::from_utf16_lossy(&wide))));
        }
        None
    }

    /// Describes a data address an instruction refers to.
    pub(crate) fn describe_data(&self, bytes: &[u8], address: u64) -> Option<String> {
        if let Some(import) = self.import_at(address) {
            return Some(import.to_string());
        }
        if self.is_code(address) {
            return self.label(address);
        }
        self.string_at(bytes, address)
    }

    /// Describes an immediate that happens to be a mapped address. A constant
    /// can land in the image by coincidence, so only an exact function start,
    /// an import slot, or a string is reported.
    pub(crate) fn describe_constant(&self, bytes: &[u8], address: u64) -> Option<String> {
        if let Some(import) = self.import_at(address) {
            return Some(import.to_string());
        }
        if self.is_code(address) {
            return self
                .function_containing(address)
                .filter(|function| function.address == address)
                .map(Function::display_name);
        }
        self.string_at(bytes, address)
    }

    /// Describes a call or jump destination: the function there, or the import
    /// behind it when the destination is a one-instruction stub.
    pub(crate) fn describe_code(&self, bytes: &[u8], address: u64) -> Option<String> {
        let named = self
            .function_containing(address)
            .filter(|function| function.address == address && function.name.is_some());
        if let Some(function) = named {
            return Some(function.display_name());
        }
        let stub = match self.architecture {
            Architecture::Arm64 => arm64::stub_target(self, bytes, address),
            Architecture::X86 | Architecture::X86_64 => x86::stub_target(self, bytes, address),
        };
        if let Some(import) = stub {
            return Some(format!("{import} (stub)"));
        }
        // An unnamed destination still gets a stable label to search for.
        self.label(address)
            .or_else(|| self.is_code(address).then(|| format!("sub_{address:x}")))
    }

    /// Disassembles linearly from `start` until the function ends, the next
    /// known function begins, or a limit is reached.
    pub fn disassemble(&self, bytes: &[u8], start: u64, limits: Limits) -> Result<Listing> {
        let region = self
            .region_at(start)
            .filter(|region| start - region.address < region.file_size)
            .ok_or_else(|| {
                HexloraError::Malformed(format!("0x{start:x} is not inside file-backed code"))
            })?;
        if !region.executable {
            return Err(HexloraError::Malformed(format!(
                "0x{start:x} is in {}, which is not executable",
                region.name
            )));
        }
        let function = self.function_containing(start);
        let region_end = region.address + region.file_size;
        // A function with a stated size ends there; otherwise the next known
        // function start is the furthest it can reach.
        let known_end = function
            .and_then(|function| {
                function
                    .size
                    .map(|size| function.address.saturating_add(size))
            })
            .filter(|end| *end > start);
        let next_function = self.next_function_after(start);
        let (end, bounded_by) = match (known_end, next_function) {
            (Some(end), _) => (end.min(region_end), EndReason::FunctionEnd),
            (None, Some(next)) if next < region_end => (next, EndReason::NextFunction),
            _ => (region_end, EndReason::EndOfData),
        };
        let window = self
            .bytes_at(
                bytes,
                start,
                usize::try_from(end - start).unwrap_or(usize::MAX),
            )
            .ok_or_else(|| HexloraError::Malformed("code bytes are not in the file".into()))?;
        let max = limits.max_instructions.clamp(1, MAX_LISTING_INSTRUCTIONS);
        // Without a stated size the next known function may be far away, with
        // undiscovered functions in between, so the end is inferred from the
        // code itself.
        let infer_end = known_end.is_none();
        let std::result::Result::Ok((mut instructions, mut reason)) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match self.architecture {
                Architecture::Arm64 => arm64::decode(self, bytes, window, start, max, infer_end),
                Architecture::X86 => x86::decode(self, bytes, window, start, max, infer_end, 32),
                Architecture::X86_64 => x86::decode(self, bytes, window, start, max, infer_end, 64),
            }))
        else {
            return Err(HexloraError::Malformed(
                "instruction decoding failed".into(),
            ));
        };
        if reason == Decoded::RanOut {
            // Padding between functions is not part of either.
            if bounded_by != EndReason::EndOfData {
                while instructions.len() > 1
                    && instructions.last().is_some_and(|last| last.is_padding())
                {
                    instructions.pop();
                }
            }
            reason = Decoded::Bounded;
        }
        let end = match reason {
            Decoded::Limit => EndReason::InstructionLimit,
            Decoded::Returned => EndReason::FunctionEnd,
            Decoded::Bounded | Decoded::RanOut => bounded_by,
        };
        Ok(Listing {
            start,
            function: function.map(Function::display_name),
            instructions,
            end,
        })
    }
}

impl Instruction {
    fn is_padding(&self) -> bool {
        self.flow == FlowKind::Invalid
            || matches!(self.text.as_str(), "int3" | "nop" | "udf #0x0")
            || self.text.starts_with("nop ")
            || self.bytes.iter().all(|byte| *byte == 0)
    }
}

/// Why an architecture decoder stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// The instruction budget was used up.
    Limit,
    /// A return or unconditional jump with nothing branching past it.
    Returned,
    /// The window given to the decoder was consumed.
    RanOut,
    Bounded,
}

/// Tracks whether a return or jump ends a function whose size is unknown: it
/// does when no earlier branch targets an address beyond it.
#[derive(Default)]
pub(crate) struct ExtentTracker {
    furthest_target: u64,
}

impl ExtentTracker {
    pub(crate) fn branch(&mut self, target: u64, window_start: u64, window_end: u64) {
        if target >= window_start && target < window_end {
            self.furthest_target = self.furthest_target.max(target);
        }
    }
    pub(crate) fn ends_at(&self, next_address: u64) -> bool {
        self.furthest_target < next_address
    }
}
