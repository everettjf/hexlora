//! Disassembly preview and debug symbols for one file node.

use crate::{ArtifactReader, CancellationToken};
use hexlora_core::{ArtifactNode, ArtifactSource, HexloraError, Result};
use hexlora_disasm::{EndReason, FlowKind, Function, Limits, Program};
use hexlora_symbols::{DebugSymbolSummary, DebugSymbols, LoadOptions};
use memmap2::{Mmap, MmapOptions};
use serde::Serialize;
use std::{fs::File, ops::Deref, path::Path};

/// Most functions a report lists for one binary.
pub const MAX_REPORTED_FUNCTIONS: usize = hexlora_disasm::MAX_FUNCTIONS;

/// The complete contents of a file node: mapped for files on disk, read into
/// memory (under the binary parse limit) for archive members.
pub enum NodeBytes {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl Deref for NodeBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(map) => map,
            Self::Owned(bytes) => bytes,
        }
    }
}

pub fn open_node_bytes(node: &ArtifactNode) -> Result<NodeBytes> {
    match node.source.as_ref() {
        Some(ArtifactSource::ArchiveMember { .. } | ArtifactSource::ContainerFile { .. }) => {
            Ok(NodeBytes::Owned(
                ArtifactReader::open(node)?.read_all(hexlora_format::MAX_PARSE_BYTES)?,
            ))
        }
        _ => {
            let io = |source| HexloraError::Io {
                path: node.path.clone(),
                source,
            };
            let file = File::open(&node.path).map_err(io)?;
            let length = file.metadata().map_err(io)?.len();
            if length == 0 {
                return Ok(NodeBytes::Owned(Vec::new()));
            }
            if length > hexlora_format::MAX_PARSE_BYTES {
                return Err(HexloraError::Limit(format!(
                    "binary parser limit is {} bytes",
                    hexlora_format::MAX_PARSE_BYTES
                )));
            }
            Ok(NodeBytes::Mapped(
                unsafe { MmapOptions::new().map(&file) }.map_err(io)?,
            ))
        }
    }
}

/// One line of a listing, with the source location that produced it when
/// debug information is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeLine {
    pub address: u64,
    /// The instruction's bytes as lowercase hexadecimal.
    pub bytes: String,
    pub text: String,
    pub flow: FlowKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeListing {
    pub start: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    pub end: EndReason,
    pub lines: Vec<CodeLine>,
}

impl CodeListing {
    /// Renders the listing as text: address, bytes, instruction, and a
    /// trailing comment, with a marker line whenever the source line changes.
    pub fn to_text(&self) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        if let Some(function) = &self.function {
            let _ = writeln!(text, "{function}:");
        }
        let mut last_source: Option<(&str, u32)> = None;
        for line in &self.lines {
            let source = line.source_file.as_deref().zip(line.source_line);
            if source.is_some() && source != last_source {
                let (file, number) = source.unwrap_or_default();
                let _ = writeln!(text, "  ; {file}:{number}");
            }
            last_source = source;
            let _ = write!(
                text,
                "  0x{:08x}  {:<24}  {}",
                line.address, line.bytes, line.text
            );
            if let Some(comment) = &line.comment {
                let padding = 34usize.saturating_sub(line.text.chars().count());
                let _ = write!(text, "{:padding$}  ; {comment}", "");
            }
            text.push('\n');
        }
        let _ = writeln!(
            text,
            "  ; {}",
            match self.end {
                EndReason::FunctionEnd => "end of function",
                EndReason::NextFunction => "next function begins",
                EndReason::InstructionLimit => "instruction limit reached; more follows",
                EndReason::EndOfData => "end of mapped code",
            }
        );
        text
    }
}

/// Everything needed to list code from one binary: its layout and function
/// starts, its bytes, and its debug symbols when any were found.
pub struct CodeView {
    pub program: Program,
    pub symbols: Option<DebugSymbols>,
    /// Why debug symbols that were found or requested could not be used.
    pub symbol_error: Option<String>,
    bytes: NodeBytes,
}

impl CodeView {
    /// Opens a binary for disassembly.
    ///
    /// `slice` selects an architecture of a universal Mach-O. `symbol_file`
    /// names a PDB, dSYM, or debug file to use; without it, embedded DWARF and
    /// then a companion file beside the binary are tried.
    pub fn open(
        node: &ArtifactNode,
        slice: Option<usize>,
        symbol_file: Option<&Path>,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        cancel.check()?;
        let bytes = open_node_bytes(node)?;
        let mut program = Program::discover(&bytes, slice)?;
        cancel.check()?;
        let on_disk = matches!(node.source, Some(ArtifactSource::Filesystem { .. }) | None);
        let should_stop = || cancel.is_cancelled();
        let loaded = hexlora_symbols::load(
            on_disk.then_some(node.path.as_path()),
            &bytes,
            &LoadOptions {
                explicit: symbol_file,
                architecture: Some(program.architecture.label()),
                should_stop: &should_stop,
            },
        );
        cancel.check()?;
        let (symbols, symbol_error) = match loaded {
            Ok(symbols) => (symbols, None),
            Err(HexloraError::Cancelled) => return Err(HexloraError::Cancelled),
            Err(error) => (None, Some(error.to_string())),
        };
        if let Some(symbols) = &symbols {
            program.add_debug_functions(
                symbols
                    .functions
                    .iter()
                    .map(|function| (function.name.clone(), function.address, function.size)),
                symbols.relative_addresses,
            );
        }
        program.demangle_with(
            hexlora_triage::demangle::MAX_DEMANGLED_PER_TABLE,
            hexlora_triage::demangle,
        );
        Ok(Self {
            program,
            symbols,
            symbol_error,
            bytes,
        })
    }

    pub fn functions(&self) -> &[Function] {
        &self.program.functions
    }

    pub fn symbol_summary(&self) -> Option<DebugSymbolSummary> {
        self.symbols.as_ref().map(DebugSymbols::summary)
    }

    fn source_at(&self, address: u64) -> Option<(&str, u32)> {
        let symbols = self.symbols.as_ref()?;
        let address = if symbols.relative_addresses {
            address.checked_sub(self.program.image_base)?
        } else {
            address
        };
        symbols.line_at(address)
    }

    /// Lists code starting at `address`.
    pub fn listing(&self, address: u64, limits: Limits) -> Result<CodeListing> {
        let listing = self.program.disassemble(&self.bytes, address, limits)?;
        let lines = listing
            .instructions
            .into_iter()
            .map(|instruction| {
                let source = self.source_at(instruction.address);
                CodeLine {
                    address: instruction.address,
                    bytes: hex::encode(&instruction.bytes),
                    text: instruction.text,
                    flow: instruction.flow,
                    target: instruction.target,
                    comment: instruction.comment,
                    source_file: source.map(|(file, _)| file.to_string()),
                    source_line: source.map(|(_, line)| line),
                }
            })
            .collect();
        Ok(CodeListing {
            start: listing.start,
            function: listing.function,
            end: listing.end,
            lines,
        })
    }

    /// Lists code at what a user typed: `entry`, a hexadecimal address, or a
    /// function name.
    pub fn listing_at(&self, target: &str, limits: Limits) -> Result<CodeListing> {
        let address = self.program.resolve(target).ok_or_else(|| {
            HexloraError::Malformed(format!(
                "\"{target}\" is not an address in this image or a known function"
            ))
        })?;
        self.listing(address, limits)
    }

    /// The file offset of the byte mapped at `address`, for jumping to it in
    /// a hex view.
    pub fn file_offset(&self, address: u64) -> Option<u64> {
        self.program.file_offset(address)
    }
}
