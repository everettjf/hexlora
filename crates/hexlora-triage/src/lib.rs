//! Static triage that needs no disassembler: readable symbol names, inferred
//! capabilities, and user-supplied pattern rules.
//!
//! Everything here reasons over already-parsed facts or performs a bounded
//! scan. Nothing loads, maps, or executes the inspected image.

pub mod capabilities;
pub mod demangle;
#[cfg(feature = "yara")]
pub mod yara;

pub use capabilities::{
    StringEvidence, StringScanner, apply_capabilities, capability_findings, detect_capabilities,
};
pub use demangle::{demangle, demangle_analysis};
