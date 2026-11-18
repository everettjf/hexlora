//! Demangling of Itanium C++, Rust, and MSVC symbol names.

use hexlora_core::{BinaryAnalysis, SymbolInfo};

/// Longer names are left as they are: real mangled names stay well below this,
/// and demangler work grows with input length.
const MAX_MANGLED_BYTES: usize = 4096;
/// Most symbols rewritten per table. The rest keep their raw names.
pub const MAX_DEMANGLED_PER_TABLE: usize = 200_000;

/// Returns the readable form of a mangled symbol, or `None` when the name is
/// not mangled or does not parse.
pub fn demangle(name: &str) -> Option<String> {
    if name.len() < 3 || name.len() > MAX_MANGLED_BYTES {
        return None;
    }
    // PE import thunks and some linkers prefix symbols.
    let name = name.strip_prefix("__imp_").unwrap_or(name);
    if name.starts_with('?') || name.starts_with("@?") {
        return demangle_msvc(name);
    }
    // Mach-O prepends one underscore to every C-level symbol.
    let itanium = if name.starts_with("__Z") || name.starts_with("__R") {
        &name[1..]
    } else {
        name
    };
    if !(itanium.starts_with("_Z") || itanium.starts_with("_R")) {
        return None;
    }
    guarded(|| {
        if let Ok(demangled) = rustc_demangle::try_demangle(itanium) {
            // The alternate form drops the trailing crate-disambiguating hash.
            return Some(format!("{demangled:#}"));
        }
        cpp_demangle::Symbol::new(itanium.as_bytes())
            .ok()
            .and_then(|symbol| symbol.demangle().ok())
    })
    .filter(|demangled| !demangled.is_empty() && demangled != name)
}

fn demangle_msvc(name: &str) -> Option<String> {
    guarded(|| {
        let flags = msvc_demangler::DemangleFlags::llvm();
        msvc_demangler::demangle(name, flags).ok()
    })
    .filter(|demangled| !demangled.is_empty() && demangled != name)
}

/// Symbol names come from untrusted files; a demangler bug must not take the
/// inspection down with it.
fn guarded(work: impl FnOnce() -> Option<String>) -> Option<String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .ok()
        .flatten()
}

fn demangle_table(symbols: &mut [SymbolInfo]) {
    let mut rewritten = 0usize;
    for symbol in symbols {
        if symbol.demangled.is_some() {
            continue;
        }
        if rewritten >= MAX_DEMANGLED_PER_TABLE {
            break;
        }
        if let Some(demangled) = demangle(&symbol.name) {
            symbol.demangled = Some(demangled);
            rewritten += 1;
        }
    }
}

/// Fills in readable names for the import, export, and symbol tables of an
/// analysis and of every architecture slice inside it.
pub fn demangle_analysis(analysis: &mut BinaryAnalysis) {
    demangle_table(&mut analysis.imports);
    demangle_table(&mut analysis.exports);
    demangle_table(&mut analysis.symbols);
    for slice in &mut analysis.slice_analyses {
        demangle_analysis(slice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_each_supported_scheme() {
        assert_eq!(
            demangle("_ZN3foo3barEv").as_deref(),
            Some("foo::bar()"),
            "Itanium C++"
        );
        assert_eq!(
            demangle("__ZN3foo3barEv").as_deref(),
            Some("foo::bar()"),
            "Mach-O underscore prefix"
        );
        assert_eq!(
            demangle("_ZN4core3fmt5Write9write_fmt17h0123456789abcdefE").as_deref(),
            Some("core::fmt::Write::write_fmt"),
            "legacy Rust, hash dropped"
        );
        assert_eq!(
            demangle("_RNvCs1234_7mycrate3foo").as_deref(),
            Some("mycrate::foo"),
            "Rust v0"
        );
        let msvc = demangle("?bar@foo@@YAHXZ").expect("MSVC name demangles");
        assert!(msvc.contains("foo::bar"), "{msvc}");
        let import = demangle("__imp_?bar@foo@@YAHXZ").expect("import thunk demangles");
        assert!(import.contains("foo::bar"), "{import}");
    }

    #[test]
    fn leaves_plain_and_hostile_names_alone() {
        for name in ["main", "_start", "CreateFileW", "", "_Z", "?", "_R"] {
            assert_eq!(demangle(name), None, "{name:?}");
        }
        assert_eq!(demangle(&format!("_Z{}", "N".repeat(8192))), None);
        // Deep nesting inside the length limit must return, not overflow.
        let nested = format!("_Z{}", "P".repeat(4000));
        let _ = demangle(&nested);
        let nested = format!("?{}", "@".repeat(4000));
        let _ = demangle(&nested);
    }

    #[test]
    fn rewrites_every_table_and_slice() {
        let symbol = |name: &str| SymbolInfo {
            name: name.into(),
            address: None,
            library: None,
            demangled: None,
        };
        let mut analysis = BinaryAnalysis {
            imports: vec![symbol("_ZN3foo3barEv"), symbol("malloc")],
            slice_analyses: vec![BinaryAnalysis {
                exports: vec![symbol("__ZN3foo3barEv")],
                ..Default::default()
            }],
            ..Default::default()
        };
        demangle_analysis(&mut analysis);
        assert_eq!(analysis.imports[0].display_name(), "foo::bar()");
        assert_eq!(analysis.imports[1].display_name(), "malloc");
        assert_eq!(
            analysis.slice_analyses[0].exports[0].display_name(),
            "foo::bar()"
        );
    }
}
