use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hexlora_analysis::{
    CancellationToken, CodeListing, CodeView, DebugSymbolSummary, FunctionSource, HashOptions,
    Limits, analyze_node, annotate_string_locations, apply_capability_strings,
    apply_signature_analysis, build_dependency_graph, enrich_analysis_entropy, enrich_triage,
    extract_strings_node_cancellable, hash_node, inspect_metadata, inspect_signature_cancellable,
    open_artifact, resolve_dependencies, scan_capability_strings,
};
use hexlora_android::{AndroidAuditReportV1, audit_apk, is_apk};
use hexlora_compare::{CompareReportV1, compare_artifacts};
use hexlora_core::{
    ArtifactKind, ArtifactNode, BinaryAnalysis, DependencyGraph, FileSummary, Finding, Severity,
    SignatureInfo,
};
use hexlora_ios::{IpaAuditReportV1, IpaViewCompatibleReport, audit_ipa, ipa_view_compatible};
use hexlora_linux::{DebianReportV1, audit_deb, is_deb};
use hexlora_policy::{
    PolicyViolation, ReleasePolicyV1, evaluate_android, evaluate_capabilities, evaluate_compare,
    evaluate_generic, evaluate_ipa, evaluate_linux, evaluate_windows,
};
use hexlora_windows::{WindowsPackageReportV1, audit_msix, is_msix};
use indexmap::IndexMap;
use serde::Serialize;
use std::{
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "hexlora-cli",
    version,
    about = "Static application, package, and binary inspection",
    after_help = "Discord: https://discord.gg/eGzEaP6TzR"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a file, application, package, or directory and emit JSON.
    Inspect(InspectArgs),
    /// Compare two artifacts and emit deterministic file, size, and IPA semantic differences.
    Compare(CompareArgs),
    /// List functions or disassemble code from a PE, ELF, or Mach-O binary.
    Disasm(DisasmArgs),
}

#[derive(Debug, Clone, Args)]
pub struct DisasmArgs {
    /// Binary to disassemble, or an application or package that contains it.
    pub path: PathBuf,

    /// Where to start: `entry`, a hexadecimal address such as 0x401000, or a
    /// function name. Repeat for several listings. Defaults to `entry`.
    #[arg(long = "at", value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Select the binary inside an application or package, by name or path suffix.
    #[arg(long, value_name = "NAME")]
    pub file: Option<String>,

    /// Architecture slice of a universal Mach-O, by index or name (arm64, x86_64).
    #[arg(long, value_name = "SLICE")]
    pub slice: Option<String>,

    /// Most instructions per listing.
    #[arg(long, default_value_t = 200, value_parser = parse_instruction_count)]
    pub count: usize,

    /// List the discovered functions instead of disassembling.
    #[arg(long)]
    pub functions: bool,

    /// Most functions listed by --functions.
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_functions)]
    pub max_functions: usize,

    /// PDB, dSYM, or debug file with symbols for this binary. Without it,
    /// embedded DWARF and a matching file beside the binary are used.
    #[arg(long, value_name = "FILE")]
    pub symbols: Option<PathBuf>,

    /// Emit JSON instead of text.
    #[arg(long)]
    pub json: bool,

    /// Pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,

    /// Write to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct CompareArgs {
    /// Baseline artifact path.
    pub before: PathBuf,
    /// Candidate artifact path.
    pub after: PathBuf,
    /// Write JSON to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,
    /// Exit with status 2 when installed-size growth exceeds this many bytes.
    #[arg(long)]
    pub max_growth_bytes: Option<i128>,
    /// Versioned JSON release policy.
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct InspectArgs {
    /// Artifact path to inspect.
    pub path: PathBuf,

    /// Write JSON to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,

    /// Accepted for explicitness; JSON is the stable default output format.
    #[arg(long)]
    pub json: bool,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    pub format: ReportFormat,

    /// Analysis depth. Deep enables SHA-256, entropy, strings, signatures, and graph building.
    #[arg(long, value_enum, default_value_t = AnalysisDepth::Standard)]
    pub depth: AnalysisDepth,

    /// Identification hashes to compute (comma-separated).
    #[arg(long = "hash", value_enum, value_delimiter = ',')]
    pub hashes: Vec<HashAlgorithm>,

    /// Extract strings from every regular file.
    #[arg(long)]
    pub strings: bool,

    /// Compute whole-file and binary-section entropy.
    #[arg(long)]
    pub entropy: bool,

    /// Run host signature verification where supported.
    #[arg(long)]
    pub signature: bool,

    /// Build the complete Artifact dependency graph.
    #[arg(long)]
    pub dependencies: bool,

    /// Minimum extracted string length.
    #[arg(long, default_value_t = 4, value_parser = parse_min_string_length)]
    pub min_string_length: usize,

    /// Maximum strings retained per file.
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_strings)]
    pub max_strings: usize,

    /// Search each binary for the strings capability rules look for. Without
    /// this, capabilities are inferred from imports alone.
    #[arg(long)]
    pub capabilities: bool,

    /// List the functions discovered in each binary, with debug symbols when
    /// they are embedded or sit beside it.
    #[arg(long)]
    pub functions: bool,

    /// Maximum functions listed per binary.
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_functions)]
    pub max_functions: usize,

    /// Scan every file with the YARA rules in this file or directory.
    #[cfg(feature = "yara")]
    #[arg(long, value_name = "RULES")]
    pub yara: Option<PathBuf>,

    /// Exit with status 2 if this severity or higher is found.
    #[arg(long, value_enum)]
    pub fail_on: Option<SeverityThreshold>,
    /// Versioned JSON release policy.
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AnalysisDepth {
    Lightweight,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HashAlgorithm {
    Sha256,
    Sha1,
    Md5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityThreshold {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Json,
    Markdown,
    Html,
    Sarif,
}

fn parse_bounded_usize(value: &str, minimum: usize, maximum: usize) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("expected an integer from {minimum} to {maximum}"))?;
    if (minimum..=maximum).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(format!("expected a value from {minimum} to {maximum}"))
    }
}

fn parse_min_string_length(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 2, 1024)
}

fn parse_max_strings(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 1, 1_000_000)
}

fn parse_max_functions(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 1, hexlora_analysis::code::MAX_REPORTED_FUNCTIONS)
}

fn parse_instruction_count(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 1, hexlora_analysis::MAX_LISTING_INSTRUCTIONS)
}

#[derive(Debug, Serialize)]
pub struct InspectionReport {
    pub schema_version: u32,
    pub generator: GeneratorInfo,
    pub artifact: ArtifactNode,
    pub artifact_signature: Option<SignatureInfo>,
    pub files: Vec<FileReport>,
    pub dependency_graph: Option<DependencyGraph>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipa: Option<IpaAuditReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipa_view_compatibility: Option<IpaViewCompatibleReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android: Option<AndroidAuditReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_package: Option<WindowsPackageReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_package: Option<DebianReportV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_violations: Vec<PolicyViolation>,
    pub findings: Vec<ReportFinding>,
    pub run: RunInfo,
}

#[derive(Debug, Serialize)]
pub struct GeneratorInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct FileReport {
    pub artifact_id: uuid::Uuid,
    pub path: PathBuf,
    pub kind: ArtifactKind,
    pub size: u64,
    pub summary: FileSummary,
    pub analysis: Option<BinaryAnalysis>,
    pub metadata: IndexMap<String, String>,
    pub strings: Option<Vec<ReportString>>,
    /// Discovered functions, one entry per architecture slice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Vec<ReportCode>>,
    /// YARA rules that matched this file.
    #[cfg(feature = "yara")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yara: Option<Vec<hexlora_analysis::YaraMatch>>,
    pub errors: Vec<ReportError>,
}

#[derive(Debug, Serialize)]
pub struct ReportCode {
    pub architecture: &'static str,
    pub image_base: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<u64>,
    /// Functions discovered, which can exceed the number listed.
    pub function_count: usize,
    /// Set when discovery or the listing limit left functions out.
    pub functions_truncated: bool,
    pub functions: Vec<ReportFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_symbols: Option<DebugSymbolSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_symbols_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportFunction {
    pub address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub name: String,
    /// The name as the file spells it, when it differs from `name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_name: Option<String>,
    pub source: FunctionSource,
}

fn report_code(view: &CodeView, max_functions: usize) -> ReportCode {
    let functions = view.functions();
    ReportCode {
        architecture: view.program.architecture.label(),
        image_base: view.program.image_base,
        entry: view.program.entry,
        function_count: functions.len(),
        functions_truncated: view.program.functions_truncated || functions.len() > max_functions,
        functions: functions
            .iter()
            .take(max_functions)
            .map(|function| {
                let name = function.display_name();
                ReportFunction {
                    address: function.address,
                    size: function.size,
                    raw_name: function.name.clone().filter(|raw| *raw != name),
                    name,
                    source: function.source,
                }
            })
            .collect(),
        debug_symbols: view.symbol_summary(),
        debug_symbols_error: view.symbol_error.clone(),
    }
}

#[derive(Debug, Serialize)]
pub struct ReportString {
    pub offset: u64,
    pub encoding: String,
    pub value: String,
    pub section: Option<String>,
    pub virtual_address: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ReportFinding {
    pub path: PathBuf,
    #[serde(flatten)]
    pub finding: Finding,
}

#[derive(Debug, Serialize)]
pub struct ReportError {
    pub stage: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct RunInfo {
    pub started_at: DateTime<Utc>,
    pub duration_ms: u128,
    pub partial: bool,
    pub cancelled: bool,
    pub errors: Vec<ReportError>,
}

pub fn run() -> u8 {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect(args) => run_inspect(args),
        Command::Compare(args) => run_compare(args),
        Command::Disasm(args) => run_disasm(args),
    }
}

#[derive(Debug, Serialize)]
pub struct DisasmReport {
    pub schema_version: u32,
    pub path: PathBuf,
    #[serde(flatten)]
    pub code: ReportCode,
    pub listings: Vec<CodeListing>,
}

fn run_disasm(args: DisasmArgs) -> u8 {
    let cancellation = CancellationToken::default();
    let signal_token = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_token.cancel()) {
        eprintln!("warning: could not install Ctrl-C handler: {error}");
    }
    let report = match disassemble(&args, &cancellation) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("hexlora-cli: {error}");
            return if cancellation.is_cancelled() { 4 } else { 1 };
        }
    };
    let written = if args.json {
        write_json(&report, args.output.as_deref(), args.pretty)
    } else {
        write_bytes(
            render_disasm_text(&report, args.functions).trim_end(),
            args.output.as_deref(),
        )
    };
    match written {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("hexlora-cli: {error}");
            1
        }
    }
}

/// Picks the one binary a `disasm` invocation is about.
fn select_binary<'a>(
    artifact: &'a ArtifactNode,
    wanted: Option<&str>,
) -> hexlora_core::Result<&'a ArtifactNode> {
    use hexlora_core::FileFormat;
    let binaries: Vec<&ArtifactNode> = artifact
        .files()
        .filter(|node| {
            matches!(
                node.format,
                Some(FileFormat::Pe | FileFormat::MachO | FileFormat::FatMachO | FileFormat::Elf)
            )
        })
        .collect();
    let malformed = hexlora_core::HexloraError::Malformed;
    match wanted {
        Some(wanted) => {
            let normalized = wanted.replace('\\', "/");
            let mut matches = binaries.iter().copied().filter(|node| {
                node.name == wanted
                    || node
                        .path
                        .to_string_lossy()
                        .replace('\\', "/")
                        .ends_with(&normalized)
            });
            let first = matches.next().ok_or_else(|| {
                malformed(format!(
                    "no binary named \"{wanted}\" in {}",
                    artifact.path.display()
                ))
            })?;
            if matches.next().is_some() {
                return Err(malformed(format!(
                    "\"{wanted}\" matches more than one binary; give a longer path suffix"
                )));
            }
            Ok(first)
        }
        None => match binaries.as_slice() {
            [] => Err(malformed(format!(
                "{} contains no PE, ELF, or Mach-O binary",
                artifact.path.display()
            ))),
            [only] => Ok(only),
            many => Err(malformed(format!(
                "{} contains {} binaries; choose one with --file, for example --file {}",
                artifact.path.display(),
                many.len(),
                many[0].name
            ))),
        },
    }
}

/// Resolves `--slice` to an index: a number, or an architecture name looked up
/// in the binary's slices.
fn select_slice(node: &ArtifactNode, slice: Option<&str>) -> hexlora_core::Result<Option<usize>> {
    let Some(slice) = slice else {
        return Ok(None);
    };
    if let Ok(index) = slice.parse::<usize>() {
        return Ok(Some(index));
    }
    let analysis = analyze_node(node)?;
    analysis
        .as_ref()
        .and_then(|analysis| {
            analysis
                .slices
                .iter()
                // Slice labels carry a subtype, as in `arm64 (subtype 0)`.
                .position(|candidate| {
                    candidate
                        .architecture
                        .split_whitespace()
                        .next()
                        .is_some_and(|name| name.eq_ignore_ascii_case(slice))
                })
        })
        .map(Some)
        .ok_or_else(|| {
            hexlora_core::HexloraError::Malformed(format!(
                "{} has no \"{slice}\" slice",
                node.path.display()
            ))
        })
}

pub fn disassemble(
    args: &DisasmArgs,
    cancellation: &CancellationToken,
) -> hexlora_core::Result<DisasmReport> {
    let artifact = open_artifact(&args.path, cancellation)?;
    let node = select_binary(&artifact, args.file.as_deref())?;
    let slice = select_slice(node, args.slice.as_deref())?;
    let view = CodeView::open(node, slice, args.symbols.as_deref(), cancellation)?;
    // Symbols the user asked for by name must load; a companion file that
    // merely happens to sit beside the binary may fail quietly.
    if let (Some(path), Some(error)) = (&args.symbols, &view.symbol_error) {
        return Err(hexlora_core::HexloraError::Malformed(format!(
            "symbols from {}: {error}",
            path.display()
        )));
    }
    let limits = Limits {
        max_instructions: args.count,
    };
    let mut listings = Vec::new();
    if !args.functions {
        let default_target = ["entry".to_string()];
        let targets = if args.targets.is_empty() {
            &default_target[..]
        } else {
            &args.targets[..]
        };
        for target in targets {
            cancellation.check()?;
            if target == "entry" && view.program.entry.is_none() {
                return Err(hexlora_core::HexloraError::Malformed(format!(
                    "{} has no entry point; pass --at with an address or function name (see --functions)",
                    node.path.display()
                )));
            }
            listings.push(view.listing_at(target, limits)?);
        }
    }
    let functions = if args.functions {
        args.max_functions
    } else {
        0
    };
    Ok(DisasmReport {
        schema_version: REPORT_SCHEMA_VERSION,
        path: node.path.clone(),
        code: report_code(&view, functions),
        listings,
    })
}

fn render_disasm_text(report: &DisasmReport, list_functions: bool) -> String {
    use std::fmt::Write;
    let code = &report.code;
    let mut text = format!(
        "; {}\n; {} · image base 0x{:x} · {} functions known\n",
        report.path.display(),
        code.architecture,
        code.image_base,
        code.function_count
    );
    if let Some(symbols) = &code.debug_symbols {
        let _ = writeln!(
            text,
            "; {} symbols from {} · {} functions · {} line records",
            symbols.format.label(),
            symbols.path.display(),
            symbols.functions,
            symbols.line_records
        );
    }
    if let Some(error) = &code.debug_symbols_error {
        let _ = writeln!(text, "; debug symbols not used: {error}");
    }
    if list_functions {
        text.push('\n');
        for function in &code.functions {
            let size = function
                .size
                .map(|size| format!("{size:>8}"))
                .unwrap_or_else(|| format!("{:>8}", "-"));
            let _ = writeln!(
                text,
                "0x{:08x}  {size}  {:<16}  {}",
                function.address,
                function.source.label(),
                function.name
            );
        }
        if code.functions_truncated {
            let _ = writeln!(
                text,
                "; {} of {} functions listed",
                code.functions.len(),
                code.function_count
            );
        }
    }
    for listing in &report.listings {
        text.push('\n');
        text.push_str(&listing.to_text());
    }
    text
}

fn run_compare(args: CompareArgs) -> u8 {
    let cancellation = CancellationToken::default();
    match compare(&args, &cancellation) {
        Ok(report) => {
            let policy = args.policy.as_deref().map(load_policy).transpose();
            let policy = match policy {
                Ok(policy) => policy,
                Err(error) => {
                    eprintln!("hexlora-cli: {error}");
                    return 1;
                }
            };
            let policy_violations = policy
                .as_ref()
                .map(|policy| evaluate_compare(policy, &report))
                .unwrap_or_default();
            let failed = !policy_violations.is_empty()
                || args
                    .max_growth_bytes
                    .is_some_and(|maximum| report.delta_bytes > maximum);
            let output = CompareOutput {
                report: &report,
                policy_violations: &policy_violations,
            };
            if let Err(error) = write_json(&output, args.output.as_deref(), args.pretty) {
                eprintln!("hexlora-cli: {error}");
                return 1;
            }
            if failed { 2 } else { 0 }
        }
        Err(error) => {
            eprintln!("hexlora-cli: {error}");
            1
        }
    }
}

#[derive(Serialize)]
struct CompareOutput<'a> {
    #[serde(flatten)]
    report: &'a CompareReportV1,
    #[serde(skip_serializing_if = "slice_is_empty")]
    policy_violations: &'a [PolicyViolation],
}

fn slice_is_empty<T>(values: &[T]) -> bool {
    values.is_empty()
}

fn load_policy(path: &Path) -> hexlora_core::Result<ReleasePolicyV1> {
    let bytes = std::fs::read(path).map_err(|source| hexlora_core::HexloraError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| hexlora_core::HexloraError::Malformed(format!("policy: {error}")))
}

pub fn compare(
    args: &CompareArgs,
    cancellation: &CancellationToken,
) -> hexlora_core::Result<CompareReportV1> {
    let before = open_artifact(&args.before, cancellation)?;
    let after = open_artifact(&args.after, cancellation)?;
    let before_ipa = is_ipa(&before)
        .then(|| audit_ipa(&before, cancellation))
        .transpose()?;
    let after_ipa = is_ipa(&after)
        .then(|| audit_ipa(&after, cancellation))
        .transpose()?;
    compare_artifacts(
        &before,
        &after,
        before_ipa.as_ref(),
        after_ipa.as_ref(),
        cancellation,
    )
}

fn is_ipa(artifact: &ArtifactNode) -> bool {
    artifact
        .properties
        .get("Package Format")
        .is_some_and(|format| format == "Apple iOS IPA")
}

fn run_inspect(args: InspectArgs) -> u8 {
    let cancellation = CancellationToken::default();
    let signal_token = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_token.cancel()) {
        eprintln!("warning: could not install Ctrl-C handler: {error}");
    }
    match inspect(&args, &cancellation) {
        Ok(report) => {
            let fail_on = args
                .fail_on
                .is_some_and(|threshold| report_reaches_threshold(&report, threshold))
                || !report.policy_violations.is_empty();
            let cancelled = report.run.cancelled;
            let partial = report.run.partial;
            if let Err(error) =
                write_report(&report, args.output.as_deref(), args.pretty, args.format)
            {
                eprintln!("hexlora-cli: {error}");
                return 1;
            }
            if cancelled {
                4
            } else if fail_on {
                2
            } else if partial {
                5
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!("hexlora-cli: {error}");
            if cancellation.is_cancelled() { 4 } else { 1 }
        }
    }
}

pub fn inspect(
    args: &InspectArgs,
    cancellation: &CancellationToken,
) -> hexlora_core::Result<InspectionReport> {
    let started_at = Utc::now();
    let started = Instant::now();
    let artifact = open_artifact(&args.path, cancellation)?;
    let deep = args.depth == AnalysisDepth::Deep;
    let parse_files = args.depth != AnalysisDepth::Lightweight;
    let want_entropy = args.entropy || deep;
    let want_strings = args.strings || deep;
    let want_signature = args.signature || deep;
    let want_graph = args.dependencies || deep;
    let hashes = if deep && args.hashes.is_empty() {
        vec![HashAlgorithm::Sha256]
    } else {
        args.hashes.clone()
    };
    let hash_options = HashOptions {
        sha256: hashes.contains(&HashAlgorithm::Sha256),
        sha1: hashes.contains(&HashAlgorithm::Sha1),
        md5: hashes.contains(&HashAlgorithm::Md5),
    };

    let want_capabilities = args.capabilities || deep;
    #[cfg(feature = "yara")]
    let yara_rules = args
        .yara
        .as_deref()
        .map(hexlora_analysis::YaraRules::load)
        .transpose()?;
    #[cfg(feature = "yara")]
    if let Some(rules) = &yara_rules {
        for warning in rules.warnings() {
            eprintln!("warning: YARA: {warning}");
        }
    }

    let mut files = Vec::new();
    let mut findings = Vec::new();
    let mut run_errors = Vec::new();
    for node in artifact.files() {
        if cancellation.check().is_err() {
            break;
        }
        let mut errors = Vec::new();
        if let Some(message) = node.properties.get("Read Error") {
            errors.push(ReportError {
                stage: "discovery",
                message: message.clone(),
            });
        }
        let mut analysis = if parse_files {
            match analyze_node(node) {
                Ok(analysis) => analysis,
                Err(error) => {
                    errors.push(ReportError {
                        stage: "binary_analysis",
                        message: error.to_string(),
                    });
                    None
                }
            }
        } else {
            None
        };
        if let Some(analysis) = &mut analysis {
            resolve_dependencies(analysis, &artifact);
            enrich_triage(analysis);
            if want_capabilities {
                match scan_capability_strings(node, cancellation) {
                    Ok(strings) => apply_capability_strings(analysis, &strings),
                    Err(error) => errors.push(ReportError {
                        stage: "capability_strings",
                        message: error.to_string(),
                    }),
                }
            }
            if want_entropy
                && !matches!(
                    node.source,
                    Some(
                        hexlora_core::ArtifactSource::ArchiveMember { .. }
                            | hexlora_core::ArtifactSource::ContainerFile { .. }
                    )
                )
                && let Err(error) = enrich_analysis_entropy(&node.path, analysis, cancellation)
            {
                errors.push(ReportError {
                    stage: "section_entropy",
                    message: error.to_string(),
                });
            }
            if want_signature
                && matches!(analysis.platform, Some(hexlora_core::BinaryPlatform::MacOs))
                && matches!(
                    node.source,
                    Some(hexlora_core::ArtifactSource::Filesystem { .. })
                )
            {
                match inspect_signature_cancellable(&node.path, cancellation) {
                    Ok(Some(signature)) => apply_signature_analysis(analysis, &signature),
                    Ok(None) => {}
                    Err(error) => errors.push(ReportError {
                        stage: "signature",
                        message: error.to_string(),
                    }),
                }
            }
            findings.extend(
                analysis
                    .findings
                    .iter()
                    .cloned()
                    .map(|finding| ReportFinding {
                        path: node.path.clone(),
                        finding,
                    }),
            );
        }

        let metadata = if parse_files {
            match inspect_metadata(node) {
                Ok(metadata) => metadata,
                Err(error) => {
                    errors.push(ReportError {
                        stage: "metadata",
                        message: error.to_string(),
                    });
                    IndexMap::new()
                }
            }
        } else {
            IndexMap::new()
        };

        let mut summary = FileSummary {
            size: node.size,
            sha256: None,
            sha1: None,
            md5: None,
            entropy: None,
            analysis: None,
        };
        if want_entropy || !hashes.is_empty() {
            match hash_node(node, hash_options, cancellation) {
                Ok(result) => summary = result,
                Err(error) => errors.push(ReportError {
                    stage: "hash_entropy",
                    message: error.to_string(),
                }),
            }
        }

        let strings = if want_strings {
            match extract_strings_node_cancellable(
                node,
                args.min_string_length,
                args.max_strings,
                cancellation,
            ) {
                Ok(mut strings) => {
                    if let Some(analysis) = analysis.as_ref() {
                        if analysis.slice_analyses.is_empty() {
                            annotate_string_locations(&mut strings, analysis);
                        } else {
                            for slice in &analysis.slice_analyses {
                                annotate_string_locations(&mut strings, slice);
                            }
                        }
                    }
                    Some(
                        strings
                            .into_iter()
                            .map(|string| ReportString {
                                offset: string.offset,
                                encoding: format!("{:?}", string.encoding),
                                value: string.value,
                                section: string.section,
                                virtual_address: string.virtual_address,
                            })
                            .collect(),
                    )
                }
                Err(error) => {
                    errors.push(ReportError {
                        stage: "strings",
                        message: error.to_string(),
                    });
                    None
                }
            }
        } else {
            None
        };
        let code = if args.functions && analysis.is_some() {
            let slices = analysis
                .as_ref()
                .map(|analysis| analysis.slice_analyses.len())
                .unwrap_or(0);
            let mut views = Vec::new();
            for slice in 0..slices.max(1) {
                match CodeView::open(node, (slices > 0).then_some(slice), None, cancellation) {
                    Ok(view) => views.push(report_code(&view, args.max_functions)),
                    Err(error) => errors.push(ReportError {
                        stage: "functions",
                        message: error.to_string(),
                    }),
                }
            }
            (!views.is_empty()).then_some(views)
        } else {
            None
        };
        #[cfg(feature = "yara")]
        let yara = match &yara_rules {
            Some(rules) => match hexlora_analysis::yara_scan_node(node, rules, cancellation) {
                Ok(matches) => {
                    findings.extend(hexlora_analysis::yara_findings(&matches).into_iter().map(
                        |finding| ReportFinding {
                            path: node.path.clone(),
                            finding,
                        },
                    ));
                    Some(matches)
                }
                Err(error) => {
                    errors.push(ReportError {
                        stage: "yara",
                        message: error.to_string(),
                    });
                    None
                }
            },
            None => None,
        };
        files.push(FileReport {
            artifact_id: node.id,
            path: node.path.clone(),
            kind: node.kind,
            size: node.size,
            summary,
            analysis,
            metadata,
            strings,
            code,
            #[cfg(feature = "yara")]
            yara,
            errors,
        });
    }

    // Anything discovery had to leave out makes the report partial rather than
    // silently complete.
    for key in [
        "Archive Members Unavailable",
        "Discovery Truncated",
        "Unreadable Entries",
        "Members Not Listed",
    ] {
        if let Some(message) = artifact.properties.get(key) {
            run_errors.push(ReportError {
                stage: "discovery",
                message: format!("{key}: {message}"),
            });
        }
    }
    let dependency_graph = if want_graph && !cancellation.is_cancelled() {
        match build_dependency_graph(&artifact, cancellation) {
            Ok(graph) => Some(graph),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "dependency_graph",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let artifact_signature = if want_signature
        && !cancellation.is_cancelled()
        && matches!(
            artifact.kind,
            ArtifactKind::Application
                | ArtifactKind::Bundle
                | ArtifactKind::Framework
                | ArtifactKind::Plugin
        ) {
        inspect_signature_cancellable(&artifact.path, cancellation).unwrap_or_else(|error| {
            run_errors.push(ReportError {
                stage: "artifact_signature",
                message: error.to_string(),
            });
            None
        })
    } else {
        None
    };
    let ipa = if artifact
        .properties
        .get("Package Format")
        .is_some_and(|format| format == "Apple iOS IPA")
    {
        match audit_ipa(&artifact, cancellation) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "ipa_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let ipa_view_compatibility = ipa.as_ref().map(ipa_view_compatible);
    let android = if is_apk(&artifact) {
        match audit_apk(&artifact, cancellation) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "android_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let windows_package = if is_msix(&artifact) {
        match audit_msix(&artifact, cancellation) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "windows_package_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let linux_package = if is_deb(&artifact.path) {
        match audit_deb(&artifact.path) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "linux_package_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let policy = args.policy.as_deref().map(load_policy).transpose()?;
    let mut policy_violations = Vec::new();
    if let Some(policy) = policy.as_ref() {
        let generic_findings = findings
            .iter()
            .map(|finding| finding.finding.clone())
            .collect::<Vec<_>>();
        let policy_artifact_bytes = ipa
            .as_ref()
            .map(|report| report.total_bytes)
            .or_else(|| linux_package.as_ref().map(|report| report.installed_bytes))
            .unwrap_or_else(|| files.iter().map(|file| file.size).sum());
        policy_violations.extend(evaluate_generic(
            policy,
            policy_artifact_bytes,
            &generic_findings,
        ));
        policy_violations.extend(evaluate_capabilities(
            policy,
            files.iter().flat_map(|file| {
                file.analysis.iter().flat_map(move |analysis| {
                    std::iter::once(analysis)
                        .chain(&analysis.slice_analyses)
                        .flat_map(|binary| &binary.capabilities)
                        .map(move |capability| (file.path.as_path(), capability))
                })
            }),
        ));
    }
    if let (Some(policy), Some(ipa)) = (policy.as_ref(), ipa.as_ref()) {
        policy_violations.extend(evaluate_ipa(policy, ipa));
    }
    if let (Some(policy), Some(android)) = (policy.as_ref(), android.as_ref()) {
        policy_violations.extend(evaluate_android(policy, android));
    }
    if let (Some(policy), Some(windows)) = (policy.as_ref(), windows_package.as_ref()) {
        policy_violations.extend(evaluate_windows(policy, windows));
    }
    if let (Some(policy), Some(linux)) = (policy.as_ref(), linux_package.as_ref()) {
        policy_violations.extend(evaluate_linux(policy, linux));
    }
    let partial = !run_errors.is_empty()
        || files.iter().any(|file| !file.errors.is_empty())
        || ipa.as_ref().is_some_and(|report| report.partial)
        || android.as_ref().is_some_and(|report| report.partial);
    Ok(InspectionReport {
        schema_version: REPORT_SCHEMA_VERSION,
        generator: GeneratorInfo {
            name: "Hexlora",
            version: env!("CARGO_PKG_VERSION"),
        },
        artifact,
        artifact_signature,
        files,
        dependency_graph,
        ipa,
        ipa_view_compatibility,
        android,
        windows_package,
        linux_package,
        policy_violations,
        findings,
        run: RunInfo {
            started_at,
            duration_ms: started.elapsed().as_millis(),
            partial,
            cancelled: cancellation.is_cancelled(),
            errors: run_errors,
        },
    })
}

fn write_report(
    report: &InspectionReport,
    output: Option<&Path>,
    pretty: bool,
    format: ReportFormat,
) -> io::Result<()> {
    match format {
        ReportFormat::Json => write_json(report, output, pretty),
        ReportFormat::Markdown => write_bytes(&render_markdown(report), output),
        ReportFormat::Html => write_bytes(&render_html(report), output),
        ReportFormat::Sarif => write_json(&render_sarif(report), output, pretty),
    }
}

fn write_bytes(contents: &str, output: Option<&Path>) -> io::Result<()> {
    write_output(output, |writer| {
        writer.write_all(contents.as_bytes())?;
        if output.is_none() {
            writer.write_all(b"\n")?;
        }
        Ok(())
    })
}

/// Write a report through a buffered writer. Regular files are replaced
/// atomically; devices, pipes and other special files such as `/dev/null`
/// cannot be renamed over, so they are written in place.
fn write_output(
    output: Option<&Path>,
    write: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    let Some(path) = output else {
        let mut writer = BufWriter::new(io::stdout().lock());
        write(&mut writer)?;
        return writer.flush();
    };
    if std::fs::metadata(path).is_ok_and(|metadata| !metadata.is_file() && !metadata.is_dir()) {
        let mut writer = BufWriter::new(std::fs::OpenOptions::new().write(true).open(path)?);
        write(&mut writer)?;
        return writer.flush();
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        write(&mut writer)?;
        writer.flush()?;
    }
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// Every finding in a report as (severity, title, evidence, rule ID).
fn all_report_findings(report: &InspectionReport) -> Vec<(Severity, String, String, String)> {
    let mut findings = report
        .findings
        .iter()
        .map(|item| {
            (
                item.finding.severity,
                item.finding.title.clone(),
                item.path.display().to_string(),
                item.finding.policy_rule_id(),
            )
        })
        .collect::<Vec<_>>();
    if let Some(ipa) = report.ipa.as_ref() {
        findings.extend(ipa.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence
                    .first()
                    .map(|evidence| evidence.path.display().to_string())
                    .unwrap_or_default(),
                item.rule_id.clone(),
            )
        }));
    }
    if let Some(android) = report.android.as_ref() {
        findings.extend(android.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence_path.display().to_string(),
                item.rule_id.clone(),
            )
        }));
    }
    if let Some(windows) = report.windows_package.as_ref() {
        findings.extend(windows.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence_path.display().to_string(),
                item.rule_id.clone(),
            )
        }));
    }
    if let Some(linux) = report.linux_package.as_ref() {
        findings.extend(linux.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence_path.display().to_string(),
                item.rule_id.clone(),
            )
        }));
    }
    findings.extend(report.policy_violations.iter().map(|violation| {
        (
            violation.severity,
            violation.message.clone(),
            format!("policy:{}", violation.rule_id),
            violation.rule_id.clone(),
        )
    }));
    findings
}

fn render_markdown(report: &InspectionReport) -> String {
    let mut output = format!(
        "# Hexlora inspection\n\n- Artifact: `{}`\n- Files: {}\n- Partial: {}\n",
        report.artifact.path.display(),
        report.files.len(),
        report.run.partial
    );
    if let Some(ipa) = report.ipa.as_ref() {
        output.push_str(&format!(
            "- Bundle ID: `{}`\n- Version: `{}` (`{}`)\n- Installed size: {} bytes\n",
            ipa.metadata.bundle_identifier.as_deref().unwrap_or(""),
            ipa.metadata.version.as_deref().unwrap_or(""),
            ipa.metadata.build.as_deref().unwrap_or(""),
            ipa.total_bytes
        ));
    }
    output.push_str("\n## Findings\n\n| Severity | Finding | Evidence |\n|---|---|---|\n");
    for (severity, title, evidence, _) in all_report_findings(report) {
        output.push_str(&format!(
            "| {severity:?} | {} | `{}` |\n",
            title.replace('|', "\\|"),
            evidence.replace('|', "\\|")
        ));
    }
    output
}

fn render_html(report: &InspectionReport) -> String {
    let rows = all_report_findings(report)
        .into_iter()
        .map(|(severity, title, evidence, _)| {
            format!(
                "<tr><td>{severity:?}</td><td>{}</td><td><code>{}</code></td></tr>",
                html_escape(&title),
                html_escape(&evidence)
            )
        })
        .collect::<String>();
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Hexlora inspection</title><style>body{{font:15px system-ui;max-width:1100px;margin:40px auto;color:#d7d3c6;background:#0d0c0a}}table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;border:1px solid #302d26;text-align:left}}h1{{color:#9bd568}}</style><h1>Hexlora inspection</h1><p><code>{}</code></p><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>",
        html_escape(&report.artifact.path.display().to_string())
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_sarif(report: &InspectionReport) -> serde_json::Value {
    let results = all_report_findings(report)
        .into_iter()
        .map(|(severity, title, evidence, rule_id)| {
            serde_json::json!({
                "ruleId": rule_id,
                "level": match severity { Severity::Critical | Severity::High => "error", Severity::Medium => "warning", _ => "note" },
                "message": { "text": title },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": evidence } } }]
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "Hexlora", "version": env!("CARGO_PKG_VERSION") } }, "results": results }]
    })
}

fn write_json(report: &impl Serialize, output: Option<&Path>, pretty: bool) -> io::Result<()> {
    write_output(output, |mut writer| {
        if pretty {
            serde_json::to_writer_pretty(&mut writer, report)?;
        } else {
            serde_json::to_writer(&mut writer, report)?;
        }
        writer.write_all(b"\n")
    })
}

fn report_reaches_threshold(report: &InspectionReport, threshold: SeverityThreshold) -> bool {
    let threshold = threshold_rank(threshold);
    all_report_findings(report)
        .iter()
        .any(|(severity, _, _, _)| severity_rank(*severity) >= threshold)
}

fn threshold_rank(severity: SeverityThreshold) -> u8 {
    match severity {
        SeverityThreshold::Info => 0,
        SeverityThreshold::Low => 1,
        SeverityThreshold::Medium => 2,
        SeverityThreshold::High => 3,
        SeverityThreshold::Critical => 4,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(path: PathBuf) -> InspectArgs {
        InspectArgs {
            path,
            output: None,
            pretty: false,
            json: true,
            format: ReportFormat::Json,
            depth: AnalysisDepth::Standard,
            hashes: vec![],
            strings: false,
            entropy: false,
            signature: false,
            dependencies: false,
            min_string_length: 4,
            max_strings: 100,
            capabilities: false,
            functions: false,
            max_functions: 10_000,
            #[cfg(feature = "yara")]
            yara: None,
            fail_on: None,
            policy: None,
        }
    }

    #[test]
    fn standard_report_is_versioned_and_serializable() {
        let root = std::env::temp_dir().join(format!("hexlora-cli-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("create CLI fixture");
        std::fs::write(root.join("metadata.json"), br#"{"name":"fixture"}"#)
            .expect("write CLI fixture");
        let report = inspect(&arguments(root.clone()), &CancellationToken::default())
            .expect("inspect CLI fixture");
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.files.len(), 1);
        let json = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(json["generator"]["name"], "Hexlora");
        assert_eq!(json["files"][0]["metadata"]["name"], "\"fixture\"");
        assert!(render_markdown(&report).starts_with("# Hexlora inspection"));
        assert!(render_html(&report).contains("<!doctype html>"));
        assert_eq!(render_sarif(&report)["version"], "2.1.0");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deep_defaults_to_sha256_and_expensive_analyses() {
        let path = std::env::temp_dir().join(format!("hexlora-cli-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"hello from Hexlora CLI").expect("write CLI fixture");
        let mut args = arguments(path.clone());
        args.depth = AnalysisDepth::Deep;
        let report = inspect(&args, &CancellationToken::default()).expect("deep CLI inspection");
        assert!(report.files[0].summary.sha256.is_some());
        assert!(report.files[0].summary.entropy.is_some());
        assert!(report.files[0].strings.is_some());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn reports_can_be_written_to_special_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample.bin");
        std::fs::write(&path, b"sample").unwrap();
        let report = inspect(&arguments(path), &CancellationToken::default()).unwrap();
        for format in [ReportFormat::Json, ReportFormat::Markdown] {
            write_report(&report, Some(Path::new("/dev/null")), false, format)
                .expect("a device cannot be renamed over, so it is written in place");
        }
        // Regular files are still replaced atomically and completely.
        let output = directory.path().join("report.json");
        std::fs::write(&output, "stale contents that are longer than nothing").unwrap();
        write_report(&report, Some(&output), false, ReportFormat::Json).unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(written["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn damaged_archive_yields_a_partial_report_instead_of_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("damaged.zip");
        std::fs::write(&path, b"PK\x03\x04 this is not a complete archive").unwrap();
        let report = inspect(&arguments(path), &CancellationToken::default())
            .expect("a damaged container is still inspected as a file");
        assert!(report.run.partial);
        assert!(
            report
                .run
                .errors
                .iter()
                .any(|error| error.stage == "discovery")
        );
        assert_eq!(report.files.len(), 1);
    }
}
