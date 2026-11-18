//! Local YARA rule scanning through the pure-Rust `boreal` engine.
//!
//! Rules come from a file or directory the user names. Hexlora ships no rules
//! and downloads none. A match means a pattern the rule author wrote occurs in
//! the file; what that implies is up to the rule.

use hexlora_core::{Finding, FindingCategory, HexloraError, Result, Severity};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// Most rule files compiled from one directory.
const MAX_RULE_FILES: usize = 2_000;
const MAX_RULE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RULE_DIRECTORY_DEPTH: usize = 8;
/// Time allowed for one scan of one file.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(60);
/// Occurrences recorded per rule; the rest are counted.
const MAX_RECORDED_OCCURRENCES: usize = 32;

/// A compiled rule set, ready to scan any number of buffers.
#[derive(Clone)]
pub struct YaraRules {
    scanner: boreal::Scanner,
    rule_count: usize,
    files: Vec<PathBuf>,
    warnings: Vec<String>,
}

impl std::fmt::Debug for YaraRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraRules")
            .field("rule_count", &self.rule_count)
            .field("files", &self.files)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct YaraOccurrence {
    /// The rule's string identifier, such as `$a`.
    pub identifier: String,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// The rule's `description` metadata, when it has one.
    pub description: Option<String>,
    /// The rule's `severity` or `threat_level` metadata mapped to a severity.
    pub severity: Option<Severity>,
    pub occurrences: Vec<YaraOccurrence>,
    /// Occurrences found beyond the recorded ones.
    pub more_occurrences: u64,
}

impl YaraMatch {
    /// The identifier policies use for this rule.
    pub fn rule_id(&self) -> String {
        if self.namespace.is_empty() || self.namespace == "default" {
            format!("yara.{}", self.rule)
        } else {
            format!("yara.{}.{}", self.namespace, self.rule)
        }
    }
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yar") || extension.eq_ignore_ascii_case("yara")
        })
}

fn collect_rule_files(directory: &Path, depth: usize, files: &mut Vec<PathBuf>) -> Result<()> {
    if depth > MAX_RULE_DIRECTORY_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(directory).map_err(|source| HexloraError::Io {
        path: directory.into(),
        source,
    })?;
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    // Directory order is not stable across platforms; rule order must be.
    paths.sort();
    for path in paths {
        // Symbolic links are not followed out of the chosen directory.
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            collect_rule_files(&path, depth + 1, files)?;
        } else if metadata.is_file() && is_rule_file(&path) {
            if files.len() >= MAX_RULE_FILES {
                return Err(HexloraError::Limit(format!(
                    "more than {MAX_RULE_FILES} YARA rule files in {}",
                    directory.display()
                )));
            }
            files.push(path);
        }
    }
    Ok(())
}

impl YaraRules {
    /// Compiles one rule file, or every `.yar`/`.yara` file below a directory.
    /// Rules from a directory are placed in a namespace named after their file
    /// so equally named rules in different files do not collide.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path).map_err(|source| HexloraError::Io {
            path: path.into(),
            source,
        })?;
        let mut files = Vec::new();
        let from_directory = metadata.is_dir();
        if from_directory {
            collect_rule_files(path, 0, &mut files)?;
            if files.is_empty() {
                return Err(HexloraError::Malformed(format!(
                    "no .yar or .yara files in {}",
                    path.display()
                )));
            }
        } else {
            files.push(path.to_path_buf());
        }
        let mut compiler = boreal::Compiler::new();
        let mut warnings = Vec::new();
        for file in &files {
            let size = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
            if size > MAX_RULE_FILE_BYTES {
                return Err(HexloraError::Limit(format!(
                    "YARA rule file {} exceeds {MAX_RULE_FILE_BYTES} bytes",
                    file.display()
                )));
            }
            let status = if from_directory {
                let namespace = file
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("rules");
                compiler.add_rules_file_in_namespace(file, namespace)
            } else {
                compiler.add_rules_file(file)
            }
            .map_err(|error| {
                HexloraError::Malformed(format!("YARA rules in {}: {error}", file.display()))
            })?;
            warnings.extend(
                status
                    .warnings()
                    .map(|warning| format!("{}: {warning}", file.display())),
            );
        }
        let mut scanner = compiler.finalize();
        scanner.set_scan_params(
            boreal::scanner::ScanParams::default().timeout_duration(Some(SCAN_TIMEOUT)),
        );
        let rule_count = scanner.rules().count();
        if rule_count == 0 {
            return Err(HexloraError::Malformed(format!(
                "{} defines no YARA rules",
                path.display()
            )));
        }
        Ok(Self {
            scanner,
            rule_count,
            files,
            warnings,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Compiler warnings, one per line, already prefixed with their file.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Scans one buffer and returns the rules that matched, in rule order.
    pub fn scan(&self, bytes: &[u8]) -> Result<Vec<YaraMatch>> {
        let result = match self.scanner.scan_mem(bytes) {
            Ok(result) => result,
            Err((boreal::scanner::ScanError::Timeout, _)) => {
                return Err(HexloraError::Limit(format!(
                    "YARA scan exceeded {} seconds",
                    SCAN_TIMEOUT.as_secs()
                )));
            }
            Err((error, _)) => return Err(HexloraError::Malformed(format!("YARA scan: {error}"))),
        };
        let mut matches = Vec::new();
        for rule in result.rules.iter().filter(|rule| rule.matched) {
            let mut description = None;
            let mut severity = None;
            for metadata in rule.metadatas {
                let name = self.scanner.get_string_symbol(metadata.name);
                let text = match metadata.value {
                    boreal::MetadataValue::Bytes(symbol) => {
                        String::from_utf8_lossy(self.scanner.get_bytes_symbol(symbol)).into_owned()
                    }
                    boreal::MetadataValue::Integer(value) => value.to_string(),
                    boreal::MetadataValue::Boolean(value) => value.to_string(),
                };
                if name.eq_ignore_ascii_case("description") {
                    description = Some(text);
                } else if name.eq_ignore_ascii_case("severity")
                    || name.eq_ignore_ascii_case("threat_level")
                {
                    severity = parse_severity(&text);
                }
            }
            let mut occurrences = Vec::new();
            let mut more_occurrences = 0u64;
            for string in &rule.matches {
                for found in &string.matches {
                    if occurrences.len() < MAX_RECORDED_OCCURRENCES {
                        occurrences.push(YaraOccurrence {
                            identifier: format!("${}", string.name),
                            offset: (found.base + found.offset) as u64,
                            length: found.length as u64,
                        });
                    } else {
                        more_occurrences += 1;
                    }
                }
            }
            occurrences.sort_by_key(|occurrence| occurrence.offset);
            matches.push(YaraMatch {
                rule: rule.name.to_string(),
                namespace: rule.namespace.to_string(),
                tags: rule
                    .tags
                    .iter()
                    .map(|tag| self.scanner.get_string_symbol(*tag).to_string())
                    .collect(),
                description,
                severity,
                occurrences,
                more_occurrences,
            });
        }
        Ok(matches)
    }
}

/// Maps the free-form severity metadata rule authors use onto a severity.
fn parse_severity(text: &str) -> Option<Severity> {
    match text.trim().to_ascii_lowercase().as_str() {
        "critical" | "5" => Some(Severity::Critical),
        "high" | "4" => Some(Severity::High),
        "medium" | "moderate" | "3" => Some(Severity::Medium),
        "low" | "2" => Some(Severity::Low),
        "info" | "informational" | "1" | "0" => Some(Severity::Info),
        other => other
            .parse::<u32>()
            .ok()
            // Some rule sets score from 0 to 100.
            .map(|score| match score {
                0..=20 => Severity::Info,
                21..=40 => Severity::Low,
                41..=60 => Severity::Medium,
                61..=80 => Severity::High,
                _ => Severity::Critical,
            }),
    }
}

/// Turns rule matches into findings. A rule without severity metadata is
/// reported as medium: someone wrote the rule to be noticed, but Hexlora cannot
/// know how serious a match is.
pub fn yara_findings(matches: &[YaraMatch]) -> Vec<Finding> {
    matches
        .iter()
        .map(|found| {
            let mut description = found
                .description
                .clone()
                .unwrap_or_else(|| "A user-supplied YARA rule matched this file.".into());
            description.push_str(" This is a pattern match; what it implies depends on the rule.");
            let mut finding = Finding::new(
                found.severity.unwrap_or(Severity::Medium),
                FindingCategory::Pattern,
                format!("YARA rule matched: {}", found.rule),
                description,
            )
            .with_rule(found.rule_id());
            if !found.tags.is_empty() {
                finding = finding.with_evidence("Tags", found.tags.join(", "));
            }
            for occurrence in &found.occurrences {
                finding = finding.with_evidence_at(
                    occurrence.identifier.clone(),
                    format!("{} bytes at 0x{:x}", occurrence.length, occurrence.offset),
                    occurrence.offset,
                );
            }
            if found.more_occurrences > 0 {
                finding = finding.with_evidence(
                    "More occurrences",
                    format!("{} not listed", found.more_occurrences),
                );
            }
            finding
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule marker_text : demo packed {
    meta:
        description = "Contains the demo marker."
        severity = "high"
    strings:
        $a = "HEXLORA-MARKER"
        $b = { 4d 5a 90 00 }
    condition:
        $a or $b
}
rule never_matches {
    strings:
        $a = "this-string-is-absent"
    condition:
        $a
}
"#;

    fn write(directory: &Path, name: &str, text: &str) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, text).expect("write rule file");
        path
    }

    #[test]
    fn matches_report_offsets_metadata_and_stable_rule_ids() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let rules =
            YaraRules::load(&write(directory.path(), "demo.yar", RULES)).expect("rules compile");
        assert_eq!(rules.rule_count(), 2);

        let matches = rules
            .scan(b"....HEXLORA-MARKER....HEXLORA-MARKER")
            .expect("scan completes");
        assert_eq!(matches.len(), 1);
        let found = &matches[0];
        assert_eq!(found.rule, "marker_text");
        assert_eq!(found.rule_id(), "yara.marker_text");
        assert_eq!(found.tags, ["demo", "packed"]);
        assert_eq!(found.severity, Some(Severity::High));
        assert_eq!(found.occurrences[0].identifier, "$a");
        assert_eq!(found.occurrences[0].offset, 4);
        assert_eq!(found.occurrences[0].length, 14);

        let findings = yara_findings(&matches);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].category, FindingCategory::Pattern);
        assert_eq!(findings[0].rule_id.as_deref(), Some("yara.marker_text"));
        assert!(
            findings[0]
                .description
                .starts_with("Contains the demo marker.")
        );
        assert_eq!(findings[0].evidence[1].offset, Some(4));

        assert!(rules.scan(b"nothing to see").expect("scan").is_empty());
        assert!(rules.scan(&[]).expect("empty scan").is_empty());
    }

    #[test]
    fn directories_compile_in_per_file_namespaces() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).expect("nested directory");
        let rule = "rule same_name { strings: $a = \"HEXLORA-MARKER\" condition: $a }";
        write(directory.path(), "first.yar", rule);
        write(&nested, "second.YARA", rule);
        write(directory.path(), "notes.txt", "not a rule file {{{");

        let rules = YaraRules::load(directory.path()).expect("directory compiles");
        assert_eq!(rules.files().len(), 2);
        let mut ids: Vec<String> = rules
            .scan(b"HEXLORA-MARKER")
            .expect("scan")
            .iter()
            .map(YaraMatch::rule_id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["yara.first.same_name", "yara.second.same_name"]);
    }

    #[test]
    fn bad_rule_sources_are_reported_not_panicked() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let broken = write(directory.path(), "broken.yar", "rule { this is not yara");
        let error = YaraRules::load(&broken).expect_err("syntax error is rejected");
        assert!(error.to_string().contains("broken.yar"), "{error}");

        let empty = write(directory.path(), "empty.yar", "// no rules here\n");
        assert!(YaraRules::load(&empty).is_err());
        assert!(YaraRules::load(&directory.path().join("missing.yar")).is_err());

        let bare = tempfile::tempdir().expect("temporary directory");
        assert!(YaraRules::load(bare.path()).is_err());
    }

    #[test]
    fn severity_metadata_accepts_words_and_scores() {
        assert_eq!(parse_severity("Critical"), Some(Severity::Critical));
        assert_eq!(parse_severity(" low "), Some(Severity::Low));
        assert_eq!(parse_severity("75"), Some(Severity::High));
        assert_eq!(parse_severity("3"), Some(Severity::Medium));
        assert_eq!(parse_severity("unknown"), None);
    }
}
