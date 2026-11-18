use std::process::Command;

#[test]
fn stdout_contains_only_machine_readable_json() {
    let directory = tempfile::tempdir().expect("create CLI fixture directory");
    let artifact = directory.path().join("artifact.json");
    std::fs::write(&artifact, br#"{"name":"fixture"}"#).expect("write CLI fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_hexlora-cli"))
        .args([
            "inspect",
            artifact.to_str().expect("UTF-8 fixture path"),
            "--json",
        ])
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse stdout JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["run"]["partial"], false);
}

#[test]
fn output_file_is_complete_and_pretty_printed() {
    let directory = tempfile::tempdir().expect("create CLI fixture directory");
    let artifact = directory.path().join("artifact.txt");
    let report = directory.path().join("report.json");
    std::fs::write(&artifact, b"Hexlora integration fixture").expect("write CLI fixture");
    let status = Command::new(env!("CARGO_BIN_EXE_hexlora-cli"))
        .args([
            "inspect",
            artifact.to_str().expect("UTF-8 fixture path"),
            "--pretty",
            "--hash",
            "sha256",
            "--output",
            report.to_str().expect("UTF-8 report path"),
        ])
        .status()
        .expect("run CLI");
    assert!(status.success());
    let bytes = std::fs::read(&report).expect("read report");
    assert!(bytes.ends_with(b"\n"));
    assert!(bytes.windows(2).any(|window| window == b"\n "));
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse report JSON");
    assert!(value["files"][0]["summary"]["sha256"].is_string());
}

#[test]
fn every_report_format_is_emitted_by_the_cli() {
    let directory = tempfile::tempdir().expect("create report fixture directory");
    let artifact = directory.path().join("artifact.txt");
    std::fs::write(&artifact, b"report formats").expect("write report fixture");
    for (format, marker) in [
        ("json", "\"schema_version\""),
        ("markdown", "# Hexlora inspection"),
        ("html", "<!doctype html>"),
        ("sarif", "\"2.1.0\""),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hexlora-cli"))
            .args([
                "inspect",
                artifact.to_str().expect("UTF-8 artifact path"),
                "--format",
                format,
            ])
            .output()
            .expect("run report format");
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(marker),
            "missing {format} marker"
        );
    }
}

#[test]
fn compare_and_policy_failures_have_stable_exit_codes() {
    let directory = tempfile::tempdir().expect("create compare fixture directory");
    let before = directory.path().join("before");
    let after = directory.path().join("after");
    std::fs::create_dir(&before).expect("create baseline");
    std::fs::create_dir(&after).expect("create candidate");
    std::fs::write(before.join("payload"), b"a").expect("write baseline");
    std::fs::write(after.join("payload"), vec![b'a'; 32]).expect("write candidate");
    let policy = directory.path().join("policy.json");
    std::fs::write(&policy, br#"{"schema_version":"1.0","max_growth_bytes":1}"#)
        .expect("write comparison policy");
    let output = Command::new(env!("CARGO_BIN_EXE_hexlora-cli"))
        .args([
            "compare",
            before.to_str().expect("UTF-8 baseline path"),
            after.to_str().expect("UTF-8 candidate path"),
            "--policy",
            policy.to_str().expect("UTF-8 policy path"),
        ])
        .output()
        .expect("run policy comparison");
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse comparison JSON");
    assert_eq!(report["delta_bytes"], 31);
    assert_eq!(
        report["policy_violations"][0]["rule_id"],
        "policy.max-growth-bytes"
    );
}

#[test]
fn policy_violations_are_visible_in_every_human_and_machine_report() {
    let directory = tempfile::tempdir().expect("create policy report fixture directory");
    let artifact = directory.path().join("artifact.bin");
    let policy = directory.path().join("policy.json");
    std::fs::write(&artifact, vec![0u8; 32]).expect("write policy artifact");
    std::fs::write(
        &policy,
        br#"{"schema_version":"1.0","max_artifact_bytes":1}"#,
    )
    .expect("write inspection policy");

    for (format, marker) in [
        ("json", "policy.max-artifact-bytes"),
        ("markdown", "policy:policy.max-artifact-bytes"),
        ("html", "policy:policy.max-artifact-bytes"),
        ("sarif", "policy:policy.max-artifact-bytes"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hexlora-cli"))
            .args([
                "inspect",
                artifact.to_str().expect("UTF-8 artifact path"),
                "--policy",
                policy.to_str().expect("UTF-8 policy path"),
                "--format",
                format,
            ])
            .output()
            .expect("run policy report format");
        assert_eq!(output.status.code(), Some(2), "{format}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(marker),
            "missing policy violation from {format} report"
        );
    }
}

fn fixture(name: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/binaries")
        .join(name)
        .to_str()
        .expect("UTF-8 fixture path")
        .to_string()
}

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hexlora-cli"))
        .args(arguments)
        .output()
        .expect("run CLI")
}

#[test]
fn disasm_prints_a_named_listing_and_stays_off_stderr() {
    let output = run(&["disasm", &fixture("fixture-x64.exe")]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).expect("UTF-8 listing");
    assert!(text.contains("x86_64 · image base 0x140000000"), "{text}");
    assert!(text.contains("PDB symbols from"), "{text}");
    assert!(text.contains("fixture_start:"), "{text}");
    assert!(text.contains("call 0x140001060"), "{text}");
    assert!(text.contains("; inject"), "{text}");
    assert!(text.contains("; KERNEL32.dll!ExitProcess"), "{text}");
    assert!(text.contains("fixture.c:"), "{text}");
    assert!(text.trim_end().ends_with("; end of function"), "{text}");
}

#[test]
fn disasm_json_lists_functions_and_honours_targets_and_limits() {
    let output = run(&[
        "disasm",
        &fixture("fixture-universal.dylib"),
        "--slice",
        "arm64",
        "--at",
        "write_message",
        "--at",
        "_puts",
        "--count",
        "3",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("disasm JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["architecture"], "arm64");
    assert_eq!(report["listings"].as_array().map(Vec::len), Some(2));
    assert_eq!(report["listings"][0]["function"], "_write_message");
    assert_eq!(
        report["listings"][0]["lines"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(report["listings"][0]["end"], "instruction_limit");
    assert_eq!(report["listings"][1]["lines"][1]["comment"], "_puts");

    let output = run(&[
        "disasm",
        &fixture("fixture-x86_64.elf"),
        "--functions",
        "--json",
    ]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("function JSON");
    assert_eq!(report["function_count"], 4);
    assert_eq!(report["debug_symbols"]["format"], "dwarf");
    assert!(report["listings"].as_array().is_some_and(Vec::is_empty));
    let names: Vec<&str> = report["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .filter_map(|function| function["name"].as_str())
        .collect();
    assert_eq!(
        names,
        ["add_numbers", "message_text", "exported_entry", "_start"]
    );
}

#[test]
fn disasm_reports_usage_problems_with_exit_status_one() {
    let fixtures = fixture("");
    for (arguments, expected) in [
        // A directory of several binaries needs a choice.
        (vec!["disasm", fixtures.as_str()], "choose one with --file"),
        (
            vec!["disasm", fixtures.as_str(), "--file", "missing.exe"],
            "no binary named",
        ),
        // A dylib has no entry point to default to.
        (
            vec!["disasm", &fixture("fixture-universal.dylib")],
            "has no entry point",
        ),
        (
            vec!["disasm", &fixture("fixture-x64.exe"), "--at", "nowhere"],
            "not an address in this image",
        ),
        (
            vec!["disasm", &fixture("fixture-x64.exe"), "--slice", "ppc"],
            "has no \"ppc\" slice",
        ),
        // A symbol file named on the command line must be usable.
        (
            vec![
                "disasm",
                &fixture("fixture-driver.sys"),
                "--symbols",
                &fixture("fixture.c"),
            ],
            "symbols from",
        ),
        (
            vec!["disasm", &fixture("fixture.c")],
            "contains no PE, ELF, or Mach-O",
        ),
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(1), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{arguments:?}: {stderr}");
    }
    // Selecting by name inside a directory works.
    let output = run(&["disasm", &fixtures, "--file", "fixture-aarch64.elf"]);
    assert!(output.status.success());
}

#[test]
fn inspect_reports_capabilities_fingerprints_functions_and_rule_ids() {
    let output = run(&["inspect", &fixture("fixture-x64.exe"), "--functions"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    let file = &report["files"][0];
    let analysis = &file["analysis"];
    assert_eq!(
        analysis["metadata"]["Import hash (imphash)"],
        "445e41ce919b3b7add0a68ebcd2b653c"
    );
    assert_eq!(analysis["capabilities"][0]["id"], "injection.remote-thread");
    assert_eq!(analysis["capabilities"][0]["confidence"], "High");
    let finding = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["rule_id"] == "capability.injection.remote-thread")
        .expect("capability finding");
    assert_eq!(finding["severity"], "Medium");
    assert_eq!(finding["confidence"], "High");
    assert_eq!(file["code"][0]["architecture"], "x86_64");
    assert_eq!(file["code"][0]["debug_symbols"]["format"], "pdb");
    assert!(
        file["code"][0]["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|f| f["name"] == "inject"))
    );
    // Functions are opt-in.
    let plain = run(&["inspect", &fixture("fixture-x64.exe")]);
    let plain: serde_json::Value = serde_json::from_slice(&plain.stdout).expect("report JSON");
    assert!(plain["files"][0].get("code").is_none());

    let sarif = run(&["inspect", &fixture("fixture-x64.exe"), "--format", "sarif"]);
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).expect("SARIF JSON");
    assert!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("results")
            .iter()
            .any(|result| result["ruleId"] == "capability.injection.remote-thread")
    );
}

#[test]
fn demangled_names_accompany_raw_symbols() {
    // The test binary itself is full of mangled Rust symbols.
    let Ok(current) = std::env::current_exe() else {
        return;
    };
    let output = run(&["inspect", current.to_str().expect("UTF-8 path")]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    let analysis = &report["files"][0]["analysis"];
    let demangled = ["imports", "exports", "symbols"]
        .iter()
        .flat_map(|table| analysis[table].as_array().into_iter().flatten())
        .filter(|symbol| symbol.get("demangled").is_some())
        .count();
    if analysis.is_object() {
        assert!(demangled > 0, "no symbol in a Rust binary was demangled");
    }
}

#[test]
fn policies_can_forbid_or_silence_capabilities_by_rule_id() {
    let directory = tempfile::tempdir().expect("create policy directory");
    let policy = directory.path().join("policy.json");
    let executable = fixture("fixture-x64.exe");
    let inspect = |policy_json: &str| {
        std::fs::write(&policy, policy_json).expect("write policy");
        let output = run(&[
            "inspect",
            &executable,
            "--policy",
            policy.to_str().expect("UTF-8 policy path"),
        ]);
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("report JSON");
        let rules: Vec<String> = report["policy_violations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|violation| violation["rule_id"].as_str().map(str::to_string))
            .collect();
        (output.status.code(), rules)
    };

    let (code, rules) = inspect(r#"{"forbidden_capabilities":["injection.*"]}"#);
    assert_eq!(code, Some(2));
    assert_eq!(rules, ["policy.forbidden-capability"]);

    let (code, rules) = inspect(r#"{"fail_on_severity":"Medium"}"#);
    assert_eq!(code, Some(2));
    assert_eq!(rules, ["capability.injection.remote-thread"]);

    let (code, rules) = inspect(
        r#"{"fail_on_severity":"Medium","disabled_rules":["capability.injection.remote-thread"]}"#,
    );
    assert_eq!(code, Some(0));
    assert!(rules.is_empty());

    let (code, rules) = inspect(r#"{"forbidden_capabilities":["network.*"]}"#);
    assert_eq!(code, Some(0));
    assert!(rules.is_empty());
}

#[cfg(feature = "yara")]
#[test]
fn yara_matches_become_findings_and_bad_rules_fail_before_any_output() {
    let directory = tempfile::tempdir().expect("create rule directory");
    let rules = directory.path().join("rules.yar");
    std::fs::write(
        &rules,
        r#"rule fixture_message : demo {
    meta:
        description = "Contains the fixture message."
        severity = "high"
    strings:
        $a = "hexlora fixture"
    condition:
        $a
}"#,
    )
    .expect("write rules");
    let rules_path = rules.to_str().expect("UTF-8 rules path");
    let fixtures = fixture("");
    let output = run(&[
        "inspect",
        &fixtures,
        "--yara",
        rules_path,
        "--fail-on",
        "high",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    let matched: Vec<&str> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|finding| finding["rule_id"] == "yara.fixture_message")
        .filter_map(|finding| finding["path"].as_str())
        .collect();
    // The user-mode binaries and the C source contain the message. The
    // driver never references it, so the linker dropped it; the PDB holds
    // names, not data.
    assert_eq!(matched.len(), 5, "{matched:?}");
    assert!(
        !matched
            .iter()
            .any(|path| path.ends_with(".pdb") || path.ends_with(".sys"))
    );
    let pdb = report["files"]
        .as_array()
        .expect("files")
        .iter()
        .find(|file| {
            file["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(".pdb"))
        })
        .expect("PDB file report");
    assert!(pdb["yara"].as_array().is_some_and(Vec::is_empty));

    std::fs::write(&rules, "rule broken { condition: ").expect("write broken rules");
    let output = run(&["inspect", &fixtures, "--yara", rules_path]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("YARA rules"));
}
