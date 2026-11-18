# Hexlora report and policy schema

Hexlora emits deterministic, versioned reports. Additive fields may appear within a schema
version; consumers should ignore unknown fields. A removed field or changed meaning requires a
new major schema version.

## Inspection report v1

The top-level JSON fields are `schema_version`, `generator`, `artifact`, `files`, `findings`,
`policy_violations`, and `run`. Optional platform reports are `ipa`,
`ipa_view_compatibility`, `android`, `windows_package`, and `linux_package`.

Each entry in `files` carries the parsed `analysis` of a binary. Within it:

- `imports`, `exports`, and `symbols` entries have `name`, `address`, `library`, and, when the
  name is a mangled C++, Rust, or MSVC name, `demangled`.
- `capabilities` lists what the binary appears able to do. Each has an `id` such as
  `injection.remote-thread`, a `group`, `name`, `description`, `severity`, `confidence`
  (`Low`, `Medium`, or `High`), and `evidence` strings naming the imports and embedded strings
  behind it. Without `--capabilities` or `--depth deep`, evidence comes from imports only.
- `metadata` gains PE fingerprints: `Import hash (imphash)`, `Rich header` fields, `Overlay offset`
  and `Overlay size`, `Packer section markers`, and for kernel drivers `Kernel driver`,
  `Driver model`, and `Driver device interface`.

Findings may carry `rule_id` and `confidence`. `rule_id` is the stable identifier policies match:
`capability.<id>` for capabilities of low severity or above, `pe.<trait>` for PE packing traits,
and `yara.<namespace>.<rule>` for YARA matches (the namespace is omitted for a single rule file).
Findings without a `rule_id` are identified, as before, by `analysis.` followed by their
lower-cased, hyphenated title.

With `--functions`, each binary's file entry has `code`: one object per architecture slice with
`architecture`, `image_base`, `entry`, `function_count`, `functions_truncated`, `functions`
(`address`, `size`, `name`, `raw_name`, `source`), and `debug_symbols` when a PDB or DWARF was
used. Function addresses are virtual addresses; for PE they include the image base.

With `--yara`, every file entry has `yara`: the rules that matched, each with `rule`, `namespace`,
`tags`, `description`, `severity`, and `occurrences` (`identifier`, `offset`, `length`).

`run.partial` means the report is usable but one or more bounded analyses failed. `run.errors`
identifies each failed stage. `run.cancelled` is distinct from partial completion. CLI exit codes
are documented in the README.

## Disassembly report v1

`hexlora-cli disasm --json` emits `schema_version`, `path`, the same fields as one `code` object
above, and `listings`. Each listing has `start`, `function`, `end` (`function_end`,
`next_function`, `instruction_limit`, or `end_of_data`), and `lines`. Each line has `address`,
`bytes` (lowercase hexadecimal), `text`, `flow` (`next`, `call`, `jump`, `conditional_jump`,
`return`, `trap`, or `invalid`), and, when known, `target`, `comment`, `source_file`, and
`source_line`. `comment` names what the instruction refers to: a function, an import, or a
quoted string.

## Comparison report v1.1

Comparison reports contain exact SHA-256-backed `files`, `moved_files`, `directory_deltas`,
`type_deltas`, `duplicate_groups`, and `largest_growth`. When both inputs are IPAs, `ipa` adds
identity, architecture, target, localization, privacy, signing, entitlement, and finding changes.

## Platform report v1

- IPA: identity, compressed and installed sizes, files, targets, frameworks, extensions,
  localizations, architectures, privacy declarations, provisioning, entitlements, findings, and
  the IPAView-compatible projection.
- Android APK: manifest identity, SDK levels, application flags, permissions, components, deep
  links, DEX counts, resources, native libraries, signing indicators, and findings.
- APPX/MSIX: package identity, target families, capabilities, applications, executable members,
  block-map/signature presence, and findings.
- Debian package: control identity, dependencies, installed size, files and modes, maintainer
  scripts, and findings.

## Release policy v1

Policies are JSON objects with `schema_version: "1.0"`. Profiles are `balanced`, `strict`, and
`store_release`. Explicit `fail_on_severity` overrides the profile threshold. Rule configuration
supports `enabled_rules`, `disabled_rules`, `severity_overrides`, and `suppressions`; each
suppression requires a reason and may provide an RFC 3339 `expires_at` timestamp. Expired
suppressions do not apply.

`forbidden_capabilities` lists capability identifiers no binary may have, whatever their
severity. An entry is an exact identifier (`injection.remote-thread`) or a group with a trailing
`.*` (`injection.*`). A match is reported as `policy.forbidden-capability`.

See [`examples/policies/store-release.json`](../examples/policies/store-release.json) for all
cross-platform gates and [`examples/github-actions/hexlora-audit.yml`](../examples/github-actions/hexlora-audit.yml)
for CI integration.

## Compatibility

The IPAView projection is camelCase and governed by the shared contract in
`tests/fixtures/ipa/ipaview-contract.json`. Its golden matrix uses 20 deterministic, legally owned
synthetic IPA variants. Report ordering is stable so JSON can be reviewed and diffed in CI.
