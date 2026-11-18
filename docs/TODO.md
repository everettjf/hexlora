# Outstanding work

Written 2026-11-18, after the binary-triage work (capabilities, YARA, debug symbols, disassembly
preview) was merged to `main`. Remove items as they are done.

## Release 1.3.0

The version is already 1.3.0 in `Cargo.toml` and the notes are in
[`docs/releases/1.3.0.md`](releases/1.3.0.md). Nothing has been tagged or published. These steps
need a Mac with the Developer ID certificate in its keychain and the notarization credentials in
its environment; they cannot be done from a Linux or cloud session.

1. On `main`, with `HEXLORA_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_SPECIFIC_PASSWORD`, and
   `APPLE_TEAM_ID` set, run `scripts/release-macos.sh 1.3.0`. It builds, signs, notarizes, staples,
   and verifies the app, and writes the artifacts to `dist/release-1.3.0/`.
2. Upload `Hexlora-1.3.0-macos.zip` and `hexlora-cli-1.3.0-aarch64-apple-darwin.tar.gz` to a
   `hexlora-v1.3.0` release in `everettjf/homebrew-tap`.
3. Update the version and both `sha256` values in `packaging/homebrew/Casks/hexlora.rb` and
   `packaging/homebrew/Formula/hexlora-cli.rb`, here and in the tap repository.
4. Commit, then tag `v1.3.0` and push the tag. The tag workflow builds the Windows and Linux
   packages and publishes the GitHub release with the written notes.
5. Confirm `brew upgrade --cask hexlora` and `brew upgrade hexlora-cli` install 1.3.0.

Do not push the tag before steps 1–3: it would publish a release with no macOS build.

## Verify on macOS before releasing

The new desktop tabs were exercised on Linux under a virtual display, and macOS CI builds and
launches the app bundle, but nobody has clicked through them on a Mac.

- Disassembly: open a Mach-O with a dSYM beside it; check function names, source lines, Follow
  Target, Back, Show in Hex, and Disassemble from a Symbols or Exports row.
- The file dialogs, which could not be driven on Linux: **Load Symbols…** and
  **File → Scan with YARA Rules** (`⇧⌘Y`), with a rule file and with a rule folder.
- Capabilities on a real application, to judge whether the default findings are too noisy.
- External tool handoff from the Disassembly tab. The IDA path writes a script that jumps to the
  address and passes it with `-S`; it has never been run against a real IDA.

## Documentation and website

- The product page at atomsprout.com/hexlora lives in another repository and does not mention
  triage, capabilities, YARA, or disassembly yet. `docs/` here only redirects to it.
- The README has no screenshots of the Capabilities, Disassembly, or YARA tabs. The existing ones
  were captured on macOS at Retina resolution; new ones should match.

## Known gaps in what shipped

- Swift symbol names are not demangled; there is no mature pure-Rust demangler.
- .NET metadata is still only detected, not parsed. `dotscope` needs Rust 1.95; the workspace
  supports 1.88.
- YARA uses `boreal` rather than VirusTotal's `yara-x` for the same reason.
- Capability rules match imports by name, so functions imported by ordinal (commonly `ws2_32`)
  and functions resolved at run time are not seen.
- The import hash is reported as not comparable when `ws2_32`, `wsock32`, or `oleaut32` are
  imported by ordinal, because the reference algorithm's ordinal-to-name table is not included.
- `EvidenceLocator::VirtualAddress` exists in the model but no finding uses it yet.
- A caught panic inside a third-party parser (a damaged PDB, for example) is reported as an error
  but still prints the panic message to stderr.

## Deferred by decision

Phase 4 of the plan, to be re-evaluated against real demand rather than built speculatively:
IOCTL code tables recovered from driver dispatch routines, API-hash lookup (ror13, djb2), and
one-level cross-references. Control-flow graphs, decompilation, and patching stay out of scope;
see section 11.1 of [the product strategy](product-strategy.md).
