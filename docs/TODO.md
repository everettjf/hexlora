# Outstanding work

Written 2026-11-18, after the binary-triage work (capabilities, YARA, debug symbols, disassembly
preview) was merged to `main` and released as 1.3.0. Remove items as they are done.

## Still to verify on macOS

Clicked through on a Mac so far: the Disassembly tab (entry listing, row details, Functions,
opening a function, Back), with a dSYM beside a Mach-O (function names, source lines, Follow
Target, Show in Hex, Disassemble from a Symbols row); **Load Symbols…** with a dSYM chosen in the
dialog; **Scan with YARA Rules…** (`⇧⌘Y`) with a rule file and **Scan with YARA Rule Folder…**
with a folder, both chosen in their dialogs; the Capabilities tab on a real application; and
objdump launched from the Disassembly tab, which starts at the function being read. Not yet
exercised by hand:

- Handoff to a graphical tool. Hopper is given the address on the clipboard. The IDA path writes a
  script that jumps to the address and passes it with `-S`; it has never been run against a real
  IDA.

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
