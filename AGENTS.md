# Hexlora repository instructions

## macOS releases

- Every distributed macOS app build must be signed with a Developer ID Application certificate, submitted to Apple for notarization, and have the accepted notarization ticket stapled to the app before it is archived or uploaded.
- A release is not complete until `codesign --verify --deep --strict`, `xcrun stapler validate`, and `spctl --assess --type execute` all succeed on the final app bundle.
- Always create macOS release artifacts with `scripts/release-macos.sh`; do not publish output from `scripts/build-macos-app.sh` directly.
- Never commit, print, or embed Apple IDs, app-specific passwords, signing certificates, or other release credentials. Read credentials from the environment only.
- After a requested release change is verified, commit it and push the commit and release tag unless the user explicitly says not to.

## Release notes

- Before tagging a release, write user-facing notes in `docs/releases/<version>.md` (no install section; `scripts/release-notes.sh` appends it). The tag workflow publishes them on the GitHub release and falls back to generated notes only when the file is missing.
