#!/bin/sh
# Print the GitHub release notes for a version: the written notes in
# docs/releases/VERSION.md followed by the standard install section.
# Fails when the notes file is missing so callers can fall back.
set -eu

version=${1:?usage: release-notes.sh VERSION}
version=${version#v}
root=$(cd "$(dirname "$0")/.." && pwd)
notes="$root/docs/releases/$version.md"

if [ ! -s "$notes" ]; then
    echo "release-notes: no written notes at docs/releases/$version.md" >&2
    exit 1
fi

cat "$notes"
cat <<FOOTER

**Install**
- macOS (Apple silicon): \`brew install --cask everettjf/tap/hexlora\`, or \`brew upgrade --cask hexlora\` to update. The app is Developer ID signed, notarized and stapled. The CLI is \`brew install everettjf/tap/hexlora-cli\`.
- Windows x64: \`Hexlora-$version-windows-x64.msi\` or the portable \`.zip\` below.
- Linux amd64: \`Hexlora-$version-linux-amd64.deb\` or the portable \`.tar.gz\` below.

The Windows and Linux packages are not code-signed yet; verify them against \`SHA256SUMS\` before installing.
FOOTER
