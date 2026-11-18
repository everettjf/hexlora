#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

cargo fmt --all -- --check
cargo test --workspace --features gpui/runtime_shaders
cargo clippy --workspace --all-targets --features gpui/runtime_shaders -- -D warnings
cargo check --locked -p hexlora --features gpui/runtime_shaders
cargo check --locked -p hexlora-cli

# The packaging checks need tools that ship with macOS. Elsewhere they are
# skipped out loud, so the Rust gate above can still be run on Linux.
if command -v plutil >/dev/null 2>&1; then
  plutil -lint packaging/macos/Info.plist
else
  echo "verify: plutil not found; skipped the Info.plist check (macOS only)" >&2
fi
if command -v ruby >/dev/null 2>&1; then
  ruby -c packaging/homebrew/Casks/hexlora.rb
  ruby -c packaging/homebrew/Formula/hexlora-cli.rb
else
  echo "verify: ruby not found; skipped the Homebrew syntax checks" >&2
fi

git diff --check
