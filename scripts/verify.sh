#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

cargo fmt --all -- --check
cargo test --workspace --features gpui/runtime_shaders
cargo clippy --workspace --all-targets --features gpui/runtime_shaders -- -D warnings
cargo check --locked -p hexlora --features gpui/runtime_shaders
cargo check --locked -p hexlora-cli

plutil -lint packaging/macos/Info.plist
ruby -c packaging/homebrew/Casks/hexlora.rb
ruby -c packaging/homebrew/Formula/hexlora-cli.rb

git diff --check
