#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/hexlora-app-smoke.XXXXXX")
test_dir=$(CDPATH= cd -- "$test_dir" && pwd -P)
app_log="$test_dir/launch.log"
trap '/bin/rm -rf "$test_dir"' EXIT HUP INT TERM

HEXLORA_CARGO_FEATURES=gpui/runtime_shaders \
  "$project_root/scripts/build-macos-app.sh" "$test_dir"

app="$test_dir/Hexlora.app"
plutil -lint "$app/Contents/Info.plist"
codesign --verify --deep --strict --verbose=2 "$app"
test "$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")" = \
  "$(sed -n 's/^version = "\([0-9.]*\)"/\1/p' "$project_root/Cargo.toml" | head -1)"

open -n -a "$app" --args >"$app_log" 2>&1
sleep 3
app_pid=$(pgrep -f "$app/Contents/MacOS/Hexlora" | head -1 || true)
if [ -z "$app_pid" ]; then
  sed -n '1,160p' "$app_log" >&2
  exit 1
fi
kill "$app_pid"
