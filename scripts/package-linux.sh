#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$project_root/dist"}
version=$(sed -n 's/^version = "\([0-9.]*\)"/\1/p' "$project_root/Cargo.toml" | head -1)
arch=$(dpkg --print-architecture)
package_root="$output_dir/hexlora_${version}_${arch}"

test -n "$version"
command -v dpkg-deb >/dev/null 2>&1

cd "$project_root"
cargo build --release --locked -p hexlora -p hexlora-cli

rm -rf "$package_root"
mkdir -p \
  "$package_root/DEBIAN" \
  "$package_root/usr/bin" \
  "$package_root/usr/share/applications" \
  "$package_root/usr/share/icons/hicolor/512x512/apps"

install -m 755 target/release/Hexlora "$package_root/usr/bin/hexlora"
install -m 755 target/release/hexlora-cli "$package_root/usr/bin/hexlora-cli"
install -m 644 packaging/linux/hexlora.desktop \
  "$package_root/usr/share/applications/hexlora.desktop"
install -m 644 packaging/macos/HexloraIcon.png \
  "$package_root/usr/share/icons/hicolor/512x512/apps/hexlora.png"

mkdir -p "$package_root/debian"
install -m 644 packaging/linux/debian-control \
  "$package_root/debian/control"
dependency_output=$(cd "$package_root" && dpkg-shlibdeps \
  -O \
  -e"usr/bin/hexlora" \
  -e"usr/bin/hexlora-cli")
dependencies=$(printf '%s\n' "$dependency_output" | sed -n 's/^shlibs:Depends=//p')
test -n "$dependencies"
rm -rf "$package_root/debian"

sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@ARCH@/$arch/g" \
  -e "s/@DEPENDS@/$dependencies/g" \
  packaging/linux/control.in > "$package_root/DEBIAN/control"

mkdir -p "$output_dir"
dpkg-deb --root-owner-group --build "$package_root" \
  "$output_dir/Hexlora-${version}-linux-${arch}.deb"

portable_dir="$output_dir/Hexlora-${version}-linux-${arch}"
rm -rf "$portable_dir"
mkdir -p "$portable_dir"
install -m 755 target/release/Hexlora "$portable_dir/hexlora"
install -m 755 target/release/hexlora-cli "$portable_dir/hexlora-cli"
cp LICENSE README.md "$portable_dir/"
tar -C "$output_dir" -czf "$portable_dir.tar.gz" "$(basename "$portable_dir")"

printf '%s\n' \
  "$output_dir/Hexlora-${version}-linux-${arch}.deb" \
  "$portable_dir.tar.gz"
