#!/bin/sh
# Rebuilds the binary fixtures from fixture.c with clang and LLD (LLVM 18).
# Output is reproducible: /Brepro and --build-id=none keep timestamps and
# host-specific identifiers out of the files.
set -eu
cd -- "$(dirname -- "$0")"
# A fixed relative directory keeps object paths, and so the PDB identity, stable.
work=.build
rm -rf "$work"
mkdir "$work"
trap 'rm -rf "$work"' EXIT

printf 'LIBRARY KERNEL32.dll\nEXPORTS\nGetStdHandle\nWriteFile\nExitProcess\nOpenProcess\nVirtualAllocEx\nWriteProcessMemory\nCreateRemoteThread\n' > "$work/kernel32.def"
printf 'LIBRARY ntoskrnl.exe\nEXPORTS\nIoCreateDevice\nIoCreateSymbolicLink\nMmMapIoSpace\nZwOpenProcess\n' > "$work/ntoskrnl.def"
llvm-dlltool -m i386:x86-64 -d "$work/kernel32.def" -l "$work/kernel32.lib"
llvm-dlltool -m i386:x86-64 -d "$work/ntoskrnl.def" -l "$work/ntoskrnl.lib"

windows="--target=x86_64-pc-windows-msvc -O1 -g -gcodeview -ffreestanding -fno-stack-protector -funwind-tables -fdebug-compilation-dir=. -fcoverage-compilation-dir=."
clang $windows -c fixture.c -o "$work/user.obj"
lld-link /nologo /entry:fixture_start /subsystem:console /nodefaultlib /debug /Brepro \
    /pdb:fixture-x64.pdb /pdbaltpath:fixture-x64.pdb /pdbsourcepath:C:\\hexlora-fixture /out:fixture-x64.exe "$work/user.obj" "$work/kernel32.lib"

clang $windows -DHEXLORA_DRIVER -c fixture.c -o "$work/driver.obj"
lld-link /nologo /entry:DriverEntry /subsystem:native /driver /nodefaultlib /Brepro \
    /out:fixture-driver.sys "$work/driver.obj" "$work/ntoskrnl.lib"

for target in x86_64 aarch64; do
    clang --target=$target-linux-gnu -O1 -g -ffreestanding -fno-stack-protector -fno-pic -nostdlib \
        -fdebug-compilation-dir=. -fuse-ld=lld -static -Wl,--build-id=none -Wl,-e,_start \
        fixture.c -o fixture-$target.elf
done
# A universal dylib exercises Mach-O slices, stubs, and the indirect symbol table.
for target in arm64 x86_64; do
    clang --target=$target-apple-macos12 -O1 -ffreestanding -fno-stack-protector -c fixture.c \
        -o "$work/macho-$target.o"
    ld64.lld-18 -arch $target -platform_version macos 12.0 12.0 -dylib -undefined dynamic_lookup \
        -install_name @rpath/libfixture.dylib -o "$work/libfixture-$target.dylib" "$work/macho-$target.o"
done
llvm-lipo-18 -create "$work/libfixture-arm64.dylib" "$work/libfixture-x86_64.dylib" \
    -output fixture-universal.dylib
rm -f fixture-x64.lib
