#!/usr/bin/env bash
# 由 build-linux.sh source，在 AlmaLinux 8/manylinux 底座内选择完整的 GCC 15 工具链。
set -euo pipefail

filecrypt_toolchain_prefix=/opt/rh/gcc-toolset-15/root/usr
dnf install -y gcc-toolset-15-gcc gcc-toolset-15-gcc-c++ \
    gcc-toolset-15-libstdc++-devel gcc-toolset-15-binutils
export PATH="$filecrypt_toolchain_prefix/bin:$PATH"
export LD_LIBRARY_PATH="$filecrypt_toolchain_prefix/lib64:$filecrypt_toolchain_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CC="$filecrypt_toolchain_prefix/bin/gcc"
export CXX="$filecrypt_toolchain_prefix/bin/g++"
export AR="$filecrypt_toolchain_prefix/bin/ar"
export RANLIB="$filecrypt_toolchain_prefix/bin/ranlib"

for filecrypt_compiler in "$CC" "$CXX"; do
    filecrypt_compiler_version=$("$filecrypt_compiler" -dumpfullversion -dumpversion)
    if [[ "${filecrypt_compiler_version%%.*}" != 15 ]]; then
        echo "Expected GCC 15, got $filecrypt_compiler: $filecrypt_compiler_version" >&2
        exit 1
    fi
    "$filecrypt_compiler" --version
done
"$AR" --version

# 不允许静默回落到系统 GCC 或旧 Toolset 的静态运行库。
for filecrypt_library in libstdc++.a libgcc.a; do
    filecrypt_library_path=$("$CXX" -print-file-name="$filecrypt_library")
    case "$filecrypt_library_path" in
        "$filecrypt_toolchain_prefix/"*) ;;
        *) echo "Wrong or missing GCC 15 runtime: $filecrypt_library_path" >&2; exit 1 ;;
    esac
    test -f "$filecrypt_library_path"
    echo "$filecrypt_library=$filecrypt_library_path"
done
rpm -q gcc-toolset-15-gcc gcc-toolset-15-gcc-c++ gcc-toolset-15-libstdc++-devel gcc-toolset-15-binutils
