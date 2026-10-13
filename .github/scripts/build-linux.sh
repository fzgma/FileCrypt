#!/usr/bin/env bash
# 在 manylinux_2_28 中使用 GCC Toolset 15 构建通用 x86-64 发布版及全部测试。
set -euo pipefail
source "${BASH_SOURCE[0]%/*}/utf8-locale.sh"

export PATH="/opt/python/cp312-cp312/bin:$PATH"
source .github/scripts/setup-gcc15.sh

mkdir -p build/toolchain
"$CXX" -std=c++23 -DFILECRYPT_REQUIRE_GCC15=1 -O2 -march=x86-64 -mtune=generic \
    -static-libstdc++ -static-libgcc .github/checks/cpp23.cpp \
    -o build/toolchain/cpp23-probe
build/toolchain/cpp23-probe
python .github/scripts/check-linux-elf.py build/toolchain/cpp23-probe

# 依赖来自已准备的环境镜像，保持安装前缀稳定，避免缓存中的绝对路径失效。
deps_prefix="${FILECRYPT_DEPS_PREFIX:?请使用已准备的 Linux 构建环境镜像}"
source "$deps_prefix/versions.env"
botan_prefix="$deps_prefix/botan-install"
zstd_prefix="$deps_prefix/zstd-install"
test -s "$botan_prefix/lib/libbotan-3.a"
test -s "$zstd_prefix/lib/libzstd.a"
export PKG_CONFIG_PATH="$botan_prefix/lib/pkgconfig:$zstd_prefix/lib/pkgconfig"
cmake --fresh -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
    "-DCMAKE_CXX_COMPILER=$CXX" "-DCMAKE_AR=$AR" "-DCMAKE_RANLIB=$RANLIB" \
    "-DCMAKE_PREFIX_PATH=$botan_prefix;$zstd_prefix" -DBotan_USE_STATIC_LIBS=ON -DZstd_USE_STATIC_LIBS=ON \
    '-DCMAKE_CXX_FLAGS=-march=x86-64 -mtune=generic' \
    '-DCMAKE_EXE_LINKER_FLAGS=-static-libstdc++ -static-libgcc'
cmake --build build --target build_all --parallel 2
ctest --test-dir build -L unit --output-on-failure
ctest --test-dir build -L smoke --output-on-failure
ctest --test-dir build -L integration -LE smoke --output-on-failure

# 所有测试程序也必须能够在没有 Botan 和 C++ 共享运行库的目标容器中执行。
python .github/scripts/check-linux-elf.py build/filecrypt build/toolchain/cpp23-probe build/tests/unit/* build/tests/integration/*
# 构建信息留在 Actions 日志，最终 Artifact 只上传 build/filecrypt。
{
    echo "commit=$GITHUB_SHA"
    echo "run=$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
    cat /etc/os-release
    "$CXX" --version
    echo "CC=$CC CXX=$CXX AR=$AR RANLIB=$RANLIB"
    echo 'Zstandard C standard=C17; FileCrypt C++ standard=C++23'
    getconf GNU_LIBC_VERSION
    echo "Botan=$botan_version SHA256=$botan_sha256"
    echo "Zstandard=$zstd_version SHA256=$zstd_sha256"
    echo 'CXXFLAGS=-march=x86-64 -mtune=generic'
    echo 'LDFLAGS=-static-libstdc++ -static-libgcc; Botan=static; Zstandard=static'
    readelf --version-info build/filecrypt
    readelf --notes build/filecrypt
    ldd build/filecrypt
}
