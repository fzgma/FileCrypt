#!/usr/bin/env bash
# 在构建环境镜像内准备固定版本静态依赖，不包含项目源码和测试结果。
set -euo pipefail
script_directory="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
source "$script_directory/setup-gcc15.sh"
source "$script_directory/linux-deps.env"
deps_prefix=/opt/filecrypt/deps
build_root=$(mktemp -d /tmp/filecrypt-deps.XXXXXX)
trap 'rm -rf "$build_root"' EXIT
cd "$build_root"

mkdir -p build/deps
curl --fail --location --retry 3 "https://botan.randombit.net/releases/Botan-$botan_version.tar.xz" \
    -o build/deps/botan.tar.xz
echo "$botan_sha256  build/deps/botan.tar.xz" | sha256sum --check
tar -xf build/deps/botan.tar.xz -C build/deps
botan_source="$PWD/build/deps/Botan-$botan_version"
botan_prefix="$deps_prefix/botan-install"

# 依赖也从源码构建；不引入发行版预编译的 v2 库，优化算法由 Botan 运行时探测 CPU。
(
    cd "$botan_source"
    python configure.py --prefix="$botan_prefix" --libdir=lib \
        --cc=gcc --cc-bin="$CXX" --cpu=x86_64 --os=linux --build-targets=static \
        --extra-cxxflags="-march=x86-64 -mtune=generic" \
        --minimized-build \
        --enable-modules=aes,gcm,chacha20poly1305,argon2,auto_rng,system_rng,entropy,locking_allocator,cpuid,aes_ni,ghash_cpu,chacha_simd32,argon2_avx2
    make -j2
    make install
)
# Zstandard 同样从固定源码构建静态库，不增加发布文件的共享库依赖。
curl --fail --location --retry 3 \
    "https://github.com/facebook/zstd/releases/download/v$zstd_version/zstd-$zstd_version.tar.gz" \
    -o build/deps/zstd.tar.gz
echo "$zstd_sha256  build/deps/zstd.tar.gz" | sha256sum --check
tar -xf build/deps/zstd.tar.gz -C build/deps
zstd_prefix="$deps_prefix/zstd-install"
cmake --fresh -S "build/deps/zstd-$zstd_version/build/cmake" -B build/deps/zstd-build -G Ninja \
    "-DCMAKE_C_COMPILER=$CC" "-DCMAKE_CXX_COMPILER=$CXX" \
    "-DCMAKE_AR=$AR" "-DCMAKE_RANLIB=$RANLIB" \
    -DCMAKE_C_STANDARD=17 -DCMAKE_C_STANDARD_REQUIRED=ON \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$zstd_prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON '-DCMAKE_C_FLAGS=-march=x86-64 -mtune=generic' \
    -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_PROGRAMS=OFF \
    -DZSTD_BUILD_TESTS=OFF -DZSTD_MULTITHREAD_SUPPORT=OFF -DZSTD_LEGACY_SUPPORT=OFF
cmake --build build/deps/zstd-build --parallel 2
cmake --install build/deps/zstd-build

cp "$script_directory/linux-deps.env" "$deps_prefix/versions.env"
