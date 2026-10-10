#!/usr/bin/env bash
# 在不预设 v2 指令集的 manylinux_2_28 中构建通用 x86-64 发布版及全部测试。
set -euo pipefail

export PATH="/opt/python/cp312-cp312/bin:$PATH"
python -m pip install --disable-pip-version-check cmake==3.31.6 ninja==1.11.1.3

botan_version=3.13.0
botan_sha256=12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620
mkdir -p build/deps
curl --fail --location --retry 3 "https://botan.randombit.net/releases/Botan-$botan_version.tar.xz" \
    -o build/deps/botan.tar.xz
echo "$botan_sha256  build/deps/botan.tar.xz" | sha256sum --check
tar -xf build/deps/botan.tar.xz -C build/deps
botan_source="$PWD/build/deps/Botan-$botan_version"
botan_prefix="$PWD/build/deps/botan-install"

# 依赖也从源码构建；不引入发行版预编译的 v2 库，优化算法由 Botan 运行时探测 CPU。
(
    cd "$botan_source"
    python configure.py --prefix="$botan_prefix" --libdir=lib \
        --cc=gcc --cpu=x86_64 --os=linux --build-targets=static \
        --extra-cxxflags="-march=x86-64 -mtune=generic" \
        --minimized-build \
        --enable-modules=aes,gcm,chacha20poly1305,argon2,auto_rng,system_rng,entropy,locking_allocator,cpuid,aes_ni,ghash_cpu,chacha_simd32,argon2_avx2
    make -j2
    make install
)
# Zstandard 同样从固定源码构建静态库，不增加发布文件的共享库依赖。
zstd_version=1.5.7
zstd_sha256=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
curl --fail --location --retry 3 \
    "https://github.com/facebook/zstd/releases/download/v$zstd_version/zstd-$zstd_version.tar.gz" \
    -o build/deps/zstd.tar.gz
echo "$zstd_sha256  build/deps/zstd.tar.gz" | sha256sum --check
tar -xf build/deps/zstd.tar.gz -C build/deps
zstd_prefix="$PWD/build/deps/zstd-install"
cmake -S "build/deps/zstd-$zstd_version/build/cmake" -B build/deps/zstd-build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$zstd_prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON '-DCMAKE_C_FLAGS=-march=x86-64 -mtune=generic' \
    -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_PROGRAMS=OFF \
    -DZSTD_BUILD_TESTS=OFF -DZSTD_MULTITHREAD_SUPPORT=OFF -DZSTD_LEGACY_SUPPORT=OFF
cmake --build build/deps/zstd-build --parallel 2
cmake --install build/deps/zstd-build
export PKG_CONFIG_PATH="$botan_prefix/lib/pkgconfig:$zstd_prefix/lib/pkgconfig"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
    "-DCMAKE_PREFIX_PATH=$botan_prefix;$zstd_prefix" -DBotan_USE_STATIC_LIBS=ON -DZstd_USE_STATIC_LIBS=ON \
    '-DCMAKE_CXX_FLAGS=-march=x86-64 -mtune=generic' \
    '-DCMAKE_EXE_LINKER_FLAGS=-static-libstdc++ -static-libgcc'
cmake --build build --target build_all --parallel 2
ctest --test-dir build -L unit --output-on-failure
ctest --test-dir build -L smoke --output-on-failure
ctest --test-dir build -R '^app_(file|directory)_crypt$' --output-on-failure

# 所有测试程序也必须能够在没有 Botan 和 C++ 共享运行库的目标容器中执行。
python .github/scripts/check-linux-elf.py build/filecrypt build/tests/unit/* build/tests/integration/*
# 构建信息留在 Actions 日志，最终 Artifact 只上传 build/filecrypt。
{
    echo "commit=$GITHUB_SHA"
    echo "run=$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
    cat /etc/os-release
    g++ --version
    getconf GNU_LIBC_VERSION
    echo "Botan=$botan_version SHA256=$botan_sha256"
    echo "Zstandard=$zstd_version SHA256=$zstd_sha256"
    echo 'CXXFLAGS=-march=x86-64 -mtune=generic'
    echo 'LDFLAGS=-static-libstdc++ -static-libgcc; Botan=static; Zstandard=static'
    readelf --version-info build/filecrypt
    readelf --notes build/filecrypt
    ldd build/filecrypt
}
