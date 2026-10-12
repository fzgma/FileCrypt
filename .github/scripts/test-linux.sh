#!/usr/bin/env bash
# 在目标发行版运行同一批已编译程序，只安装 CLI 测试所需的 CMake。
set -euo pipefail
source "${BASH_SOURCE[0]%/*}/utf8-locale.sh"
distribution="${1:?缺少发行版标识}"
case "$distribution" in
    debian*|ubuntu*)
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cmake unzip
        ;;
    almalinux*) dnf install -y cmake unzip ;;
    archlinux*) pacman -Syu --noconfirm --needed cmake unzip ;;
    *) echo "未配置的正式测试发行版：$distribution" >&2; exit 1 ;;
esac
getconf GNU_LIBC_VERSION
runner=()
filecrypt="$PWD/build/filecrypt"
test_root="$PWD/build/runtime-tests/$distribution"
if [[ "${FILECRYPT_TEST_CPU:-}" == baseline ]]; then
    apt-get install -y --no-install-recommends qemu-user
    # qemu64 不提供完整 v2 指令集；让库的 CPU 探测和两种密码算法都走实际执行路径。
    runner=(qemu-x86_64 -cpu qemu64)
    mkdir -p "$test_root"
    export FILECRYPT_TEST_BINARY="$filecrypt"
    filecrypt="$test_root/filecrypt-qemu"
    cat > "$filecrypt" <<'EOF'
#!/usr/bin/env bash
exec qemu-x86_64 -cpu qemu64 "$FILECRYPT_TEST_BINARY" "$@"
EOF
    chmod +x "$filecrypt"
fi
# Register tests without compiling; use the same definitions as the build.
test_runner=$(IFS=';'; echo "${runner[*]}")
# 复验只配置测试；无需在最小发行版容器中安装 make 或 Ninja。
cmake -S tests/runtime -B "$test_root" -G "Unix Makefiles" -DCMAKE_MAKE_PROGRAM=/bin/true \
    "-DFILECRYPT_BUILD_DIR=$PWD/build" "-DFILECRYPT_CLI=$filecrypt" \
    "-DFILECRYPT_TEST_RUNNER=$test_runner"
ctest --test-dir "$test_root" --output-on-failure --no-tests=error
