#!/usr/bin/env bash
# 在目标发行版运行同一批已编译程序，只安装 CLI 测试所需的 CMake。
set -euo pipefail
distribution="${1:?缺少发行版标识}"
case "$distribution" in
    debian*|ubuntu*)
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cmake
        ;;
    almalinux*) dnf install -y cmake ;;
    archlinux*) pacman -Syu --noconfirm --needed cmake ;;
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
echo '运行单元测试'
for test in header metadata aad detect crypto; do
    "${runner[@]}" "build/tests/unit/${test}_test"
done
echo '运行正式程序冒烟测试：格式信息及两种算法加解密'
cmake "-DFILECRYPT=$filecrypt" "-DTEST_DIR=$test_root/info" -P tests/cli/info_test.cmake
cmake "-DFILECRYPT=$filecrypt" "-DTEST_DIR=$test_root/crypt" -P tests/cli/crypt_test.cmake
echo '运行文件流程集成测试'
"${runner[@]}" build/tests/integration/file_crypt_test "$test_root/app"
