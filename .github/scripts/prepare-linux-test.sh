#!/usr/bin/env bash
# 只在测试环境镜像构建时安装工具；运行项目测试时不访问包仓库。
set -euo pipefail
install_qemu="${1:-0}"
source /etc/os-release
case "$ID" in
    debian|ubuntu)
        packages=(cmake unzip)
        if [[ "$install_qemu" == 1 ]]; then
            packages+=(qemu-user)
        fi
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
        rm -rf /var/lib/apt/lists/*
        ;;
    almalinux)
        [[ "$install_qemu" == 0 ]]
        dnf install -y cmake unzip
        dnf clean all
        ;;
    arch)
        [[ "$install_qemu" == 0 ]]
        pacman -Syu --noconfirm --needed cmake unzip
        pacman -Scc --noconfirm
        ;;
    *) echo "未配置的测试环境：$ID" >&2; exit 1 ;;
esac
