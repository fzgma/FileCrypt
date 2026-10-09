#!/usr/bin/env python3
"""检查 Linux 发布程序的架构、动态依赖和 glibc 符号版本。"""

import os
import re
import subprocess
import sys
from pathlib import Path

ALLOWED_LIBRARIES = {
    "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1",
    "ld-linux-x86-64.so.2",
}


def readelf(option: str, path: Path) -> str:
    """用固定英文输出读取 ELF 中指定的结构信息。"""
    return subprocess.check_output(
        ["readelf", option, "--wide", str(path)], text=True, env={**os.environ, "LC_ALL": "C"}
    )


def check(path: Path) -> None:
    """拒绝超出 glibc 2.34 基线或带非系统动态依赖的发布程序。"""
    header = readelf("--file-header", path)
    if "Advanced Micro Devices X86-64" not in header or "ELF64" not in header:
        raise ValueError(f"{path}: expected x86-64 ELF64")
    program = readelf("--program-headers", path)
    if "Requesting program interpreter: /lib64/ld-linux-x86-64.so.2" not in program:
        raise ValueError(f"{path}: expected dynamically linked glibc interpreter")
    needed = set(re.findall(r"\(NEEDED\).*?\[(.*?)\]", readelf("--dynamic", path)))
    if "libc.so.6" not in needed or needed - ALLOWED_LIBRARIES:
        raise ValueError(f"{path}: unexpected dynamic dependencies: {sorted(needed)}")
    versions = set(re.findall(r"Name: GLIBC_([^\s]+)", readelf("--version-info", path)))
    if not versions:
        raise ValueError(f"{path}: missing glibc symbol versions")
    for version in versions:
        if not re.fullmatch(r"\d+(?:\.\d+)+", version) or tuple(map(int, version.split("."))) > (2, 34):
            raise ValueError(f"{path}: unsupported GLIBC_{version}")
    notes = readelf("--notes", path)
    for requirement in re.findall(r"x86 ISA needed: (.*)", notes):
        if re.search(r"x86-64-v[234]", requirement):
            raise ValueError(f"{path}: unsupported ISA requirement: {requirement}")
    print(f"{path}: glibc <= 2.34, dependencies={','.join(sorted(needed))}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: check-linux-elf.py EXECUTABLE...")
    for argument in sys.argv[1:]:
        check(Path(argument))
