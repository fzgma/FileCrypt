#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <iosfwd>

namespace filecrypt::io {
/// 从输入流完整读取目标缓冲区，拒绝截断输入。
void read_exact(std::istream& input, std::span<std::byte> bytes);
/// 排他创建文件并写入全部字节，拒绝覆盖已有路径。
void write_new_file(const std::filesystem::path& path, std::span<const std::byte> data);
}
