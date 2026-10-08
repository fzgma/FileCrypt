#pragma once

#include <cstddef>
#include <filesystem>
#include <span>

namespace filecrypt::io {
/// 排他创建文件并写入全部字节，拒绝覆盖已有路径。
void write_new_file(const std::filesystem::path& path, std::span<const std::byte> data);
}
