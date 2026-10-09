#pragma once
#include <filesystem>
#include <istream>
#include <cstdint>

namespace filecrypt::app::v1 {
/// 扩展名优先；仅在没有后缀时读取有界文件头，返回前恢复流位置。
std::uint16_t detect_file_type(const std::filesystem::path& path, std::istream& input);
/// 仅为有效的无后缀输出文件名追加已登记的后缀。
std::filesystem::path restore_file_extension(std::filesystem::path path, std::uint16_t type);
}
