#pragma once
#include <filecrypt/app/operations.hpp>
#include <istream>

namespace filecrypt::app::v1 {
/// 从定位到文件起点的输入流读取 v1 公开格式信息。
[[nodiscard]] FileInfo inspect(std::istream& input);
/// 生成 v1 Header 与 Metadata 格式样本并写入新文件。
void sample(const std::filesystem::path& path, const SampleOptions& options);
}
