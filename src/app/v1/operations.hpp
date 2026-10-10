#pragma once
#include <filecrypt/app/operations.hpp>
#include <istream>

namespace filecrypt::app::v1 {
/// 从定位到文件起点的输入流读取 v1 公开格式信息。
[[nodiscard]] FileInfo inspect(std::istream& input);
/// 生成 v1 Header 与 Metadata 格式样本并写入新文件。
void sample(const std::filesystem::path& path, const SampleOptions& options);
/// 执行 v1 文件或目录加密及真实 Tag 写回。
void encrypt(const std::filesystem::path& input, const std::filesystem::path& output,
    std::span<const std::uint8_t> password, const EncryptOptions& options);
/// 执行 v1 文件或目录解密，认证成功后按需受限解压、校验并提交输出。
std::filesystem::path decrypt(std::istream& input, const std::filesystem::path& output,
    std::span<const std::uint8_t> password, const crypto::KdfLimits& limits,
    const compression::DecompressionLimits& decompression_limits, bool restore_extension,
    const directory::Limits& directory_limits);
}
