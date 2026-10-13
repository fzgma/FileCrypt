#pragma once

#include <filecrypt/format/v1/metadata.hpp>

#include <expected>

namespace filecrypt::format::v1 {

/// 校验逻辑对象并编码 v1 AAD，包含 Header 和 Tag 之前的全部 Metadata。
[[nodiscard]] std::vector<std::byte> build_aad(const Header& header, const Metadata& metadata);

/// 校验原始 Header 与完整 Metadata 后直接拼接认证字节，不重新编码输入。
[[nodiscard]] std::vector<std::byte> build_aad(std::span<const std::byte> header_bytes,
    std::span<const std::byte> metadata_bytes);

/// 以 expected 返回 AAD 的格式语义错误，分配或未知异常继续传播。
[[nodiscard]] std::expected<std::vector<std::byte>, Error> try_build_aad(
    const Header& header, const Metadata& metadata);
/// 校验原始认证字节并以 expected 返回 AAD 或格式错误。
[[nodiscard]] std::expected<std::vector<std::byte>, Error> try_build_aad(
    std::span<const std::byte> header_bytes, std::span<const std::byte> metadata_bytes);

// 原始 Header 必须恰好 32 字节，Metadata 必须与 Header 和布局长度精确一致。
// 格式错误抛出 std::invalid_argument；此处只构造 AAD，不执行认证。
// 创建文件时 Tag 可使用占位值，写回真实 Tag 不影响 AAD。
} // namespace filecrypt::format::v1
