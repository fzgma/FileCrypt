#pragma once

#include <filecrypt/format/header.hpp>

#include <optional>
#include <vector>

namespace filecrypt::format {

struct Argon2idParameters {
    std::uint8_t version{0x13};
    std::array<std::byte, 3> reserved{};
    // 不提供生产默认值，调用者必须显式设置成本参数。
    std::uint32_t memory_cost_kib{};
    std::uint32_t time_cost{};
    std::uint32_t parallelism{};

    /// 比较两组 Argon2id 参数的全部字段。
    bool operator==(const Argon2idParameters&) const = default;
};

struct CompressionMetadata {
    std::uint16_t id{1};
    std::vector<std::byte> parameters;

    /// 比较两组压缩信息的编号和参数。
    bool operator==(const CompressionMetadata&) const = default;
};

struct Metadata {
    std::optional<std::uint64_t> index_length;
    std::optional<CompressionMetadata> compression;
    std::uint16_t kdf_id{1};
    Argon2idParameters kdf_parameters;
    std::array<std::byte, 16> salt{};
    std::vector<std::byte> nonce;
    std::array<std::byte, 16> tag{};

    /// 比较两个 Metadata 的全部逻辑字段。
    bool operator==(const Metadata&) const = default;
};

struct MetadataLayout {
    std::optional<std::size_t> index_offset;
    std::optional<std::size_t> compression_offset;
    std::size_t kdf_id_offset;
    std::size_t kdf_parameters_offset;
    std::size_t salt_offset;
    std::size_t nonce_offset;
    std::size_t tag_offset;
    std::size_t padding_offset;
    std::size_t padding_size;
    std::size_t metadata_size;
};

/// 根据 Header 上下文与 Registry 计算 v1 Metadata 的字段偏移及填充长度。
[[nodiscard]] MetadataLayout metadata_layout(const Header& header,
    std::uint16_t kdf_id = 1, std::uint16_t compression_id = 1);

/// 校验并将 Metadata 编码为与 Header.metadata_length 一致的小端字节序列。
[[nodiscard]] std::vector<std::byte> serialize_metadata(const Header& header,
    const Metadata& metadata);

/// 校验并解析完整 Metadata 区域，输入长度必须精确匹配 Header.metadata_length。
[[nodiscard]] Metadata deserialize_metadata(const Header& header,
    std::span<const std::byte> data);

// 所有格式错误和不支持的协议编号均抛出 std::invalid_argument。
// 本层不计算 Tag、不执行 KDF，也不验证密文认证或实际 Index 长度。
} // namespace filecrypt::format
