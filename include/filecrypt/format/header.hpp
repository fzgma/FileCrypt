#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace filecrypt::format {

inline constexpr std::size_t header_size = 32;
inline constexpr std::array<std::byte, 4> header_magic{
    std::byte{0x46}, std::byte{0x43}, std::byte{0x52}, std::byte{0x59}};

struct Header {
    std::uint16_t version{};
    std::uint16_t flags{};
    std::uint16_t algorithm{};
    std::uint16_t file_type{};
    std::uint64_t metadata_length{};
    std::array<std::byte, 12> reserved{};

    /// 比较两个 Header 的所有逻辑字段是否相同。
    bool operator==(const Header&) const = default;
};

// 本层只负责二进制编解码，协议语义由上层校验。
/// 将 Header 的逻辑字段编码为固定 32 字节的小端数据。
[[nodiscard]] std::array<std::byte, header_size> serialize(const Header& header);

/// 从输入的前 32 字节还原 Header，忽略后续字节。
// 输入不足 32 字节或 Magic 错误时抛出 std::invalid_argument。
[[nodiscard]] Header deserialize(std::span<const std::byte> data);

} // namespace filecrypt::format
