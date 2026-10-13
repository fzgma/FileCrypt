#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

namespace filecrypt::utils {

/// 固定宽度字节编码只接受至多 64 位的无符号整数，不接受 bool。
template<class Integer>
concept LittleEndianInteger = std::unsigned_integral<Integer> &&
    !std::same_as<Integer, bool> && sizeof(Integer) <= sizeof(std::uint64_t);

/// 将整数写入指定偏移；调用方须先确认完整字段位于缓冲区内。
template<LittleEndianInteger Integer>
constexpr void write_le(std::span<std::byte> bytes, std::size_t offset, Integer value) noexcept {
    for (std::size_t i = 0; i < sizeof(Integer); ++i)
        bytes[offset + i] = static_cast<std::byte>((value >> (8 * i)) & 0xFFu);
}

/// 读取指定偏移的小端整数；调用方保留长度校验和协议错误诊断。
template<LittleEndianInteger Integer>
[[nodiscard]] constexpr Integer read_le(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    std::uint64_t value{};
    for (std::size_t i = 0; i < sizeof(Integer); ++i)
        value |= std::to_integer<std::uint64_t>(bytes[offset + i]) << (8 * i);
    return static_cast<Integer>(value);
}

} // namespace filecrypt::utils
