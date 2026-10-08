#pragma once
#include <cstddef>
#include <cstdint>
#include <span>

namespace filecrypt::format {
inline constexpr std::size_t identification_size = 6;
/// 校验固定六字节识别前缀并返回受支持的协议版本。
[[nodiscard]] std::uint16_t detect_version(std::span<const std::byte> data);
}
