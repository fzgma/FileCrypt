#include <filecrypt/format/detect.hpp>
#include <array>
#include <algorithm>
#include <stdexcept>

namespace filecrypt::format {
/// 仅通过 FCRY 和小端版本号识别协议，不套用任何版本的完整 Header。
std::uint16_t detect_version(std::span<const std::byte> data) {
    constexpr std::array magic{std::byte{0x46}, std::byte{0x43}, std::byte{0x52}, std::byte{0x59}};
    if (data.size() < identification_size || !std::equal(magic.begin(), magic.end(), data.begin())) {
        throw std::invalid_argument("Invalid FileCrypt identification prefix");
    }
    const auto version = static_cast<std::uint16_t>(std::to_integer<unsigned>(data[4]) |
        (std::to_integer<unsigned>(data[5]) << 8));
    if (version != 1) {
        throw std::invalid_argument("Unsupported FileCrypt version");
    }
    return version;
}
}
