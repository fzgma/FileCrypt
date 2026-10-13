#pragma once
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>

namespace filecrypt::utils {

/// 使用拒绝采样均匀选择字符，随机缓冲区由调用方提供并负责安全清理。
template<class FillRandom>
void fill_random_password(std::span<std::uint8_t> output, std::string_view alphabet,
    std::span<std::uint8_t> random_buffer, FillRandom fill_random) {
    if (alphabet.empty() || alphabet.size() > 256 || random_buffer.empty())
        throw std::invalid_argument("密码采样参数无效");
    const auto accepted = 256 - 256 % alphabet.size();
    std::size_t position{};
    while (position < output.size()) {
        fill_random(random_buffer);
        for (const auto value : random_buffer) {
            // 拒绝不足一整组字符集的尾部，避免直接取模产生偏差。
            if (value >= accepted) continue;
            output[position++] = static_cast<std::uint8_t>(alphabet[value % alphabet.size()]);
            if (position == output.size()) break;
        }
    }
}

} // namespace filecrypt::utils
