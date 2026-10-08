#include <filecrypt/format/detect.hpp>
#include <filecrypt/app/operations.hpp>
#include <array>
#include <iostream>
#include <stdexcept>

namespace {
/// 验证识别或应用分发操作拒绝不支持的输入。
template <typename Function>
void require_invalid(Function action) {
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("Unsupported input was accepted");
}
}

/// 验证版本识别只依赖六字节前缀并严格拒绝截断、错误 Magic 和未知版本。
int main() {
    try {
        constexpr std::array prefix{std::byte{0x46}, std::byte{0x43}, std::byte{0x52},
            std::byte{0x59}, std::byte{1}, std::byte{0}};
        if (filecrypt::format::detect_version(prefix) != 1) {
            throw std::runtime_error("Version mismatch");
        }
        for (std::size_t length = 0; length < prefix.size(); ++length) {
            require_invalid([&] {
                (void)filecrypt::format::detect_version(std::span(prefix).first(length));
            });
        }
        for (std::size_t offset = 0; offset < 4; ++offset) {
            auto invalid = prefix;
            invalid[offset] ^= std::byte{1};
            require_invalid([&] { (void)filecrypt::format::detect_version(invalid); });
        }
        for (const auto version : {0u, 2u, 256u, 65535u}) {
            auto invalid = prefix;
            invalid[4] = static_cast<std::byte>(version & 255);
            invalid[5] = static_cast<std::byte>(version >> 8);
            require_invalid([&] { (void)filecrypt::format::detect_version(invalid); });
            filecrypt::app::SampleOptions options;
            options.version = static_cast<std::uint16_t>(version);
            // 空路径不会被访问，未知版本必须在任何文件操作之前拒绝。
            require_invalid([&] { filecrypt::app::generate_sample({}, options); });
        }
        std::cout << "Version detection tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
