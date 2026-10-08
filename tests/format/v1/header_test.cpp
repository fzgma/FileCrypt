#include <filecrypt/format/v1/header.hpp>

#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {
using namespace filecrypt::format::v1;

/// 条件不满足时抛出包含失败原因的测试异常。
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/// 验证非法输入会导致反序列化抛出 std::invalid_argument。
void require_invalid(std::span<const std::byte> data) {
    try {
        (void)deserialize(data);
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("Invalid input was accepted");
}

/// 使用固定字节向量验证编码、解码、往返转换与尾随数据处理。
void test_fixed_vector() {
    const Header expected{0x1234, 0x8000, 0x0102, 0x0304,
        0x0102030405060708ULL,
        {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
         std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
         std::byte{0x08}, std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}}};
    // 独立列出预期字节，避免编码与解码的同类错误被往返测试掩盖。
    constexpr std::array<std::byte, 32> bytes{
        std::byte{0x46}, std::byte{0x43}, std::byte{0x52}, std::byte{0x59},
        std::byte{0x34}, std::byte{0x12}, std::byte{0x00}, std::byte{0x80},
        std::byte{0x02}, std::byte{0x01}, std::byte{0x04}, std::byte{0x03},
        std::byte{0x08}, std::byte{0x07}, std::byte{0x06}, std::byte{0x05},
        std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
        std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
        std::byte{0x08}, std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}};

    require(serialize(expected) == bytes, "Fixed encoding vector mismatch");
    require(deserialize(bytes) == expected, "Fixed decoding vector mismatch");
    require(deserialize(serialize(expected)) == expected, "Round-trip mismatch");

    std::vector<std::byte> extended(bytes.begin(), bytes.end());
    extended.push_back(std::byte{0xFF});
    require(deserialize(extended) == expected, "Trailing data changed header");
}

/// 验证四种已定义 Flags 组合的小端编码与往返转换。
void test_flags() {
    for (const auto flags : std::array<std::uint16_t, 4>{0, 0x4000, 0x8000, 0xC000}) {
        Header header;
        header.flags = flags;
        const auto bytes = serialize(header);
        require(bytes[6] == std::byte{0}, "Flags low byte mismatch");
        require(bytes[7] == static_cast<std::byte>(flags >> 8), "Flags high byte mismatch");
        require(deserialize(bytes) == header, "Flags round-trip mismatch");
    }
}

/// 验证 Metadata Length 边界值与 Reserved 全零、全 FF 的编码。
void test_boundaries() {
    for (const auto length : std::array<std::uint64_t, 3>{
             0, 16, std::numeric_limits<std::uint64_t>::max()}) {
        for (const auto reserved : {std::byte{0}, std::byte{0xFF}}) {
            Header header;
            header.metadata_length = length;
            header.reserved.fill(reserved);
            const auto bytes = serialize(header);
            for (std::size_t i = 0; i < 8; ++i) {
                require(bytes[12 + i] == static_cast<std::byte>((length >> (8 * i)) & 0xFFu),
                        "Metadata length boundary encoding mismatch");
            }
            require(std::all_of(bytes.begin() + 20, bytes.end(),
                        [reserved](std::byte value) { return value == reserved; }),
                    "Reserved boundary encoding mismatch");
            require(deserialize(bytes) == header, "Boundary round-trip mismatch");
        }
    }
}

/// 验证所有短输入和错误 Magic 均被拒绝。
void test_invalid_inputs() {
    const auto valid = serialize(Header{});
    for (std::size_t length = 0; length < header_size; ++length) {
        require_invalid(std::span<const std::byte>(valid).first(length));
    }
    for (std::size_t i = 0; i < header_magic.size(); ++i) {
        auto corrupt = valid;
        corrupt[i] ^= std::byte{0x01};
        require_invalid(corrupt);
    }
    for (const auto magic : {std::array<char, 4>{'F', 'C', 'r', 'y'},
                            std::array<char, 4>{'f', 'c', 'r', 'y'},
                            std::array<char, 4>{'F', 'C', 'R', 'X'}}) {
        auto corrupt = valid;
        for (std::size_t i = 0; i < magic.size(); ++i) {
            corrupt[i] = static_cast<std::byte>(magic[i]);
        }
        require_invalid(corrupt);
    }
}
} // namespace

/// 运行全部 Header 测试并通过退出码报告结果。
int main() {
    try {
        test_fixed_vector();
        test_flags();
        test_boundaries();
        test_invalid_inputs();
        std::cout << "Header tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Header test failed: " << error.what() << '\n';
        return 1;
    }
}
