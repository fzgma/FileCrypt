#include <filecrypt/format/v1/aad.hpp>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace {
using namespace filecrypt::format::v1;

/// 条件失败时报告具体测试原因。
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/// 将独立书写的十六进制向量转换为测试字节。
std::vector<std::byte> hex_bytes(std::string_view text) {
    std::istringstream input{std::string(text)};
    std::vector<std::byte> result;
    unsigned value;
    while (input >> std::hex >> value) {
        require(value <= 255, "Invalid test byte");
        result.push_back(static_cast<std::byte>(value));
    }
    return result;
}

/// 验证 AAD 构造拒绝非法格式输入。
template <typename Function>
void require_invalid(Function action) {
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("Invalid AAD input was accepted");
}

/// 构造对应算法与容器标志的合法 Header。
Header sample_header(std::uint16_t algorithm, std::uint16_t flags) {
    Header header;
    header.version = 1;
    header.algorithm = algorithm;
    header.flags = flags;
    header.file_type = (flags & 0x8000) != 0 ? 0 : 0xFFFE;
    header.metadata_length = metadata_layout(header).metadata_size;
    return header;
}

/// 构造带有可辨认 Salt、Nonce 和 Tag 的固定 Metadata。
Metadata sample_metadata(const Header& header) {
    Metadata metadata;
    if ((header.flags & 0x8000) != 0) {
        metadata.index_length = 0x0102030405060708ULL;
    }
    if ((header.flags & 0x4000) != 0) {
        metadata.compression = CompressionMetadata{};
    }
    metadata.kdf_parameters.memory_cost_kib = 0x00010203;
    metadata.kdf_parameters.time_cost = 0x00020304;
    metadata.kdf_parameters.parallelism = 2;
    for (std::size_t i = 0; i < metadata.salt.size(); ++i) {
        metadata.salt[i] = static_cast<std::byte>(0x10 + i);
    }
    metadata.nonce = hex_bytes("20 21 22 23 24 25 26 27 28 29 2a 2b");
    if (header.algorithm == 2) {
        const auto extra = hex_bytes("2c 2d 2e 2f 30 31 32 33 34 35 36 37");
        metadata.nonce.insert(metadata.nonce.end(), extra.begin(), extra.end());
    }
    metadata.tag.fill(std::byte{0xFF});
    return metadata;
}

/// 使用八种完整 AAD 固定向量验证 Header、字段、零填充及 Tag 边界。
void test_fixed_vectors() {
    constexpr std::uint16_t flags[]{0, 0x4000, 0x8000, 0xC000};
    constexpr std::size_t sizes[2][4]{{64, 80, 80, 80}, {80, 80, 96, 96}};
    constexpr std::size_t padding[2][4]{{2, 14, 10, 6}, {6, 2, 14, 10}};
    for (std::uint16_t algorithm = 1; algorithm <= 2; ++algorithm) {
        for (std::size_t i = 0; i < 4; ++i) {
            const auto header = sample_header(algorithm, flags[i]);
            const auto metadata = sample_metadata(header);
            // 预期值独立书写，不使用序列化器或布局函数计算认证边界。
            std::string expected_hex = "46 43 52 59 01 00 ";
            constexpr std::string_view flag_hex[]{"00 00 ", "00 40 ", "00 80 ", "00 c0 "};
            expected_hex += flag_hex[i];
            expected_hex += algorithm == 1 ? "01 00 " : "02 00 ";
            expected_hex += i < 2 ? "fe ff " : "00 00 ";
            expected_hex += sizes[algorithm - 1][i] == 64 ? "40 " :
                sizes[algorithm - 1][i] == 80 ? "50 " : "60 ";
            expected_hex += "00 00 00 00 00 00 00 ";
            expected_hex += "00 00 00 00 00 00 00 00 00 00 00 00 ";
            if (i >= 2) {
                expected_hex += "08 07 06 05 04 03 02 01 ";
            }
            if (i == 1 || i == 3) {
                expected_hex += "01 00 00 00 ";
            }
            expected_hex += "01 00 13 00 00 00 03 02 01 00 04 03 02 00 02 00 00 00 ";
            expected_hex += "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f ";
            expected_hex += "20 21 22 23 24 25 26 27 28 29 2a 2b ";
            if (algorithm == 2) {
                expected_hex += "2c 2d 2e 2f 30 31 32 33 34 35 36 37 ";
            }
            auto expected = hex_bytes(expected_hex);
            expected.insert(expected.end(), padding[algorithm - 1][i], std::byte{0});
            require(expected.size() == 32 + sizes[algorithm - 1][i] - 16,
                "Expected AAD size mismatch");
            require(build_aad(header, metadata) == expected, "Object AAD vector mismatch");
            const auto header_bytes = serialize(header);
            const auto metadata_bytes = serialize_metadata(header, metadata);
            require(build_aad(header_bytes, metadata_bytes) == expected, "Raw AAD vector mismatch");
            // 任意 Tag 字节变化不能改变 AAD，包含占位 Tag 和最终 Tag。
            for (std::size_t tag_byte = 0; tag_byte < 16; ++tag_byte) {
                auto changed = metadata_bytes;
                changed[changed.size() - 16 + tag_byte] ^= std::byte{0xFF};
                require(build_aad(header_bytes, changed) == expected, "Tag entered AAD");
            }
            auto placeholder = metadata;
            placeholder.tag.fill(std::byte{0});
            require(build_aad(header, placeholder) == expected, "Placeholder Tag changed AAD");
        }
    }
}

/// 验证合法字段变化会改变认证字节，非法 Padding 则直接拒绝。
void test_authenticated_fields() {
    const auto header = sample_header(1, 0x8000);
    const auto metadata = sample_metadata(header);
    const auto original = build_aad(header, metadata);
    for (int field = 0; field < 6; ++field) {
        auto changed = metadata;
        switch (field) {
        case 0: ++*changed.index_length; break;
        case 1: changed.salt[0] ^= std::byte{1}; break;
        case 2: changed.nonce[0] ^= std::byte{1}; break;
        case 3: ++changed.kdf_parameters.memory_cost_kib; break;
        case 4: ++changed.kdf_parameters.time_cost; break;
        case 5: ++changed.kdf_parameters.parallelism; break;
        }
        require(build_aad(header, changed) != original, "Metadata change absent from AAD");
    }
    const auto changed_header = sample_header(2, 0x8000);
    require(build_aad(changed_header, sample_metadata(changed_header)) != original,
        "Algorithm change absent from AAD");
    const auto compressed_header = sample_header(1, 0xC000);
    require(build_aad(compressed_header, sample_metadata(compressed_header)) != original,
        "Compression change absent from AAD");
    const auto single_header = sample_header(1, 0);
    require(build_aad(single_header, sample_metadata(single_header)) != original,
        "Container change absent from AAD");
    const auto header_bytes = serialize(header);
    const auto bytes = serialize_metadata(header, metadata);
    const auto layout = metadata_layout(header);
    for (std::size_t offset = layout.padding_offset; offset < layout.tag_offset; ++offset) {
        require(original[32 + offset] == std::byte{0}, "Padding absent from AAD");
        auto changed = bytes;
        changed[offset] = std::byte{1};
        require_invalid([&] { (void)build_aad(header_bytes, changed); });
    }
}

/// 验证原始字节输入和对象输入均执行必要的格式校验。
void test_invalid_inputs() {
    const auto header = sample_header(1, 0xC000);
    const auto metadata = sample_metadata(header);
    const auto header_bytes = serialize(header);
    const auto bytes = serialize_metadata(header, metadata);
    for (std::size_t length = 0; length < 32; ++length) {
        require_invalid([&] { (void)build_aad(std::span(header_bytes).first(length), bytes); });
    }
    std::vector<std::byte> extended_header(header_bytes.begin(), header_bytes.end());
    extended_header.push_back(std::byte{0});
    require_invalid([&] { (void)build_aad(extended_header, bytes); });
    for (std::size_t length = 0; length < bytes.size(); ++length) {
        require_invalid([&] { (void)build_aad(header_bytes, std::span(bytes).first(length)); });
    }
    auto extended = bytes;
    extended.resize(bytes.size() + 16);
    require_invalid([&] { (void)build_aad(header_bytes, extended); });
    // 任何 Header 位变化必须改变 AAD 或因违反协议而被拒绝。
    for (std::size_t offset = 0; offset < header_bytes.size(); ++offset) {
        auto changed = header_bytes;
        changed[offset] ^= std::byte{1};
        try {
            require(build_aad(changed, bytes) != build_aad(header_bytes, bytes),
                "Header change absent from AAD");
        } catch (const std::invalid_argument&) {
            // v1 严格校验会拒绝未知 ID、版本、Reserved 和布局不匹配。
        }
    }
    auto invalid_metadata = metadata;
    invalid_metadata.kdf_parameters.time_cost = 0;
    require_invalid([&] { (void)build_aad(header, invalid_metadata); });
    const auto layout = metadata_layout(header);
    for (const auto offset : {*layout.compression_offset, *layout.compression_offset + 2,
            layout.kdf_id_offset, layout.kdf_parameters_offset}) {
        auto changed = bytes;
        changed[offset] = std::byte{0xFF};
        require_invalid([&] { (void)build_aad(header_bytes, changed); });
    }
}
}

/// 运行全部 v1 AAD 测试并通过退出码报告结果。
int main() {
    try {
        test_fixed_vectors();
        test_authenticated_fields();
        test_invalid_inputs();
        std::cout << "AAD tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "AAD test failed: " << error.what() << '\n';
        return 1;
    }
}
