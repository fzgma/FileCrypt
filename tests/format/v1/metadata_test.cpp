#include <filecrypt/format/v1/metadata.hpp>
#include <filecrypt/format/v1/registry.hpp>

#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace {
using namespace filecrypt::format::v1;

/// 条件失败时抛出带有原因的测试异常。
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/// 验证指定操作会明确拒绝非法格式或不支持的编号。
template <typename Function>
void require_invalid(Function action) {
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("Invalid Metadata was accepted");
}

/// 将独立列出的十六进制测试向量转换为字节数组。
std::vector<std::byte> hex_bytes(std::string_view text) {
    std::istringstream input{std::string(text)};
    std::vector<std::byte> result;
    unsigned value;
    while (input >> std::hex >> value) {
        require(value <= 255, "Invalid test vector byte");
        result.push_back(static_cast<std::byte>(value));
    }
    return result;
}

/// 构造使用已知字段值的合法 v1 Header。
Header sample_header(std::uint16_t algorithm, std::uint16_t flags) {
    Header header;
    header.version = 1;
    header.flags = flags;
    header.algorithm = algorithm;
    header.file_type = (flags & 0x8000) != 0 ? 0 : 0xFFFE;
    header.metadata_length = metadata_layout(header).metadata_size;
    return header;
}

/// 构造与 Header 对应的固定 Metadata 测试样本。
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
    for (std::size_t i = 0; i < 16; ++i) {
        metadata.salt[i] = static_cast<std::byte>(0x10 + i);
        metadata.tag[i] = static_cast<std::byte>(0x40 + i);
    }
    metadata.nonce.resize(header.algorithm == 1 ? 12 : 24);
    for (std::size_t i = 0; i < metadata.nonce.size(); ++i) {
        metadata.nonce[i] = static_cast<std::byte>(0x20 + i);
    }
    return metadata;
}

/// 用八组固定布局向量验证编码、解码和最小零填充。
void test_fixed_vectors() {
    // 独立列出的布局大小，不使用被测布局函数生成预期值。
    constexpr std::size_t sizes[2][4]{{64, 80, 80, 80}, {80, 80, 96, 96}};
    constexpr std::size_t paddings[2][4]{{2, 14, 10, 6}, {6, 2, 14, 10}};
    constexpr std::uint16_t flags[]{0, 0x4000, 0x8000, 0xC000};
    for (std::uint16_t algorithm = 1; algorithm <= 2; ++algorithm) {
        for (std::size_t i = 0; i < 4; ++i) {
            const auto header = sample_header(algorithm, flags[i]);
            const auto metadata = sample_metadata(header);
            std::string vector;
            if ((flags[i] & 0x8000) != 0) {
                vector += "08 07 06 05 04 03 02 01 ";
            }
            if ((flags[i] & 0x4000) != 0) {
                vector += "01 00 00 00 ";
            }
            vector += "01 00 13 00 00 00 03 02 01 00 04 03 02 00 02 00 00 00 ";
            vector += "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f ";
            vector += "20 21 22 23 24 25 26 27 28 29 2a 2b ";
            if (algorithm == 2) {
                vector += "2c 2d 2e 2f 30 31 32 33 34 35 36 37 ";
            }
            auto expected = hex_bytes(vector);
            expected.insert(expected.end(), paddings[algorithm - 1][i], std::byte{0});
            const auto tag = hex_bytes("40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f");
            expected.insert(expected.end(), tag.begin(), tag.end());
            require(expected.size() == sizes[algorithm - 1][i], "Test vector size mismatch");
            const auto layout = metadata_layout(header);
            require(layout.metadata_size == expected.size(), "Metadata layout size mismatch");
            require(layout.padding_size == paddings[algorithm - 1][i], "Padding size mismatch");
            require(serialize_metadata(header, metadata) == expected, "Fixed encoding mismatch");
            require(deserialize_metadata(header, expected) == metadata, "Fixed decoding mismatch");
            require(deserialize_metadata(header, serialize_metadata(header, metadata)) == metadata,
                "Metadata round-trip mismatch");
        }
    }
}

/// 验证 Registry 中的固定定义及未知编号拒绝行为。
void test_registry() {
    const auto& aes = algorithm_definition(1);
    const auto& xchacha = algorithm_definition(2);
    require(aes.id == 1 && aes.key_size == 32 && aes.nonce_size == 12 && aes.tag_size == 16 &&
        aes.max_message_size == 68719476704ULL, "AES definition mismatch");
    require(xchacha.id == 2 && xchacha.key_size == 32 && xchacha.nonce_size == 24 &&
        xchacha.tag_size == 16 && xchacha.max_message_size == 274877906880ULL,
        "XChaCha definition mismatch");
    require(kdf_definition(1).parameters_size == 16 && kdf_definition(1).salt_size == 16,
        "KDF definition mismatch");
    require(compression_definition(1).parameters_size == 0, "Compression definition mismatch");
    for (const auto id : {std::uint16_t{0}, std::uint16_t{3}, std::uint16_t{0xFFFF}}) {
        require_invalid([id] { (void)algorithm_definition(id); });
        require_invalid([id] { (void)kdf_definition(id); });
        require_invalid([id] { (void)compression_definition(id); });
    }
}

/// 验证所有组合的截断、额外数据、恶意长度和非零填充均被拒绝。
void test_lengths() {
    for (const auto algorithm : {std::uint16_t{1}, std::uint16_t{2}}) {
        for (const auto flags : {std::uint16_t{0}, std::uint16_t{0x4000},
                                std::uint16_t{0x8000}, std::uint16_t{0xC000}}) {
            const auto header = sample_header(algorithm, flags);
            const auto valid = serialize_metadata(header, sample_metadata(header));
            for (std::size_t size = 0; size < valid.size(); ++size) {
                auto shortened_header = header;
                shortened_header.metadata_length = size;
                const auto truncated = std::span<const std::byte>(valid).first(size);
                require_invalid([&] { (void)deserialize_metadata(header, truncated); });
                require_invalid([&] { (void)deserialize_metadata(shortened_header, truncated); });
            }
            auto altered = valid;
            altered[metadata_layout(header).padding_offset] = std::byte{1};
            require_invalid([&] { (void)deserialize_metadata(header, altered); });
            altered = valid;
            altered.resize(valid.size() + 16);
            auto extended_header = header;
            extended_header.metadata_length = altered.size();
            require_invalid([&] { (void)deserialize_metadata(header, altered); });
            require_invalid([&] { (void)deserialize_metadata(extended_header, altered); });
            auto huge_header = header;
            huge_header.metadata_length = std::numeric_limits<std::uint64_t>::max();
            require_invalid([&] { (void)deserialize_metadata(huge_header, valid); });
            require_invalid([&] { (void)serialize_metadata(huge_header, sample_metadata(header)); });
        }
    }
}

/// 验证非法参数、编号、字段存在性及 Header 上下文均被拒绝。
void test_invalid_fields() {
    const auto header = sample_header(1, 0xC000);
    const auto metadata = sample_metadata(header);
    const auto valid = serialize_metadata(header, metadata);
    const auto layout = metadata_layout(header);
    for (const auto offset : {*layout.compression_offset, *layout.compression_offset + 2,
            layout.kdf_id_offset, layout.kdf_parameters_offset,
            layout.kdf_parameters_offset + 1, layout.kdf_parameters_offset + 2,
            layout.kdf_parameters_offset + 3}) {
        auto altered = valid;
        altered[offset] = std::byte{0xFF};
        require_invalid([&] { (void)deserialize_metadata(header, altered); });
    }
    for (const auto offset : {layout.kdf_parameters_offset + 4,
                             layout.kdf_parameters_offset + 8,
                             layout.kdf_parameters_offset + 12}) {
        auto altered = valid;
        std::fill_n(altered.begin() + offset, 4, std::byte{0});
        require_invalid([&] { (void)deserialize_metadata(header, altered); });
    }
    auto oversized_lanes = valid;
    std::fill_n(oversized_lanes.begin() + layout.kdf_parameters_offset + 12, 4,
        std::byte{0xFF});
    require_invalid([&] { (void)deserialize_metadata(header, oversized_lanes); });
    // 同时测试编码和解码路径，避免只在一侧执行语义校验。
    for (int test = 0; test < 6; ++test) {
        auto altered = metadata;
        auto& parameters = altered.kdf_parameters;
        switch (test) {
        case 0: parameters.version = 0x10; break;
        case 1: parameters.reserved[0] = std::byte{1}; break;
        case 2: parameters.time_cost = 0; break;
        case 3: parameters.parallelism = 0; break;
        case 4: parameters.parallelism = 0xFFFFFFFF; break;
        case 5: parameters.memory_cost_kib = 15; break;
        }
        require_invalid([&] { (void)serialize_metadata(header, altered); });
    }
    auto altered = metadata;
    altered.index_length.reset();
    require_invalid([&] { (void)serialize_metadata(header, altered); });
    altered = metadata;
    altered.compression.reset();
    require_invalid([&] { (void)serialize_metadata(header, altered); });
    altered = metadata;
    altered.compression->parameters.push_back(std::byte{0});
    require_invalid([&] { (void)serialize_metadata(header, altered); });
    altered = metadata;
    altered.compression->id = 0;
    require_invalid([&] { (void)serialize_metadata(header, altered); });
    altered = metadata;
    altered.kdf_id = 0;
    require_invalid([&] { (void)serialize_metadata(header, altered); });
    for (const auto size : {std::size_t{0}, std::size_t{11}, std::size_t{13}, std::size_t{24}}) {
        altered = metadata;
        altered.nonce.resize(size);
        require_invalid([&] { (void)serialize_metadata(header, altered); });
    }
    const auto single_header = sample_header(1, 0);
    const auto single_metadata = sample_metadata(single_header);
    for (const auto type : {std::uint16_t{0}, std::uint16_t{1},
                           std::uint16_t{0xFFFD}, std::uint16_t{0xFFFF}}) {
        auto invalid_header = single_header;
        invalid_header.file_type = type;
        const auto bytes = serialize_metadata(single_header, single_metadata);
        require_invalid([&] { (void)serialize_metadata(invalid_header, single_metadata); });
        require_invalid([&] { (void)deserialize_metadata(invalid_header, bytes); });
    }
    require_invalid([&] { (void)serialize_metadata(single_header, metadata); });
    altered = single_metadata;
    altered.compression = CompressionMetadata{};
    require_invalid([&] { (void)serialize_metadata(single_header, altered); });
    altered = single_metadata;
    altered.index_length = 0;
    require_invalid([&] { (void)serialize_metadata(single_header, altered); });
    for (int test = 0; test < 6; ++test) {
        auto invalid_header = header;
        switch (test) {
        case 0: invalid_header.version = 2; break;
        case 1: invalid_header.flags |= 1; break;
        case 2: invalid_header.algorithm = 3; break;
        case 3: invalid_header.reserved[0] = std::byte{1}; break;
        case 4: invalid_header.file_type = 0xFFFF; break;
        case 5: invalid_header.file_type = 0xFFFE; break;
        }
        require_invalid([&] { (void)serialize_metadata(invalid_header, metadata); });
        require_invalid([&] { (void)deserialize_metadata(invalid_header, valid); });
    }
}

/// 验证合法成本边界和最大 Index Length 的无截断往返转换。
void test_boundaries() {
    const auto header = sample_header(2, 0x8000);
    auto metadata = sample_metadata(header);
    for (const auto index : {std::uint64_t{0}, std::numeric_limits<std::uint64_t>::max()}) {
        metadata.index_length = index;
        for (const auto lanes : {std::uint32_t{1}, std::uint32_t{0xFFFFFF}}) {
            metadata.kdf_parameters.parallelism = lanes;
            metadata.kdf_parameters.memory_cost_kib = 8 * lanes;
            metadata.kdf_parameters.time_cost = 1;
            require(deserialize_metadata(header, serialize_metadata(header, metadata)) == metadata,
                "Minimum Argon2 costs or Index Length boundary mismatch");
        }
        metadata.kdf_parameters.memory_cost_kib = std::numeric_limits<std::uint32_t>::max();
        metadata.kdf_parameters.time_cost = std::numeric_limits<std::uint32_t>::max();
        metadata.salt.fill(std::byte{0xFF});
        metadata.tag.fill(std::byte{0xFF});
        require(deserialize_metadata(header, serialize_metadata(header, metadata)) == metadata,
            "Maximum fields boundary mismatch");
    }
}
}

/// 执行全部 Metadata 测试并通过退出码报告结果。
int main() {
    try {
        test_registry();
        test_fixed_vectors();
        test_lengths();
        test_invalid_fields();
        test_boundaries();
        std::cout << "Metadata tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Metadata test failed: " << error.what() << '\n';
        return 1;
    }
}
