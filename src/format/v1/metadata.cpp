#include <filecrypt/format/v1/metadata.hpp>
#include <filecrypt/format/v1/registry.hpp>

#include <algorithm>
#include <stdexcept>

namespace filecrypt::format::v1 {
namespace {
constexpr std::uint16_t directory_flag = 0x8000;
constexpr std::uint16_t compression_flag = 0x4000;

/// 条件不成立时抛出可定位格式问题的异常。
void check(bool condition, const char* message) {
    if (!condition) {
        throw std::invalid_argument(message);
    }
}

/// 校验 Metadata 所依赖的 v1 Header 上下文。
void validate_context(const Header& header) {
    check(header.version == 1, "Unsupported FileCrypt version");
    check((header.flags & 0x3FFF) == 0, "Reserved header flags must be zero");
    check(std::all_of(header.reserved.begin(), header.reserved.end(),
        [](std::byte value) { return value == std::byte{0}; }),
        "Reserved header bytes must be zero");
    const bool directory = (header.flags & directory_flag) != 0;
    check(directory ? header.file_type == 0 : header.file_type == 0xFFFE,
        "Unsupported or invalid v1 file type for container");
}

/// 校验 Argon2id 的协议参数而不执行密钥派生。
void validate_parameters(const Argon2idParameters& parameters) {
    check(parameters.version == 0x13, "Unsupported Argon2 version");
    check(std::all_of(parameters.reserved.begin(), parameters.reserved.end(),
        [](std::byte value) { return value == std::byte{0}; }),
        "Reserved Argon2 bytes must be zero");
    check(parameters.time_cost >= 1, "Invalid Argon2 time cost");
    check(parameters.parallelism >= 1 && parameters.parallelism <= 0xFFFFFF,
        "Invalid Argon2 parallelism");
    // 先提升为 64 位再相乘，避免恶意输入引发 32 位溢出。
    check(parameters.memory_cost_kib >= std::uint64_t{8} * parameters.parallelism,
        "Invalid Argon2 memory cost");
}

/// 将无符号整数写入指定位置的小端字段。
template <typename Integer>
void write_le(std::span<std::byte> data, std::size_t offset, Integer value) {
    for (std::size_t i = 0; i < sizeof(Integer); ++i) {
        data[offset + i] = static_cast<std::byte>((value >> (8 * i)) & 0xFFu);
    }
}

/// 确认字段未截断后读取指定位置的小端整数。
template <typename Integer>
Integer read_le(std::span<const std::byte> data, std::size_t offset) {
    check(offset <= data.size() && sizeof(Integer) <= data.size() - offset,
        "Truncated Metadata field");
    std::uint64_t value{};
    for (std::size_t i = 0; i < sizeof(Integer); ++i) {
        value |= std::to_integer<std::uint64_t>(data[offset + i]) << (8 * i);
    }
    return static_cast<Integer>(value);
}
}

/// 按容器、压缩和算法定义计算 Metadata 的固定布局。
MetadataLayout metadata_layout(const Header& header, std::uint16_t kdf_id,
    std::uint16_t compression_id) {
    validate_context(header);
    const auto& algorithm = algorithm_definition(header.algorithm);
    const auto& kdf = kdf_definition(kdf_id);
    MetadataLayout layout{};
    std::size_t offset{};
    if ((header.flags & directory_flag) != 0) {
        layout.index_offset = offset;
        offset += 8;
    }
    if ((header.flags & compression_flag) != 0) {
        const auto& compression = compression_definition(compression_id);
        layout.compression_offset = offset;
        offset += 4 + compression.parameters_size;
    }
    layout.kdf_id_offset = offset;
    offset += 2;
    layout.kdf_parameters_offset = offset;
    offset += kdf.parameters_size;
    layout.salt_offset = offset;
    offset += kdf.salt_size;
    layout.nonce_offset = offset;
    offset += algorithm.nonce_size;
    layout.padding_offset = offset;
    layout.padding_size = (16 - (offset + algorithm.tag_size) % 16) % 16;
    layout.tag_offset = offset + layout.padding_size;
    layout.metadata_size = layout.tag_offset + algorithm.tag_size;
    return layout;
}

/// 校验字段与上下文后按固定布局编码 Metadata 并生成零填充。
std::vector<std::byte> serialize_metadata(const Header& header, const Metadata& metadata) {
    const auto layout = metadata_layout(header, metadata.kdf_id,
        metadata.compression ? metadata.compression->id : 1);
    check(header.metadata_length == layout.metadata_size, "Metadata length mismatch");
    check(metadata.index_length.has_value() == layout.index_offset.has_value(),
        "Index Length presence mismatch");
    check(metadata.compression.has_value() == layout.compression_offset.has_value(),
        "Compression presence mismatch");
    if (metadata.compression) {
        check(metadata.compression->parameters.size() ==
            compression_definition(metadata.compression->id).parameters_size,
            "Invalid compression parameters length");
    }
    check(metadata.nonce.size() == algorithm_definition(header.algorithm).nonce_size,
        "Invalid nonce length");
    validate_parameters(metadata.kdf_parameters);
    std::vector<std::byte> data(layout.metadata_size, std::byte{0});
    if (layout.index_offset) {
        write_le(data, *layout.index_offset, *metadata.index_length);
    }
    if (layout.compression_offset) {
        write_le(data, *layout.compression_offset, metadata.compression->id);
        write_le(data, *layout.compression_offset + 2, std::uint16_t{0});
    }
    write_le(data, layout.kdf_id_offset, metadata.kdf_id);
    const auto offset = layout.kdf_parameters_offset;
    data[offset] = static_cast<std::byte>(metadata.kdf_parameters.version);
    write_le(data, offset + 4, metadata.kdf_parameters.memory_cost_kib);
    write_le(data, offset + 8, metadata.kdf_parameters.time_cost);
    write_le(data, offset + 12, metadata.kdf_parameters.parallelism);
    std::copy(metadata.salt.begin(), metadata.salt.end(), data.begin() + layout.salt_offset);
    std::copy(metadata.nonce.begin(), metadata.nonce.end(), data.begin() + layout.nonce_offset);
    std::copy(metadata.tag.begin(), metadata.tag.end(), data.begin() + layout.tag_offset);
    return data;
}

/// 先读取布局所需编号，再校验完整长度、参数和零填充并还原 Metadata。
Metadata deserialize_metadata(const Header& header, std::span<const std::byte> data) {
    validate_context(header);
    (void)algorithm_definition(header.algorithm);
    check(header.metadata_length == data.size(), "Metadata input length mismatch");
    Metadata metadata;
    std::size_t offset{};
    if ((header.flags & directory_flag) != 0) {
        metadata.index_length = read_le<std::uint64_t>(data, offset);
        offset += 8;
    }
    if ((header.flags & compression_flag) != 0) {
        const auto id = read_le<std::uint16_t>(data, offset);
        const auto length = read_le<std::uint16_t>(data, offset + 2);
        const auto& compression = compression_definition(id);
        check(length == compression.parameters_size, "Invalid compression parameters length");
        metadata.compression = CompressionMetadata{id, {}};
        offset += 4;
    }
    metadata.kdf_id = read_le<std::uint16_t>(data, offset);
    const auto layout = metadata_layout(header, metadata.kdf_id,
        metadata.compression ? metadata.compression->id : 1);
    // 布局只可能来自已支持的 Registry，先校验长度再访问后续字节。
    check(data.size() == layout.metadata_size, "Metadata layout length mismatch");
    offset = layout.kdf_parameters_offset;
    auto& parameters = metadata.kdf_parameters;
    parameters.version = std::to_integer<std::uint8_t>(data[offset]);
    std::copy_n(data.begin() + offset + 1, 3, parameters.reserved.begin());
    parameters.memory_cost_kib = read_le<std::uint32_t>(data, offset + 4);
    parameters.time_cost = read_le<std::uint32_t>(data, offset + 8);
    parameters.parallelism = read_le<std::uint32_t>(data, offset + 12);
    validate_parameters(parameters);
    std::copy_n(data.begin() + layout.salt_offset, metadata.salt.size(), metadata.salt.begin());
    metadata.nonce.assign(data.begin() + layout.nonce_offset, data.begin() + layout.padding_offset);
    std::copy_n(data.begin() + layout.tag_offset, metadata.tag.size(), metadata.tag.begin());
    check(std::all_of(data.begin() + layout.padding_offset, data.begin() + layout.tag_offset,
        [](std::byte value) { return value == std::byte{0}; }), "Nonzero Metadata padding");
    return metadata;
}
} // namespace filecrypt::format::v1
