#include <filecrypt/format/v1/header.hpp>

#include <algorithm>
#include <stdexcept>

namespace filecrypt::format::v1 {
namespace {

/// 将无符号整数按小端顺序写入指定偏移。
template <typename Integer>
void write_le(std::span<std::byte> data, std::size_t offset, Integer value) {
    for (std::size_t i = 0; i < sizeof(Integer); ++i) {
        data[offset + i] = static_cast<std::byte>((value >> (8 * i)) & 0xFFu);
    }
}

/// 从指定偏移读取小端编码的无符号整数。
template <typename Integer>
Integer read_le(std::span<const std::byte> data, std::size_t offset) {
    std::uint64_t value{};
    for (std::size_t i = 0; i < sizeof(Integer); ++i) {
        value |= std::to_integer<std::uint64_t>(data[offset + i]) << (8 * i);
    }
    return static_cast<Integer>(value);
}

} // namespace

/// 按协议规定的偏移将 Header 编码为 32 字节。
std::array<std::byte, header_size> serialize(const Header& header) {
    std::array<std::byte, header_size> data{};
    std::copy(header_magic.begin(), header_magic.end(), data.begin());
    write_le(data, 0x04, header.version);
    write_le(data, 0x06, header.flags);
    write_le(data, 0x08, header.algorithm);
    write_le(data, 0x0A, header.file_type);
    write_le(data, 0x0C, header.metadata_length);
    std::copy(header.reserved.begin(), header.reserved.end(), data.begin() + 0x14);
    return data;
}

/// 检查输入长度与 Magic 后读取 Header 的各个字段。
Header deserialize(std::span<const std::byte> data) {
    if (data.size() < header_size) {
        throw std::invalid_argument("FileCrypt header requires at least 32 bytes");
    }
    if (!std::equal(header_magic.begin(), header_magic.end(), data.begin())) {
        throw std::invalid_argument("Invalid FileCrypt header magic");
    }

    Header header;
    header.version = read_le<std::uint16_t>(data, 0x04);
    header.flags = read_le<std::uint16_t>(data, 0x06);
    header.algorithm = read_le<std::uint16_t>(data, 0x08);
    header.file_type = read_le<std::uint16_t>(data, 0x0A);
    header.metadata_length = read_le<std::uint64_t>(data, 0x0C);
    std::copy_n(data.begin() + 0x14, header.reserved.size(), header.reserved.begin());
    return header;
}

} // namespace filecrypt::format::v1
