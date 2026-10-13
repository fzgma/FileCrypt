#include <filecrypt/format/v1/header.hpp>
#include "../../utils/little_endian.hpp"

#include <algorithm>
#include <stdexcept>

namespace filecrypt::format::v1 {
using utils::read_le;
using utils::write_le;

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
        throw FormatError("FileCrypt Header 至少需要 32 字节");
    }
    if (!std::equal(header_magic.begin(), header_magic.end(), data.begin())) {
        throw FormatError("FileCrypt Header 的 Magic 无效");
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

/// 复用 Header 解析，将已分类格式错误转换为 expected；其他异常继续传播。
std::expected<Header, Error> try_deserialize(std::span<const std::byte> data) {
    try {
        return deserialize(data);
    } catch (const FormatError& error) {
        return std::unexpected(error_from_exception(error));
    }
}

} // namespace filecrypt::format::v1
