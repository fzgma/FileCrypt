#include <filecrypt/format/v1/aad.hpp>

#include <stdexcept>

namespace filecrypt::format::v1 {

/// 序列化合法对象后构造与文件字节完全一致的 AAD。
std::vector<std::byte> build_aad(const Header& header, const Metadata& metadata) {
    const auto header_bytes = serialize(header);
    const auto metadata_bytes = serialize_metadata(header, metadata);
    return build_aad(header_bytes, metadata_bytes);
}

/// 严格校验原始前缀后保留 Header 和 Metadata 的原始认证字节。
std::vector<std::byte> build_aad(std::span<const std::byte> header_bytes,
    std::span<const std::byte> metadata_bytes) {
    if (header_bytes.size() != header_size) {
        throw std::invalid_argument("AAD requires exactly 32 header bytes");
    }
    const auto header = deserialize(header_bytes);
    const auto metadata = deserialize_metadata(header, metadata_bytes);
    const auto layout = metadata_layout(header, metadata.kdf_id,
        metadata.compression ? metadata.compression->id : 1);
    // 校验得到的 TagOffset 只用于切片，认证字节始终来自原始输入。
    const auto authenticated_metadata = metadata_bytes.first(layout.tag_offset);
    std::vector<std::byte> aad;
    aad.reserve(header_size + authenticated_metadata.size());
    aad.insert(aad.end(), header_bytes.begin(), header_bytes.end());
    aad.insert(aad.end(), authenticated_metadata.begin(), authenticated_metadata.end());
    return aad;
}
} // namespace filecrypt::format::v1
