#include <filecrypt/format/v1/registry.hpp>

#include <stdexcept>

namespace filecrypt::format::v1 {
namespace {
constexpr AlgorithmDefinition aes{1, "AES-256-GCM", 32, 12, 16,
    (std::uint64_t{1} << 36) - 32};
constexpr AlgorithmDefinition xchacha{2, "XChaCha20-Poly1305", 32, 24, 16,
    (std::uint64_t{1} << 38) - 64};
constexpr KdfDefinition argon2id{1, "Argon2id", 16, 16};
constexpr CompressionDefinition zstandard{1, "Zstandard", 0};
constexpr FileTypeDefinition file_types[]{
    {0x0001, "txt"}, {0x0002, "md"}, {0x0003, "csv"}, {0x0004, "json"},
    {0x0005, "xml"}, {0x0006, "yaml"}, {0x0007, "yml"}, {0x0008, "pdf"},
    {0x0009, "png"}, {0x000A, "jpg"}, {0x000B, "jpeg"}, {0x000C, "gif"},
    {0x000D, "bmp"}, {0x000E, "webp"}, {0x000F, "svg"}, {0x0010, "tif"},
    {0x0011, "tiff"}, {0x0012, "zip"}, {0x0013, "7z"}, {0x0014, "rar"},
    {0x0015, "tar"}, {0x0016, "gz"}, {0x0017, "bz2"}, {0x0018, "xz"},
    {0x0019, "zst"}, {0x001A, "mp3"}, {0x001B, "wav"}, {0x001C, "flac"},
    {0x001D, "mp4"}, {0x001E, "mkv"}, {0x001F, "mov"}, {0x0020, "avi"},
    {0x0021, "tar.gz"}, {0x0022, "tar.bz2"}, {0x0023, "tar.xz"}, {0x0024, "tar.zst"}};
constexpr FileTypeDefinition not_applicable{0, ""};
constexpr FileTypeDefinition unknown{unknown_file_type, ""};
}

std::span<const FileTypeDefinition> file_type_definitions() {
    return file_types;
}

const FileTypeDefinition& file_type_definition(std::uint16_t id) {
    if (id == 0) return not_applicable;
    if (id == unknown_file_type) return unknown;
    for (const auto& type : file_types) {
        if (type.id == id) return type;
    }
    throw std::invalid_argument("Unsupported or invalid v1 file type ID");
}

std::uint16_t file_type_id(std::string_view extension) {
    for (const auto& type : file_types) {
        if (type.extension == extension) return type.id;
    }
    return unknown_file_type;
}

/// 根据协议编号返回 v1 算法的固定定义。
const AlgorithmDefinition& algorithm_definition(std::uint16_t id) {
    switch (id) {
    case 1: return aes;
    case 2: return xchacha;
    default: throw std::invalid_argument("Unsupported v1 algorithm ID");
    }
}

/// 根据协议编号返回 v1 KDF 的固定定义。
const KdfDefinition& kdf_definition(std::uint16_t id) {
    if (id != argon2id.id) {
        throw std::invalid_argument("Unsupported v1 KDF ID");
    }
    return argon2id;
}

/// 根据协议编号返回 v1 压缩算法的固定定义。
const CompressionDefinition& compression_definition(std::uint16_t id) {
    if (id != zstandard.id) {
        throw std::invalid_argument("Unsupported v1 compression ID");
    }
    return zstandard;
}
} // namespace filecrypt::format::v1
