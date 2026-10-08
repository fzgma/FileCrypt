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
