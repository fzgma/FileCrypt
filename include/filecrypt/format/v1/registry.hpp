#pragma once

#include <cstdint>
#include <string_view>

namespace filecrypt::format::v1 {

struct AlgorithmDefinition {
    std::uint16_t id;
    std::string_view name;
    std::uint32_t key_size;
    std::uint32_t nonce_size;
    std::uint32_t tag_size;
    std::uint64_t max_message_size;
};

struct KdfDefinition {
    std::uint16_t id;
    std::string_view name;
    std::uint32_t parameters_size;
    std::uint32_t salt_size;
};

struct CompressionDefinition {
    std::uint16_t id;
    std::string_view name;
    std::uint32_t parameters_size;
};

// Registry 只保存协议定义，不依赖底层密码库或压缩库。
/// 查询 v1 算法定义，未知 ID 抛出 std::invalid_argument。
[[nodiscard]] const AlgorithmDefinition& algorithm_definition(std::uint16_t id);
/// 查询 v1 KDF 定义，未知 ID 抛出 std::invalid_argument。
[[nodiscard]] const KdfDefinition& kdf_definition(std::uint16_t id);
/// 查询 v1 压缩定义，未知 ID 抛出 std::invalid_argument。
[[nodiscard]] const CompressionDefinition& compression_definition(std::uint16_t id);

} // namespace filecrypt::format::v1
