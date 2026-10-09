#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include <utility>
#include <filecrypt/crypto/crypto.hpp>

namespace filecrypt::app {
struct FileInfo {
    std::uint16_t version;
    std::string algorithm;
    bool compressed;
    std::string compression;
    bool directory;
    std::string file_type;
    std::string kdf;
    std::vector<std::pair<std::string, std::string>> details;
    bool has_payload;
    bool authenticated{false};
};

struct SampleOptions {
    std::uint16_t version{1};
    std::string algorithm{"aes-256-gcm"};
    bool directory{false};
    bool compressed{false};
};

struct EncryptOptions {
    std::uint16_t version{1};
    crypto::Algorithm algorithm{crypto::Algorithm::aes256_gcm};
    // 可调整的运行参数，不是协议常数；正式默认值仍待跨平台测量。
    crypto::Argon2idParameters kdf{65536, 3, 1};
    crypto::KdfLimits limits{262144, 10, 16};
};

/// 识别文件版本并调用相应流程读取公开信息。
[[nodiscard]] FileInfo inspect_file(const std::filesystem::path& path);
/// 根据明确版本和选项生成格式样本，不执行真实加密。
void generate_sample(const std::filesystem::path& path, const SampleOptions& options);
/// 将普通单文件加密到新路径，成功后提交最终输出。
void encrypt_file(const std::filesystem::path& input, const std::filesystem::path& output,
    std::span<const std::uint8_t> password, const EncryptOptions& options = {});
/// 按文件版本解密，认证成功才提交输出，并按调用者策略限制 KDF 资源。
void decrypt_file(const std::filesystem::path& input, const std::filesystem::path& output,
    std::span<const std::uint8_t> password,
    const crypto::KdfLimits& limits = {262144, 10, 16});
}
