#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include <utility>

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

/// 识别文件版本并调用相应流程读取公开信息。
[[nodiscard]] FileInfo inspect_file(const std::filesystem::path& path);
/// 根据明确版本和选项生成格式样本，不执行真实加密。
void generate_sample(const std::filesystem::path& path, const SampleOptions& options);
}
