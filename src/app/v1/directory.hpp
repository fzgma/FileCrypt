#pragma once
#include <filecrypt/directory/limits.hpp>
#include <filecrypt/format/v1/directory.hpp>
#include <filecrypt/io/source.hpp>
#include <filecrypt/io/output.hpp>
#include <filecrypt/crypto/crypto.hpp>
#include <filesystem>
#include <memory>

namespace filecrypt::app::v1 {
struct DirectoryScan {
    std::vector<format::v1::DirectoryEntry> entries;
    std::vector<std::filesystem::path> paths;
    std::vector<io::SourceSnapshot> snapshots;
    crypto::SecureBytes index;
    std::uint64_t payload_size{};
};
DirectoryScan scan_directory(const std::filesystem::path& root, const std::filesystem::path& output,
    const directory::Limits& limits);
void verify_scan(const DirectoryScan& scan);
/// Index + 按 Entry ID 排列的 File Data 流；读完每个文件检查身份和长度。
class DirectoryReader {
public:
    explicit DirectoryReader(const DirectoryScan& scan) : scan_(scan) {}
    std::size_t read(std::span<std::byte> bytes);
private:
    const DirectoryScan& scan_;
    std::size_t index_position_{}, entry_{0};
    std::uint64_t remaining_{};
    std::unique_ptr<io::SourceFile> file_;
};
void restore_directory(io::OutputTransaction& payload, std::uint64_t index_length,
    const std::filesystem::path& output, const directory::Limits& limits);
}
