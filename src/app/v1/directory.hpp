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
    // 扫描生成连续 ID；这三个数组按同一下标保存 Entry、源路径和对象快照。
    std::vector<format::v1::DirectoryEntry> entries;
    std::vector<std::filesystem::path> paths;
    std::vector<io::SourceSnapshot> snapshots;
    crypto::SecureBytes index;
    std::uint64_t payload_size{};
};
/// 扫描普通文件与目录，构造有界 Index，并拒绝源树内的输出路径。
DirectoryScan scan_directory(const std::filesystem::path& root, const std::filesystem::path& output,
    const directory::Limits& limits);
/// 核对扫描结果中的对象快照及目录实际成员集合。
void verify_scan(const DirectoryScan& scan);
/// Index + 按 Entry ID 排列的 File Data 流；读完每个文件检查身份和长度。
class DirectoryReader {
public:
    /// 引用已校验的扫描结果；调用者须保证其存活至读取结束。
    explicit DirectoryReader(const DirectoryScan& scan) : scan_(scan) {}
    /// 读取下一段 Index 或 File Data，归档结束时返回零。
    std::size_t read(std::span<std::byte> bytes);
private:
    const DirectoryScan& scan_;
    std::size_t index_position_{}, entry_{0};
    std::uint64_t remaining_{};
    std::unique_ptr<io::SourceFile> file_;
};
/// 从完整认证并按需解压的载荷恢复目录，结构校验与全部写入成功后提交。
void restore_directory(io::OutputTransaction& payload, std::uint64_t index_length,
    const std::filesystem::path& output, const directory::Limits& limits);
}
