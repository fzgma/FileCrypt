#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>

namespace filecrypt::io {
struct SourceSnapshot {
    bool directory{};
    std::uint64_t size{}, device{}, identity{}, modified{}, changed{};
    bool operator==(const SourceSnapshot&) const = default;
};
/// 不跟随最后一个组件，拒绝符号链接/reparse point 和特殊文件。
SourceSnapshot inspect_source(const std::filesystem::path& path);
/// 在消去 . 或 .. 之前核对原始路径组件，拒绝被归一化隐藏的源链接。
void validate_source_path(const std::filesystem::path& path);
/// 只读打开扫描过的普通文件，检查身份和修改信息；Windows 不允许并发写入或删除。
class SourceFile {
public:
    SourceFile(const std::filesystem::path& path, const SourceSnapshot& expected);
    ~SourceFile();
    SourceFile(const SourceFile&) = delete;
    SourceFile& operator=(const SourceFile&) = delete;
    std::size_t read(std::span<std::byte> bytes);
    void verify_unchanged() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
