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
    /// 比较对象类型、大小、身份与修改信息的全部快照字段。
    bool operator==(const SourceSnapshot&) const = default;
};
/// 不跟随最后一个组件，拒绝符号链接/reparse point 和特殊文件。
SourceSnapshot inspect_source(const std::filesystem::path& path);
/// 在消去 . 或 .. 之前核对原始路径组件，拒绝被归一化隐藏的源链接。
void validate_source_path(const std::filesystem::path& path);
/// 只读打开扫描过的普通文件，检查身份和修改信息；Windows 不允许并发写入或删除。
class SourceFile {
public:
    /// 打开扫描过的普通文件，拒绝链接及与预期快照不符的对象。
    SourceFile(const std::filesystem::path& path, const SourceSnapshot& expected);
    /// 关闭源文件并释放平台路径保护资源。
    ~SourceFile();
    /// 禁止复制源文件句柄与快照所有权。
    SourceFile(const SourceFile&) = delete;
    /// 禁止复制赋值已打开的源文件。
    SourceFile& operator=(const SourceFile&) = delete;
    /// 读取至多一个有界数据块，文件末尾返回零。
    std::size_t read(std::span<std::byte> bytes);
    /// 复核句柄和原路径仍对应预期对象及修改信息。
    void verify_unchanged() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
