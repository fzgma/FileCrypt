#pragma once
#include <filesystem>
#include <memory>
#include <string_view>

namespace filecrypt::io {
/// 校验目标平台可创建的名称，不改写原名称。
void validate_target_name(std::string_view name);
/// 创建权限受限的新目录；已有路径（含名称别名）必须失败。
void create_restricted_directory(const std::filesystem::path& path);
/// 在同一父目录创建受限暂存目录，完整恢复后不覆盖提交。
class DirectoryTransaction {
public:
    explicit DirectoryTransaction(const std::filesystem::path& destination);
    ~DirectoryTransaction();
    DirectoryTransaction(const DirectoryTransaction&) = delete;
    DirectoryTransaction& operator=(const DirectoryTransaction&) = delete;
    const std::filesystem::path& root() const;
    void commit();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
