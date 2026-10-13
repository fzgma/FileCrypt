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
    /// 在目标同父目录排他创建暂存根并记录其身份。
    explicit DirectoryTransaction(const std::filesystem::path& destination);
    /// 清理未提交且身份仍匹配的暂存目录。
    ~DirectoryTransaction();
    /// 禁止复制暂存目录的清理与提交所有权。
    DirectoryTransaction(const DirectoryTransaction&) = delete;
    /// 禁止复制赋值目录事务。
    DirectoryTransaction& operator=(const DirectoryTransaction&) = delete;
    /// 返回仍由事务持有的暂存根路径。
    const std::filesystem::path& root() const;
    /// 核对身份并原子发布暂存树，拒绝覆盖已有目标。
    void commit();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
