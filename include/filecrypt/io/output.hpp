#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>

namespace filecrypt::io {
class OutputTransaction {
public:
    /// 在目标同目录排他创建受控临时文件，拒绝已有目标。
    explicit OutputTransaction(const std::filesystem::path& destination);
    /// 关闭文件并清理尚未提交的临时输出。
    ~OutputTransaction();
    /// 禁止复制输出事务的所有权。
    OutputTransaction(const OutputTransaction&) = delete;
    /// 禁止复制赋值输出事务。
    OutputTransaction& operator=(const OutputTransaction&) = delete;
    /// 完整写入字节，写入失败时抛出异常。
    void write(std::span<const std::byte> bytes);
    /// 从当前指针读取受控临时内容，文件末尾返回零。
    [[nodiscard]] std::size_t read(std::span<std::byte> bytes);
    /// 将临时文件读写指针移动到指定绝对偏移。
    void seek(std::uint64_t offset);
    /// 查询临时载荷的实际长度，不改变当前读写位置。
    [[nodiscard]] std::uint64_t size() const;
    /// 刷新并关闭输出，将其提交到不存在的目标路径。
    void commit();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
