#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <iosfwd>
#include <stdexcept>

namespace filecrypt::io {
/// 精确读取提前遇到 EOF；由调用者根据数据用途解释，不包含文件协议语义。
class UnexpectedEndOfInput : public std::runtime_error {
public:
    /// 保留运行时读取异常的基类约定，单独标识短读原因。
    UnexpectedEndOfInput() : std::runtime_error("输入数据被截断") {}
};

/// 从输入流完整读取目标缓冲区，拒绝截断输入。
// 短读抛出 UnexpectedEndOfInput；读取故障抛出语义为 io_error 的 OperationError。
void read_exact(std::istream& input, std::span<std::byte> bytes);
/// 查询输入是否仍有字节而不消费内容，正常 EOF 返回 false，读取故障抛出异常。
[[nodiscard]] bool has_data(std::istream& input);
/// 排他创建文件并写入全部字节，拒绝覆盖已有路径。
void write_new_file(const std::filesystem::path& path, std::span<const std::byte> data);
}
