#include <filecrypt/io/file.hpp>
#include <filecrypt/error.hpp>
#include <istream>
#include <stdexcept>

namespace filecrypt::io {
namespace {
/// 临时启用 badbit 异常，使 streambuf 的分配失败能够传播，并恢复调用者设置。
class InputExceptionGuard {
public:
    /// 保存原异常掩码；启用操作放在读取的异常处理范围内。
    explicit InputExceptionGuard(std::istream& input) : input_(input), original_(input.exceptions()) {}
    /// 恢复原掩码；即使当前状态会触发异常，设置本身已生效，不能在析构中抛出。
    ~InputExceptionGuard() {
        try { input_.exceptions(original_); } catch (...) {}
    }
    /// 仅添加 badbit，保留调用者已有的 EOF 和 failbit 行为。
    void enable() { input_.exceptions(original_ | std::ios::badbit); }
private:
    std::istream& input_;
    std::ios::iostate original_;
};
}

/// 从输入流读取全部目标字节，截断或读取失败时抛出异常。
void read_exact(std::istream& input, std::span<std::byte> bytes) {
    InputExceptionGuard guard(input);
    try {
        guard.enable();
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    } catch (const std::bad_alloc&) {
        throw;
    } catch (...) {
        // badbit 优先于 EOF；同时存在时不能把真实读取故障误报为截断。
        if (input.bad()) throw OperationError(ErrorCode::io_error, "输入数据读取失败");
        if (input.eof()) throw UnexpectedEndOfInput();
        if (input.fail()) throw OperationError(ErrorCode::io_error, "输入数据读取失败");
        throw;
    }
    if (input.bad()) throw OperationError(ErrorCode::io_error, "输入数据读取失败");
    if (input.eof()) throw UnexpectedEndOfInput();
    if (input.fail()) throw OperationError(ErrorCode::io_error, "输入数据读取失败");
}

/// 使用有界前瞻区分正常 EOF 与读取故障，并保留流缓冲区的分配异常。
bool has_data(std::istream& input) {
    InputExceptionGuard guard(input);
    int next;
    try {
        guard.enable();
        next = input.peek();
    } catch (const std::bad_alloc&) {
        throw;
    } catch (...) {
        if (input.bad()) throw OperationError(ErrorCode::io_error, "输入载荷状态读取失败");
        if (input.eof()) return false;
        if (input.fail()) throw OperationError(ErrorCode::io_error, "输入载荷状态读取失败");
        throw;
    }
    if (input.bad() || (input.fail() && !input.eof()))
        throw OperationError(ErrorCode::io_error, "输入载荷状态读取失败");
    return next != std::char_traits<char>::eof();
}
}
