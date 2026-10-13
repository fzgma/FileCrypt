#pragma once

#include <stdexcept>
#include <string>
#include <new>

namespace filecrypt {

enum class ErrorCode {
    invalid_argument,
    // 保留旧试点枚举及其数值；新接口不将这些泛化类别作为语义错误返回。
    length,
    logic,
    runtime,
    unsupported_format,
    invalid_format,
    resource_limit,
    authentication_failed,
    output_conflict,
    io_error,
    internal_error
};

struct Error {
    ErrorCode code;
    std::string message;
};

/// 携带格式错误语义，同时保留原 std::invalid_argument 捕获约定。
class FormatError : public std::invalid_argument {
public:
    /// 在知道格式失败原因的位置记录类别与诊断。
    explicit FormatError(const char* message, ErrorCode code = ErrorCode::invalid_format)
        : std::invalid_argument(message), code_(code) {}
    /// 返回失败点记录的格式错误类别。
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};

/// 携带操作失败语义，同时保留原 std::runtime_error 捕获约定。
class OperationError : public std::runtime_error {
public:
    /// 记录应用或 IO 已确认的失败类别，不根据诊断文本推断。
    OperationError(ErrorCode code, const char* message)
        : std::runtime_error(message), code_(code) {}
    /// 返回失败点记录的操作错误类别。
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
private:
    ErrorCode code_;
};

/// 保留已分类语义与诊断；旧标准异常保持旧枚举映射，分配失败继续抛出。
// 新结果接口只在捕获已分类异常后调用，不以此函数泛化吞掉未知失败。
inline Error error_from_exception(const std::exception& error) {
    if (dynamic_cast<const std::bad_alloc*>(&error)) {
        throw std::bad_alloc();
    }
    if (const auto* format = dynamic_cast<const FormatError*>(&error)) {
        return {format->code(), error.what()};
    }
    if (const auto* operation = dynamic_cast<const OperationError*>(&error)) {
        return {operation->code(), error.what()};
    }
    if (dynamic_cast<const std::invalid_argument*>(&error)) {
        return {ErrorCode::invalid_argument, error.what()};
    }
    if (dynamic_cast<const std::length_error*>(&error)) {
        return {ErrorCode::length, error.what()};
    }
    if (dynamic_cast<const std::logic_error*>(&error)) {
        return {ErrorCode::logic, error.what()};
    }
    return {ErrorCode::runtime, error.what()};
}

} // namespace filecrypt
