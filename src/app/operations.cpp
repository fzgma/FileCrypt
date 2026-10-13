#include <filecrypt/app/operations.hpp>
#include <filecrypt/format/detect.hpp>
#include <filecrypt/io/file.hpp>
#include <filecrypt/io/source.hpp>
#include "v1/operations.hpp"
#include <array>
#include <fstream>
#include <stdexcept>

namespace filecrypt::app {
/// 在应用边界分类验证失败；不将资源上限或读取故障解释为文件损坏。
void verify_file(const std::filesystem::path& path, std::span<const std::uint8_t> password,
    const crypto::KdfLimits& limits, const compression::DecompressionLimits& decompression_limits,
    const directory::Limits& directory_limits) {
    if (path.empty() || password.empty())
        throw OperationError(ErrorCode::invalid_argument, "输入路径和密码不能为空");
    compression::validate_limits(decompression_limits);
    try {
        std::error_code error;
        const auto regular = std::filesystem::is_regular_file(path, error);
        if (error) throw OperationError(ErrorCode::io_error, "无法读取输入文件信息");
        if (!regular) throw OperationError(ErrorCode::invalid_argument, "验证输入必须是普通加密文件");
        std::ifstream input(path, std::ios::binary);
        if (!input) throw OperationError(ErrorCode::io_error, "无法打开输入文件");
        std::array<std::byte, format::identification_size> prefix{};
        io::read_exact(input, prefix);
        const auto version = format::detect_version(prefix);
        input.seekg(0);
        if (!input) throw OperationError(ErrorCode::io_error, "无法定位输入文件");
        switch (version) {
        case 1: v1::verify(input, password, limits, decompression_limits, directory_limits); return;
        default: throw FormatError("不支持的 FileCrypt 格式版本", ErrorCode::unsupported_format);
        }
    } catch (const crypto::AuthenticationError&) {
        throw OperationError(ErrorCode::authentication_failed, "认证失败，密码错误或文件已损坏");
    } catch (const FormatError& error) {
        if (error.code() == ErrorCode::resource_limit)
            throw OperationError(ErrorCode::resource_limit, "验证所需资源超过当前上限");
        if (error.code() == ErrorCode::invalid_format)
            throw FormatError("加密文件格式或目录结构不合法");
        throw;
    } catch (const io::UnexpectedEndOfInput&) {
        throw FormatError("加密文件被截断");
    } catch (const std::length_error&) {
        throw OperationError(ErrorCode::resource_limit, "验证所需资源超过当前上限");
    } catch (const std::filesystem::filesystem_error&) {
        throw OperationError(ErrorCode::io_error, "无法访问验证所需的文件或临时目录");
    }
}

/// 读取最小识别前缀后分发到对应版本的公开信息流程。
FileInfo inspect_file(const std::filesystem::path& path) {
    // 空路径是请求参数错误；仍使用 runtime_error 子类兼容原打开失败的捕获约定。
    if (path.empty()) throw OperationError(ErrorCode::invalid_argument, "输入文件路径不能为空");
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw OperationError(ErrorCode::io_error, "无法打开输入文件");
    }
    std::array<std::byte, format::identification_size> prefix{};
    try { io::read_exact(input, prefix); }
    catch (const io::UnexpectedEndOfInput& error) {
        throw OperationError(ErrorCode::invalid_format, error.what());
    }
    const auto version = format::detect_version(prefix);
    input.seekg(0);
    if (!input) {
        throw OperationError(ErrorCode::io_error, "无法定位输入文件");
    }
    switch (version) {
    case 1: return v1::inspect(input);
    default: throw FormatError("不支持的 FileCrypt 格式版本", ErrorCode::unsupported_format);
    }
}

/// 将已分类的信息读取失败返回给调用者，保留原实现与其他异常的传播。
std::expected<FileInfo, Error> try_inspect_file(const std::filesystem::path& path) {
    try {
        return inspect_file(path);
    } catch (const FormatError& error) {
        return std::unexpected(error_from_exception(error));
    } catch (const OperationError& error) {
        return std::unexpected(error_from_exception(error));
    }
}

/// 根据创建选项的版本分发样本流程，未知版本不降级。
void generate_sample(const std::filesystem::path& path, const SampleOptions& options) {
    switch (options.version) {
    case 1: v1::sample(path, options); return;
    default: throw std::invalid_argument("Unsupported FileCrypt version");
    }
}

/// 校验输入类型并分发真实文件加密到显式指定的协议版本。
void encrypt_file(const std::filesystem::path& input, const std::filesystem::path& output,
    std::span<const std::uint8_t> password, const EncryptOptions& options) {
    io::validate_source_path(input);
    const auto snapshot = io::inspect_source(input);
    // 单文件扩展名以用户输入为准，避免 Windows absolute() 消去尾部句点。
    auto source = input;
    if (snapshot.directory) {
        source = std::filesystem::absolute(input).lexically_normal();
        if (source.filename().empty() && source != source.root_path()) source = source.parent_path();
    }
    switch (options.version) {
    case 1: v1::encrypt(source, output, password, options); return;
    default: throw std::invalid_argument("Unsupported FileCrypt version");
    }
}

/// 在最小识别前缀确认版本后分发真实文件解密。
std::filesystem::path decrypt_file(const std::filesystem::path& path, const std::filesystem::path& output,
    std::span<const std::uint8_t> password, const crypto::KdfLimits& limits,
    const compression::DecompressionLimits& decompression_limits, bool restore_extension,
    const directory::Limits& directory_limits) {
    compression::validate_limits(decompression_limits);
    if (!std::filesystem::is_regular_file(path)) {
        throw std::invalid_argument("Decryption input must be a regular file");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot open input file");
    }
    std::array<std::byte, format::identification_size> prefix{};
    io::read_exact(input, prefix);
    const auto version = format::detect_version(prefix);
    input.seekg(0);
    if (!input) {
        throw std::runtime_error("Cannot seek input file");
    }
    switch (version) {
    case 1: return v1::decrypt(input, output, password, limits, decompression_limits, restore_extension, directory_limits);
    default: throw std::invalid_argument("Unsupported FileCrypt version");
    }
}
}
