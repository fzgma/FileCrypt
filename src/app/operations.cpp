#include <filecrypt/app/operations.hpp>
#include <filecrypt/format/detect.hpp>
#include <filecrypt/io/file.hpp>
#include <filecrypt/io/source.hpp>
#include <filecrypt/io/output.hpp>
#include "v1/operations.hpp"
#include "../utils/reader_stream.hpp"
#include <array>
#include <fstream>
#include <stdexcept>

namespace filecrypt::app {
/// 持有源句柄完成换密及回读；复核源状态后才发布或替换最终文件。
void rekey_file(const std::filesystem::path& path, const std::filesystem::path& destination,
    std::span<const std::uint8_t> old_password, std::span<const std::uint8_t> new_password,
    const RekeyOptions& options) {
    if (path.empty() || destination.empty() || old_password.empty() || new_password.empty())
        throw OperationError(ErrorCode::invalid_argument, "输入、输出路径和密码不能为空");
    compression::validate_limits(options.decompression_limits);
    try {
        // 先检查原始组件，避免路径归一化掩盖链接；替换只授权用户指定的原路径。
        io::validate_source_path(path);
        const auto source_path = std::filesystem::absolute(path).lexically_normal();
        const auto output_path = std::filesystem::absolute(destination).lexically_normal();
        if (options.replace && source_path != output_path)
            throw OperationError(ErrorCode::invalid_argument, "替换模式的输出必须为输入路径");
        if (!options.replace && (source_path == output_path ||
                std::filesystem::symlink_status(destination).type() != std::filesystem::file_type::not_found))
            throw OperationError(ErrorCode::output_conflict, "输出路径已存在或与输入相同");
        const auto snapshot = io::inspect_source(source_path);
        if (snapshot.directory)
            throw OperationError(ErrorCode::invalid_argument, "换密输入必须是普通加密文件");
        auto source = std::make_unique<io::SourceFile>(source_path, snapshot);
        std::array<std::byte, format::identification_size> prefix{};
        std::size_t position{};
        while (position < prefix.size()) {
            const auto count = source->read(std::span(prefix).subspan(position));
            if (count == 0) throw io::UnexpectedEndOfInput();
            position += count;
        }
        const auto version = format::detect_version(prefix);
        if (version != 1) throw FormatError("不支持的 FileCrypt 格式版本", ErrorCode::unsupported_format);
        utils::ReaderStreamBuffer buffer([&](std::span<std::byte> bytes) { return source->read(bytes); }, prefix);
        std::istream input(&buffer);
        input.exceptions(std::ios::badbit);
        auto output = options.replace ? std::make_unique<io::OutputTransaction>(output_path, snapshot)
            : std::make_unique<io::OutputTransaction>(output_path);
        v1::rekey(input, *output, old_password, new_password, options);
        source->verify_unchanged();
        // Windows 源句柄禁止删除共享，必须先关闭；替换事务在提交前再次核对快照。
        source.reset();
        output->commit();
    } catch (const crypto::AuthenticationError&) {
        throw OperationError(ErrorCode::authentication_failed, "认证失败，旧密码错误或文件已损坏");
    } catch (const FormatError& error) {
        if (error.code() == ErrorCode::resource_limit)
            throw OperationError(ErrorCode::resource_limit, "换密所需资源超过当前上限");
        if (error.code() == ErrorCode::invalid_format) throw FormatError("加密文件格式或目录结构不合法");
        throw;
    } catch (const io::UnexpectedEndOfInput&) {
        throw FormatError("加密文件被截断");
    } catch (const std::length_error&) {
        throw OperationError(ErrorCode::resource_limit, "换密所需资源超过当前上限");
    } catch (const std::filesystem::filesystem_error&) {
        throw OperationError(ErrorCode::io_error, "无法访问换密所需的输入或输出路径");
    }
}

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
