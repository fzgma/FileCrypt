#include <filecrypt/io/output.hpp>
#include <filecrypt/error.hpp>
#include <algorithm>
#include <cstdio>
#include <limits>
#include <random>
#include <format>
#include <stdexcept>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include <sddl.h>
    #include "../utils/win32_resource.hpp"
#else
    #include <cerrno>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace filecrypt::io {
struct OutputTransaction::Impl {
    std::filesystem::path destination;
    std::filesystem::path temporary;
    bool committed{false};
#ifdef _WIN32
    HANDLE handle{INVALID_HANDLE_VALUE};
#else
    int descriptor{-1};
#endif
    /// 无异常关闭临时文件的操作系统句柄。
    void close() noexcept {
#ifdef _WIN32
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
        }
#else
        if (descriptor >= 0) {
            ::close(descriptor);
            descriptor = -1;
        }
#endif
    }
    /// 在任意退出路径清理未提交的事务文件。
    ~Impl() {
        close();
        if (!temporary.empty()) {
#ifdef _WIN32
            // 使用原生删除接口清理受限 DACL 文件，避免不同标准库删除实现的差异。
            if (!DeleteFileW(temporary.c_str())) {
                const auto error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                    // 析构不能抛异常，但清理失败必须留下诊断，不能静默遗留明文。
                    std::fprintf(stderr, "临时输出清理失败（Windows 错误 %lu）\n",
                        static_cast<unsigned long>(error));
                }
            }
#else
            std::error_code error;
            std::filesystem::remove(temporary, error);
#endif
        }
    }
};

/// 为输出创建权限受限的独占临时文件，名称碰撞时重试。
OutputTransaction::OutputTransaction(const std::filesystem::path& destination)
    : OutputTransaction(destination, false) {}

/// 创建只供内部读取的暂存文件，不要求输入文件所在目录可写。
std::unique_ptr<OutputTransaction> OutputTransaction::create_temporary() {
    return std::unique_ptr<OutputTransaction>(new OutputTransaction(std::filesystem::temp_directory_path(), true));
}

/// 复用排他创建及受限权限，临时模式由系统负责关闭后的删除。
OutputTransaction::OutputTransaction(const std::filesystem::path& destination, bool temporary_only)
    : impl_(std::make_unique<Impl>()) {
    if (!temporary_only && std::filesystem::exists(destination)) {
        throw std::runtime_error("Output already exists");
    }
    if (!temporary_only) impl_->destination = destination;
    std::random_device random;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto first = random();
        const auto second = random();
        const auto candidate = (temporary_only ? destination : destination.parent_path()) /
            std::format(".filecrypt-{:x}{:x}.tmp", first, second);
#ifdef _WIN32
        // 受保护的 DACL 只允许所有者和 SYSTEM 访问，避免继承宽松目录权限。
        utils::UniqueSecurityDescriptor descriptor;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;FA;;;OW)(A;;FA;;;SY)", SDDL_REVISION_1, std::out_ptr(descriptor), nullptr)) {
            throw OperationError(ErrorCode::io_error, "无法设置临时文件权限");
        }
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor.get(), FALSE};
        impl_->handle = CreateFileW(candidate.c_str(), GENERIC_READ | GENERIC_WRITE | (temporary_only ? DELETE : 0),
            0, &attributes, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | (temporary_only ? FILE_FLAG_DELETE_ON_CLOSE : 0), nullptr);
        const auto error = GetLastError();
        if (impl_->handle != INVALID_HANDLE_VALUE) {
            if (!temporary_only) impl_->temporary = candidate;
            return;
        }
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
            throw OperationError(ErrorCode::io_error, "无法创建临时文件");
        }
#else
        impl_->descriptor = open(candidate.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        if (impl_->descriptor >= 0) {
            impl_->temporary = candidate;
            if (temporary_only) {
                if (unlink(candidate.c_str()) != 0)
                    throw OperationError(ErrorCode::io_error, "无法移除临时文件名称");
                impl_->temporary.clear();
            }
            return;
        }
        if (errno != EEXIST) {
            throw OperationError(ErrorCode::io_error, "无法创建临时文件");
        }
#endif
    }
    throw OperationError(ErrorCode::io_error, "无法分配唯一的临时文件");
}

/// 释放事务并自动删除未提交的临时文件。
OutputTransaction::~OutputTransaction() = default;

/// 使用系统写入循环完整写入临时文件。
void OutputTransaction::write(std::span<const std::byte> bytes) {
    if (impl_->committed) {
        throw std::logic_error("Output already committed");
    }
    while (!bytes.empty()) {
        const auto size = std::min(bytes.size(), std::size_t{65536});
#ifdef _WIN32
        DWORD written{};
        if (!WriteFile(impl_->handle, bytes.data(), static_cast<DWORD>(size), &written, nullptr) ||
            written == 0) {
            throw OperationError(ErrorCode::io_error, "临时文件写入失败");
        }
#else
        const auto written = ::write(impl_->descriptor, bytes.data(), size);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            throw OperationError(ErrorCode::io_error, "临时文件写入失败");
        }
#endif
        bytes = bytes.subspan(static_cast<std::size_t>(written));
    }
}

/// 通过原有独占句柄读取受控临时文件，不暴露路径或提前发布内容。
std::size_t OutputTransaction::read(std::span<std::byte> bytes) {
    if (impl_->committed) {
        throw std::logic_error("Output already committed");
    }
    const auto size = std::min(bytes.size(), std::size_t{65536});
#ifdef _WIN32
    DWORD count{};
    if (!ReadFile(impl_->handle, bytes.data(), static_cast<DWORD>(size), &count, nullptr)) {
        throw OperationError(ErrorCode::io_error, "临时文件读取失败");
    }
    return count;
#else
    ssize_t count;
    do {
        count = ::read(impl_->descriptor, bytes.data(), size);
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
        throw OperationError(ErrorCode::io_error, "临时文件读取失败");
    }
    return static_cast<std::size_t>(count);
#endif
}

/// 在可表示范围内定位临时文件读写指针。
void OutputTransaction::seek(std::uint64_t offset) {
    if (impl_->committed || offset > std::numeric_limits<std::int64_t>::max()) {
        throw std::invalid_argument("Invalid output seek");
    }
#ifdef _WIN32
    LARGE_INTEGER position;
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(impl_->handle, position, nullptr, FILE_BEGIN)) {
        throw OperationError(ErrorCode::io_error, "临时文件定位失败");
    }
#else
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
        lseek(impl_->descriptor, static_cast<off_t>(offset), SEEK_SET) < 0) {
        throw OperationError(ErrorCode::io_error, "临时文件定位失败");
    }
#endif
}

/// 通过原有句柄查询临时文件的实际长度，不改变读写位置。
std::uint64_t OutputTransaction::size() const {
    if (impl_->committed) throw std::logic_error("Output already committed");
#ifdef _WIN32
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(impl_->handle, &size) || size.QuadPart < 0) throw OperationError(ErrorCode::io_error, "无法读取临时文件大小");
    return static_cast<std::uint64_t>(size.QuadPart);
#else
    struct stat info{};
    if (fstat(impl_->descriptor, &info) != 0 || info.st_size < 0) throw OperationError(ErrorCode::io_error, "无法读取临时文件大小");
    return static_cast<std::uint64_t>(info.st_size);
#endif
}

/// 刷新并发布已完成输出，提交竞态也不得覆盖已有目标。
void OutputTransaction::commit() {
    if (impl_->destination.empty()) throw std::logic_error("Temporary payload cannot be committed");
    if (impl_->committed) {
        throw std::logic_error("Output already committed");
    }
#ifdef _WIN32
    if (!FlushFileBuffers(impl_->handle)) {
        throw std::runtime_error("Output flush failed");
    }
    const auto handle = impl_->handle;
    impl_->handle = INVALID_HANDLE_VALUE;
    if (!CloseHandle(handle) || !MoveFileExW(impl_->temporary.c_str(),
            impl_->destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("Output commit failed; destination may already exist");
    }
    impl_->temporary.clear();
#else
    if (fsync(impl_->descriptor) != 0) {
        throw std::runtime_error("Output flush failed");
    }
    const auto descriptor = impl_->descriptor;
    impl_->descriptor = -1;
    if (::close(descriptor) != 0 || link(impl_->temporary.c_str(), impl_->destination.c_str()) != 0) {
        throw std::runtime_error("Output commit failed; destination may already exist");
    }
    // 同目录硬链接原子发布且不覆盖目标，随后删除临时名称。
    if (unlink(impl_->temporary.c_str()) != 0) {
        std::error_code error;
        std::filesystem::remove(impl_->temporary, error);
        if (!error) impl_->temporary.clear();
    } else {
        impl_->temporary.clear();
    }
#endif
    impl_->committed = true;
}
}
