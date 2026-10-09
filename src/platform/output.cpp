#include <filecrypt/io/output.hpp>
#include <algorithm>
#include <cstdio>
#include <limits>
#include <random>
#include <sstream>
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
#else
#include <cerrno>
#include <fcntl.h>
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
    : impl_(std::make_unique<Impl>()) {
    if (std::filesystem::exists(destination)) {
        throw std::runtime_error("Output already exists");
    }
    impl_->destination = destination;
    std::random_device random;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        std::ostringstream name;
        name << ".filecrypt-" << std::hex << random() << random() << ".tmp";
        const auto candidate = destination.parent_path() / name.str();
#ifdef _WIN32
        // 受保护的 DACL 只允许所有者和 SYSTEM 访问，避免继承宽松目录权限。
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;FA;;;OW)(A;;FA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr)) {
            throw std::runtime_error("Cannot set temporary output permissions");
        }
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
        impl_->handle = CreateFileW(candidate.c_str(), GENERIC_READ | GENERIC_WRITE, 0, &attributes,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto error = GetLastError();
        LocalFree(descriptor);
        if (impl_->handle != INVALID_HANDLE_VALUE) {
            impl_->temporary = candidate;
            return;
        }
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
            throw std::runtime_error("Cannot create temporary output");
        }
#else
        impl_->descriptor = open(candidate.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        if (impl_->descriptor >= 0) {
            impl_->temporary = candidate;
            return;
        }
        if (errno != EEXIST) {
            throw std::runtime_error("Cannot create temporary output");
        }
#endif
    }
    throw std::runtime_error("Cannot allocate unique temporary output");
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
            throw std::runtime_error("Temporary output write failed");
        }
#else
        const auto written = ::write(impl_->descriptor, bytes.data(), size);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            throw std::runtime_error("Temporary output write failed");
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
        throw std::runtime_error("Temporary output read failed");
    }
    return count;
#else
    ssize_t count;
    do {
        count = ::read(impl_->descriptor, bytes.data(), size);
    } while (count < 0 && errno == EINTR);
    if (count < 0) {
        throw std::runtime_error("Temporary output read failed");
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
        throw std::runtime_error("Output seek failed");
    }
#else
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) ||
        lseek(impl_->descriptor, static_cast<off_t>(offset), SEEK_SET) < 0) {
        throw std::runtime_error("Output seek failed");
    }
#endif
}

/// 刷新并发布已完成输出，提交竞态也不得覆盖已有目标。
void OutputTransaction::commit() {
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
    }
#endif
    impl_->committed = true;
}
}
