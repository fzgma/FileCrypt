#include <filecrypt/io/file.hpp>

#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace filecrypt::io {

/// 使用操作系统排他创建接口写入文件并在失败时清理未完成输出。
void write_new_file(const std::filesystem::path& path, std::span<const std::byte> data) {
#ifdef _WIN32
    // Windows API 按操作系统分支，MSVC 与 MinGW 共用相同实现。
    const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Cannot create output file; it may already exist");
    }
    bool success = true;
    std::size_t offset{};
    while (offset < data.size()) {
        const auto remaining = data.size() - offset;
        const auto size = static_cast<DWORD>(remaining > MAXDWORD ? MAXDWORD : remaining);
        DWORD written{};
        if (!WriteFile(handle, data.data() + offset, size, &written, nullptr) || written == 0) {
            success = false;
            break;
        }
        offset += written;
    }
    if (!CloseHandle(handle)) {
        success = false;
    }
    if (!success) {
        DeleteFileW(path.c_str());
        throw std::runtime_error("Output file write failed");
    }
#else
    const int descriptor = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) {
        throw std::runtime_error("Cannot create output file; it may already exist");
    }
    bool success = true;
    std::size_t offset{};
    while (offset < data.size()) {
        // 限制单次系统调用大小，不把任意 size_t 转为有符号长度。
        const auto remaining = data.size() - offset;
        const auto size = remaining > 65536 ? std::size_t{65536} : remaining;
        const auto written = write(descriptor, data.data() + offset, size);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            success = false;
            break;
        }
        offset += static_cast<std::size_t>(written);
    }
    if (close(descriptor) != 0) {
        success = false;
    }
    if (!success) {
        unlink(path.c_str());
        throw std::runtime_error("Output file write failed");
    }
#endif
}
}
