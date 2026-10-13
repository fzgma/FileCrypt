#pragma once
#include <filecrypt/io/source.hpp>
#include <filecrypt/error.hpp>
#include <stdexcept>

#ifdef _WIN32
    #include "win32_resource.hpp"
#else
    #include <sys/stat.h>
#endif

namespace filecrypt::utils {
#ifdef _WIN32
/// 从句柄提取普通文件或目录的身份与修改信息，拒绝 reparse point。
inline io::SourceSnapshot source_snapshot(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) throw OperationError(ErrorCode::io_error, "无法检查源文件信息");
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || GetFileType(handle) != FILE_TYPE_DISK)
        throw OperationError(ErrorCode::invalid_argument, "源对象不受支持：不能使用链接或特殊文件");
    // Win32 将大小、对象编号和时间拆为两个 DWORD，先扩宽再合并高低位。
    auto pair = [](DWORD high, DWORD low) { return (std::uint64_t{high} << 32) | low; };
    return {(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
        pair(info.nFileSizeHigh, info.nFileSizeLow), info.dwVolumeSerialNumber,
        pair(info.nFileIndexHigh, info.nFileIndexLow), pair(info.ftLastWriteTime.dwHighDateTime, info.ftLastWriteTime.dwLowDateTime),
        pair(info.ftCreationTime.dwHighDateTime, info.ftCreationTime.dwLowDateTime)};
}
#else
/// 从 stat 提取普通文件或目录的快照，拒绝链接与特殊对象。
inline io::SourceSnapshot source_snapshot(const struct stat& info) {
    if (!S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode)) throw OperationError(ErrorCode::invalid_argument, "源对象不受支持：不能使用链接或特殊文件");
    return {S_ISDIR(info.st_mode), static_cast<std::uint64_t>(info.st_size),
        static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino),
        static_cast<std::uint64_t>(info.st_mtim.tv_sec) * 1000000000 + info.st_mtim.tv_nsec,
        static_cast<std::uint64_t>(info.st_ctim.tv_sec) * 1000000000 + info.st_ctim.tv_nsec};
}
#endif
} // namespace filecrypt::utils
