#include <filecrypt/io/source.hpp>
#include <algorithm>
#include <stdexcept>
#include <vector>
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
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace filecrypt::io {
namespace {
#ifdef _WIN32
/// 从句柄提取普通文件或目录的身份与修改信息，拒绝 reparse point。
SourceSnapshot from_handle(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        GetFileType(handle) != FILE_TYPE_DISK) throw std::runtime_error("Unsupported or changed source object");
    // Win32 将大小、对象编号和时间拆为两个 DWORD，先扩宽再合并高低位。
    auto pair = [](DWORD high, DWORD low) { return (std::uint64_t{high} << 32) | low; };
    return {(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
        pair(info.nFileSizeHigh, info.nFileSizeLow), info.dwVolumeSerialNumber,
        pair(info.nFileIndexHigh, info.nFileIndexLow), pair(info.ftLastWriteTime.dwHighDateTime, info.ftLastWriteTime.dwLowDateTime),
        pair(info.ftCreationTime.dwHighDateTime, info.ftCreationTime.dwLowDateTime)};
}
#else
/// 从 stat 提取普通文件或目录的快照，拒绝链接与特殊对象。
SourceSnapshot from_stat(const struct stat& info) {
    if (!S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode)) throw std::runtime_error("Unsupported source object; links and special files are rejected");
    return {S_ISDIR(info.st_mode), static_cast<std::uint64_t>(info.st_size),
        static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino),
        static_cast<std::uint64_t>(info.st_mtim.tv_sec) * 1000000000 + info.st_mtim.tv_nsec,
        static_cast<std::uint64_t>(info.st_ctim.tv_sec) * 1000000000 + info.st_ctim.tv_nsec};
}
#endif
}

/// 不跟随末级链接读取源对象快照，供扫描与读取前后复核。
SourceSnapshot inspect_source(const std::filesystem::path& path) {
#ifdef _WIN32
    const auto handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot inspect source");
    try { const auto value = from_handle(handle); CloseHandle(handle); return value; }
    catch (...) { CloseHandle(handle); throw; }
#else
    struct stat info{};
    if (lstat(path.c_str(), &info) != 0) throw std::runtime_error("Cannot inspect source");
    return from_stat(info);
#endif
}

/// 在路径归一化前逐组件检查源对象，拒绝链接和非目录祖先。
void validate_source_path(const std::filesystem::path& path) {
    // Windows 的 absolute() 也可能先消去 ..；先拼接当前目录，保留原始组件。
    auto absolute = path;
    if (!path.is_absolute()) {
        if (path.has_root_directory()) absolute = std::filesystem::current_path().root_name() / path;
        else absolute = (path.has_root_name() ? std::filesystem::absolute(path.root_name()) :
            std::filesystem::current_path()) / path.relative_path();
    }
    auto prefix = absolute.root_path();
#ifdef _WIN32
    // UNC 的 server 前缀不是文件系统对象，首次检查从 share 组件开始。
    const bool unc = absolute.root_name().native().starts_with(L"\\\\");
    if (!unc && !inspect_source(prefix).directory) throw std::invalid_argument("Invalid source root");
#else
    if (!inspect_source(prefix).directory) throw std::invalid_argument("Invalid source root");
#endif
    const auto components = absolute.relative_path();
    for (auto component = components.begin(); component != components.end(); ++component) {
        if (component->empty()) continue;
        prefix /= *component;
        const auto snapshot = inspect_source(prefix);
        auto next = component; ++next;
        if (next != components.end() && !snapshot.directory)
            throw std::invalid_argument("Source ancestor is not a directory");
    }
}

struct SourceFile::Impl {
    std::filesystem::path path;
    SourceSnapshot expected;
#ifdef _WIN32
    HANDLE handle{INVALID_HANDLE_VALUE};
    std::vector<HANDLE> ancestors;
    /// 释放源文件及全部祖先目录句柄。
    ~Impl() {
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        for (const auto ancestor : ancestors) CloseHandle(ancestor);
    }
#else
    int descriptor{-1};
    /// 关闭仍由源文件持有的 POSIX 描述符。
    ~Impl() { if (descriptor >= 0) close(descriptor); }
#endif
    /// 从已打开的文件对象读取快照，不重新解析其路径。
    SourceSnapshot snapshot() const {
#ifdef _WIN32
        return from_handle(handle);
#else
        struct stat info{};
        if (fstat(descriptor, &info) != 0) throw std::runtime_error("Cannot inspect open source");
        return from_stat(info);
#endif
    }
};

/// 不跟随链接打开扫描过的普通文件，并确认对象仍与扫描快照一致。
SourceFile::SourceFile(const std::filesystem::path& path, const SourceSnapshot& expected) : impl_(std::make_unique<Impl>()) {
    for (const auto& component : path) {
        if (component == "." || component == "..") { validate_source_path(path); break; }
    }
    impl_->path = path;
    impl_->expected = expected;
#ifdef _WIN32
    // 保持祖先目录句柄，拒绝 reparse point，并阻止读取期间的祖先删除/替换。
    const auto absolute = std::filesystem::absolute(path).lexically_normal();
    auto ancestor_path = absolute.root_path();
    auto open_ancestor = [&] {
        const auto ancestor = CreateFileW(ancestor_path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (ancestor == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot lock source ancestor");
        try {
            if (!from_handle(ancestor).directory) throw std::runtime_error("Invalid source ancestor");
            impl_->ancestors.push_back(ancestor);
        } catch (...) { CloseHandle(ancestor); throw; }
    };
    if (!absolute.root_name().native().starts_with(L"\\\\")) open_ancestor();
    for (const auto& component : absolute.parent_path().relative_path()) {
        if (component.empty()) continue;
        ancestor_path /= component; open_ancestor();
    }
    impl_->handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (impl_->handle == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot exclusively read source file");
#else
    // openat 锚定各级目录；并发替换路径组件也不能把读操作重定向到链接目标。
    const auto absolute = std::filesystem::absolute(path).lexically_normal();
    int parent = open(absolute.root_path().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) throw std::runtime_error("Cannot open source root");
    for (const auto& component : absolute.parent_path().relative_path()) {
        if (component.empty()) continue;
        const auto next = openat(parent, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(parent); parent = next;
        if (parent < 0) throw std::runtime_error("Cannot open source ancestor without following links");
    }
    // 非阻塞打开避免替换成 FIFO 后卡住，随后通过句柄快照拒绝特殊对象。
    impl_->descriptor = openat(parent, absolute.filename().c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    close(parent);
    if (impl_->descriptor < 0) throw std::runtime_error("Cannot read source file without following links");
#endif
    if (expected.directory || impl_->snapshot() != expected) throw std::runtime_error("Source changed after scan");
}
/// 释放文件句柄及为源路径持有的祖先目录句柄。
SourceFile::~SourceFile() = default;

/// 从已打开的普通文件读取至多 64 KiB，末尾返回零。
std::size_t SourceFile::read(std::span<std::byte> bytes) {
    const auto size = std::min(bytes.size(), std::size_t{65536});
#ifdef _WIN32
    DWORD count{};
    if (!ReadFile(impl_->handle, bytes.data(), static_cast<DWORD>(size), &count, nullptr)) throw std::runtime_error("Source file read failed");
    return count;
#else
    ssize_t count;
    do { count = ::read(impl_->descriptor, bytes.data(), size); } while (count < 0 && errno == EINTR);
    if (count < 0) throw std::runtime_error("Source file read failed");
    return static_cast<std::size_t>(count);
#endif
}

/// 同时复核打开对象与原路径，检测内容变化和路径替换。
void SourceFile::verify_unchanged() const {
    if (impl_->snapshot() != impl_->expected || inspect_source(impl_->path) != impl_->expected)
        throw std::runtime_error("Source file changed during encryption");
}
}
