#include <filecrypt/io/source.hpp>
#include "../utils/source_snapshot.hpp"
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <utility>
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include "../utils/win32_resource.hpp"
#else
    #include <cerrno>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace filecrypt::io {

/// 不跟随末级链接读取源对象快照，供扫描与读取前后复核。
SourceSnapshot inspect_source(const std::filesystem::path& path) {
#ifdef _WIN32
    const utils::UniqueFileHandle handle(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!handle) throw OperationError(ErrorCode::io_error, "无法检查源文件");
    return utils::source_snapshot(handle.get());
#else
    struct stat info{};
    if (lstat(path.c_str(), &info) != 0) throw OperationError(ErrorCode::io_error, "无法检查源文件");
    return utils::source_snapshot(info);
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
    if (!unc && !inspect_source(prefix).directory) throw OperationError(ErrorCode::invalid_argument, "源路径的根目录无效");
#else
    if (!inspect_source(prefix).directory) throw OperationError(ErrorCode::invalid_argument, "源路径的根目录无效");
#endif
    const auto components = absolute.relative_path();
    for (auto component = components.begin(); component != components.end(); ++component) {
        if (component->empty()) continue;
        prefix /= *component;
        const auto snapshot = inspect_source(prefix);
        auto next = component; ++next;
        if (next != components.end() && !snapshot.directory)
            throw OperationError(ErrorCode::invalid_argument, "源路径的上级组件不是目录");
    }
}

struct SourceFile::Impl {
    std::filesystem::path path;
    SourceSnapshot expected;
#ifdef _WIN32
    // 成员按声明逆序析构，先关闭源文件，再释放阻止祖先替换的目录句柄。
    std::vector<utils::UniqueFileHandle> ancestors;
    utils::UniqueFileHandle handle;
#else
    int descriptor{-1};
    /// 关闭仍由源文件持有的 POSIX 描述符。
    ~Impl() { if (descriptor >= 0) close(descriptor); }
#endif
    /// 从已打开的文件对象读取快照，不重新解析其路径。
    SourceSnapshot snapshot() const {
#ifdef _WIN32
        return utils::source_snapshot(handle.get());
#else
        struct stat info{};
        if (fstat(descriptor, &info) != 0) throw OperationError(ErrorCode::io_error, "无法检查已打开的源文件");
        return utils::source_snapshot(info);
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
        utils::UniqueFileHandle ancestor(CreateFileW(ancestor_path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        if (!ancestor) throw OperationError(ErrorCode::io_error, "无法保护源文件的父目录");
        if (!utils::source_snapshot(ancestor.get()).directory) throw OperationError(ErrorCode::io_error, "源文件的父目录无效");
        // 扩容失败时局部所有者仍会关闭；成功后锁随容器存活。
        impl_->ancestors.push_back(std::move(ancestor));
    };
    if (!absolute.root_name().native().starts_with(L"\\\\")) open_ancestor();
    for (const auto& component : absolute.parent_path().relative_path()) {
        if (component.empty()) continue;
        ancestor_path /= component; open_ancestor();
    }
    impl_->handle.reset(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!impl_->handle) throw OperationError(ErrorCode::io_error, "无法独占读取源文件，请检查文件占用和权限");
#else
    // openat 锚定各级目录；并发替换路径组件也不能把读操作重定向到链接目标。
    const auto absolute = std::filesystem::absolute(path).lexically_normal();
    int parent = open(absolute.root_path().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) throw OperationError(ErrorCode::io_error, "无法打开源文件的根目录");
    for (const auto& component : absolute.parent_path().relative_path()) {
        if (component.empty()) continue;
        const auto next = openat(parent, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(parent); parent = next;
        if (parent < 0) throw OperationError(ErrorCode::io_error, "无法在不跟随链接的情况下打开源文件的父目录");
    }
    // 非阻塞打开避免替换成 FIFO 后卡住，随后通过句柄快照拒绝特殊对象。
    impl_->descriptor = openat(parent, absolute.filename().c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    close(parent);
    if (impl_->descriptor < 0) throw OperationError(ErrorCode::io_error, "无法在不跟随链接的情况下读取源文件");
#endif
    if (expected.directory || impl_->snapshot() != expected) throw OperationError(ErrorCode::io_error, "源文件在检查后已变化");
}
/// 释放文件句柄及为源路径持有的祖先目录句柄。
SourceFile::~SourceFile() = default;

/// 从已打开的普通文件读取至多 64 KiB，末尾返回零。
std::size_t SourceFile::read(std::span<std::byte> bytes) {
    const auto size = std::min(bytes.size(), std::size_t{65536});
#ifdef _WIN32
    DWORD count{};
    if (!ReadFile(impl_->handle.get(), bytes.data(), static_cast<DWORD>(size), &count, nullptr)) throw OperationError(ErrorCode::io_error, "源文件读取失败");
    return count;
#else
    ssize_t count;
    do { count = ::read(impl_->descriptor, bytes.data(), size); } while (count < 0 && errno == EINTR);
    if (count < 0) throw OperationError(ErrorCode::io_error, "源文件读取失败");
    return static_cast<std::size_t>(count);
#endif
}

/// 同时复核打开对象与原路径，检测内容变化和路径替换。
void SourceFile::verify_unchanged() const {
    try {
        if (impl_->snapshot() != impl_->expected || inspect_source(impl_->path) != impl_->expected)
            throw OperationError(ErrorCode::io_error, "源文件在处理期间已变化");
    } catch (const OperationError& error) {
        if (error.code() == ErrorCode::invalid_argument)
            throw OperationError(ErrorCode::io_error, "源文件在处理期间已变化");
        throw;
    }
}
}
