#include <filecrypt/io/output.hpp>
#include <filecrypt/error.hpp>
#include "../utils/source_snapshot.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <random>
#include <format>
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
    #include <sddl.h>
    #include "../utils/win32_resource.hpp"
#else
    #include <cerrno>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace filecrypt::io {
namespace {
/// 不跟随末级链接检查目标占用，悬空链接同样属于不可覆盖的已有目标。
bool destination_exists(const std::filesystem::path& destination) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(destination, error);
    if (error && error != std::errc::no_such_file_or_directory)
        throw OperationError(ErrorCode::io_error, "无法检查输出路径");
    return status.type() != std::filesystem::file_type::not_found && status.type() != std::filesystem::file_type::none;
}
}
struct OutputTransaction::Impl {
    std::filesystem::path destination;
    std::filesystem::path temporary;
    std::optional<SourceSnapshot> replacement;
    bool committed{false};
#ifdef _WIN32
    std::vector<utils::UniqueFileHandle> ancestors;
    HANDLE handle{INVALID_HANDLE_VALUE};
#else
    std::filesystem::path temporary_name;
    int parent_descriptor{-1};
    int descriptor{-1};
#endif
    /// 锚定替换目标的父目录，拒绝链接祖先并保持事务期间的路径约束。
    void lock_replacement_parent() {
        auto ancestor_path = destination.root_path();
#ifdef _WIN32
        auto open_ancestor = [&] {
            utils::UniqueFileHandle ancestor(CreateFileW(ancestor_path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            if (!ancestor || !utils::source_snapshot(ancestor.get()).directory)
                throw OperationError(ErrorCode::io_error, "无法保护替换目标的父目录");
            ancestors.push_back(std::move(ancestor));
        };
        if (!destination.root_name().native().starts_with(L"\\\\")) open_ancestor();
        for (const auto& component : destination.parent_path().relative_path()) {
            if (component.empty()) continue;
            ancestor_path /= component;
            open_ancestor();
        }
#else
        parent_descriptor = open(ancestor_path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent_descriptor < 0) throw OperationError(ErrorCode::io_error, "无法打开替换目标的根目录");
        for (const auto& component : destination.parent_path().relative_path()) {
            if (component.empty()) continue;
            const auto next = openat(parent_descriptor, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            ::close(parent_descriptor);
            parent_descriptor = next;
            if (parent_descriptor < 0) throw OperationError(ErrorCode::io_error, "无法保护替换目标的父目录");
        }
#endif
    }
    /// 在提交前复核原对象及父目录；此检查不能替代操作系统未提供的快照比较交换。
    void verify_replacement() const {
        try {
#ifdef _WIN32
            if (inspect_source(destination) != *replacement)
                throw OperationError(ErrorCode::io_error, "原文件已变化，取消替换");
#else
            struct stat parent{}, target{};
            if (fstat(parent_descriptor, &parent) != 0 ||
                fstatat(parent_descriptor, destination.filename().c_str(), &target, AT_SYMLINK_NOFOLLOW) != 0)
                throw OperationError(ErrorCode::io_error, "无法复核原文件，取消替换");
            validate_source_path(destination);
            const auto actual_parent = inspect_source(destination.parent_path());
            const auto held_parent = utils::source_snapshot(parent);
            if (actual_parent.device != held_parent.device || actual_parent.identity != held_parent.identity ||
                utils::source_snapshot(target) != *replacement || inspect_source(destination) != *replacement)
                throw OperationError(ErrorCode::io_error, "原文件或父目录已变化，取消替换");
#endif
        } catch (const OperationError& error) {
            if (error.code() == ErrorCode::invalid_argument)
                throw OperationError(ErrorCode::io_error, "原文件或父目录已变化，取消替换");
            throw;
        } catch (const std::filesystem::filesystem_error&) {
            throw OperationError(ErrorCode::io_error, "无法复核原文件，取消替换");
        }
    }
    /// 刷新后以单次改名替换目标，失败时不使用删除原文件再移动的回退。
    void commit_replacement() {
#ifdef _WIN32
        if (!FlushFileBuffers(handle)) throw OperationError(ErrorCode::io_error, "新密文刷新失败，取消替换");
        const auto name = destination.native();
        const auto bytes = name.size() * sizeof(wchar_t);
        const auto capacity = sizeof(FILE_RENAME_INFO) + bytes;
        if (capacity > std::numeric_limits<DWORD>::max())
            throw OperationError(ErrorCode::invalid_argument, "替换路径过长");
        std::unique_ptr<FILE_RENAME_INFO, decltype(&std::free)> rename_info(
            static_cast<FILE_RENAME_INFO*>(std::calloc(1, capacity)), &std::free);
        if (!rename_info) throw std::bad_alloc();
        rename_info->ReplaceIfExists = TRUE;
        // Win32 包装层使用绝对路径；保留全部祖先句柄防止路径在提交时被重定向。
        rename_info->RootDirectory = nullptr;
        rename_info->FileNameLength = static_cast<DWORD>(bytes);
        std::memcpy(rename_info->FileName, name.data(), bytes);
        verify_replacement();
        // 保持新文件的独占句柄直至改名完成，避免关闭与按路径重新打开之间的竞态。
        if (!SetFileInformationByHandle(handle, FileRenameInfo, rename_info.get(), static_cast<DWORD>(capacity)))
            throw OperationError(ErrorCode::io_error,
                std::format("无法替换原文件；请检查文件占用和目录权限（Windows 错误 {}）", GetLastError()).c_str());
#else
        if (fsync(descriptor) != 0) throw OperationError(ErrorCode::io_error, "新密文刷新失败，取消替换");
        struct stat held{}, named{};
        if (fstat(descriptor, &held) != 0 ||
            fstatat(parent_descriptor, temporary_name.c_str(), &named, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(held.st_mode) || !S_ISREG(named.st_mode) ||
            utils::source_snapshot(held) != utils::source_snapshot(named))
            throw OperationError(ErrorCode::io_error, "临时密文已变化，取消替换");
        verify_replacement();
        // 两个名称均相对同一父目录句柄解释，不跟随被换走的祖先路径。
        if (renameat(parent_descriptor, temporary_name.c_str(), parent_descriptor, destination.filename().c_str()) != 0)
            throw OperationError(ErrorCode::io_error, "无法替换原文件；请检查文件占用和目录权限");
#endif
        temporary.clear();
        committed = true;
        close();
#ifndef _WIN32
        // 改名已发生后不能回滚或谎报原文件未变；单独报告目录持久化的不确定状态。
        if (fsync(parent_descriptor) != 0)
            throw OperationError(ErrorCode::io_error, "原文件已替换，但无法确认目录写入已持久化");
#endif
    }
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
            if (parent_descriptor >= 0) {
                if (unlinkat(parent_descriptor, temporary_name.c_str(), 0) != 0 && errno != ENOENT)
                    std::fprintf(stderr, "临时输出清理失败（系统错误 %d）\n", errno);
            } else {
                std::error_code error;
                std::filesystem::remove(temporary, error);
            }
#endif
        }
#ifndef _WIN32
        if (parent_descriptor >= 0) ::close(parent_descriptor);
#endif
    }
};

/// 为输出创建权限受限的独占临时文件，名称碰撞时重试。
OutputTransaction::OutputTransaction(const std::filesystem::path& destination)
    : OutputTransaction(destination, false) {}

/// 显式替换模式保留源快照，复核成功后才允许一次性发布新密文。
OutputTransaction::OutputTransaction(const std::filesystem::path& destination, const SourceSnapshot& expected)
    : OutputTransaction(destination, false, &expected) {}

/// 创建只供内部读取的暂存文件，不要求输入文件所在目录可写。
std::unique_ptr<OutputTransaction> OutputTransaction::create_temporary() {
    return std::unique_ptr<OutputTransaction>(new OutputTransaction(std::filesystem::temp_directory_path(), true));
}

/// 复用排他创建及受限权限，临时模式由系统负责关闭后的删除。
OutputTransaction::OutputTransaction(const std::filesystem::path& destination, bool temporary_only, const SourceSnapshot* expected)
    : impl_(std::make_unique<Impl>()) {
    if (expected) {
        if (expected->directory) throw OperationError(ErrorCode::invalid_argument, "替换目标必须是普通文件");
        validate_source_path(destination);
        impl_->destination = std::filesystem::absolute(destination).lexically_normal();
        impl_->replacement = *expected;
        impl_->lock_replacement_parent();
        impl_->verify_replacement();
    } else if (!temporary_only && destination_exists(destination)) {
        throw OperationError(ErrorCode::output_conflict, "输出路径已存在，拒绝覆盖");
    }
    if (!temporary_only && !expected) impl_->destination = destination;
    std::random_device random;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto first = random();
        const auto second = random();
        auto candidate = (temporary_only ? destination : impl_->destination.parent_path()) /
            std::format(".filecrypt-{:x}{:x}.tmp", first, second);
#ifdef _WIN32
        // 受保护的 DACL 只允许所有者和 SYSTEM 访问，避免继承宽松目录权限。
        utils::UniqueSecurityDescriptor descriptor;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;FA;;;OW)(A;;FA;;;SY)", SDDL_REVISION_1, std::out_ptr(descriptor), nullptr)) {
            throw OperationError(ErrorCode::io_error, "无法设置临时文件权限");
        }
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor.get(), FALSE};
        impl_->handle = CreateFileW(candidate.c_str(), GENERIC_READ | GENERIC_WRITE | ((temporary_only || expected) ? DELETE : 0),
            0, &attributes, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | (temporary_only ? FILE_FLAG_DELETE_ON_CLOSE : 0), nullptr);
        const auto error = GetLastError();
        if (impl_->handle != INVALID_HANDLE_VALUE) {
            if (!temporary_only) impl_->temporary = std::move(candidate);
            return;
        }
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
            throw OperationError(ErrorCode::io_error, "无法创建临时文件");
        }
#else
        auto candidate_name = candidate.filename();
        impl_->descriptor = expected ?
            openat(impl_->parent_descriptor, candidate_name.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) :
            open(candidate.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        if (impl_->descriptor >= 0) {
            // 成功创建后只移动已分配路径，避免路径复制分配失败使清理失去临时名称。
            impl_->temporary = std::move(candidate);
            impl_->temporary_name = std::move(candidate_name);
            if (temporary_only) {
                if (unlink(impl_->temporary.c_str()) != 0)
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

/// 刷新并发布已完成输出，仅显式替换模式允许覆盖经过快照复核的原文件。
void OutputTransaction::commit() {
    if (impl_->destination.empty()) throw std::logic_error("Temporary payload cannot be committed");
    if (impl_->committed) {
        throw std::logic_error("Output already committed");
    }
    if (impl_->replacement) {
        impl_->commit_replacement();
        return;
    }
#ifdef _WIN32
    if (!FlushFileBuffers(impl_->handle)) {
        throw OperationError(ErrorCode::io_error, "输出文件刷新失败");
    }
    const auto handle = impl_->handle;
    impl_->handle = INVALID_HANDLE_VALUE;
    if (!CloseHandle(handle)) throw OperationError(ErrorCode::io_error, "输出文件关闭失败");
    if (!MoveFileExW(impl_->temporary.c_str(), impl_->destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS || destination_exists(impl_->destination))
            throw OperationError(ErrorCode::output_conflict, "输出路径已存在，拒绝覆盖");
        throw OperationError(ErrorCode::io_error, "输出文件提交失败");
    }
    impl_->temporary.clear();
#else
    if (fsync(impl_->descriptor) != 0) {
        throw OperationError(ErrorCode::io_error, "输出文件刷新失败");
    }
    const auto descriptor = impl_->descriptor;
    impl_->descriptor = -1;
    if (::close(descriptor) != 0) throw OperationError(ErrorCode::io_error, "输出文件关闭失败");
    if (link(impl_->temporary.c_str(), impl_->destination.c_str()) != 0) {
        if (errno == EEXIST) throw OperationError(ErrorCode::output_conflict, "输出路径已存在，拒绝覆盖");
        throw OperationError(ErrorCode::io_error, "输出文件提交失败");
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
