#include <filecrypt/io/directory.hpp>
#include <filecrypt/io/source.hpp>
#include <algorithm>
#include <cstdio>
#include <random>
#include <format>
#include <stdexcept>
#include <string>
#include <optional>
#include <system_error>
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
    #include "../utils/win32_directory_move.hpp"
#else
    #include <cerrno>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #ifdef __linux__
        #include <sys/syscall.h>
    #endif
#endif

namespace filecrypt::io {
/// 检查恢复名称是否符合目标平台规则，不修改归档中的原始名称。
void validate_target_name(std::string_view name) {
#ifdef _WIN32
    if (name.empty() || name.back() == ' ' || name.back() == '.' || name.find_first_of("<>:\"/\\|?*") != name.npos ||
        std::any_of(name.begin(), name.end(), [](unsigned char c) { return c < 32; }))
        throw std::invalid_argument("Name is not valid on Windows");
    // Windows 设备名即使带扩展名仍保留；COM/LPT 也识别上标数字 1、2、3。
    auto device = std::string(name.substr(0, name.find('.')));
    while (!device.empty() && device.back() == ' ') device.pop_back();
    for (auto& c : device) if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
    if (device == "CON" || device == "PRN" || device == "AUX" || device == "NUL" || device == "CONIN$" || device == "CONOUT$" ||
        ((device.starts_with("COM") || device.starts_with("LPT")) &&
            ((device.size() == 4 && device[3] >= '1' && device[3] <= '9') ||
             device.substr(3) == "\xC2\xB9" || device.substr(3) == "\xC2\xB2" || device.substr(3) == "\xC2\xB3")))
        throw std::invalid_argument("Windows reserved device Name");
#else
    (void)name;
#endif
}

/// 排他创建权限受限目录，Windows 的访问规则可继承到子对象。
void create_restricted_directory(const std::filesystem::path& path) {
#ifdef _WIN32
    utils::UniqueSecurityDescriptor descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)",
            SDDL_REVISION_1, std::out_ptr(descriptor), nullptr)) throw std::runtime_error("Cannot set directory permissions");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor.get(), FALSE};
    const bool created = CreateDirectoryW(path.c_str(), &attributes) != 0;
    if (!created) throw std::runtime_error("Cannot create directory; target may conflict");
#else
    if (mkdir(path.c_str(), 0700) != 0) throw std::runtime_error("Cannot create restricted directory; target may conflict");
#endif
}

namespace {
/// 清理本事务创建的目录树，不跟随 symlink 或 Windows reparse point。
void cleanup_tree(const std::filesystem::path& path) {
#ifdef _WIN32
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return;
        throw std::runtime_error("Cannot inspect temporary directory during cleanup");
    }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        if (!DeleteFileW(path.c_str())) throw std::runtime_error("Cannot clean temporary directory file");
        return;
    }
    if (!(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        for (const auto& item : std::filesystem::directory_iterator(path)) cleanup_tree(item.path());
    }
    if (!RemoveDirectoryW(path.c_str())) throw std::runtime_error("Cannot clean temporary directory");
#else
    const auto status = std::filesystem::symlink_status(path);
    if (!std::filesystem::exists(status)) return;
    if (std::filesystem::is_directory(status)) {
        for (const auto& item : std::filesystem::directory_iterator(path)) cleanup_tree(item.path());
    }
    std::filesystem::remove(path);
#endif
}
}

struct DirectoryTransaction::Impl {
    std::filesystem::path destination, temporary;
    std::optional<SourceSnapshot> original;
    /// 核对暂存根的设备与对象身份，拒绝触碰旧路径上的替代对象。
    void verify_identity() const {
        if (!original) throw std::runtime_error("Temporary directory identity is unavailable");
        const auto current = inspect_source(temporary);
        if (!current.directory || current.device != original->device || current.identity != original->identity)
            throw std::runtime_error("Temporary directory root was replaced; refusing to touch it");
    }
    /// 复核身份后清理未提交的目录树，清理失败时仅报告诊断。
    ~Impl() {
        if (!temporary.empty()) {
            try { verify_identity(); cleanup_tree(temporary); }
            catch (const std::exception& error) { std::fprintf(stderr, "Directory cleanup failed: %s\n", error.what()); }
        }
    }
};

/// 在目标同父目录创建受限暂存根并记录身份，名称碰撞时重试。
DirectoryTransaction::DirectoryTransaction(const std::filesystem::path& destination) : impl_(std::make_unique<Impl>()) {
    impl_->destination = std::filesystem::absolute(destination).lexically_normal();
    if (impl_->destination.filename().empty() && impl_->destination != impl_->destination.root_path())
        impl_->destination = impl_->destination.parent_path();
    if (impl_->destination.filename().empty() || std::filesystem::exists(std::filesystem::symlink_status(impl_->destination)))
        throw std::runtime_error("Directory output already exists or is invalid");
    std::random_device random;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto first = random();
        const auto second = random();
        auto candidate = impl_->destination.parent_path() / std::format(".filecrypt-{:x}{:x}.dir", first, second);
        try { create_restricted_directory(candidate); }
        catch (...) {
            if (std::filesystem::exists(std::filesystem::symlink_status(candidate))) continue;
            throw;
        }
        impl_->temporary = std::move(candidate);
        impl_->original = inspect_source(impl_->temporary);
        return;
    }
    throw std::runtime_error("Cannot allocate temporary directory");
}
/// 释放事务并清理仍由本事务持有的暂存树。
DirectoryTransaction::~DirectoryTransaction() = default;
/// 返回暂存根路径，供恢复流程在私有目录内创建对象。
const std::filesystem::path& DirectoryTransaction::root() const { return impl_->temporary; }

/// 复核暂存根身份后原子发布目录，已有目标或不支持的接口均失败。
void DirectoryTransaction::commit() {
    if (impl_->temporary.empty()) throw std::logic_error("Directory already committed");
    impl_->verify_identity();
#ifdef _WIN32
    const auto error = utils::move_directory_no_replace(impl_->temporary, impl_->destination,
        [&] { impl_->verify_identity(); });
    if (error != ERROR_SUCCESS)
        throw std::system_error(static_cast<int>(error), std::system_category(), "Directory commit failed");
#elif defined(__linux__)
    // rename() 会替换已有空目录；必须使用内核的原子 no-replace 接口。
    if (syscall(SYS_renameat2, AT_FDCWD, impl_->temporary.c_str(), AT_FDCWD, impl_->destination.c_str(), 1u) != 0)
        throw std::runtime_error("Directory no-replace commit failed");
#else
    throw std::runtime_error("Atomic directory no-replace commit is unsupported on this platform");
#endif
    // 发布成功后释放临时名称，析构不再清理该名称上的对象。
    impl_->temporary.clear();
}
}
