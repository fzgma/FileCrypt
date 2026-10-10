#include <filecrypt/io/directory.hpp>
#include <filecrypt/io/source.hpp>
#include <algorithm>
#include <cstdio>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <optional>
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
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#endif

namespace filecrypt::io {
void validate_target_name(std::string_view name) {
#ifdef _WIN32
    if (name.empty() || name.back() == ' ' || name.back() == '.' || name.find_first_of("<>:\"/\\|?*") != name.npos ||
        std::any_of(name.begin(), name.end(), [](unsigned char c) { return c < 32; }))
        throw std::invalid_argument("Name is not valid on Windows");
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

void create_restricted_directory(const std::filesystem::path& path) {
#ifdef _WIN32
    PSECURITY_DESCRIPTOR descriptor{};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)",
            SDDL_REVISION_1, &descriptor, nullptr)) throw std::runtime_error("Cannot set directory permissions");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const bool created = CreateDirectoryW(path.c_str(), &attributes) != 0;
    LocalFree(descriptor);
    if (!created) throw std::runtime_error("Cannot create directory; target may conflict");
#else
    if (mkdir(path.c_str(), 0700) != 0) throw std::runtime_error("Cannot create restricted directory; target may conflict");
#endif
}

namespace {
// 清理只遍历本事务排他创建的目录；不跟随 symlink 或 Windows reparse point。
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
    void verify_identity() const {
        if (!original) throw std::runtime_error("Temporary directory identity is unavailable");
        const auto current = inspect_source(temporary);
        if (!current.directory || current.device != original->device || current.identity != original->identity)
            throw std::runtime_error("Temporary directory root was replaced; refusing to touch it");
    }
    ~Impl() {
        if (!temporary.empty()) {
            try { verify_identity(); cleanup_tree(temporary); }
            catch (const std::exception& error) { std::fprintf(stderr, "Directory cleanup failed: %s\n", error.what()); }
        }
    }
};

DirectoryTransaction::DirectoryTransaction(const std::filesystem::path& destination) : impl_(std::make_unique<Impl>()) {
    impl_->destination = std::filesystem::absolute(destination).lexically_normal();
    if (impl_->destination.filename().empty() && impl_->destination != impl_->destination.root_path())
        impl_->destination = impl_->destination.parent_path();
    if (impl_->destination.filename().empty() || std::filesystem::exists(std::filesystem::symlink_status(impl_->destination)))
        throw std::runtime_error("Directory output already exists or is invalid");
    std::random_device random;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        std::ostringstream name;
        name << ".filecrypt-" << std::hex << random() << random() << ".dir";
        auto candidate = impl_->destination.parent_path() / name.str();
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
DirectoryTransaction::~DirectoryTransaction() = default;
const std::filesystem::path& DirectoryTransaction::root() const { return impl_->temporary; }

void DirectoryTransaction::commit() {
    if (impl_->temporary.empty()) throw std::logic_error("Directory already committed");
    impl_->verify_identity();
#ifdef _WIN32
    if (!MoveFileExW(impl_->temporary.c_str(), impl_->destination.c_str(), MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("Directory commit failed; target may already exist");
#elif defined(__linux__)
    // rename() 会替换已有空目录；必须使用内核的原子 no-replace 接口。
    if (syscall(SYS_renameat2, AT_FDCWD, impl_->temporary.c_str(), AT_FDCWD, impl_->destination.c_str(), 1u) != 0)
        throw std::runtime_error("Directory no-replace commit failed");
#else
    throw std::runtime_error("Atomic directory no-replace commit is unsupported on this platform");
#endif
    impl_->temporary.clear();
}
}
