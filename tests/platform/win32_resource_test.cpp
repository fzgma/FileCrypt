#include "win32_resource_test.hpp"
#include "../../src/utils/win32_resource.hpp"
#include "../../src/utils/win32_directory_move.hpp"
#include <filecrypt/io/source.hpp>
#include <filecrypt/io/directory.hpp>
#include <sddl.h>
#include <fstream>
#include <new>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <vector>

namespace test_win32_resource {
namespace {
using filecrypt::utils::UniqueFileHandle;

/// 报告所有权或锁行为不符合约定的情况。
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

/// 打开夹具文件并立即接管句柄，测试中不使用借用句柄构造所有者。
UniqueFileHandle open_file(const std::filesystem::path& path) {
    UniqueFileHandle handle(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    check(static_cast<bool>(handle), "Cannot open resource fixture");
    return handle;
}

/// 查询句柄是否已关闭，不对失效句柄再次调用 CloseHandle。
bool closed(HANDLE handle) {
    DWORD flags{};
    return !GetHandleInformation(handle, &flags) && GetLastError() == ERROR_INVALID_HANDLE;
}

/// 确定性注入容器分配失败，验证临时句柄未转交时仍被关闭。
template<class T>
struct FailingAllocator {
    using value_type = T;
    /// 容器首次扩容时失败，不修改全局分配器。
    [[nodiscard]] T* allocate(std::size_t) { throw std::bad_alloc(); }
    /// 与分配器接口配套，本测试不会成功分配内存。
    void deallocate(T*, std::size_t) noexcept {}
    bool operator==(const FailingAllocator&) const = default;
};

/// 验证空对象、移动、覆盖旧资源、转交及扩容失败均不会重复关闭或泄漏。
void handle_tests(const std::filesystem::path& path) {
    static_assert(!std::is_copy_constructible_v<UniqueFileHandle>);
    static_assert(std::is_nothrow_move_constructible_v<UniqueFileHandle>);
    static_assert(std::is_nothrow_move_assignable_v<UniqueFileHandle>);
    check(!UniqueFileHandle{} && !UniqueFileHandle{nullptr}, "Invalid handle was treated as owned");
    HANDLE transferred{};
    {
        auto first = open_file(path);
        transferred = first.get();
        UniqueFileHandle second(std::move(first));
        check(!first && second.get() == transferred, "Move construction lost ownership");
        auto third = open_file(path);
        const auto replaced = third.get();
        third = std::move(second);
        check(!second && third.get() == transferred && closed(replaced), "Move assignment leaked old handle");
        third = std::move(third);
        check(third.get() == transferred, "Self move closed the handle");
        UniqueFileHandle final(third.release());
        check(!third && final.get() == transferred, "Release failed to transfer ownership");
    }
    check(closed(transferred), "Owned handle leaked on scope exit");
    HANDLE pending{};
    bool failed = false;
    try {
        std::vector<UniqueFileHandle, FailingAllocator<UniqueFileHandle>> handles;
        auto handle = open_file(path);
        pending = handle.get();
        handles.push_back(std::move(handle));
    } catch (const std::bad_alloc&) { failed = true; }
    check(failed && closed(pending), "Container allocation failure leaked pending handle");
}

/// 验证 out_ptr 接收成功描述符，移动保持有效，失败时对象保持为空。
void descriptor_tests() {
    filecrypt::utils::UniqueSecurityDescriptor descriptor;
    // out_ptr 临时适配器在完整表达式结束时接管返回值，必须在下一条语句检查所有者。
    const auto converted = ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)(A;;FA;;;SY)",
        SDDL_REVISION_1, std::out_ptr(descriptor), nullptr);
    if (!converted) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
        "Security descriptor conversion failed");
    check(static_cast<bool>(descriptor), "Descriptor adoption failed");
    check(IsValidSecurityDescriptor(descriptor.get()) != 0, "Adopted security descriptor is invalid");
    auto moved = std::move(descriptor);
    check(!descriptor && IsValidSecurityDescriptor(moved.get()), "Descriptor move failed");
    moved.reset();
    const auto invalid = ConvertStringSecurityDescriptorToSecurityDescriptorW(L"invalid", SDDL_REVISION_1,
        std::out_ptr(descriptor), nullptr);
    check(!invalid && !descriptor, "Invalid descriptor was accepted");
}

/// 查询进程当前句柄数量，独立核对 Source 的文件及祖先资源持有和释放。
DWORD handle_count() {
    DWORD count{};
    check(GetProcessHandleCount(GetCurrentProcess(), &count) != 0, "Cannot query process handle count");
    return count;
}

/// 验证正常读取保持祖先锁，析构和构造校验失败都释放文件及祖先句柄。
void source_tests(const std::filesystem::path& path) {
    const auto snapshot = filecrypt::io::inspect_source(path);
    const auto before = handle_count();
    {
        filecrypt::io::SourceFile source(path, snapshot);
        check(handle_count() >= before + 2, "Source did not retain file and ancestor handles");
        UniqueFileHandle writer(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        check(!writer && GetLastError() == ERROR_SHARING_VIOLATION, "Source allowed concurrent writes");
        std::byte byte{};
        check(source.read(std::span(&byte, 1)) == 1, "Source fixture read failed");
        source.verify_unchanged();
    }
    check(handle_count() == before, "Source destructor leaked file or ancestor handles");
    auto changed = snapshot;
    ++changed.size;
    bool rejected = false;
    try { filecrypt::io::SourceFile source(path, changed); }
    catch (const std::runtime_error&) { rejected = true; }
    check(rejected && handle_count() == before, "Source validation failure leaked file or ancestor handles");
    UniqueFileHandle writer(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    check(static_cast<bool>(writer), "Source validation failure leaked file lock");
}

/// 验证短暂拒绝可恢复，持续拒绝有上限，其他错误及身份校验失败不被吞掉。
void move_retry_tests() {
    unsigned attempts{}, waits{};
    const auto success = filecrypt::utils::detail::retry_directory_move([&] {
        ++attempts;
        return attempts == 1 ? DWORD{ERROR_ACCESS_DENIED} :
            attempts == 2 ? DWORD{ERROR_SHARING_VIOLATION} : DWORD{ERROR_SUCCESS};
    }, [&](DWORD delay) { check(delay == 50, "Unexpected directory retry delay"); ++waits; });
    check(success == ERROR_SUCCESS && attempts == 3 && waits == 2, "Transient directory error was not retried");
    attempts = waits = 0;
    const auto denied = filecrypt::utils::detail::retry_directory_move([&] {
        ++attempts; return DWORD{ERROR_ACCESS_DENIED};
    }, [&](DWORD) { ++waits; });
    check(denied == ERROR_ACCESS_DENIED && attempts == 10 && waits == 9, "Persistent denial was not bounded");
    attempts = waits = 0;
    const auto conflict = filecrypt::utils::detail::retry_directory_move([&] {
        ++attempts; return DWORD{ERROR_ALREADY_EXISTS};
    }, [&](DWORD) { ++waits; });
    check(conflict == ERROR_ALREADY_EXISTS && attempts == 1 && waits == 0, "Conflict was retried");
    attempts = waits = 0;
    bool rejected = false;
    try {
        (void)filecrypt::utils::detail::retry_directory_move([&]() -> DWORD {
            if (++attempts == 2) throw std::runtime_error("Source identity changed");
            return ERROR_SHARING_VIOLATION;
        }, [&](DWORD) { ++waits; });
    } catch (const std::runtime_error&) { rejected = true; }
    check(rejected && attempts == 2 && waits == 1, "Identity failure was swallowed during retry");
}

/// 用不允许删除共享的子文件确定性复现目录移动拒绝，再释放占用验证提交。
void directory_move_tests(const std::filesystem::path& root) {
    const auto output = root / "committed";
    const auto staged = root / "staged";
    filecrypt::io::create_restricted_directory(staged);
    const auto original = filecrypt::io::inspect_source(staged);
    const auto child = staged / "held.bin";
    { std::ofstream stream(child, std::ios::binary); stream << "private"; }
    UniqueFileHandle held(CreateFileW(child.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr));
    check(static_cast<bool>(held), "Cannot lock directory child fixture");
    check(!MoveFileExW(staged.c_str(), output.c_str(), MOVEFILE_WRITE_THROUGH),
        "Directory child did not reproduce rename denial");
    const auto error = GetLastError();
    check(error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION, "Unexpected locked directory error");
    unsigned checks{};
    const auto moved = filecrypt::utils::move_directory_no_replace(staged, output, [&] {
        const auto current = filecrypt::io::inspect_source(staged);
        check(current.directory && current.device == original.device && current.identity == original.identity,
            "Directory retry changed source identity");
        // 第三次尝试前释放占用，确定性验证重试而不依赖线程调度时机。
        if (++checks == 3) held.reset();
    });
    check(moved == ERROR_SUCCESS && checks == 3 && std::filesystem::exists(output / "held.bin"),
        "Directory was not moved after unlock");
}
}

/// 在独立夹具内验证 Windows 所有权封装，不改变既有测试注册数量。
void run(const std::filesystem::path& directory) {
    const auto root = directory / "resource-test";
    std::filesystem::create_directory(root);
    const auto path = root / "source.bin";
    { std::ofstream output(path, std::ios::binary); output << "fixture"; }
    descriptor_tests();
    handle_tests(path);
    source_tests(path);
    move_retry_tests();
    directory_move_tests(root);
}
}
