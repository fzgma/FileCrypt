#pragma once

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include <memory>
    #include <utility>

namespace filecrypt::utils {

/// 释放 Win32 LocalAlloc 系列 API 返回的内存，不在清理中抛异常。
struct LocalFreeDeleter {
    /// 配合独占指针释放安全描述符，不能使用 delete 或 CloseHandle。
    void operator()(void* pointer) const noexcept { LocalFree(pointer); }
};

using UniqueSecurityDescriptor = std::unique_ptr<void, LocalFreeDeleter>;

/// 独占 CreateFileW 返回的文件或目录句柄，禁止复制与隐式借用转所有权。
class UniqueFileHandle {
public:
    /// 空对象不持有句柄；NULL 与 INVALID_HANDLE_VALUE 都表示无资源。
    explicit UniqueFileHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : handle_(handle) {}
    /// 在成功和异常退出时关闭仍持有的文件句柄。
    ~UniqueFileHandle() { reset(); }
    UniqueFileHandle(const UniqueFileHandle&) = delete;
    UniqueFileHandle& operator=(const UniqueFileHandle&) = delete;
    /// 无分配转交所有权，原对象变为空对象。
    UniqueFileHandle(UniqueFileHandle&& other) noexcept : handle_(other.release()) {}
    /// 先释放原资源再接收新所有权，自移动保留原对象。
    UniqueFileHandle& operator=(UniqueFileHandle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    /// 借用句柄供 Win32 调用使用，不转交所有权。
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    /// 判断是否持有可关闭的文件或目录句柄。
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }
    /// 转交句柄给其他所有者，当前对象不再负责关闭。
    [[nodiscard]] HANDLE release() noexcept { return std::exchange(handle_, INVALID_HANDLE_VALUE); }
    /// 释放原资源并接收新句柄，清理行为与原 Source 析构一致。
    void reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept {
        if (handle_ == handle) return;
        if (*this) CloseHandle(handle_);
        handle_ = handle;
    }
private:
    HANDLE handle_;
};

} // namespace filecrypt::utils
#endif // _WIN32

