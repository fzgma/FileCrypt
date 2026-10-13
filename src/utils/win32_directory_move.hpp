#pragma once

#ifdef _WIN32
    #include "win32_resource.hpp"
    #include <filesystem>

namespace filecrypt::utils {
namespace detail {
/// 目录重命名的访问或共享冲突最多尝试十次，计划等待共 450 ms，其他错误立即返回。
template<class Attempt, class Wait>
DWORD retry_directory_move(Attempt attempt, Wait wait) {
    constexpr unsigned max_attempts = 10;
    for (unsigned i = 0; i < max_attempts; ++i) {
        const auto error = attempt();
        if ((error != ERROR_ACCESS_DENIED && error != ERROR_SHARING_VIOLATION) || i + 1 == max_attempts)
            return error;
        wait(50);
    }
    return ERROR_ACCESS_DENIED;
}
}

/// 不覆盖目标移动目录；等待外部短暂占用后重新验证源对象，不放宽权限。
template<class VerifySource>
DWORD move_directory_no_replace(const std::filesystem::path& source,
    const std::filesystem::path& destination, VerifySource verify_source) {
    return detail::retry_directory_move([&] {
        verify_source();
        if (MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) return DWORD{ERROR_SUCCESS};
        const auto error = GetLastError();
        // 同名目标无需等待；后续创建目标的竞态仍由无覆盖移动接口拒绝。
        if ((error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) &&
            GetFileAttributesW(destination.c_str()) != INVALID_FILE_ATTRIBUTES) return DWORD{ERROR_ALREADY_EXISTS};
        return error;
    }, [](DWORD milliseconds) { Sleep(milliseconds); });
}

} // namespace filecrypt::utils
#endif
