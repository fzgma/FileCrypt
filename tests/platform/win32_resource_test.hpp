#pragma once
#include <filesystem>

namespace test_win32_resource {
/// 验证描述符所有权、文件句柄转移和 Source 祖先锁的生命周期。
void run(const std::filesystem::path& directory);
}
