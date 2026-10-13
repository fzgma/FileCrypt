#pragma once
#include <filesystem>

namespace test_rekey {
/// 验证流式换密、完整载荷检查、原文件保护和替换行为。
void run(const std::filesystem::path& root);
}
