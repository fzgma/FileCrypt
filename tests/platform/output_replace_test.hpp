#pragma once
#include <filesystem>

namespace test_output_replace {
/// 验证显式替换事务的原文件保护、竞争拒绝和清理行为。
void run(const std::filesystem::path& directory);
}
