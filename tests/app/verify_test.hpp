#pragma once
#include <filesystem>
namespace test_verify {
/// 验证认证、内部格式、资源策略及临时文件生命周期。
void run(const std::filesystem::path& root);
}
