#pragma once
#include <filesystem>

namespace test_inspect {
/// 在独立夹具中验证信息读取结果、错误语义及输入流故障。
void run(const std::filesystem::path& directory);
}
