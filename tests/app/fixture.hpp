#pragma once
#include <filesystem>
#include <random>
#include <stdexcept>
#include <string>

namespace test_fixture {
// 加密输出有所有者专属权限，每轮夹具必须独立于其他账户及并发运行。
inline std::filesystem::path create(const std::filesystem::path& parent) {
    std::filesystem::create_directories(parent);
    std::random_device random;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const auto candidate = parent / ("run-" + std::to_string(random()));
        if (std::filesystem::create_directory(candidate)) return candidate;
    }
    throw std::runtime_error("Cannot allocate independent test fixture");
}
}
