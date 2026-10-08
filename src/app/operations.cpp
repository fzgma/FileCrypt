#include <filecrypt/app/operations.hpp>
#include <filecrypt/format/detect.hpp>
#include <filecrypt/io/file.hpp>
#include "v1/operations.hpp"
#include <array>
#include <fstream>
#include <stdexcept>

namespace filecrypt::app {
/// 读取最小识别前缀后分发到对应版本的公开信息流程。
FileInfo inspect_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot open input file");
    }
    std::array<std::byte, format::identification_size> prefix{};
    io::read_exact(input, prefix);
    const auto version = format::detect_version(prefix);
    input.seekg(0);
    if (!input) {
        throw std::runtime_error("Cannot seek input file");
    }
    switch (version) {
    case 1: return v1::inspect(input);
    default: throw std::invalid_argument("Unsupported FileCrypt version");
    }
}

/// 根据创建选项的版本分发样本流程，未知版本不降级。
void generate_sample(const std::filesystem::path& path, const SampleOptions& options) {
    switch (options.version) {
    case 1: v1::sample(path, options); return;
    default: throw std::invalid_argument("Unsupported FileCrypt version");
    }
}
}
