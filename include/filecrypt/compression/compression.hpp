#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

namespace filecrypt::compression {
using Reader = std::function<std::size_t(std::span<std::byte>)>;
using Writer = std::function<void(std::span<const std::byte>)>;

// 可调整的运行策略，不是 v1 格式常数；上限累计覆盖全部帧。
struct DecompressionLimits {
    std::uint64_t max_output_bytes{16ULL * 1024 * 1024 * 1024};
    std::uint32_t max_window_log{26};
};

/// 校验解压窗口策略，拒绝库不支持的范围。
void validate_limits(const DecompressionLimits& limits);
/// 从回调读取明文并流式输出一个带校验和、无字典的 Zstandard 帧。
void compress(const Reader& read, const Writer& write, int level = 3);
/// 流式解压标准 Zstandard 帧序列并执行窗口及累计输出限制。
void decompress(const Reader& read, const Writer& write, const DecompressionLimits& limits = {});
}
