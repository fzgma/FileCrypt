#pragma once
#include <cstdint>

namespace filecrypt::directory {
// 可调整的运行策略，不是任何版本的协议常数。
struct Limits {
    std::uint64_t max_index_bytes{64 * 1024 * 1024};
    std::uint32_t max_entries{100000};
    std::uint32_t max_name_bytes{4096};
    std::uint32_t max_depth{256};
    std::uint64_t max_output_bytes{std::uint64_t{16} * 1024 * 1024 * 1024};
};
}
