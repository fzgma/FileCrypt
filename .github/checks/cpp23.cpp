// 发布工具链预检；使用相同 CPU 基线及静态 C++ 运行库，并纳入 ELF/运行矩阵验证。
#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <expected>
#include <format>
#include <memory>
#include <optional>
#include <print>
#include <ranges>
#include <string_view>
#include <utility>
#include <vector>

#if defined(FILECRYPT_REQUIRE_GCC15) && (!defined(_GLIBCXX_RELEASE) || _GLIBCXX_RELEASE != 15)
#error "The release probe requires GCC 15 libstdc++ headers"
#endif

enum class Kind : std::uint16_t { file = 1 };
void allocate(int** value) { *value = new int(42); }

int main() {
    std::vector<int> values{1, 2};
    values.append_range(std::array{3, 4});
    const auto doubled = values | std::views::transform([](int n) { return n * 2; }) |
        std::ranges::to<std::vector<int>>();
    for (auto [index, value] : std::views::enumerate(doubled)) {
        if (value != static_cast<int>((index + 1) * 2)) return 1;
    }
    for (auto [a, b] : std::views::zip(values, doubled)) if (a * 2 != b) return 1;
    std::ranges::sort(values);
    if (std::ranges::lower_bound(values, 3) == values.end()) return 1;
    if (!std::string_view("tar.gz").contains('.')) return 1;
    std::unique_ptr<int> value;
    allocate(std::out_ptr(value));
    if (*value != 42 || std::expected<int, int>(21).transform([](int n) { return n * 2; }).value() != 42 ||
        std::optional<int>(21).transform([](int n) { return n * 2; }).value() != 42) return 1;
    if (std::to_underlying(Kind::file) != 1 || std::byteswap(0x12345678u) != 0x78563412u) return 1;
    std::println("libstdc++ {} / C++23 预检通过：{}", _GLIBCXX_RELEASE, std::format("{} elements", values.size()));
}
