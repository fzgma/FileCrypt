#include <filecrypt/compression/compression.hpp>
#include <zstd.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
using Bytes = std::vector<std::byte>;
using namespace filecrypt;

/// 检查压缩测试条件并报告原因。
void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/// 验证异常输入或资源限制会导致明确失败。
template <typename Exception = std::exception, typename Function>
void rejects(Function action) {
    try {
        action();
    } catch (const Exception&) {
        return;
    }
    throw std::runtime_error("Expected compression failure");
}

/// 按指定输入分块运行压缩或解压并收集测试结果。
Bytes transform(bool compressing, std::span<const std::byte> input, std::size_t chunk = 65536,
    const compression::DecompressionLimits& limits = {}) {
    std::size_t position = 0;
    Bytes output;
    const compression::Reader read = [&](std::span<std::byte> buffer) {
        const auto count = std::min({chunk, buffer.size(), input.size() - position});
        std::copy_n(input.begin() + position, count, buffer.begin());
        position += count;
        return count;
    };
    const compression::Writer write = [&](std::span<const std::byte> bytes) {
        output.insert(output.end(), bytes.begin(), bytes.end());
    };
    if (compressing) {
        compression::compress(read, write);
    } else {
        compression::decompress(read, write, limits);
    }
    return output;
}

/// 验证空输入、缓冲区边界、随机数据和 Zstandard 原生 API 互操作。
void roundtrip_tests() {
    for (const std::size_t size : {0u, 1u, 65536u, 131073u}) {
        Bytes plain(size);
        std::uint32_t random = 0x12345678;
        for (auto& value : plain) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            value = static_cast<std::byte>(random & 255);
        }
        for (const std::size_t chunk : {1u, 17u, 65536u}) {
            const auto compressed = transform(true, plain, chunk);
            check(transform(false, compressed, 7) == plain, "Chunked roundtrip mismatch");
            Bytes restored(std::max(size, std::size_t{1}));
            const auto result = ZSTD_decompress(restored.data(), restored.size(), compressed.data(), compressed.size());
            check(!ZSTD_isError(result) && result == size, "Native Zstandard rejected frame");
            restored.resize(size);
            check(restored == plain, "Native decoder output mismatch");
        }
        Bytes native(ZSTD_compressBound(plain.size()));
        const auto size_compressed = ZSTD_compress(native.data(), native.size(), plain.data(), plain.size(), 3);
        check(!ZSTD_isError(size_compressed), "Native compression failed");
        native.resize(size_compressed);
        check(transform(false, native, 1) == plain, "Native frame decoding mismatch");
    }
}

/// 验证异常帧、拼接帧、标准跳过帧和累计输出上限。
void frame_tests() {
    const Bytes plain(131073, std::byte{0x61});
    const auto frame = transform(true, plain);
    for (const auto length : {std::size_t{0}, std::size_t{3}, frame.size() / 2, frame.size() - 1}) {
        rejects([&] { transform(false, std::span(frame).first(length)); });
    }
    auto changed = frame;
    changed.back() ^= std::byte{1};
    rejects([&] { transform(false, changed); });
    auto trailing = frame;
    trailing.push_back(std::byte{0xFF});
    rejects([&] { transform(false, trailing); });
    auto joined = frame;
    joined.insert(joined.end(), frame.begin(), frame.end());
    auto double_plain = plain;
    double_plain.insert(double_plain.end(), plain.begin(), plain.end());
    check(transform(false, joined, 1) == double_plain, "Concatenated frames mismatch");
    rejects<std::length_error>([&] { transform(false, joined, 65536, {plain.size(), 26}); });
    rejects<std::length_error>([&] { transform(false, frame, 65536, {plain.size() - 1, 26}); });
    check(transform(false, frame, 65536, {plain.size(), 26}) == plain, "Exact output limit failed");
    check(transform(false, transform(true, {}), 1, {0, 26}).empty(), "Empty output limit failed");
    Bytes skipped{std::byte{0x50}, std::byte{0x2A}, std::byte{0x4D}, std::byte{0x18},
        std::byte{3}, std::byte{}, std::byte{}, std::byte{}, std::byte{1}, std::byte{2}, std::byte{3}};
    skipped.insert(skipped.end(), frame.begin(), frame.end());
    check(transform(false, skipped, 1) == plain, "Standard skippable frame mismatch");

    // 流式帧没有单段标志，窗口描述字节可改为 128 MiB，帧内容校验和不变。
    auto large_window = frame;
    check((std::to_integer<unsigned>(large_window.at(4)) & 0x20) == 0, "Expected streaming frame header");
    large_window.at(5) = std::byte{0x88};
    rejects<std::length_error>([&] { transform(false, large_window); });
    check(transform(false, large_window, 1, {plain.size(), 27}) == plain, "Raised window limit failed");
    rejects<std::invalid_argument>([&] { transform(false, frame, 1, {plain.size(), 9}); });
    rejects<std::invalid_argument>([&] { transform(false, frame, 1, {plain.size(), 31}); });
}

/// 验证有界回调契约和输出失败会中止处理。
void callback_tests() {
    rejects<std::logic_error>([] {
        compression::compress([](std::span<std::byte> buffer) { return buffer.size() + 1; },
            [](std::span<const std::byte>) {});
    });
    rejects<std::runtime_error>([] {
        compression::compress([](std::span<std::byte>) { return std::size_t{0}; },
            [](std::span<const std::byte>) { throw std::runtime_error("Writer failed"); });
    });
    rejects<std::invalid_argument>([] {
        compression::compress([](std::span<std::byte>) { return std::size_t{0}; },
            [](std::span<const std::byte>) {}, 1000);
    });
}
}

/// 执行压缩层全部测试并以退出码报告结果。
int main() {
    try {
        roundtrip_tests();
        frame_tests();
        callback_tests();
        std::cout << "Compression tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
