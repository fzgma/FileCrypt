#include <filecrypt/compression/compression.hpp>
#include <zstd.h>
#include <zstd_errors.h>
#include <array>
#include <memory>
#include <stdexcept>
#include <string>

namespace filecrypt::compression {
namespace {
struct Buffer {
    std::array<std::byte, 65536> bytes{};
    /// 在退出时擦除本层固定缓冲区中的明文与压缩数据。
    ~Buffer() {
        volatile std::byte* data = bytes.data();
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            data[i] = std::byte{};
        }
    }
};

/// 将 Zstandard 错误转换为资源超限或数据处理异常。
std::size_t checked(std::size_t result) {
    if (ZSTD_isError(result)) {
        if (ZSTD_getErrorCode(result) == ZSTD_error_frameParameter_windowTooLarge) {
            throw std::length_error("Zstandard window exceeds runtime limit");
        }
        throw std::runtime_error(std::string("Zstandard: ") + ZSTD_getErrorName(result));
    }
    return result;
}

/// 读取一个有界数据块并拒绝违反回调约定的长度。
std::size_t read_chunk(const Reader& read, Buffer& buffer) {
    const auto count = read(buffer.bytes);
    if (count > buffer.bytes.size()) {
        throw std::logic_error("Compression reader returned an invalid length");
    }
    return count;
}
}

/// 校验可移植的 Zstandard 最大窗口范围。
void validate_limits(const DecompressionLimits& limits) {
    if (limits.max_window_log < 10 || limits.max_window_log > 30) {
        throw std::invalid_argument("Zstandard window log must be between 10 and 30");
    }
}

/// 以固定缓冲区压缩输入，结束时完整刷新单个帧。
void compress(const Reader& read, const Writer& write, int level) {
    if (level < ZSTD_minCLevel() || level > ZSTD_maxCLevel()) {
        throw std::invalid_argument("Invalid Zstandard compression level");
    }
    const std::unique_ptr<ZSTD_CCtx, decltype(&ZSTD_freeCCtx)> context(ZSTD_createCCtx(), ZSTD_freeCCtx);
    if (!context) {
        throw std::bad_alloc();
    }
    checked(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_compressionLevel, level));
    checked(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_checksumFlag, 1));
    Buffer source;
    Buffer target;
    while (true) {
        const auto count = read_chunk(read, source);
        ZSTD_inBuffer input{source.bytes.data(), count, 0};
        const auto mode = count == 0 ? ZSTD_e_end : ZSTD_e_continue;
        std::size_t remaining;
        do {
            ZSTD_outBuffer output{target.bytes.data(), target.bytes.size(), 0};
            remaining = checked(ZSTD_compressStream2(context.get(), &output, &input, mode));
            if (output.pos > 0) {
                write(std::span(target.bytes).first(output.pos));
            }
        } while (input.pos < input.size || (mode == ZSTD_e_end && remaining != 0));
        if (mode == ZSTD_e_end) {
            return;
        }
    }
}

/// 解压完整帧序列并在交给输出回调之前检查累计长度。
void decompress(const Reader& read, const Writer& write, const DecompressionLimits& limits) {
    validate_limits(limits);
    const std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> context(ZSTD_createDCtx(), ZSTD_freeDCtx);
    if (!context) {
        throw std::bad_alloc();
    }
    checked(ZSTD_DCtx_setParameter(context.get(), ZSTD_d_windowLogMax, static_cast<int>(limits.max_window_log)));
    Buffer source;
    Buffer target;
    std::uint64_t total = 0;
    std::size_t remaining = 1;
    while (const auto count = read_chunk(read, source)) {
        ZSTD_inBuffer input{source.bytes.data(), count, 0};
        std::size_t produced;
        do {
            ZSTD_outBuffer output{target.bytes.data(), target.bytes.size(), 0};
            remaining = checked(ZSTD_decompressStream(context.get(), &output, &input));
            produced = output.pos;
            if (produced > limits.max_output_bytes - total) {
                throw std::length_error("Decompressed output exceeds runtime limit");
            }
            total += produced;
            if (produced > 0) {
                write(std::span(target.bytes).first(produced));
            }
        } while (input.pos < input.size || (produced == target.bytes.size() && remaining != 0));
    }
    if (remaining != 0) {
        throw std::runtime_error("Truncated or empty Zstandard stream");
    }
}
}
