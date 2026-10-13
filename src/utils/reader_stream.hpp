#pragma once
#include <algorithm>
#include <array>
#include <cstddef>
#include <functional>
#include <span>
#include <stdexcept>
#include <streambuf>
#include <utility>

namespace filecrypt::utils {
/// 将密文读取回调适配为有界流缓冲区；可重放版本分发已经消费的前缀。
class ReaderStreamBuffer final : public std::streambuf {
public:
    using Reader = std::function<std::size_t(std::span<std::byte>)>;

    /// 保存读取回调并复制短前缀；本适配器不用于缓存解密载荷。
    explicit ReaderStreamBuffer(Reader read, std::span<const std::byte> prefix = {})
        : read_(std::move(read)) {
        if (prefix.size() > buffer_.size()) throw std::logic_error("Reader prefix exceeds buffer");
        std::transform(prefix.begin(), prefix.end(), buffer_.begin(),
            [](std::byte value) { return static_cast<char>(value); });
        setg(buffer_.data(), buffer_.data(), buffer_.data() + prefix.size());
    }
private:
    /// 仅在已有字节耗尽后读取下一块，读取异常由启用 badbit 异常的流传播。
    int_type underflow() override {
        if (gptr() != egptr()) return traits_type::to_int_type(*gptr());
        const auto count = read_(std::as_writable_bytes(std::span(buffer_)));
        if (count > buffer_.size()) throw std::logic_error("Reader returned an invalid length");
        setg(buffer_.data(), buffer_.data(), buffer_.data() + count);
        return count ? traits_type::to_int_type(*gptr()) : traits_type::eof();
    }
    Reader read_;
    std::array<char, 65536> buffer_{};
};
}
