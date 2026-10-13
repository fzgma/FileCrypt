#pragma once
#include <filecrypt/crypto/crypto.hpp>
#include <cstddef>

namespace filecrypt::crypto {

enum class PasswordCharset { alnum, readable, symbols };

struct PasswordOptions {
    std::size_t length{12};
    PasswordCharset charset{PasswordCharset::alnum};
};

/// 使用系统安全随机源生成 8 至 64 个 ASCII 字符，结果由安全分配器管理。
[[nodiscard]] SecureBytes generate_password(const PasswordOptions& options = {});

} // namespace filecrypt::crypto
