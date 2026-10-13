#include <filecrypt/crypto/password_generator.hpp>
#include "../../utils/random_password.hpp"
#include <botan/system_rng.h>
#include <stdexcept>
#include <string_view>

namespace filecrypt::crypto {
namespace {
/// 返回预定义且没有重复字符的 ASCII 字符集，拒绝未知枚举值。
std::string_view password_alphabet(PasswordCharset charset) {
    constexpr std::string_view alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    switch (charset) {
    case PasswordCharset::alnum: return alnum;
    case PasswordCharset::readable: return "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    case PasswordCharset::symbols: return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-=?@_";
    default: throw std::invalid_argument("不支持的密码字符集");
    }
}
}

/// 系统随机源直接填充安全缓冲区，密码不经过普通字符串或公开随机字节容器。
SecureBytes generate_password(const PasswordOptions& options) {
    if (options.length < 8 || options.length > 64) throw std::invalid_argument("密码长度必须为 8 到 64");
    const auto alphabet = password_alphabet(options.charset);
    SecureBytes password(options.length);
    SecureBytes random_buffer(64);
    Botan::System_RNG random;
    utils::fill_random_password(password, alphabet, random_buffer,
        [&](std::span<std::uint8_t> bytes) { random.randomize(bytes.data(), bytes.size()); });
    return password;
}

} // namespace filecrypt::crypto
