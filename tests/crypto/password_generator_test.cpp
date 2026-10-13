#include "password_generator_test.hpp"
#include <filecrypt/crypto/password_generator.hpp>
#include "../../src/utils/random_password.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace test_password_generator {
namespace {
/// 测试失败只报告规则，不把随机生成的密码写入日志。
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

/// 验证所有预定义字符集的长度边界与内容范围，不依赖随机输出是否重复。
void generation_tests() {
    using namespace filecrypt::crypto;
    const auto default_password = generate_password();
    check(default_password.size() == 12, "Default password length changed");
    constexpr std::string_view alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    constexpr std::string_view symbols = "!#$%&*+-=?@_";
    for (const auto charset : {PasswordCharset::alnum, PasswordCharset::readable, PasswordCharset::symbols}) {
        for (const auto length : {std::size_t{8}, std::size_t{12}, std::size_t{64}}) {
            const auto password = generate_password({length, charset});
            check(password.size() == length, "Requested password length changed");
            for (const auto byte : password) {
                const auto character = static_cast<char>(byte);
                check(alnum.find(character) != alnum.npos ||
                    (charset == PasswordCharset::symbols && symbols.find(character) != symbols.npos),
                    "Password contains disallowed character");
                if (charset == PasswordCharset::readable)
                    check(std::string_view("0Oo1Iil").find(character) == std::string_view::npos,
                        "Readable password contains ambiguous character");
            }
        }
    }
    for (const auto length : {std::size_t{0}, std::size_t{7}, std::size_t{65}, std::numeric_limits<std::size_t>::max()}) {
        bool rejected = false;
        try { (void)generate_password({length, PasswordCharset::alnum}); }
        catch (const std::invalid_argument&) { rejected = true; }
        check(rejected, "Invalid password length accepted");
    }
    bool rejected = false;
    try { (void)generate_password({12, static_cast<PasswordCharset>(99)}); }
    catch (const std::invalid_argument&) { rejected = true; }
    check(rejected, "Unknown password charset accepted");
}

/// 使用独立向量验证尾部字节被拒绝，接受值按完整字符组映射。
void sampling_tests() {
    std::array<std::uint8_t, 6> password{};
    std::array<std::uint8_t, 7> random_buffer{};
    unsigned reads{};
    filecrypt::utils::fill_random_password(password, "ABC", random_buffer, [&](std::span<std::uint8_t> bytes) {
        ++reads;
        constexpr std::array<std::uint8_t, 7> input{255, 0, 1, 2, 254, 253, 252};
        std::copy(input.begin(), input.end(), bytes.begin());
    });
    constexpr std::array<std::uint8_t, 6> expected{'A', 'B', 'C', 'C', 'B', 'A'};
    check(password == expected && reads == 1, "Rejection sampling vector mismatch");
    bool failed = false;
    try {
        filecrypt::utils::fill_random_password(password, "ABC", random_buffer,
            [](std::span<std::uint8_t>) { throw std::runtime_error("Injected RNG failure"); });
    } catch (const std::runtime_error&) { failed = true; }
    check(failed, "Random source failure was swallowed");
}
}

/// 在现有密码层测试目标中运行密码生成回归。
void run() {
    generation_tests();
    sampling_tests();
}
}
