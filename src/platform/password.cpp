#include <filecrypt/io/password.hpp>
#include <iostream>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace filecrypt::io {
namespace {
constexpr std::size_t password_limit = 1024 * 1024;

struct EchoGuard {
#ifdef _WIN32
    HANDLE input{GetStdHandle(STD_INPUT_HANDLE)};
    DWORD original{};
#else
    termios original{};
#endif
    bool terminal{false};
    /// 检测真实终端并暂时关闭密码回显。
    EchoGuard() {
#ifdef _WIN32
        terminal = GetConsoleMode(input, &original) != 0;
        if (terminal && !SetConsoleMode(input, original & ~ENABLE_ECHO_INPUT)) {
            throw std::runtime_error("Cannot disable password echo");
        }
#else
        terminal = isatty(STDIN_FILENO) != 0;
        if (terminal) {
            if (tcgetattr(STDIN_FILENO, &original) != 0) {
                throw std::runtime_error("Cannot read terminal mode");
            }
            auto mode = original;
            mode.c_lflag &= static_cast<tcflag_t>(~ECHO);
            if (tcsetattr(STDIN_FILENO, TCSANOW, &mode) != 0) {
                throw std::runtime_error("Cannot disable password echo");
            }
        }
#endif
    }
    /// 在正常结束或异常时恢复原始终端模式。
    ~EchoGuard() {
        if (terminal) {
#ifdef _WIN32
            SetConsoleMode(input, original);
#else
            tcsetattr(STDIN_FILENO, TCSANOW, &original);
#endif
            std::cerr << '\n';
        }
    }
};
}

/// 读取终端或管道中的一行密码，终端隐藏输入且不修改密码内容。
Botan::secure_vector<std::uint8_t> read_password(std::string_view prompt) {
    EchoGuard guard;
    std::cerr << prompt << std::flush;
#ifdef _WIN32
    if (guard.terminal) {
        Botan::secure_vector<wchar_t> wide;
        bool complete = false;
        while (!complete) {
            Botan::secure_vector<wchar_t> buffer(128);
            DWORD count{};
            if (!ReadConsoleW(guard.input, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr) ||
                count == 0) {
                throw std::runtime_error("Password input ended");
            }
            for (DWORD i = 0; i < count; ++i) {
                if (buffer[i] == L'\n') {
                    complete = true;
                    break;
                }
                wide.push_back(buffer[i]);
            }
            if (wide.size() > password_limit) {
                throw std::length_error("Password input too long");
            }
        }
        if (!wide.empty() && wide.back() == L'\r') {
            wide.pop_back();
        }
        if (wide.empty()) {
            return {};
        }
        const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(),
            static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
        if (size == 0) {
            throw std::runtime_error("Invalid Unicode password");
        }
        Botan::secure_vector<std::uint8_t> password(static_cast<std::size_t>(size));
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), static_cast<int>(wide.size()),
                reinterpret_cast<char*>(password.data()), size, nullptr, nullptr) != size) {
            throw std::runtime_error("Password UTF-8 conversion failed");
        }
        return password;
    }
#endif
    Botan::secure_vector<std::uint8_t> password;
    bool received = false;
    char value;
    while (std::cin.get(value)) {
        received = true;
        if (value == '\n') {
            break;
        }
        if (password.size() == password_limit) {
            throw std::length_error("Password input too long");
        }
        password.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(value)));
    }
    if (!received || std::cin.bad()) {
        throw std::runtime_error("Password input ended");
    }
    return password;
}
}
