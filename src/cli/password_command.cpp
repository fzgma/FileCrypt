#include "password_command.hpp"
#include <filecrypt/crypto/password_generator.hpp>
#include <charconv>
#include <cstdio>
#include <stdexcept>
#include <string_view>
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
#else
    #include <csignal>
    #include <unistd.h>
#endif

namespace filecrypt::cli {
namespace {
#ifndef _WIN32
/// 将断开的输出管道转换为写出失败，避免 SIGPIPE 在检查退出码前终止命令。
class PipeSignalGuard {
    using Handler = void (*)(int);
    Handler original_;
public:
    /// 仅在本命令输出期间忽略 SIGPIPE，保留原信号处理方式。
    PipeSignalGuard() : original_(std::signal(SIGPIPE, SIG_IGN)) {
        if (original_ == SIG_ERR) throw std::runtime_error("无法配置密码输出管道");
    }
    /// 退出时恢复原处理方式，清理中不抛异常。
    ~PipeSignalGuard() { std::signal(SIGPIPE, original_); }
};
#endif

/// 仅在标准输出连接真实终端时显示非密码提示，管道输出保持单行。
bool output_is_terminal() {
#ifdef _WIN32
    DWORD mode{};
    return GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

/// 在接触随机源和输出前拒绝重复、缺值、未知选项及非法参数。
crypto::PasswordOptions parse_password_options(int argc, char** argv) {
    crypto::PasswordOptions options;
    bool length_seen{}, charset_seen{};
    for (int i = 2; i < argc; ++i) {
        const std::string_view name = argv[i];
        if (name != "length" && name != "charset") throw std::invalid_argument("未知密码生成选项");
        auto& seen = name == "length" ? length_seen : charset_seen;
        if (seen) throw std::invalid_argument("密码生成选项重复");
        seen = true;
        if (++i >= argc) throw std::invalid_argument("密码生成选项缺少值");
        const std::string_view value = argv[i];
        if (name == "length") {
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), options.length);
            if (error != std::errc{} || end != value.data() + value.size() || options.length < 8 || options.length > 64)
                throw std::invalid_argument("密码长度必须为 8 到 64 的整数");
        } else if (value == "alnum") options.charset = crypto::PasswordCharset::alnum;
        else if (value == "readable") options.charset = crypto::PasswordCharset::readable;
        else if (value == "symbols") options.charset = crypto::PasswordCharset::symbols;
        else throw std::invalid_argument("密码字符集必须为 alnum、readable 或 symbols");
    }
    return options;
}
}

/// 密码保存在安全内存中直接输出，写出或刷新失败不报告密码内容。
void generate_password_command(int argc, char** argv) {
    const auto options = parse_password_options(argc, argv);
    auto password = crypto::generate_password(options);
#ifndef _WIN32
    PipeSignalGuard pipe_signal;
#endif
    if (output_is_terminal()) {
        if (std::fputs("请自行安全保存此密码，程序不会保存或再次显示。\n", stderr) == EOF || std::fflush(stderr) != 0)
            throw std::runtime_error("无法输出密码保存提示");
    }
    if (std::fwrite(password.data(), 1, password.size(), stdout) != password.size() ||
        std::fputc('\n', stdout) == EOF || std::fflush(stdout) != 0)
        throw std::runtime_error("密码输出失败");
}

} // namespace filecrypt::cli
