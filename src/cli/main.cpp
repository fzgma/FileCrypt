#include <filecrypt/app/operations.hpp>
#include <filecrypt/io/password.hpp>
#include <array>
#include <charconv>
#include <algorithm>
#include <bit>
#include <print>
#include <ranges>
#include <set>
#include <string>
#include <stdexcept>
#include <string_view>
#include <vector>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif

    #ifndef NOMINMAX
        #define NOMINMAX
    #endif

    #include <windows.h>
#endif // _WIN32

namespace {
/// CLI 参数统一使用 UTF-8，避免 Windows 按当前 ANSI 代码页解释路径。
std::filesystem::path argument_path(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

/// 仅为没有扩展名的密文文件路径补充默认后缀。
std::filesystem::path ciphertext_path(std::filesystem::path path) {
    if (path.has_filename() && path.filename() != "." && path.filename() != ".." &&
        !path.has_extension()) {
        path += ".fcry";
    }
    return path;
}

#ifdef _WIN32
/// 仅在连接真实控制台时切换输出代码页，退出前刷新输出并恢复原设置。
class ConsoleOutputGuard {
    UINT original_{};
public:
    ConsoleOutputGuard() {
        DWORD mode{};
        if (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) ||
            GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode)) {
            original_ = GetConsoleOutputCP();
            if (original_ == 0 || !SetConsoleOutputCP(CP_UTF8)) {
                throw std::runtime_error("Cannot configure UTF-8 console output");
            }
        }
    }
    ~ConsoleOutputGuard() {
        std::fflush(stdout);
        std::fflush(stderr);
        if (original_ != 0) {
            SetConsoleOutputCP(original_);
        }
    }
};

/// 无损转换 Windows 原生命令行；非法 UTF-16 明确失败。
std::string argument_utf8(const wchar_t* text) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1,
        nullptr, 0, nullptr, nullptr);
    if (size == 0) {
        throw std::invalid_argument("Invalid Unicode command-line argument");
    }
    std::string result;
    int written{};
    // 回调不抛异常；成功时直接排除终止符，失败在回调结束后报告。
    result.resize_and_overwrite(static_cast<std::size_t>(size),
        [&](char* buffer, std::size_t) noexcept -> std::size_t {
            written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1,
                buffer, size, nullptr, nullptr);
            return written == size ? static_cast<std::size_t>(size - 1) : 0;
        });
    if (written != size) {
        throw std::runtime_error("Command-line UTF-8 conversion failed");
    }
    return result;
}
#endif

/// 显示完整命令、简写和固定路径位置的用法。
void print_usage() {
    std::print("用法：\n"
        "  filecrypt encrypt|-e <输入路径> <输出.fcry> [选项]\n"
        "  filecrypt decrypt|-d <输入.fcry> <输出路径> [资源上限]\n"
        "  filecrypt info|-i <文件路径>\n"
        "  filecrypt sample <文件路径> [algorithm|-a aes|xchacha] [directory] [compress|-z|no-compress]\n"
        "  filecrypt help|-h\n"
        "完整名称不带横线，简写带单横线；加解密的前两个参数固定为输入、输出路径。\n"
        "加密输出、解密输入未指定后缀时自动补 .fcry；已有后缀原样保留。\n"
        "解密输出未指定后缀时补上记录的扩展名（含 tar.gz 等复合后缀）；Unknown 不补。\n"
        "加密选项：algorithm|-a aes|xchacha（默认 aes），compress|-z 或 no-compress（默认）\n"
        "算法值也接受 aes-256-gcm 和 xchacha20-poly1305。\n"
        "加密参数：memory-kib N iterations N parallelism N\n"
        "资源上限：max-memory-kib N max-iterations N max-parallelism N\n"
        "解压上限：max-output-bytes N（默认 16 GiB），max-window-kib N（默认 65536）\n"
        "密码从隐藏终端或标准输入读取；加密需要输入两次，解密一次。\n"
        "encrypt/decrypt 支持普通文件和目录，可选 Zstandard 压缩；目录恢复目标就是根目录。\n"
        "目录上限：max-index-bytes N max-entries N max-name-bytes N max-depth N max-archive-bytes N\n"
        "解密自动读取算法和布局，不接受算法或压缩选项；拒绝覆盖已有输出。\n"
        "sample 仅生成 Header 与 Metadata 格式示例，不执行加密。\n");
}

/// 将文件路径的末级文件名转换为 UTF-8 输出文本。
std::string display_filename(const std::filesystem::path& path) {
    const auto name = path.filename().u8string();
    return std::string(name.begin(), name.end());
}

/// 将不依赖协议内部类型的公开信息显示给用户。
void print_info(const std::filesystem::path& path, const filecrypt::app::FileInfo& info) {
    std::println("加密文件名：{}", display_filename(path));
    std::println("格式版本：{}", info.version);
    std::println("加密算法：{}", info.algorithm);
    std::println("压缩：{}", info.compressed ? "是" : "否");
    if (info.compressed) {
        std::println("压缩算法：{}", info.compression);
    }
    std::println("目录：{}", info.directory ? "是" : "否");
    std::println("文件类型：{}", info.file_type);
    std::println("密钥派生：{}", info.kdf);
    for (const auto& [name, value] : info.details) {
        std::println("{}：{}", name, value);
    }
    std::println("载荷：{}", info.has_payload ? "存在" : "空");
    std::println("认证状态：{}", info.authenticated ? "已验证" : "未验证");
}

/// 拒绝同一选项的重复或冲突写法。
void claim_option(std::set<std::string_view>& seen, std::string_view name) {
    if (!seen.insert(name).second) {
        throw std::invalid_argument("选项重复或冲突：" + std::string(name));
    }
}

/// 读取当前选项的必需值，缺失时报告选项名称。
std::string_view next_value(int& index, int argc, char** argv) {
    if (index + 1 >= argc) {
        throw std::invalid_argument("选项缺少值：" + std::string(argv[index]));
    }
    return argv[++index];
}

/// 将简短或完整算法名称转换为密码层算法枚举。
filecrypt::crypto::Algorithm parse_algorithm(std::string_view value) {
    if (value == "aes" || value == "aes-256-gcm") {
        return filecrypt::crypto::Algorithm::aes256_gcm;
    }
    if (value == "xchacha" || value == "xchacha20-poly1305") {
        return filecrypt::crypto::Algorithm::xchacha20_poly1305;
    }
    throw std::invalid_argument("不支持的算法名称：" + std::string(value));
}

/// 按固定输出路径及后续选项解析格式样本命令。
void generate_sample(const std::filesystem::path& path, int argc, char** argv) {
    filecrypt::app::SampleOptions options;
    std::set<std::string_view> seen;
    for (int i = 3; i < argc; ++i) {
        const std::string_view option = argv[i];
        if (option == "directory") {
            claim_option(seen, "directory");
            options.directory = true;
        } else if (option == "compress" || option == "-z" || option == "no-compress") {
            claim_option(seen, "compress/no-compress");
            options.compressed = option != "no-compress";
        } else if (option == "algorithm" || option == "-a") {
            claim_option(seen, "algorithm");
            const auto algorithm = parse_algorithm(next_value(i, argc, argv));
            options.algorithm = algorithm == filecrypt::crypto::Algorithm::aes256_gcm
                ? "aes-256-gcm" : "xchacha20-poly1305";
        } else {
            throw std::invalid_argument("未知选项：" + std::string(option));
        }
    }
    filecrypt::app::generate_sample(path, options);
    std::println("已生成格式示例：{}（仅 Header 与 Metadata，未执行加密）", display_filename(path));
}

/// 将命令行数值严格解析为正的 32 位整数。
std::uint32_t parse_positive(std::string_view text) {
    std::uint32_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0) {
        throw std::invalid_argument("参数必须是正的 32 位整数");
    }
    return value;
}

/// 将解压输出字节上限严格解析为正的 64 位整数。
std::uint64_t parse_output_limit(std::string_view text) {
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0) {
        throw std::invalid_argument("解压输出上限必须是正的 64 位整数");
    }
    return value;
}

/// 将以 KiB 表示的二次幂窗口上限转换为 Zstandard 运行策略。
std::uint32_t parse_window_log(std::string_view text) {
    const auto kib = parse_positive(text);
    if (!std::has_single_bit(kib) || kib > 1048576) {
        throw std::invalid_argument("解压窗口 KiB 必须是 1 到 1048576 之间的二次幂");
    }
    return static_cast<std::uint32_t>(std::countr_zero(kib)) + 10;
}

enum class OptionId {
    algorithm,
    compression,
    memory,
    iterations,
    parallelism,
    max_memory,
    max_iterations,
    max_parallelism,
    max_output,
    max_window,
    max_index,
    max_entries,
    max_name,
    max_depth,
    max_archive
};

struct OptionSpec {
    std::string_view name;
    // 别名和互斥写法共用 claim，使重复检测不依赖用户采用哪种拼写。
    std::string_view claim;
    OptionId id;
    bool encrypt_only;
    bool decrypt_only;
};

constexpr std::array option_specs{
    OptionSpec{"algorithm", "algorithm", OptionId::algorithm, true, false},
    OptionSpec{"-a", "algorithm", OptionId::algorithm, true, false},
    OptionSpec{"compress", "compress/no-compress", OptionId::compression, true, false},
    OptionSpec{"-z", "compress/no-compress", OptionId::compression, true, false},
    OptionSpec{"no-compress", "compress/no-compress", OptionId::compression, true, false},
    OptionSpec{"memory-kib", "memory-kib", OptionId::memory, true, false},
    OptionSpec{"iterations", "iterations", OptionId::iterations, true, false},
    OptionSpec{"parallelism", "parallelism", OptionId::parallelism, true, false},
    OptionSpec{"max-memory-kib", "max-memory-kib", OptionId::max_memory, false, false},
    OptionSpec{"max-iterations", "max-iterations", OptionId::max_iterations, false, false},
    OptionSpec{"max-parallelism", "max-parallelism", OptionId::max_parallelism, false, false},
    OptionSpec{"max-output-bytes", "max-output-bytes", OptionId::max_output, false, true},
    OptionSpec{"max-window-kib", "max-window-kib", OptionId::max_window, false, true},
    OptionSpec{"max-index-bytes", "max-index-bytes", OptionId::max_index, false, false},
    OptionSpec{"max-entries", "max-entries", OptionId::max_entries, false, false},
    OptionSpec{"max-name-bytes", "max-name-bytes", OptionId::max_name, false, false},
    OptionSpec{"max-depth", "max-depth", OptionId::max_depth, false, false},
    OptionSpec{"max-archive-bytes", "max-archive-bytes", OptionId::max_archive, false, false}};

/// 按完整名称或别名查询静态选项表，未找到时返回空指针。
const OptionSpec* find_option(std::string_view name) {
    const auto found = std::ranges::find_if(option_specs,
        [name](const auto& spec) { return spec.name == name; });
    return found == option_specs.end() ? nullptr : &*found;
}

/// 解析两个固定路径之后的选项，在读取密码前拒绝重复或不适用的参数。
void parse_file_options(bool encrypting, int argc, char** argv,
    filecrypt::app::EncryptOptions& options,
    filecrypt::compression::DecompressionLimits& decompression_limits,
    std::set<std::string_view>& seen) {
    for (int i = 4; i < argc; ++i) {
        const auto name = std::string_view(argv[i]);
        const auto* spec = find_option(name);
        if (!spec || (spec->encrypt_only && !encrypting) ||
            (spec->decrypt_only && encrypting)) {
            throw std::invalid_argument("未知或不适用于当前命令的选项：" + std::string(name));
        }
        claim_option(seen, spec->claim);
        switch (spec->id) {
        case OptionId::algorithm:
            options.algorithm = parse_algorithm(next_value(i, argc, argv));
            break;
        case OptionId::compression:
            options.compressed = name != "no-compress";
            break;
        case OptionId::memory:
            options.kdf.memory_kib = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::iterations:
            options.kdf.iterations = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::parallelism:
            options.kdf.parallelism = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::max_memory:
            options.limits.max_memory_kib = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::max_iterations:
            options.limits.max_iterations = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::max_parallelism:
            options.limits.max_parallelism = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::max_output:
            decompression_limits.max_output_bytes = parse_output_limit(next_value(i, argc, argv));
            break;
        case OptionId::max_window:
            decompression_limits.max_window_log = parse_window_log(next_value(i, argc, argv));
            break;
        case OptionId::max_index:
            options.directory_limits.max_index_bytes = parse_output_limit(next_value(i, argc, argv));
            break;
        case OptionId::max_entries:
            options.directory_limits.max_entries = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::max_name:
            options.directory_limits.max_name_bytes = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::max_depth:
            options.directory_limits.max_depth = parse_positive(next_value(i, argc, argv));
            break;
        case OptionId::max_archive:
            options.directory_limits.max_output_bytes = parse_output_limit(next_value(i, argc, argv));
            break;
        }
    }
}

/// 解析真实文件操作选项，读取安全密码并调用应用流程。
void crypt_file(bool encrypting, int argc, char** argv) {
    if (argc < 4) {
        throw std::invalid_argument("需要指定输入和输出文件");
    }
    filecrypt::app::EncryptOptions options;
    std::set<std::string_view> seen;
    filecrypt::compression::DecompressionLimits decompression_limits;
    parse_file_options(encrypting, argc, argv, options, decompression_limits, seen);
    const auto input = encrypting ? argument_path(argv[2]) : ciphertext_path(argument_path(argv[2]));
    const auto output = encrypting ? ciphertext_path(argument_path(argv[3])) : argument_path(argv[3]);
    // 显式解压输出上限也收紧目录归档上限，保留两项策略中更严格的值。
    if (!encrypting && seen.contains("max-output-bytes")) options.directory_limits.max_output_bytes =
        std::min(options.directory_limits.max_output_bytes, decompression_limits.max_output_bytes);
    auto password = filecrypt::io::read_password("密码：");
    if (password.empty()) {
        throw std::invalid_argument("密码不能为空");
    }
    if (encrypting) {
        {
            const auto confirmation = filecrypt::io::read_password("确认密码：");
            if (confirmation != password) {
                throw std::invalid_argument("两次密码不一致，未开始加密");
            }
        }
        filecrypt::app::encrypt_file(input, output, password, options);
        password.clear();
        std::println("加密完成：{}", display_filename(output));
        std::println("警告：忘记密码将无法恢复文件，FileCrypt 无法重置或绕过密码。");
    } else {
        const auto restored = filecrypt::app::decrypt_file(input, output, password,
            options.limits, decompression_limits, true, options.directory_limits);
        password.clear();
        std::println("解密完成（认证通过）：{}", display_filename(restored));
    }
}
} //namespace

/// 分派完整或简写命令并将失败转换为非零退出码。
int run_cli(int argc, char** argv) {
    try {
        if (argc == 2 && (std::string_view(argv[1]) == "help" || std::string_view(argv[1]) == "-h")) {
            print_usage();
            return 0;
        }
        if (argc < 3) {
            print_usage();
            return 1;
        }
        const std::string_view command = argv[1];
        const auto path = argument_path(argv[2]);
        if ((command == "info" || command == "-i") && argc == 3) {
            print_info(path, filecrypt::app::inspect_file(path));
        } else if (command == "sample") {
            generate_sample(path, argc, argv);
        } else if (command == "encrypt" || command == "-e" || command == "decrypt" || command == "-d") {
            crypt_file(command == "encrypt" || command == "-e", argc, argv);
        } else {
            throw std::invalid_argument("未知命令或多余参数，请使用 help 或 -h 查看用法");
        }
        return 0;
    } catch (const filecrypt::crypto::AuthenticationError&) {
        std::println(stderr, "错误：密码错误或文件已被篡改，未提交解密输出。");
        return 1;
    } catch (const std::exception& error) {
        std::println(stderr, "错误：{}", error.what());
        return 1;
    }
}

#ifdef _WIN32
/// MSVC 与 MinGW 使用原生宽字符入口，路径不依赖系统 ANSI 代码页。
int wmain(int argc, wchar_t** argv) {
    try {
        ConsoleOutputGuard console;
        std::vector<std::string> arguments;
        arguments.reserve(static_cast<std::size_t>(argc));
        for (int i = 0; i < argc; ++i) {
            arguments.push_back(argument_utf8(argv[i]));
        }
        std::vector<char*> pointers;
        pointers.reserve(arguments.size() + 1);
        for (auto& argument : arguments) {
            pointers.push_back(argument.data());
        }
        pointers.push_back(nullptr);
        return run_cli(argc, pointers.data());
    } catch (const std::exception& error) {
        std::println(stderr, "Error: {}", error.what());
        return 1;
    }
}
#else
/// 将原生窄字符参数交给统一 CLI 分发流程。
int main(int argc, char** argv) {
    return run_cli(argc, argv);
}
#endif
