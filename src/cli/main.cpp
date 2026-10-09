#include <filecrypt/app/operations.hpp>
#include <filecrypt/io/password.hpp>
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
/// 显示文件信息读取与格式示例生成命令的用法。
void print_usage() {
    std::cout << "用法：\n"
        "  filecrypt info <文件路径>\n"
        "  filecrypt encrypt <输入文件> <输出.fcry> [--algorithm aes-256-gcm|xchacha20-poly1305]\n"
        "  filecrypt decrypt <输入.fcry> <输出文件>\n"
        "  filecrypt sample <文件路径> [--algorithm aes-256-gcm|xchacha20-poly1305]"
        " [--directory] [--compressed]\n"
        "加密参数：--memory-kib N --iterations N --parallelism N\n"
        "资源上限：--max-memory-kib N --max-iterations N --max-parallelism N\n"
        "密码从隐藏终端或标准输入读取；加密需要输入两次，解密一次。\n"
        "encrypt/decrypt 当前支持无压缩单文件，拒绝覆盖已有输出。\n"
        "sample 仅生成 Header 与 Metadata 格式示例，不执行加密。\n";
}

/// 将文件路径的末级文件名转换为 UTF-8 输出文本。
std::string display_filename(const std::filesystem::path& path) {
    const auto name = path.filename().u8string();
    return std::string(name.begin(), name.end());
}

/// 将不依赖协议内部类型的公开信息显示给用户。
void print_info(const std::filesystem::path& path, const filecrypt::app::FileInfo& info) {
    std::cout << "加密文件名：" << display_filename(path) << '\n'
        << "格式版本：" << info.version << '\n'
        << "加密算法：" << info.algorithm << '\n'
        << "压缩：" << (info.compressed ? "是" : "否") << '\n';
    if (info.compressed) {
        std::cout << "压缩算法：" << info.compression << '\n';
    }
    std::cout << "目录：" << (info.directory ? "是" : "否") << '\n'
        << "文件类型：" << info.file_type << '\n'
        << "密钥派生：" << info.kdf << '\n';
    for (const auto& [name, value] : info.details) {
        std::cout << name << "：" << value << '\n';
    }
    std::cout << "载荷：" << (info.has_payload ? "存在" : "空") << '\n'
        << "认证状态：" << (info.authenticated ? "已验证" : "未验证") << '\n';
}

/// 解析示例命令选项并调用 Application 生成样本。
void generate_sample(const std::filesystem::path& path, int argc, char** argv) {
    filecrypt::app::SampleOptions options;
    for (int i = 3; i < argc; ++i) {
        const std::string_view option = argv[i];
        if (option == "--directory") {
            options.directory = true;
        } else if (option == "--compressed") {
            options.compressed = true;
        } else if (option == "--algorithm" && i + 1 < argc) {
            const std::string_view algorithm = argv[++i];
            options.algorithm = algorithm;
        } else {
            throw std::invalid_argument("未知选项或缺少选项值");
        }
    }
    filecrypt::app::generate_sample(path, options);
    std::cout << "已生成格式示例：" << display_filename(path)
        << "（仅 Header 与 Metadata，未执行加密）\n";
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

/// 解析真实文件操作选项，读取安全密码并调用应用流程。
void crypt_file(bool encrypting, int argc, char** argv) {
    if (argc < 4) {
        throw std::invalid_argument("需要指定输入和输出文件");
    }
    filecrypt::app::EncryptOptions options;
    for (int i = 4; i < argc; ++i) {
        const std::string_view name = argv[i];
        if (i + 1 >= argc) {
            throw std::invalid_argument("选项缺少值");
        }
        const std::string_view value = argv[++i];
        if (encrypting && name == "--algorithm") {
            if (value == "aes-256-gcm") {
                options.algorithm = filecrypt::crypto::Algorithm::aes256_gcm;
            } else if (value == "xchacha20-poly1305") {
                options.algorithm = filecrypt::crypto::Algorithm::xchacha20_poly1305;
            } else {
                throw std::invalid_argument("不支持的算法名称");
            }
        } else if (encrypting && name == "--memory-kib") {
            options.kdf.memory_kib = parse_positive(value);
        } else if (encrypting && name == "--iterations") {
            options.kdf.iterations = parse_positive(value);
        } else if (encrypting && name == "--parallelism") {
            options.kdf.parallelism = parse_positive(value);
        } else if (name == "--max-memory-kib") {
            options.limits.max_memory_kib = parse_positive(value);
        } else if (name == "--max-iterations") {
            options.limits.max_iterations = parse_positive(value);
        } else if (name == "--max-parallelism") {
            options.limits.max_parallelism = parse_positive(value);
        } else {
            throw std::invalid_argument("未知或不适用于当前命令的选项");
        }
    }
    const std::filesystem::path input = argv[2];
    const std::filesystem::path output = argv[3];
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
        std::cout << "加密完成：" << display_filename(output) << '\n'
            << "警告：忘记密码将无法恢复文件，FileCrypt 无法重置或绕过密码。\n";
    } else {
        filecrypt::app::decrypt_file(input, output, password, options.limits);
        password.clear();
        std::cout << "解密完成（认证通过）：" << display_filename(output) << '\n';
    }
}
}

/// 分派示例生成与文件信息命令并将失败转换为非零退出码。
int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--help") {
            print_usage();
            return 0;
        }
        if (argc < 3) {
            print_usage();
            return 1;
        }
        const std::string_view command = argv[1];
        const std::filesystem::path path = argv[2];
        if (command == "info" && argc == 3) {
            print_info(path, filecrypt::app::inspect_file(path));
        } else if (command == "sample") {
            generate_sample(path, argc, argv);
        } else if (command == "encrypt" || command == "decrypt") {
            crypt_file(command == "encrypt", argc, argv);
        } else {
            throw std::invalid_argument("未知命令或多余参数，请使用 --help 查看用法");
        }
        return 0;
    } catch (const filecrypt::crypto::AuthenticationError&) {
        std::cerr << "错误：密码错误或文件已被篡改，未提交解密输出。\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "错误：" << error.what() << '\n';
        return 1;
    }
}
