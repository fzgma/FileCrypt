#include <filecrypt/app/operations.hpp>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
/// 显示文件信息读取与格式示例生成命令的用法。
void print_usage() {
    std::cout << "用法：\n"
        "  filecrypt info <文件路径>\n"
        "  filecrypt sample <文件路径> [--algorithm aes-256-gcm|xchacha20-poly1305]"
        " [--directory] [--compressed]\n"
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
        } else {
            throw std::invalid_argument("未知命令或多余参数，请使用 --help 查看用法");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "错误：" << error.what() << '\n';
        return 1;
    }
}
