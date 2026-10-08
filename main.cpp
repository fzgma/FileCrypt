#include <filecrypt/format/metadata.hpp>
#include <filecrypt/format/registry.hpp>
#include <filecrypt/io/file.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
using namespace filecrypt::format;

/// 显示文件信息读取与格式示例生成命令的用法。
void print_usage() {
    std::cout << "用法：\n"
        "  filecrypt info <文件路径>\n"
        "  filecrypt sample <文件路径> [--algorithm aes-256-gcm|xchacha20-poly1305]"
        " [--directory] [--compressed]\n"
        "sample 仅生成 Header 与 Metadata 格式示例，不执行加密。\n";
}

/// 从文件读取指定数量的字节并拒绝截断输入。
void read_exact(std::istream& input, std::span<std::byte> bytes) {
    // 字节缓冲区可作为字符流读写，不映射任何 C++ 结构体布局。
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input) {
        throw std::runtime_error("文件内容截断或读取失败");
    }
}

/// 将文件路径的末级文件名转换为 UTF-8 输出文本。
std::string display_filename(const std::filesystem::path& path) {
    const auto name = path.filename().u8string();
    return std::string(name.begin(), name.end());
}

/// 读取并校验 Header 与 Metadata 后显示文件的公开格式信息。
void inspect_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("无法打开输入文件");
    }
    std::array<std::byte, header_size> header_bytes{};
    read_exact(input, header_bytes);
    const auto header = deserialize(header_bytes);
    // 当前 Registry 仅支持 Argon2id 和零参数 Zstandard，长度由这组定义确定。
    // 在分配缓冲区前核对布局，避免信任磁盘中的任意 64 位长度。
    const auto layout = metadata_layout(header);
    if (header.metadata_length != layout.metadata_size) {
        throw std::invalid_argument("Metadata 长度不符合当前 v1 布局");
    }
    std::vector<std::byte> bytes(layout.metadata_size);
    read_exact(input, bytes);
    const auto metadata = deserialize_metadata(header, bytes);
    const bool has_payload = input.peek() != std::char_traits<char>::eof();
    if (input.bad()) {
        throw std::runtime_error("载荷状态读取失败");
    }
    std::cout << "加密文件名：" << display_filename(path) << '\n'
        << "格式版本：" << header.version << '\n'
        << "加密算法：" << algorithm_definition(header.algorithm).name << '\n'
        << "压缩：" << (metadata.compression ? "是" : "否") << '\n';
    if (metadata.compression) {
        std::cout << "压缩算法：" << compression_definition(metadata.compression->id).name << '\n';
    }
    std::cout << "目录：" << (metadata.index_length ? "是" : "否") << '\n'
        << "文件类型：" << (metadata.index_length ? "N/A" : "Unknown") << '\n'
        << "密钥派生：" << kdf_definition(metadata.kdf_id).name << '\n'
        << "内存成本：" << metadata.kdf_parameters.memory_cost_kib << " KiB\n"
        << "迭代次数：" << metadata.kdf_parameters.time_cost << '\n'
        << "并行度：" << metadata.kdf_parameters.parallelism << '\n'
        << "Metadata 长度：" << header.metadata_length << " 字节\n"
        << "Nonce 长度：" << metadata.nonce.size() << " 字节\n"
        << "Tag 长度：" << metadata.tag.size() << " 字节\n";
    if (metadata.index_length) {
        std::cout << "目录索引长度：" << *metadata.index_length << " 字节\n";
    }
    std::cout << "载荷：" << (has_payload ? "存在" : "空") << '\n'
        << "认证状态：未验证\n";
}

/// 按命令选项生成仅包含合法 Header 与 Metadata 的固定格式样本。
void generate_sample(const std::filesystem::path& path, int argc, char** argv) {
    Header header;
    header.version = 1;
    header.algorithm = 1;
    for (int i = 3; i < argc; ++i) {
        const std::string_view option = argv[i];
        if (option == "--directory") {
            header.flags |= 0x8000;
        } else if (option == "--compressed") {
            header.flags |= 0x4000;
        } else if (option == "--algorithm" && i + 1 < argc) {
            const std::string_view algorithm = argv[++i];
            if (algorithm == "aes-256-gcm") {
                header.algorithm = 1;
            } else if (algorithm == "xchacha20-poly1305") {
                header.algorithm = 2;
            } else {
                throw std::invalid_argument("不支持的算法名称");
            }
        } else {
            throw std::invalid_argument("未知选项或缺少选项值");
        }
    }
    Metadata metadata;
    if ((header.flags & 0x8000) != 0) {
        metadata.index_length = 0;
        header.file_type = 0;
    } else {
        header.file_type = 0xFFFE;
    }
    if ((header.flags & 0x4000) != 0) {
        metadata.compression = CompressionMetadata{};
    }
    // 固定的非敏感格式样本，不是生产 KDF 默认值；Salt、Nonce、Tag 均为占位字节。
    metadata.kdf_parameters.memory_cost_kib = 8192;
    metadata.kdf_parameters.time_cost = 1;
    metadata.kdf_parameters.parallelism = 1;
    metadata.nonce.resize(algorithm_definition(header.algorithm).nonce_size);
    header.metadata_length = metadata_layout(header).metadata_size;
    const auto header_bytes = serialize(header);
    const auto metadata_bytes = serialize_metadata(header, metadata);
    std::vector<std::byte> file_bytes(header_bytes.begin(), header_bytes.end());
    file_bytes.insert(file_bytes.end(), metadata_bytes.begin(), metadata_bytes.end());
    filecrypt::io::write_new_file(path, file_bytes);
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
            inspect_file(path);
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
