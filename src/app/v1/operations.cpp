#include "operations.hpp"
#include <filecrypt/format/v1/metadata.hpp>
#include <filecrypt/format/v1/registry.hpp>
#include <filecrypt/io/file.hpp>
#include <stdexcept>

namespace filecrypt::app::v1 {
using namespace filecrypt::format::v1;

/// 解析并校验 v1 前缀，将版本内部数据转换为公开展示结果。
FileInfo inspect(std::istream& input) {
    std::array<std::byte, header_size> header_bytes{};
    io::read_exact(input, header_bytes);
    const auto header = deserialize(header_bytes);
    // 当前 Registry 仅支持 Argon2id 和零参数 Zstandard，长度由这组定义确定。
    // 在分配缓冲区前核对布局，避免信任磁盘中的任意 64 位长度。
    const auto layout = metadata_layout(header);
    if (header.metadata_length != layout.metadata_size) {
        throw std::invalid_argument("Metadata 长度不符合当前 v1 布局");
    }
    std::vector<std::byte> bytes(layout.metadata_size);
    io::read_exact(input, bytes);
    const auto metadata = deserialize_metadata(header, bytes);
    const bool has_payload = input.peek() != std::char_traits<char>::eof();
    if (input.bad()) {
        throw std::runtime_error("载荷状态读取失败");
    }
    FileInfo info{};
    info.version = header.version;
    info.algorithm = algorithm_definition(header.algorithm).name;
    info.compressed = metadata.compression.has_value();
    if (metadata.compression) {
        info.compression = compression_definition(metadata.compression->id).name;
    }
    info.directory = metadata.index_length.has_value();
    const auto extension = file_type_definition(header.file_type).extension;
    info.file_type = info.directory ? "N/A" : extension.empty() ? "Unknown" : std::string(extension);
    info.kdf = kdf_definition(metadata.kdf_id).name;
    info.has_payload = has_payload;
    info.details = {
        {"内存成本", std::to_string(metadata.kdf_parameters.memory_cost_kib) + " KiB"},
        {"迭代次数", std::to_string(metadata.kdf_parameters.time_cost)},
        {"并行度", std::to_string(metadata.kdf_parameters.parallelism)},
        {"Metadata 长度", std::to_string(header.metadata_length) + " 字节"},
        {"Nonce 长度", std::to_string(metadata.nonce.size()) + " 字节"},
        {"Tag 长度", std::to_string(metadata.tag.size()) + " 字节"}};
    if (metadata.index_length) {
        info.details.emplace_back("目录索引长度", std::to_string(*metadata.index_length) + " 字节");
    }
    return info;
}

/// 根据应用选项构造 v1 格式样本并排他创建输出文件。
void sample(const std::filesystem::path& path, const SampleOptions& options) {
    Header header;
    header.version = 1;
    if (options.algorithm == "aes-256-gcm") {
        header.algorithm = 1;
    } else if (options.algorithm == "xchacha20-poly1305") {
        header.algorithm = 2;
    } else {
        throw std::invalid_argument("Unsupported sample algorithm");
    }
    header.flags = static_cast<std::uint16_t>((options.directory ? 0x8000 : 0) |
        (options.compressed ? 0x4000 : 0));
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
}
}
