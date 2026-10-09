#include "operations.hpp"
#include "file_type.hpp"
#include <filecrypt/format/v1/aad.hpp>
#include <filecrypt/format/v1/registry.hpp>
#include <filecrypt/io/file.hpp>
#include <filecrypt/io/output.hpp>
#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace filecrypt::app::v1 {
namespace {
namespace format = filecrypt::format::v1;
constexpr std::uint16_t compressed_flag = 0x4000;
constexpr std::uint16_t directory_flag = 0x8000;

/// 将已支持的 v1 协议编号转换为独立 Crypto 算法枚举。
crypto::Algorithm cipher_algorithm(std::uint16_t id) {
    switch (id) {
    case 1: return crypto::Algorithm::aes256_gcm;
    case 2: return crypto::Algorithm::xchacha20_poly1305;
    default: throw std::invalid_argument("Unsupported v1 algorithm");
    }
}

/// 将 Crypto 操作算法转换为明确的 v1 协议编号。
std::uint16_t algorithm_id(crypto::Algorithm algorithm) {
    switch (algorithm) {
    case crypto::Algorithm::aes256_gcm: return 1;
    case crypto::Algorithm::xchacha20_poly1305: return 2;
    default: throw std::invalid_argument("Unsupported cipher algorithm");
    }
}

/// 显式转换公开协议字节到 Crypto 字节类型。
crypto::Bytes crypto_bytes(std::span<const std::byte> bytes) {
    crypto::Bytes result;
    result.reserve(bytes.size());
    for (const auto value : bytes) {
        result.push_back(std::to_integer<std::uint8_t>(value));
    }
    return result;
}

/// 读取有界输入块，区分正常文件末尾和读取错误。
std::size_t read_stream(std::istream& input, std::span<std::byte> bytes) {
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (input.bad() || (input.fail() && !input.eof())) {
        throw std::runtime_error("Input file read failed");
    }
    return static_cast<std::size_t>(input.gcount());
}

/// 将一个输入块交给密码层并写入受控临时输出。
void write_cipher(crypto::CipherContext& cipher, io::OutputTransaction& output,
    std::span<const std::byte> bytes) {
    const auto part = cipher.update({reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()});
    output.write(std::as_bytes(std::span(part)));
}

/// 用固定大小安全缓冲区处理剩余输入流并写入受控临时输出。
void process_stream(std::istream& input, crypto::CipherContext& cipher, io::OutputTransaction& output) {
    crypto::SecureBytes buffer(65536);
    while (const auto count = read_stream(input, std::as_writable_bytes(std::span(buffer)))) {
        write_cipher(cipher, output, std::as_bytes(std::span(buffer).first(count)));
    }
}
}

/// 构造真实 v1 前缀并流式加密，写回 Tag 后提交输出。
void encrypt(const std::filesystem::path& path, const std::filesystem::path& destination,
    std::span<const std::uint8_t> password, const EncryptOptions& options) {
    format::Header header;
    header.version = 1;
    header.algorithm = algorithm_id(options.algorithm);
    header.flags = options.compressed ? compressed_flag : 0;
    // AEAD 限制计数压缩后的字节，不能用原始大小提前拒绝可压缩输入。
    if (!options.compressed && std::filesystem::file_size(path) > crypto::message_limit(options.algorithm)) {
        throw std::length_error("File too large for selected AEAD");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot open input file");
    }
    header.file_type = detect_file_type(path, input);
    header.metadata_length = format::metadata_layout(header).metadata_size;
    format::Metadata metadata;
    if (options.compressed) {
        metadata.compression = format::CompressionMetadata{};
    }
    metadata.kdf_parameters.memory_cost_kib = options.kdf.memory_kib;
    metadata.kdf_parameters.time_cost = options.kdf.iterations;
    metadata.kdf_parameters.parallelism = options.kdf.parallelism;
    const auto salt = crypto::random_bytes(metadata.salt.size());
    std::transform(salt.begin(), salt.end(), metadata.salt.begin(),
        [](std::uint8_t value) { return static_cast<std::byte>(value); });
    const auto nonce = crypto::random_bytes(crypto::nonce_size(options.algorithm));
    for (const auto value : nonce) {
        metadata.nonce.push_back(static_cast<std::byte>(value));
    }
    const auto aad = crypto_bytes(format::build_aad(header, metadata));
    const auto key = crypto::derive_key(password, salt, options.kdf, options.limits,
        format::algorithm_definition(header.algorithm).key_size);
    crypto::CipherContext cipher(options.algorithm, crypto::Direction::encrypt, key, nonce, aad);
    io::OutputTransaction output(destination);
    output.write(format::serialize(header));
    output.write(format::serialize_metadata(header, metadata));
    if (options.compressed) {
        compression::compress(
            [&](std::span<std::byte> bytes) { return read_stream(input, bytes); },
            [&](std::span<const std::byte> bytes) { write_cipher(cipher, output, bytes); });
    } else {
        process_stream(input, cipher, output);
    }
    const auto final = cipher.finish();
    output.write(std::as_bytes(std::span(final.output)));
    std::transform(final.tag.begin(), final.tag.end(), metadata.tag.begin(),
        [](std::uint8_t value) { return static_cast<std::byte>(value); });
    output.seek(format::header_size);
    output.write(format::serialize_metadata(header, metadata));
    input.close();
    output.commit();
}

/// 校验 v1 前缀并认证完整消息，按需解压后才提交明文。
std::filesystem::path decrypt(std::istream& input, const std::filesystem::path& destination,
    std::span<const std::uint8_t> password, const crypto::KdfLimits& limits,
    const compression::DecompressionLimits& decompression_limits, bool restore_extension) {
    std::array<std::byte, format::header_size> header_bytes{};
    io::read_exact(input, header_bytes);
    const auto header = format::deserialize(header_bytes);
    const auto layout = format::metadata_layout(header);
    const auto resolved_destination = restore_extension
        ? restore_file_extension(destination, header.file_type) : destination;
    if ((header.flags & directory_flag) != 0) {
        throw std::invalid_argument("File decryption currently supports only single files");
    }
    if (header.metadata_length != layout.metadata_size) {
        throw std::invalid_argument("Invalid v1 Metadata length");
    }
    std::vector<std::byte> metadata_bytes(layout.metadata_size);
    io::read_exact(input, metadata_bytes);
    const auto metadata = format::deserialize_metadata(header, metadata_bytes);
    const auto aad = crypto_bytes(format::build_aad(header_bytes, metadata_bytes));
    const auto algorithm = cipher_algorithm(header.algorithm);
    const auto& p = metadata.kdf_parameters;
    const auto key = crypto::derive_key(password, crypto_bytes(metadata.salt),
        {p.memory_cost_kib, p.time_cost, p.parallelism}, limits,
        format::algorithm_definition(header.algorithm).key_size);
    crypto::CipherContext cipher(algorithm, crypto::Direction::decrypt, key,
        crypto_bytes(metadata.nonce), aad);
    io::OutputTransaction output(resolved_destination);
    process_stream(input, cipher, output);
    const auto final = cipher.finish(crypto_bytes(metadata.tag));
    output.write(std::as_bytes(std::span(final.output)));
    if ((header.flags & compressed_flag) != 0) {
        // 只有 finish 验证通过，压缩载荷才允许进入解压器；中间事务始终不发布。
        output.seek(0);
        io::OutputTransaction restored(resolved_destination);
        compression::decompress(
            [&](std::span<std::byte> bytes) { return output.read(bytes); },
            [&](std::span<const std::byte> bytes) { restored.write(bytes); }, decompression_limits);
        restored.commit();
    } else {
        output.commit();
    }
    return resolved_destination;
}
}
