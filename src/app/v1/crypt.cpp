#include "operations.hpp"
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

/// 用固定大小安全缓冲区处理剩余输入流并写入受控临时输出。
void process_stream(std::istream& input, crypto::CipherContext& cipher, io::OutputTransaction& output) {
    crypto::SecureBytes buffer(65536);
    while (true) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (input.bad() || (input.fail() && !input.eof())) {
            throw std::runtime_error("Input file read failed");
        }
        if (count > 0) {
            const auto part = cipher.update(std::span(buffer).first(static_cast<std::size_t>(count)));
            output.write(std::as_bytes(std::span(part)));
        }
        if (input.eof()) {
            break;
        }
    }
}
}

/// 构造真实 v1 前缀并流式加密，写回 Tag 后提交输出。
void encrypt(const std::filesystem::path& path, const std::filesystem::path& destination,
    std::span<const std::uint8_t> password, const EncryptOptions& options) {
    format::Header header;
    header.version = 1;
    header.algorithm = algorithm_id(options.algorithm);
    header.file_type = 0xFFFE;
    header.metadata_length = format::metadata_layout(header).metadata_size;
    if (std::filesystem::file_size(path) > crypto::message_limit(options.algorithm)) {
        throw std::length_error("File too large for selected AEAD");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot open input file");
    }
    format::Metadata metadata;
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
    process_stream(input, cipher, output);
    const auto final = cipher.finish();
    output.write(std::as_bytes(std::span(final.output)));
    std::transform(final.tag.begin(), final.tag.end(), metadata.tag.begin(),
        [](std::uint8_t value) { return static_cast<std::byte>(value); });
    output.seek(format::header_size);
    output.write(format::serialize_metadata(header, metadata));
    input.close();
    output.commit();
}

/// 校验 v1 前缀并流式解密，整条消息认证成功才提交明文。
void decrypt(std::istream& input, const std::filesystem::path& destination,
    std::span<const std::uint8_t> password, const crypto::KdfLimits& limits) {
    std::array<std::byte, format::header_size> header_bytes{};
    io::read_exact(input, header_bytes);
    const auto header = format::deserialize(header_bytes);
    const auto layout = format::metadata_layout(header);
    if (header.flags != 0) {
        throw std::invalid_argument("File decryption currently supports only uncompressed single files");
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
    io::OutputTransaction output(destination);
    process_stream(input, cipher, output);
    const auto final = cipher.finish(crypto_bytes(metadata.tag));
    output.write(std::as_bytes(std::span(final.output)));
    output.commit();
}
}
