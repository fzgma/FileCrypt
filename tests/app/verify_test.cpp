#include "verify_test.hpp"
#include <filecrypt/app/operations.hpp>
#include <filecrypt/format/v1/aad.hpp>
#include <filecrypt/format/v1/directory.hpp>
#include <filecrypt/io/output.hpp>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>

namespace test_verify {
namespace {
namespace app = filecrypt::app;
namespace crypto = filecrypt::crypto;
namespace format = filecrypt::format::v1;
using filecrypt::ErrorCode;
const crypto::Bytes password{'v', 'e', 'r', 'i', 'f', 'y'};
const crypto::Bytes wrong{'w', 'r', 'o', 'n', 'g'};

/// 断言失败保留稳定错误，不输出测试密码或明文。
void require(bool value) {
    if (!value) throw std::runtime_error("Verify regression failed");
}

/// 同时支持格式层和操作层的语义错误，并拒绝无分类的失败。
template<class Action> void expect_error(ErrorCode expected, Action action) {
    try { action(); }
    catch (const filecrypt::FormatError& error) { require(error.code() == expected); return; }
    catch (const filecrypt::OperationError& error) { require(error.code() == expected); return; }
    throw std::runtime_error("Verification unexpectedly succeeded");
}

/// 读取测试文件字节，用于检查验证前后输入保持不变。
std::vector<char> read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

/// 写入受控测试字节，可构造截断或篡改的密文。
void write(const std::filesystem::path& path, const std::vector<char>& bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    require(static_cast<bool>(output));
}

/// 构造认证正确、内部载荷可非法的样本，避免只覆盖认证失败路径。
void seal(const std::filesystem::path& path, std::span<const std::byte> payload,
    bool compressed, std::optional<std::uint64_t> index_length = {}) {
    format::Header header;
    header.version = 1;
    header.algorithm = 1;
    header.file_type = index_length ? 0 : 0xFFFE;
    header.flags = (compressed ? 0x4000 : 0) | (index_length ? 0x8000 : 0);
    header.metadata_length = format::metadata_layout(header).metadata_size;
    format::Metadata metadata;
    metadata.kdf_parameters.memory_cost_kib = 8192;
    metadata.kdf_parameters.time_cost = 1;
    metadata.kdf_parameters.parallelism = 1;
    metadata.nonce.resize(12);
    metadata.index_length = index_length;
    if (compressed) metadata.compression = format::CompressionMetadata{};
    const auto aad = format::build_aad(header, metadata);
    const auto key = crypto::derive_key(password,
        {reinterpret_cast<const std::uint8_t*>(metadata.salt.data()), metadata.salt.size()},
        {8192, 1, 1}, {8192, 1, 1}, 32);
    const auto encrypted = crypto::encrypt(crypto::Algorithm::aes256_gcm, key,
        {reinterpret_cast<const std::uint8_t*>(metadata.nonce.data()), metadata.nonce.size()},
        {reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size()},
        {reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size()});
    std::transform(encrypted.tag.begin(), encrypted.tag.end(), metadata.tag.begin(),
        [](auto value) { return static_cast<std::byte>(value); });
    filecrypt::io::OutputTransaction output(path);
    output.write(format::serialize(header));
    output.write(format::serialize_metadata(header, metadata));
    output.write(std::as_bytes(std::span(encrypted.ciphertext)));
    output.commit();
}
}

/// 覆盖文件、目录、压缩组合和认证之后才可发现的结构错误。
void run(const std::filesystem::path& root) {
    const auto directory = root / "verify";
    std::filesystem::create_directory(directory);
    const auto source = directory / "source";
    std::filesystem::create_directory(source);
    write(source / "data", std::vector<char>(70001, 'x'));
    write(source / "empty", {});
    std::filesystem::create_directory(source / "empty-directory");
    unsigned id{};
    for (const auto algorithm : {crypto::Algorithm::aes256_gcm, crypto::Algorithm::xchacha20_poly1305}) {
        for (const bool compressed : {false, true}) {
            for (const auto& input : {source / "data", source}) {
                app::EncryptOptions options;
                options.algorithm = algorithm;
                options.compressed = compressed;
                options.kdf = {8192, 1, 1};
                const auto encrypted = directory / (std::to_string(id++) + ".fcry");
                app::encrypt_file(input, encrypted, password, options);
                const auto before = read(encrypted);
                app::verify_file(encrypted, password);
                require(read(encrypted) == before);
                expect_error(ErrorCode::authentication_failed, [&] { app::verify_file(encrypted, wrong); });
                expect_error(ErrorCode::resource_limit, [&] { app::verify_file(encrypted, password, {4096, 1, 1}); });
                if (compressed) expect_error(ErrorCode::resource_limit, [&] {
                    app::verify_file(encrypted, password, {8192, 1, 1}, {1, 26});
                });
                if (input == source) expect_error(ErrorCode::resource_limit, [&] {
                    filecrypt::directory::Limits limits;
                    limits.max_entries = 1;
                    app::verify_file(encrypted, password, {8192, 1, 1}, {}, limits);
                });
            }
        }
    }
    const auto corrupted = directory / "corrupted.fcry";
    auto bytes = read(directory / "0.fcry");
    bytes.back() ^= 1;
    write(corrupted, bytes);
    expect_error(ErrorCode::authentication_failed, [&] { app::verify_file(corrupted, password); });
    bytes.pop_back();
    write(corrupted, bytes);
    expect_error(ErrorCode::authentication_failed, [&] { app::verify_file(corrupted, password); });
    write(corrupted, {'F'});
    expect_error(ErrorCode::invalid_format, [&] { app::verify_file(corrupted, password); });

    seal(directory / "empty.fcry", {}, false);
    app::verify_file(directory / "empty.fcry", password);
    const std::array invalid{std::byte{1}, std::byte{2}};
    seal(directory / "bad-zstd.fcry", invalid, true);
    expect_error(ErrorCode::invalid_format, [&] { app::verify_file(directory / "bad-zstd.fcry", password); });
    expect_error(ErrorCode::authentication_failed, [&] { app::verify_file(directory / "bad-zstd.fcry", wrong); });

    // 冒号名称在协议中合法；verify 不应套用 Windows 恢复名称限制。
    std::vector<format::DirectoryEntry> entries{{0, 0xFFFFFFFF, format::EntryType::directory, 0, 0, "root"},
        {1, 0, format::EntryType::file, 0, 0, "a:b"}};
    auto index = format::serialize_index(entries);
    seal(directory / "portable.fcry", index, false, index.size());
    app::verify_file(directory / "portable.fcry", password);
    // 修改名称为路径分隔符后重新认证，应在索引校验阶段拒绝。
    index.back() = std::byte{'/'};
    seal(directory / "bad-index.fcry", index, false, index.size());
    expect_error(ErrorCode::invalid_format, [&] { app::verify_file(directory / "bad-index.fcry", password); });
    seal(directory / "short-index.fcry", invalid, false, 100);
    expect_error(ErrorCode::invalid_format, [&] { app::verify_file(directory / "short-index.fcry", password); });

    // 临时文件支持读写和定位，但没有发布到目标路径的能力。
    const auto temporary = filecrypt::io::OutputTransaction::create_temporary();
    temporary->write(invalid);
    require(temporary->size() == invalid.size());
    temporary->seek(0);
    std::array<std::byte, 2> restored{};
    require(temporary->read(restored) == restored.size() && restored == invalid);
    bool rejected{};
    try { temporary->commit(); } catch (const std::logic_error&) { rejected = true; }
    require(rejected);
}
}
