#include "rekey_test.hpp"
#include <filecrypt/app/operations.hpp>
#include <filecrypt/format/v1/aad.hpp>
#include <filecrypt/format/v1/directory.hpp>
#include <filecrypt/io/output.hpp>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>

namespace test_rekey {
namespace {
namespace app = filecrypt::app;
namespace crypto = filecrypt::crypto;
namespace format = filecrypt::format::v1;
using filecrypt::ErrorCode;
const crypto::Bytes old_password{'o', 'l', 'd', 0, ' '};
const crypto::Bytes new_password{'n', 'e', 'w', 0, ' '};
const crypto::Bytes wrong_password{'w', 'r', 'o', 'n', 'g'};

/// 每项断言提供稳定诊断，不泄漏密码或载荷内容。
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

/// 读取测试字节，用于独立比较换密前后的协议及内容。
crypto::Bytes read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(static_cast<bool>(input), "Cannot read rekey fixture");
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

/// 写入非敏感测试样本，包括经过受控篡改的密文。
void write(const std::filesystem::path& path, std::span<const std::uint8_t> bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    require(static_cast<bool>(output), "Cannot write rekey fixture");
}

/// 将协议字节视图交给密码接口，不复制公开参数。
std::span<const std::uint8_t> as_u8(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()};
}

struct Opened {
    format::Header header;
    format::Metadata metadata;
    crypto::SecureBytes payload;
};

/// 独立解开已知合法样本，比较原始压缩或归档载荷，避免往返掩盖重新编码。
Opened open(const std::filesystem::path& path, std::span<const std::uint8_t> password) {
    const auto bytes = read(path);
    const auto raw = std::as_bytes(std::span(bytes));
    const auto header = format::deserialize(raw);
    const auto metadata = format::deserialize_metadata(header,
        raw.subspan(format::header_size, static_cast<std::size_t>(header.metadata_length)));
    const auto aad = format::build_aad(header, metadata);
    const auto key = crypto::derive_key(password, as_u8(metadata.salt),
        {metadata.kdf_parameters.memory_cost_kib, metadata.kdf_parameters.time_cost,
            metadata.kdf_parameters.parallelism}, {8192, 1, 1}, 32);
    auto payload = crypto::decrypt(header.algorithm == 1 ? crypto::Algorithm::aes256_gcm :
        crypto::Algorithm::xchacha20_poly1305, key, as_u8(metadata.nonce), as_u8(aad),
        std::span(bytes).subspan(format::header_size + static_cast<std::size_t>(header.metadata_length)),
        as_u8(metadata.tag));
    return {header, metadata, std::move(payload)};
}

/// 只允许随机参数与认证标签变化，压缩字节、索引及 KDF 均须保留。
void require_preserved(const Opened& before, const Opened& after) {
    require(before.header == after.header, "Rekey changed header fields");
    require(before.metadata.salt != after.metadata.salt, "Rekey reused salt");
    require(before.metadata.nonce != after.metadata.nonce, "Rekey reused nonce");
    auto metadata = before.metadata;
    metadata.salt = after.metadata.salt;
    metadata.nonce = after.metadata.nonce;
    metadata.tag = after.metadata.tag;
    require(metadata == after.metadata, "Rekey changed preserved metadata");
    require(before.payload == after.payload, "Rekey changed compressed or directory payload");
}

/// 无论操作成功或失败，都不能遗留旁路临时文件。
void require_clean(const std::filesystem::path& directory) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
        require(!entry.path().filename().u8string().starts_with(u8".filecrypt-"),
            "Rekey left a temporary file");
    }
}

/// 同时检查分类失败、输入保留和已有目标保留。
void expect_failure(const std::filesystem::path& input, const std::filesystem::path& output,
    ErrorCode expected, const app::RekeyOptions& options = {},
    std::span<const std::uint8_t> password = old_password,
    std::span<const std::uint8_t> replacement_password = new_password) {
    const auto before = read(input);
    const auto existed = std::filesystem::exists(output);
    const auto target = existed ? read(output) : crypto::Bytes{};
    bool rejected{};
    try { app::rekey_file(input, output, password, replacement_password, options); }
    catch (const filecrypt::FormatError& error) {
        require(error.code() == expected, "Rekey returned wrong format error");
        rejected = true;
    } catch (const filecrypt::OperationError& error) {
        require(error.code() == expected, "Rekey returned wrong operation error");
        rejected = true;
    }
    require(rejected, "Invalid rekey unexpectedly succeeded");
    require(read(input) == before, "Failed rekey changed input");
    require(std::filesystem::exists(output) == existed, "Failed rekey published output");
    if (existed) require(read(output) == target, "Failed rekey changed existing output");
    require_clean(input.parent_path());
}

/// 认证有效的载荷也可能不符合压缩或目录协议，单独构造以覆盖第二阶段。
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
    const auto key = crypto::derive_key(old_password, as_u8(metadata.salt), {8192, 1, 1}, {8192, 1, 1}, 32);
    const auto encrypted = crypto::encrypt(crypto::Algorithm::aes256_gcm, key,
        as_u8(metadata.nonce), as_u8(aad), as_u8(payload));
    std::transform(encrypted.tag.begin(), encrypted.tag.end(), metadata.tag.begin(),
        [](auto value) { return static_cast<std::byte>(value); });
    filecrypt::io::OutputTransaction output(path);
    output.write(format::serialize(header));
    output.write(format::serialize_metadata(header, metadata));
    output.write(std::as_bytes(std::span(encrypted.ciphertext)));
    output.commit();
}

/// 将目录样本压缩，检查同一结构错误在压缩路径中也会被拒绝。
std::vector<std::byte> compress(std::span<const std::byte> source) {
    std::vector<std::byte> output;
    std::size_t position{};
    filecrypt::compression::compress([&](std::span<std::byte> buffer) {
        const auto count = std::min(buffer.size(), source.size() - position);
        std::copy_n(source.begin() + position, count, buffer.begin());
        position += count;
        return count;
    }, [&](std::span<const std::byte> block) { output.insert(output.end(), block.begin(), block.end()); });
    return output;
}

/// 两种算法与压缩、目录组合都应保留载荷，且只有新密码能解密新文件。
void roundtrip_tests(const std::filesystem::path& directory) {
    const auto source = directory / "source";
    std::filesystem::create_directory(source);
    crypto::Bytes content(131073);
    for (std::size_t i = 0; i < content.size(); ++i) content[i] = static_cast<std::uint8_t>(i * 31 + i / 17);
    write(source / "data", content);
    write(source / "empty", {});
    std::filesystem::create_directory(source / "empty-directory");
    unsigned id{};
    for (const auto algorithm : {crypto::Algorithm::aes256_gcm, crypto::Algorithm::xchacha20_poly1305}) {
        for (const bool compressed : {false, true}) {
            for (const bool is_directory : {false, true}) {
                app::EncryptOptions options;
                options.algorithm = algorithm;
                options.compressed = compressed;
                options.kdf = {8192, 1, 1};
                const auto name = std::to_string(id++);
                const auto input = directory / (name + ".fcry");
                const auto output = directory / (name + "-new.fcry");
                const auto restored = directory / (name + "-restored");
                app::encrypt_file(is_directory ? source : source / "data", input, old_password, options);
                const auto before = read(input);
                app::rekey_file(input, output, old_password, new_password);
                require(read(input) == before, "Rekey modified source ciphertext");
                require_preserved(open(input, old_password), open(output, new_password));
                app::decrypt_file(output, restored, new_password);
                if (is_directory) {
                    require(read(restored / "data") == content && read(restored / "empty").empty() &&
                        std::filesystem::is_directory(restored / "empty-directory"), "Rekey directory roundtrip failed");
                } else {
                    require(read(restored) == content, "Rekey file roundtrip failed");
                }
                bool rejected{};
                try { app::verify_file(output, old_password); }
                catch (const filecrypt::OperationError& error) {
                    require(error.code() == ErrorCode::authentication_failed, "Old password returned wrong error");
                    rejected = true;
                }
                require(rejected, "Old password opened rekeyed ciphertext");
                // 显式替换沿用相同检查，但只能在成功时修改输入路径。
                app::RekeyOptions replacement;
                replacement.replace = true;
                app::rekey_file(output, output, new_password, old_password, replacement);
                require_preserved(open(input, old_password), open(output, old_password));
                require_clean(directory);
            }
        }
    }
    // 空载荷及处理块边界不能丢失 CipherContext::finish 返回的尾部。
    for (const auto algorithm : {crypto::Algorithm::aes256_gcm, crypto::Algorithm::xchacha20_poly1305}) {
        for (const std::size_t size : {0u, 65535u, 65536u, 65537u}) {
            const auto input = directory / (std::to_string(id++) + ".fcry");
            const auto output = directory / (std::to_string(id++) + ".fcry");
            write(source / "boundary", crypto::Bytes(size, 42));
            app::EncryptOptions options;
            options.algorithm = algorithm;
            options.kdf = {8192, 1, 1};
            app::encrypt_file(source / "boundary", input, old_password, options);
            // 同密码换密也要更新公开随机参数，不擅自拒绝合法操作。
            app::rekey_file(input, output, old_password, old_password);
            require_preserved(open(input, old_password), open(output, old_password));
        }
    }
}

/// 认证、资源和目标冲突失败均须保护原密文并撤销临时输出。
void failure_tests(const std::filesystem::path& directory) {
    const auto input = directory / "0.fcry";
    const auto output = directory / "rejected.fcry";
    expect_failure(input, output, ErrorCode::authentication_failed, {}, wrong_password);
    expect_failure(input, output, ErrorCode::invalid_argument, {}, {});
    expect_failure(input, output, ErrorCode::invalid_argument, {}, old_password, {});
    expect_failure(input, input, ErrorCode::output_conflict);
    write(output, crypto::Bytes{7, 8, 9});
    expect_failure(input, output, ErrorCode::output_conflict);
    std::filesystem::remove(output);
    app::RekeyOptions options;
    options.limits.max_memory_kib = 4096;
    expect_failure(input, output, ErrorCode::resource_limit, options);
    options = {};
    options.replace = true;
    expect_failure(input, output, ErrorCode::invalid_argument, options);
    expect_failure(input, input, ErrorCode::authentication_failed, options, wrong_password);
    options = {};
    options.decompression_limits.max_output_bytes = 1;
    expect_failure(directory / "2.fcry", output, ErrorCode::resource_limit, options);
    options = {};
    options.decompression_limits.max_window_log = 10;
    expect_failure(directory / "2.fcry", output, ErrorCode::resource_limit, options);
    for (const auto name : {"1.fcry", "3.fcry"}) {
        options = {};
        options.directory_limits.max_entries = 1;
        expect_failure(directory / name, output, ErrorCode::resource_limit, options);
        options = {};
        options.directory_limits.max_index_bytes = 1;
        expect_failure(directory / name, output, ErrorCode::resource_limit, options);
        options = {};
        options.directory_limits.max_output_bytes = 1;
        expect_failure(directory / name, output, ErrorCode::resource_limit, options);
    }
    const auto corrupted = directory / "corrupted.fcry";
    auto bytes = read(input);
    bytes.back() ^= 1;
    write(corrupted, bytes);
    expect_failure(corrupted, output, ErrorCode::authentication_failed);
    options = {};
    options.replace = true;
    expect_failure(corrupted, corrupted, ErrorCode::authentication_failed, options);
    bytes = read(input);
    bytes.pop_back();
    write(corrupted, bytes);
    expect_failure(corrupted, output, ErrorCode::authentication_failed);
    bytes = read(input);
    bytes.push_back(0);
    write(corrupted, bytes);
    expect_failure(corrupted, output, ErrorCode::authentication_failed);
    write(corrupted, crypto::Bytes{'F'});
    expect_failure(corrupted, output, ErrorCode::invalid_format);
    // 文件系统支持别名时，另存拒绝已有别名，替换只接受同一个规范化路径。
    const auto alias = directory / "hardlink.fcry";
    std::error_code error;
    std::filesystem::create_hard_link(input, alias, error);
    if (!error) {
        expect_failure(input, alias, ErrorCode::output_conflict);
        expect_failure(input, alias, ErrorCode::invalid_argument, options);
        const auto old_ciphertext = read(alias);
        app::rekey_file(input, input, old_password, new_password, options);
        require(read(alias) == old_ciphertext, "Replacement changed historical hardlink ciphertext");
        require_preserved(open(alias, old_password), open(input, new_password));
        std::filesystem::remove(alias);
    }
    std::filesystem::create_symlink(input.filename(), alias, error);
    if (!error) {
        expect_failure(input, alias, ErrorCode::output_conflict);
        expect_failure(alias, output, ErrorCode::invalid_argument);
        std::filesystem::remove(alias);
    }
}

/// 有效认证不能掩盖非法压缩、路径或数据范围，替换模式也必须拒绝。
void payload_tests(const std::filesystem::path& directory) {
    const auto output = directory / "invalid-new.fcry";
    const auto invalid = directory / "bad-zstd.fcry";
    const std::array junk{std::byte{1}, std::byte{2}};
    seal(invalid, junk, true);
    expect_failure(invalid, output, ErrorCode::invalid_format);
    expect_failure(invalid, output, ErrorCode::authentication_failed, {}, wrong_password);
    app::RekeyOptions replacement;
    replacement.replace = true;
    expect_failure(invalid, invalid, ErrorCode::invalid_format, replacement);
    std::vector<format::DirectoryEntry> entries{{0, 0xFFFFFFFF, format::EntryType::directory, 0, 0, "root"},
        {1, 0, format::EntryType::file, 0, 0, "a:b"}};
    auto index = format::serialize_index(entries);
    const auto portable = directory / "portable.fcry";
    seal(portable, index, false, index.size());
    app::rekey_file(portable, output, old_password, new_password);
    require_preserved(open(portable, old_password), open(output, new_password));
    std::filesystem::remove(output);
    // 协议合法名称不受本机恢复规则限制；路径分隔符则在所有平台拒绝。
    index.back() = std::byte{'/'};
    for (const bool compressed : {false, true}) {
        const auto input = directory / (compressed ? "bad-index-zstd.fcry" : "bad-index.fcry");
        const auto payload = compressed ? compress(index) : index;
        seal(input, payload, compressed, index.size());
        expect_failure(input, output, ErrorCode::invalid_format);
        expect_failure(input, input, ErrorCode::invalid_format, replacement);
    }
    const auto short_index = directory / "short-index.fcry";
    seal(short_index, junk, false, 100);
    expect_failure(short_index, output, ErrorCode::invalid_format);
    // 索引声明文件有一个字节，实际数据区为空，需等到完整读取后才能发现。
    entries.back().data_length = 1;
    index = format::serialize_index(entries);
    const auto missing_data = directory / "missing-data.fcry";
    seal(missing_data, index, false, index.size());
    expect_failure(missing_data, output, ErrorCode::invalid_format);
    const auto empty_zstd = directory / "empty-zstd.fcry";
    const auto empty_frame = compress({});
    seal(empty_zstd, empty_frame, true);
    app::rekey_file(empty_zstd, output, old_password, new_password);
    require_preserved(open(empty_zstd, old_password), open(output, new_password));
    std::filesystem::remove(output);
    // 大索引跨越处理块边界；无文件数据仍须累计并完整解析索引。
    entries.resize(1);
    for (std::uint32_t id = 1; id <= 2300; ++id) {
        entries.push_back({id, 0, format::EntryType::file, 0, 0, "entry-" + std::to_string(id)});
    }
    index = format::serialize_index(entries);
    require(index.size() > 65536, "Large index fixture did not cross a block boundary");
    for (const bool compressed : {false, true}) {
        const auto input = directory / (compressed ? "large-index-zstd.fcry" : "large-index.fcry");
        const auto payload = compressed ? compress(index) : index;
        seal(input, payload, compressed, index.size());
        app::rekey_file(input, output, old_password, new_password);
        require_preserved(open(input, old_password), open(output, new_password));
        std::filesystem::remove(output);
    }
    require_clean(directory);
}
}

/// 使用低成本测试 KDF 覆盖完整换密流程，保持 CLI 测试规模可控。
void run(const std::filesystem::path& root) {
    const auto directory = root / "rekey";
    std::filesystem::create_directory(directory);
    roundtrip_tests(directory);
    failure_tests(directory);
    payload_tests(directory);
    require_clean(directory);
}
}
