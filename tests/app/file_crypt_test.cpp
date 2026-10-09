#include <filecrypt/app/operations.hpp>
#include <filecrypt/io/file.hpp>
#include <filecrypt/io/output.hpp>
#include <filecrypt/format/v1/aad.hpp>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace {
using namespace filecrypt;

/// 条件不满足时报告端到端测试失败。
void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

/// 验证失败操作不会被误判为成功。
template <typename Function>
void rejects(Function action) {
    try {
        action();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("Expected file operation failure");
}

/// 替换测试专有路径中的字节样本。
void write_file(const std::filesystem::path& path, const crypto::Bytes& bytes) {
    std::filesystem::remove(path);
    io::write_new_file(path, std::as_bytes(std::span(bytes)));
}

/// 读取测试文件用于独立字节比较。
crypto::Bytes read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    check(static_cast<bool>(input), "Cannot read test file");
    return crypto::Bytes(std::istreambuf_iterator<char>(input), {});
}

/// 检查所有失败路径均未遗留本轮临时输出。
void check_no_temporary(const std::filesystem::path& directory) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        check(!entry.path().filename().string().starts_with(".filecrypt-"), "Temporary output leaked");
    }
}

/// 验证真实文件往返、篡改拒绝、KDF 上限和输出保护。
void file_tests(const std::filesystem::path& directory) {
    const auto source = directory / "plain.bin";
    const auto encrypted = directory / "encrypted.fcry";
    const auto restored = directory / "restored.bin";
    const auto corrupted = directory / "corrupted.fcry";
    const crypto::SecureBytes password{'p', 0, 0xE4, 0xB8, 0xAD, ' '};
    auto wrong_password = password;
    wrong_password[0] ^= 1;
    app::EncryptOptions options;
    options.kdf = {8192, 1, 1};
    options.limits = {16384, 4, 4};
    for (const auto algorithm : {crypto::Algorithm::aes256_gcm, crypto::Algorithm::xchacha20_poly1305}) {
        options.algorithm = algorithm;
        for (const std::size_t size : {0u, 1u, 65536u, 131073u}) {
            crypto::Bytes plaintext(size);
            for (std::size_t i = 0; i < size; ++i) {
                plaintext[i] = static_cast<std::uint8_t>(i * 17);
            }
            write_file(source, plaintext);
            std::filesystem::remove(encrypted);
            std::filesystem::remove(restored);
            app::encrypt_file(source, encrypted, password, options);
            const auto original = read_file(encrypted);
            const auto info = app::inspect_file(encrypted);
            check(!info.compressed && !info.directory && !info.authenticated,
                "Encrypted file information mismatch");
            check(original.size() == size + 32 + (algorithm == crypto::Algorithm::aes256_gcm ? 64 : 80),
                "Encrypted file size mismatch");
            app::decrypt_file(encrypted, restored, password, options.limits);
            check(read_file(restored) == plaintext, "File roundtrip mismatch");
            // 现有目标与输入本身均不得被覆盖。
            rejects([&] { app::encrypt_file(source, encrypted, password, options); });
            rejects([&] { app::decrypt_file(encrypted, restored, password, options.limits); });
            rejects([&] { app::encrypt_file(source, source, password, options); });
            check(read_file(encrypted) == original && read_file(source) == plaintext &&
                read_file(restored) == plaintext, "Existing file was modified");
            std::filesystem::remove(restored);
            rejects([&] { app::decrypt_file(encrypted, restored, wrong_password, options.limits); });
            check(!std::filesystem::exists(restored), "Wrong password published plaintext");
            rejects([&] { app::decrypt_file(encrypted, restored, password, {4096, 4, 4}); });
            check(!std::filesystem::exists(restored), "Resource rejection created output");
            // Header、AAD 中的 Salt/Nonce、Tag 以及密文分别被改变。
            std::vector<std::size_t> offsets{0, 4, 6, 12, 20, 32 + 18, 32 + 34,
                std::size_t{32} + (algorithm == crypto::Algorithm::aes256_gcm ? 64u : 80u) - 1};
            if (size > 0) {
                offsets.push_back(original.size() - 1);
            }
            for (const auto offset : offsets) {
                auto changed = original;
                changed[offset] ^= 1;
                write_file(corrupted, changed);
                rejects([&] { app::decrypt_file(corrupted, restored, password, options.limits); });
                check(!std::filesystem::exists(restored), "Tampered file published output");
                check_no_temporary(directory);
            }
            for (const auto length : {std::size_t{5}, std::size_t{31}, original.size() - 1}) {
                write_file(corrupted, crypto::Bytes(original.begin(), original.begin() + length));
                rejects([&] { app::decrypt_file(corrupted, restored, password, options.limits); });
                check(!std::filesystem::exists(restored), "Truncated file published output");
            }
            auto appended = original;
            appended.push_back(0);
            write_file(corrupted, appended);
            rejects([&] { app::decrypt_file(corrupted, restored, password, options.limits); });
            check_no_temporary(directory);
        }
    }
    // 同密码加密两次应使用不同公开随机参数。
    std::filesystem::remove(encrypted);
    app::encrypt_file(source, encrypted, password, options);
    const auto first = read_file(encrypted);
    std::filesystem::remove(encrypted);
    app::encrypt_file(source, encrypted, password, options);
    check(read_file(encrypted) != first, "Repeated encryption reused salt and nonce");
    const auto sample = directory / "sample.fcry";
    for (const auto mode : {app::SampleOptions{1, "aes-256-gcm", false, true},
                           app::SampleOptions{1, "aes-256-gcm", true, false}}) {
        std::filesystem::remove(sample);
        app::generate_sample(sample, mode);
        rejects([&] { app::decrypt_file(sample, restored, password, options.limits); });
        check(!std::filesystem::exists(restored), "Unsupported mode created output");
    }
    check_no_temporary(directory);
}

/// 创建认证有效但压缩内容由测试指定的 v1 文件。
void write_authenticated_compressed(const std::filesystem::path& path,
    std::span<const std::uint8_t> password, std::span<const std::uint8_t> payload) {
    namespace format = filecrypt::format::v1;
    format::Header header;
    header.version = 1;
    header.flags = 0x4000;
    header.algorithm = 1;
    header.file_type = 0xFFFE;
    header.metadata_length = format::metadata_layout(header).metadata_size;
    format::Metadata metadata;
    metadata.compression = format::CompressionMetadata{};
    metadata.kdf_parameters.memory_cost_kib = 8192;
    metadata.kdf_parameters.time_cost = 1;
    metadata.kdf_parameters.parallelism = 1;
    metadata.nonce.resize(12);
    const crypto::Bytes salt(16);
    const crypto::Bytes nonce(12);
    const auto raw_aad = format::build_aad(header, metadata);
    crypto::Bytes aad;
    for (const auto value : raw_aad) {
        aad.push_back(std::to_integer<std::uint8_t>(value));
    }
    const auto key = crypto::derive_key(password, salt, {8192, 1, 1}, {16384, 4, 4}, 32);
    const auto encrypted = crypto::encrypt(crypto::Algorithm::aes256_gcm, key, nonce, aad, payload);
    std::transform(encrypted.tag.begin(), encrypted.tag.end(), metadata.tag.begin(),
        [](std::uint8_t value) { return static_cast<std::byte>(value); });
    crypto::Bytes bytes;
    for (const auto value : format::serialize(header)) {
        bytes.push_back(std::to_integer<std::uint8_t>(value));
    }
    for (const auto value : format::serialize_metadata(header, metadata)) {
        bytes.push_back(std::to_integer<std::uint8_t>(value));
    }
    bytes.insert(bytes.end(), encrypted.ciphertext.begin(), encrypted.ciphertext.end());
    write_file(path, bytes);
}

/// 验证压缩文件往返、认证顺序、解压限制及临时文件清理。
void compressed_file_tests(const std::filesystem::path& directory) {
    const auto source = directory / "compressed-source.bin";
    const auto encrypted = directory / "compressed.fcry";
    const auto restored = directory / "decompressed.bin";
    const auto corrupted = directory / "compressed-corrupted.fcry";
    const crypto::SecureBytes password{'p', 0, ' '};
    const crypto::SecureBytes wrong_password{'x'};
    app::EncryptOptions options;
    options.compressed = true;
    options.kdf = {8192, 1, 1};
    options.limits = {16384, 4, 4};
    for (const auto algorithm : {crypto::Algorithm::aes256_gcm, crypto::Algorithm::xchacha20_poly1305}) {
        options.algorithm = algorithm;
        for (const std::size_t size : {0u, 1u, 65536u, 131073u}) {
            const crypto::Bytes plain(size, 0x61);
            write_file(source, plain);
            std::filesystem::remove(encrypted);
            std::filesystem::remove(restored);
            app::encrypt_file(source, encrypted, password, options);
            const auto original = read_file(encrypted);
            const auto info = app::inspect_file(encrypted);
            check(info.compressed && !info.directory && !info.authenticated && info.compression == "Zstandard",
                "Compressed file information mismatch");
            if (size >= 65536) {
                check(original.size() < size, "Compression did not reduce repeated input");
            }
            app::decrypt_file(encrypted, restored, password, options.limits, {size, 26});
            check(read_file(restored) == plain, "Compressed file roundtrip mismatch");
            rejects([&] { app::decrypt_file(encrypted, restored, password, options.limits); });
            check(read_file(restored) == plain, "Compressed decryption overwrote destination");
            std::filesystem::remove(restored);
            bool authentication_failed = false;
            try {
                app::decrypt_file(encrypted, restored, wrong_password, options.limits, {0, 10});
            } catch (const crypto::AuthenticationError&) {
                authentication_failed = true;
            }
            check(authentication_failed, "Decompression ran before authentication");
            auto changed = original;
            changed.back() ^= 1;
            write_file(corrupted, changed);
            rejects([&] { app::decrypt_file(corrupted, restored, password, options.limits); });
            if (size > 0) {
                rejects([&] { app::decrypt_file(encrypted, restored, password, options.limits, {size - 1, 26}); });
            }
            if (size >= 65536) {
                rejects([&] { app::decrypt_file(encrypted, restored, password, options.limits, {size, 10}); });
            }
            check(!std::filesystem::exists(restored), "Failed compressed decryption published output");
            check_no_temporary(directory);
        }
    }
    // 即使密码和 Tag 正确，畸形或截断的压缩载荷也不得发布输出。
    for (const auto payload : {crypto::Bytes{}, crypto::Bytes{1, 2, 3, 4, 5}}) {
        write_authenticated_compressed(corrupted, password, payload);
        rejects([&] { app::decrypt_file(corrupted, restored, password, options.limits); });
        check(!std::filesystem::exists(restored), "Authenticated invalid compression published output");
        check_no_temporary(directory);
    }
}

/// 验证事务放弃时清理以及提交竞争时拒绝覆盖目标。
void transaction_tests(const std::filesystem::path& directory) {
    const auto target = directory / "transaction.bin";
    std::filesystem::remove(target);
    const crypto::Bytes bytes{1, 2, 3};
    // 验证空事务及异常展开均会清理临时文件，而非仅验证正常离开作用域。
    {
        io::OutputTransaction output(target);
    }
    check_no_temporary(directory);
    rejects([&] {
        io::OutputTransaction output(target);
        output.write(std::as_bytes(std::span(bytes)));
        throw std::runtime_error("Simulated processing failure");
    });
    check(!std::filesystem::exists(target), "Failed output was published");
    check_no_temporary(directory);
    {
        io::OutputTransaction output(target);
        output.write(std::as_bytes(std::span(bytes)));
    }
    check(!std::filesystem::exists(target), "Uncommitted output was published");
    check_no_temporary(directory);
    {
        io::OutputTransaction output(target);
        output.write(std::as_bytes(std::span(bytes)));
        write_file(target, crypto::Bytes{9});
        rejects([&] { output.commit(); });
        check(read_file(target) == crypto::Bytes{9}, "Commit overwrote competing output");
    }
    check_no_temporary(directory);
    std::filesystem::remove(target);
    {
        io::OutputTransaction output(target);
        output.write(std::as_bytes(std::span(bytes)));
        output.seek(1);
        const crypto::Bytes change{9};
        output.write(std::as_bytes(std::span(change)));
        output.seek(0);
        std::array<std::byte, 4> readback{};
        check(output.read(readback) == 3 && readback[1] == std::byte{9}, "Temporary read or seek failed");
        check(output.read(readback) == 0, "Temporary reader did not reach EOF");
        output.commit();
        rejects([&] { output.commit(); });
        rejects([&] { output.write({}); });
        rejects([&] { static_cast<void>(output.read(readback)); });
    }
    check(read_file(target) == crypto::Bytes({1, 9, 3}), "Seek or commit failed");
    check_no_temporary(directory);
}
}

/// 在专用构建目录执行文件流程与输出事务端到端测试。
int main(int argc, char** argv) {
    try {
        check(argc == 2, "Missing test directory");
        const std::filesystem::path directory = argv[1];
        std::filesystem::create_directories(directory);
        file_tests(directory);
        compressed_file_tests(directory);
        transaction_tests(directory);
        std::cout << "File encryption tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "File test failed: " << error.what() << '\n';
        return 1;
    }
}
