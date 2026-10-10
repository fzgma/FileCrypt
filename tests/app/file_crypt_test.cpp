#include <filecrypt/app/operations.hpp>
#include <filecrypt/io/file.hpp>
#include <filecrypt/io/output.hpp>
#include <filecrypt/format/v1/aad.hpp>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string_view>
#include <cstdio>

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
    std::filesystem::remove(target);
    std::filesystem::path old_temporary;
    {
        io::OutputTransaction output(target);
        output.write(std::as_bytes(std::span(bytes)));
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (entry.path().filename().string().starts_with(".filecrypt-")) old_temporary = entry.path();
        }
        check(!old_temporary.empty(), "Cannot find transaction fixture");
        output.commit();
        write_file(old_temporary, crypto::Bytes{9});
    }
    check(std::filesystem::exists(old_temporary) && read_file(old_temporary) == crypto::Bytes{9},
        "Committed transaction deleted a replacement at its old temporary name");
    std::filesystem::remove(old_temporary);
    check_no_temporary(directory);
}

/// 验证实际加密 Header、原始后缀优先、复合后缀恢复及受认证的类型信息。
void file_type_tests(const std::filesystem::path& directory) {
    using namespace std::string_view_literals;
    constexpr std::string_view extensions[]{"txt", "md", "csv", "json", "xml", "yaml", "yml", "pdf",
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "tif", "tiff", "zip", "7z", "rar",
        "tar", "gz", "bz2", "xz", "zst", "mp3", "wav", "flac", "mp4", "mkv", "mov", "avi",
        "tar.gz", "tar.bz2", "tar.xz", "tar.zst"};
    const crypto::SecureBytes password{'t', 'e', 's', 't'};
    app::EncryptOptions options;
    options.kdf = {8192, 1, 1};
    const auto encrypted = directory / "typed.fcry";
    const auto output = directory / "typed-restored";
    const crypto::Bytes content{0x89, 'P', 'N', 'G', 13, 10, 0x1A, 10, 42};
    auto verify = [&](const std::filesystem::path& source, const crypto::Bytes& bytes,
            std::uint16_t id, std::string_view extension) {
        write_file(source, bytes);
        std::filesystem::remove(encrypted);
        app::encrypt_file(source, encrypted, password, options);
        const auto ciphertext = read_file(encrypted);
        check(ciphertext[10] == (id & 255) && ciphertext[11] == (id >> 8), "Wrong File Type Header ID");
        check(app::inspect_file(encrypted).file_type == (extension.empty() ? "Unknown" : extension),
            "File Type info mismatch");
        auto expected = output;
        if (!extension.empty()) expected += "." + std::string(extension);
        std::filesystem::remove(expected);
        std::filesystem::remove(output);
        const auto actual = app::decrypt_file(encrypted, output, password, options.limits, {}, true);
        check(actual == expected && read_file(actual) == bytes, "Extension restoration or input replay failed");
        if (actual != output) check(!std::filesystem::exists(output), "Suffixless plaintext was published");
        rejects([&] { app::decrypt_file(encrypted, output, password, options.limits, {}, true); });
        check(read_file(expected) == bytes, "Restoration overwrote existing output");
        std::filesystem::remove(expected);
    };
    for (std::size_t i = 0; i < std::size(extensions); ++i) {
        std::string upper(extensions[i]);
        for (auto& c : upper) if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
        options.compressed = (i % 2) != 0;
        verify(directory / ("type." + upper), content, static_cast<std::uint16_t>(i + 1), extensions[i]);
    }
    verify(directory / "photo.png.jpg", content, 0x000A, "jpg");
    verify(directory / "archive.tar.gz.jpg", content, 0x000A, "jpg");
    verify(directory / "archive.custom.gz", content, 0x0016, "gz");
    verify(directory / "photo.custom", content, 0xFFFE, "");
    verify(directory / "photo.", content, 0xFFFE, "");

    // 独立 magic 向量；扩展名未登记时同样内容也必须保持 Unknown。
    struct Magic { std::string_view bytes; std::uint16_t id; std::string_view extension; };
    constexpr Magic samples[]{
        {"\x89PNG\r\n\x1a\n"sv, 0x0009, "png"}, {"\xff\xd8\xff"sv, 0x000A, "jpg"},
        {"GIF87a", 0x000C, "gif"}, {"GIF89a", 0x000C, "gif"}, {"BM", 0x000D, "bmp"},
        {"II\x2a\0"sv, 0x0010, "tif"}, {"MM\0\x2a"sv, 0x0010, "tif"}, {"%PDF-", 0x0008, "pdf"},
        {"PK\x03\x04"sv, 0x0012, "zip"}, {"PK\x05\x06"sv, 0x0012, "zip"},
        {"7z\xbc\xaf\x27\x1c"sv, 0x0013, "7z"}, {"Rar!\x1a\x07\0"sv, 0x0014, "rar"},
        {"Rar!\x1a\x07\x01\0"sv, 0x0014, "rar"}, {"\x1f\x8b\x08"sv, 0x0016, "gz"},
        {"BZh9", 0x0017, "bz2"}, {"\xfd" "7zXZ\0"sv, 0x0018, "xz"},
        {"\x28\xb5\x2f\xfd"sv, 0x0019, "zst"}, {"ID3", 0x001A, "mp3"}, {"fLaC", 0x001C, "flac"},
        {"RIFF\0\0\0\0WEBP"sv, 0x000E, "webp"}, {"RIFF\0\0\0\0WAVE"sv, 0x001B, "wav"},
        {"RIFF\0\0\0\0AVI "sv, 0x0020, "avi"},
        {"\0\0\0\x10" "ftypisom\0\0\0\0"sv, 0x001D, "mp4"},
        {"\0\0\0\x10" "ftypqt  \0\0\0\0"sv, 0x001F, "mov"},
        {"\x1a\x45\xdf\xa3\x8b\x42\x82\x88matroska"sv, 0x001E, "mkv"},
        {"\x1a\x45\xdf\xa3\x87\x42\x82\x84webm"sv, 0xFFFE, ""},
        {"\x1a\x45\xdf\xa3\x80"sv, 0xFFFE, ""},
        {"\x1a\x45\xdf\xa3\x81\0"sv, 0xFFFE, ""},
        {"\0\0\0\x10" "ftypavif\0\0\0\0"sv, 0xFFFE, ""},
        {"BZh0", 0xFFFE, ""}, {"\x89PNG"sv, 0xFFFE, ""}, {"plain text", 0xFFFE, ""}, {"", 0xFFFE, ""}};
    for (const auto& sample : samples) {
        const crypto::Bytes bytes(sample.bytes.begin(), sample.bytes.end());
        verify(directory / "magic-source", bytes, sample.id, sample.extension);
        verify(directory / "magic-source.custom", bytes, 0xFFFE, "");
    }
    auto large = content;
    large.resize(65537, 42);
    verify(directory / "magic-source", large, 0x0009, "png");
    crypto::Bytes tar(512);
    std::copy_n("ustar", 5, tar.begin() + 257);
    unsigned checksum = 8 * ' ';
    for (const auto byte : tar) checksum += byte;
    char octal[8]{};
    std::snprintf(octal, sizeof(octal), "%06o", checksum);
    std::copy_n(octal, 7, tar.begin() + 148);
    tar[155] = ' ';
    verify(directory / "magic-source", tar, 0x0015, "tar");
    tar[0] = 1;
    verify(directory / "magic-source", tar, 0xFFFE, "");

    // 有效编号改成另一个有效编号，格式仍合法但认证必须失败。
    verify(directory / "typed.txt", content, 1, "txt");
    // 库调用默认使用明确指定的路径；只有 CLI 等显式请求才恢复后缀。
    const auto literal = directory / "literal-output";
    std::filesystem::remove(literal);
    check(app::decrypt_file(encrypted, literal, password, options.limits) == literal &&
        read_file(literal) == content, "Library unexpectedly changed explicit output path");
    auto changed = read_file(encrypted);
    changed[10] = 2;
    write_file(encrypted, changed);
    const auto tampered_output = directory / "tampered-type";
    std::filesystem::remove(directory / "tampered-type.md");
    rejects([&] { app::decrypt_file(encrypted, tampered_output, password, options.limits, {}, true); });
    check(!std::filesystem::exists(tampered_output) && !std::filesystem::exists(directory / "tampered-type.md"),
        "Tampered type published plaintext");
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
        file_type_tests(directory);
        std::cout << "File encryption tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "File test failed: " << error.what() << '\n';
        return 1;
    }
}
