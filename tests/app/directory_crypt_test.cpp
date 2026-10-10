#include <filecrypt/app/operations.hpp>
#include <filecrypt/format/v1/directory.hpp>
#include <filecrypt/format/v1/aad.hpp>
#include <filecrypt/io/output.hpp>
#include <filecrypt/io/directory.hpp>
#include <filecrypt/io/source.hpp>
#include "../../src/app/v1/directory.hpp"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include "fixture.hpp"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace {
using namespace filecrypt;
namespace format = filecrypt::format::v1;
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template<class F> void rejects(F action) {
    try { action(); } catch (const std::exception&) { return; }
    throw std::runtime_error("Expected directory operation failure");
}
void write(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    check(static_cast<bool>(out), "Cannot write fixture");
}
void write(const std::filesystem::path& path, std::string_view text) { write(path, std::as_bytes(std::span(text))); }
std::string read(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    check(static_cast<bool>(in), "Cannot read restored file");
    return {std::istreambuf_iterator<char>(in), {}};
}
auto inventory(const std::filesystem::path& root) {
    std::map<std::filesystem::path, std::string> entries;
    for (const auto& item : std::filesystem::recursive_directory_iterator(root)) {
        entries.emplace(item.path().lexically_relative(root), item.is_directory() ? "directory" : "file:" + read(item.path()));
    }
    return entries;
}
void clean(const std::filesystem::path& directory) {
    for (const auto& item : std::filesystem::directory_iterator(directory))
        check(!item.path().filename().u8string().starts_with(u8".filecrypt-"), "Temporary file or directory leaked");
}
const crypto::SecureBytes password{'d', 'i', 'r'};
app::EncryptOptions options() { app::EncryptOptions result; result.kdf = {8192, 1, 1}; return result; }

void authenticated_archive(const std::filesystem::path& file, std::span<const std::byte> plaintext,
    std::uint64_t index_length, bool compressed = false) {
    format::Header header;
    header.version = 1;
    header.flags = static_cast<std::uint16_t>(0x8000 | (compressed ? 0x4000 : 0));
    header.algorithm = 1; header.file_type = 0;
    header.metadata_length = format::metadata_layout(header).metadata_size;
    format::Metadata metadata;
    metadata.index_length = index_length;
    metadata.kdf_parameters.memory_cost_kib = 8192;
    metadata.kdf_parameters.time_cost = 1;
    metadata.kdf_parameters.parallelism = 1;
    metadata.nonce.resize(12);
    if (compressed) metadata.compression = format::CompressionMetadata{};
    const auto aad = format::build_aad(header, metadata);
    const auto key = crypto::derive_key(password,
        {reinterpret_cast<const std::uint8_t*>(metadata.salt.data()), metadata.salt.size()}, {8192, 1, 1}, {16384, 4, 4}, 32);
    const auto encrypted = crypto::encrypt(crypto::Algorithm::aes256_gcm, key,
        {reinterpret_cast<const std::uint8_t*>(metadata.nonce.data()), metadata.nonce.size()},
        {reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size()},
        {reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size()});
    std::transform(encrypted.tag.begin(), encrypted.tag.end(), metadata.tag.begin(),
        [](auto byte) { return static_cast<std::byte>(byte); });
    std::vector<std::byte> bytes;
    const auto prefix = format::serialize(header);
    bytes.insert(bytes.end(), prefix.begin(), prefix.end());
    const auto meta = format::serialize_metadata(header, metadata);
    bytes.insert(bytes.end(), meta.begin(), meta.end());
    for (const auto byte : encrypted.ciphertext) bytes.push_back(static_cast<std::byte>(byte));
    write(file, bytes);
}

void tests(const std::filesystem::path& base) {
    const auto source = base / std::filesystem::path(u8"原始 根 🔐");
    const auto output = base / "restored";
    const auto encrypted = base / "directory.fcry";
    std::filesystem::create_directories(source / "sub" / "empty");
    std::filesystem::create_directories(source / "empty");
    write(source / "a.txt", "hello");
    write(source / std::filesystem::path(u8"中文 空格 🔑.bin"), std::string(131073, '\xA5'));
    write(source / "sub" / "zero", "");
    const auto expected = inventory(source);
    for (const auto algorithm : {crypto::Algorithm::aes256_gcm, crypto::Algorithm::xchacha20_poly1305}) {
        for (const bool compressed : {false, true}) {
            auto opts = options(); opts.algorithm = algorithm; opts.compressed = compressed;
            std::filesystem::remove(encrypted); std::filesystem::remove_all(output);
            app::encrypt_file(source, encrypted, password, opts);
            const auto info = app::inspect_file(encrypted);
            check(info.directory && info.compressed == compressed && info.file_type == "N/A", "Directory public info mismatch");
            check(app::decrypt_file(encrypted, output, password, opts.limits, {}, true) == output, "Directory output got file suffix");
            check(inventory(output) == expected, "Directory tree roundtrip mismatch");
            check(!std::filesystem::exists(output / source.filename()), "Unexpected extra original Root directory");
#ifndef _WIN32
            struct stat root_stat{}, file_stat{};
            check(stat(output.c_str(), &root_stat) == 0 && (root_stat.st_mode & 0777) == 0700, "Directory permissions not restricted");
            check(stat((output / "a.txt").c_str(), &file_stat) == 0 && (file_stat.st_mode & 0777) == 0600, "File permissions not restricted");
#endif
            rejects([&] { app::decrypt_file(encrypted, output, password); });
            check(inventory(output) == expected, "Existing directory overwritten");
            std::filesystem::remove_all(output);
            const crypto::SecureBytes wrong{'b', 'a', 'd'};
            rejects([&] { app::decrypt_file(encrypted, output, wrong); });
            check(!std::filesystem::exists(output), "Wrong password published directory"); clean(base);
            auto limits = directory::Limits{}; limits.max_entries = 1;
            rejects([&] { app::decrypt_file(encrypted, output, password, opts.limits, {}, false, limits); });
            limits = {}; limits.max_index_bytes = 1;
            rejects([&] { app::decrypt_file(encrypted, output, password, opts.limits, {}, false, limits); });
            limits = {}; limits.max_depth = 1;
            rejects([&] { app::decrypt_file(encrypted, output, password, opts.limits, {}, false, limits); });
            limits = {}; limits.max_output_bytes = 100;
            rejects([&] { app::decrypt_file(encrypted, output, password, opts.limits, {}, false, limits); });
            clean(base);
            rejects([&] { app::encrypt_file(source, source / "inside.fcry", password, opts); });
            check(!std::filesystem::exists(source / "inside.fcry"), "Encryption wrote inside source");
            opts.directory_limits.max_entries = 1;
            std::filesystem::remove(encrypted);
            rejects([&] { app::encrypt_file(source, encrypted, password, opts); });
            check(!std::filesystem::exists(encrypted), "Scan failure published ciphertext");
        }
    }
    // 空目录的 Root Entry 是有效载荷。
    const auto empty = base / "empty-source";
    std::filesystem::create_directory(empty);
    for (const bool compressed : {false, true}) {
        auto opts = options(); opts.compressed = compressed;
        std::filesystem::remove(encrypted); std::filesystem::remove_all(output);
        app::encrypt_file(empty, encrypted, password, opts);
        app::decrypt_file(encrypted, output, password);
        check(std::filesystem::is_empty(output), "Empty directory restoration failed");
    }
    std::filesystem::remove_all(output);
    // Root 名称超过 127 bytes 时，其 LEB128 长度需要两个字节。
    const auto long_root = base / std::string(128, 'r');
    std::filesystem::create_directory(long_root);
    directory::Limits exact;
    exact.max_index_bytes = 156; exact.max_output_bytes = 156;
    check(app::v1::scan_directory(long_root, encrypted, exact).index.size() == 156,
        "Root LEB128 encoded size mismatch");
    exact.max_index_bytes = 155;
    rejects([&] { (void)app::v1::scan_directory(long_root, encrypted, exact); });
    std::filesystem::remove(long_root);
    // 非连续最大 ID、父节点晚于子节点；原始 Root 名称不参与子目录重名判定。
    const std::vector<format::DirectoryEntry> maximum_id{{0, 0xFFFFFFFF, format::EntryType::directory, 0, 0, "file"},
        {1, 0xFFFFFFFF, format::EntryType::file, 0, 1, "file"},
        {0xFFFFFFFF, 0, format::EntryType::directory, 0, 0, "parent"}};
    auto maximum_payload = format::serialize_index(maximum_id);
    const auto maximum_index_length = maximum_payload.size();
    maximum_payload.push_back(std::byte{'x'});
    authenticated_archive(encrypted, maximum_payload, maximum_index_length);
    app::decrypt_file(encrypted, output, password);
    check(read(output / "parent" / "file") == "x", "Forward maximum Parent ID restoration failed");
    std::filesystem::remove_all(output);
    // 认证有效的攻击载荷：数据空洞、越界、重复名称、路径穿越及无引用尾部。
    std::vector<format::DirectoryEntry> entries{{0, 0xFFFFFFFF, format::EntryType::directory, 0, 0, "root"},
        {1, 0, format::EntryType::file, 0, 1, "aa"}, {2, 0, format::EntryType::file, 1, 1, "bb"}};
    const auto valid_index = format::serialize_index(entries);
    for (int mutation = 0; mutation < 7; ++mutation) {
        auto index = valid_index;
        const auto second = std::size_t{31}; // Root: 26 + 1 + 4。
        const auto third = second + 29;
        auto index_length = static_cast<std::uint64_t>(index.size());
        switch (mutation) {
        case 0: index[second + 10] = std::byte{1}; break; // 第一个 Data Offset 不是零。
        case 1: index[second + 18] = std::byte{3}; break;
        case 2: index[third + 27] = std::byte{'a'}; index[third + 28] = std::byte{'a'}; break;
        case 3: index[second + 27] = std::byte{'.'}; index[second + 28] = std::byte{'.'}; break;
        case 4: index[second + 27] = std::byte{'/'}; break;
        case 5: ++index_length; break;
        case 6: break;
        }
        index.push_back(std::byte{1}); index.push_back(std::byte{2});
        if (mutation == 6) index.push_back(std::byte{3});
        authenticated_archive(encrypted, index, index_length);
        rejects([&] { app::decrypt_file(encrypted, output, password); });
        check(!std::filesystem::exists(output), "Malformed authenticated archive published directory"); clean(base);
    }
    // 认证成功但压缩载荷无效，不能开始恢复。
    authenticated_archive(encrypted, std::as_bytes(std::span("bad zstd", 8)), 31, true);
    rejects([&] { app::decrypt_file(encrypted, output, password); }); clean(base);
    // 平台名称规则与实际文件系统冲突（不在格式层改写）。
    for (const auto name : {"CON", "A", "a."}) {
        auto names = entries; names[1].name = name; names[2].name = "a";
        auto index = format::serialize_index(names); const auto length = index.size();
        index.push_back(std::byte{1}); index.push_back(std::byte{2});
        authenticated_archive(encrypted, index, length);
#ifdef _WIN32
        rejects([&] { app::decrypt_file(encrypted, output, password); });
#else
        app::decrypt_file(encrypted, output, password);
        std::filesystem::remove_all(output);
#endif
        clean(base);
    }
    // 不覆盖提交竞态，以及异常离开暂存目录后的自动清理。
    {
        io::DirectoryTransaction transaction(output);
        io::create_restricted_directory(transaction.root() / "sub");
        write(transaction.root() / "sub" / "data", "private");
        std::filesystem::create_directory(output);
        rejects([&] { transaction.commit(); });
        check(std::filesystem::is_empty(output), "Directory commit replaced competing target");
    }
    std::filesystem::remove_all(output); clean(base);
    rejects([&] {
        io::DirectoryTransaction transaction(output);
        write(transaction.root() / "data", "private");
        throw std::runtime_error("Simulated restore failure");
    }); clean(base);
    // 暂存根被移走并在旧名称放置另一个目录，不能发布或清理替代对象。
    const auto moved = base / "moved-owned-stage";
    std::filesystem::remove_all(moved);
    std::filesystem::path replaced;
    {
        io::DirectoryTransaction transaction(output);
        replaced = transaction.root();
        write(replaced / "owned", "private");
        std::filesystem::rename(replaced, moved);
        std::filesystem::create_directory(replaced);
        write(replaced / "unrelated", "keep");
        rejects([&] { transaction.commit(); });
    }
    check(read(replaced / "unrelated") == "keep" && !std::filesystem::exists(output),
        "Directory transaction touched a replacement root");
    std::filesystem::remove_all(replaced);
    std::filesystem::remove_all(moved);
    clean(base);
    // 源文件长度、身份与目录集合在扫描后发生变化，明确失败。
    auto scan = app::v1::scan_directory(source, encrypted, {});
    write(source / "a.txt", "changed length");
    rejects([&] { app::v1::verify_scan(scan); });
    rejects([&] { app::v1::DirectoryReader reader(scan); crypto::SecureBytes buffer(65536);
        while (reader.read(std::as_writable_bytes(std::span(buffer)))) {} });
    write(source / "a.txt", "hello");
    scan = app::v1::scan_directory(source, encrypted, {});
    write(source / "new-entry", "new");
    rejects([&] { app::v1::verify_scan(scan); });
    std::filesystem::remove(source / "new-entry");
    // 符号链接不能作为根或树中成员。
    const auto link = base / "source-link";
    std::error_code error;
    std::filesystem::create_directory_symlink(source, link, error);
    if (!error) {
        rejects([&] { app::encrypt_file(link, encrypted, password, options()); });
        rejects([&] { app::encrypt_file(link / ".." / empty.filename(), encrypted, password, options()); });
        std::filesystem::remove(link);
        std::filesystem::create_symlink(source / "a.txt", source / "linked-file", error);
        if (!error) {
            rejects([&] { app::encrypt_file(source, encrypted, password, options()); });
            std::filesystem::remove(source / "linked-file");
        }
    }
#ifndef _WIN32
    else throw std::runtime_error("Cannot create source link fixture");
#endif
    clean(base);
}
}

int run_tests(const std::filesystem::path& directory) {
    try {
        const auto base = test_fixture::create(std::filesystem::absolute(directory).lexically_normal());
        tests(base);
        std::filesystem::remove_all(base);
        std::cout << "Directory encryption tests passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring_view(argv[1]) == L"--remove-junction") {
        const auto path = std::filesystem::absolute(argv[2]).lexically_normal();
        const auto flags = GetFileAttributesW(path.c_str());
        if (path.filename() != L"junction" || flags == INVALID_FILE_ATTRIBUTES ||
            !(flags & FILE_ATTRIBUTE_REPARSE_POINT) || !(flags & FILE_ATTRIBUTE_DIRECTORY)) return 1;
        return RemoveDirectoryW(path.c_str()) ? 0 : 1;
    }
    return argc == 2 ? run_tests(argv[1]) : 1;
}
#else
int main(int argc, char** argv) { return argc == 2 ? run_tests(argv[1]) : 1; }
#endif
