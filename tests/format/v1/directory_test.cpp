#include <filecrypt/format/v1/directory.hpp>
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace filecrypt::format::v1;
namespace {
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
template<class F> void rejects(F action) {
    try { action(); } catch (const std::exception&) { return; }
    throw std::runtime_error("Invalid Index was accepted");
}
std::vector<DirectoryEntry> tree() {
    return {{0, 0xFFFFFFFF, EntryType::directory, 0, 0, "root"},
        {1, 0, EntryType::file, 0, 3, "a.txt"}, {2, 0, EntryType::directory, 0, 0, "empty"},
        {3, 0, EntryType::directory, 0, 0, "sub"}, {4, 3, EntryType::file, 3, 0, "空 🔑"},
        {5, 3, EntryType::file, 3, 2, "b.bin"}};
}
void tests() {
    auto entries = tree();
    const auto bytes = serialize_index(entries);
    check(deserialize_index(bytes, 5) == entries, "Index roundtrip mismatch");
    const std::vector<DirectoryEntry> root{{0, 0xFFFFFFFF, EntryType::directory, 0, 0, "r"}};
    const auto root_bytes = serialize_index(root);
    std::vector<std::byte> expected(28);
    std::fill(expected.begin() + 4, expected.begin() + 8, std::byte{255});
    expected[8] = std::byte{2}; expected[26] = std::byte{1}; expected[27] = std::byte{'r'};
    check(root_bytes == expected, "Independent Entry encoding vector mismatch");
    for (std::size_t size = 0; size < root_bytes.size(); ++size)
        rejects([&] { (void)deserialize_index(std::span(root_bytes).first(size), 0); });
    rejects([&] { (void)deserialize_index(bytes, 4); });
    rejects([&] { (void)deserialize_index(bytes, 6); });
    // 大名称跨越 LEB128 边界。
    entries[4].name = std::string(128, 'n');
    check(deserialize_index(serialize_index(entries), 5) == entries, "LEB128 name boundary failed");
    for (const auto name : {"", ".", "..", "a/b", "a\\b"}) rejects([&] { validate_entry_name(name); });
    rejects([] { validate_entry_name(std::string("a\0b", 3)); });
    for (const auto name : {std::string("\xC0\xAF"), std::string("\xED\xA0\x80"),
            std::string("\xF4\x90\x80\x80"), std::string("\xE4\xB8"), std::string("\x80")})
        rejects([&] { validate_entry_name(name); });
    validate_entry_name("中文 🔑");
    validate_entry_name("CON"); // 格式层不施加 Windows 名称规则。
    for (int mutation = 0; mutation < 13; ++mutation) {
        auto bad = tree();
        switch (mutation) {
        case 0: bad[0].id = 1; break;
        case 1: bad[0].parent_id = 0; break;
        case 2: bad[0].type = EntryType::file; break;
        case 3: bad[1].id = 0; break;
        case 4: bad[4].parent_id = 99; break;
        case 5: bad[4].parent_id = 1; break;
        case 6: bad[2].name = bad[3].name; break;
        case 7: bad[2].parent_id = 3; bad[3].parent_id = 2; break;
        case 8: bad[1].data_offset = 1; break;
        case 9: bad[5].data_offset = 2; break;
        case 10: bad[3].data_length = 1; break;
        case 11: bad[1].type = static_cast<EntryType>(3); break;
        case 12: bad[5].data_length = std::numeric_limits<std::uint64_t>::max(); break;
        }
        rejects([&] { (void)serialize_index(bad); });
    }
    // 父节点可以晚于子节点，ID 不要求无间隙。
    auto forward = tree(); forward[1].parent_id = 3; forward[5].id = 10;
    check(deserialize_index(serialize_index(forward), 5) == forward, "Valid forward parent was rejected");
    auto unordered = tree();
    unordered[1].parent_id = 3;
    std::swap(unordered[2], unordered[3]);
    rejects([&] { (void)validate_index(unordered); });
    const std::vector<DirectoryEntry> maximum_id{{0, 0xFFFFFFFF, EntryType::directory, 0, 0, "file"},
        {1, 0xFFFFFFFF, EntryType::file, 0, 1, "file"},
        {0xFFFFFFFF, 0, EntryType::directory, 0, 0, "parent"}};
    check(deserialize_index(serialize_index(maximum_id), 1) == maximum_id, "uint32 ID range was restricted");
    for (int policy = 0; policy < 5; ++policy) {
        filecrypt::directory::Limits limits;
        switch (policy) {
        case 0: limits.max_index_bytes = 27; break;
        case 1: limits.max_entries = 2; break;
        case 2: limits.max_name_bytes = 2; break;
        case 3: limits.max_depth = 1; break;
        case 4: limits.max_output_bytes = bytes.size() + 4; break;
        }
        rejects([&] { (void)deserialize_index(bytes, 5, limits); });
    }
    auto overlong = root_bytes;
    overlong.resize(26);
    overlong.insert(overlong.end(), 10, std::byte{128});
    rejects([&] { (void)deserialize_index(overlong, 0); });
    overlong.back() = std::byte{2};
    rejects([&] { (void)deserialize_index(overlong, 0); });
}
}
int main() {
    try { tests(); std::cout << "Directory format tests passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
