#include <filecrypt/format/v1/directory.hpp>
#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

namespace filecrypt::format::v1 {
namespace {
void require(bool condition, const char* text) {
    if (!condition) throw std::invalid_argument(text);
}
template<class T> void put(std::vector<std::byte>& out, T value) {
    for (std::size_t i = 0; i < sizeof(T); ++i) out.push_back(static_cast<std::byte>((value >> (8 * i)) & 255));
}
template<class T> T get(std::span<const std::byte> bytes, std::size_t& pos) {
    require(sizeof(T) <= bytes.size() - pos, "Truncated directory Entry");
    std::uint64_t value{};
    for (std::size_t i = 0; i < sizeof(T); ++i) value |= std::to_integer<std::uint64_t>(bytes[pos++]) << (8 * i);
    return static_cast<T>(value);
}
}

void validate_entry_name(std::string_view name) {
    require(!name.empty() && name != "." && name != ".." && name.find_first_of("/\\") == name.npos,
        "Directory Name must be a nonempty single component");
    for (std::size_t i = 0; i < name.size();) {
        const auto first = static_cast<unsigned char>(name[i++]);
        require(first != 0, "Directory Name contains NUL");
        if (first < 128) continue;
        unsigned length{};
        std::uint32_t code{}, minimum{};
        if (first >= 0xC2 && first <= 0xDF) { length = 1; code = first & 31; minimum = 0x80; }
        else if (first >= 0xE0 && first <= 0xEF) { length = 2; code = first & 15; minimum = 0x800; }
        else if (first >= 0xF0 && first <= 0xF4) { length = 3; code = first & 7; minimum = 0x10000; }
        else throw std::invalid_argument("Invalid UTF-8 directory Name");
        require(length <= name.size() - i, "Truncated UTF-8 directory Name");
        while (length--) {
            const auto next = static_cast<unsigned char>(name[i++]);
            require((next & 0xC0) == 0x80, "Invalid UTF-8 continuation");
            code = (code << 6) | (next & 63);
        }
        require(code >= minimum && code <= 0x10FFFF && !(code >= 0xD800 && code <= 0xDFFF),
            "Invalid UTF-8 code point");
    }
}

std::uint64_t validate_index(std::span<const DirectoryEntry> entries, const directory::Limits& limits) {
    require(!entries.empty() && entries.size() <= limits.max_entries, "Directory Entry count exceeds policy or is empty");
    require(entries[0].id == 0 && entries[0].parent_id == 0xFFFFFFFF && entries[0].type == EntryType::directory,
        "Invalid directory Root Entry");
    // 所有二分查找都以整个范围有序为前提，必须先验证完整 ID 序列。
    for (std::size_t i = 1; i < entries.size(); ++i)
        require(entries[i - 1].id < entries[i].id, "Directory IDs must be unique and increasing");
    std::set<std::pair<std::uint32_t, std::string_view>> names;
    std::vector<std::size_t> parents(entries.size());
    std::uint64_t data_size{}, encoded_size{};
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        validate_entry_name(entry.name);
        require(entry.name.size() <= limits.max_name_bytes, "Directory Name exceeds policy");
        auto n = entry.name.size();
        std::uint64_t size = 26 + n + 1;
        while (n >= 128) { ++size; n >>= 7; }
        require(encoded_size <= limits.max_index_bytes && size <= limits.max_index_bytes - encoded_size,
            "Directory Index exceeds policy");
        encoded_size += size;
        if (i) require(names.emplace(entry.parent_id, entry.name).second, "Duplicate sibling Name");
        if (entry.type == EntryType::file) {
            require(entry.data_offset == data_size && entry.data_length <= std::numeric_limits<std::uint64_t>::max() - data_size,
                "Directory File Data is discontinuous or overflows");
            data_size += entry.data_length;
        } else {
            require(entry.type == EntryType::directory && entry.data_offset == 0 && entry.data_length == 0,
                "Invalid directory Entry Type or data fields");
        }
        if (i) {
            const auto parent = std::lower_bound(entries.begin(), entries.end(), entry.parent_id,
                [](const DirectoryEntry& value, std::uint32_t id) { return value.id < id; });
            require(parent != entries.end() && parent->id == entry.parent_id && parent->type == EntryType::directory,
                "Missing or non-directory Parent ID");
            parents[i] = static_cast<std::size_t>(parent - entries.begin());
        }
    }
    require(encoded_size <= limits.max_output_bytes && data_size <= limits.max_output_bytes - encoded_size,
        "Directory archive output exceeds policy");
    // 迭代遍历父链，允许父节点 ID 晚于子节点，不使用无界递归。
    std::vector<unsigned char> state(entries.size());
    std::vector<std::uint32_t> depths(entries.size());
    state[0] = 2;
    for (std::size_t i = 1; i < entries.size(); ++i) {
        std::vector<std::size_t> chain;
        auto node = i;
        while (state[node] == 0) {
            state[node] = 1;
            chain.push_back(node);
            require(chain.size() <= limits.max_depth, "Directory depth exceeds policy");
            node = parents[node];
        }
        require(state[node] == 2, "Cycle in directory tree");
        auto depth = depths[node];
        while (!chain.empty()) {
            node = chain.back(); chain.pop_back();
            require(depth < limits.max_depth, "Directory depth exceeds policy");
            depths[node] = ++depth;
            state[node] = 2;
        }
    }
    return data_size;
}

std::vector<std::byte> serialize_index(std::span<const DirectoryEntry> entries, const directory::Limits& limits) {
    (void)validate_index(entries, limits);
    std::vector<std::byte> bytes;
    for (const auto& entry : entries) {
        put(bytes, entry.id); put(bytes, entry.parent_id); put(bytes, static_cast<std::uint16_t>(entry.type));
        put(bytes, entry.data_offset); put(bytes, entry.data_length);
        auto length = static_cast<std::uint64_t>(entry.name.size());
        do { const auto value = length & 127; length >>= 7; bytes.push_back(static_cast<std::byte>(value | (length ? 128 : 0))); } while (length);
        for (const unsigned char value : entry.name) bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

std::vector<DirectoryEntry> deserialize_index(std::span<const std::byte> bytes, std::uint64_t file_data_length,
    const directory::Limits& limits) {
    require(bytes.size() <= limits.max_index_bytes, "Directory Index exceeds policy");
    require(bytes.size() <= limits.max_output_bytes && file_data_length <= limits.max_output_bytes - bytes.size(),
        "Directory archive exceeds output policy");
    std::vector<DirectoryEntry> entries;
    std::size_t position{};
    while (position < bytes.size()) {
        require(entries.size() < limits.max_entries, "Directory Entry count exceeds policy");
        DirectoryEntry entry;
        entry.id = get<std::uint32_t>(bytes, position); entry.parent_id = get<std::uint32_t>(bytes, position);
        entry.type = static_cast<EntryType>(get<std::uint16_t>(bytes, position));
        entry.data_offset = get<std::uint64_t>(bytes, position); entry.data_length = get<std::uint64_t>(bytes, position);
        std::uint64_t length{};
        unsigned shift{};
        while (true) {
            require(position < bytes.size() && shift <= 63, "Truncated or overflowing Name Length LEB128");
            const auto value = std::to_integer<unsigned>(bytes[position++]);
            require(shift != 63 || (value & 127) <= 1, "Name Length LEB128 overflow");
            length |= std::uint64_t{value & 127} << shift;
            if (!(value & 128)) break;
            shift += 7;
        }
        require(length <= limits.max_name_bytes && length <= bytes.size() - position, "Invalid or oversized Name Length");
        entry.name.assign(reinterpret_cast<const char*>(bytes.data() + position), static_cast<std::size_t>(length));
        position += static_cast<std::size_t>(length);
        entries.push_back(std::move(entry));
    }
    require(validate_index(entries, limits) == file_data_length, "Unreferenced or truncated File Data");
    return entries;
}
}
