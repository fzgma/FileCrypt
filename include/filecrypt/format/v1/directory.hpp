#pragma once
#include <filecrypt/directory/limits.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace filecrypt::format::v1 {
enum class EntryType : std::uint16_t { file = 1, directory = 2 };
struct DirectoryEntry {
    std::uint32_t id{};
    std::uint32_t parent_id{0xFFFFFFFF};
    EntryType type{EntryType::directory};
    std::uint64_t data_offset{};
    std::uint64_t data_length{};
    std::string name;
    bool operator==(const DirectoryEntry&) const = default;
};
/// 校验合法 UTF-8 单路径组件，不施加目标平台名称规则。
void validate_entry_name(std::string_view name);
/// 校验有序唯一 ID、根、父目录、树结构、深度及连续数据，返回 File Data 总长度。
std::uint64_t validate_index(std::span<const DirectoryEntry> entries, const directory::Limits& limits = {});
/// 显式小端编码 Index，Name Length 使用 unsigned LEB128。
std::vector<std::byte> serialize_index(std::span<const DirectoryEntry> entries, const directory::Limits& limits = {});
/// 仅解释给定 Index 字节；验证完整树与实际 File Data 区域长度。
std::vector<DirectoryEntry> deserialize_index(std::span<const std::byte> bytes,
    std::uint64_t file_data_length, const directory::Limits& limits = {});
}
