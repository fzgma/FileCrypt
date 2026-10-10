#include "directory.hpp"
#include <filecrypt/io/directory.hpp>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <set>

namespace filecrypt::app::v1 {
namespace {
namespace format = filecrypt::format::v1;
std::string utf8_name(const std::filesystem::path& path) {
    const auto value = path.filename().u8string();
    return {value.begin(), value.end()};
}
std::uint64_t encoded_entry_size(std::string_view name) {
    std::uint64_t size = 27 + name.size();
    for (auto length = name.size(); length >= 128; length >>= 7) ++size;
    return size;
}
void read_exact(io::OutputTransaction& input, std::span<std::byte> bytes) {
    while (!bytes.empty()) {
        const auto size = input.read(bytes);
        if (!size) throw std::invalid_argument("Truncated directory archive");
        bytes = bytes.subspan(size);
    }
}
}

DirectoryScan scan_directory(const std::filesystem::path& input, const std::filesystem::path& output,
    const directory::Limits& limits) {
    io::validate_source_path(input);
    auto root = std::filesystem::absolute(input).lexically_normal();
    if (root.filename().empty()) root = root.parent_path();
    auto parent = std::filesystem::weakly_canonical(std::filesystem::absolute(output).parent_path());
    while (!parent.empty()) {
        if (std::filesystem::exists(parent) && std::filesystem::equivalent(parent, root))
            throw std::invalid_argument("Encrypted output must be outside the source directory");
        const auto next = parent.parent_path();
        if (next == parent) break;
        parent = next;
    }
    DirectoryScan scan;
    const auto snapshot = io::inspect_source(root);
    if (!snapshot.directory) throw std::invalid_argument("Expected source directory");
    auto root_name = utf8_name(root);
    if (root_name.empty()) root_name = "root";
    format::validate_entry_name(root_name);
    auto index_size = encoded_entry_size(root_name);
    if (!limits.max_entries || root_name.size() > limits.max_name_bytes ||
        index_size > limits.max_index_bytes || index_size > limits.max_output_bytes)
        throw std::length_error("Directory Root exceeds runtime policy");
    scan.entries.push_back({0, 0xFFFFFFFF, format::EntryType::directory, 0, 0, root_name});
    scan.paths.push_back(root);
    scan.snapshots.push_back(snapshot);
    std::vector<std::uint32_t> depths{0};
    std::uint64_t offset{};
    // 编码器会精确核对 LEB128 大小；扫描过程中也限制增长，避免先无界收集。
    for (std::size_t i = 0; i < scan.entries.size(); ++i) {
        if (scan.entries[i].type != format::EntryType::directory) continue;
        const auto path = scan.paths[i];
        if (io::inspect_source(path) != scan.snapshots[i]) throw std::runtime_error("Source directory changed during scan");
        std::vector<std::filesystem::path> children;
        for (const auto& child : std::filesystem::directory_iterator(path)) {
            if (children.size() >= limits.max_entries - std::min<std::size_t>(scan.entries.size(), limits.max_entries))
                throw std::length_error("Directory Entry count exceeds policy");
            children.push_back(child.path());
        }
        std::sort(children.begin(), children.end(), [](const auto& a, const auto& b) { return utf8_name(a) < utf8_name(b); });
        for (const auto& child : children) {
            if (depths[i] >= limits.max_depth || scan.entries.size() >= limits.max_entries || scan.entries.size() >= 0xFFFFFFFF)
                throw std::length_error("Directory count or depth exceeds policy");
            auto name = utf8_name(child);
            format::validate_entry_name(name);
            const auto entry_size = encoded_entry_size(name);
            if (name.size() > limits.max_name_bytes || index_size > limits.max_index_bytes ||
                entry_size > limits.max_index_bytes - index_size) throw std::length_error("Directory Index or Name exceeds policy");
            index_size += entry_size;
            const auto info = io::inspect_source(child);
            if (index_size > limits.max_output_bytes || offset > limits.max_output_bytes - index_size ||
                (!info.directory && info.size > limits.max_output_bytes - index_size - offset))
                throw std::length_error("Directory data exceeds policy");
            scan.entries.push_back({static_cast<std::uint32_t>(scan.entries.size()), scan.entries[i].id,
                info.directory ? format::EntryType::directory : format::EntryType::file, info.directory ? 0 : offset,
                info.directory ? 0 : info.size, std::move(name)});
            scan.paths.push_back(child);
            scan.snapshots.push_back(info);
            depths.push_back(depths[i] + 1);
            if (!info.directory) offset += info.size;
        }
    }
    auto index = format::serialize_index(scan.entries, limits);
    scan.index.assign(reinterpret_cast<const std::uint8_t*>(index.data()),
        reinterpret_cast<const std::uint8_t*>(index.data()) + index.size());
    std::fill(index.begin(), index.end(), std::byte{0});
    if (scan.index.size() > limits.max_output_bytes || offset > limits.max_output_bytes - scan.index.size())
        throw std::length_error("Directory archive exceeds output policy");
    scan.payload_size = scan.index.size() + offset;
    verify_scan(scan);
    return scan;
}

void verify_scan(const DirectoryScan& scan) {
    std::set<std::pair<std::uint32_t, std::string_view>> children;
    std::vector<std::size_t> counts(scan.entries.size());
    for (std::size_t i = 1; i < scan.entries.size(); ++i) {
        const auto& entry = scan.entries[i];
        children.emplace(entry.parent_id, entry.name);
        ++counts[entry.parent_id];
    }
    for (std::size_t i = 0; i < scan.paths.size(); ++i) {
        if (io::inspect_source(scan.paths[i]) != scan.snapshots[i]) throw std::runtime_error("Source tree changed during encryption");
        if (scan.entries[i].type == format::EntryType::directory) {
            std::size_t count{};
            for (const auto& child : std::filesystem::directory_iterator(scan.paths[i])) {
                const auto name = utf8_name(child.path());
                if (!children.contains({scan.entries[i].id, name}) || ++count > counts[i])
                    throw std::runtime_error("Source directory contents changed during encryption");
            }
            if (count != counts[i]) throw std::runtime_error("Source directory contents changed during encryption");
        }
    }
}

std::size_t DirectoryReader::read(std::span<std::byte> bytes) {
    if (bytes.empty()) return 0;
    if (index_position_ < scan_.index.size()) {
        const auto count = std::min(bytes.size(), scan_.index.size() - index_position_);
        std::copy_n(reinterpret_cast<const std::byte*>(scan_.index.data()) + index_position_, count, bytes.data());
        index_position_ += count;
        return count;
    }
    while (entry_ < scan_.entries.size()) {
        const auto& entry = scan_.entries[entry_];
        if (entry.type != format::EntryType::file) { ++entry_; continue; }
        if (!file_) {
            // 重新核对祖先目录，避免可观察的链接替换。
            auto parent = entry.parent_id;
            while (parent != 0xFFFFFFFF) {
                if (io::inspect_source(scan_.paths[parent]) != scan_.snapshots[parent]) throw std::runtime_error("Source ancestor changed");
                parent = scan_.entries[parent].parent_id;
            }
            file_ = std::make_unique<io::SourceFile>(scan_.paths[entry_], scan_.snapshots[entry_]);
            remaining_ = entry.data_length;
        }
        if (remaining_) {
            const auto count = file_->read(bytes.first(static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, bytes.size()))));
            if (!count) throw std::runtime_error("Source file shortened during encryption");
            remaining_ -= count;
            return count;
        }
        std::byte extra{};
        if (file_->read({&extra, 1}) != 0) throw std::runtime_error("Source file grew during encryption");
        file_->verify_unchanged();
        file_.reset(); ++entry_;
    }
    return 0;
}

void restore_directory(io::OutputTransaction& payload, std::uint64_t index_length,
    const std::filesystem::path& output, const directory::Limits& limits) {
    const auto length = payload.size();
    if (length > limits.max_output_bytes || index_length > limits.max_index_bytes || index_length > length ||
        index_length > std::numeric_limits<std::size_t>::max()) throw std::length_error("Directory payload or Index exceeds policy");
    crypto::SecureBytes index(static_cast<std::size_t>(index_length));
    payload.seek(0);
    read_exact(payload, std::as_writable_bytes(std::span(index)));
    const auto entries = format::deserialize_index(std::as_bytes(std::span(index)), length - index_length, limits);
    index.clear();
    for (std::size_t i = 1; i < entries.size(); ++i) io::validate_target_name(entries[i].name);
    auto parent_index = [&](std::uint32_t id) {
        return static_cast<std::size_t>(std::lower_bound(entries.begin(), entries.end(), id,
            [](const auto& entry, auto key) { return entry.id < key; }) - entries.begin());
    };
    io::DirectoryTransaction tree(output);
    std::vector<bool> created(entries.size());
    created[0] = true;
    // 不缓存所有展开路径，避免共享深祖先使内存按条目数乘深度增长。
    auto target_path = [&](std::size_t node) {
        std::vector<std::size_t> chain;
        while (node) { chain.push_back(node); node = parent_index(entries[node].parent_id); }
        auto path = tree.root();
        while (!chain.empty()) {
            const auto current = chain.back(); chain.pop_back();
            const auto& entry = entries[current];
            path /= std::filesystem::path(std::u8string(entry.name.begin(), entry.name.end()));
            if (entry.type == format::EntryType::directory && !created[current]) {
                io::create_restricted_directory(path);
                created[current] = true;
            }
        }
        return path;
    };
    for (std::size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].type == format::EntryType::directory) (void)target_path(i);
    }
    crypto::SecureBytes buffer(65536);
    for (std::size_t i = 1; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        if (entry.type != format::EntryType::file) continue;
        io::OutputTransaction file(target_path(i));
        payload.seek(index_length + entry.data_offset);
        auto remaining = entry.data_length;
        while (remaining) {
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
            auto part = std::as_writable_bytes(std::span(buffer)).first(count);
            read_exact(payload, part); file.write(part); remaining -= count;
        }
        file.commit();
    }
    tree.commit();
}
}
