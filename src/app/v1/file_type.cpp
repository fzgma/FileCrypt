#include "file_type.hpp"
#include <filecrypt/format/v1/registry.hpp>
#include <filecrypt/crypto/crypto.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

namespace filecrypt::app::v1 {
namespace {
namespace format = filecrypt::format::v1;
using namespace std::string_view_literals;

std::string lower_ascii(const std::u8string& text) {
    std::string result(text.begin(), text.end());
    for (auto& value : result) {
        if (value >= 'A' && value <= 'Z') value += 'a' - 'A';
    }
    return result;
}

bool match(std::string_view data, std::size_t offset, std::string_view signature) {
    return offset <= data.size() && data.substr(offset).starts_with(signature);
}

// 仅解析有界 EBML Header 中的 DocType，避免把 WebM 等也当作 Matroska。
bool matroska_header(std::string_view data) {
    if (!match(data, 0, "\x1a\x45\xdf\xa3"sv)) return false;
    std::size_t position = 4;
    auto vint = [&](bool id, std::uint64_t& value) {
        if (position >= data.size()) return false;
        const auto first = static_cast<unsigned char>(data[position]);
        unsigned length = 1;
        unsigned mask = 0x80;
        while (mask && !(first & mask)) { mask >>= 1; ++length; }
        if (!mask || length > (id ? 4u : 8u) || length > data.size() - position) return false;
        value = id ? first : first & (mask - 1);
        for (unsigned i = 1; i < length; ++i) {
            value = (value << 8) | static_cast<unsigned char>(data[position + i]);
        }
        position += length;
        return true;
    };
    std::uint64_t length{};
    if (!vint(false, length) || length > data.size() - position) return false;
    const auto end = position + static_cast<std::size_t>(length);
    data = data.substr(0, end);
    while (position < end) {
        std::uint64_t id{}, size{};
        if (!vint(true, id) || !vint(false, size) || size > end - position) return false;
        if (id == 0x4282) return data.substr(position, static_cast<std::size_t>(size)) == "matroska";
        position += static_cast<std::size_t>(size);
    }
    return false;
}

std::string_view magic_extension(std::string_view data) {
    if (match(data, 0, "\x89PNG\r\n\x1a\n"sv)) return "png";
    if (match(data, 0, "\xff\xd8\xff"sv)) return "jpg";
    if (match(data, 0, "GIF87a") || match(data, 0, "GIF89a")) return "gif";
    if (match(data, 0, "BM")) return "bmp";
    if (match(data, 0, "II\x2a\0"sv) || match(data, 0, "MM\0\x2a"sv)) return "tif";
    if (match(data, 0, "%PDF-")) return "pdf";
    if (match(data, 0, "PK\x03\x04"sv) || match(data, 0, "PK\x05\x06"sv) ||
        match(data, 0, "PK\x07\x08"sv)) return "zip";
    if (match(data, 0, "7z\xbc\xaf\x27\x1c"sv)) return "7z";
    if (match(data, 0, "Rar!\x1a\x07\0"sv) || match(data, 0, "Rar!\x1a\x07\x01\0"sv)) return "rar";
    if (match(data, 0, "\x1f\x8b\x08"sv)) return "gz";
    if (match(data, 0, "BZh") && data.size() >= 4 && data[3] >= '1' && data[3] <= '9') return "bz2";
    if (match(data, 0, "\xfd" "7zXZ\0"sv)) return "xz";
    if (match(data, 0, "\x28\xb5\x2f\xfd"sv)) return "zst";
    if (match(data, 0, "ID3")) return "mp3";
    if (match(data, 0, "fLaC")) return "flac";
    if (match(data, 0, "RIFF")) {
        if (match(data, 8, "WEBP")) return "webp";
        if (match(data, 8, "WAVE")) return "wav";
        if (match(data, 8, "AVI ")) return "avi";
    }
    if (data.size() >= 16 && match(data, 4, "ftyp")) {
        const auto brand = data.substr(8, 4);
        if (brand == "qt  ") return "mov";
        for (const auto known : {"isom", "iso2", "mp41", "mp42", "avc1", "M4V "}) {
            if (brand == known) return "mp4";
        }
    }
    if (matroska_header(data)) return "mkv";
    // ustar 需要完整的首个 512-byte 块及合法校验和。
    if (data.size() == 512 && (match(data, 257, "ustar\0"sv) || match(data, 257, "ustar "))) {
        unsigned checksum{}, expected{};
        bool digit = false;
        for (std::size_t i = 0; i < 512; ++i) {
            checksum += i >= 148 && i < 156 ? ' ' : static_cast<unsigned char>(data[i]);
        }
        for (std::size_t i = 148; i < 156; ++i) {
            if (data[i] >= '0' && data[i] <= '7') {
                if (expected > 0x1FFFFF) return {};
                expected = expected * 8 + data[i] - '0';
                digit = true;
            } else if (data[i] != '\0' && data[i] != ' ') return {};
        }
        if (digit && expected == checksum) return "tar";
    }
    return {};
}
}

std::uint16_t detect_file_type(const std::filesystem::path& path, std::istream& input) {
    const auto filename = lower_ascii(path.filename().u8string());
    const format::FileTypeDefinition* longest = nullptr;
    for (const auto& type : format::file_type_definitions()) {
        if (type.extension.find('.') != std::string_view::npos &&
            filename.ends_with("." + std::string(type.extension)) &&
            (!longest || type.extension.size() > longest->extension.size())) {
            longest = &type;
        }
    }
    if (longest) return longest->id;
    if (path.has_extension()) {
        const auto extension = lower_ascii(path.extension().u8string());
        return format::file_type_id(std::string_view(extension).substr(1));
    }
    const auto position = input.tellg();
    if (position == std::istream::pos_type(-1)) throw std::runtime_error("Cannot locate input for magic detection");
    crypto::SecureBytes header(512);
    input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    const auto count = input.gcount();
    if (input.bad() || (input.fail() && !input.eof())) throw std::runtime_error("Magic detection read failed");
    input.clear();
    input.seekg(position);
    if (!input) throw std::runtime_error("Cannot restore input after magic detection");
    return format::file_type_id(magic_extension({reinterpret_cast<const char*>(header.data()),
        static_cast<std::size_t>(count)}));
}

std::filesystem::path restore_file_extension(std::filesystem::path path, std::uint16_t type) {
    const auto extension = format::file_type_definition(type).extension;
    if (!extension.empty() && path.has_filename() && !path.has_extension() &&
        path.filename() != "." && path.filename() != "..") {
        path += "." + std::string(extension);
    }
    return path;
}
}
