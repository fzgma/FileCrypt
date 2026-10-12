#include <filecrypt/format/v1/aad.hpp>

#include <iostream>
#include <stdexcept>

using namespace filecrypt::format::v1;

int main() {
    Header header;
    header.version = 1;
    header.algorithm = 1;
    header.file_type = 0xFFFE;
    header.metadata_length = metadata_layout(header).metadata_size;
    const auto bytes = serialize(header);

    const auto parsed = try_deserialize(bytes);
    if (!parsed || parsed->version != header.version) return 1;

    auto invalid = bytes;
    invalid[0] = std::byte{0};
    const auto rejected = try_deserialize(invalid);
    if (rejected || rejected.error().code != filecrypt::ErrorCode::invalid_argument ||
        rejected.error().message.empty()) return 1;

    const auto aad = try_build_aad(std::span<const std::byte>(bytes).first(31), {});
    if (aad || aad.error().code != filecrypt::ErrorCode::invalid_argument) return 1;

    std::cout << "Expected format API tests passed\n";
}
