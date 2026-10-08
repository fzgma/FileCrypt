#include <filecrypt/io/file.hpp>
#include <istream>
#include <stdexcept>

namespace filecrypt::io {
/// 从输入流读取全部目标字节，截断或读取失败时抛出异常。
void read_exact(std::istream& input, std::span<std::byte> bytes) {
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input) {
        throw std::runtime_error("Truncated input or read failure");
    }
}
}
