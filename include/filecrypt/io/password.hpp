#pragma once
#include <botan/secmem.h>
#include <cstdint>
#include <string_view>

namespace filecrypt::io {
/// 从终端或标准输入读取一行密码，终端关闭回显，返回安全容器中的 UTF-8 字节。
[[nodiscard]] Botan::secure_vector<std::uint8_t> read_password(std::string_view prompt);
}
