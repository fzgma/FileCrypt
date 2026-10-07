# Botan AEAD proof of concept

此目录是独立的 C++23 技术验证工程，位于 `poc/botan-aead` 分支。
它不实现 `.fcry`、正式 CLI 或文件加解密，不修改现有 Hello World。

## 依赖和构建

需要 Botan 3（包含 AES/GCM、ChaCha20Poly1305、Argon2id、AutoSeeded_RNG）、
CMake >= 3.24、C++23 编译器。项目配置不包含本机路径。

```sh
cmake -S poc -B build-poc -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-poc
ctest --test-dir build-poc --output-on-failure
```

Botan 安装在非默认位置时，配置增加 `-DCMAKE_PREFIX_PATH=<安装前缀>`。
编译器和 Botan 必须来自兼容的工具链：MSVC 使用 MSVC 构建的 Botan，
MinGW 使用 MinGW 构建的 Botan。运行时将 Botan DLL 所在目录加入 PATH；
Linux 非系统安装可设置 LD_LIBRARY_PATH。

Windows UCRT64 安装包：`mingw-w64-ucrt-x86_64-libbotan`、
`mingw-w64-ucrt-x86_64-cmake`、`mingw-w64-ucrt-x86_64-ninja`。
MSVC 和 Linux 可从 Botan 3.13.0 源码构建；三种环境的相同测试已配置于
`.github/workflows/botan-poc.yml`。当前实际验证是 Windows UCRT64 GCC 16.2.0 +
Botan 3.13.0 + Release；MSVC 和 Linux 的 CI 尚未执行，不能视为已通过。

## 已验证的能力

- AES-256-GCM：32 字节 Key、12 字节 Nonce、16 字节 Tag。
- XChaCha20-Poly1305：Botan 名称为 `ChaCha20Poly1305`，固定使用 24 字节 Nonce；
  32 字节 Key、16 字节 Tag。
- AEAD 增量处理、AAD、独立 Tag 的拆分/回接、不同输入分块得到相同结果。
- 固定 AES-GCM 与 XChaCha 向量、空明文、块边界、截断和篡改拒绝。
- Argon2id 显式参数派生 32 字节 Key；密码按字节处理，包含 NUL 和 UTF-8。
- Botan 安全随机数；Password/Key 使用者应选择安全容器，派生 Key 和 Backend
  缓冲区使用 `secure_vector`。测试中的密码与测试明文是非敏感固定样本。
- 计数器在提交 AEAD 输入前拒绝超限，避免整数溢出；测试不分配巨型文件。

Argon2id 测试使用 8 MiB、1 次迭代、1 lane，仅用于快速技术验证，
不作为正式程序的密码保护默认值。生产参数与持久化编码仍需另定。

## v1 单消息策略

| Algorithm | 最大 AEAD 输入字节数 |
|---|---:|
| AES-256-GCM | `2^36 - 32` = 68,719,476,704 |
| XChaCha20-Poly1305 | `2^38 - 64` = 274,877,906,880 |

超出抛出 `std::length_error("File too large for selected AEAD")`。
AES-GCM 限制来自 NIST SP 800-38D 的明文上限 `2^39 - 256` bits。
XChaCha 限制采用 Botan 所使用的 32-bit block-counter 构造的保守边界，
不是把所有名为 XChaCha 的构造都视为具有相同上限。

计数对象是**交给 AEAD 的实际输入**：压缩启用时是压缩后的字节，
目录模式还包括 Index；不是只检查原始文件 size。正式应用可以预检查已知长度，
但运行中的计数检查仍然必需。Tag 不计入明文/密文数据长度。
AAD 上限及完整容器长度检查将由正式实现补齐。

Botan 的 finish 将 Tag 附加到最终缓冲区。此 PoC 加密时拆出 Tag，
解密时把 Metadata 中读取的 Tag 回接到最后的缓冲区，因此无需改变外层格式。
增量解密产生的明文在 finish 前未认证；测试函数只在认证成功后返回完整结果。
正式应用应先写受控临时输出，认证成功才提交，目录也适用。

当前包安装的 Botan 是共享库；本 FindBotan 模块只验证共享库链接。
静态链接及其传递系统依赖不在此次验证范围。

## 参考

- [Botan AEAD 和 XChaCha nonce 语义](https://botan.randombit.net/handbook/api_ref/cipher_modes.html)
- [Botan 密码派生参数](https://botan.randombit.net/handbook/api_ref/pbkdf.html)
- [XChaCha 固定向量来源](https://github.com/randombit/botan/blob/3.9.0/src/tests/data/aead/chacha20poly1305.vec)
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
