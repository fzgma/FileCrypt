# TODO

## 目标

实现 FileCrypt v1 外层固定 Header 的基础数据结构、Little-Endian 序列化/反序列化以及单元测试。

本提交只处理 **Header**。

不要实现：

* Metadata
* KDF
* 加密算法
* 压缩
* Directory Archive
* CLI
* 文件加解密流程
* 第三方密码库

提交完成后，应当能够在内存中完成：

```text
Header object
    ↓
serialize
    ↓
32 bytes
    ↓
deserialize
    ↓
Header object
```

并证明序列化结果严格符合 `docs/SPEC.md` 中定义的 FileCrypt v1 Header。

---

# 1. 需要创建/修改的文件

推荐结构：

```text
include/
└── filecrypt/
    └── format/
        └── header.hpp

src/
└── format/
    └── header.cpp

tests/
└── format/
    └── header_test.cpp
```

如果项目当前还没有完整 CMake 测试结构，可以在本提交中同时加入最小的 CTest / 测试 target，但不要引入其他功能。

---

# 2. Header 格式

FileCrypt v1 Header 固定为 **32 bytes**。

| Offset | Size | Field           |
| -----: | ---: | --------------- |
| `0x00` |    4 | Magic           |
| `0x04` |    2 | Version         |
| `0x06` |    2 | Flags           |
| `0x08` |    2 | Algorithm       |
| `0x0A` |    2 | File Type       |
| `0x0C` |    8 | Metadata Length |
| `0x14` |   12 | Reserved        |

总长度：

```text
4 + 2 + 2 + 2 + 2 + 8 + 12 = 32 bytes
```

所有多字节整数：

```text
Little-Endian
```

---

# 3. Header 数据结构

定义一个表示逻辑 Header 的 C++ 类型。

建议：

```cpp
struct Header {
    uint16_t version;
    uint16_t flags;
    uint16_t algorithm;
    uint16_t file_type;
    uint64_t metadata_length;
    std::array<std::byte, 12> reserved{};
};
```

Magic 不需要作为普通可修改字段存储。

可以由序列化器固定写入：

```text
FCRY
```

或者在 Header 类型中提供固定常量。

---

# 4. Header 不得直接内存映射到文件

禁止使用：

```cpp
file.write(
    reinterpret_cast<const char*>(&header),
    sizeof(header)
);
```

也不要依赖：

```cpp
sizeof(Header)
```

来决定文件格式大小。

原因：

* struct padding
* ABI
* 编译器布局
* 平台差异

文件格式布局必须通过显式序列化实现。

---

# 5. 序列化

实现类似：

```cpp
std::array<std::byte, 32> serialize(const Header& header);
```

要求：

### Offset `0x00`

固定写入：

```text
46 43 52 59
```

即：

```text
F C R Y
```

### Offset `0x04`

写入：

```text
version
```

Little-Endian。

### Offset `0x06`

写入：

```text
flags
```

Little-Endian。

注意当前 Flags 已定义：

```text
Bit 15 = Container Type
    0 = Single File
    1 = Directory Archive

Bit 14 = Compression
    0 = Uncompressed
    1 = Compressed
```

因此这些值必须能够正确序列化：

```text
0x0000
0x4000
0x8000
0xC000
```

### Offset `0x08`

写入：

```text
algorithm
```

Little-Endian。

### Offset `0x0A`

写入：

```text
file_type
```

Little-Endian。

### Offset `0x0C`

写入：

```text
metadata_length
```

8 bytes，Little-Endian。

### Offset `0x14`

写入 12 bytes：

```text
reserved
```

---

# 6. 反序列化

实现类似：

```cpp
Header deserialize(std::span<const std::byte> data);
```

基本要求：

```text
输入长度 < 32
    ↓
失败
```

输入不是：

```text
FCRY
```

则失败。

反序列化后必须正确恢复：

```text
Version
Flags
Algorithm
File Type
Metadata Length
Reserved
```

---

# 7. Magic 校验

Magic 必须严格检查：

```text
46 43 52 59
```

即：

```text
"FCRY"
```

例如：

```text
FCry
fcry
FCRX
```

都不是合法 Magic。

错误行为至少需要能够被测试检测。

具体使用 exception、error code 或项目统一错误类型，由当前项目实现决定。

不要为了这个提交引入复杂的错误体系。

---

# 8. Reserved

v1 Header 的 Reserved：

```text
12 bytes
```

序列化时原样写入。

测试至少覆盖：

```text
all zero
```

以及非零数据能否正确 round-trip。

注意：

> Header 二进制层负责读写 Reserved，不在这一提交中决定 Reserved 的业务校验策略。

也就是说，不需要在 `Header::deserialize()` 中自行扩展未来协议语义。

---

# 9. Round-trip Test

必须有：

```text
Header
    ↓
serialize
    ↓
deserialize
    ↓
Header
```

测试两个 Header 对象逻辑上完全一致。

至少测试：

```text
version
flags
algorithm
file_type
metadata_length
reserved
```

---

# 10. 固定二进制布局测试

不要只做 round-trip。

必须直接检查序列化后的字节。

例如构造：

```text
version         = 0x1234
flags           = 0x8000
algorithm       = 0x0102
file_type       = 0x0304
metadata_length = 0x0102030405060708
reserved        = 12 bytes of known values
```

然后检查输出：

```text
Offset  Expected
0x00    46 43 52 59
0x04    34 12
0x06    00 80
0x08    02 01
0x0A    04 03
0x0C    08 07 06 05 04 03 02 01
...
```

这样可以证明确实是 Little-Endian，而不是仅仅“序列化后又自己正确地反序列化回来”。

---

# 11. Flags 测试

必须至少测试：

```text
0x0000
0x4000
0x8000
0xC000
```

确认二进制结果：

```text
0x0000 → 00 00
0x4000 → 00 40
0x8000 → 00 80
0xC000 → 00 C0
```

这一测试特别重要，因为 Flags 的 Bit 14 / Bit 15 已经属于正式文件格式。

---

# 12. 边界测试

至少加入：

### Metadata Length = 0

```text
0
```

### Metadata Length = 16

```text
16
```

### 最大 uint64

```text
0xFFFFFFFFFFFFFFFF
```

确认序列化不会截断。

### Reserved 全部为 `0x00`

### Reserved 全部为 `0xFF`

---

# 13. 非法输入测试

至少测试：

```text
空数据
1 byte
31 bytes
```

都不能成功解析为 Header。

Magic 错误：

```text
FCRX
```

也必须失败。

---

# 14. API 约束

Header 层应该只负责：

```text
Header object
    ↕
32-byte binary representation
```

不要在这一层实现：

```text
KDF
AEAD
Compression
File IO
Password
Directory
CLI
```

不要让 Header 类依赖：

```text
libsodium
OpenSSL
zstd
```

---

# 15. CMake 要求

本提交需要保证：

```text
cmake configure
cmake build
ctest
```

能够运行。

如果当前项目尚无测试框架，允许选择一个轻量的测试方案。

不要为了测试 Header 引入大型第三方依赖。

---

# 16. 完成标准

本提交完成后，应满足：

```text
[✓] Header 类型存在
[✓] Header 固定序列化为 32 bytes
[✓] Magic 正确
[✓] 所有整数 Little-Endian
[✓] Reserved 正确处理
[✓] serialize / deserialize 可互相转换
[✓] 固定二进制布局测试通过
[✓] Flags 四种当前合法组合测试通过
[✓] 非法 Header 测试通过
[✓] CMake build 成功
[✓] Tests 全部通过
```

---

# 17. 本提交禁止做的事情

不要顺手实现：

```text
 Metadata
 MetadataLayout
 KDF
 Algorithm Registry
 Crypto Backend
 Compression
 Directory Archive
 Password
 Encrypt / Decrypt
 CLI
```

即使发现这些模块未来需要某个公共类型，也暂时不要为了“提前设计”把它们一起实现。

---



# 18. 提交后的预期状态

代码仓库完成第一次真正的功能提交后，应该达到：

```text
FileCrypt
│
├── 能识别 FCRY Header
├── 能构造 v1 Header
├── 能序列化 Header
├── 能反序列化 Header
└── 能通过测试证明二进制布局正确
```

**除此之外，FileCrypt 还不能加密任何东西。**

这是刻意控制的范围：第一提交只建立整个文件格式实现的最底层基础。
