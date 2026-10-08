# FileCrypt v1 Architecture

**架构版本：v1**  
**状态：Design / 已确定**

本文定义 FileCrypt 程序内部架构。

---

# 1. 总体架构

```text
                         ┌───────────────┐
                         │      CLI      │
                         └───────┬───────┘
                                 │
                                 ▼
                       ┌──────────────────┐
                       │   Application    │
                       │                  │
                       │ Encrypt / Decrypt│
                       │ Inspect          │
                       └───────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
       ┌──────────┐      ┌──────────┐      ┌──────────┐
       │   IO     │      │  Format  │      │  Crypto  │
       └──────────┘      └──────────┘      └────┬─────┘
                                                │
                                                ▼
                                        Crypto Backend
```

核心原则：

- Application 负责业务流程编排。
- Format 负责 FileCrypt 文件格式。
- Crypto 负责密码学操作。
- IO 负责文件读写与定位。
- Backend 负责调用具体第三方密码学库。

Format 不实现密码学。
Crypto 不理解 `.fcry` 文件格式。
IO 不理解加密逻辑。

---

# 2. 项目目录

```text
FileCrypt/
├── CMakeLists.txt
├── LICENSE
├── README.md
│
├── docs/
│   ├── FILE_FORMAT.md
│   ├── DIRECTORY_FORMAT.md
│   ├── ARCHITECTURE.md
│   └── CRYPTOGRAPHY.md
│
├── include/
│   └── filecrypt/
│       ├── app/
│       │   ├── encrypt.hpp
│       │   ├── decrypt.hpp
│       │   └── inspect.hpp
│       │
│       ├── crypto/
│       │   ├── algorithm.hpp
│       │   ├── kdf.hpp
│       │   ├── cipher.hpp
│       │   ├── compression.hpp
│       │   └── registry.hpp
│       │
│       ├── format/
│       │   ├── header.hpp
│       │   ├── metadata.hpp
│       │   ├── layout.hpp
│       │   └── directory.hpp
│       │
│       └── io/
│           ├── file.hpp
│           └── stream.hpp
│
├── src/
│   ├── app/
│   ├── crypto/
│   ├── format/
│   ├── io/
│   └── main.cpp
│
└── tests/
    ├── format/
    ├── crypto/
    ├── io/
    └── integration/
```

---

# 3. CLI 层

CLI 是最外层入口。

主要职责：

```text
解析命令
解析参数
读取用户选项
调用 Application
显示结果
```

CLI 不负责：

```text
AES
KDF
Header
Metadata
Archive
文件加密流程
```

---

# 4. Application 层

Application 是业务流程控制层。

主要功能：

```text
Encrypt
Decrypt
Inspect
```

Application 负责协调：

```text
IO
Format
Crypto
```

并根据输入决定 Plaintext 是：

```text
Single File
```

还是：

```text
Directory Archive
```

Application 不实现具体密码算法，也不实现具体格式序列化。

---

# 5. Format 层

Format 层负责：

- Fixed Header
- Metadata
- Metadata Layout
- Directory Index
- 二进制序列化与反序列化

Format 层不调用密码学 Backend。

---

# 6. Header

Header 表示 FileCrypt v1 的固定 32-byte Header：

```text
Magic
Version
Flags
Algorithm
File Type
Metadata Length
Reserved
```

Header 类型表示逻辑字段；具体二进制布局由显式序列化器实现。

禁止依赖 C++ struct 的内存布局直接写文件。

---

# 7. Metadata

Metadata 根据当前容器类型和 Header Flags 变化。

`Flags.Bit14` 是压缩状态的唯一来源：

```text
Bit 14 = 0
    → 不压缩
    → Metadata 不存在 Compression ID / Parameters Length / Parameters

Bit 14 = 1
    → 压缩
    → Metadata 必须存在 Compression ID / Parameters Length / Parameters
```

### Single File

未压缩：

```text
KDF ID
KDF Parameters
Salt
Nonce
Padding
Authentication Tag
```

压缩：

```text
Compression ID
Compression Parameters Length
Compression Parameters
KDF ID
KDF Parameters
Salt
Nonce
Padding
Authentication Tag
```

### Directory Archive

未压缩：

```text
Index Length
KDF ID
KDF Parameters
Salt
Nonce
Padding
Authentication Tag
```

压缩：

```text
Index Length
Compression ID
Compression Parameters Length
Compression Parameters
KDF ID
KDF Parameters
Salt
Nonce
Padding
Authentication Tag
```

因此 Metadata 不是一个对所有容器完全固定的 C++ struct。

---

# 8. MetadataLayout

`MetadataLayout` 的职责是：

> 根据当前 FileCrypt Version、Flags、KDF 和 Algorithm，计算 Metadata 的布局与长度；当 `Flags.Bit14 = 1` 时，同时使用 Compression Definition。

其输入至少包括：

```text
Version
Flags
KDF Definition
Algorithm Definition
Compression Definition（仅当 Flags.Bit14 = 1）
```

其中 `Flags.Bit15` 决定是否存在 Directory-specific Metadata（`Index Length`），`Flags.Bit14` 决定是否存在 Compression Metadata。

逻辑关系：

```text
Version
Container Type
Compression
KDF ID
Algorithm ID
        ↓
   Registries
        ↓
MetadataLayout
```

MetadataLayout 负责计算：

```text
Compression Parameters Size
Compression Parameters Length Size（2 bytes，仅压缩时）
KDF Parameters Size
Salt Size
Nonce Size
Tag Size
Padding Size
Metadata Size
Encrypted Raw Offset
```

其中：

```text
MetadataSize = 实际 Metadata + Padding

EncryptedRawOffset = 32 + MetadataSize
```

MetadataLayout 不负责：

```text
保存 Metadata 内容
读取文件
写文件
执行 KDF
执行加密
```

---

# 9. Metadata

Metadata 对象保存实际 Metadata 数据，例如：

```text
Index Length（仅 Directory）
Compression ID / Parameters Length / Parameters（仅 Flags.Bit14 = 1）
KDF ID
KDF Parameters
Salt
Nonce
Authentication Tag
```

其中 Compression 状态本身不在 Metadata 中重复保存。是否存在 Compression 字段完全由 Header.Flags.Bit14 决定。

其中 Directory-specific 的 `Index Length` 由 Container Type 决定是否存在。

---

# 10. MetadataWriter

MetadataWriter 负责：

> 按 MetadataLayout 将 Metadata 对象序列化为 FileCrypt Metadata。

包括：

```text
Index Length（仅 Directory）
Compression ID / Parameters Length / Parameters（仅 Flags.Bit14 = 1）
KDF ID
KDF Parameters
Salt
Nonce
Zero Padding
Authentication Tag
```

实际存在的字段取决于当前 Container Type 和 Compression 状态。

Padding 由 MetadataWriter 最终生成。

---

# 11. MetadataReader

MetadataReader 首先根据 Header 中已经可用的信息确定外层布局：

```text
Version
Flags
Algorithm
Metadata Length
```

随后按照 v1 固定字段顺序读取 Metadata 中的 KDF ID，以及在 `Flags.Bit14 = 1` 时读取 Compression ID，并查询对应 Registry 解析后续参数。

KDF Definition 和 Compression Definition 不作为“预先已知”的输入；它们由 Metadata 中各自的 ID 在解析过程中确定。

它只负责格式解析，不负责：

```text
KDF
解密
Compression
Authentication
```

---

# 12. Directory Format 层

Directory Archive 的明文内容由 Directory Format 负责解释：

```text
Entry
├── ID
├── Parent ID
├── Type
├── Data Offset
├── Data Length
├── Name Length
└── Name
```

Index 的结束由 Metadata 中的 `Index Length` 决定。

Directory Format 不增加第二个 Magic、Version 或独立 Archive Header。

---

# 13. Algorithm Registry

Algorithm Registry 建立：

```text
Algorithm ID
    ↓
Algorithm Definition
```

Algorithm Definition 提供至少：

```text
Key Size
Nonce Size
Tag Size
Cipher implementation
```

Algorithm Registry 可以同时包含多个 AEAD 算法，例如 AES-GCM 与 XChaCha20-Poly1305。它们是并列的可选实现，并非只能保留一种。每个 `.fcry` 文件通过 Header 中的 Algorithm ID 选择一个具体算法。

MetadataLayout 和 CipherContext 创建流程都使用 Algorithm Registry。

---

# 14. KDF Registry

KDF Registry 建立：

```text
KDF ID
    ↓
KDF Definition
```

KDF Definition 提供至少：

```text
KDF Parameters Size
Salt Size
Derived Key Size
KDF implementation
```

MetadataLayout 和 KDF 执行流程都使用 KDF Registry。

Derived Key Size 从 Algorithm Definition 的 Key Size 得到，不作为 KDF 独立固定值，也不单独写入 Metadata。v1 的编号和字段长度统一以 `REGISTRY_V1.md` 为准。

---

# 15. Compression Registry

Compression Registry 建立：

```text
Compression ID
    ↓
Compression Definition
```

Compression Definition 提供至少：

```text
Compression Parameters Size
Compression implementation
```

只有 `Flags.Bit14 = 1` 时才查询 Compression Registry。

Header 的 `Flags.Bit14` 只表示“是否压缩”；具体 Compression ID 和 Parameters 位于 Metadata。Header 不重复保存具体压缩算法信息。
当 `Flags.Bit14 = 0` 时，Metadata 中不得出现 Compression 字段，也不查询 Compression Registry。

---

# 16. CipherContext

CipherContext 负责流式 AEAD 加密/解密。

模型：

```text
update()
update()
update()
...
finalize()
```

加密：

```text
Plaintext
   ↓
update()
   ↓
Ciphertext
```

最终：

```text
finalize()
   ↓
Authentication Tag
```

`finalize()` 返回 Tag。

CipherContext 不直接：

```text
写文件
修改 Metadata
Seek
写 Header
```

Application 负责把返回的 Tag 写入 Metadata 对象。

---

# 17. Compression Layer

启用压缩时，Application 将 Plaintext Stream 依次经过：

```text
Plaintext
   ↓
Compression
   ↓
CipherContext
   ↓
Ciphertext
```

解密时反向：

```text
Ciphertext
   ↓
CipherContext
   ↓
Decompression
   ↓
Plaintext
```

Compression 层不理解 `.fcry` 文件格式。

---

# 18. IO 层

IO 层只负责：

```text
read()
write()
seek()
tell()
size()
```

IO 层不知道：

```text
FCRY
AES
KDF
Metadata
AAD
Directory Index
```

---

# 19. Encrypt 流程

加密开始前，可以确定除 Authentication Tag 值之外的全部文件结构信息。

流程：

```text
用户选项
    ↓
读取输入类型
    ↓
确定 Container Type / Compression State
    ↓
Algorithm Registry
    ↓
KDF Registry
    ↓
Compression Registry（仅当 Flags.Bit14 = 1）
    ↓
生成 KDF Parameters
    ↓
生成 Salt
    ↓
生成 Nonce
    ↓
MetadataLayout
    ↓
计算 Metadata Length
    ↓
计算 EncryptedRawOffset
    ↓
构造 Header
    ↓
构造 Metadata（Tag 尚未知）
    ↓
构造 AAD
    ↓
Seek 到 EncryptedRawOffset
    ↓
Plaintext
    ↓
Compression（如果启用）
    ↓
CipherContext::update()
    ↓
写 Ciphertext
    ↓
CipherContext::finalize()
    ↓
得到 Authentication Tag
    ↓
写入 Metadata 对象
    ↓
Seek 到 0
    ↓
Write Header
    ↓
Write Metadata
```

---

# 20. Decrypt 流程

```text
读取 Header
    ↓
验证 Magic / Version / Flags
    ↓
确定 Container Type / Compression State
    ↓
查询 Algorithm Registry
    ↓
读取 Metadata 中用于识别布局的固定 ID 字段
    ↓
读取 KDF ID / Compression ID（若存在）
    ↓
查询 KDF / Compression Registry
    ↓
MetadataLayout
    ↓
按 Layout 解析完整 Metadata
    ↓
构造 AAD
    ↓
Password → KDF → Key
    ↓
Seek 到 EncryptedRawOffset
    ↓
CipherContext
    ↓
Decompression（如果启用）
    ↓
Single File / Directory Archive
```

认证失败时不得提交最终输出文件。

---

# 21. Inspect

`info` 命令无需执行解密。

流程：

```text
.fcry
 ↓
Header
 ↓
Version / Flags
 ↓
Container Type
 ↓
Compression
 ↓
Registry
 ↓
Metadata
 ↓
显示信息
```

---

# 22. 临时文件与 Commit

最终输出使用临时文件：

```text
output.fcry.tmp
```

成功完成加密并写回 Header / Metadata 后，才提交为：

```text
output.fcry
```

解密同样在认证和输出完成后 Commit。

临时文件机制属于 Application / IO 层，不属于文件格式。

---

# 23. 核心依赖关系

```text
CLI
 │
 ▼
Application
 ├───────────────┐
 ▼               ▼
Format          Crypto
 │               │
 ▼               ▼
IO             Backend
```

Application 是主要编排者。

避免出现：

```text
Crypto → Format
Format → Crypto
IO → Crypto
IO → Format
```

---

# 24. 核心原则

```text
Registry
   ↓
MetadataLayout
   ↓
Application 规划文件布局
   ↓
Compression（可选）
   ↓
Crypto 产生 Ciphertext
   ↓
Application 得到 Tag
   ↓
Format 最终写入 Header + Metadata
```

FileCrypt 的程序架构必须保持：

> Format 负责“文件怎么表示”，Crypto 负责“数据怎么加密”，Application 负责“这些步骤怎么串起来”。
