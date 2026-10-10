# FileCrypt Architecture

**架构：版本隔离与共享基础能力**
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

# 2. 项目目录与版本边界

```text
include/filecrypt/
    app/operations.hpp          公共操作与展示结果
    format/detect.hpp           六字节版本识别
    format/v1/                  v1 Header、Metadata、Registry
    io/file.hpp                 共享文件操作
src/
    cli/main.cpp                参数与展示
    app/operations.cpp          版本分发
    app/v1/operations.cpp       v1 信息读取与样本流程
    format/detect.cpp
    format/v1/
    io/
    platform/
tests/
    format/detect_test.cpp
    format/v1/
    cli/
```

Application 读取 `FCRY + uint16 Version` 后分发，不能先把未知版本按 v1 Header 解析。
v1 的字段布局、Registry 和 AAD 实现属于 `filecrypt::format::v1`；未来版本独立新增模块，
不复用 v1 的裸协议编号或强制继承 v1 解析对象。当前不创建 v2 空目录。

公开 `FileInfo` 只包含展示信息，不暴露 Header、Metadata 或协议偏移。

`format/v1/aad.hpp` 提供两种 `build_aad` 入口：创建时序列化逻辑对象，
读取时校验原始 Header 与完整 Metadata 后直接拼接原始字节。
结果固定为 Header + Metadata[0 : TagOffset]，Padding 只包含一次，Tag 不参与。
对象入口允许 Tag 占位，真实 Tag 写回后 AAD 不变；原始 Header 输入必须恰好 32 bytes。
`SampleOptions` 显式携带创建版本，默认 v1；未知版本在文件创建前拒绝。
CLI 只依赖 Application；Application 调用 Format 和 IO；Format、IO 彼此独立。

Crypto 与 Compression 提供不依赖文件协议编号的基础能力，版本流程负责转换与编排。
临时输出和清理由 IO 提供，允许提交的时机由版本流程决定；当前已实现 v1 可选压缩的文件及目录加解密。

当前 Crypto 内存能力已位于 `include/filecrypt/crypto/crypto.hpp` 与 `src/crypto/botan/`，
由独立 `FileCrypt::Crypto` 库提供，依赖 Botan 而不依赖 Format、IO 或 Application。
算法枚举表达密码操作，不等于文件协议 ID。密钥派生显式接收参数和调用者资源策略，
当前提供 Argon2id 1.3 的 32 字节输出；安全容器基于 Botan 的安全分配器。

`CipherContext` 的实现通过私有对象隔离 Botan AEAD 模式，消息大小计数在处理输入前检查，
内部只缓存不足一个更新粒度的尾部。增量明文未经最终认证；高层内存 `decrypt`
暂存明文，认证成功才返回，认证失败统一为 `AuthenticationError`。
最终认证或处理失败后清理底层状态，拒绝任何再次使用。

`src/app/v1/crypt.cpp` 负责文件及目录载荷读写：加密生成随机 Salt/Nonce，
构造 Header、Metadata 和 AAD，以 64 KiB 安全缓冲区流式处理，最后写回真实 Tag。
解密保留原始 Header 与 Metadata 的认证字节，转换 v1 参数给 Crypto，
未认证明文只写入 `io::OutputTransaction`，`finish` 成功后才提交。
启用压缩时，独立 `FileCrypt::Compression` 层在加密之前输出 Zstandard 帧，
AEAD 计数压缩后的消息长度。压缩解密先认证临时载荷，再通过 IO 独占句柄回读并受限解压到第二个输出事务，
完整解压成功后才提交；中间事务始终不发布。窗口和累计输出上限属于运行策略，见 [压缩实现](COMPRESSION.md)。
目录模式由 `src/app/v1/directory.cpp` 扫描并流式提供 Index + File Data；Format 的 `directory.cpp` 负责独立编解码、UTF-8 单组件名称、树与连续数据校验。SourceFile 不跟随源链接并检查快照；DirectoryTransaction 提供受限暂存树和原子无覆盖提交。恢复流程先完整认证，按需解压，再校验 Index 和实际载荷长度、执行平台名称检查，全部恢复成功后发布。版本无关运行上限位于 `directory::Limits`，见 [目录实现](DIRECTORY_IMPLEMENTATION.md)。

输出事务在目标同目录排他创建临时文件，POSIX 权限为 0600，Windows 使用只允许
所有者和 SYSTEM 的受保护 DACL。写入、定位、刷新与不覆盖目标的提交由平台层完成，
所有失败路径自动清理临时输出；提交竞态不允许替换已有路径。
CLI 终端密码输入关闭回显，Windows 终端输入转换为 UTF-8，密码缓冲区使用安全容器。
加密确认密码，解密单次输入，管道输入按行读取；最终目标参数策略仍属于运行配置。

---

# 3. CLI 层

CLI 是最外层入口。

CLI 完整命令和选项不带横线，简写带单横线；`encrypt/-e`、`decrypt/-d`、`info/-i`、
`help/-h` 等价，算法通过 `algorithm/-a` 选择。加解密的输入、输出路径固定为命令后的
前两个参数，其余参数才按选项解析，避免路径与选项同名时产生歧义。
CLI 将 `aes`、`xchacha` 等名称转换为应用层选项，重复或冲突选项在读取密码前拒绝。
加密输出路径和解密输入路径没有扩展名时，CLI 补上 `.fcry`，已有扩展名保留。
v1 应用层的 `file_type.cpp` 根据文件名选择登记扩展名，无后缀才使用 512-byte 有界 magic 检测，检测后恢复同一输入流位置；Format Registry 只提供编号映射。
CLI 解密请求恢复扩展名，v1 流程从同一次读取的 Header 计算实际目标，认证及解压成功后才提交。公共 `decrypt_file` 返回实际输出路径，默认保持调用者提供的路径；最后一个 `restore_extension` 参数为 true 时启用无后缀路径补全，CLI 据返回值显示结果。
Windows CLI 使用 `wmain` 接收原生 UTF-16 参数，严格转换为 UTF-8 后统一解析，路径由 UTF-8 显式构造；
MinGW 链接时启用 `-municode`。真实控制台输出临时切换为 UTF-8 代码页，刷新后恢复原值；重定向输出保持 UTF-8 字节。

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
受控临时载荷 + Tag 认证
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
受控临时载荷 + Tag 认证
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
.filecrypt-随机后缀.tmp
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
