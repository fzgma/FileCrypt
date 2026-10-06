# FileCrypt v1 Cryptography Design

**版本：v1**  
**状态：Frozen / 已冻结**

本文定义 FileCrypt v1 的密码学处理流程、密钥来源、认证方式及相关安全规则。

具体 Algorithm ID、KDF ID 与 Compression ID 由相应 Registry 定义。

---

# 1. 密码模式

FileCrypt v1 使用密码派生密钥模式。

用户提供密码，FileCrypt 不直接使用密码作为加密密钥。

```text
User Password
      │
      ▼
     KDF
      │
      │ + Salt
      │ + KDF Parameters
      ▼
Derived Key
      │
      │ + Nonce
      │ + AAD
      ▼
    AEAD
      │
      ├───────────────┐
      ▼               ▼
Ciphertext      Authentication Tag
```

Password 本身永远不会写入 `.fcry`。

---

# 2. 数据处理顺序

FileCrypt 的数据处理顺序固定为：

```text
Plaintext
   ↓
Compression（仅当 Header.Flags.Bit14 = 1）
   ↓
AEAD Encryption
   ↓
Encrypted Raw
```

不能在加密之后再执行压缩。

Single File 模式中：

```text
Plaintext = 原始文件数据
```

Directory Archive 模式中：

```text
Plaintext = Directory Archive
```

---

# 3. Password

用户输入的密码经过 UTF-8 编码后作为 KDF 输入。

```text
Password Bytes = UTF-8 encoding of user password
```

FileCrypt 不自动执行：

```text
大小写转换
Trim
Unicode 规范化
其他字符串修改
```

---

# 4. KDF

KDF 将用户密码转换为实际加密 Key。

输入：

```text
Password
Salt
KDF Parameters
```

输出：

```text
Derived Key
```

Derived Key 的长度由 Algorithm Definition 决定。

---

# 5. KDF ID

KDF ID 存储在 Metadata 中。

KDF ID 决定：

```text
KDF Parameters 的格式
KDF Parameters 的长度
Salt 的长度
KDF 的具体实现
```

解析流程：

```text
KDF ID
   ↓
KDF Registry
   ↓
KDF Definition
```

不同 FileCrypt Version 使用独立的 KDF ID 定义。

---

# 6. Salt

Salt 由密码学安全随机数生成器产生。

Salt：

- 不需要保密
- 存储在 Metadata 中
- 每个加密文件独立生成
- 长度由 KDF Definition 决定

例如相同密码用于两个文件时：

```text
Password + Salt A → Key A
Password + Salt B → Key B
```

---

# 7. Nonce

Nonce 由密码学安全随机数生成器产生。

Nonce：

- 不需要保密
- 存储在 Metadata 中
- 长度由 Algorithm Definition 决定
- 必须满足所选 Algorithm 对 Nonce 唯一性的要求

FileCrypt 不规定所有 Algorithm 使用相同长度的 Nonce。

同一个 Key 不得重复使用同一个 Nonce。

---

# 8. AEAD

FileCrypt 使用 AEAD（Authenticated Encryption with Associated Data）作为数据加密机制。

输入：

```text
Key
Nonce
AAD
Plaintext
```

输出：

```text
Ciphertext
Authentication Tag
```

AEAD 提供：

```text
Confidentiality
Integrity
Authentication
```

---

# 9. Authentication Tag

Authentication Tag：

- 由 AEAD 产生
- 长度由 Algorithm Definition 决定
- 存储在 Metadata
- 不属于 Encrypted Raw
- 用于验证 Ciphertext 与 AAD

因此：

```text
Metadata
└── Authentication Tag

Encrypted Raw
└── Ciphertext
```

---

# 10. AAD

FileCrypt v1 的 AAD 固定定义为：

```text
AAD =
    Header
  + Metadata 中除 Authentication Tag 外的部分
  + Metadata Padding
```

因此以下字段会受到认证保护：

```text
Header
Index Length（Directory）
Compression ID / Parameters（如果启用）
KDF ID
KDF Parameters
Salt
Nonce
Metadata Padding
```

Authentication Tag 本身不参与自己的计算。

---

# 11. 压缩

压缩是可选处理步骤，由：

```text
Flags.Bit14
```

表示是否启用。

```text
Bit 14 = 0
    → Uncompressed

Bit 14 = 1
    → Compressed
```

Header 的 `Flags.Bit14` 只记录“是否压缩”，不记录具体压缩算法。

当 `Flags.Bit14 = 1` 时，Metadata 必须进一步提供：

```text
Compression ID
Compression Parameters
```

当 `Flags.Bit14 = 0` 时，这两个字段都不存在。

具体压缩算法由当前 Version 对应的 Compression Registry 定义。

处理顺序：

```text
Plaintext
   ↓
Compression
   ↓
AEAD
   ↓
Ciphertext
```

解密时反向处理：

```text
Ciphertext
   ↓
AEAD
   ↓
Decompression
   ↓
Plaintext
```

---

# 12. 加密开始前的布局确定

在开始写 Ciphertext 之前，以下信息已经确定：

```text
Container Type
Compression State（由 Header.Flags.Bit14 决定）
Compression Parameters（仅当 Bit14 = 1）
KDF
KDF Parameters
Salt
Nonce
Algorithm
Tag 长度
Metadata Padding
Metadata Length
EncryptedRawOffset
```

唯一尚未产生的是 Authentication Tag 的具体值。

因此可以提前构造除 Tag 外的完整 AAD，并计算 Encrypted Raw 的起始偏移。

---

# 13. 流式加密

FileCrypt 不要求将整个 Plaintext 一次性加载到内存。

数据通过流处理：

```text
Input
  ↓
Compression（可选）
  ↓
AEAD Update
  ↓
Ciphertext Output
```

加密结束时：

```text
AEAD Finalize
    ↓
Authentication Tag
```

---

# 14. 解密

解密流程：

```text
Encrypted Raw
   ↓
AEAD Decrypt
   ↓
Decompression（如果启用）
   ↓
Plaintext
```

Single File：

```text
Plaintext → 原始文件
```

Directory Archive：

```text
Plaintext → Index + File Data
```

---

# 15. 密钥重建

解密时读取：

```text
KDF ID
KDF Parameters
Salt
```

用户重新输入密码后：

```text
Password
   ↓
KDF
   ↑
Salt + Parameters
   ↓
Derived Key
```

如果 Password、KDF、Parameters、Salt 完全相同，则必须得到相同的 Derived Key。

---

# 16. Authentication Failure

以下情况必须导致认证失败：

```text
密码错误
Ciphertext 被修改
AAD 被修改
Algorithm 参数不匹配
KDF 参数不匹配
Authentication Tag 错误
```

认证失败时不得把部分解密数据作为最终输出文件。

---

# 17. Password Warning

加密完成后，CLI 应以显眼方式提示用户：

```text
WARNING:
忘记密码，文件将无法恢复。
FileCrypt 无法恢复、重置或绕过密码。
```

加密时应要求用户确认密码：

```text
Password:
Confirm Password:
```

两次输入不一致时不开始加密。

---

# 18. Randomness

Salt 与 Nonce 必须由密码学安全随机数生成器产生。

不得使用：

```text
std::rand()
time()
普通非密码学伪随机数生成器
```

作为唯一随机来源。

---

# 19. Sensitive Memory

以下数据属于敏感 Key Material：

```text
Password Bytes
Derived Key
```

使用完成后应尽快清零，并不得写入：

```text
日志
调试输出
Metadata
```

Salt、Nonce、Ciphertext、Authentication Tag 不属于需要保密的 Key Material。

---

# 20. 不自行实现密码学原语

FileCrypt 不自行实现：

```text
AES
ChaCha20
GCM
Poly1305
Argon2
PBKDF2
CSPRNG
```

这些功能由成熟的密码学库提供。

FileCrypt 自身负责：

```text
算法选择
参数管理
Metadata
文件格式
调用流程
```

---

# 21. Algorithm / KDF / Compression 可替换性

具体实现通过 Registry 选择：

```text
Algorithm ID
    ↓
Algorithm Definition

KDF ID
    ↓
KDF Definition

Compression ID
    ↓
Compression Definition
```

FileCrypt 的核心流程不依赖某个单独的具体实现。

不同 FileCrypt Version 使用独立的 ID 定义。

---

# 22. Single File 与 Directory Archive

Crypto 层不区分容器类型。

两种模式最终都向 Crypto 层提供一个 Plaintext Stream：

```text
Single File:
Original File
    ↓
Crypto

Directory:
Directory Archive
    ↓
Crypto
```

容器类型、Index、Entry 等都属于 Application / Format / Directory 层。

---

# 23. v1 Key Mode

FileCrypt v1 使用：

```text
Password
   ↓
KDF
   ↓
Derived Key
```

作为唯一密钥来源。

独立 Key File、Key Wrapping、多密码等功能不属于 v1。

---

# 24. 核心模型

```text
                  Password
                     │
                     ▼
                 ┌───────┐
                 │  KDF  │
                 └───┬───┘
                     │
               Derived Key
                     │
                     ▼
      ┌───────────────────────────┐
      │           AEAD            │
      │                           │
AAD ──┤                           │
Nonce ┤                           │
Data ─┤                           │
      └────────────┬──────────────┘
                   │
             ┌─────┴─────┐
             ▼           ▼
        Ciphertext       Tag
```

最终：

```text
Password
    ↓
KDF
    ↓
Key
    ↓
Compression（可选）
    ↓
AEAD
    ↓
Encrypted Raw + Authentication Tag
```

其中：

```text
Authentication Tag
    → Metadata

Ciphertext
    → Encrypted Raw
```

**FileCrypt v1 的密码学设计到此冻结。**
