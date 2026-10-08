# FileCrypt v1 File Format

**Format version:** v1  
**Status:** Frozen / 已冻结

本文定义 FileCrypt v1 外层文件格式。

---

## 1. 文件整体结构

FileCrypt 文件由三个连续区域组成：

```text
┌──────────────────────────────┐
│ Fixed Header      32 bytes   │
├──────────────────────────────┤
│ Metadata          16 × N     │
├──────────────────────────────┤
│ Encrypted Raw                │
└──────────────────────────────┘
```

文件顺序：

```text
Header
  ↓
Metadata
  ↓
Encrypted Raw
```

FileCrypt v1 的 Fixed Header 固定为 32 bytes，因此：

```text
MetadataOffset = 32
```

Encrypted Raw 的起始偏移：

```text
EncryptedRawOffset = 32 + MetadataLength
```

Metadata Length 必须是 16 的倍数，因此 Encrypted Raw 的起始偏移也始终是 16 字节对齐的。

---

## 2. 字节序

所有多字节整数统一使用：

```text
Little-Endian
```

适用于：

```text
uint16
uint32
uint64
```

---

# 3. Fixed Header

FileCrypt v1 的固定 Header 长度为：

```text
32 bytes
```

布局：

| Offset | Size | Field | Description |
|---:|---:|---|---|
| `0x00` | 4 B | Magic | 固定为 ASCII `"FCRY"` |
| `0x04` | 2 B | Version | 文件格式版本 |
| `0x06` | 2 B | Flags | 文件容器类型、压缩状态及其他特性 |
| `0x08` | 2 B | Algorithm | 加密算法 ID |
| `0x0A` | 2 B | File Type | 单文件模式下的原始文件类型 |
| `0x0C` | 8 B | Metadata Length | Metadata 实际存储长度 |
| `0x14` | 12 B | Reserved | 保留字段 |
| | **32 B** | | |

---

## 3.1 Magic

Offset：

```text
0x00
```

Size：

```text
4 bytes
```

固定值：

```text
FCRY
```

ASCII 字节：

```text
46 43 52 59
 F  C  R  Y
```

用于快速识别 FileCrypt 文件。

---

## 3.2 Version

Offset：

```text
0x04
```

Size：

```text
2 bytes
```

表示 FileCrypt 文件格式版本。

v1：

```text
0x0001
```

Version 定义：

- Header 的布局
- Metadata 的布局
- Algorithm ID 的含义
- KDF ID 的含义
- Compression ID 的含义
- File Type ID 的含义

不同 Version 的 ID 定义彼此独立。

例如：

```text
v1:
Algorithm ID 0x0001 = A

v2:
Algorithm ID 0x0001 = B
```

二者不冲突，因为 Version 不同。

---

## 3.3 Flags

Offset：

```text
0x06
```

Size：

```text
2 bytes
```

Flags 用于表示 FileCrypt 文件的容器类型、压缩状态及其他文件特性。

### Bit 15 — Container Type

```text
0 = Single File
1 = Directory Archive
```

### Bit 14 — Compression

```text
0 = Uncompressed
1 = Compressed
```

按照 FileCrypt 的 Little-Endian 规则：

```text
Single File, Uncompressed:
00 00

Single File, Compressed:
00 40

Directory Archive, Uncompressed:
00 80

Directory Archive, Compressed:
00 C0
```

Bits `0 ~ 13` 在 FileCrypt v1 中暂未定义，必须为：

```text
0
```

因此当前合法值为：

```text
0x0000  Single File, Uncompressed
0x4000  Single File, Compressed
0x8000  Directory Archive, Uncompressed
0xC000  Directory Archive, Compressed
```

Header 只通过 Bit 14 表示是否启用压缩，不存储具体 Compression ID 或 Compression Parameters。具体压缩算法和参数位于 Metadata。

---

## 3.4 Algorithm

Offset：

```text
0x08
```

Size：

```text
2 bytes
```

表示 Encrypted Raw 使用的加密算法。

Algorithm ID 的具体含义由当前 Version 对应的算法注册表定义。

Algorithm Definition 同时规定：

- Key 长度
- Nonce 长度
- Authentication Tag 长度
- 加密方式
- Metadata 中算法相关字段的解释方式

Algorithm Registry 可以同时注册多个 AEAD 算法。不同算法之间不是互斥关系；每个 `.fcry` 文件通过 Header 中的 Algorithm ID 选择其中一个。

---

## 3.5 File Type

Offset：

```text
0x0A
```

Size：

```text
2 bytes
```

### File Type Registry

当前仅定义特殊值，具体普通文件类型 ID 暂不注册。

```text
0x0000 = N/A
0x0001 ~ 0xFFFE = 由未来 File Type Registry 定义
0xFFFF = Unknown / Invalid
```

### Single File

当 `Flags.Bit15 = 0` 时，File Type 表示加密前原始文件的类型。

正常情况下应使用未来 File Type Registry 定义的具体 ID。`0x0000` 表示 N/A，不作为正常 Single File 文件类型使用；`0xFFFF` 表示 Unknown / Invalid。

### Directory Archive

当 `Flags.Bit15 = 1` 时，File Type 固定为：

```text
0x0000 = N/A
```

因为 Directory Archive 不对应单一原始文件类型。具体文件类型属于 Directory Index 中各 File Entry 的语义，由目录中的实际文件分别确定。

---

## 3.6 Metadata Length

Offset：

```text
0x0C
```

Size：

```text
8 bytes
```

表示 Metadata 在文件中实际占用的字节数，包括末尾 Padding。

必须满足：

```text
MetadataLength % 16 == 0
```

因此有效 FileCrypt v1 文件中的 Metadata Length 为正的 16 倍数，例如：

```text
16
32
48
64
80
...
```

`0` 虽然可以被无符号整数表示，但对于 v1 加密文件属于无效 Metadata Length，因为 v1 必须包含 KDF、Salt、Nonce 和 Authentication Tag 等 Metadata 字段。

---

## 3.7 Reserved

Offset：

```text
0x14
```

Size：

```text
12 bytes
```

FileCrypt v1 中必须全部为：

```text
00 00 00 00 00 00 00 00
00 00 00 00
```

该区域保留给未来格式扩展。

---

# 4. Metadata

Metadata 紧跟在 Fixed Header 后，起始偏移为：

```text
0x20
```

Metadata 不使用 TLV。

其布局由以下信息共同决定：

```text
Version
Flags.Bit15 / Container Type
Flags.Bit14 / Compression State
KDF ID
Algorithm ID
```

其中：

- `Flags.Bit14` 是是否启用压缩的唯一状态来源。
- 当 `Flags.Bit14 = 0` 时，Metadata 中不得出现 Compression ID 或 Compression Parameters。
- 当 `Flags.Bit14 = 1` 时，Metadata 必须包含 Compression ID 和 Compression Parameters。
- Metadata 不重复存储“是否压缩”这一状态，只存储启用压缩时所需的具体算法与参数。

### Single File Metadata

未启用压缩：

```text
KDF ID
KDF Parameters
Salt
Nonce
Authentication Tag
Zero Padding
```

启用压缩：

```text
Compression ID
Compression Parameters
KDF ID
KDF Parameters
Salt
Nonce
Authentication Tag
Zero Padding
```

### Directory Archive Metadata

未启用压缩：

```text
Index Length
KDF ID
KDF Parameters
Salt
Nonce
Authentication Tag
Zero Padding
```

启用压缩：

```text
Index Length
Compression ID
Compression Parameters
KDF ID
KDF Parameters
Salt
Nonce
Authentication Tag
Zero Padding
```

其中：

- `Index Length` 仅 Directory Archive 存在。
- `Compression ID` 与 `Compression Parameters` 仅在启用压缩时存在。
- `KDF ID`、`KDF Parameters`、`Salt`、`Nonce`、`Authentication Tag` 为密码学字段。
- `Zero Padding` 始终位于 Metadata 最末尾。

各字段的长度由当前 Version 对应的 KDF、Algorithm 和 Compression 定义决定。

---

# 5. Metadata Padding

完成实际 Metadata 字段后，如果长度不是 16 的倍数，则在末尾追加 Padding。

Padding：

```text
每个 Padding Byte = 0x00
```

Padding 长度：

```text
0 ~ 15 bytes
```

Metadata Length 包含 Padding。

规则：

- Padding 只允许位于 Metadata 最末尾。
- Padding 内容必须全部为 `0x00`。
- Metadata Length 必须包含 Padding。

---

# 6. Encrypted Raw

Encrypted Raw 是经过可选压缩与加密后的最终密文数据。

处理顺序：

```text
Plaintext
   ↓
Compression（可选）
   ↓
AEAD Encryption
   ↓
Encrypted Raw
```

Single File 模式：

```text
Plaintext = 原始文件数据
```

Directory Archive 模式：

```text
Plaintext = Directory Archive
```

Encrypted Raw 不包含：

```text
Chunk Header
Chunk Length
Packet Header
额外 Padding
其他外层文件字段
```

---

# 7. AAD

FileCrypt v1 的 AAD 定义为：

```text
AAD =
    Header
  + Metadata 中除 Authentication Tag 外的部分
  + Metadata Padding
```

因此 Metadata 中的 `Index Length`、Compression 信息、KDF 信息等都会受到认证保护。

---

# 8. 文件识别

读取 `.fcry` 时，解析顺序为：

```text
Magic
  ↓
Version
  ↓
Flags
  ↓
Container Type / Compression State
  ↓
Algorithm / File Type
  ↓
Metadata
  ↓
Encrypted Raw
```

其中：

```text
Flags.Bit15 = 0
    → Single File

Flags.Bit15 = 1
    → Directory Archive

Flags.Bit14 = 0
    → Metadata 不包含 Compression ID / Parameters

Flags.Bit14 = 1
    → Metadata 必须包含 Compression ID / Parameters
```

---

# 9. 核心规则

```text
Magic              = "FCRY"
Fixed Header       = 32 bytes
Integer Endianness = Little-Endian

Flags:
    Bit 15 = Container Type
    Bit 14 = Compression
    Bits 0~13 = Reserved

Metadata Length    = multiple of 16
Metadata Padding   = 0x00

EncryptedRawOffset = 32 + MetadataLength
```

Single File 与 Directory Archive 共享外层 FileCrypt v1 格式，但对 Encrypted Raw 的解释不同。
