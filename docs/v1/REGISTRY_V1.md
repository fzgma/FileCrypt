# FileCrypt v1 Registry Specification

本文定义 FileCrypt v1 中 Algorithm、KDF、Compression 和 File Type 的 Registry。

除特别说明外，所有多字节整数均采用 **Little-Endian** 编码。

## 1. General Rules

FileCrypt 文件格式中的 Registry ID 是 **FileCrypt 自身的协议编号**，与底层密码库、压缩库或操作系统中的编号无关。

实现可以使用 Botan、zstd 或其他兼容库，但不得将第三方库的内部 ID、枚举值或字符串直接作为 `.fcry` 文件格式的一部分。

Registry ID 未知时：

* 如果该字段在当前上下文中要求一个已支持的 Registry ID，则必须报告“不支持”。
* 不得将未知 ID 静默当作另一个算法或格式处理。

当前 Registry 为 v1 固定定义，未来版本可以增加新的 ID，但不得重新解释已经分配的 ID。

---

# 2. Algorithm Registry

Algorithm Registry 定义 `.fcry` 使用的 AEAD 加密算法。

Header 中：

```text
Algorithm : uint16
```

## 2.1 Assigned IDs

|       ID | Algorithm          | Key Size | Nonce Size | Tag Size |
| -------: | ------------------ | -------: | ---------: | -------: |
| `0x0001` | AES-256-GCM        | 32 bytes |   12 bytes | 16 bytes |
| `0x0002` | XChaCha20-Poly1305 | 32 bytes |   24 bytes | 16 bytes |

### `0x0001` — AES-256-GCM

* Key size: 32 bytes
* Nonce size: 12 bytes
* Authentication Tag size: 16 bytes
* AEAD
* AAD 参与认证
* Encrypted Raw 仅包含 ciphertext
* Tag 单独存储于 Metadata

AES-256-GCM 的单条 AEAD 消息明文长度不得超过：

```text
2^39 - 256 bits
```

即：

```text
68,719,476,704 bytes
```

实现不得产生超过该限制的单条 AES-GCM 消息。

### `0x0002` — XChaCha20-Poly1305

* Key size: 32 bytes
* Nonce size: 24 bytes
* Authentication Tag size: 16 bytes
* AEAD
* AAD 参与认证
* Encrypted Raw 仅包含 ciphertext
* Tag 单独存储于 Metadata

Botan 中的 192-bit nonce ChaCha20-Poly1305 对应 XChaCha20-Poly1305。

FileCrypt v1 采用单条消息上限 `2^38 - 64` = 274,877,906,880 bytes，对应已验证的 32-bit block-counter 构造。实现必须通过 Algorithm Registry 提供的 `max_message_size` 检查输入长度。

两种算法均计数实际交给 AEAD 的输入字节：启用压缩时为压缩结果，目录模式包括 Index；Tag 不计入消息长度。

## 2.2 Algorithm Definition

实现层应能够通过 Algorithm ID 得到完整算法定义：

```cpp
struct AlgorithmDefinition {
    uint16_t id;
    std::string_view name;

    uint32_t key_size;
    uint32_t nonce_size;
    uint32_t tag_size;

    uint64_t max_message_size;
};
```

`max_message_size` 是实现语义的一部分，不写入 `.fcry`。

Derived Key 的长度由所选 Algorithm Definition 决定，不由 KDF Metadata 单独指定。

---

# 3. KDF Registry

KDF Registry 定义密码模式下由用户密码派生加密密钥的方法。

Metadata 中使用：

```text
KDF ID : uint16
```

## 3.1 Assigned IDs

|       ID | KDF      |
| -------: | -------- |
| `0x0001` | Argon2id |

v1 仅支持 Argon2id。

## 3.2 Salt

Argon2id 使用：

```text
Salt = 16 bytes
```

Salt 为随机公开参数，不属于秘密数据。

同一密码配合不同 Salt 必须得到不同的派生结果。

## 3.3 Argon2id Parameters

v1 的 Argon2id 参数固定编码为 16 bytes：

| Offset | Size | Field          |
| -----: | ---: | -------------- |
| `0x00` |    1 | Argon2 Version |
| `0x01` |    3 | Reserved       |
| `0x04` |    4 | Memory Cost    |
| `0x08` |    4 | Time Cost      |
| `0x0C` |    4 | Parallelism    |

全部多字节字段为 Little-Endian。

### Argon2 Version

v1 使用：

```text
0x13
```

即 Argon2 1.3。

### Memory Cost

单位：

```text
KiB
```

编码为：

```text
uint32
```

### Time Cost

表示 Argon2 的 passes / iterations：

```text
uint32
```

### Parallelism

表示 Argon2 的并行度：

```text
uint32
```

## 3.4 Default Parameters

FileCrypt v1 的协议只冻结：

* 字段宽度
* 字段顺序
* 单位
* Argon2 版本

生产环境默认的：

```text
Memory Cost
Time Cost
Parallelism
```

暂不在本协议中永久固定。

实现应根据实际目标平台进行安全性与性能测试后选择默认值。

但是，一旦文件创建完成，实际使用的参数必须完整写入 Metadata，使解密端能够重建相同的 KDF。

## 3.5 Derived Key

KDF 不单独定义输出长度。

最终 Derived Key 长度由 Algorithm Registry 中的 `key_size` 决定。

当前两种 Algorithm 均需要：

```text
32 bytes
```

因此：

```text
Password
    ↓
Argon2id + Salt + Parameters
    ↓
32-byte Derived Key
```

---

# 4. Compression Registry

Compression Registry 定义 Encrypted Raw 对应的压缩算法。

Header.Flags 的 Bit 14 是压缩开关。

## 4.1 Compression Flag

```text
Bit 14 = 0
```

表示：

```text
Uncompressed
```

此时 Metadata **不得包含 Compression Metadata**。

```text
Bit 14 = 1
```

表示：

```text
Compressed
```

此时 Metadata **必须包含 Compression Metadata**。

Compression 状态只由 Header.Flags Bit 14 决定。

Metadata 不重复存储“是否压缩”的布尔状态。

## 4.2 Assigned IDs

|       ID | Compression |
| -------: | ----------- |
| `0x0001` | Zstandard   |

v1 仅支持 Zstandard。

## 4.3 Compression Metadata

当 Bit 14 = 1 时，Metadata 增加：

| Field             |    Size |
| ----------------- | ------: |
| Compression ID    | 2 bytes |
| Parameters Length | 2 bytes |
| Parameters        | N bytes |

字段全部采用 Little-Endian。

因此：

```text
Compression ID
Parameters Length
Parameters
```

是一个完整的 Compression Metadata 单元。

## 4.4 Zstandard v1 Parameters

Zstandard 在 v1 中：

```text
Compression ID       = 0x0001
Parameters Length    = 0
Parameters           = empty
```

因此其 Metadata 固定占：

```text
4 bytes
```

对应：

```text
01 00
00 00
```

v1 不在 `.fcry` Metadata 中记录：

* Zstandard Compression Level
* Worker Thread Count
* Compression Speed Preference
* Window Size
* 其他 zstd 私有运行参数

这些属于创建文件时的实现参数，而不是解密协议必需参数。

Zstandard Frame 本身包含解压所需的信息，解压端不需要知道创建时使用的 Compression Level。

未来如果新的 Compression Registry ID 需要额外参数，可以通过 `Parameters Length` 和 `Parameters` 扩展。

对于 ID `0x0001`，v1 中 `Parameters Length` 必须为 `0`。

---

# 5. File Type Registry

File Type 用于记录 Single File Container 的已登记原始扩展名；没有扩展名时可由有界 magic 检测给出默认扩展名。它是公开的、受 AAD 认证保护的提示，不保证文件内容符合对应格式。

Header 中：

```text
File Type : uint16
```

## 5.1 Assigned Values

|             Value | Meaning            |
| ----------------: | ------------------ |
|          `0x0000` | N/A                |
| `0x0001 ~ 0xFFFD` | File Type Registry |
|          `0xFFFE` | Unknown            |
|          `0xFFFF` | Invalid            |

### `0x0000` — N/A

表示当前容器没有单一文件类型。

典型情况：

```text
Directory Archive
```

Directory Archive 使用：

```text
File Type = 0x0000
```

### `0x0001 ~ 0xFFFD`

当前分配如下；扩展名不含开头的点，编号不得重新解释或复用。

| ID | 扩展名 | ID | 扩展名 |
| --- | --- | --- | --- |
| `0x0001` | txt | `0x0013` | 7z |
| `0x0002` | md | `0x0014` | rar |
| `0x0003` | csv | `0x0015` | tar |
| `0x0004` | json | `0x0016` | gz |
| `0x0005` | xml | `0x0017` | bz2 |
| `0x0006` | yaml | `0x0018` | xz |
| `0x0007` | yml | `0x0019` | zst |
| `0x0008` | pdf | `0x001A` | mp3 |
| `0x0009` | png | `0x001B` | wav |
| `0x000A` | jpg | `0x001C` | flac |
| `0x000B` | jpeg | `0x001D` | mp4 |
| `0x000C` | gif | `0x001E` | mkv |
| `0x000D` | bmp | `0x001F` | mov |
| `0x000E` | webp | `0x0020` | avi |
| `0x000F` | svg | `0x0021` | tar.gz |
| `0x0010` | tif | `0x0022` | tar.bz2 |
| `0x0011` | tiff | `0x0023` | tar.xz |
| `0x0012` | zip | `0x0024` | tar.zst |

`0x0025 ~ 0xFFFD` 尚未分配，读取时严格报告“不支持”。Single File 使用已登记编号或 `0xFFFE`；Directory Archive 必须使用 `0x0000`。

### 扩展名选择与恢复

- 匹配时只对 ASCII 大写字母转小写，恢复时使用表中的小写后缀。
- 优先匹配最长的已登记复合后缀；其他名称只取最后一段。例如 `backup.tar.gz` 记录 `tar.gz`，`photo.png.jpg` 和 `backup.tar.gz.jpg` 记录 `jpg`。
- 有扩展名时以扩展名为准，未登记则记 `Unknown`，不再检测内容。
- 无扩展名时有界读取文件头检测 magic，未命中记 `Unknown`。JPEG 默认选 `jpg`，TIFF 默认选 `tif`；压缩格式只判断外层，不解压推断 `tar.gz` 等复合后缀。
- 类型编号不保存原始大小写、任意扩展名字符串、完整文件名或路径。
- CLI 解密输出无扩展名时补上已登记后缀；显式后缀保留，Unknown 不补。类型由同一次解密读取的 Header 决定，认证和解压完成前不发布输出。

### 当前 magic 实现范围

识别逻辑属于版本应用层，不由 Format 执行。最多读取文件头 512 bytes，并恢复原输入流位置；文件头暂存使用安全容器，不解压、不扫描整个文件。支持 PNG、JPEG、GIF、BMP、TIFF、PDF、ZIP、7z、RAR、gzip、bzip2、xz、Zstandard、带 ID3 前缀的 MP3、FLAC，以及 RIFF 下的 WebP/WAV/AVI。

MP4/QuickTime 仅识别 `ftyp` 与已知 major brand：`isom`、`iso2`、`mp41`、`mp42`、`avc1`、`M4V ` 对应 `mp4`，`qt  ` 对应 `mov`；不把任意 ISO BMFF（例如 AVIF）映射为 MP4。Matroska 要求有界 EBML Header 的 DocType 为 `matroska`，WebM 不映射为 MKV。TAR 要求完整 512-byte 首块、ustar 标识与合法校验和。

未覆盖的变体和无明确 magic 的文本类型保持 Unknown；扩展名登记不表示一定有 magic 检测规则。检测只提供后缀提示，不执行完整内容格式校验。
签名参考 [file 项目的图像规则](https://github.com/file/file/blob/master/magic/Magdir/images)、[压缩规则](https://github.com/file/file/blob/master/magic/Magdir/compress)、[RIFF 规则](https://github.com/file/file/blob/master/magic/Magdir/riff)和[归档规则](https://github.com/file/file/blob/master/magic/Magdir/archive)。实现不引入 libmagic 依赖。

### `0xFFFE` — Unknown

表示：

> 当前程序无法识别或确定原始文件类型。

这是一个合法的 File Type 值。

### `0xFFFF` — Invalid

表示：

> 该值在当前协议语境下是非法或保留值。

它不能作为普通文件的“未知类型”使用。

因此：

```text
无法识别文件类型
→ 0xFFFE

字段本身非法
→ 0xFFFF
```

这两个状态必须区分。

---

# 6. Registry Validation

解析 Header 和 Metadata 时，FileCrypt 应根据当前上下文执行 Registry 语义检查。

## 6.1 Algorithm

必须满足：

```text
Algorithm ID
→ 当前实现存在对应 Definition
```

并验证：

* Key Size
* Nonce Size
* Tag Size
* Maximum Message Size

## 6.2 KDF

必须满足：

```text
KDF ID
→ 当前实现支持
```

Argon2id Parameters 必须验证：

* Version 合法
* Reserved 为零
* Memory Cost 合法
* Time Cost 合法
* Parallelism 合法

具体要求：Version 必须为 `0x13`，三个 Reserved 字节必须为零；Time Cost 至少为 1；Parallelism 范围为 `1 ~ 0xFFFFFF`；Memory Cost 至少为 `8 × Parallelism` KiB，乘法使用足够宽的整数以避免溢出。

以上是协议合法性，不代表本机必须允许执行全部合法参数；实际 KDF 调用前另行检查资源上限，格式编解码不执行 KDF。

## 6.3 Compression

如果：

```text
Flags.Bit14 = 0
```

则：

```text
Compression Metadata 不存在
```

如果：

```text
Flags.Bit14 = 1
```

则：

```text
Compression ID
Parameters Length
Parameters
```

必须存在。

对于：

```text
Compression ID = 0x0001
```

必须满足：

```text
Parameters Length = 0
```

## 6.4 File Type

必须区分：

```text
N/A
Unknown
Invalid
```

其中：

```text
0xFFFF
```

不得作为正常文件类型写入有效 `.fcry` 文件。

---

# 7. Protocol Independence

Registry 定义属于 FileCrypt 协议本身。

例如：

```text
Algorithm = 0x0002
```

只表示：

```text
XChaCha20-Poly1305
```

它不表示：

```text
Botan::...
```

同一个 `.fcry` 文件可以由不同语言和不同实现处理，例如：

```text
C++ / Botan
C++
Rust
C#
Java
```

只要这些实现遵循相同的 FileCrypt Registry 和文件格式定义，就必须得到相同的协议行为。

---

# 8. Current v1 Registry Summary

当前 FileCrypt v1 已分配：

```text
Algorithm
    0x0001 = AES-256-GCM
    0x0002 = XChaCha20-Poly1305

KDF
    0x0001 = Argon2id

Compression
    0x0001 = Zstandard

File Type
    0x0000 = N/A
    0x0001 ~ 0x0024 = Registered Extensions
    0x0025 ~ 0xFFFD = Future Registry
    0xFFFE = Unknown
    0xFFFF = Invalid
```

这些编号一旦进入正式 v1 文件，不得重新解释。
