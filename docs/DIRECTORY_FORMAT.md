# FileCrypt v1 Directory Format

**格式：FileCrypt v1 Directory Archive**  
**状态：Frozen / 已冻结**

本文定义 FileCrypt v1 的目录加密格式。

Directory Archive 复用 FileCrypt v1 的外层 Header、Metadata、AAD 与加密机制，不修改 Single File 格式。

---

# 1. Directory Archive 标识

Directory Archive 使用 FileCrypt Header 的 `Flags.Bit15` 标识：

```text
Bit 15 = 1
```

因此：

```text
Flags = 0x8000
```

如果同时启用压缩：

```text
Flags = 0xC000
```

Directory Archive 的 `File Type` 固定为：

```text
0x0000 = N/A
```

因为 Directory Archive 不对应单一原始文件类型。容器类型由 `Flags.Bit15` 表示；该 Header 字段在 Directory Archive 中不承担具体文件类型语义。

---

# 2. Directory Metadata

Directory Archive 在 FileCrypt v1 通用 Metadata 基础上增加：

```text
Index Length
```

同时，Header.Flags.Bit14 决定是否存在 Compression Metadata：

```text
Bit14 = 0 → 无 Compression ID / Parameters
Bit14 = 1 → 必须存在 Compression ID / Parameters
```

因此目录 Metadata 为：

### 未压缩

```text
Index Length
KDF ID
KDF Parameters
Salt
Nonce
Authentication Tag
Zero Padding
```

### 压缩

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

`Index Length` 是 Directory Archive 独有的 Metadata 字段。

Directory Archive 不在 Metadata 中重复存储 Compression 开关；是否压缩只由 Header.Flags.Bit14 决定。

Directory Metadata 最终存储长度仍必须为 16 的倍数。

---

# 3. Index Length

`Index Length`：

```text
Size = 8 bytes
```

表示：

> 解密后的 Encrypted Raw 中，Index 所占的字节数。

因此解密后的 Directory Archive 为：

```text
Encrypted Raw Plaintext
├── Index
│   └── Index Length bytes
└── File Data
    └── 剩余全部字节
```

File Data 的起始位置：

```text
FileDataStart = IndexLength
```

Index Length 不表示密文长度，也不表示外层 `.fcry` 文件中的字节数。

---

# 4. Directory Encrypted Raw

Directory Archive 的 Encrypted Raw 在解密后只有两部分：

```text
┌──────────────────────────────┐
│ Index                        │
│                              │
│ Index Length bytes           │
├──────────────────────────────┤
│ File Data                    │
│                              │
│ Remaining bytes              │
└──────────────────────────────┘
```

不增加独立的 Magic、Version 或 Archive Header。

外层 FileCrypt Header 的 Version、Flags 已经完成格式识别。

---

# 5. Index

Index 是连续排列的 Entry。

Index 中不单独存储 Entry Count。

读取时：

```text
读取 Entry
读取 Entry
读取 Entry
...
直到已读取字节数 == Index Length
```

因此：

```text
Index Start = 0
Index End   = Index Length
```

Index 与 File Data 之间没有额外 Padding。

---

# 6. Entry ID

每个 Entry 包含：

```text
ID = uint32
```

Entry ID 在当前 Directory Archive 内唯一。

Root Entry 固定为：

```text
ID = 0
```

Entry ID 按目录扫描后的顺序分配，并按 ID 顺序写入 Index 与 File Data。

---

# 7. Parent ID

每个 Entry 包含：

```text
Parent ID = uint32
```

表示当前 Entry 所属的父目录。

Root Entry 没有父目录：

```text
Parent ID = 0xFFFFFFFF
```

例如：

```text
ID  Parent ID  Type       Name
0   0xFFFFFFFF Directory  root
1   0          File       a.txt
2   0          File       b.png
3   0          Directory  empty
4   0          Directory  sub
5   4          File       c.bin
```

对应目录树：

```text
root/
├── a.txt
├── b.png
├── empty/
└── sub/
    └── c.bin
```

---

# 8. Entry Type

Entry Type：

```text
Size = 2 bytes
```

定义：

```text
0x0001 = File
0x0002 = Directory
```

Directory Entry 不包含文件数据。

---

# 9. Entry 二进制结构

每个 Entry 按以下顺序存储：

```text
┌──────────────────────────────┐
│ ID             4 bytes       │
├──────────────────────────────┤
│ Parent ID      4 bytes       │
├──────────────────────────────┤
│ Type           2 bytes       │
├──────────────────────────────┤
│ Data Offset    8 bytes       │
├──────────────────────────────┤
│ Data Length    8 bytes       │
├──────────────────────────────┤
│ Name Length    LEB128        │
├──────────────────────────────┤
│ Name           variable      │
└──────────────────────────────┘
```

固定字段长度：

```text
4 + 4 + 2 + 8 + 8 = 26 bytes
```

Entry 之间不进行 16-byte 对齐。

---

# 10. Data Offset

`Data Offset`：

```text
Size = 8 bytes
```

表示当前 File Entry 对应数据在 **File Data 区域**中的偏移。

它不是相对于：

- 整个 `.fcry` 文件
- Encrypted Raw
- Index

而是相对于：

```text
File Data Start
```

例如：

```text
Entry 1:
Data Offset = 0

Entry 2:
Data Offset = 100

Entry 5:
Data Offset = 600
```

---

# 11. Data Length

`Data Length`：

```text
Size = 8 bytes
```

表示该 File Entry 在解密后的 File Data 区域中占用的字节数。

例如：

```text
Data Offset = 100
Data Length = 500
```

表示该文件使用：

```text
FileData[100 ... 599]
```

Directory Entry：

```text
Data Offset = 0
Data Length = 0
```

---

# 12. Name

每个 Entry 只保存自己的名称，不保存完整路径。

例如：

```text
root/
└── sub/
    └── c.bin
```

Index：

```text
ID  Parent ID  Name
0   NONE       root
1   0          sub
2   1          c.bin
```

目录关系由：

```text
ID
Parent ID
Name
```

共同表达。

---

# 13. Name Encoding

Name 使用：

```text
UTF-8
```

Name Length 表示 UTF-8 编码后的字节数，而不是 Unicode 字符数。

---

# 14. Name Length

Name Length 使用：

```text
Unsigned LEB128
```

编码。

例如：

```text
Name Length = 5
```

编码为：

```text
05
```

Name Length 后紧跟 Name 字节。

---

# 15. 文件数据顺序

File Data 按 Entry ID 顺序写入，只处理 `File` Entry。

例如：

```text
ID  Type
0   Directory
1   File
2   File
3   Directory
4   Directory
5   File
```

File Data 顺序：

```text
Entry 1
Entry 2
Entry 5
```

Data Offset 按该顺序累计计算：

```text
current_offset = 0

Entry 1:
    Data Offset = current_offset
    Data Length = file_size
    current_offset += file_size

Entry 2:
    Data Offset = current_offset
    Data Length = file_size
    current_offset += file_size

Entry 5:
    Data Offset = current_offset
    Data Length = file_size
```

因此 File Data 不需要额外的块表或 Padding。

---

# 16. Index 与 File Data 对齐

Index 与 File Data 不进行 16-byte 对齐。

Index 结束后立即进入 File Data：

```text
Index
└── last Entry
       ↓
File Data
└── first File data
```

外层 FileCrypt Metadata 的 16-byte 对齐规则与 Directory Archive 内部结构无关。

---

# 17. 目录构造

输入目录：

```text
root/
├── a.txt
├── b.png
├── empty/
└── sub/
    └── c.bin
```

逻辑 Index：

```text
ID  Parent ID  Type       Name
0   0xFFFFFFFF Directory  root
1   0          File       a.txt
2   0          File       b.png
3   0          Directory  empty
4   0          Directory  sub
5   4          File       c.bin
```

对应：

```text
0 root
├── 1 a.txt
├── 2 b.png
├── 3 empty
└── 4 sub
    └── 5 c.bin
```

File Data：

```text
Entry 1 data
Entry 2 data
Entry 5 data
```

---

# 18. Directory Archive 数据流

目录模式的明文数据流为：

```text
Directory
   ↓
Index + File Data
   ↓
Compression（可选）
   ↓
AEAD Encryption
   ↓
Encrypted Raw
```

解密顺序：

```text
Encrypted Raw
   ↓
AEAD Decryption
   ↓
Decompression（如果启用）
   ↓
Index + File Data
   ↓
Restore Directory
```

---

# 19. 核心规则

```text
Flags.Bit15 = 1
    → Directory Archive

File Type = 0x0000

Flags.Bit14 = 0
    → Metadata 无 Compression ID / Parameters

Flags.Bit14 = 1
    → Metadata 必须包含 Compression ID / Parameters

Metadata:
    Index Length
    [Compression ID + Parameters]
    KDF ID
    KDF Parameters
    Salt
    Nonce
    Authentication Tag
    Zero Padding

Encrypted Raw:
    Index
    File Data

Index:
    Entry 0 ... Entry N
    由 Index Length 定位结束

Root:
    Entry ID = 0

Entry:
    ID
    Parent ID
    Type
    Data Offset
    Data Length
    Name Length
    Name

Name:
    UTF-8
    Length = UTF-8 byte count

Name Length:
    Unsigned LEB128

File Data:
    按 Entry ID 顺序写入

Index / File Data:
    不进行 16-byte 对齐
```
