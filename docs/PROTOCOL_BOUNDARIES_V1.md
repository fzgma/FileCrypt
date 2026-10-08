# FileCrypt v1 Protocol Boundary Decisions

> 本文是 FileCrypt v1 现有规范的**补充文档**。
>
> 本文不替代、不修改既有文件格式、目录格式、密码学或架构文档；用于记录这些文档中目前已经正式确定、且会影响后续实现的边界决策。

## 1. AEAD 消息粒度

### 跨版本识别前缀

FileCrypt 各协议版本共用前六字节：`FCRY`（4 bytes）和 Little-Endian
`uint16 Version`（2 bytes）。分发器只读取这个前缀，再调用对应版本实现；
六字节之后的布局、Registry、AAD 和载荷模型由各版本独立定义。
当前只支持版本 1，未知版本必须明确失败，不按 v1 尝试解析。

FileCrypt v1 使用**单 AEAD 消息**模型。

完整加密载荷按照以下顺序处理：

```text
Plaintext
    ↓
Compression（如启用）
    ↓
One AEAD Message
    ↓
Ciphertext
```

v1 不使用分块 AEAD，不在 Encrypted Raw 中保存多个独立 Chunk 的 Tag。

因此，每个 `.fcry` 文件只有一个 Authentication Tag，并存放在 Metadata 最后。

所选 Algorithm 的单消息长度上限必须由实现检查。超过对应算法允许的最大单次消息长度时，创建文件必须失败。

对于启用压缩的文件，该限制适用于**压缩后的明文载荷**，而不是压缩前的原始文件大小。

未来如需支持分块认证、超大文件随机访问等能力，应设计新的协议版本或明确的扩展格式，不在 v1 中隐式加入。

---

## 2. Metadata 字段解析规则

FileCrypt v1 不采用通用 TLV Metadata 格式。

Metadata 中各字段的：

- 存在条件
- 字段顺序
- 字段大小
- 字段编码方式
- 可变长度规则

由对应的 Registry 和 v1 Metadata 结构共同定义。

Registry 是协议定义的一部分，而不是第三方库 API 的直接暴露。

例如：

```text
Algorithm ID
    ↓
Algorithm Registry
    ↓
Key Size / Nonce Size / Tag Size / Message Limit
```

以及：

```text
KDF ID
    ↓
KDF Registry
    ↓
KDF Parameter Encoding and Size
```

实现不得依赖 C/C++ 结构体的内存布局、padding 或 ABI 来解析 Metadata。

所有字段都必须按照协议规定进行显式序列化和反序列化。

---

## 3. Authentication Tag、Padding 与 AAD 边界

Authentication Tag **永远位于 Metadata 的最后**。

Metadata 的逻辑结构为：

```text
Metadata Fields
Padding
Authentication Tag
```

其中：

- Padding 必须全部为 `0x00`
- Padding 长度由 Metadata 对齐规则计算
- Authentication Tag 不属于 AAD
- Header 与 Tag 之前的 Metadata 内容属于 AAD
- Padding 位于 Tag 之前，因此 Padding 也属于 AAD

因此逻辑上：

```text
AAD = Header + Metadata[0 : TagOffset]
```

其中 `Metadata[0 : TagOffset]` 包含正常 Metadata 字段和全部 zero padding，但不包含 Authentication Tag。

Authentication Tag 不得参与其自身的 AAD。

任何非零 Padding 都不符合 v1 Metadata 编码规则。

## 3.1 Metadata 对齐计算

Metadata 的 16 字节对齐约束作用于**整个 Metadata**，而不是 Padding 或 Authentication Tag 单独的区域。

设：

* `F` = Tag 之前所有 Metadata 字段的总长度
* `T` = 当前 Algorithm Registry 定义的 Authentication Tag 长度
* `P` = Padding 长度

则：

```text
P = (16 - ((F + T) mod 16)) mod 16
```

最终：

```text
MetadataLength = F + P + T
```

因此无论 Authentication Tag 的长度是否为 16 的倍数，都必须满足：

```text
MetadataLength % 16 == 0
```

Metadata 的排列固定为：

```text
Fields
Padding
Authentication Tag
```

Authentication Tag 永远位于 Metadata 最后。

Padding 必须全部为 `0x00`，且其长度由 `F`、`T` 和 16 字节对齐要求动态计算。

例如，若 `F = 100`：

```text
Tag = 16 bytes
100 + 16 = 116
Padding = 12
MetadataLength = 128
```

若 `Tag = 15 bytes`：

```text
100 + 15 = 115
Padding = 13
MetadataLength = 128
```

若 `Tag = 24 bytes`：

```text
100 + 24 = 124
Padding = 4
MetadataLength = 128
```

因此，未来增加不同 Authentication Tag 长度的算法时，无需修改 Metadata 的总体对齐规则；`MetadataLayout` 只需使用 Algorithm Registry 提供的 `Tag Size` 计算 Padding。
---

## 4. Directory 的树模型与 Entry Name

Directory Archive 是一棵**文件树**，不是路径字符串列表。

节点之间通过：

```text
ParentID + Name
```

构成树结构。

Entry Name 表示**单个路径组件**，而不是完整路径。

### 4.1 格式层禁止内容

Entry Name 必须是合法 UTF-8，并满足：

- 不包含 `/`
- 不包含 `\\`
- 不包含 NUL（`U+0000`）
- 不得等于 `.`
- 不得等于 `..`
- 不得包含路径分隔语义

同一 `ParentID` 下，Name 必须唯一。

因此同一目录中不允许同时存在两个相同名称的 Entry。

### 4.2 平台相关名称检查

平台文件名限制**不属于 `.fcry` 格式本身**。

FileCrypt 在实际创建、提取或恢复文件时，应根据运行目标平台执行文件系统名称合法性检查。

Windows 目标下，除格式层限制外，还必须遵守 Windows 文件名规则，包括但不限于：

- `< > : " / \\ | ? *` 等非法字符
- 以空格或句点结尾的名称
- Windows 保留设备名，例如 `CON`、`PRN`、`AUX`、`NUL`
- `COM1` ~ `COM9`
- `LPT1` ~ `LPT9`

这些检查属于平台适配和提取阶段的合法性检查，不得因此修改 `.fcry` 中保存的原始 Name。

FileCrypt 不应自动把非法名称改写为另一个名称。

### 4.3 跨平台名称冲突

同一个 `.fcry` 在不同操作系统上恢复时，必须根据**目标文件系统的实际名称语义**检查冲突。

例如 Linux 允许：

```text
A.txt
a.txt
```

而某些 Windows 文件系统语义下二者可能发生冲突。

因此提取阶段不得只依赖字节级字符串比较判断目标路径是否冲突。

---

## 5. Directory File Data 连续性

Directory Archive 的 File Data 区域必须严格连续排列。

对所有 File 类型 Entry，按照 Entry ID 顺序排列其数据：

```text
File A
File B
File C
...
```

并满足：

```text
first_file.DataOffset == 0
```

以及对于相邻两个 File Entry：

```text
next.DataOffset = current.DataOffset + current.DataLength
```

因此：

- 不允许空洞
- 不允许重叠
- 不允许 File Data 乱序
- 不允许未引用的 File Data

Directory Entry 的 `DataOffset` 和 `DataLength` 必须为 `0`。

文件区域的有效长度等于所有 File Entry 的 `DataLength` 之和。

该连续性规则既是编码约束，也是解析器应验证的完整性不变量。

---

## 6. Password 字节语义

FileCrypt 不对用户密码做隐式修改。

密码处理规则为：

```text
User Input
    ↓
UTF-8 byte sequence
    ↓
KDF
```

FileCrypt v1 不执行以下操作：

- 不自动 trim 前后空白
- 不删除内部空白
- 不改变大小写
- 不进行 Unicode normalization
- 不自动追加 NUL
- 不自动转换为其他字符编码
- 不添加协议未定义的密码长度前缀

因此，用户输入的具体字符及其 UTF-8 编码结果直接决定 KDF 的输入。

例如：

```text
"abc"
```

对应输入字节：

```text
61 62 63
```

而：

```text
"abc "
```

必须视为不同密码。

---

## 7. Unknown / Unsupported 内容

FileCrypt v1 对未知或不支持的协议内容采取**严格失败**策略。

解析器不得猜测字段含义，也不得自动降级到其他算法或格式。

典型情况包括：

- 不支持的 Version
- 未知 Algorithm ID
- 未知 KDF ID
- 未知 Compression ID
- 未定义 Flags 位被置位
- 不符合 Registry 定义的参数格式
- 不符合当前 v1 Metadata 结构的字段布局

遇到上述情况时，协议层必须报告错误并停止继续解析。

应用层可以将协议错误转换为用户可见的错误信息和非零退出状态，但不得为了继续处理而忽略未知内容。

---

## 8. 资源上限：暂不冻结

FileCrypt v1 当前**不冻结最终资源上限参数**。

需要进一步研究并参考成熟压缩归档工具对恶意或异常压缩数据的处理策略，再确定合理的安全限制。

重点需要研究的资源包括：

- Metadata 最大长度
- Directory Index 最大长度
- Entry 数量上限
- 单个 Entry Name 最大长度
- 单个 File Data 最大长度
- 整体解压输出大小
- 压缩数据与解压数据的资源比例
- 解压过程中的内存占用
- 递归目录深度
- 其他可能导致 OOM、超长运行时间或资源耗尽的条件

在这些上限正式冻结之前，实现不得把某组临时数值当作永久的 v1 协议常数。

不过实现仍然应避免无界内存分配和明显的资源耗尽问题，并在必要时提供合理的运行时限制。

---

# 9. 当前冻结的 v1 边界摘要

```text
1. AEAD：单消息，不分块。

2. Metadata：字段长度与格式由 Registry / v1 结构定义，
   不使用通用 TLV。

3. Tag：永远位于 Metadata 最后；Padding 全零；
   Tag 不进入 AAD，Padding 进入 AAD。

4. Directory：文件树。
   Name 是单个路径组件；格式层禁止 /、\\、NUL、.、..；
   同一 ParentID 下 Name 必须唯一。
   Windows 额外执行 Windows 文件名规则检查。

5. File Data：严格连续排列，不允许空洞、重叠、乱序。

6. Password：用户输入什么就按什么处理，
   UTF-8 字节序列直接进入 KDF。

7. Unknown：v1 遇到未知或不支持的协议内容即报错并停止解析。

8. Resource Limits：暂不冻结，后续参考成熟归档格式后确定。
```

本文只记录上述协议边界，不对既有 FileCrypt 文档的正文进行替换或修改。
