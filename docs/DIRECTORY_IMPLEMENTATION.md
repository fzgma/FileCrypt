# 目录加密与恢复

实现遵循已冻结的 [v1 目录格式](DIRECTORY_FORMAT.md)和[协议边界](PROTOCOL_BOUNDARIES_V1.md)。目录与单文件共用版本分发、密码派生、AAD 和单条 AEAD 消息，不新增归档 Header 或修改现有 Entry 布局。

## CLI 行为

`encrypt/-e` 根据输入对象自动选择普通文件或目录；目录同样支持 `algorithm/-a` 和 `compress/-z`。解密从 Header 自动识别。

```powershell
.\filecrypt.exe -e .\documents backup -z
.\filecrypt.exe -d backup .\restored
```

解密目标就是归档 Root 对应的根目录，原始 Root Name 不再套一层；树内名称保持原 UTF-8 和大小写，不执行 File Type 后缀补全。已有目标文件、目录或链接均拒绝覆盖，不合并到已有目录。

## 格式层

`format/v1/directory.hpp` 提供 Entry 类型、Index 编解码与校验；不访问文件系统，不调用 Crypto。

- 固定字段显式小端编码，Name Length 使用 unsigned LEB128；Index 结束由外层 Metadata 的 Index Length 指定。
- ID 唯一且按升序排列，Root 固定 ID 0、Parent 0xFFFFFFFF、Type Directory；普通 ID 保持协议定义的 uint32 范围。
- 在任何父 ID 二分查找之前先核对完整 ID 序列，避免对不可信无序范围执行要求有序的算法。
- 不要求普通 ID 连续，也不要求父 ID 小于子 ID；父节点必须存在且为目录，所有节点必须连到 Root，禁止环。
- Name 为非空、合法 UTF-8 单组件，禁止 NUL、分隔符、`.` 和 `..`，拒绝过长编码、代理码点及无效码点；同一父节点下按原始字节检查重名。
- Directory 的 Offset/Length 必须为零。File Data 按 ID 严格连续，检查累计长度溢出，并与实际载荷长度精确比较，拒绝空洞、重叠、截断和未引用尾部。
- Name Length 读取最多 10 bytes 并检查 uint64 溢出和剩余长度；编码器生成最短 LEB128，读取器可接受合法的非最短编码，仍执行全部长度限制。

树校验和父链处理使用迭代算法；恢复时不缓存所有展开后的完整路径，避免内存按条目数乘目录深度增长。

## 扫描与加密

扫描收集普通目录和文件，按每个目录的 UTF-8 名称排序，分配连续 ID；记录源对象身份、大小及修改信息，并核对目录实际成员集合。符号链接、Windows reparse point（含 junction）以及 FIFO、设备等特殊对象拒绝处理。普通硬链接作为独立普通文件保存，不保存链接关系。

原始输入路径在消去 `.`/`..` 前逐组件检查，拒绝 `junction/..` 等会被归一化隐藏的源链接；Windows 相对路径先拼接当前目录，避免 absolute() 提前消去组件。Root 与每个条目的 LEB128 编码大小在扫描时精确累计，Index 与 File Data 一起受归档上限约束。

加密输出必须位于源树之外，避免把输出或临时文件打包进源目录。Index 在受限内存中构造，文件内容以 64 KiB 安全缓冲区流式读取：

```text
Index + 连续 File Data → 可选 Zstandard → 单条 AEAD 消息 → 输出事务
```

Windows 源文件通过不跟随 reparse point 的只读句柄打开，排除并发写入/删除，并保持祖先目录句柄防止替换。Linux 使用逐级 `openat` 和 `O_NOFOLLOW` 锚定祖先，再打开普通文件；非阻塞打开后以 fstat 拒绝特殊对象，避免 FIFO 阻塞。

文件读取前后检查身份、长度和修改信息；扫描后及提交前重新核对全部源对象和目录成员。可观察变化导致整个事务失败。该机制不是文件系统快照，不承诺把并发修改的目录捕获为同一时刻的视图；加密期间源目录应保持不变。

## 认证与恢复

解密首先把完整载荷写入权限受限的临时文件并验证 Tag。压缩目录只有认证成功后才进入受限解压，解压到第二个临时文件，完整成功后再解释 Index。

校验 Index、实际 File Data 长度与平台名称后，在目标同父目录创建唯一、受限的暂存目录，恢复空目录和普通文件。文件也使用输出事务，不暴露部分文件。全部成功后才发布完整目录；失败时清理仍由本事务持有的中间载荷与暂存树。

暂存根在创建时记录设备/文件身份，提交和清理前再次核对；发现根被移动或替换时拒绝发布及删除替代对象，并输出诊断。此时原先被移动的目录可能需要人工清理。目标父目录应由调用者控制，身份复核是操作前检查，不提供对恶意并发目录命名空间修改的隔离保证。文件事务成功释放临时名称后也清空该路径，析构不会删除后来占用旧名称的对象。

Windows 暂存目录使用受保护、可继承的所有者/SYSTEM DACL，文件由已有 OutputTransaction 创建；Linux 目录 0700、文件 0600。恢复不保留原始时间戳、权限、稀疏布局、ACL 或链接关系。

Windows 使用不带覆盖标志的 MoveFileExW；Linux 使用 `renameat2(RENAME_NOREPLACE)`，避免普通 rename 替换已存在的空目录。若内核或文件系统不支持此操作，明确失败，不降级为存在竞态的检查后 rename。清理不跟随 symlink/reparse point。

## 平台名称与冲突

格式层的名称合法性独立于平台规则。恢复到 Windows 时拒绝非法字符、控制字符、末尾空格/句点、保留设备名（含 COM/LPT 的上标数字变体）等；不自动改写名称。归档原始 Root Name 不用于目标路径，不施加目标平台名称限制。

名称冲突通过暂存目标文件系统中的真实创建操作检测，而非只比较字符串；目录排他创建、文件无覆盖提交。大小写、短名称别名或目标平台归一化导致的冲突使整个恢复失败，最终目标保持不存在。目标路径及组件长度也受系统接口和文件系统限制。

## 可调整运行上限

以下属于运行策略，不是 v1 协议常数；公开 API 使用 `directory::Limits`，CLI 可显式调整：

| CLI | 当前默认值 | 约束 |
| --- | --- | --- |
| `max-index-bytes` | 64 MiB | Index 实际字节数 |
| `max-entries` | 100000 | 含 Root 的条目数 |
| `max-name-bytes` | 4096 | 单名称 UTF-8 字节数 |
| `max-depth` | 256 | Root 以下路径深度 |
| `max-archive-bytes` | 16 GiB | Index + File Data 明文总长度 |

Index Length 在 KDF 和输出创建前受限；解密后在分配 Index 缓冲区前再次与实际载荷长度比较。无压缩目录解密也在写入前检查累计明文上限。压缩目录同时受解压窗口、累计解压输出和归档上限约束；解密显式 `max-output-bytes` 也会收紧目录输出。

目录恢复至少需要完整归档暂存和恢复树的空间；压缩目录还需要压缩中间载荷。当前不预留磁盘空间，磁盘写满等错误使事务失败并清理。资源默认值仍需真实场景评估。

## 验证

- `format_directory`：独立二进制向量、UTF-8、LEB128、父链/环、非连续 ID、数据连续性、溢出和运行上限。
- `app_directory_crypt`：两种算法/两种压缩状态、空目录和 Unicode、多块文件、认证有效的畸形载荷、源变化、平台名称/冲突、提交竞态、暂存根替换、Root LEB128 边界、异常清理和 Linux 权限。
- `cli_directory_crypt`：正式 CLI 往返、密码错误、资源限制、已有目标保护、目录内输出拒绝；Windows 另验证根、嵌套 junction 和 `junction/..` 路径，通过原生接口仅删除测试链接本身。

新测试纳入全量构建、Actions 和 Linux 发行版/CPU 运行矩阵。先前 v0.2.0 验证已通过，本阶段的远端结果单独记录在 TODO。

平台接口参考：[Windows 名称规则](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)、[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)、[Linux rename/renameat2](https://man7.org/linux/man-pages/man2/rename.2.html)。
