# FileCrypt

> 使用密码加密和恢复本地文件的跨平台 C++23 命令行工具。

FileCrypt 支持 **文件与目录加解密、可选 Zstandard 压缩、公开信息查看和扩展名恢复**，使用 Argon2id 派生密钥，并通过 AEAD 验证文件完整性。

面向 Windows 和 Linux，目前提供 CLI。下载入口：[GitHub Releases](https://github.com/fzgma/FileCrypt/releases)。构建与发布验证进度见 [TODO](docs/TODO.md)。

## 1. 功能

* **文件加密**：将普通文件加密为 `.fcry` 容器
* **文件解密**：验证认证标签，成功后发布恢复文件
* **目录加解密**：保存目录树、文件内容和空目录，完整恢复后发布
* **算法选择**：AES-256-GCM / XChaCha20-Poly1305
* **密码派生**：Argon2id，每个文件使用独立随机 Salt 与 Nonce
* **可选压缩**：加密前执行 Zstandard 压缩，解密自动识别
* **扩展名恢复**：登记 36 种后缀，支持 `.tar.gz` 等复合后缀
* **文件识别**：扩展名优先，无后缀时通过有界 magic 检测识别部分格式
* **信息查看**：无需密码查看版本、算法、压缩状态、扩展名和 KDF 参数
* **输出保护**：拒绝覆盖已有目标，使用受限权限临时文件处理输出
* **Unicode 路径**：支持中文、空格和 emoji 文件名

## 2. 快速开始

### Windows

下载 Windows 程序后，可将 `filecrypt-windows-x86_64.exe` 重命名为 `filecrypt.exe`。

```powershell
# 加密：生成 backup.fcry
.\filecrypt.exe -e photo.png backup

# 解密：读取 backup.fcry，恢复为 restored.png
.\filecrypt.exe -d backup restored

# 查看公开信息
.\filecrypt.exe -i backup.fcry

# 查看帮助
.\filecrypt.exe -h
```

加密时输入并确认密码，解密时输入一次；终端密码输入隐藏回显。

**忘记密码将无法恢复文件，FileCrypt 无法重置或绕过密码。**

### Linux

下载 Linux 程序后赋予执行权限：

```bash
chmod +x filecrypt-linux-x86_64
./filecrypt-linux-x86_64 -e photo.png backup
./filecrypt-linux-x86_64 -d backup restored
./filecrypt-linux-x86_64 -h
```

Linux 发布目标为 x86-64、glibc 2.34+；正式支持仍在维护的发行版，暂不支持 Alpine/musl。

## 3. 命令与选项

| 命令 | 简写 | 用途 |
| --- | --- | --- |
| `encrypt` | `-e` | 加密文件 |
| `decrypt` | `-d` | 解密文件 |
| `info` | `-i` | 查看公开信息 |
| `help` | `-h` | 查看帮助 |
| `sample` | — | 生成格式示例，不执行真实加密 |

加解密命令后的前两个参数固定为输入、输出路径，其后才解析选项。完整命令和选项不带横线，简写带单横线。

### 算法与压缩

默认使用 AES-256-GCM，不压缩。

```powershell
# 使用 XChaCha20-Poly1305
.\filecrypt.exe -e input.txt backup -a xchacha

# 启用 Zstandard 压缩
.\filecrypt.exe -e input.txt backup -z

# 完整写法
.\filecrypt.exe encrypt input.txt backup algorithm aes compress
```

解密自动读取算法与压缩状态，无需重复指定这些选项。

### 目录加密与恢复

输入是目录时自动使用目录布局，支持两种算法和可选压缩：

```powershell
.\filecrypt.exe -e .\documents backup -z
.\filecrypt.exe -d backup .\restored
```

`restored` 就是恢复后的根目录，不会再套一层 `documents`。目录目标不会补文件扩展名，已有文件或目录均拒绝覆盖。
加密输出必须放在源目录之外。首版拒绝符号链接、Windows junction/reparse point 和其他特殊对象；源目录在加密期间应保持不变。

### 后缀处理

* 加密输出没有后缀时补 `.fcry`；解密输入同理。
* 解密输出没有后缀时，补上文件中记录的扩展名；`Unknown` 保持无后缀。
* 用户显式指定的后缀原样保留。
* 扩展名匹配忽略 ASCII 大小写，恢复时使用小写后缀。
* 已登记复合后缀优先匹配：`.tar.gz`、`.tar.bz2`、`.tar.xz`、`.tar.zst`。
* 其余只取最后一段，例如 `photo.png.jpg` 记录 `jpg`。

```powershell
.\filecrypt.exe -e archive.tar.gz backup
.\filecrypt.exe -d backup restored        # restored.tar.gz
.\filecrypt.exe -d backup restored.bin    # restored.bin
```

### 资源限制

| 参数 | 当前默认值 | 用途 |
| --- | --- | --- |
| `memory-kib` | 65536 | 加密 Argon2id 内存成本 |
| `iterations` | 3 | 加密 Argon2id 迭代次数 |
| `parallelism` | 1 | 加密 Argon2id 并行度 |
| `max-memory-kib` | 262144 | KDF 内存上限 |
| `max-iterations` | 10 | KDF 迭代上限 |
| `max-parallelism` | 16 | KDF 并行度上限 |
| `max-output-bytes` | 16 GiB | 累计解压输出上限 |
| `max-window-kib` | 65536 | 解压窗口上限 |

这些是可调整的运行策略；实际 KDF 参数写入文件，解密时按记录值派生密钥。普通文件的解压上限约束压缩载荷，目录还受以下归档策略限制；更多说明见 [压缩实现](docs/COMPRESSION.md)。

目录还提供以下可调上限，加密与解密均可指定：

| 参数 | 当前默认值 | 用途 |
| --- | --- | --- |
| `max-index-bytes` | 64 MiB | 目录 Index 大小 |
| `max-entries` | 100000 | 条目数，包含根目录 |
| `max-name-bytes` | 4096 | 单组件 UTF-8 名称字节数 |
| `max-depth` | 256 | 根目录以下的路径深度 |
| `max-archive-bytes` | 16 GiB | Index 与全部 File Data 总长度 |

解密时显式指定 `max-output-bytes` 也会限制目录归档输出；压缩目录同时受解压窗口和解压输出上限约束。这些均为运行策略，不是冻结的协议限制。

## 4. 从源码构建

要求 **CMake 3.24+、C++23 编译器、Botan 3 和 Zstandard 1.5.2+**。

Botan 必须与编译器工具链兼容；依赖安装在非默认位置时，配置 `CMAKE_PREFIX_PATH`。

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Visual Studio 等多配置生成器构建时增加 `--config Release`，测试时增加 `-C Release`。
开发构建默认使用共享依赖库，运行时需确保相关库可被加载。发布构建的链接与平台验证流程见 [发布政策](docs/LINUX_RELEASE.md)。

## 5. 项目结构

```text
.
├── include/filecrypt/   # 公共接口
├── src/
│   ├── cli/            # 命令解析、密码输入与结果展示
│   ├── app/            # 版本分发与业务流程
│   │   └── v1/         # v1 加解密、信息读取及文件类型识别
│   ├── format/         # 版本识别、Header、Metadata、Registry 与 AAD
│   ├── crypto/         # Botan 密码学后端
│   ├── compression/    # Zstandard 压缩与解压
│   ├── io/             # 共享 IO
│   └── platform/       # 平台文件操作与终端密码输入
├── tests/              # 单元、CLI 与文件流程测试
├── docs/               # 协议、架构、发布政策与 TODO
├── cmake/              # 依赖查找与构建配置
└── .github/            # 构建、测试与发布工作流
```

## 6. 限制

* 目录仅支持普通文件和目录；不保存链接关系、时间戳或原始权限，不支持恢复到已有目录并合并。
* 单文件不保存完整原始文件名；扩展名仅保存已登记类型，未登记后缀记 `Unknown`。目录中的名称和树结构保存在加密 Index 中。
* File Type 位于公开 Header，未输入密码也可读取；`info` 不验证文件真实性。
* magic 检测只提供后缀提示，不校验完整内容；未命中的无后缀文件记 `Unknown`。
* 压缩解密和目录恢复需要额外临时磁盘空间；错误密码、结构异常、资源超限、平台非法名称或目标名称冲突均不发布最终目录。
* Windows 名称限制、文件系统大小写及路径长度限制可能使跨平台恢复失败；不会自动改名。
* v1 使用单条 AEAD 消息，载荷受所选算法的消息长度上限约束。
* 不接受命令行明文密码；管道密码输入需使用 UTF-8。

## 7. 文档

* [文件格式](docs/FILE_FORMAT.md)
* [扩展名及算法编号](docs/REGISTRY_V1.md)
* [协议边界](docs/PROTOCOL_BOUNDARIES_V1.md)
* [密码学设计](docs/CRYPTOGRAPHY.md)
* [压缩实现](docs/COMPRESSION.md)
* [目录格式](docs/DIRECTORY_FORMAT.md)
* [目录实现与运行策略](docs/DIRECTORY_IMPLEMENTATION.md)
* [项目架构](docs/ARCHITECTURE.md)
* [发布政策](docs/LINUX_RELEASE.md)
* [开发进度与待办](docs/TODO.md)

## 8. 开源协议

[GNU General Public License v3.0](LICENSE)
