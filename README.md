# FileCrypt

使用 C++23 编写的跨平台文件加密工具，已支持 v1 无压缩单文件加解密、公开信息读取与格式示例生成。

v1 格式层已提供 AAD 构造：`build_aad(header, metadata)` 用于逻辑对象，
`build_aad(header_bytes, metadata_bytes)` 用于原始文件字节。两者均校验格式，
包含 Header、Metadata 字段和 Padding，排除末尾 Tag；原始字节入口不重新编码认证内容。
文件加解密流程使用该认证输入保护 Header、Metadata 和密文。

## 构建与测试

需要 CMake >= 3.24、C++23 编译器和 Botan 3（AES/GCM、ChaCha20Poly1305、Argon2id、AutoSeeded_RNG），暂不依赖 zstd。

Botan 必须与编译器工具链兼容：MinGW 使用 MinGW 构建的库，MSVC 使用 MSVC 构建的库。
非默认安装位置可传入 `-DCMAKE_PREFIX_PATH=<安装前缀>`；Windows 运行密码层测试时将
Botan DLL 目录加入 PATH，运行正式程序也需要该 DLL；Linux 非系统安装按需设置 LD_LIBRARY_PATH。
普通开发构建默认使用共享库；Linux 发布流程从源码构建静态 Botan，并读取其 pkg-config 静态传递依赖。

使用 Ninja，将整个项目构建到 `build/`：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Visual Studio 等多配置生成器使用 `cmake --build build --config Release`，
测试时增加 `-C Release`；可执行文件一般位于 `build/Release/`。

默认 `cmake --build build` 同时构建正式程序、单元测试与集成测试，也可使用
`cmake --build build --target build_all`。正式程序为 `build/filecrypt.exe`，
单元测试程序位于 `build/tests/unit/`；多配置生成器会增加配置子目录。
单独构建程序使用 `--target filecrypt`，单独构建单元测试使用 `--target unit_tests`。
集成测试程序位于 `build/tests/integration/`，单独构建使用 `--target integration_tests`。
运行单元测试使用 `ctest --test-dir build -L unit --output-on-failure`，
运行正式程序冒烟测试使用 `ctest --test-dir build -L smoke --output-on-failure`，
运行文件流程与 CLI 集成测试使用 `ctest --test-dir build -L integration --output-on-failure`。

编辑器也应执行 CMake 全量构建，不能只编译当前活动文件。

`build/` 曾使用其他生成器时，在配置命令中增加 `--fresh` 重建 CMake 缓存。

个人构建预设可放在 `CMakeUserPresets.json`，该文件已被 Git 忽略，不随仓库分发。

GitHub Actions 的“手动构建与测试”工作流仅通过 `workflow_dispatch` 触发，
分别执行 Linux x86-64 和 Windows MSVC x64 的 Release 构建、单元测试、正式程序冒烟测试和文件流程集成测试。
在仓库 Actions 页面选择该工作流并点击 Run workflow，Linux 测试通过后可从该次运行的
Artifacts 下载 `filecrypt-linux-x86_64`，其中只有正式可执行文件 `filecrypt`，保留 14 天；Windows 构建产物不上传。
Artifact 下载会丢失 Linux 执行权限，解压后先运行 `chmod +x filecrypt`，再运行 `./filecrypt` 命令。
Linux 发布最低支持 glibc 2.34，目标为通用 x86-64，不强制要求 x86-64-v2；
Botan、libstdc++ 和 libgcc 静态链接，glibc 动态链接，接收方无需另外安装 Botan 或 C++ 运行库。
构建信息和 ELF 审计输出留在 Actions 日志；只支持仍在维护的 glibc 发行版，
EOL 系统不承诺兼容或测试，也不主动阻止运行，Alpine/musl 暂不支持。
具体构建、审计与发行版测试矩阵见 [Linux 发布政策](docs/LINUX_RELEASE.md)；工作流尚需在 GitHub 上实际运行验证。

根 `CMakeLists.txt` 管理项目标准、CLI 和测试开关；`src/CMakeLists.txt` 定义应用、格式与 IO 库，`tests/CMakeLists.txt` 定义格式、版本分发及 CLI 测试。可使用 `-DBUILD_TESTING=OFF` 关闭测试目标。

当前代码按职责分层：`src/cli/` 负责命令解析与展示，`src/app/` 负责版本分发，
`src/app/v1/` 负责 v1 文件流程，`src/format/v1/` 保存 v1 协议与 Registry，
`src/io/` 和 `src/platform/` 提供共享文件操作。CLI 不依赖 v1 格式类型。

## 加密与解密文件

```powershell
.\build\filecrypt.exe encrypt .\input.txt .\input.fcry
.\build\filecrypt.exe decrypt .\input.fcry .\restored.txt
```

加密要求输入并确认密码，解密只输入一次；终端输入隐藏回显。也支持从标准输入读取密码行，
适合通过受控管道自动化，不接受命令行明文密码。密码保持原始字节语义，CLI 拒绝空密码。
Windows 交互式密码转换为 UTF-8，管道输入需要提供 UTF-8；密码行的换行符不属于密码。
当前密码输入运行限制为 1 MiB，不是协议限制。

默认算法为 AES-256-GCM，可指定 `--algorithm xchacha20-poly1305`。
两种算法均使用 Argon2id、每文件独立随机 Salt 与 Nonce，并将真实 Tag 写回 Metadata。
当前命令只处理普通单文件，不支持压缩或目录；已有输出绝不覆盖。

加密和解密均使用目标同目录的受限权限临时文件，失败自动清理；解密在整条消息认证成功后才发布输出。
POSIX 使用 0600 权限，Windows 临时文件和最终文件只允许所有者及 SYSTEM 访问。
普通文件加密不保存原始文件名、时间戳或权限，解密输出路径由用户指定。

当前可调整的运行默认值为内存 65536 KiB、3 次迭代、1 lane，最终生产策略仍待跨平台评估。
可使用 `--memory-kib N --iterations N --parallelism N` 修改加密成本；实际值全部写入 Metadata。
加密和解密的默认 KDF 资源上限为 262144 KiB、10 次迭代、16 lanes，
可使用 `--max-memory-kib N --max-iterations N --max-parallelism N` 显式调整。
它们是运行策略，不是 v1 协议常数；超限会在 KDF 计算和输出创建前拒绝。

## 生成 Header 与 Metadata 示例

```powershell
.\build\filecrypt.exe sample .\example.fcry --directory
```

默认使用 AES-256-GCM、单文件、无压缩。可通过以下选项改变布局：

* `--algorithm aes-256-gcm` 或 `--algorithm xchacha20-poly1305`
* `--directory`：目录布局，Index Length 占位值为 0
* `--compressed`：增加 Zstandard Metadata，不实际执行压缩

示例只有合法的 Header 与 Metadata 字节，不包含真实加密载荷。Salt、Nonce、Tag 使用固定占位值，KDF 成本仅用于格式演示；不能作为真实加密文件或生产默认配置使用。已有路径不会被覆盖。

## 读取公开格式信息

```powershell
.\build\filecrypt.exe info .\example.fcry
```

程序显示文件名、版本、算法、压缩状态、目录状态、KDF 参数、字段长度与载荷是否存在。它只检查 Header 和 Metadata 的格式，始终显示“认证状态：未验证”，不需要密码，也不验证载荷真实性。

## 内存密码接口

`include/filecrypt/crypto/crypto.hpp` 提供独立的 `FileCrypt::Crypto` 库接口：

* `derive_key`：显式传入 Argon2id 内存 KiB、迭代次数、并行度、资源上限与密钥长度；当前支持 32 字节密钥。
* `random_bytes`：生成安全随机 Salt 与 Nonce。
* `CipherContext`：AES-256-GCM 或 XChaCha20-Poly1305 增量处理，`finish` 返回或验证独立 Tag。
* `encrypt`、`decrypt`：单消息内存接口，`decrypt` 只在认证成功后返回完整明文。

密码、密钥和明文建议使用 `SecureBytes`；调用者负责尽快释放敏感数据。
增量 `update` 的解密输出尚未认证，只能放入受控临时输出；不能当作最终明文发布。
`finish` 或处理错误后上下文关闭，不能重试或复用。认证失败统一抛出 `AuthenticationError`。
Crypto 接口的 KDF 参数及资源策略由调用者显式指定，测试成本仅用于快速验证。Crypto 不理解文件版本或协议 ID，
由版本应用流程负责转换参数；测试已验证其与 v1 AAD、Metadata 的衔接。
CLI 已通过 v1 应用流程接入 Crypto，`info` 的公开信息读取仍不执行认证。

Metadata 使用 [v1 协议边界](docs/PROTOCOL_BOUNDARIES_V1.md) 中的顺序：字段、零填充、末尾 Tag；具体编号与参数见 [v1 Registry](docs/REGISTRY_V1.md)，后续工作见 [TODO](docs/TODO.md)。

当前实际验证环境为 Windows/MinGW；MSVC、Linux 尚未验证。中文输出为 UTF-8，终端需使用对应编码；Windows Unicode 命令行路径支持仍待完善。
