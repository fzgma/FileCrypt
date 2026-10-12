# Windows MSVC x64 发布

Windows 正式程序由 MSVC x64 构建，以单个可执行文件分发。当前 CI 使用 `windows-latest` runner（Windows Server 2025）、Visual Studio 2026 和 PowerShell；该构建环境不代表已经验证所有 Windows 版本。

## 构建与链接

[构建测试工作流](../.github/workflows/build-test.yml)的 `msvc` 任务使用 runner 提供的 vcpkg 安装 Botan 和 Zstandard，依赖版本随该 vcpkg checkout 的 ports 确定。

自定义 [x64-windows-release triplet](../cmake/triplets/x64-windows-release.cmake)要求 x64、静态依赖库、静态 MSVC 运行库，并且仅构建 Release。项目使用 Visual Studio 18 2026 多配置生成器，设置 `CMAKE_CONFIGURATION_TYPES=Release` 和 `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`，通过 `Botan_USE_STATIC_LIBS=ON`、`Zstd_USE_STATIC_LIBS=ON` 链接静态依赖。

MSVC 编译启用 `/EHsc` 和 `/utf-8`，将缺少异常展开语义的警告视为错误，确保输出事务清理与 Unicode 源码处理符合预期。正式程序及全部测试通过 `build_all` 目标构建。

## vcpkg 二进制缓存

MSVC 使用 GitHub Actions Cache 保存独立目录中的 vcpkg 二进制包，通过 `VCPKG_BINARY_SOURCES` 配置文件缓存的读写。恢复前缀包含 Windows 构建环境、vcpkg checkout 版本和 Release triplet 内容哈希；vcpkg 根据包 ABI 检查决定能否复用，工具链或依赖变化时重编译受影响的包。

依赖安装成功且新增二进制包后立即保存缓存，保存位于项目构建与测试之前，后续测试失败也能复用依赖。保存键包含运行编号和重跑次数，允许补充新的 ABI 包；全部复用时不重复保存。默认分支建立的缓存可供后续标签运行读取。本轮缓存验证已由用户确认完成。

## 验证与分发

MSVC 构建后执行 8 项单元测试、4 项正式程序冒烟测试和 3 项非冒烟集成测试，共 15 项：

- 单元测试覆盖 Header、Metadata、AAD、版本识别、密码学、压缩、目录格式及 Format 层 expected 接口。
- 冒烟测试覆盖信息读取、文件及目录 CLI 加解密，以及隐藏控制台测试。控制台测试验证非 UTF-8 代码页下的中文标准输出、错误输出及退出后的代码页恢复。
- 非冒烟集成测试覆盖文件/目录 API 流程和 `cli_directory_corpus`，素材测试执行两种算法与压缩开关四组往返，校验 93 文件、23 子目录的完整树、大小与 SHA-256，并拒绝错误密码。

CLI 与目录流程同时覆盖中文、空格、emoji 路径、Windows 名称限制、junction 拒绝和已有输出保护。CTest 使用 `unit`、`integration`、`smoke`、`corpus` 标签；非冒烟集成测试通过 `-L integration -LE smoke` 选择。

全部测试通过后，将正式程序复制到独立目录，把 `PATH` 缩减为 Windows 系统目录，并执行帮助命令，验证程序无需随附第三方 DLL 或 MSVC 运行库。

验证成功后上传 `filecrypt-windows-x86_64` Artifact，保留 14 天，内容只有正式程序 `filecrypt.exe`；测试程序、依赖源码和构建信息均不上传。上传显式设置 `archive: true` 保留命名 ZIP Artifact。

推送 `v*` 标签触发[发布工作流](../.github/workflows/release.yml)。发布阶段从同次运行下载 Windows Artifact，将正式程序命名为 `filecrypt-windows-x86_64.exe`，纳入 `SHA256SUMS` 并上传 GitHub Release。发布工作流要求全部构建验证任务成功，任一失败均不发布。

本轮目录素材、路径修复及缓存的 MSVC Actions 验证已由用户确认完成。后续改动的验证待办见 [TODO](TODO.md)；本地 MinGW 测试结果不替代 MSVC 验证。
