# FileCrypt

使用 C++23 编写的跨平台文件加密工具，目前已实现 Header、Metadata 编解码和公开格式信息读取。

## 构建与测试

需要 CMake >= 3.24、C++23 编译器，不依赖 Botan 或 zstd。

使用 Ninja，将整个项目构建到 `build/`：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Visual Studio 等多配置生成器使用 `cmake --build build --config Release`，
测试时增加 `-C Release`；可执行文件一般位于 `build/Release/`。

`build/` 曾使用其他生成器时，在配置命令中增加 `--fresh` 重建 CMake 缓存。

个人构建预设可放在 `CMakeUserPresets.json`，该文件已被 Git 忽略，不随仓库分发。

根 `CMakeLists.txt` 管理项目标准、CLI 和测试开关；`src/CMakeLists.txt` 定义格式库与 IO 库，`tests/CMakeLists.txt` 定义格式及 CLI 测试。可使用 `-DBUILD_TESTING=OFF` 关闭测试目标。

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

Metadata 使用 [v1 协议边界](docs/PROTOCOL_BOUNDARIES_V1.md) 中的顺序：字段、零填充、末尾 Tag；具体编号与参数见 [v1 Registry](docs/REGISTRY_V1.md)，后续工作见 [TODO](docs/TODO.md)。

当前实际验证环境为 Windows/MinGW；MSVC、Linux 尚未验证。中文输出为 UTF-8，终端需使用对应编码；Windows Unicode 命令行路径支持仍待完善。
