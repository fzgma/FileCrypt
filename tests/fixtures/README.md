# 目录集成测试素材

`directory-corpus.zip` 用于真实目录大小下的 CLI 加密与恢复回归。ZIP 保留原始字节、Unicode 名称和空目录，不受 Git 换行转换影响。素材包含合成文本、二进制数据和照片，不包含链接；2026-10-10 从更新后的 `FileCrypt_Directory_Test` 目录重新打包。

- 93 个文件（包含原 `manifest.json`）、23 个子目录，总计 23,621,278 字节；ZIP 为 22,918,463 字节。
- 空文件、空目录、单字节、完整字节值、零填充、随机数据及重复内容；最大文件为 9,981,045 字节的 JPEG。
- CRLF / LF / UTF-8 BOM、多语言内容、CSV / JSON、空格和标点文件名。
- 多层目录、中日韩文件名及 Emoji、长文件名、特殊标点、NFC/NFD 名称。
- 5 张照片及原 `09-photo/SOURCES.md`，其中记录来源和 CC0 许可；该说明随素材完整保留。

原 manifest 的 92 项大小及 SHA-256 已全部核验。原 README 中 `manifest.sha256` 应理解为 `manifest.json` 内的 `sha256` 字段；原文件保持原样。

外部的 `directory-corpus.json` 额外记录 ZIP SHA-256、全部 93 个文件的大小与哈希以及 23 个目录路径。因此也能验证原 manifest 自身、空目录及多余条目。

Windows 使用系统 PowerShell 调用 .NET ZIP 解包，Linux 使用 Info-ZIP `unzip` 解包，二者都保留原始 NFC/NFD 名称；本地 CMake/libarchive 解包会将 NFD 名称归一化成 NFC。Linux CI 脚本会安装 `unzip` 并设置 UTF-8 locale。

测试 `cli_directory_corpus` 先校验 ZIP 和解包树，再执行 AES-256-GCM / XChaCha20-Poly1305 与压缩 / 不压缩的四组往返，拒绝错误密码，最后确认源目录未改变。每轮夹具独立，成功后清理，失败保留现场。使用测试专用低成本 KDF 参数，不作为生产参数建议。

```powershell
ctest --test-dir build -C Release -R "^cli_directory_corpus$" --output-on-failure
```

Windows Actions、Linux 构建容器及发行版/CPU 运行矩阵均执行此测试。素材补充正常目录往返覆盖；恶意 Index、链接、事务竞态和资源限制仍由现有测试验证。
