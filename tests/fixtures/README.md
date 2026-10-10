# 目录集成测试素材

`directory-corpus.zip` 用于真实目录大小下的 CLI 加密与恢复回归。ZIP 保留原始字节、Unicode 名称和空目录，不受 Git 换行转换影响。素材是合成文本及二进制数据，不包含链接。

- 67 个文件（包含原 `manifest.json`）、16 个子目录，总计 5,920,768 字节。
- 空文件、空目录、单字节、完整字节值、零填充、随机数据，最大文件 4 MiB。
- CRLF / LF / UTF-8 BOM、多语言内容、CSV / JSON、空格和标点文件名。
- 多层目录、中日韩文件名及 Emoji。

原 manifest 的 66 项大小及 SHA-256 已全部核验。原 README 中 `manifest.sha256` 应理解为 `manifest.json` 内的 `sha256` 字段；原文件保持原样。

外部的 `directory-corpus.json` 额外记录 ZIP SHA-256、全部 67 个文件的大小与哈希以及 16 个目录路径。因此也能验证原 manifest 自身、空目录及多余条目。

测试 `cli_directory_corpus` 先校验 ZIP 和解包树，再执行 AES-256-GCM / XChaCha20-Poly1305 与压缩 / 不压缩的四组往返，拒绝错误密码，最后确认源目录未改变。每轮夹具独立，成功后清理，失败保留现场。使用测试专用低成本 KDF 参数，不作为生产参数建议。

```powershell
ctest --test-dir build -C Release -R "^cli_directory_corpus$" --output-on-failure
```

Windows Actions、Linux 构建容器及发行版/CPU 运行矩阵均执行此测试。素材补充正常目录往返覆盖；恶意 Index、链接、事务竞态和资源限制仍由现有测试验证。
