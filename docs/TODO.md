# TODO

只保留尚未完成的工作；构建、运行和已完成模块说明见 [README](../README.md) 与协议文档。

## 下一步：AAD 与正式密码库接口

- 按 `PROTOCOL_BOUNDARIES_V1.md` 实现 AAD 构造：Header + Metadata[0 : TagOffset]，包含 Padding，排除 Tag。
- 用固定字节向量测试 AAD，验证修改 Tag 不改变 AAD、修改 Header 或其他 Metadata 字段会改变 AAD。
- 将 PoC 验证结果转化为独立的正式 Crypto 接口，不直接复制为最终实现。
- 实现按 Metadata 参数重建 Argon2id 密钥、安全随机 Salt 与 Nonce、流式 AEAD 和独立 Tag。
- 确定生产 KDF 默认参数和运行时资源策略，区分协议合法参数与本机允许执行的参数。

## 后续：真实文件加解密

- 实现单文件加解密、密码输入及确认、敏感内存管理。
- 完成加密后写回真实 Tag；解密认证成功后才提交临时输出。
- 接入可选 Zstandard 压缩与解压，检查消息长度及运行时资源限制。
- 实现目录 Index 编解码、树结构校验、连续 File Data 和目录恢复。
- 按协议边界验证 UTF-8 名称及路径组件，并在恢复时执行目标平台名称与冲突检查。

## 跨平台与工程完善

- 实际运行 MSVC、Linux/GCC 构建和相同测试；当前仅验证 MinGW。
- 完善 Windows Unicode 命令行路径与终端编码处理。
- 整理编辑器任务，统一使用 CMake 构建。
- 完善 CLI 错误分类、用户帮助与发布说明。
