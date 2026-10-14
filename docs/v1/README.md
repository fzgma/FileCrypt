# FileCrypt v1 文档

本目录保存当前已实现的 v1 协议及相应实现说明。文档迁移不改变既有字段、编号、密码字节、认证范围或文件兼容性；已冻结的规范继续保持冻结。

- [文件格式](FILE_FORMAT.md)
- [扩展名、算法及参数编号](REGISTRY_V1.md)
- [协议边界](PROTOCOL_BOUNDARIES_V1.md)
- [密码学设计](CRYPTOGRAPHY.md)
- [压缩实现](COMPRESSION.md)
- [目录格式](DIRECTORY_FORMAT.md)
- [目录实现与运行策略](DIRECTORY_IMPLEMENTATION.md)

各版本共用的 [架构](../ARCHITECTURE.md)、[错误语义](../ERROR_HANDLING.md)、[Linux 发布说明](../LINUX_RELEASE.md)、[Windows 发布说明](../MSVC_RELEASE.md)及 [TODO](../TODO.md)继续放在 `docs/` 根目录。

后续格式设计见 [v2 计划](../v2/README.md)。新版按文件版本进入完整的 v1 或 v2 流程；历史 v1 文件无需为了继续使用而迁移，普通读取、验证和换密不暗中改变文件格式。
