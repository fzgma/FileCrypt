# FileCrypt 文档

程序发布版本与文件格式版本分别管理；`v1.1.0` 发布使用的文件格式仍为 v1。当前代码只实现 v1，v2 文档处于设计阶段。

| 范围 | 入口 |
| --- | --- |
| 已有文件格式与实现 | [v1 文档](v1/README.md) |
| 下一代格式范围、设计与验收计划 | [v2 文档](v2/README.md) |
| 版本分发与共享模块 | [项目架构](ARCHITECTURE.md) |
| 错误分类与接口约定 | [错误语义](ERROR_HANDLING.md) |
| 跨平台构建与分发 | [Linux](LINUX_RELEASE.md)、[Windows MSVC](MSVC_RELEASE.md) |
| 尚未完成的工作 | [TODO](TODO.md) |

v1 规范按其冻结状态维护；v2 草案中的未决参数和字段不能作为已发布格式使用。共用代码的改动仍须保持 v1 历史文件回归。
