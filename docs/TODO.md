# TODO

本文件只保留尚未完成的工作及关闭待办所需的验证依据。每完成一个实现、修复或验证步骤，核对代码与测试现状并立即更新；已实现但待验证的事项明确标注验证范围，收到对应结果后再关闭。已完成模块及使用说明见 [README](../README.md)、[目录实现](DIRECTORY_IMPLEMENTATION.md)与[测试素材说明](../tests/fixtures/README.md)。

## 当前：cpp23perview 分支 GCC 15 构建验证

- GCC 15 工作流改动已恢复到最新本地 main（e9348e2）基础，保留最新素材、UTF-8 locale、Linux 共享 CTest 注册及 MSVC vcpkg 缓存。Linux 在原 manylinux_2_28 底座内使用 GCC Toolset 15，显式选择项目与依赖工具链，Zstandard 固定 C17，并执行 C++23 静态预检及 ELF/发行版/CPU 验证；待 Actions 实际验证 GCC 15 包安装、运行库、全量构建和运行矩阵。本机无 Docker/Linux 环境。
- Actions 已安装 GCC 15.2.1，并确认 Toolset 的 libstdc++.a 与 libgcc.a 路径；首次运行因错误要求 libstdc++exp.a 而在预检编译前停止。已移除该检查和链接参数，保留全部 C++23 功能预检；待重新运行 Actions 验证预检、全量构建及发行版/CPU 矩阵。

## 后续：运行策略

生产资源默认值评估暂缓，后续再开展。本阶段继续使用现有默认值和可调限制。后续评估需测量目标机器上的 KDF 耗时与峰值内存、大文件及大量小文件的处理开销、解压窗口和累计输出限制，以及临时磁盘峰值占用和写满后的清理行为。

- 确定生产 KDF 默认参数和运行时资源策略，区分协议合法参数与本机允许执行的参数。
- 结合真实文件评估解压窗口、累计输出上限及临时磁盘资源策略，保持与协议限制分离。

## 跨平台与工程完善

- 补齐 MSVC 环境诊断与符号链接夹具跳过报告；配置本地独立 MSVC 构建，并覆盖 Unicode 测试根路径。
- Linux 测试注册已提取为共享 CTest 定义，发行版/CPU 复验只配置测试并执行 CTest。需实际验证。
- 完善 CLI 错误分类、用户帮助与发布说明。

GCC 15 原始储藏 `cpp23perview GCC15 workflow WIP` 和迁移前备份 `cpp23perview GCC15 rebase onto local main` 均保留。
