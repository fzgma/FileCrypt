# Linux x86-64 发布与支持政策

Linux 发布目标为通用 x86-64，最低支持 glibc 2.34；不强制要求 x86-64-v2。
正式支持的系统还必须处于发行版提供的维护期，满足 glibc 版本只是必要条件。
Alpine Linux 与其他 musl 系统暂不支持。

EOL 系统不承诺兼容，也不纳入正式测试矩阵。这是支持政策，不是运行时拦截规则：
不检查发行版名称、支持截止日期或人为提高最低符号版本，旧系统恰好可以运行时不刻意破坏兼容性。

## 构建与链接

- 使用仍在维护的 AlmaLinux 8 系 `quay.io/pypa/manylinux_2_28_x86_64` 构建，发布产物所需 glibc 符号不得高于 2.34。
- 程序和 Botan 均显式使用 `-march=x86-64 -mtune=generic`，不使用 `-march=native`。
- Botan 3.13.0 从官方源码构建静态库，校验固定 SHA-256；不使用发行版预编译的 Botan。
- Zstandard 1.5.7 同样从官方源码构建静态库并校验固定 SHA-256，使用通用 x86-64 编译选项。
- 使用 `-static-libstdc++ -static-libgcc` 优先静态链接 C++ 运行库，产物审计要求不再依赖它们的共享库。
- glibc 继续动态链接，不使用 `-static`，不尝试完全静态链接 glibc。

Linux 构建脚本为 [.github/scripts/build-linux.sh](../.github/scripts/build-linux.sh)。
`Botan_USE_STATIC_LIBS=ON` 要求通过 `PKG_CONFIG_PATH` 指向同一 Botan 安装前缀的
`botan-3.pc`，以读取静态传递依赖；普通开发构建默认仍查找共享库。

manylinux 的兼容承诺针对 Python wheel，本项目借用其构建环境，不将其视为 ELF 兼容认证。
构建环境低于项目支持下限是有意选择：RHEL 9 系预编译库（包括静态 C++ 运行库）可能以
x86-64-v2 为目标，选择 AlmaLinux 8 系工具链可避免把该要求带入程序。
构建环境的 glibc 2.28 不意味着项目承诺支持 glibc 2.28；正式支持下限仍为 2.34，
不人为引入 2.34 符号来阻止旧系统运行，也不将更旧系统纳入正式矩阵。
Botan 的可选指令集优化保留运行时 CPU 探测，不能全局强制启用 AVX、SSE4 等指令。

## 验证与分发

Linux 和 MSVC 构建后分别执行 7 项单元测试、3 项正式程序冒烟测试和 2 项文件/目录流程集成测试。
Windows 另执行 1 项隐藏控制台测试，验证非 UTF-8 代码页下的中文标准输出、错误输出及退出后的代码页恢复。
冒烟测试直接调用正式可执行文件，验证格式生成与读取、两种算法的压缩及无压缩加解密、密码错误和已有输出保护；
CLI 测试同时覆盖中文、空格及 emoji 路径和重定向 UTF-8 输出；Windows 控制台测试也使用 `smoke` 标签。
CTest 标签为 `unit`、`smoke`，冒烟测试同时保留 `integration` 标签。
Linux 随后审计正式程序和测试程序的 ELF：

- ELF64、x86-64，使用 `/lib64/ld-linux-x86-64.so.2` 动态加载器。
- 所需 glibc 符号不高于 2.34，不允许私有或未知 glibc ABI。
- 动态依赖仅允许 glibc 系统库，不允许 Botan、Zstandard、libstdc++、libgcc 或其他第三方共享库。
- ELF ISA 必需属性不能声明 x86-64-v2/v3/v4；属性检查不能替代实际运行验证。

同一批已编译程序会在以下正式矩阵中执行全部 12 项对应测试，不重新编译：

| 发行版 | 测试版本 |
| --- | --- |
| Ubuntu | 22.04、24.04 |
| Debian | 12（LTS）、13 |
| AlmaLinux | 9 |
| Arch Linux | 当前滚动版本 |

矩阵按 2026 年 10 月的维护状态选取；版本进入 EOL 后移除或替换，不以付费延长支持作为正式支持前提。
额外在 Ubuntu 22.04 中使用 QEMU `qemu64` CPU 执行同样测试，检查不满足完整 x86-64-v2 的机器路径。
容器测试共用宿主内核，不代表已经验证所有历史内核或所有 CPU；原生机器的实际测试仍有价值。

只有上述 Linux 验证全部通过后才上传 `filecrypt-linux-x86_64` Artifact，保留 14 天，
内容只有正式可执行文件 `filecrypt`；测试程序、依赖源码、文档和构建信息均不上传。
构建版本、依赖校验信息及 ELF 审计结果留在 Actions 日志。
Artifact 下载不保留执行权限，解压后运行 `chmod +x filecrypt` 即可使用，
无需另外安装 Botan、Zstandard 或 C++ 运行库。Windows MSVC 同样在测试通过后上传仅含 `filecrypt.exe` 的
`filecrypt-windows-x86_64` Artifact，依赖与 MSVC 运行库静态链接，vcpkg 仅编译 Release。

推送 `v*` 标签触发独立发布工作流，复用上述两平台构建测试；全部验证成功后下载同次运行的 Artifacts，
将 Linux 和 Windows 可执行文件分别命名为 `filecrypt-linux-x86_64`、`filecrypt-windows-x86_64.exe`，
生成包含两者 SHA-256 的 `SHA256SUMS` 并创建 GitHub Release；任一验证失败均不发布。

v0.2.0 的 Linux 与 MSVC Actions 验证已由用户确认全部成功。本阶段新增目录功能的 Linux/发行版矩阵/CPU 模拟及 MSVC 验证待新一轮 Actions 确认；Windows/MinGW 本地检查同步记录在 TODO。

## 参考资料

- [manylinux 构建环境与 x86-64-v2 注意事项](https://github.com/pypa/manylinux#readme)
- [GCC 静态运行库链接选项](https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html)
- [GCC x86 目标指令集选项](https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html)
- [Botan 构建与模块裁剪](https://botan.randombit.net/handbook/building.html)
