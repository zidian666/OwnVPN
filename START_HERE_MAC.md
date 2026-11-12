# OwnVPN：给 Mac 上 Codex 的入口

这是 **OwnVPN 0.2.7 的 Windows C++ 源码及 macOS 迁移交接包**，不是已经能运行的 Mac 应用。当前 CMake 和 Win32 界面不能在 macOS 上直接编译。

## 到 Mac 后怎么用

1. 解压压缩包，用 Codex 打开解压后的项目文件夹。
2. 将下面的提示词发给 Codex。详细技术交接见 [docs/macos-porting.md](docs/macos-porting.md)。
3. 公司 `.ovpn`、`users.pem`、配套 CA/TLS 文件、个人二维码和密码均未打包。迁移完成后，在 Mac 本机单独导入和填写。Windows 凭据管理器中的密码及 TOTP 绑定不能靠本压缩包搬过去。
4. `third_party/` 附带已固定版本、校验过的 ZXing-C++ 上游源码及许可证。`PACKAGE_MANIFEST.json` 记录包内文件 SHA-256；压缩包旁的 `.sha256` 用于传输校验。

## 可以直接复制给 Codex 的提示词

```text
请先阅读 START_HERE_MAC.md、docs/macos-porting.md、docs/architecture.md 和 README.md，
然后实际把 OwnVPN 0.2.7 移植为本机可运行的 macOS 桌面应用，不要只给迁移建议。

先检测本机 macOS 版本、CPU 架构、Xcode/Command Line Tools、CMake、Qt 和 OpenVPN 环境。
默认优先用 C++20 + Qt 6 Widgets 重建 Mac 界面，复用现有业务逻辑；有更合适的本机方案时说明理由。
保留 Windows 版本，将平台代码分开，先拆除 core.h 对公共业务头文件的 Windows API 依赖。

功能必须保留：导入 .ovpn 和配套 users.pem、公司内网分流、用户名、密码、6位验证码，
提交密码时直接拼接验证码；TOTP 二维码绑定和实时只读预览；记住密码、显示密码、复制按钮；
自动重连、模拟断线测试、可展开的诊断与使用说明、可点击的二维码门户链接、字母 O 图标。
保留管理接口主动放行和逐条命令应答的修复，不能恢复为仅等待 HOLD 通知。
服务器拒绝认证后停止自动重试；手动断开或退出不重连；预览不消耗验证码使用周期。

Mac 上使用 Keychain 保存密码和 TOTP 密钥，采用正规的系统权限方案管理 VPN 后台进程。
不要把整个 GUI 长期以 root 运行，不要把密码、验证码、种子或证书私钥写入日志、命令行或仓库。
本包没有真实公司配置和个人绑定资料：先完成离线模块、界面、构建和本机测试，
到真实连接验证时再让我在 Mac 本机导入，不要让我把密码或绑定密钥发到聊天中。

最终交付能在本机编译运行的 .app、构建脚本、模块说明及测试结果；明确区分已通过的模拟测试、
本机真实 OpenVPN 探测和公司 VPN 实连验证，不能以模拟成功代替真实连接成功。
```

## 推荐的第一步

先执行只读环境检查：`sw_vers`、`uname -m`、`xcode-select -p`、`clang++ --version`、`cmake --version`，并检查已有的 Qt/OpenVPN 安装。不要在这份 Windows CMake 上直接换一个编译器就声称完成迁移。

优先做内部自用、Mac 上本地运行的版本。签名、公证、分发及是否改用 Network Extension，在确定目标 macOS 和分发方式后落实，见迁移文档。
