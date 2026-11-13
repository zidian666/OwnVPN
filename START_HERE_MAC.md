# OwnVPN：Mac 开发入口

同一主干包含 Windows、Android 和 macOS 平台目录。Mac 当前为 `0.6.0-alpha.1` 的开发基础，提供 AppKit 界面、配置导入、Keychain、TOTP 和二维码识别；**尚未接入 VPN 后台服务，不能建立 VPN 连接**。

在 Mac 上获取最新源码后执行：

```bash
git clone https://github.com/zidian666/OwnVPN.git
cd OwnVPN
bash tools/inspect_macos.sh
bash build-macos.sh
```

需要 CMake 和支持 C++20 `std::stop_token` 的当前 Xcode / Command Line Tools。构建脚本最低目标设为 macOS 15，默认构建本机架构；也可传 `--arch arm64`、`--arch x86_64` 或 `--arch universal`。输出位于 `dist`，包含版本号，仅做本机 ad-hoc 签名，没有 Developer ID 签名或公证。

继续开发前阅读 [Mac 开发状态与验收](docs/macos-development.md)、[后台连接设计](docs/macos-porting.md) 和 [多平台构建](docs/multiplatform-build.md)。窗口的连接按钮明确不可用，不能把界面、公共核心或离线测试通过当作实连成功。

给 Mac 上开发会话的任务：

```text
请继续当前 OwnVPN 主干的 macOS 实现，不复制公共核心或创建永久的平台分支。
先阅读 START_HERE_MAC.md、docs/macos-development.md、docs/macos-porting.md。
执行只读环境检查，再构建和运行离线测试，修复本机实际遇到的问题。

现有 AppKit 界面、Keychain、CommonCrypto、Vision QR 和配置导入已有代码，
不要重新实现 TOTP，也不要以 root 启动整个界面。
下一阶段实现 IConnectionBackend、官方 OpenVPN 2.x 进程适配、受控后台权限服务、
管理接口启动放行、逐条命令确认、取消、断开、自动重连和 DNS/路由恢复。
优先在环回服务器、公开合成凭据下验证，保持真实连接按钮禁用直到后端可用。

真实公司配置、PEM、CA/TLS 文件、二维码和登录资料在 Mac 本机单独导入，
不要从公开仓库寻找这些资料，也不要让我把密码或绑定密钥发送到聊天中。
最终需要实测公司内网分流、认证拒绝、重复连接、取消和睡眠唤醒，
Windows 与 Android 既有功能和构建应继续保留。
```
