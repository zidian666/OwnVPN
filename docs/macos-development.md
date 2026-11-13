# macOS 开发与测试

当前 Mac 平台版本为 `0.6.0-alpha.1`，是开发基础，VPN 隧道尚未接入。源码保留在同一主干，Windows 仍为 0.4.0，Android 为 0.5.0-alpha.2。

## 已实现的代码

| 文件 | 责任 |
| --- | --- |
| `src/platform/macos/mac_app.mm` | AppKit 窗口、文件选择、账号输入、只读自动验证码、复制、菜单栏入口 |
| `mac_import.*` | 原始 ZIP 和独立 .ovpn 导入；保留相对依赖，缺失文件可显式选择；临时文件清理 |
| `mac_keychain.mm` | SecItem 按配置和字段读写；使用独立服务名，不同步 iCloud，无明文降级 |
| `mac_crypto.cpp` | 系统 CommonCrypto HMAC/SHA、SecRandomCopyBytes |
| `mac_network.cpp` | IP 字面量和带超时、取消的 DNSServiceGetAddrInfo |
| `mac_platform.mm` | Application Support 路径、目录权限、平台接口组装 |
| `mac_qr.mm` | Vision 识别单个 TOTP 二维码，ImageIO 检查图片尺寸 |

公共配置、证书复制、分流策略、凭据、TOTP 计算和仓库继续来自 `ownvpn_core`。Keychain 操作与导入在串行后台队列执行。预览只计算当前验证码，不消耗认证使用周期。首次没有绑定时保持手动模式；绑定保存为自动模式。

用户资料位于 `~/Library/Application Support/OwnVPN`，私有目录为 0700，进程使用 0077 umask。Mac 本机重新导入公司附件及绑定资料；不迁移 Windows 凭据。ZIP 拒绝绝对路径、目录穿越、链接和特殊文件，并限制数量及解压大小。

开发版使用 SecItem 的 Mac 文件式 Keychain，便于本地 ad-hoc 构建和测试；正式签名和访问控制策略应在目标 Mac 确定后验证。访问 Keychain 可能需要系统确认，失败会报告错误，不改存普通配置文件。平台差异见 [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)。

## 构建和检查

```bash
bash tools/inspect_macos.sh
bash build-macos.sh
# 或指定架构
bash build-macos.sh --arch universal
```

需要 macOS、CMake 和当前 Apple SDK/C++20 工具链，最低部署目标为 macOS 15。脚本不下载公司资料、不请求 root、不更改 VPN。构建、CTest、ad-hoc 签名验证通过后，输出 `dist/OwnVPN-Mac-0.6.0-alpha.1-<架构>.app`、ZIP 和 SHA-256。为避免覆盖已有产物，重复发布前先移动上一份输出。

ZIP 读取静态链接固定的 libarchive 3.8.11 官方源码，下载时校验 SHA-256，只使用系统 zlib，不依赖另一台机器的 Homebrew 动态库。固定值见 `cmake/MacDependencies.cmake`，上游 COPYING 随应用放在 `Contents/Resources/licenses`，组件说明见 [第三方声明](macos-third-party-notices.txt)。

`macos_platform_tests` 包含 18 组 RFC6238 向量、SHA256、随机源、私有目录、配置依赖、ZIP 清理及路径边界、IP/取消、Vision QR 样本。默认不读写用户 Keychain，不解析真实域名，不发起 VPN。显式运行以下命令会在随机命名的测试服务内写入公开合成样本，再删除该条目：

```bash
build-macos-$(uname -m)/src/platform/macos/macos_platform_tests --keychain
```

GitHub Actions 的 `macOS` 流程覆盖 Apple Silicon 和 Intel 构建、离线测试及构建产物保存；没有公司配置、账号、VPN 授权或实连任务。流程结果以对应提交的实际运行记录为准。Windows 本机只验证了脚本语法、CMake 平台隔离及原有 5/5 回归，不能代替 Mac 编译和运行。

## 仍需实现和验收

连接按钮目前禁用，防止假成功。下一阶段是 [macOS 连接后台](macos-porting.md)：权限服务、官方 OpenVPN 进程、受限 IPC、管理协议、DNS 配置恢复、自动重连和流量状态。随后在真实 Mac 上验证布局、Keychain 权限、文件选择、菜单栏及多屏，再进行公司 VPN 实连。

参考：[Keychain](https://developer.apple.com/documentation/security/keychain-services)、[Vision QR](https://developer.apple.com/documentation/vision/vndetectbarcodesrequest)、[SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)。
