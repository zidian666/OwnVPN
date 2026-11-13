# macOS 迁移技术交接

当前仓库已升级至 0.4.0 架构：先阅读 [同一主干的多平台构建](multiplatform-build.md)，复用 `src/core/` 并为 `Platform()` 和 `IConnectionBackend` 提供 macOS 实现。以下内容是 0.2.7 历史交接包的说明，其中“公共头文件引入 Windows API”等旧拆分任务已在 0.4.0 处理，不应重新复制一套业务代码。

## 当前基线与包的边界

- 交接基线为 OwnVPN 0.2.7，C++20、Win32 原生界面、CMake；Windows 使用已安装的官方 OpenVPN 2.x 可执行文件及管理接口。它没有链接 OpenVPN GUI 的库，也不控制官方 GUI 的窗口。Windows 上曾检查到 OpenVPN 2.7.8；这不是 Mac 上必须照搬的安装版本。
- 已实现真实公司 VPN 登录，认证约定已由用户确认：**用户名单独提交，密码后直接追加 6 位动态验证码，无分隔符**。只接受公司内网路由，普通互联网流量保留本地默认路由。
- 包含所有项目源码、测试、公开测试二维码、图标、文档、构建脚本及固定的 ZXing-C++ 3.1.1 原始源码归档。不含 Windows 编译器、OpenVPN/驱动二进制和本机构建缓存。
- 不含个人 `.ovpn`、`users.pem`、证书私钥、二维码、密码、TOTP 种子、运行日志、Windows 凭据或 AppData。`tests/fixtures/` 中二维码是公开测试密钥生成的合成样本，不是公司账号。
- Windows 0.2.6 已实测首次连接及模拟断线后的自动重连成功，后一次复用同一个已授权 helper。0.2.7 增加可展开的使用说明，现有三组测试通过。**未验证真实服务器强制踢线、Mac 实连或 Mac 睡眠/唤醒。** 旧 README/architecture 中“尚未实连”等早期描述属于历史记录，以这里的交接状态为准。
- 此次交付没有改写 Mac 代码。还需要在真正的 Mac 上完成实现、构建和验证。

## 建议路线与需要在 Mac 确认的事项

优先考虑 **Qt 6 Widgets + C++20 业务层 + macOS 平台适配 + 官方 OpenVPN 2.x 管理接口**，为 Mac 新增 UI 目标，保留现有 Win32 目标。这是迁移建议，不是用户对框架的硬性要求。Qt 提供 macOS 支持，并允许通过 Objective-C++ 接入平台 API，见 [Qt for macOS](https://doc.qt.io/qt-6.8/macos.html)。

如果更重视纯原生界面，也可以用 SwiftUI/AppKit + Objective-C++/C 接口包住 C++ 核心；额外处理对象生命周期、线程与字符串桥接。不要为了换界面重新实现 TOTP 哈希或完整 OpenVPN 协议。

先检查目标 OS、arm64/x86_64、SDK 和工具链是否支持项目所用的 `std::jthread`、`std::stop_token` 等 C++20 功能。按目标 Mac 选择可用的 Qt 版本，不假设最新 Qt 的所有预构建包都支持所有旧 macOS 或 Intel 机器。

个人/内部自用首版可延续官方核心进程路线。若要采用 Network Extension，需另外实现隧道后端、应用扩展/系统扩展和相应签名能力；不是把 OpenVPN CLI 换名即可。Apple 对 [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider) 要求 Network Extension entitlement；具体分发配置见 [Apple Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)。

## 模块迁移表

| 文件/模块 | 可保留的逻辑 | Mac 上要替换的部分 |
| --- | --- | --- |
| `main.cpp`、`otp_setup_dialog.*`、`usage_panel.*` | 字段含义、交互、状态、帮助文案 | Win32 控件、绘制、消息循环；用 Qt 或原生界面重新实现 |
| `core.*` | 随机数、转换、文件、目录等职责 | `windows.h`、HANDLE、SID/ACL、KnownFolder、BCrypt、Unicode WinAPI；先拆出纯数据类型和平台接口 |
| `protocol.*` | 管理消息解析、认证打包、到期检查、状态事件 | Base64 使用了 Wincrypt；公共头依赖 `core.h`，目前仍会间接包含 Windows API |
| `management_startup.*` | 主动启动放行及进度跟踪，接近纯 C++ | 保留语义；不要因换平台删掉启动修复 |
| `management_commands.*` | 单条在途、精确 ACK、到期禁止发送、待发秘密清理 | 去掉对 Windows 公共头的间接依赖，保留 UTF-8 协议字符串 |
| `reconnect_policy.*` | 退避、倒计时、取消、稳定一分钟后重置 | 接到 Mac 的控制器和网络/休眠事件 |
| `otp_provider.h`、`totp.*` | RFC 6238、URI/Base32、窗口、防重复取码、取消等待 | HMAC/SHA 的 BCrypt 实现、Windows 擦除函数和字符串转换；用成熟加密 API 替换后跑原向量 |
| `totp_preview.*`、`totp_detection.*` | 不消耗使用周期的预览、两轮参数核对 | 公共类型/字符串适配；保留同一手机时间窗口不算第二轮的规则 |
| `credential_store.*`、`totp_store.*` | 按配置和精确用户名隔离、记忆开关、计数记录 | Windows Credential Manager 改为 Keychain，账号标识 SHA-256 也要换后端 |
| `profile.*`、`settings.*` | 配置解析、允许列表、依赖复制、分流策略 | 私有目录和路径、权限、平台选项；不能重用 Windows 绝对路径配置副本 |
| `qr_import.*` | ZXing 单个 QR、旋转/反色、TOTP URI 校验、资源上限 | WIC/COM 图像解码改为 QImage 或 ImageIO；保留多码/非绑定拒绝 |
| `connection_controller.*`、`ipc.*` | 会话内 helper 复用、请求与状态边界、非阻塞取消 | UAC、命名管道、命名事件、PID/API；采用验证对端身份的 Mac IPC/权限实现 |
| `engine.*` | 官方核心生命周期、管理认证、状态机组装与超时 | Winsock、端点进程检查、CreateProcess、句柄继承、Job Object、Windows `--service` 退出事件 |
| `clipboard.*`、图标/超链接 | 复制完整内容、成功反馈、O 图标和固定门户 | NSPasteboard/QClipboard、NSWorkspace/QDesktopServices、`.icns`/app bundle |
| `tests/`、`tools/` | 测试向量、样本和大多数断言 | Windows 进程/管道/凭据测试后端；Windows 凭据诊断工具不适用于 Mac |

注意：这些模块的“逻辑可复用”不等于能原文件直接编译。`core.h` 当前把 Windows 类型带入很多公共头。建议拆成纯 C++ 的事件、配置、接口和通用类型，以及 `platform/windows`、`platform/macos` 实现；避免靠伪造 HANDLE 或空实现绕过编译。

## 必须保持的产品行为

1. 配置导入支持 `.ovpn` 和配套 `users.pem`；依赖文件复制到应用私有位置。支持允许列表内的外部/内嵌材料。保留证书校验，不为“连通”而降低 TLS 校验或开放任意脚本。
2. 用户名、密码、6 位验证码均有界面输入。密码支持记住、显示/隐藏、复制；不再有“记住验证码”。自动模式验证码只读、实时更新、可复制；手动模式可输入。
3. 使用原始 TOTP 二维码/密钥本机绑定，支持 SHA1/SHA256/SHA512 和周期；VPN 当前仅允许 6 位。使用 RFC 测试向量验证成熟 HMAC 后端，不自行实现密码学哈希。
4. 登录时按服务器认证请求获取有效码；距到期不足 5 秒或该周期已经取用则等待下一周期。预览和复制不消耗使用周期；等待可取消。账号/配置/计数记录隔离，时间回退明确报错。
5. 自动重连默认关闭，本次运行勾选后生效。3、6、12、24、30 秒退避，上限 30 秒；稳定一分钟后重置。认证拒绝、验证码不可用、手动取消/断开或退出时停止重试。
6. “测试自动重连”仅在已连接并启用自动重连后可用：注入连接丢失事件，正常清理本次隧道，再走实际重连流程。模拟测试成功不能证明服务端强制踢线和断网检测都通过。
7. GUI 不阻塞等待读写、认证或进程退出，连续点断开不冻结。后台在一次应用会话中复用，关闭 GUI 后应结束该会话及子隧道；Mac 上服务注册/用户批准机制遵循 OS 行为，不能承诺与 UAC 弹窗时机完全相同。
8. 仅收到官方核心 `CONNECTED,SUCCESS` 后显示成功；诊断只记录固定类别、阶段和耗时，不记录任意服务端文本及秘密。帮助和诊断默认收起，切换显示，空间不够可以滚动。
9. 使用说明必须保留 Windows 版的五步内容与可点击二维码门户链接；图标源为 `resources/app-icon.svg` / PNG，Mac 生成适配的图标资源。

## 管理接口：不要回归的启动与命令顺序

原先出现过“管理接口已就绪，正在建立 VPN 连接…”停住，也记录过认证阶段等待超时。Windows 0.2.6 最终采用以下顺序，真实首次连接及自动重连均验证成功：

1. 只绑定本机接口；验证对端和受控核心身份；随机管理口令不落盘、不进命令行。
2. 处理没有换行的 `ENTER PASSWORD:` 提示，管理口令只发送一次，直到收到认证成功。
3. 主动安排 `state on` → `bytecount 1` → `hold off` → `hold release`。**不依赖首次 `>HOLD:` 一定在某个时刻到达。**
4. `management_commands.*` 保证一个在途命令，精确匹配对应成功应答后才发送下一条；异步 HOLD、状态或流量通知不能当作 ACK。用户名和密码命令也逐条确认。不得把不明确是否处理过的认证命令自动重发。
5. 排队后 OTP 过期时禁止再发送密码命令。等待命令确认 10 秒、管理认证 20 秒、放行后无认证/网络进度 15 秒、初始连接总体 90 秒等现有边界要保留或作出明确、经测试的调整。
6. 用户取消立即向控制器发独立取消信号；不在 UI 线程中往正被同步读锁住的连接写停止命令。

`HOLD`、状态订阅和认证命令含义见 [OpenVPN 官方管理接口](https://openvpn.net/community-docs/management-interface/)。归因是当前应用启动/命令往返处理需要修正，不应在没有额外证据时宣称是 OpenVPN 某个版本的缺陷。

## Mac 平台重点

### 权限、IPC 与进程

Apple 在 macOS 13 及以后提供 [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice) 注册/管理 bundle 内的 helper；需要 root 工作时应研究其 daemon 路线及实际签名、批准流程。不要采用保存管理员密码、每次重连拼接 `sudo` 命令或将整个 GUI 以 root 运行的方案。

GUI 读取当前用户的受保护数据，只把本次需要的材料交给受身份验证的 helper。root helper 不能假设能直接读取当前登录用户的 Keychain。XPC 对端应验证代码身份/签名及会话归属，不做接受任意程序路径、任意 shell 命令或任意配置脚本的通用 root 执行器。

通过直接 argv 启动受信任的 OpenVPN，可采用 POSIX 进程 API 或合适的框架封装；不要复用 Windows `QuoteArg` 到 shell。取消/退出使用 Mac/POSIX 的受控子进程停止方案，必要时只结束本应用拥有的进程组。删除 Windows 专属的 `--service <event> 0`，保留标准输入/输出隔离和明确的父应用断开处理。

Mac 本机官方核心位置应按实际安装探测并验证版本，不继承 Windows 路径，不从不可信工作目录或用户导入配置中寻找提权执行文件。App Store/Network Extension 与直接进程路线分开设计；必要时先交付本机开发可运行版，再落实正式签名分发。

### 凭据与加密

使用 [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services) 保存记住的密码和 TOTP 种子。沿用配置 + 精确用户名隔离，单次验证码不持久化；界面“不记住密码”时仅在当前连接会话内保留重连需要的内存副本。

HMAC/SHA、随机数、Base64、内存擦除统一经平台接口实现；可选系统成熟加密能力或已核对版本/许可的库，要求 SHA1/SHA256/SHA512 的 RFC 6238 向量全部一致。不要把 Qt 的普通设置文件当作密码库，不要让 Windows 凭据导出成为迁移前置步骤。

### 路由、DNS 和系统恢复

优先让官方 OpenVPN 处理其支持的 Mac 隧道设备与路由，依据本机版本核对 [OpenVPN 参数手册](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)。不能带 Windows TAP/DCO 驱动到 Mac，也不能把 `dev tun` 的迁移等同于只替换网卡名称。

现有 `SplitTunnelPolicy()` 保留公司特定路由并过滤默认路由接管。Mac 还要显式验证公司域名解析和 DNS 恢复；不能假设 Windows 上的 DNS 行为在 Mac CLI 后端自动相同。需要 DNS 配置时使用应用控制的可信平台实现，不允许用户配置中的任意 up/down 脚本绕过原允许列表。记录并恢复本应用变更的 DNS/路由，测试退出、崩溃、网络切换和睡眠唤醒。

## 构建与依赖处理

- 当前顶层 `project(... LANGUAGES CXX RC)`、Win32 宏和 Windows 链接库均需条件化；RC、manifest.specs 和 MinGW 静态链接选项只用于 Windows 目标。
- 新增 Mac app bundle 目标和平台实现，Windows 目标保持可用。建议保留 CMake 构建，Qt 的 bundle/部署步骤参考 [Qt macOS deployment](https://doc.qt.io/qt-6.8/macos-deployment.html)。
- CMake 当前固定 ZXing-C++ 3.1.1，SHA-256 为 `7286b1e6ade66fe82b7c8208b4595deeb55d6486b410834fdc65702f46650542`。包内 `third_party/ZXing-Cpp-3.1.1-source.tar.gz` 与该归档一致，未修改上游源码。
- Mac CMake 分支实现后，可预置下载缓存：`mkdir -p build-macos/downloads`，然后把上述归档复制为 `build-macos/downloads/zxing-cpp-3.1.1.tar.gz`。这只免除该依赖的再次下载，不会自动消除 Windows API 依赖。
- 应用不运行 Python；`tools/generate_app_icon.py`、`generate_test_qr.py` 是开发工具，使用 Pillow/二维码生成依赖。其余 Windows 凭据检查工具不要直接当成 Mac 工具执行。
- 本包没有附带 OpenVPN 本体。自行安装/打包 Mac 核心时核对版本、架构、签名和依赖许可；原有第三方声明已随包附上。项目自身目前没有声明一个开源许可证，不擅自给用户代码新增开源授权。

## 建议实施和验收顺序

1. 读取文档，检测 Mac 环境；先拆公共类型和平台接口，恢复可构建的 C++ 核心。
2. 先跑协议、命令队列、重连、RFC TOTP、参数核对等无需 VPN 的测试；测试持久化后端使用独立测试命名空间/假仓库，不改用户真实密码库。
3. 实现 Qt/原生界面、Keychain、图像解码和二维码绑定；用包内公开样本验证，不要求用户先提交个人二维码。
4. 实现管理 socket、核心进程、可取消等待和权限 helper。先在强制环回目标、仅合成凭据的测试配置下验证管理放行、逐条 ACK 和重复连接；不将公司配置误用于离线测试。
5. 由用户在 Mac 本机导入完整配置依赖和当前有效二维码，填写密码，实测首次连接、断开、再次连接、自动重连、取消、认证拒绝和公司内网访问。
6. 实测公网默认路由未被 VPN 接管，公司 DNS 正常，断开/关闭后的路由和 DNS 恢复。测试断网、服务器踢线、进程退出、睡眠唤醒，不把本地“测试自动重连”按钮当作这些场景的替代。
7. 输出可运行 `.app`、可重复构建脚本、测试报告及实际验证范围。没有公司附件时完成前四步并明确列出待实连项目，不能伪造成功状态。
