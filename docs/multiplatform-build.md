# 同一主干的多平台构建

## 0.4.0 的目标和范围

同一份仓库按目标平台选择实现，不长期维护三套平台分支。Windows 0.4.0 完成公共核心剥离和 Windows 适配；Android 0.5.0-alpha.1 在同一主干新增原生界面、平台适配、VPN 隧道和 APK 构建。macOS 尚未实现。

```text
src/core/                 公共 C++20 逻辑和平台接口
src/platform/windows/    Win32 界面、连接服务及 Windows 能力实现
src/platform/android/    JNI、Android 平台能力及 OpenVPN 3 原生适配
android/                 Android 原生界面、VpnService 和 Gradle 工程
tests/support/           仅用于公共核心测试的隔离适配器
```

Android 的 Gradle 工程通过 NDK/CMake 编译同一个 `ownvpn_core`。以后接入 macOS 继续增加平台实现，不复制公共核心或建立永久的平台分支。

Android 开发机工具、NDK 编译检查及真机测试步骤见 [Android 开发与测试](android-development.md)。

## 公共核心

- 配置解析、危险选项拒绝及分流策略。
- 账号密码与验证码组合、管理协议状态机、启动放行与命令确认队列。
- RFC 6238 TOTP、Base32、绑定 URI、验证码过期/取消、参数核对及显示预览。
- 重连时序、DNS 地址缓存与回退规则、日志事件和流量文本格式。
- UTF-8/UTF-16/UTF-32 转换、Base64、文件读写及内存清理。

公共代码不引用 Windows SDK，不链接系统加密、凭据或网络库。Unicode 转换按 `wchar_t` 宽度处理；文件名使用 UTF-8 明确转换，避免依赖系统语言设置。

## 平台接口及 Windows 适配

| 接口 | 责任 | 现有 Windows 实现 |
| --- | --- | --- |
| `ICryptoProvider` | HMAC、哈希、安全随机数 | Windows BCrypt |
| `ISecretStore` | 按配置/字段读写受保护数据 | Windows 凭据管理器 |
| `IPlatformPaths` | 应用数据路径、保护私有目录 | LocalAppData、用户/管理员/SYSTEM ACL |
| `INetworkServices` | IP 字面量校验、可取消域名解析 | InetPton、GetAddrInfoEx |
| `IConnectionBackend` | 接受连接请求、报告事件、取消、授权会话状态 | 原 Windows 控制器、UAC、命名管道及官方 OpenVPN 进程 |

`Platform()` 由最终程序链接的平台适配器提供，每个程序只链接一个生产实现。平台服务存活至进程结束，初始化后不替换。公共逻辑通过接口使用能力，不能反向包含平台头文件。

Windows 主界面通过 `IConnectionBackend` 调用连接服务。`Start` 返回值只表示请求已接受，必须收到真实 `Connected` 事件才显示连接成功。`Stop` 仅请求取消，不在 UI 线程等待同步管道或子进程结束。Windows 提权、连接复用、停止事件及 Job Object 回收规则保留。

Windows 凭据的 `OwnVPN/<配置>/<字段>` 命名、用户名 SHA256 标识、保存格式和数据目录保持一致，升级继续读取已有账号、密码和验证码绑定。未自行实现任何密码学哈希。

## 构建

Windows 完整程序：

```powershell
./build.ps1
```

脚本显式开启 Windows 目标、运行测试，输出 `dist/OwnVPN-0.4.0.exe`。

只构建公共核心及隔离测试，在具有 C++20 编译器的宿主系统上运行：

```text
cmake -S . -B build-core -DOWNVPN_BUILD_WINDOWS_APP=OFF -DBUILD_TESTING=ON
cmake --build build-core
ctest --test-dir build-core --output-on-failure
```

此模式不启用 RC、不下载 ZXing、不编译 Win32 界面、不链接 Windows 适配器。测试适配器只提供内存存储、临时目录和受控样本，不访问系统凭据或真实网络，不能用于生产程序。测试 HMAC 只接受一个公开 RFC 向量；完整 SHA1/SHA256/SHA512 向量由 Windows 测试通过真实 BCrypt 验证。

`core_platform_boundary` 在 Python 可用时检查公共目录的 SDK 引用和平台符号，避免以后重新引入 Windows 依赖。项目程序运行不依赖 Python。

## 后续平台接入

1. 使用该平台的安全加密、受保护存储、文件权限和网络能力实现四个服务接口。
2. 实现 `IConnectionBackend`，处理平台的授权、VPN 引擎、路由/DNS、后台生命周期和取消；复用公共认证与重连规则。
3. 编写该平台的界面和二维码图像读取适配。当前 WIC 图像读取及 Win32 控件属于 Windows 层。
4. 新增对应的本机构建、签名和分发目标，验证目标 SDK 的 C++20 标准库能力。
5. 在目标设备验收真实登录、分流、DNS、断开恢复、网络切换、睡眠/后台切换。公共核心测试通过不代表完整平台客户端已可用。

本次在 Windows 上验证完整构建、公共核心独立构建、核心边界检查、原有回归测试及官方 OpenVPN 环回启动探测。不声称已在 macOS、Android 或 Linux 原生环境执行测试。
