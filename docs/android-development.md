# Android 开发与测试

当前开发版为 `0.5.0-alpha.2`。已实现 Android 原生界面、JNI、VpnService、官方 OpenVPN 3 引擎、Android Keystore 安全存储、二维码导入和公共 C++ 核心复用。属于调试签名的开发版本。

`src/platform/android/` 实现公共平台接口和 JNI 隧道适配，`android/` 提供原生界面和系统服务。Windows 的 OpenVPN 2.x 进程实现保持原样；两个平台共用配置校验、TOTP、DNS 缓存与重连时序。

## 构建 APK

```powershell
./build-android.ps1
./build-android.ps1 -Install -DeviceSerial <设备序列号>
./build-android.ps1 -Test -DeviceSerial <设备序列号>
```

使用 Gradle 8.13、AGP 8.13.2、JDK 21、SDK 36、NDK 30；输出 `dist/OwnVPN-Android-0.5.0-alpha.2.apk`。当前 APK 包含 ARM64，最低 API 26；核心还验证了 x86_64 构建。Gradle 安装在本机 `D:\DevTools\Gradle`，缓存位于 `D:\DevTools\GradleCache`。其他宿主系统准备相同 SDK/NDK 与 Gradle 后可执行 `gradle -p android assembleDebug`。

配置导入会复制到应用私有目录；密码和验证码绑定通过 Android Keystore 的 AES-GCM 密钥加密。默认勾选自动重连和 DNS 回退，自动重连需要自动验证码。关闭界面不结束 VPN；通知栏提供断开。认证失败和手动取消会停止重试。

推荐直接导入邮件中的原始 ZIP 配置包，保留配置和依赖的相对目录；包内有多个 `.ovpn` 时先选择一个，再选择单独下载的 `users.pem`。也支持单独导入 `.ovpn`：Android 文件选择器不授予同目录其他文件的读取权限，程序会按配置引用逐项提示选择缺失的 `.key`、`.crt` 等文件。`users.pem` 仅补齐客户端证书和私钥，不能替代 TLS 认证密钥或 CA 证书。已内嵌所需证书的配置可跳过 PEM 选择。导入取消或结束后清理临时目录，不修改源文件。

`0.5.0-alpha.2` 的导入修复已通过电脑端 22 项 Java 文件工作区检查（包括 ZIP 路径、文件上限与清理）和 Windows 5/5 回归；公共核心测试覆盖缺失依赖、显式选择、PEM 与 TLS 密钥区分、ZIP 目录结构和引用边界。新 APK 已编译；本次未操作手机，新的文件选择界面尚待真机验收。以下真机记录来自 `alpha.1`。

Android 只接收指定的公司路由；不添加默认路由或两个 `/1` 半默认路由。DNS 服务器会添加对应的主机路由。配置使用 TUN，暂不支持 TAP、外部 PKI、需独立密码解锁的私钥，以及部分证书选项；失败时不会降低证书校验要求。

系统首次 VPN 授权及通知权限由用户在手机上确认。小米设备可能还需要在开发者选项允许 USB 安装。

普通卸载会移除私有配置和登录资料。覆盖安装保留应用数据；本版关闭系统备份，暂不实现备份／恢复功能。

## Windows 开发机

工具安装在实际机器的 `D:\DevTools\Android\Sdk`，不在 Codex 沙箱中。

| 工具 | 版本 / 位置 |
| --- | --- |
| JDK | 复用本机 JDK 21，`D:\Program Files\Java\jdk-21` |
| Command-line Tools | 15859902，`cmdline-tools/latest` |
| Android SDK Platform | Android 16 / API 36 |
| Build Tools | 36.0.0 |
| NDK | 30.0.16248370 |
| CMake | 3.31.6 |
| Platform Tools | 37.0.1，提供 adb |
| Emulator | 37.2.13；运行还需要系统镜像与可用的虚拟化加速 |

用户环境变量 `ANDROID_HOME` 指向 SDK；`ANDROID_USER_HOME` 和 `ANDROID_AVD_HOME` 分别指向 `D:\DevTools\Android\User`、`D:\DevTools\Android\Avd`。更新环境变量后重新打开终端；现有 Codex 进程可能仍使用旧环境，可显式传入 `-SdkRoot`。

2026-11-13 的验证：小米 15 / Android 16 / ARM64 上运行公共核心 90 项检查；客户端 22 项检查涵盖真实加密提供者的 18 组 RFC6238 向量、Keystore、二维码、重连时序、连续 8 次启动前取消、两份配置的完整环回启动和界面启动。已通过真实公司 VPN 认证；Android 路由没有默认接管，指定内网主机经 TUN 的 ICMP 检查 3/3 成功。一个历史站点的 TCP 端口仍不可达，不据此声称该站点可用。Windows 原有回归 5/5 通过。系统镜像未下载，模拟器只验证了 WHPX 可用。

同时运行电脑和手机的同账号会话时，观察到两端反复重连；隔离为手机单端后连接保持稳定。此现象提示服务端可能限制并发，尚未确认服务器的实际策略。实用中建议先只保留一个终端连接。

常规测试不提交真实 VPN 认证，界面按正常流程读取已保存的配置和登录资料。完整启动测试使用环回服务器覆盖和公开合成凭据，不连接配置里的真实服务器。测试结果不输出密码、验证码或密钥。实连探测使用独立 `probe` APK 内的 `ExternalVpnProbe`，从参数接收用户指定的内网目标，检查 Android VPN 网络、目标路由、默认路由、端口可达性与短时稳定性；运行在探测包自己的进程，结束后保留客户端连接。用户确认账号资料迁移后，测试 APK 可用临时 RSA-OAEP 公钥与 AES-GCM 加密信封导入登录资料；临时密钥和密文导入后删除，此入口不在主 APK 中。

Android 适配会移除本地 `topology` 指令，交给 OpenVPN 3 接收服务器下发值；建立 TUN 时校验它与原配置要求一致，不匹配即停止。启动阶段的永久配置错误会报告诊断并停止重试。为兼容新版 Mbed TLS，固定的 OpenVPN 3.11.8 回移了官方提交 `ee481a02cb6ab946ec388efac7ca13d39305ff7b` 的 hostname 初始化修复，补丁位于 `cmake/OpenVPNMbedTLSCompatibility.cmake`；未启用弱证书验证兼容宏，保留 CA、证书角色和 `verify-x509-name` 检查。

第三方源码来自固定的官方归档，SHA-256 位于 `cmake/AndroidDependencies.cmake` 和 `cmake/ZXing.cmake`；上游许可随 APK 打包。点击界面底部版本号可查看许可，详见 [第三方组件](android-third-party-notices.txt)。

## 公共核心编译检查

在仓库目录执行：

```powershell
./tools/test_android_core.ps1 -SdkRoot D:/DevTools/Android/Sdk
./tools/test_android_core.ps1 -SdkRoot D:/DevTools/Android/Sdk -Abi x86_64
```

脚本使用 NDK 编译 `ownvpn_core` 和 `portable_core_tests`，输出到忽略提交的 `build-android-core-<ABI>`。最低目标为 API 26，使用静态 C++ 运行库。编译通过仅说明源码和链接符合该 Android 工具链，不能视为设备测试通过。

只在开发电脑检查 Android 文件导入工作区，不连接手机：

```powershell
./tools/test_android_import.ps1
```

## 真机运行公共核心测试

主要验收设备为小米 15 / Android 16。先在手机开启开发者选项和 USB 调试，用 USB 连接电脑，并在手机上确认电脑的调试授权。若 Windows 无法识别，按设备厂商说明安装对应驱动。

```powershell
& D:/DevTools/Android/Sdk/platform-tools/adb.exe devices
./tools/test_android_core.ps1 -SdkRoot D:/DevTools/Android/Sdk -RunOnDevice
```

多设备时增加 `-DeviceSerial <adb显示的序列号>`。脚本检查设备 ABI，然后将测试程序复制到 `/data/local/tmp`、执行并删除。测试使用公开样本和隔离存储，不读取实际 VPN 配置、密码或二维码密钥，不连接公司 VPN。

模拟器启动且 adb 已识别后，也可以用 `-Abi x86_64 -RunOnDevice -DeviceSerial <模拟器序列号>` 执行相同测试。

## 完整 Android 应用的验收

实现 Android 客户端后，由开发机编译调试 APK，通过 adb 安装并收集应用日志。首次 VPN 系统授权由用户在手机确认。按以下顺序验收：

1. 界面布局、文件选择、配置和证书导入、二维码绑定、验证码刷新与复制。
2. 使用公开 RFC 样本验证 TOTP；用同一绑定资料与手机认证器核对实际验证码。
3. 实际登录公司 VPN，确认内网目标可达，公共网络仍按配置分流，断开后路由恢复。
4. 手动断开、服务端断开、认证失败、DNS 失败以及取消连接，检查状态和重连策略。
5. 真机切换 Wi-Fi / 移动网络、锁屏和后台长时间运行，验证 HyperOS 电源管理与 VPN 前台服务行为。
6. 最后回归 Windows 构建和既有测试，防止 Android 适配破坏公共核心。

模拟器用于日常界面和流程验证；公司网络、设备省电策略和网络切换以真机结果为准。Android 的 VPN 服务与 Windows 的进程/UAC 实现不同，需要单独的平台适配。

实连测试先记录未连接时的网络基线，再检查 Android VPN 服务建立、内网可达与断开恢复。模拟器会受电脑现有 VPN 路由影响，不能仅凭内网网页能打开就判定 Android VPN 成功；真机使用自己的 Wi-Fi / 移动网络做独立验证。

参考：[Android 真机调试](https://developer.android.com/studio/run/device)、[模拟器加速](https://developer.android.com/studio/run/emulator-acceleration)、[SDK 环境变量](https://developer.android.com/tools/variables)。
