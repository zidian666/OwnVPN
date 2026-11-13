# Android 开发与测试

当前仓库已拆出公共 C++20 核心。Android 界面、VpnService、VPN 引擎和安全存储适配尚未实现，公共核心测试程序不是 VPN 客户端，也不是 APK。

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

2026-11-13 的环境验证结果：SDK 安装包通过官方校验值核对，sdkmanager 完成安装；adb、aapt2 可启动，模拟器报告 WHPX 可用。ARM64 与 x86_64 的公共核心及测试程序均编译、链接成功；Windows 公共核心检查 2/2 通过。当前未下载模拟器系统镜像，adb 未发现手机，尚未在 Android 系统执行测试，也没有完整 Android APK。

## 公共核心编译检查

在仓库目录执行：

```powershell
./tools/test_android_core.ps1 -SdkRoot D:/DevTools/Android/Sdk
./tools/test_android_core.ps1 -SdkRoot D:/DevTools/Android/Sdk -Abi x86_64
```

脚本使用 NDK 编译 `ownvpn_core` 和 `portable_core_tests`，输出到忽略提交的 `build-android-core-<ABI>`。最低目标为 API 26，使用静态 C++ 运行库。编译通过仅说明源码和链接符合该 Android 工具链，不能视为设备测试通过。

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
