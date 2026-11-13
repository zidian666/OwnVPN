#include "connection_controller.h"
#include "windows_platform.h"
#include <sddl.h>
#include <shellapi.h>

namespace ownvpn {
std::unique_ptr<IConnectionBackend> CreateWindowsConnectionBackend(HWND owner, EventSink sink) {
    return std::make_unique<ConnectionController>(std::move(sink), ConnectionController::HelperLauncher{},
                                                  std::chrono::seconds(30), owner);
}
ConnectionController::~ConnectionController() {
    Stop();
    if (reader_.joinable()) {
        reader_.join();
    }
    CloseSession();
}
void ConnectionController::CloseSession() {
    if (helper_.valid() && WaitForSingleObject(helper_.value, 0) == WAIT_TIMEOUT) {
        // The reader has finished and the worker is idle. Only this thread
        // owns pipe I/O now; the bounded shutdown packet contains no secrets.
        SendPacket(pipe_.value, 101, {});
        if (WaitForSingleObject(helper_.value, 2000) == WAIT_TIMEOUT) {
            DisconnectNamedPipe(pipe_.value);
            WaitForSingleObject(helper_.value, 1000);
        }
    }
    pipe_.reset();
    helper_.reset();
    stopEvent_.reset();
    sessionReady_ = false;
}
bool ConnectionController::Start(HWND owner, ConnectionRequest request) {
    if (active_) {
        return false;
    }
    if (reader_.joinable()) {
        reader_.join();
    }
    stopping_ = false;
    if (authorized()) {
        ResetEvent(stopEvent_.value);
        sessionReady_ = false;
        active_ = true;
        sink_({EventType::Diagnostic, L"复用本次程序运行期间已授权的连接服务。"});
        reader_ = std::thread(&ConnectionController::Pump, this, std::move(request),
                              GetProcessId(helper_.value), true);
        return true;
    }
    CloseSession();
    auto name = L"\\\\.\\pipe\\OwnVPN-" + Wide(RandomHex(24));
    auto acl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + CurrentSid() + L")";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        throw std::runtime_error("Cannot secure helper IPC");
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    pipe_.reset(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                 1, 65536, 65536, 0, &sa));
    auto stopName = L"Local\\OwnVPN.Stop." + Wide(RandomHex(24));
    stopEvent_.reset(CreateEventW(&sa, TRUE, FALSE, stopName.c_str()));
    LocalFree(sd);
    if (!pipe_.valid() || !stopEvent_.valid()) {
        throw std::runtime_error("Cannot create private helper IPC");
    }
    if (launcher_) {
        helper_ = launcher_(owner, name, stopName);
    } else {
        auto exe = Executable();
        auto args = L"--worker " + QuoteArg(name) + L" " + std::to_wstring(GetCurrentProcessId()) + L" " +
                    QuoteArg(stopName);
        SHELLEXECUTEINFOW launch{};
        launch.cbSize = sizeof(launch);
        launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        launch.hwnd = owner;
        launch.lpVerb = L"runas";
        launch.lpFile = exe.c_str();
        launch.lpParameters = args.c_str();
        launch.nShow = SW_HIDE;
        if (!ShellExecuteExW(&launch)) {
            DWORD error = GetLastError();
            pipe_.reset();
            sink_({EventType::Failed, error == ERROR_CANCELLED ? L"已取消管理员授权，未发起 VPN 连接"
                                                               : L"无法启动连接服务：" + WinError(error)});
            return false;
        }
        helper_.reset(launch.hProcess);
    }
    if (!helper_.valid()) {
        throw std::runtime_error("Cannot start connection helper");
    }
    active_ = true;
    auto helperId = GetProcessId(helper_.value);
    reader_ = std::thread(&ConnectionController::Pump, this, std::move(request), helperId, false);
    return true;
}
void ConnectionController::Stop() {
    if (!active_) {
        return;
    }
    if (!stopping_.exchange(true) && stopEvent_.valid()) {
        // Never write to the synchronous pipe here: the reader may own its
        // file-object lock while waiting for the server's authentication reply.
        SetEvent(stopEvent_.value);
    }
}
void ConnectionController::Pump(ConnectionRequest request, DWORD helperId, bool reuse) {
    bool sawStopped = false, failed = false;
    std::atomic<bool> connected = reuse;
    std::atomic<bool> receivedEvent = false, startupTimedOut = false;
    Handle currentThread;
    std::jthread watchdog;
    try {
        HANDLE current = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &current,
                             THREAD_TERMINATE, FALSE, 0)) {
            throw std::runtime_error("Cannot retain reader thread handle");
        }
        currentThread.reset(current);
        watchdog = std::jthread([&](std::stop_token shutdown) {
            const auto start = std::chrono::steady_clock::now();
            std::optional<std::chrono::steady_clock::time_point> stopTime;
            while (!shutdown.stop_requested()) {
                auto now = std::chrono::steady_clock::now();
                if (stopping_ && !stopTime) {
                    stopTime = now;
                }
                bool exited = WaitForSingleObject(helper_.value, 25) != WAIT_TIMEOUT;
                bool startupExpired = !receivedEvent && now - start > startupTimeout_;
                if (startupExpired && !stopping_) {
                    startupTimedOut = true;
                    SetEvent(stopEvent_.value);
                }
                bool timedOut = (!connected && now - start > std::chrono::seconds(15)) || startupExpired ||
                                (stopTime && now - *stopTime > std::chrono::seconds(12));
                if (exited || timedOut) {
                    CancelSynchronousIo(current);
                }
                if (exited) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(25));
                }
            }
        });
        if (!reuse) {
            BOOL result = ConnectNamedPipe(pipe_.value, nullptr);
            DWORD error = GetLastError();
            connected = true;
            if (!result && error != ERROR_PIPE_CONNECTED) {
                throw std::runtime_error("Elevated helper did not establish IPC");
            }
        }
        ULONG clientId = 0;
        if (!GetNamedPipeClientProcessId(pipe_.value, &clientId) || clientId != helperId) {
            throw std::runtime_error("Helper identity mismatch");
        }
        sink_({EventType::Diagnostic, L"连接服务已接入，本机 IPC 身份校验通过。"});
        {
            std::vector<std::string> fields{Utf8(request.profile.id),
                                            request.username,
                                            request.password,
                                            request.otp,
                                            "concat",
                                            request.automaticOtp ? "totp" : "manual",
                                            request.dnsFallback ? "dns-fallback" : "dns-normal"};
            bool sent = SendPacket(pipe_.value, 100, fields);
            for (auto& f : fields) {
                Wipe(f);
            }
            Wipe(request.username);
            Wipe(request.password);
            Wipe(request.otp);
            if (!sent) {
                throw std::runtime_error("Cannot send connection request");
            }
        }
        uint32_t type = 0;
        std::vector<std::string> fields;
        while (ReceivePacket(pipe_.value, type, fields)) {
            if (type < 1 || type > static_cast<uint32_t>(EventType::ConnectionLost) || fields.size() != 1) {
                throw std::runtime_error("Invalid helper event");
            }
            auto event = Event{static_cast<EventType>(type), Wide(fields[0])};
            receivedEvent = true;
            if (event.type == EventType::Failed) {
                failed = true;
            }
            if (event.type == EventType::Stopped) {
                sawStopped = true;
                break;
            }
            if (event.type != EventType::Stopped &&
                !(stopping_ && (event.type == EventType::Status || event.type == EventType::Connected ||
                                event.type == EventType::Failed))) {
                sink_(std::move(event));
            }
        }
    } catch (const std::exception& e) {
        if (!stopping_) {
            failed = true;
            sink_({EventType::Diagnostic, startupTimedOut
                                              ? L"连接服务启动超时：未收到启动确认，已请求结束本次连接。"
                                              : Wide(e.what())});
            sink_({EventType::Failed, L"连接服务异常，请查看诊断信息"});
        }
    }
    watchdog.request_stop();
    if (watchdog.joinable()) {
        watchdog.join();
    }
    if (!sawStopped && helper_.valid() && WaitForSingleObject(helper_.value, 1000) == WAIT_TIMEOUT) {
        // Also unblock a helper that was sending an event when cancellation hit.
        DisconnectNamedPipe(pipe_.value);
        if (WaitForSingleObject(helper_.value, 2000) == WAIT_TIMEOUT) {
            sink_({EventType::Failed, L"连接服务尚未退出，请检查 VPN 网卡和网络状态"});
        }
    }
    if (!sawStopped && !stopping_ && !failed) {
        sink_({EventType::Failed, L"连接服务已退出，请重新连接"});
    }
    sessionReady_ = sawStopped;
    active_ = false;
    sink_({EventType::Stopped, L"已断开"});
}
} // namespace ownvpn
