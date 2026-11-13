#include "engine.h"
#include "dns_fallback.h"
#include "ipc.h"
#include "management_commands.h"
#include "management_startup.h"
#include "totp_store.h"
#include "windows_platform.h"
#include <array>
#include <chrono>
#include <iphlpapi.h>
#include <sstream>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace ownvpn {
namespace {
struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() {
        if (value != INVALID_SOCKET) {
            closesocket(value);
        }
    }
};
struct Winsock {
    Winsock() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data)) {
            throw std::runtime_error("Cannot initialize Winsock");
        }
    }
    ~Winsock() {
        WSACleanup();
    }
};
bool SendSocket(SOCKET socket, std::string_view message) {
    while (!message.empty()) {
        int n = send(socket, message.data(), static_cast<int>(message.size()), 0);
        if (n <= 0) {
            return false;
        }
        message.remove_prefix(n);
    }
    return true;
}
bool IsExpectedPeer(const sockaddr_in& peer, const sockaddr_in& listener, DWORD processId) {
    // Verify the process at the opposite endpoint before sending any secret.
    DWORD n = 0;
    GetExtendedTcpTable(nullptr, &n, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<unsigned char> bytes(n);
    if (GetExtendedTcpTable(bytes.data(), &n, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return false;
    }
    auto table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(bytes.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwLocalAddr == peer.sin_addr.s_addr && row.dwLocalPort == peer.sin_port &&
            row.dwRemotePort == listener.sin_port && row.dwOwningPid == processId) {
            return true;
        }
    }
    return false;
}
void Diagnose(std::string_view line, const EventSink& sink) {
    // Deliberately emit categories, never raw OpenVPN output. This keeps
    // usernames, OTPs, embedded keys and server-supplied text out of logs.
    std::wstring message;
    if (line.find("Options error") != line.npos) {
        message = L"配置选项不兼容，请重新导入配置或检查 OpenVPN 版本。";
    } else if (line.find("VERIFY ERROR") != line.npos ||
               line.find("certificate verify failed") != line.npos) {
        message = L"证书验证失败，请检查证书有效期、服务器证书和系统时间。";
    } else if (line.find("AUTH_FAILED") != line.npos) {
        message = L"服务器拒绝认证，请检查账号密码并更换验证码。";
        sink({EventType::RetryBlocked, L"服务器拒绝认证，自动重连已停止。"});
    } else if (line.find("TLS Error") != line.npos) {
        message = L"TLS 握手失败，请检查网络、证书和服务器状态。";
    } else if (line.find("RESOLVE: Cannot resolve") != line.npos) {
        message = L"无法解析 VPN 服务器域名，请检查网络和 DNS。";
    } else if (line.find("Access is denied") != line.npos || line.find("Access denied") != line.npos) {
        message = L"虚拟网卡或路由访问被拒绝，请检查管理员权限。";
    } else if (line.find("no shared cipher") != line.npos ||
               line.find("OPTIONS ERROR: cipher negotiation failed") != line.npos ||
               line.find("OPTIONS ERROR: failed to negotiate cipher") != line.npos) {
        message = L"与公司服务器没有共同的加密算法，需要管理员确认服务器配置。";
    } else if (line.find("All TAP-Windows adapters") != line.npos) {
        message = L"没有可用的 TAP 网卡，请检查其他 VPN 连接是否正在占用。";
    }
    if (!message.empty()) {
        sink({EventType::Diagnostic, std::move(message)});
    }
}
} // namespace
void RunOpenVpn(ConnectionRequest request, std::unique_ptr<IOtpProvider> otp, const EventSink& sink,
                const std::function<bool()>& stopRequested, EngineMode mode) {
    const bool offlineProbe = mode != EngineMode::Connect;
    const bool keepHeld = mode == EngineMode::HeldProbe;
    sink({EventType::Status, L"正在检查连接配置…"});
    auto exe = OpenVpnExecutable();
    if (exe.empty()) {
        throw std::runtime_error("Official OpenVPN installation not found");
    }
    if (!offlineProbe) {
        ProfileRepository().Validate(request.profile);
    }
    Winsock winsock;
    struct RuntimeConfig {
        fs::path path;
        ~RuntimeConfig() {
            if (!path.empty()) {
                std::error_code error;
                fs::remove(path, error);
            }
        }
    } runtimeConfig;
    if (!offlineProbe) {
        auto original = ReadFile(request.profile.config);
        auto effective = PrepareDnsFallback(
            original, request.profile.config.parent_path() / L"dns-cache.txt", request.dnsFallback,
            [&](const std::string& host, int family) { return ResolveEndpoint(host, family, stopRequested); },
            sink, stopRequested);
        Wipe(original);
        if (!effective.empty()) {
            runtimeConfig.path =
                request.profile.config.parent_path() / (L"runtime-" + Wide(RandomHex()) + L".ovpn");
            WriteFile(runtimeConfig.path, effective);
            Wipe(effective);
        }
        if (stopRequested()) {
            return;
        }
    }
    Socket listener, management;
    listener.value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener.value == INVALID_SOCKET) {
        throw std::runtime_error("Cannot create local management listener");
    }
    BOOL exclusive = TRUE;
    setsockopt(listener.value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<char*>(&exclusive),
               sizeof(exclusive));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
        listen(listener.value, 4)) {
        throw std::runtime_error("Cannot bind private management listener");
    }
    int addressSize = sizeof(address);
    getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &addressSize);
    u_long nonblock = 1;
    ioctlsocket(listener.value, FIONBIO, &nonblock);
    auto secret = RandomHex(32);
    auto exitEventName = L"Local\\OwnVPN.Exit." + Wide(RandomHex(24));
    Handle exitEvent(CreateEventW(nullptr, TRUE, FALSE, exitEventName.c_str()));
    if (!exitEvent.valid()) {
        throw std::runtime_error("Cannot create private OpenVPN exit event");
    }
    Handle stdinRead, stdinWrite, stdoutRead, stdoutWrite;
    HANDLE r, w;
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    if (!CreatePipe(&r, &w, &inherit, 0)) {
        throw std::runtime_error("Cannot create engine stdin pipe");
    }
    stdinRead.reset(r);
    stdinWrite.reset(w);
    SetHandleInformation(w, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&r, &w, &inherit, 0)) {
        throw std::runtime_error("Cannot create engine output pipe");
    }
    stdoutRead.reset(r);
    stdoutWrite.reset(w);
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    std::vector<unsigned char> attributeBytes(attributeSize);
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeBytes.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize)) {
        throw std::runtime_error("Cannot initialize child handle list");
    }
    struct AttributeGuard {
        LPPROC_THREAD_ATTRIBUTE_LIST p;
        ~AttributeGuard() {
            DeleteProcThreadAttributeList(p);
        }
    } attributeGuard{attributes};
    HANDLE inheritedHandles[] = {stdinRead.value, stdoutWrite.value};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inheritedHandles,
                                   sizeof(inheritedHandles), nullptr, nullptr)) {
        throw std::runtime_error("Cannot isolate child handles");
    }
    std::wstring command = QuoteArg(exe.wstring());
    if (mode == EngineMode::StartupProbe) {
        ProfileRepository().Validate(request.profile);
        auto text = ReadFile(request.profile.config);
        std::istringstream lines(text);
        std::string line, ca;
        while (std::getline(lines, line)) {
            auto tokens = ConfigTokens(line);
            if (tokens.size() == 2 && tokens[0] == "ca") {
                ca = tokens[1];
                break;
            }
        }
        Wipe(text);
        if (ca.empty()) {
            throw std::runtime_error("Startup probe needs an imported CA file");
        }
        command += L" --client --dev null --proto tcp-client --remote 127.0.0.1 9 --auth-user-pass "
                   L"--auth-retry none --verb 3 --ca " +
                   QuoteArg(Wide(ca));
    } else if (offlineProbe && request.profile.config.empty()) {
        command += L" --dev null --tls-client --remote 127.0.0.1 9 --verb 3";
    } else {
        command +=
            L" --cd " + QuoteArg(request.profile.config.parent_path().wstring()) + L" --config " +
            QuoteArg((runtimeConfig.path.empty() ? request.profile.config : runtimeConfig.path).wstring());
    }
    command += L" --management 127.0.0.1 " + std::to_wstring(ntohs(address.sin_port)) +
               L" stdin --management-client --management-query-passwords --management-hold "
               L"--management-forget-disconnect";
    command += L" --service " + QuoteArg(exitEventName) + L" 0";
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.StartupInfo.hStdInput = stdinRead.value;
    startup.StartupInfo.hStdOutput = stdoutWrite.value;
    startup.StartupInfo.hStdError = stdoutWrite.value;
    Handle job(CreateJobObjectW(nullptr, nullptr));
    if (!job.valid()) {
        throw std::runtime_error("Cannot create engine job");
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        throw std::runtime_error("Cannot protect engine lifecycle");
    }
    PROCESS_INFORMATION pi{};
    sink({EventType::Status, L"正在启动 OpenVPN 核心…"});
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                        exe.parent_path().c_str(), &startup.StartupInfo, &pi)) {
        throw std::runtime_error("Cannot launch official OpenVPN core");
    }
    Handle process(pi.hProcess), thread(pi.hThread);
    sink({EventType::Diagnostic, L"官方 OpenVPN 核心进程已创建。"});
    if (!AssignProcessToJobObject(job.value, process.value)) {
        TerminateProcess(process.value, 1);
        throw std::runtime_error("Cannot contain OpenVPN process");
    }
    ResumeThread(thread.value);
    thread.reset();
    stdinRead.reset();
    stdoutWrite.reset();
    auto secretLine = secret + '\n';
    DWORD written = 0;
    bool wrote = ::WriteFile(stdinWrite.value, secretLine.data(), static_cast<DWORD>(secretLine.size()),
                             &written, nullptr) &&
                 written == secretLine.size();
    Wipe(secretLine);
    stdinWrite.reset();
    if (!wrote) {
        throw std::runtime_error("Cannot supply private management secret");
    }
    std::stop_source cancellation;
    std::jthread cancellationMonitor([&](std::stop_token shutdown) {
        while (!shutdown.stop_requested()) {
            if (stopRequested()) {
                cancellation.request_stop();
                SetEvent(exitEvent.value);
                // Independent of protocol/pipe processing: still reclaim only
                // this connection's core if it does not honor normal shutdown.
                for (int i = 0; i < 160 && !shutdown.stop_requested(); ++i) {
                    if (WaitForSingleObject(process.value, 50) != WAIT_TIMEOUT) {
                        return;
                    }
                }
                if (!shutdown.stop_requested()) {
                    TerminateJobObject(job.value, ERROR_CANCELLED);
                }
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });
    OtpRequest otpContext{request.profile.id, Wide(request.username), L""};
    ManagementProtocol protocol(std::move(request.username), std::move(request.password), std::move(otp),
                                sink, std::move(otpContext), cancellation.get_token());
    Wipe(request.otp);
    ManagementStartup startupProtocol(keepHeld);
    ManagementCommands commandQueue;
    std::optional<std::chrono::steady_clock::time_point> commandAt;
    bool stopping = false, probePassed = false, secretSent = false;
    bool sawManagementError = false;
    std::optional<std::chrono::steady_clock::time_point> readyAt;
    std::string buffer, output;
    auto started = std::chrono::steady_clock::now(), stopTime = started;
    sink({EventType::Status, L"正在等待 OpenVPN 管理接口…"});
    auto commandOut = [&](std::string text) {
        text += '\n';
        bool ok = SendSocket(management.value, text);
        Wipe(text);
        if (!ok) {
            throw std::runtime_error("Management connection was interrupted");
        }
    };
    while (WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT) {
        auto now = std::chrono::steady_clock::now();
        if (cancellation.stop_requested() && !stopping) {
            stopping = true;
            stopTime = now;
            SetEvent(exitEvent.value);
        }
        if (management.value == INVALID_SOCKET && !stopping) {
            sockaddr_in peer{};
            int peerSize = sizeof(peer);
            SOCKET accepted = accept(listener.value, reinterpret_cast<sockaddr*>(&peer), &peerSize);
            if (accepted != INVALID_SOCKET) {
                bool expected = false;
                for (int retry = 0; retry < 20 && !expected; ++retry) {
                    expected = IsExpectedPeer(peer, address, pi.dwProcessId);
                    if (!expected) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }
                if (!expected) {
                    closesocket(accepted);
                } else {
                    management.value = accepted;
                    ioctlsocket(management.value, FIONBIO, &nonblock);
                    sink({EventType::Diagnostic, L"本机管理接口已接入，核心进程身份已核对。"});
                }
            }
        }
        if (management.value != INVALID_SOCKET) {
            std::array<char, 8192> bytes{};
            int count = recv(management.value, bytes.data(), static_cast<int>(bytes.size()), 0);
            if (count > 0) {
                buffer.append(bytes.data(), count);
            } else if (count == 0 && !stopping) {
                sink({EventType::Failed, L"与 OpenVPN 核心的连接已中断，请重新连接"});
                stopping = true;
                stopTime = now;
                SetEvent(exitEvent.value);
            } else if (count < 0 && WSAGetLastError() != WSAEWOULDBLOCK && !stopping) {
                sink({EventType::Failed, L"与 OpenVPN 核心的通信异常，请重新连接"});
                stopping = true;
                stopTime = now;
                SetEvent(exitEvent.value);
            }
            if (buffer.size() > 65536) {
                throw std::runtime_error("Management message exceeds limit");
            }
            auto prompt = buffer.find("ENTER PASSWORD:");
            if (!startupProtocol.authenticated() && prompt != buffer.npos) {
                if (!secretSent) {
                    commandOut(secret);
                    secretSent = true;
                }
                buffer.erase(0, prompt + 15);
            }
            size_t end;
            while ((end = buffer.find('\n')) != buffer.npos) {
                auto line = Trim(buffer.substr(0, end));
                buffer.erase(0, end + 1);
                if (commandQueue.OnLine(line)) {
                    commandAt.reset();
                }
                bool wasAuthenticated = startupProtocol.authenticated();
                auto startupCommands = startupProtocol.OnLine(line);
                commandQueue.Enqueue(std::move(startupCommands));
                if (line.starts_with(">HOLD:")) {
                    sink({EventType::Diagnostic, L"已收到核心 HOLD 等待通知。"});
                }
                if (line.starts_with("ERROR:") && !sawManagementError) {
                    sawManagementError = true;
                    sink({EventType::Diagnostic, L"管理接口返回命令错误（不记录命令或认证内容）。"});
                    if (commandQueue.waiting()) {
                        throw std::runtime_error("OpenVPN rejected a management command");
                    }
                }
                if (line == "SUCCESS: real-time state notification set to ON") {
                    sink({EventType::Diagnostic, L"核心已确认状态通知订阅。"});
                }
                if (!wasAuthenticated && startupProtocol.authenticated()) {
                    Wipe(secret);
                    readyAt = now;
                    sink({EventType::Status, L"管理接口已就绪，正在建立 VPN 连接…"});
                    if (!keepHeld) {
                        sink({EventType::Diagnostic,
                              L"已安排核心启动命令，逐条确认后放行，不依赖 HOLD 通知到达时机。"});
                    }
                }
                if (!keepHeld && line == "SUCCESS: hold release succeeded") {
                    sink({EventType::Diagnostic, L"OpenVPN 已确认启动放行。"});
                }
                if (mode == EngineMode::StartupProbe && startupProtocol.authenticated() &&
                    line == "SUCCESS: 'Auth' password entered, but not yet verified" && !stopping) {
                    probePassed = true;
                    stopping = true;
                    stopTime = now;
                    sink(
                        {EventType::Diagnostic, L"本机测试认证命令已获确认（仅合成信息，目标为环回地址）。"});
                    SetEvent(exitEvent.value);
                } else if (startupProtocol.heldProbeReady() && !stopping) {
                    probePassed = true;
                    stopping = true;
                    stopTime = now;
                    sink(
                        {EventType::Diagnostic, L"官方 OpenVPN 管理接口认证成功（未释放 HOLD，未连接远端）"});
                    SetEvent(exitEvent.value);
                } else if (startupProtocol.authenticated() && !stopping && !line.starts_with(">HOLD:")) {
                    auto commands = protocol.OnLine(line);
                    commandQueue.Enqueue(std::move(commands), protocol.authenticationExpiry());
                    if (protocol.terminal()) {
                        stopping = true;
                        stopTime = now;
                        SetEvent(exitEvent.value);
                    }
                }
                if (!stopping) {
                    try {
                        if (auto command = commandQueue.TakeNext()) {
                            try {
                                commandOut(*command);
                            } catch (...) {
                                Wipe(*command);
                                throw;
                            }
                            Wipe(*command);
                            commandAt = std::chrono::steady_clock::now();
                        }
                    } catch (...) {
                        sink({EventType::RetryBlocked,
                              L"管理命令未完成，自动重连已暂停，请查看诊断后手动连接。"});
                        throw;
                    }
                }
                Wipe(line);
            }
        }
        DWORD available = 0;
        if (PeekNamedPipe(stdoutRead.value, nullptr, 0, nullptr, &available, nullptr) && available) {
            std::array<char, 8192> bytes{};
            DWORD got = 0;
            if (::ReadFile(stdoutRead.value, bytes.data(),
                           std::min<DWORD>(available, static_cast<DWORD>(bytes.size())), &got, nullptr)) {
                output.append(bytes.data(), got);
            }
            size_t end;
            while ((end = output.find('\n')) != output.npos) {
                auto line = output.substr(0, end);
                output.erase(0, end + 1);
                Diagnose(line, sink);
                Wipe(line);
            }
            if (output.size() > 32768) {
                Wipe(output);
            }
        }
        if (!startupProtocol.authenticated() && !stopping && now - started > std::chrono::seconds(20)) {
            sink({EventType::Diagnostic, management.value == INVALID_SOCKET
                                             ? L"启动超时：核心未接入本机管理接口，尚未提交账号认证。"
                                             : L"启动超时：本机管理接口握手未完成，尚未提交账号认证。"});
            throw std::runtime_error("OpenVPN management handshake timed out");
        }
        if (!keepHeld && !stopping && readyAt && !startupProtocol.progressed() &&
            now - *readyAt > std::chrono::seconds(15)) {
            sink({EventType::Diagnostic,
                  startupProtocol.releaseConfirmed()
                      ? L"核心已确认放行，但尚未进入认证或网络连接阶段；本次连接已超时。"
                      : L"管理接口已认证，但核心未确认启动放行；本次连接已超时。"});
            sink({EventType::Failed, L"OpenVPN 启动未继续，已结束本次尝试，请查看诊断。"});
            stopping = true;
            stopTime = now;
            SetEvent(exitEvent.value);
        }
        if (!stopping && commandAt && now - *commandAt > std::chrono::seconds(10)) {
            sink({EventType::Diagnostic, L"管理命令应答超时；未重发本次认证命令。"});
            sink({EventType::RetryBlocked, L"管理命令应答超时，自动重连已暂停，请手动连接。"});
            throw std::runtime_error("OpenVPN management command acknowledgment timed out");
        }
        if (mode == EngineMode::StartupProbe && !stopping && now - started > std::chrono::seconds(15)) {
            throw std::runtime_error("Loopback startup probe timed out");
        }
        if (!protocol.connected() && !stopping && !offlineProbe && now - started > std::chrono::seconds(90)) {
            sink({EventType::Failed, L"连接超时，请检查公司 VPN 是否可访问"});
            stopping = true;
            stopTime = now;
            SetEvent(exitEvent.value);
        }
        if (stopping && now - stopTime > std::chrono::seconds(8)) {
            if (offlineProbe) {
                throw std::runtime_error("Held management probe did not shut down gracefully");
            }
            sink({EventType::Diagnostic, L"OpenVPN 未按时退出，已结束本次进程；请检查网络已恢复。"});
            TerminateJobObject(job.value, ERROR_CANCELLED);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    WaitForSingleObject(process.value, 2000);
    Wipe(secret);
    Wipe(buffer);
    Wipe(output);
    DWORD exitCode = 0;
    GetExitCodeProcess(process.value, &exitCode);
    if (offlineProbe && (!probePassed || exitCode == STILL_ACTIVE || (keepHeld && exitCode != 0))) {
        throw std::runtime_error("Real OpenVPN held management probe failed");
    }
    if (!stopping && !protocol.terminal()) {
        sink({EventType::Failed, L"OpenVPN 已退出，请查看诊断并检查配置"});
    }
    sink({EventType::Stopped, L"已断开"});
}
int RunElevatedWorker(std::wstring_view pipeName, DWORD expectedParent, std::wstring_view stopEventName) {
    if (!IsAdmin() || !pipeName.starts_with(L"\\\\.\\pipe\\OwnVPN-") || pipeName.size() > 120) {
        return 2;
    }
    if (!WaitNamedPipeW(std::wstring(pipeName).c_str(), 15000)) {
        return 3;
    }
    Handle pipe(CreateFileW(std::wstring(pipeName).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (!pipe.valid()) {
        return 4;
    }
    ULONG serverId = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &serverId) || serverId != expectedParent) {
        return 5;
    }
    DWORD parentSession = 0, ownSession = 0;
    if (!ProcessIdToSessionId(serverId, &parentSession) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &ownSession) || parentSession != ownSession) {
        return 6;
    }
    if (!stopEventName.starts_with(L"Local\\OwnVPN.Stop.") || stopEventName.size() > 120) {
        return 9;
    }
    Handle stopEvent(OpenEventW(SYNCHRONIZE, FALSE, std::wstring(stopEventName).c_str()));
    Handle parent(OpenProcess(SYNCHRONIZE, FALSE, expectedParent));
    if (!stopEvent.valid() || !parent.valid()) {
        return 10;
    }
    auto sink = [&](Event event) {
        SendPacket(pipe.value, static_cast<uint32_t>(event.type), {Utf8(event.text)});
    };
    for (;;) {
        uint32_t type = 0;
        std::vector<std::string> fields;
        if (!ReceivePacket(pipe.value, type, fields)) {
            return 0;
        }
        if (type == 101 && fields.empty()) {
            return 0;
        }
        struct FieldsGuard {
            std::vector<std::string>& fields;
            ~FieldsGuard() {
                for (auto& field : fields) {
                    Wipe(field);
                }
            }
        } fieldsGuard{fields};
        if (type != 100 || (fields.size() != 6 && fields.size() != 7)) {
            return 7;
        }
        try {
            ConnectionRequest request;
            request.profile.id = Wide(fields[0]);
            request.profile.config = AppData() / L"profiles" / request.profile.id / L"profile.ovpn";
            if (request.profile.id.size() != 32 ||
                request.profile.id.find_first_not_of(L"0123456789abcdef") != request.profile.id.npos) {
                throw std::runtime_error("Invalid managed profile ID");
            }
            request.username = std::move(fields[1]);
            request.password = std::move(fields[2]);
            request.otp = std::move(fields[3]);
            if (fields.size() == 7) {
                if (fields[6] != "dns-normal" && fields[6] != "dns-fallback") {
                    throw std::runtime_error("Unsupported DNS mode");
                }
                request.dnsFallback = fields[6] == "dns-fallback";
            }
            if (fields[4] != "concat") {
                throw std::runtime_error("Unsupported authentication mode");
            }
            std::unique_ptr<IOtpProvider> otp;
            if (fields[5] == "totp") {
                if (!request.otp.empty()) {
                    throw std::runtime_error("Automatic OTP request must not include a manual code");
                }
                otp = std::make_unique<TotpOtpProvider>(
                    [](const OtpRequest& context) {
                        return TotpRepository().Load(context.profileId, context.username);
                    },
                    SystemTotpClock(),
                    [](const OtpRequest& context) {
                        return TotpRepository().LastIssuedCounter(context.profileId, context.username);
                    },
                    [](const OtpRequest& context, int64_t counter) {
                        TotpRepository().MarkIssued(context.profileId, context.username, counter);
                    });
            } else if (fields[5] == "manual") {
                otp = std::make_unique<ManualOtpProvider>(std::move(request.otp));
            } else {
                throw std::runtime_error("Unsupported OTP provider");
            }
            auto stop = [&] {
                return WaitForSingleObject(stopEvent.value, 0) == WAIT_OBJECT_0 ||
                       WaitForSingleObject(parent.value, 0) == WAIT_OBJECT_0;
            };
            // Report completion only after the core and all per-attempt resources
            // have been destroyed. The same authenticated session can then retry.
            RunOpenVpn(
                std::move(request), std::move(otp),
                [&](Event event) {
                    if (event.type != EventType::Stopped) {
                        sink(std::move(event));
                    }
                },
                stop);
        } catch (const std::exception& e) {
            sink({EventType::Diagnostic, Wide(e.what())});
            sink({EventType::Failed, L"连接未完成，请查看诊断信息"});
        }
        sink({EventType::Stopped, L"已断开"});
    }
}
bool ProbeManagement(const EventSink& sink, bool releaseStartup) {
    ConnectionRequest request;
    try {
        auto profiles = ProfileRepository().List();
        if (profiles.empty()) {
            throw std::runtime_error("Import a company profile before running the held management probe");
        }
        request.profile = profiles.front();
        if (releaseStartup) {
            request.username = "synthetic-probe-user";
            request.password = "synthetic-probe-password";
        }
        RunOpenVpn(
            std::move(request), std::make_unique<ManualOtpProvider>("000000"), sink, [] { return false; },
            releaseStartup ? EngineMode::StartupProbe : EngineMode::HeldProbe);
        return true;
    } catch (const std::exception& e) {
        sink({EventType::Diagnostic, Wide(e.what())});
        return false;
    }
}
} // namespace ownvpn
