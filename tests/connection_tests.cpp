#include "connection_controller.h"
#include "reconnect_policy.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

using namespace ownvpn;
namespace {
int checks = 0;
void Check(bool value, const char* label) {
    ++checks;
    if (!value) {
        throw std::runtime_error(label);
    }
}
int FakeHelper(const std::wstring& pipeName, const std::wstring& eventName, const std::wstring& scenario) {
    Handle stop(OpenEventW(SYNCHRONIZE, FALSE, eventName.c_str()));
    if (!stop.valid()) {
        return 2;
    }
    if (scenario == L"before-ipc") {
        return WaitForSingleObject(stop.value, 4000) == WAIT_OBJECT_0 ? 0 : 3;
    }
    Handle pipe(
        CreateFileW(pipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!pipe.valid()) {
        return 4;
    }
    if (scenario == L"persistent" || scenario == L"retry-error" || scenario == L"network-drop") {
        for (int attempt = 0;; ++attempt) {
            uint32_t type = 0;
            std::vector<std::string> fields;
            if (!ReceivePacket(pipe.value, type, fields)) {
                return 0;
            }
            if (type == 101 && fields.empty()) {
                return 0;
            }
            if (type != 100 || fields.size() != 7 ||
                (fields[6] != "dns-normal" && fields[6] != "dns-fallback")) {
                return 8;
            }
            for (auto& field : fields) {
                Wipe(field);
            }
            if (WaitForSingleObject(stop.value, 0) != WAIT_TIMEOUT) {
                return 9;
            }
            SendPacket(pipe.value, static_cast<uint32_t>(EventType::Status), {"synthetic-auth"});
            if (scenario == L"network-drop") {
                SendPacket(pipe.value, static_cast<uint32_t>(EventType::Connected), {"192.0.2.1"});
                if (attempt == 0) {
                    SendPacket(pipe.value, static_cast<uint32_t>(EventType::ConnectionLost),
                               {"synthetic-drop"});
                }
            }
            if (scenario == L"retry-error" && attempt == 0) {
                SendPacket(pipe.value, static_cast<uint32_t>(EventType::Failed), {"synthetic-error"});
            } else if (WaitForSingleObject(stop.value, 4000) != WAIT_OBJECT_0) {
                return 10;
            }
            SendPacket(pipe.value, static_cast<uint32_t>(EventType::Stopped), {"stopped"});
        }
    }
    uint32_t type = 0;
    std::vector<std::string> fields;
    if (!ReceivePacket(pipe.value, type, fields) || type != 100) {
        return 5;
    }
    for (auto& field : fields) {
        Wipe(field);
    }
    if (scenario == L"silent-start") {
        return WaitForSingleObject(stop.value, 4000) == WAIT_OBJECT_0 ? 0 : 7;
    }
    SendPacket(pipe.value, static_cast<uint32_t>(EventType::Status), {Utf8(L"正在验证账号…")});
    if (scenario == L"exit") {
        return 6;
    }
    if (scenario == L"partial") {
        uint32_t length = 64;
        DWORD count = 0;
        ::WriteFile(pipe.value, &length, sizeof(length), &count, nullptr);
        ::WriteFile(pipe.value, "ab", 2, &count, nullptr);
    }
    // No reads on this synchronous pipe after AUTH. The previous GUI Stop()
    // would block in WriteFile behind the GUI reader's pending ReadFile.
    if (WaitForSingleObject(stop.value, 4000) != WAIT_OBJECT_0) {
        return 7;
    }
    if (scenario == L"delayed") {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (scenario == L"auth" || scenario == L"delayed") {
        SendPacket(pipe.value, static_cast<uint32_t>(EventType::Stopped), {Utf8(L"已断开")});
    }
    return 0;
}
Handle Launch(const std::wstring& pipeName, const std::wstring& stopName, const std::wstring& scenario) {
    auto exe = Executable();
    auto command = QuoteArg(exe.wstring()) + L" --fake-helper " + QuoteArg(pipeName) + L" " +
                   QuoteArg(stopName) + L" " + QuoteArg(scenario);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &startup, &process)) {
        throw std::runtime_error("Cannot launch fake helper");
    }
    CloseHandle(process.hThread);
    return Handle(process.hProcess);
}
void RunScenario(const std::wstring& scenario) {
    Handle auth(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Handle stopped(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    std::atomic<int> stoppedCount = 0, failures = 0;
    ConnectionController controller(
        [&](Event event) {
            if (event.type == EventType::Status) {
                SetEvent(auth.value);
            }
            if (event.type == EventType::Failed) {
                ++failures;
            }
            if (event.type == EventType::Stopped) {
                ++stoppedCount;
                SetEvent(stopped.value);
            }
        },
        [&](HWND, const std::wstring& pipe, const std::wstring& stop) {
            return Launch(pipe, stop, scenario);
        },
        scenario == L"silent-start" ? std::chrono::milliseconds(250) : std::chrono::seconds(30));
    ConnectionRequest request;
    request.profile.id = L"synthetic-profile";
    request.username = "synthetic-user";
    request.password = "synthetic-password";
    request.otp = "123456";
    Check(controller.Start(nullptr, std::move(request)), "start isolated connection controller");
    if (scenario != L"before-ipc" && scenario != L"silent-start") {
        Check(WaitForSingleObject(auth.value, 2000) == WAIT_OBJECT_0, "fake helper reached authentication");
    }
    if (scenario == L"silent-start") {
        Check(WaitForSingleObject(stopped.value, 2500) == WAIT_OBJECT_0,
              "helper startup stall is bounded after IPC connection");
        Check(failures == 1, "startup stall reported once");
    } else if (scenario == L"exit") {
        Check(WaitForSingleObject(stopped.value, 2000) == WAIT_OBJECT_0,
              "helper crash unblocks event reader");
        Check(failures == 1, "unexpected helper exit reported");
    } else {
        // Let the reader enter its pending (or partial) synchronous read.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < 20; ++i) {
            controller.Stop();
        }
        auto elapsed = std::chrono::steady_clock::now() - start;
        Check(elapsed < std::chrono::milliseconds(100), "disconnect never waits on pipe I/O or helper exit");
        Check(WaitForSingleObject(stopped.value, 2500) == WAIT_OBJECT_0,
              "disconnect finishes while authentication read is pending");
        Check(failures == 0, "intentional disconnect is not an authentication error");
    }
    Check(!controller.active(), "controller idle after stop");
    Check(stoppedCount == 1, "one final stopped event");
}
void ReuseSession(const std::wstring& scenario) {
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Handle stopped(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Handle helper;
    int launches = 0;
    std::atomic<int> stops = 0;
    {
        ConnectionController controller(
            [&](Event event) {
                if (event.type == EventType::Status) {
                    SetEvent(ready.value);
                }
                if (event.type == EventType::Stopped) {
                    ++stops;
                    SetEvent(stopped.value);
                }
            },
            [&](HWND, const std::wstring& pipe, const std::wstring& stop) {
                ++launches;
                auto process = Launch(pipe, stop, scenario);
                HANDLE retained = nullptr;
                Check(DuplicateHandle(GetCurrentProcess(), process.value, GetCurrentProcess(), &retained,
                                      SYNCHRONIZE | PROCESS_TERMINATE, FALSE, 0),
                      "retain fake host process");
                helper.reset(retained);
                return process;
            });
        for (int attempt = 0; attempt < 4; ++attempt) {
            ResetEvent(ready.value);
            ResetEvent(stopped.value);
            ConnectionRequest request;
            request.profile.id = attempt % 2 ? L"other-profile" : L"synthetic-profile";
            request.username = "synthetic-user";
            request.password = "synthetic-password";
            request.otp = "123456";
            request.dnsFallback = attempt % 2 != 0;
            IConnectionBackend& backend = controller;
            Check(attempt % 2 ? backend.Start(std::move(request))
                              : controller.Start(nullptr, std::move(request)),
                  "start or reuse session through portable and Windows interfaces");
            Check(WaitForSingleObject(ready.value, 2000) == WAIT_OBJECT_0, "reused host accepts new request");
            if (!(scenario == L"retry-error" && attempt == 0)) {
                backend.Stop();
            }
            Check(WaitForSingleObject(stopped.value, 2500) == WAIT_OBJECT_0, "reused host finishes attempt");
            Check(!controller.active() && controller.authorized(), "authorization survives disconnect");
        }
        Check(launches == 1, "four connections need only one elevation/launch");
        Check(stops == 4, "exactly one stopped event per attempt");
        Check(TerminateProcess(helper.value, 11), "simulate idle elevated host crash");
        Check(WaitForSingleObject(helper.value, 2000) == WAIT_OBJECT_0, "idle fake host exited");
        ResetEvent(ready.value);
        ResetEvent(stopped.value);
        ConnectionRequest request;
        Check(controller.Start(nullptr, std::move(request)), "restart after host crash");
        Check(WaitForSingleObject(ready.value, 2000) == WAIT_OBJECT_0, "replacement host accepted request");
        if (scenario != L"retry-error") {
            controller.Stop();
        }
        Check(WaitForSingleObject(stopped.value, 2000) == WAIT_OBJECT_0, "replacement host finishes");
        Check(launches == 2, "new authorization only after host exits");
    }
    Check(WaitForSingleObject(helper.value, 2000) == WAIT_OBJECT_0, "idle host exits with controller");
}
void RetryTiming() {
    ReconnectPolicy retry;
    auto now = ReconnectPolicy::Clock::time_point{};
    Check(!retry.pending(), "retry off by default");
    for (int delay : {3, 6, 12, 24, 30, 30}) {
        Check(retry.Schedule(now), "schedule retry");
        Check(!retry.Schedule(now), "one pending retry only");
        Check(retry.Remaining(now) == delay, "bounded backoff");
        Check(!retry.Due(now + std::chrono::milliseconds(delay * 1000 - 1)), "never retry early");
        now += std::chrono::seconds(delay);
        Check(retry.Due(now), "retry due at boundary");
        retry.AttemptStarted();
    }
    retry.Connected(now);
    now += std::chrono::seconds(61);
    retry.Schedule(now);
    Check(retry.Remaining(now) == 3, "stable connection resets backoff");
    retry.Cancel();
    Check(!retry.pending() && !retry.Due(now + std::chrono::hours(1)), "user cancellation stops retry");
}
void AutomaticRecovery() {
    Handle connected(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Handle stopped(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    std::atomic<bool> lost = false;
    int launches = 0;
    ConnectionController* current = nullptr;
    ConnectionController controller(
        [&](Event event) {
            if (event.type == EventType::Connected) {
                SetEvent(connected.value);
            }
            if (event.type == EventType::ConnectionLost) {
                lost = true;
                current->Stop();
            }
            if (event.type == EventType::Stopped) {
                SetEvent(stopped.value);
            }
        },
        [&](HWND, const std::wstring& pipe, const std::wstring& stop) {
            ++launches;
            return Launch(pipe, stop, L"network-drop");
        });
    current = &controller;
    ConnectionRequest request;
    Check(controller.Start(nullptr, std::move(request)), "start synthetic network session");
    Check(WaitForSingleObject(stopped.value, 2500) == WAIT_OBJECT_0 && lost,
          "unexpected disconnect follows normal stop path");
    ReconnectPolicy policy;
    auto now = ReconnectPolicy::Clock::now();
    policy.Schedule(now);
    Check(policy.Due(now + std::chrono::seconds(3)), "disconnect schedules recovery");
    policy.AttemptStarted();
    ResetEvent(connected.value);
    ResetEvent(stopped.value);
    ConnectionRequest retry;
    Check(controller.Start(nullptr, std::move(retry)), "automatic recovery starts new attempt");
    Check(WaitForSingleObject(connected.value, 2500) == WAIT_OBJECT_0, "recovery reaches connected state");
    Check(launches == 1, "automatic recovery reuses original authorized host");
    policy.Cancel();
    controller.Stop();
    Check(WaitForSingleObject(stopped.value, 2500) == WAIT_OBJECT_0, "user stops recovered session");
    Check(!policy.pending(), "manual stop leaves no retry scheduled");
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    if (argc == 5 && std::wstring_view(argv[1]) == L"--fake-helper") {
        return FakeHelper(argv[2], argv[3], argv[4]);
    }
    try {
        for (auto scenario : {L"auth", L"partial", L"delayed", L"before-ipc", L"exit", L"silent-start"}) {
            RunScenario(scenario);
        }
        ReuseSession(L"persistent");
        ReuseSession(L"retry-error");
        RetryTiming();
        AutomaticRecovery();
        std::cout << "PASS: " << checks << " disconnect lifecycle checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
