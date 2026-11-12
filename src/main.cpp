#include "../resources/resource.h"
#include "clipboard.h"
#include "connection_controller.h"
#include "credential_store.h"
#include "otp_setup_dialog.h"
#include "reconnect_policy.h"
#include "settings.h"
#include "system_tray.h"
#include "totp_preview.h"
#include "ui_redraw.h"
#include "ui_text.h"
#include "usage_panel.h"
#include <algorithm>
#include <chrono>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <memory>
#include <shellapi.h>
#include <sstream>
#include <uxtheme.h>

namespace ownvpn {
namespace {
constexpr UINT WM_VPN_EVENT = WM_APP + 1;
constexpr UINT WM_DIAGNOSE_CONNECT = WM_APP + 2;
constexpr int WindowWidth = 500, CollapsedHeight = 588, PanelTop = 588;
enum ControlId {
    ID_PROFILE = 101,
    ID_IMPORT,
    ID_USER,
    ID_PASS,
    ID_OTP,
    ID_REMEMBER_PASS,
    ID_RESERVED_107,
    ID_CONNECT,
    ID_DETAIL,
    ID_FORGET,
    ID_LOG,
    ID_AUTOMATIC_OTP,
    ID_OTP_SETUP,
    ID_SHOW_PASSWORD,
    ID_COPY_PASSWORD,
    ID_COPY_OTP,
    ID_AUTO_RECONNECT,
    ID_TEST_RECONNECT,
    ID_USAGE,
    ID_COPY_INSTANT_PASSWORD,
    ID_DNS_FALLBACK,
    ID_COPY_IP
};
constexpr COLORREF BG = RGB(255, 255, 255), INK = RGB(32, 35, 40), MUTED = RGB(108, 113, 120),
                   ACCENT = RGB(0, 119, 106), WHITE = RGB(255, 255, 255), BORDER = RGB(218, 226, 234),
                   ERROR_COLOR = RGB(174, 48, 53);
std::wstring Text(HWND control) {
    int n = GetWindowTextLengthW(control);
    std::wstring s(n + 1, L'\0');
    GetWindowTextW(control, s.data(), n + 1);
    s.resize(n);
    return s;
}
bool Checked(HWND control) {
    return SendMessageW(control, BM_GETCHECK, 0, 0) == BST_CHECKED;
}
void SetTextIfChanged(HWND control, const std::wstring& text) {
    if (control && Text(control) != text) {
        SetWindowTextW(control, text.c_str());
    }
}
void EnableIfChanged(HWND control, bool enabled) {
    if (control && (IsWindowEnabled(control) != FALSE) != enabled) {
        EnableWindow(control, enabled);
    }
}
std::optional<fs::path> ChooseFile(HWND owner, bool pem) {
    std::wstring path(32768, L'\0');
    OPENFILENAMEW file{};
    file.lStructSize = sizeof(file);
    file.hwndOwner = owner;
    file.lpstrFile = path.data();
    file.nMaxFile = static_cast<DWORD>(path.size());
    file.lpstrFilter = pem ? L"证书与私钥 (*.pem)\0*.pem\0所有文件\0*.*\0"
                           : L"OpenVPN 配置 (*.ovpn)\0*.ovpn\0所有文件\0*.*\0";
    file.lpstrTitle = pem ? L"选择配置依赖的 users.pem（同时包含证书和私钥）" : L"导入 OpenVPN 配置";
    file.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;
    if (!GetOpenFileNameW(&file)) {
        return std::nullopt;
    }
    path.resize(wcslen(path.c_str()));
    return fs::path(path);
}
class MainWindow {
  public:
    explicit MainWindow(std::wstring diagnosticProfile = L"", bool diagnosticReconnect = false)
        : diagnosticProfile_(std::move(diagnosticProfile)), diagnosticReconnect_(diagnosticReconnect),
          diagnosticTestPending_(diagnosticReconnect) {}
    HWND window = nullptr;
    bool UsageHasFocus() const {
        return usagePanel_.HasFocus();
    }
    ~MainWindow() {
        Wipe(manualOtpDraft_);
        controller_.reset();
        for (auto f : {font_, titleFont_, brandFont_, smallFont_}) {
            if (f) {
                DeleteObject(f);
            }
        }
        for (auto b : {background_, white_}) {
            if (b) {
                DeleteObject(b);
            }
        }
    }
    bool Create(HINSTANCE instance) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.hInstance = instance;
        wc.lpfnWndProc = WndProc;
        wc.lpszClassName = L"OwnVPN.MainWindow";
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_OWNVPN), IMAGE_ICON,
                                                 GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                                                 LR_SHARED));
        wc.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_OWNVPN), IMAGE_ICON,
                                                   GetSystemMetrics(SM_CXSMICON),
                                                   GetSystemMetrics(SM_CYSMICON), LR_SHARED));
        if (!RegisterClassExW(&wc)) {
            return false;
        }
        UINT dpi = GetDpiForSystem();
        RECT r{0, 0, MulDiv(WindowWidth, dpi, 96), MulDiv(CollapsedHeight, dpi, 96)};
        AdjustWindowRectExForDpi(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0, dpi);
        window = CreateWindowExW(0, wc.lpszClassName, L"OwnVPN 公司内网",
                                 WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
                                 CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top, nullptr,
                                 nullptr, instance, this);
        return window != nullptr;
    }

  private:
    HWND profile_ = nullptr, import_ = nullptr, user_ = nullptr, pass_ = nullptr, otp_ = nullptr,
         rememberPass_ = nullptr, showPassword_ = nullptr, connect_ = nullptr, detail_ = nullptr,
         forget_ = nullptr, log_ = nullptr, automaticOtp_ = nullptr, otpSetup_ = nullptr;
    HWND copyPassword_ = nullptr, copyOtp_ = nullptr, copyTooltips_ = nullptr,
         autoReconnectControl_ = nullptr, testReconnect_ = nullptr;
    HWND usage_ = nullptr, copyInstantPassword_ = nullptr, dnsFallback_ = nullptr, copyIp_ = nullptr;
    std::wstring connectedAddress_;
    ULONGLONG ipCopiedUntil_ = 0;
    UsagePanel usagePanel_;
    bool usageExpanded_ = false;
    SystemTray tray_;
    std::optional<bool> iconConnected_;
    UINT iconDpi_ = 0;
    ULONGLONG passwordCopiedUntil_ = 0, otpCopiedUntil_ = 0, instantPasswordCopiedUntil_ = 0;
    ReconnectPolicy reconnect_;
    bool reconnectArmed_ = false, userDisconnected_ = false, retryBlocked_ = false;
    HFONT font_ = nullptr, titleFont_ = nullptr, brandFont_ = nullptr, smallFont_ = nullptr;
    HBRUSH background_ = nullptr, white_ = nullptr;
    UINT dpi_ = 96;
    ProfileRepository repository_;
    std::vector<Profile> profiles_;
    Settings settings_;
    TotpRepository totpRepository_;
    TotpMetadata totpMetadata_;
    TotpPreview preview_{
        [](const OtpRequest& request) { return TotpRepository().Load(request.profileId, request.username); }};
    bool previewError_ = false;
    std::wstring otpHint_ = L"验证码会过期，连接前请确认仍有效。";
    bool automatic_ = false;
    std::wstring manualOtpDraft_;
    std::unique_ptr<ConnectionController> controller_;
    bool details_ = false, connected_ = false, failed_ = false, closing_ = false, loading_ = false;
    std::wstring status_ = L"准备连接", hint_ = L"选择配置并填写账号信息，即可访问公司内网。", traffic_;
    std::vector<std::wstring> diagnostics_;
    std::wstring diagnosticProfile_;
    bool diagnosticReconnect_ = false, diagnosticTestPending_ = false;
    std::chrono::steady_clock::time_point attemptAt_{};
    unsigned attempt_ = 0;
    std::chrono::steady_clock::time_point connectedAt_;
    int S(int v) const {
        return MulDiv(v, static_cast<int>(dpi_), 96);
    }
    void SetFont(HWND h, HFONT f) {
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), TRUE);
    }
    HWND Control(const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex = 0) {
        auto h = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, window,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr),
                                 nullptr);
        SetFont(h, font_);
        return h;
    }
    HFONT MakeFont(int size, int weight) {
        return CreateFontW(-MulDiv(size, static_cast<int>(dpi_), 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH, L"Microsoft YaHei UI");
    }
    void Fonts() {
        for (auto f : {font_, titleFont_, brandFont_, smallFont_}) {
            if (f) {
                DeleteObject(f);
            }
        }
        font_ = MakeFont(10, FW_NORMAL);
        titleFont_ = MakeFont(18, FW_SEMIBOLD);
        brandFont_ = MakeFont(10, FW_SEMIBOLD);
        smallFont_ = MakeFont(9, FW_NORMAL);
        for (auto h : {profile_,
                       import_,
                       user_,
                       pass_,
                       otp_,
                       rememberPass_,
                       showPassword_,
                       connect_,
                       detail_,
                       forget_,
                       log_,
                       automaticOtp_,
                       otpSetup_,
                       copyPassword_,
                       copyOtp_,
                       autoReconnectControl_,
                       testReconnect_,
                       usage_,
                       copyInstantPassword_,
                       dnsFallback_,
                       copyIp_}) {
            if (h) {
                SetFont(h, font_);
            }
        }
        if (detail_) {
            SetFont(detail_, smallFont_);
        }
        if (forget_) {
            SetFont(forget_, smallFont_);
        }
        if (usage_) {
            SetFont(usage_, smallFont_);
        }
        usagePanel_.SetFont(smallFont_);
        if (log_) {
            SetFont(log_, smallFont_);
        }
    }
    void Initialize() {
        dpi_ = GetDpiForWindow(window);
        background_ = CreateSolidBrush(BG);
        white_ = CreateSolidBrush(WHITE);
        Fonts();
        profile_ = Control(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, ID_PROFILE);
        import_ = Control(L"BUTTON", L"导入配置", BS_OWNERDRAW | WS_TABSTOP, ID_IMPORT);
        user_ = Control(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, ID_USER, WS_EX_CLIENTEDGE);
        pass_ = Control(L"EDIT", L"", ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP, ID_PASS, WS_EX_CLIENTEDGE);
        otp_ = Control(L"EDIT", L"", ES_PASSWORD | ES_NUMBER | ES_AUTOHSCROLL | WS_TABSTOP, ID_OTP,
                       WS_EX_CLIENTEDGE);
        SendMessageW(user_, EM_SETLIMITTEXT, 256, 0);
        SendMessageW(pass_, EM_SETLIMITTEXT, 512, 0);
        SendMessageW(otp_, EM_SETLIMITTEXT, 6, 0);
        SendMessageW(user_, EM_SETCUEBANNER, 0, reinterpret_cast<LPARAM>(L"公司 VPN 用户名"));
        SendMessageW(pass_, EM_SETCUEBANNER, 0, reinterpret_cast<LPARAM>(L"输入账号密码"));
        SendMessageW(otp_, EM_SETCUEBANNER, 0, reinterpret_cast<LPARAM>(L"6 位数字"));
        rememberPass_ = Control(L"BUTTON", L"记住密码", BS_AUTOCHECKBOX | WS_TABSTOP, ID_REMEMBER_PASS);
        showPassword_ = Control(L"BUTTON", L"显示密码", BS_AUTOCHECKBOX | WS_TABSTOP, ID_SHOW_PASSWORD);
        automaticOtp_ = Control(L"BUTTON", L"", BS_AUTOCHECKBOX | WS_TABSTOP, ID_AUTOMATIC_OTP);
        otpSetup_ = Control(L"BUTTON", L"自动生成", BS_OWNERDRAW | WS_TABSTOP, ID_OTP_SETUP);
        connect_ = Control(L"BUTTON", L"连接公司内网", BS_OWNERDRAW | WS_TABSTOP, ID_CONNECT);
        detail_ = Control(L"BUTTON", L"查看诊断", BS_OWNERDRAW | WS_TABSTOP, ID_DETAIL);
        usage_ = Control(L"BUTTON", L"使用说明 ▾", BS_OWNERDRAW | WS_TABSTOP, ID_USAGE);
        forget_ = Control(L"BUTTON", L"清除登录信息", BS_OWNERDRAW | WS_TABSTOP, ID_FORGET);
        copyPassword_ = Control(L"BUTTON", L"复制密码", BS_OWNERDRAW | WS_TABSTOP, ID_COPY_PASSWORD);
        copyOtp_ = Control(L"BUTTON", L"复制验证码", BS_OWNERDRAW | WS_TABSTOP, ID_COPY_OTP);
        copyInstantPassword_ =
            Control(L"BUTTON", L"复制即时密码", BS_OWNERDRAW | WS_TABSTOP, ID_COPY_INSTANT_PASSWORD);
        autoReconnectControl_ =
            Control(L"BUTTON", L"自动重连", BS_AUTOCHECKBOX | WS_TABSTOP, ID_AUTO_RECONNECT);
        testReconnect_ = Control(L"BUTTON", L"测试自动重连", BS_OWNERDRAW | WS_TABSTOP, ID_TEST_RECONNECT);
        dnsFallback_ = Control(L"BUTTON", L"尝试绕过DNS", BS_AUTOCHECKBOX | WS_TABSTOP, ID_DNS_FALLBACK);
        copyIp_ = Control(L"BUTTON", L"", BS_OWNERDRAW | WS_TABSTOP, ID_COPY_IP);
        ShowWindow(copyIp_, SW_HIDE);
        SendMessageW(autoReconnectControl_, BM_SETCHECK, BST_CHECKED, 0);
        SendMessageW(dnsFallback_, BM_SETCHECK, BST_CHECKED, 0);
        SetWindowTheme(dnsFallback_, L"Explorer", nullptr);
        SetWindowTheme(autoReconnectControl_, L"Explorer", nullptr);
        copyTooltips_ = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP,
                                        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, window,
                                        nullptr, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(copyTooltips_, TTM_SETMAXTIPWIDTH, 0, S(320));
        for (auto button : {copyPassword_, copyOtp_, automaticOtp_, otpSetup_, copyInstantPassword_,
                            dnsFallback_, copyIp_}) {
            TOOLINFOW info{};
            info.cbSize = sizeof(info);
            info.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
            info.hwnd = window;
            info.uId = reinterpret_cast<UINT_PTR>(button);
            info.lpszText = const_cast<wchar_t*>(
                button == copyPassword_   ? L"复制密码"
                : button == copyOtp_      ? L"复制验证码"
                : button == automaticOtp_ ? L"启用或关闭自动生成验证码"
                : button == copyInstantPassword_
                    ? L"复制密码和当前6位验证码，中间不加分隔符。自动生成模式会先刷新验证码。"
                : button == dnsFallback_
                    ? L"先正常解析VPN域名，解析失败时尝试已保存的IP。解析成功会自动更新IP。"
                : button == copyIp_ ? L"点击复制VPN IP地址"
                                    : L"打开验证码绑定设置");
            SendMessageW(copyTooltips_, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&info));
        }
        SetWindowTheme(rememberPass_, L"Explorer", nullptr);
        SetWindowTheme(showPassword_, L"Explorer", nullptr);
        SetWindowTheme(automaticOtp_, L"Explorer", nullptr);
        Fonts();
        Layout();
        settings_ = Settings::Load();
        LoadProfiles(diagnosticProfile_);
        controller_ = std::make_unique<ConnectionController>([this](Event e) {
            auto payload = std::make_unique<Event>(std::move(e));
            if (PostMessageW(window, WM_VPN_EVENT, 0, reinterpret_cast<LPARAM>(payload.get()))) {
                payload.release();
            }
        });
        SetTimer(window, 1, 100, nullptr);
        tray_.Create(window, GetModuleHandleW(nullptr));
        ResizeDetails();
        Update();
        if (!diagnosticProfile_.empty()) {
            if (diagnosticReconnect_ && automatic_) {
                SendMessageW(autoReconnectControl_, BM_SETCHECK, BST_CHECKED, 0);
            }
            PostMessageW(window, WM_DIAGNOSE_CONNECT, 0, 0);
        }
    }
    void Layout() {
        auto move = [&](HWND h, int x, int y, int w, int height) {
            MoveWindow(h, S(x), S(y), S(w), S(height), TRUE);
        };
        move(profile_, 24, 114, 338, 220);
        move(copyIp_, 172, 24, 304, 28);
        move(import_, 372, 114, 104, 30);
        move(user_, 24, 180, 452, 32);
        move(pass_, 24, 248, 406, 32);
        move(copyPassword_, 440, 246, 36, 36);
        move(rememberPass_, 24, 288, 120, 24);
        move(showPassword_, 156, 288, 128, 24);
        move(copyInstantPassword_, 300, 288, 176, 24);
        move(otp_, 24, 348, 226, 36);
        move(copyOtp_, 260, 348, 36, 36);
        move(automaticOtp_, 324, 354, 24, 24);
        move(otpSetup_, 352, 348, 124, 36);
        move(autoReconnectControl_, 24, 422, 132, 26);
        move(dnsFallback_, 164, 422, 170, 26);
        move(testReconnect_, 344, 420, 132, 28);
        move(connect_, 24, 462, 452, 38);
        move(detail_, 16, 548, 96, 28);
        move(usage_, 116, 548, 108, 28);
        move(forget_, 336, 548, 148, 28);
        RECT bounds{};
        GetClientRect(window, &bounds);
        int logHeight = std::max(32, MulDiv(bounds.bottom, 96, static_cast<int>(dpi_)) - PanelTop - 16);
        if (log_) {
            move(log_, 24, PanelTop, 452, logHeight);
        }
        if (usagePanel_.window()) {
            move(usagePanel_.window(), 24, PanelTop, 452, logHeight);
        }
    }
    const Profile* Selected() const {
        auto index = static_cast<int>(SendMessageW(profile_, CB_GETCURSEL, 0, 0));
        return index >= 0 && static_cast<size_t>(index) < profiles_.size() ? &profiles_[index] : nullptr;
    }
    void LoadProfiles(std::wstring_view choose = L"") {
        loading_ = true;
        profiles_ = repository_.List();
        SendMessageW(profile_, CB_RESETCONTENT, 0, 0);
        int selected = 0;
        auto id = choose.empty() ? settings_.profileId : std::wstring(choose);
        for (size_t i = 0; i < profiles_.size(); ++i) {
            DeleteLegacyOtp(profiles_[i].id);
            SendMessageW(profile_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(profiles_[i].name.c_str()));
            if (profiles_[i].id == id) {
                selected = static_cast<int>(i);
            }
        }
        if (!profiles_.empty()) {
            SendMessageW(profile_, CB_SETCURSEL, selected, 0);
        }
        loading_ = false;
        LoadProfileCredentials();
    }
    void LoadProfileCredentials() {
        loading_ = true;
        automatic_ = false;
        Wipe(manualOtpDraft_);
        Credentials c;
        if (auto p = Selected()) {
            settings_.profileId = p->id;
            settings_.Save();
            c = LoadCredentials(p->id);
        }
        SetWindowTextW(user_, c.username.c_str());
        SetWindowTextW(pass_, c.password.c_str());
        SetWindowTextW(otp_, c.otp.c_str());
        SendMessageW(rememberPass_, BM_SETCHECK, c.rememberPassword ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(showPassword_, BM_SETCHECK, BST_UNCHECKED, 0);
        SendMessageW(pass_, EM_SETPASSWORDCHAR, 0x25CF, 0);
        c.ClearSecrets();
        loading_ = false;
        auto flagEnabled = [&](const wchar_t* name) {
            if (auto p = Selected()) {
                auto flag = p->config.parent_path() / name;
                try {
                    if (fs::exists(flag)) {
                        return Trim(ReadFile(flag)) == "1";
                    }
                } catch (...) {
                }
            }
            return true;
        };
        SendMessageW(dnsFallback_, BM_SETCHECK,
                     flagEnabled(L"dns-fallback.enabled") ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(autoReconnectControl_, BM_SETCHECK,
                     flagEnabled(L"auto-reconnect.enabled") ? BST_CHECKED : BST_UNCHECKED, 0);
        RefreshAutomaticBinding();
        failed_ = false;
        status_ = L"准备连接";
        hint_ =
            profiles_.empty() ? L"先导入公司的 .ovpn 配置。" : L"仅公司路由走 VPN，其他流量使用本地网络。";
        Update();
    }
    Credentials ReadCredentials() {
        return {Text(user_), Text(pass_), Text(otp_), Checked(rememberPass_)};
    }
    void Persist() {
        if (loading_ || (controller_ && controller_->active())) {
            return;
        }
        if (auto p = Selected()) {
            auto c = ReadCredentials();
            SaveCredentials(p->id, c);
            c.ClearSecrets();
        }
    }
    void RefreshAutomaticBinding() {
        preview_.Reset();
        previewError_ = false;
        totpMetadata_ = {};
        if (auto p = Selected()) {
            totpMetadata_ = totpRepository_.Metadata(p->id, Text(user_));
        }
        bool enabled = totpMetadata_.bound && totpMetadata_.automatic;
        if (enabled != automatic_) {
            if (enabled) {
                Wipe(manualOtpDraft_);
                manualOtpDraft_ = Text(otp_);
                automatic_ = true;
                SetWindowTextW(otp_, L"");
            } else {
                automatic_ = false;
                SetWindowTextW(otp_, manualOtpDraft_.c_str());
                Wipe(manualOtpDraft_);
            }
        }
        SendMessageW(automaticOtp_, BM_SETCHECK, enabled ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(otp_, EM_SETCUEBANNER, 0,
                     reinterpret_cast<LPARAM>(enabled ? L"自动验证码" : L"6 位数字"));
        SendMessageW(otp_, EM_SETPASSWORDCHAR, enabled ? 0 : 0x25CF, 0);
        SendMessageW(otp_, EM_SETREADONLY, enabled ? TRUE : FALSE, 0);
        if (!enabled) {
            reconnectArmed_ = false;
            reconnect_.Cancel();
        }
        RefreshOtpPreview();
        Update();
    }
    void RefreshOtpPreview() {
        std::wstring nextHint = L"验证码会过期，连接前请确认仍有效。";
        if (automatic_) {
            try {
                if (auto profile = Selected()) {
                    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                    auto code =
                        preview_.Code({profile->id, Text(user_), L""}, totpMetadata_.periodSeconds, seconds);
                    SetTextIfChanged(otp_, code);
                    Wipe(code);
                    previewError_ = false;
                    int remaining =
                        totpMetadata_.periodSeconds - static_cast<int>(seconds % totpMetadata_.periodSeconds);
                    nextHint = std::to_wstring(remaining) + L" 秒后更新，登录时自动取码";
                }
            } catch (...) {
                SetTextIfChanged(otp_, L"");
                previewError_ = true;
                nextHint = L"自动验证码不可用，请检查绑定和系统时间";
            }
        }
        if (otpHint_ != nextHint) {
            otpHint_ = std::move(nextHint);
            RECT hint{S(24), S(392), S(476), S(416)};
            InvalidateRect(window, &hint, FALSE);
        }
        UpdateCopyButtons();
    }
    void UpdateCopyButtons() {
        if (ipCopiedUntil_ && GetTickCount64() >= ipCopiedUntil_) {
            ipCopiedUntil_ = 0;
        }
        SetTextIfChanged(copyIp_, connectedAddress_ + (ipCopiedUntil_ ? L" 已复制" : L""));
        EnableIfChanged(copyPassword_, GetWindowTextLengthW(pass_) > 0);
        EnableIfChanged(copyOtp_, GetWindowTextLengthW(otp_) > 0 && (!automatic_ || !previewError_));
        EnableIfChanged(copyInstantPassword_, !closing_);
        auto now = GetTickCount64();
        if (passwordCopiedUntil_ && now >= passwordCopiedUntil_) {
            passwordCopiedUntil_ = 0;
            SetTextIfChanged(copyPassword_, L"复制密码");
        }
        if (otpCopiedUntil_ && now >= otpCopiedUntil_) {
            otpCopiedUntil_ = 0;
            SetTextIfChanged(copyOtp_, L"复制验证码");
        }
        if (instantPasswordCopiedUntil_ && now >= instantPasswordCopiedUntil_) {
            instantPasswordCopiedUntil_ = 0;
            SetTextIfChanged(copyInstantPassword_, L"复制即时密码");
        }
    }
    void CopyField(bool password) {
        if (!password && automatic_) {
            RefreshOtpPreview();
        }
        auto value = Text(password ? pass_ : otp_);
        bool copied = CopyTextToClipboard(window, value);
        Wipe(value);
        if (!copied) {
            MessageBoxW(window, L"无法复制，请确认内容非空，或稍后重试。", L"复制",
                        MB_OK | MB_ICONINFORMATION);
            return;
        }
        (password ? passwordCopiedUntil_ : otpCopiedUntil_) = GetTickCount64() + 1500;
        SetTextIfChanged(password ? copyPassword_ : copyOtp_, password ? L"密码已复制" : L"验证码已复制");
    }
    void CopyInstantPassword() {
        if (automatic_) {
            RefreshOtpPreview();
        }
        auto password = Text(pass_);
        auto code = Text(otp_);
        bool valid = !password.empty() && code.size() == 6 && (!automatic_ || !previewError_) &&
                     std::all_of(code.begin(), code.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; });
        if (!valid) {
            Wipe(password);
            Wipe(code);
            MessageBoxW(window, L"请先填写密码和有效的 6 位验证码。", L"复制即时密码",
                        MB_OK | MB_ICONINFORMATION);
            return;
        }
        std::wstring value;
        value.reserve(password.size() + code.size());
        value.append(password);
        value.append(code);
        Wipe(password);
        Wipe(code);
        bool copied = CopyTextToClipboard(window, value);
        Wipe(value);
        if (!copied) {
            MessageBoxW(window, L"暂时无法复制，请稍后重试。", L"复制即时密码", MB_OK | MB_ICONINFORMATION);
            return;
        }
        instantPasswordCopiedUntil_ = GetTickCount64() + 1500;
        SetTextIfChanged(copyInstantPassword_, L"已复制");
    }
    void SetupAutomaticOtp() {
        auto profile = Selected();
        auto username = Text(user_);
        if (!profile || username.empty()) {
            MessageBoxW(window, L"请先选择配置并填写 VPN 用户名，再绑定验证码。", L"绑定验证码",
                        MB_OK | MB_ICONINFORMATION);
            return;
        }
        Persist();
        ShowOtpSetupDialog(window, profile->id, username);
        RefreshAutomaticBinding();
    }
    void ToggleAutomaticOtp() {
        auto profile = Selected();
        auto username = Text(user_);
        bool enabled = Checked(automaticOtp_);
        if (!profile || username.empty()) {
            RefreshAutomaticBinding();
            SetupAutomaticOtp();
            return;
        }
        auto metadata = totpRepository_.Metadata(profile->id, username);
        if (enabled && !metadata.bound) {
            SetupAutomaticOtp();
            return;
        }
        Persist();
        if (metadata.bound) {
            totpRepository_.SetAutomatic(profile->id, username, enabled);
        }
        RefreshAutomaticBinding();
    }
    void Import() {
        auto path = ChooseFile(window, false);
        if (!path) {
            return;
        }
        Profile p;
        try {
            p = repository_.Import(*path);
        } catch (const std::exception& e) {
            std::string reason = e.what();
            if (reason.starts_with("Missing dependency:") && (reason.find(".pem") != reason.npos)) {
                MessageBoxW(window, L"此配置依赖独立的 users.pem。请选择与公司配置配套的证书和私钥文件。",
                            L"补充证书", MB_OK | MB_ICONINFORMATION);
                auto pem = ChooseFile(window, true);
                if (!pem) {
                    return;
                }
                p = repository_.Import(*path, *pem);
            } else {
                throw;
            }
        }
        LoadProfiles(p.id);
        AddDiagnostic(L"配置已导入到本机私有目录，原文件未修改。");
    }
    void Connect(bool retry = false) {
        if (controller_->active()) {
            userDisconnected_ = true;
            reconnectArmed_ = false;
            reconnect_.Cancel();
            status_ = L"正在断开…";
            controller_->Stop();
            Update();
            return;
        }
        if (reconnect_.pending() && !retry) {
            CancelReconnect();
            return;
        }
        if (retry) {
            reconnect_.AttemptStarted();
        } else {
            reconnect_.Cancel();
        }
        retryBlocked_ = false;
        userDisconnected_ = false;
        auto p = Selected();
        if (!p) {
            Import();
            return;
        }
        auto c = ReadCredentials();
        struct SecretGuard {
            Credentials& c;
            ~SecretGuard() {
                c.ClearSecrets();
            }
        } guard{c};
        if (c.username.empty() || c.password.empty()) {
            MessageBoxW(window, L"请填写用户名和密码。", L"填写登录信息", MB_OK | MB_ICONINFORMATION);
            return;
        }
        if (!automatic_ && (c.otp.size() != 6 || c.otp.find_first_not_of(L"0123456789") != c.otp.npos)) {
            MessageBoxW(window, L"请输入 6 位数字验证码。", L"填写验证码", MB_OK | MB_ICONINFORMATION);
            SetFocus(otp_);
            return;
        }
        repository_.Validate(*p);
        SaveCredentials(p->id, c);
        settings_.profileId = p->id;
        settings_.Save();
        ConnectionRequest request;
        request.profile = *p;
        request.username = Utf8(c.username);
        request.password = Utf8(c.password);
        request.automaticOtp = automatic_;
        request.dnsFallback = Checked(dnsFallback_);
        request.otp = automatic_ ? std::string{} : Utf8(c.otp);
        failed_ = false;
        attemptAt_ = std::chrono::steady_clock::now();
        AddDiagnostic(L"开始第 " + std::to_wstring(++attempt_) + L" 次连接。");
        status_ = controller_->authorized() ? L"正在复用已授权连接服务…" : L"等待管理员授权…";
        hint_ = controller_->authorized() ? L"本次程序运行期间无需重复授权。"
                                          : L"连接服务需要权限来配置 VPN 网卡和公司路由。";
        traffic_.clear();
        InvalidateRect(window, nullptr, FALSE);
        UpdateWindow(window);
        bool started = controller_->Start(window, std::move(request));
        reconnectArmed_ = started && Checked(autoReconnectControl_) && automatic_;
        if (started) {
            status_ = L"正在启动连接服务…";
            AddDiagnostic(L"连接模式：账号密码后拼接 6 位验证码；公司内网分流。");
        }
        Update();
    }
    void CancelReconnect() {
        reconnect_.Cancel();
        reconnectArmed_ = false;
        userDisconnected_ = true;
        if (!controller_->active()) {
            status_ = L"自动重连已取消";
            hint_ = L"点击连接可重新发起连接。";
            if (!Checked(rememberPass_)) {
                SetWindowTextW(pass_, L"");
            }
        }
        Update();
    }
    void ToggleAutoReconnect() {
        if (Checked(autoReconnectControl_)) {
            if (!automatic_) {
                SendMessageW(autoReconnectControl_, BM_SETCHECK, BST_UNCHECKED, 0);
                MessageBoxW(window, L"请先绑定并启用自动生成验证码，自动重连时需要取得新的验证码。",
                            L"自动重连", MB_OK | MB_ICONINFORMATION);
                return;
            }
            reconnectArmed_ = controller_->active();
            userDisconnected_ = false;
        } else {
            CancelReconnect();
        }
        Update();
    }
    void RefreshReconnect() {
        if (!reconnect_.pending()) {
            return;
        }
        auto now = ReconnectPolicy::Clock::now();
        if (reconnect_.Due(now)) {
            if (!controller_->authorized()) {
                CancelReconnect();
                status_ = L"自动重连已暂停";
                hint_ = L"连接服务已退出，请手动连接并重新授权。";
                Update();
                return;
            }
            AddDiagnostic(L"开始自动重连，将获取新的有效验证码。");
            Connect(true);
            return;
        }
        auto text = std::to_wstring(reconnect_.Remaining(now)) + L" 秒后自动重连…";
        if (status_ != text) {
            status_ = std::move(text);
            Update();
        }
    }
    void TestReconnect() {
        if (!connected_ || !Checked(autoReconnectControl_) || !controller_->active() ||
            controller_->stopping()) {
            return;
        }
        AddDiagnostic(L"测试自动重连：模拟连接中断，正常清理本次隧道后触发重连。");
        userDisconnected_ = false;
        retryBlocked_ = false;
        reconnectArmed_ = true;
        status_ = L"正在模拟连接中断…";
        OnEvent({EventType::ConnectionLost, L"测试事件：模拟 VPN 连接意外中断。"});
    }
    void AddDiagnostic(const std::wstring& text) {
        if (!diagnostics_.empty() && diagnostics_.back().ends_with(text)) {
            return;
        }
        SYSTEMTIME now{};
        GetLocalTime(&now);
        wchar_t time[32];
        swprintf_s(time, L"%02u:%02u:%02u.%03u  ", now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
        std::wstring elapsed;
        if (attempt_) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                            attemptAt_)
                          .count();
            elapsed = L"[+" + std::to_wstring(ms) + L" ms] ";
        }
        diagnostics_.push_back(std::wstring(time) + elapsed + text);
        if (diagnostics_.size() > 150) {
            diagnostics_.erase(diagnostics_.begin());
        }
        std::wstring all;
        for (const auto& s : diagnostics_) {
            all += s + L"\r\n";
        }
        {
            try {
                WriteFile(AppData() / (diagnosticProfile_.empty() ? L"connection-diagnostic.log"
                                                                  : L"reconnect-diagnostic.log"),
                          Utf8(all));
            } catch (...) {
                // Diagnostic persistence must not interrupt tunnel operation.
            }
        }
        if (log_) {
            SetWindowTextW(log_, all.c_str());
            SendMessageW(log_, EM_SETSEL, all.size(), all.size());
            SendMessageW(log_, EM_SCROLLCARET, 0, 0);
        }
    }
    void OnEvent(const Event& e) {
        if (controller_ && controller_->stopping() &&
            (e.type == EventType::Status || e.type == EventType::Connected)) {
            return;
        }
        switch (e.type) {
        case EventType::Status:
            if (!failed_) {
                status_ = e.text;
            }
            AddDiagnostic(e.text);
            break;
        case EventType::Connected:
            connected_ = true;
            connectedAddress_ = e.text;
            ipCopiedUntil_ = 0;
            failed_ = false;
            connectedAt_ = std::chrono::steady_clock::now();
            reconnect_.Connected(connectedAt_);
            status_ = L"已连接公司内网";
            hint_.clear();
            traffic_ = L"下载 0 KB    上传 0 KB";
            AddDiagnostic(L"VPN 连接成功。");
            break;
        case EventType::Failed:
            if (diagnosticReconnect_) {
                reconnectArmed_ = false;
            }
            failed_ = true;
            connected_ = false;
            status_ = L"连接未完成";
            hint_ = e.text;
            AddDiagnostic(e.text);
            break;
        case EventType::Stopped:
            connected_ = false;
            if (reconnectArmed_ && Checked(autoReconnectControl_) && automatic_ && !userDisconnected_ &&
                !retryBlocked_ && !closing_ && controller_->authorized()) {
                reconnect_.Schedule(ReconnectPolicy::Clock::now());
                failed_ = false;
                hint_ = L"将使用新的验证码重连；点击按钮可取消。";
                AddDiagnostic(L"连接已中断，已安排自动重连；可点击按钮取消。");
            }
            if (!failed_) {
                status_ = L"已断开";
                if (!reconnect_.pending()) {
                    hint_ = L"其他流量继续使用本地网络。";
                }
            }
            traffic_.clear();
            if (!automatic_) {
                SetWindowTextW(otp_, L"");
            }
            if (!Checked(rememberPass_) && !reconnect_.pending()) {
                SetWindowTextW(pass_, L"");
            }
            AddDiagnostic(controller_->authorized() ? L"本次隧道已断开，已授权连接服务保留供重连使用。"
                                                    : L"连接服务已退出。");
            if (closing_) {
                DestroyWindow(window);
                return;
            }
            RefreshReconnect();
            break;
        case EventType::RetryBlocked:
            retryBlocked_ = true;
            reconnectArmed_ = false;
            reconnect_.Cancel();
            AddDiagnostic(e.text);
            break;
        case EventType::ConnectionLost:
            connected_ = false;
            status_ = L"连接已中断，正在处理…";
            AddDiagnostic(e.text);
            if (reconnectArmed_ && Checked(autoReconnectControl_) && !userDisconnected_ && !closing_) {
                controller_->Stop();
            }
            break;
        case EventType::Diagnostic:
            AddDiagnostic(e.text);
            break;
        case EventType::Traffic: {
            auto comma = e.text.find(L',');
            if (comma != e.text.npos) {
                try {
                    auto down = std::stoull(e.text.substr(0, comma)),
                         up = std::stoull(e.text.substr(comma + 1));
                    traffic_ = L"下载 " + FormatTrafficBytes(down) + L"    上传 " + FormatTrafficBytes(up);
                } catch (...) {
                }
            }
            break;
        }
        case EventType::NeedOtp:
            break;
        }
        Update();
    }
    void Update() {
        if (!connected_) {
            connectedAddress_.clear();
            ipCopiedUntil_ = 0;
        }
        bool showIp = connected_ && !closing_ && !(controller_ && controller_->stopping()) &&
                      !connectedAddress_.empty();
        if (((GetWindowLongPtrW(copyIp_, GWL_STYLE) & WS_VISIBLE) != 0) != showIp) {
            ShowWindow(copyIp_, showIp ? SW_SHOW : SW_HIDE);
        }
        bool active = controller_ && controller_->active();
        for (auto h : {profile_, import_, user_, pass_, rememberPass_, forget_, automaticOtp_, otpSetup_}) {
            EnableIfChanged(h, !active && !reconnect_.pending());
        }
        EnableIfChanged(otp_, automatic_ || !active);
        bool stopping = active && controller_->stopping();
        EnableIfChanged(autoReconnectControl_, automatic_ && !closing_);
        EnableIfChanged(dnsFallback_, !closing_);
        EnableIfChanged(testReconnect_,
                        connected_ && active && Checked(autoReconnectControl_) && !stopping && !closing_);
        UpdateCopyButtons();
        EnableIfChanged(connect_, !closing_ && !stopping);
        SetTextIfChanged(connect_, stopping               ? L"正在断开…"
                                   : reconnect_.pending() ? L"取消自动重连"
                                   : active ? L"断开连接"
                                            : (profiles_.empty() ? L"导入公司配置" : L"连接公司内网"));
        SetTextIfChanged(window, L"OwnVPN " + CleanUiText(status_));
        UpdateAppIcons();
        tray_.Update(connected_, status_, active, stopping, reconnect_.pending(), closing_);
        RECT header{0, 0, S(WindowWidth), S(80)};
        RECT information{S(24), S(508), S(476), S(536)};
        InvalidateRect(window, &header, FALSE);
        InvalidateRect(window, &information, FALSE);
    }
    void UpdateAppIcons() {
        if (iconConnected_ == connected_ && iconDpi_ == dpi_) {
            return;
        }
        auto instance = GetModuleHandleW(nullptr);
        auto large = LoadAppIcon(instance, connected_, false, dpi_);
        auto small = LoadAppIcon(instance, connected_, true, dpi_);
        if (!large || !small) {
            return;
        }
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large));
        SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(small));
        SetClassLongPtrW(window, GCLP_HICON, reinterpret_cast<LONG_PTR>(large));
        SetClassLongPtrW(window, GCLP_HICONSM, reinterpret_cast<LONG_PTR>(small));
        iconConnected_ = connected_;
        iconDpi_ = dpi_;
        RECT brand{S(16), S(14), S(62), S(60)};
        InvalidateRect(window, &brand, FALSE);
    }
    void RestoreFromTray() {
        ShowWindow(window, SW_RESTORE);
        SetForegroundWindow(window);
    }
    void HideToTray() {
        if (closing_) {
            return;
        }
        if (!tray_.EnsurePresent()) {
            MessageBoxW(window, L"暂时无法创建托盘图标，窗口将保持显示。", L"OwnVPN",
                        MB_OK | MB_ICONINFORMATION);
            ShowWindow(window, SW_RESTORE);
            return;
        }
        Persist();
        ShowWindow(window, SW_HIDE);
    }
    void RequestExit() {
        if (closing_) {
            return;
        }
        closing_ = true;
        reconnect_.Cancel();
        reconnectArmed_ = false;
        userDisconnected_ = true;
        Persist();
        if (controller_ && controller_->active()) {
            controller_->Stop();
            status_ = L"正在断开并退出…";
            Update();
        } else {
            DestroyWindow(window);
        }
    }
    void ToggleDetails() {
        details_ = !details_;
        if (details_ && usageExpanded_) {
            usageExpanded_ = false;
            ShowWindow(usagePanel_.window(), SW_HIDE);
            SetWindowTextW(usage_, L"使用说明 ▾");
        }
        if (details_ && !log_) {
            log_ = Control(L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, ID_LOG,
                           WS_EX_CLIENTEDGE);
            SetFont(log_, smallFont_);
            std::wstring all;
            for (const auto& line : diagnostics_) {
                all += line + L"\r\n";
            }
            if (all.empty()) {
                all = L"暂无诊断记录，连接后将在这里显示。";
            }
            SetWindowTextW(log_, all.c_str());
        }
        ShowWindow(log_, details_ ? SW_SHOW : SW_HIDE);
        SetWindowTextW(detail_, details_ ? L"收起诊断" : L"查看诊断");
        ResizeDetails();
    }
    void ToggleUsage() {
        usageExpanded_ = !usageExpanded_;
        if (usageExpanded_) {
            usagePanel_.Create(window, smallFont_);
            if (details_) {
                details_ = false;
                ShowWindow(log_, SW_HIDE);
                SetWindowTextW(detail_, L"查看诊断");
            }
        }
        ShowWindow(usagePanel_.window(), usageExpanded_ ? SW_SHOW : SW_HIDE);
        SetWindowTextW(usage_, usageExpanded_ ? L"收起说明 ▴" : L"使用说明 ▾");
        ResizeDetails();
    }
    void ResizeDetails() {
        RECT r{
            0, 0, S(WindowWidth),
            S(usageExpanded_ ? CollapsedHeight + 270 : (details_ ? CollapsedHeight + 196 : CollapsedHeight))};
        AdjustWindowRectExForDpi(&r, GetWindowLongW(window, GWL_STYLE), FALSE, 0, dpi_);
        MONITORINFO monitor{};
        monitor.cbSize = sizeof(monitor);
        GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST), &monitor);
        RECT current{};
        GetWindowRect(window, &current);
        int height = std::min(r.bottom - r.top, monitor.rcWork.bottom - monitor.rcWork.top);
        int y = std::min(current.top, monitor.rcWork.bottom - height);
        SetWindowPos(window, nullptr, current.left, std::max<LONG>(y, monitor.rcWork.top), r.right - r.left,
                     height, SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS);
        Layout();
        InvalidateRect(window, nullptr, FALSE);
    }
    void DrawTextAt(HDC dc, const std::wstring& text, HFONT font, COLORREF color, int x, int y, int width,
                    int height, UINT flags = DT_LEFT | DT_TOP | DT_NOPREFIX) {
        SelectObject(dc, font);
        SetTextColor(dc, color);
        RECT r{S(x), S(y), S(x + width), S(y + height)};
        auto display = CleanUiText(text);
        DrawTextW(dc, display.c_str(), -1, &r, flags);
    }
    void Paint() {
        PAINTSTRUCT ps{};
        HDC target = BeginPaint(window, &ps);
        RECT bounds;
        GetClientRect(window, &bounds);
        HDC buffer = CreateCompatibleDC(target);
        HBITMAP bitmap = buffer ? CreateCompatibleBitmap(target, bounds.right, bounds.bottom) : nullptr;
        HGDIOBJ previous = bitmap ? SelectObject(buffer, bitmap) : nullptr;
        HDC dc = bitmap ? buffer : target;
        SetBkMode(dc, TRANSPARENT);
        FillRect(dc, &bounds, background_);
        DrawIconEx(dc, S(24), S(22), reinterpret_cast<HICON>(GetClassLongPtrW(window, GCLP_HICON)), S(32),
                   S(32), 0, nullptr, DI_NORMAL);
        bool active = controller_ && controller_->active();
        bool stopping = active && controller_->stopping();
        std::wstring heading = closing_               ? L"正在退出"
                               : stopping             ? L"正在断开"
                               : connected_           ? L"已连接"
                               : reconnect_.pending() ? L"等待重连"
                               : failed_              ? L"连接失败"
                               : active               ? L"正在连接"
                                                      : L"未连接";
        std::wstring summary = (active && !connected_) || reconnect_.pending() || closing_ ? status_
                               : connected_                                                ? L""
                               : failed_                                                   ? hint_
                               : profiles_.empty() ? L"导入 .ovpn 配置开始使用"
                                                   : L"选择配置，连接公司内网";
        DrawTextAt(dc, heading, titleFont_, failed_ ? ERROR_COLOR : INK, 72, 22, 404, 32,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        DrawTextAt(dc, summary, smallFont_, MUTED, 72, 58, 404, 18,
                   DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        auto pen = CreatePen(PS_SOLID, 1, BORDER);
        auto oldPen = SelectObject(dc, pen);
        MoveToEx(dc, S(24), S(80), nullptr);
        LineTo(dc, S(476), S(80));
        MoveToEx(dc, S(24), S(540), nullptr);
        LineTo(dc, S(476), S(540));
        SelectObject(dc, oldPen);
        DeleteObject(pen);
        DrawTextAt(dc, L"连接配置", smallFont_, INK, 24, 92, 452, 20);
        DrawTextAt(dc, L"用户名", smallFont_, INK, 24, 158, 452, 20);
        DrawTextAt(dc, L"密码", smallFont_, INK, 24, 226, 452, 20);
        DrawTextAt(dc, L"动态验证码", smallFont_, INK, 24, 326, 240, 20);
        DrawTextAt(dc, otpHint_, smallFont_, MUTED, 24, 392, 452, 22);
        DrawTextAt(dc, traffic_, smallFont_, MUTED, 24, 512, 452, 20,
                   DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
        if (bitmap) {
            BitBlt(target, ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right - ps.rcPaint.left,
                   ps.rcPaint.bottom - ps.rcPaint.top, buffer, ps.rcPaint.left, ps.rcPaint.top, SRCCOPY);
            SelectObject(buffer, previous);
            DeleteObject(bitmap);
        }
        if (buffer) {
            DeleteDC(buffer);
        }
        EndPaint(window, &ps);
    }
    void DrawButton(const DRAWITEMSTRUCT& item) {
        bool primary = item.CtlID == ID_CONNECT, disabled = (item.itemState & ODS_DISABLED) != 0,
             pressed = (item.itemState & ODS_SELECTED) != 0;
        bool filled =
            primary && !(controller_ && controller_->active()) && !connected_ && !reconnect_.pending();
        bool link = item.CtlID == ID_DETAIL || item.CtlID == ID_FORGET || item.CtlID == ID_USAGE ||
                    item.CtlID == ID_TEST_RECONNECT || item.CtlID == ID_COPY_INSTANT_PASSWORD ||
                    item.CtlID == ID_COPY_IP;
        COLORREF bg = filled    ? (disabled ? RGB(190, 194, 198) : (pressed ? RGB(0, 94, 84) : ACCENT))
                      : pressed ? RGB(242, 244, 246)
                                : WHITE;
        auto brush = CreateSolidBrush(bg);
        FillRect(item.hDC, &item.rcItem, brush);
        DeleteObject(brush);
        if (primary || item.CtlID == ID_IMPORT || item.CtlID == ID_OTP_SETUP) {
            auto border = CreatePen(PS_SOLID, 1, filled ? bg : BORDER);
            auto oldPen = SelectObject(item.hDC, border);
            auto oldBrush = SelectObject(item.hDC, GetStockObject(HOLLOW_BRUSH));
            Rectangle(item.hDC, item.rcItem.left, item.rcItem.top, item.rcItem.right, item.rcItem.bottom);
            SelectObject(item.hDC, oldBrush);
            SelectObject(item.hDC, oldPen);
            DeleteObject(border);
        }
        SetBkMode(item.hDC, TRANSPARENT);
        SetTextColor(item.hDC, disabled ? RGB(166, 170, 175)
                               : (item.CtlID == ID_COPY_INSTANT_PASSWORD || item.CtlID == ID_COPY_IP) ? ACCENT
                               : filled                                                               ? WHITE
                               : link                                                                 ? MUTED
                                                                                                      : INK);
        if (item.CtlID == ID_COPY_PASSWORD || item.CtlID == ID_COPY_OTP) {
            auto pen = CreatePen(PS_SOLID, S(2), MUTED);
            auto oldPen = SelectObject(item.hDC, pen);
            auto oldBrush = SelectObject(item.hDC, GetStockObject(HOLLOW_BRUSH));
            int x = (item.rcItem.left + item.rcItem.right) / 2 - S(9);
            int y = (item.rcItem.top + item.rcItem.bottom) / 2 - S(9);
            bool copied = item.CtlID == ID_COPY_PASSWORD ? passwordCopiedUntil_ != 0 : otpCopiedUntil_ != 0;
            if (copied) {
                MoveToEx(item.hDC, x, y + S(9), nullptr);
                LineTo(item.hDC, x + S(6), y + S(15));
                LineTo(item.hDC, x + S(18), y + S(2));
            } else {
                Rectangle(item.hDC, x, y, x + S(13), y + S(14));
                SelectObject(item.hDC, GetStockObject(WHITE_BRUSH));
                Rectangle(item.hDC, x + S(5), y + S(5), x + S(18), y + S(19));
            }
            SelectObject(item.hDC, oldBrush);
            SelectObject(item.hDC, oldPen);
            DeleteObject(pen);
            if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) {
                auto r = item.rcItem;
                InflateRect(&r, -S(3), -S(3));
                DrawFocusRect(item.hDC, &r);
            }
            return;
        }
        SelectObject(item.hDC, primary ? brandFont_ : font_);
        auto text = CleanUiText(Text(item.hwndItem));
        auto r = item.rcItem;
        DrawTextW(item.hDC, text.c_str(), -1, &r,
                  (item.CtlID == ID_COPY_IP ? DT_LEFT | DT_END_ELLIPSIS : DT_CENTER) | DT_VCENTER |
                      DT_SINGLELINE | DT_NOPREFIX);
        if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) {
            if (item.CtlID == ID_COPY_IP) {
                // Keep keyboard focus visible without drawing over IP digits.
                SIZE extent{};
                GetTextExtentPoint32W(item.hDC, text.c_str(), static_cast<int>(text.size()), &extent);
                auto pen = CreatePen(PS_SOLID, 1, ACCENT);
                auto oldPen = SelectObject(item.hDC, pen);
                MoveToEx(item.hDC, r.left, r.bottom - S(2), nullptr);
                LineTo(item.hDC, std::min(r.right, r.left + extent.cx), r.bottom - S(2));
                SelectObject(item.hDC, oldPen);
                DeleteObject(pen);
            } else {
                InflateRect(&r, -S(4), -S(4));
                DrawFocusRect(item.hDC, &r);
            }
        }
    }
    static LRESULT CALLBACK WndProc(HWND h, UINT message, WPARAM wp, LPARAM lp) {
        auto self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(h, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<MainWindow*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            self->window = h;
            SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) {
            return DefWindowProcW(h, message, wp, lp);
        }
        try {
            if (self->tray_.TaskbarCreatedMessage() && message == self->tray_.TaskbarCreatedMessage()) {
                if (!self->tray_.Recreate() && !self->closing_) {
                    self->RestoreFromTray();
                }
                return 0;
            }
            switch (message) {
            case SystemTray::Message: {
                auto action = self->tray_.OnCallback(wp, lp);
                if (action == TrayAction::Show) {
                    self->RestoreFromTray();
                } else if (action == TrayAction::Exit) {
                    self->RequestExit();
                } else if (action == TrayAction::ToggleConnection) {
                    if ((!self->controller_ || !self->controller_->active()) && !self->reconnect_.pending() &&
                        (!self->automatic_ || !GetWindowTextLengthW(self->user_) ||
                         !GetWindowTextLengthW(self->pass_))) {
                        self->RestoreFromTray();
                    }
                    self->Connect();
                }
                return 0;
            }
            case WM_SIZE:
                if (wp == SIZE_MINIMIZED) {
                    self->HideToTray();
                }
                return 0;
            case WM_CREATE:
                self->Initialize();
                return 0;
            case WM_PAINT:
                self->Paint();
                return 0;
            case WM_ERASEBKGND:
                return 1;
            case WM_DRAWITEM:
                self->DrawButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lp));
                return TRUE;
            case WM_CTLCOLOREDIT:
            case WM_CTLCOLORSTATIC:
            case WM_CTLCOLORBTN: {
                auto dc = reinterpret_cast<HDC>(wp);
                SetTextColor(dc, INK);
                SetBkColor(dc, WHITE);
                return reinterpret_cast<LRESULT>(self->white_);
            }
            case WM_COMMAND: {
                int id = LOWORD(wp), notification = HIWORD(wp);
                if (id == ID_IMPORT && notification == BN_CLICKED) {
                    self->Import();
                } else if (id == ID_PROFILE && notification == CBN_SELCHANGE) {
                    self->LoadProfileCredentials();
                } else if (id == ID_CONNECT && notification == BN_CLICKED) {
                    self->Connect();
                } else if (id == ID_DETAIL && notification == BN_CLICKED) {
                    self->ToggleDetails();
                } else if (id == ID_USAGE && notification == BN_CLICKED) {
                    self->ToggleUsage();
                } else if (id == ID_FORGET && notification == BN_CLICKED) {
                    if (auto p = self->Selected()) {
                        DeleteCredentials(p->id);
                    }
                    self->LoadProfileCredentials();
                } else if (id == ID_AUTOMATIC_OTP && notification == BN_CLICKED) {
                    self->ToggleAutomaticOtp();
                } else if (id == ID_OTP_SETUP && notification == BN_CLICKED) {
                    self->SetupAutomaticOtp();
                } else if (id == ID_SHOW_PASSWORD && notification == BN_CLICKED) {
                    SendMessageW(self->pass_, EM_SETPASSWORDCHAR, Checked(self->showPassword_) ? 0 : 0x25CF,
                                 0);
                    InvalidateRect(self->pass_, nullptr, FALSE);
                } else if ((id == ID_COPY_PASSWORD || id == ID_COPY_OTP) && notification == BN_CLICKED) {
                    self->CopyField(id == ID_COPY_PASSWORD);
                } else if (id == ID_COPY_INSTANT_PASSWORD && notification == BN_CLICKED) {
                    self->CopyInstantPassword();
                } else if (id == ID_COPY_IP && notification == BN_CLICKED) {
                    if (self->connected_ && CopyTextToClipboard(h, self->connectedAddress_)) {
                        self->ipCopiedUntil_ = GetTickCount64() + 1500;
                        self->UpdateCopyButtons();
                    }
                } else if (id == ID_AUTO_RECONNECT && notification == BN_CLICKED) {
                    self->ToggleAutoReconnect();
                    if (auto p = self->Selected()) {
                        WriteFile(p->config.parent_path() / L"auto-reconnect.enabled",
                                  Checked(self->autoReconnectControl_) ? "1" : "0");
                    }
                } else if (id == ID_DNS_FALLBACK && notification == BN_CLICKED) {
                    if (auto p = self->Selected()) {
                        WriteFile(p->config.parent_path() / L"dns-fallback.enabled",
                                  Checked(self->dnsFallback_) ? "1" : "0");
                    }
                    self->AddDiagnostic(Checked(self->dnsFallback_)
                                            ? L"已启用尝试绕过DNS：仅解析失败时使用历史 IP。"
                                            : L"已关闭尝试绕过DNS。");
                } else if (id == ID_TEST_RECONNECT && notification == BN_CLICKED) {
                    self->TestReconnect();
                } else if ((id == ID_PASS || id == ID_OTP) && notification == EN_CHANGE) {
                    auto button = id == ID_PASS ? self->copyPassword_ : self->copyOtp_;
                    (id == ID_PASS ? self->passwordCopiedUntil_ : self->otpCopiedUntil_) = 0;
                    SetTextIfChanged(button, id == ID_PASS ? L"复制密码" : L"复制验证码");
                    self->instantPasswordCopiedUntil_ = 0;
                    SetTextIfChanged(self->copyInstantPassword_, L"复制即时密码");
                    self->UpdateCopyButtons();
                } else if (id == ID_REMEMBER_PASS && notification == BN_CLICKED) {
                    self->Persist();
                } else if ((id == ID_USER || id == ID_PASS || id == ID_OTP) && notification == EN_KILLFOCUS) {
                    self->Persist();
                    if (id == ID_USER) {
                        self->RefreshAutomaticBinding();
                    }
                }
                return 0;
            }
            case WM_VPN_EVENT: {
                std::unique_ptr<Event> e(reinterpret_cast<Event*>(lp));
                self->OnEvent(*e);
                return 0;
            }
            case WM_DIAGNOSE_CONNECT: {
                auto profile = self->Selected();
                if (!profile || profile->id != self->diagnosticProfile_ || Text(self->user_).empty() ||
                    Text(self->pass_).empty() || !self->automatic_) {
                    self->AddDiagnostic(L"诊断重连未启动：配置或已保存的自动登录信息不完整。");
                    return 0;
                }
                self->ToggleDetails();
                self->Connect();
                return 0;
            }
            case WM_TIMER: {
                self->RefreshOtpPreview();
                self->RefreshReconnect();
                if (self->diagnosticTestPending_ && self->connected_ &&
                    std::chrono::steady_clock::now() - self->connectedAt_ >= std::chrono::seconds(2)) {
                    self->diagnosticTestPending_ = false;
                    self->TestReconnect();
                }
                return 0;
            }
            case WM_DPICHANGED: {
                ScopedUiRedraw redraw(h);
                self->dpi_ = HIWORD(wp);
                auto r = reinterpret_cast<RECT*>(lp);
                SetWindowPos(h, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                             SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS);
                self->Fonts();
                self->UpdateAppIcons();
                // Recompute the expanded/collapsed size for the destination
                // monitor, rather than retaining a previously capped height.
                self->ResizeDetails();
                return 0;
            }
            case WM_CLOSE:
                self->HideToTray();
                return 0;
            case WM_QUERYENDSESSION:
                return TRUE;
            case WM_ENDSESSION:
                if (wp) {
                    self->RequestExit();
                }
                return 0;
            case WM_DESTROY:
                self->tray_.Remove();
                KillTimer(h, 1);
                self->controller_.reset();
                PostQuitMessage(0);
                return 0;
            }
        } catch (const std::exception& e) {
            MessageBoxW(h, Wide(e.what()).c_str(), L"OwnVPN", MB_OK | MB_ICONERROR);
            return 0;
        }
        return DefWindowProcW(h, message, wp, lp);
    }
};
} // namespace
} // namespace ownvpn
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    using namespace ownvpn;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        return 1;
    }
    std::vector<std::wstring> args;
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    LocalFree(argv);
    try {
        if (args.size() == 5 && args[1] == L"--worker") {
            return RunElevatedWorker(args[2], static_cast<DWORD>(std::stoul(args[3])), args[4]);
        }
        if (args.size() >= 3 && args[1] == L"--import") {
            auto p = ProfileRepository().Import(args[2], args.size() > 3 ? fs::path(args[3]) : fs::path{});
            Settings{p.id}.Save();
            return 0;
        }
        bool diagnose =
            args.size() == 3 && (args[1] == L"--diagnose-connect" || args[1] == L"--diagnose-reconnect") &&
            args[2].size() == 32 && args[2].find_first_not_of(L"0123456789abcdef") == args[2].npos;
        if (args.size() > 1 && !diagnose) {
            return 2;
        }
        auto mutexName = L"Local\\OwnVPN.UI." + CurrentSid();
        Handle instanceLock(CreateMutexW(nullptr, FALSE, mutexName.c_str()));
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            auto existing = FindWindowW(L"OwnVPN.MainWindow", nullptr);
            if (existing) {
                ShowWindow(existing, SW_RESTORE);
                SetForegroundWindow(existing);
            }
            return 0;
        }
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_LINK_CLASS};
        InitCommonControlsEx(&controls);
        PrivateDirectory(AppData());
        MainWindow window(diagnose ? args[2] : L"", diagnose && args[1] == L"--diagnose-reconnect");
        if (!window.Create(instance)) {
            throw std::runtime_error("Cannot create main window");
        }
        ShowWindow(window.window, show);
        UpdateWindow(window.window);
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            if (message.message == WM_KEYDOWN && message.wParam == VK_RETURN && !window.UsageHasFocus()) {
                if (GetDlgCtrlID(GetFocus()) == ID_USAGE || GetDlgCtrlID(GetFocus()) == ID_OTP_SETUP ||
                    GetDlgCtrlID(GetFocus()) == ID_COPY_INSTANT_PASSWORD ||
                    GetDlgCtrlID(GetFocus()) == ID_COPY_IP) {
                    SendMessageW(GetFocus(), BM_CLICK, 0, 0);
                    continue;
                }
                SendMessageW(window.window, WM_COMMAND, MAKEWPARAM(ID_CONNECT, BN_CLICKED), 0);
                continue;
            }
            if (!IsDialogMessageW(window.window, &message)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        CoUninitialize();
        return 0;
    } catch (const std::exception& e) {
        MessageBoxW(nullptr, Wide(e.what()).c_str(), L"OwnVPN", MB_OK | MB_ICONERROR);
        return 1;
    }
}
