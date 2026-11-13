#include "otp_setup_dialog.h"
#include "qr_import.h"
#include "totp_detection.h"
#include "ui_redraw.h"
#include "windows_platform.h"
#include <commctrl.h>
#include <commdlg.h>

namespace ownvpn {
namespace {
enum { ID_QR = 1001, ID_SECRET, ID_ALGORITHM, ID_PERIOD, ID_REMOVE, ID_PHONE_CODE, ID_VERIFY };
std::wstring Text(HWND control) {
    int length = GetWindowTextLengthW(control);
    std::wstring text(length + 1, L'\0');
    GetWindowTextW(control, text.data(), length + 1);
    text.resize(length);
    return text;
}
std::optional<fs::path> SelectImage(HWND owner) {
    std::wstring path(32768, L'\0');
    OPENFILENAMEW file{};
    file.lStructSize = sizeof(file);
    file.hwndOwner = owner;
    file.lpstrFile = path.data();
    file.nMaxFile = static_cast<DWORD>(path.size());
    file.lpstrFilter = L"二维码图片 (*.png;*.jpg;*.jpeg;*.bmp)\0*.png;*.jpg;*.jpeg;*.bmp\0所有文件\0*.*\0";
    file.lpstrTitle = L"选择公司提供的 TOTP 绑定二维码";
    file.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;
    if (!GetOpenFileNameW(&file)) {
        return std::nullopt;
    }
    path.resize(wcslen(path.c_str()));
    return fs::path(path);
}
class SetupDialog {
  public:
    SetupDialog(HWND owner, std::wstring id, std::wstring username)
        : owner_(owner), id_(std::move(id)), username_(std::move(username)) {}
    ~SetupDialog() {
        if (font_) {
            DeleteObject(font_);
        }
    }
    bool Show() {
        WNDCLASSW wc{};
        wc.lpfnWndProc = Procedure;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wc.lpszClassName = L"OwnVPN.TotpSetup";
        RegisterClassW(&wc);
        dpi_ = GetDpiForWindow(owner_);
        RECT size{0, 0, S(500), S(562)};
        AdjustWindowRectExForDpi(&size, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME, dpi_);
        RECT parent{};
        GetWindowRect(owner_, &parent);
        HWND window = CreateWindowExW(
            WS_EX_DLGMODALFRAME, wc.lpszClassName, L"自动验证码设置", WS_CAPTION | WS_SYSMENU,
            parent.left + ((parent.right - parent.left) - (size.right - size.left)) / 2, parent.top + S(50),
            size.right - size.left, size.bottom - size.top, owner_, nullptr, wc.hInstance, this);
        if (!window) {
            throw std::runtime_error("无法创建验证码设置窗口");
        }
        EnableWindow(owner_, FALSE);
        ShowWindow(window, SW_SHOW);
        SetFocus(secret_);
        MSG message{};
        bool quit = false;
        while (!done_) {
            auto result = GetMessageW(&message, nullptr, 0, 0);
            if (result <= 0) {
                quit = result == 0;
                break;
            }
            if (!IsDialogMessageW(window, &message)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        if (IsWindow(window)) {
            DestroyWindow(window);
        }
        EnableWindow(owner_, TRUE);
        SetForegroundWindow(owner_);
        if (quit) {
            PostQuitMessage(static_cast<int>(message.wParam));
        }
        return changed_;
    }

  private:
    HWND owner_, window_ = nullptr, secret_ = nullptr, algorithm_ = nullptr, period_ = nullptr,
                 description_ = nullptr, phoneCode_ = nullptr, verification_ = nullptr;
    std::wstring id_, username_;
    HFONT font_ = nullptr;
    UINT dpi_ = 96;
    bool done_ = false, changed_ = false;
    TotpParameterDetector detector_;
    struct Placement {
        HWND control;
        int x, y, width, height;
    };
    std::vector<Placement> placements_;
    int S(int n) const {
        return MulDiv(n, static_cast<int>(dpi_), 96);
    }
    HWND Add(const wchar_t* cls, const wchar_t* text, DWORD style, int id, int x, int y, int width,
             int height, DWORD ex = 0) {
        HWND control = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, S(x), S(y), S(width),
                                       S(height), window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                       GetModuleHandleW(nullptr), nullptr);
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
        placements_.push_back({control, x, y, width, height});
        return control;
    }
    void Initialize() {
        dpi_ = GetDpiForWindow(window_);
        font_ = CreateFontW(-MulDiv(10, static_cast<int>(dpi_), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                            DEFAULT_PITCH, L"Microsoft YaHei UI");
        Add(L"STATIC", (L"绑定到 VPN 用户名：" + username_).c_str(), SS_LEFT, 0, 24, 20, 450, 26);
        Add(L"STATIC",
            L"导入原始绑定二维码，或填写 Base32 密钥 / otpauth "
            L"链接。\n仅保存在本机，不读取微软验证器里的现有账号。",
            SS_LEFT, 0, 24, 57, 450, 49);
        Add(L"BUTTON", L"导入二维码图片…", WS_TABSTOP | BS_PUSHBUTTON, ID_QR, 24, 119, 200, 36);
        Add(L"STATIC", L"绑定密钥或 otpauth 链接（输入时隐藏）", SS_LEFT, 0, 24, 173, 450, 24);
        secret_ = Add(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, ID_SECRET, 24, 201, 450, 34,
                      WS_EX_CLIENTEDGE);
        SendMessageW(secret_, EM_SETLIMITTEXT, 4096, 0);
        Add(L"STATIC", L"算法", SS_LEFT, 0, 24, 252, 180, 23);
        Add(L"STATIC", L"周期（秒）", SS_LEFT, 0, 254, 252, 180, 23);
        algorithm_ = Add(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST, ID_ALGORITHM, 24, 280, 200, 150);
        for (auto name : {L"SHA1", L"SHA256", L"SHA512"}) {
            SendMessageW(algorithm_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(name));
        }
        SendMessageW(algorithm_, CB_SETCURSEL, 0, 0);
        period_ = Add(L"EDIT", L"30", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, ID_PERIOD, 254, 280, 220, 32,
                      WS_EX_CLIENTEDGE);
        SendMessageW(period_, EM_SETLIMITTEXT, 3, 0);
        description_ =
            Add(L"STATIC",
                L"链接和二维码中的参数优先。此 VPN 使用 6 位验证码。\n没有绑定资料时，仍可在主界面手动输入。",
                SS_LEFT, 0, 24, 330, 450, 46);
        Add(L"STATIC", L"手机当前验证码（仅在本机核对，不保存）", SS_LEFT, 0, 24, 372, 450, 24);
        phoneCode_ = Add(L"EDIT", L"", WS_TABSTOP | ES_PASSWORD | ES_NUMBER, ID_PHONE_CODE, 24, 400, 200, 34,
                         WS_EX_CLIENTEDGE);
        SendMessageW(phoneCode_, EM_SETLIMITTEXT, 6, 0);
        Add(L"BUTTON", L"核对算法和周期", WS_TABSTOP | BS_PUSHBUTTON, ID_VERIFY, 254, 400, 220, 34);
        verification_ =
            Add(L"STATIC", L"不会自动修改参数。请在手机刚换码时核对。", SS_LEFT, 0, 24, 445, 450, 50);
        Add(L"BUTTON", L"删除绑定", WS_TABSTOP | BS_PUSHBUTTON, ID_REMOVE, 24, 512, 112, 34);
        Add(L"BUTTON", L"保存绑定", WS_TABSTOP | BS_DEFPUSHBUTTON, IDOK, 246, 512, 110, 34);
        Add(L"BUTTON", L"取消", WS_TABSTOP | BS_PUSHBUTTON, IDCANCEL, 366, 512, 108, 34);
        auto metadata = TotpRepository().Metadata(id_, username_);
        if (metadata.bound) {
            SendMessageW(algorithm_, CB_SETCURSEL, static_cast<int>(metadata.algorithm), 0);
            SetWindowTextW(period_, std::to_wstring(metadata.periodSeconds).c_str());
            SetWindowTextW(
                description_,
                L"已绑定：密钥留空可沿用，并保存所选算法和周期。\n导入新资料并保存将替换现有绑定。");
        }
    }
    void ImportQr() {
        auto path = SelectImage(window_);
        if (!path) {
            return;
        }
        auto config = ImportTotpQrImage(*path);
        auto secret = Wide(config.secretBase32);
        SetWindowTextW(secret_, secret.c_str());
        Wipe(secret);
        SendMessageW(algorithm_, CB_SETCURSEL, static_cast<int>(config.algorithm), 0);
        SetWindowTextW(period_, std::to_wstring(config.periodSeconds).c_str());
        SetWindowTextW(description_,
                       L"已识别标准 TOTP 绑定。点击“保存绑定”后启用。\n原二维码图片不会复制或上传。");
    }
    TotpConfig ReadConfiguration() {
        auto text = Text(secret_);
        struct Guard {
            std::wstring& s;
            ~Guard() {
                Wipe(s);
            }
        } guard{text};
        auto periodText = Text(period_);
        if (periodText.empty() || periodText.find_first_not_of(L"0123456789") != periodText.npos) {
            throw std::runtime_error("验证码周期必须是整数");
        }
        auto period = std::stoi(periodText);
        auto algorithm = static_cast<TotpAlgorithm>(SendMessageW(algorithm_, CB_GETCURSEL, 0, 0));
        if (text.empty()) {
            return WithTotpParameters(TotpRepository().Load(id_, username_), algorithm, period);
        } else {
            auto raw = Utf8(text);
            struct Guard8 {
                std::string& s;
                ~Guard8() {
                    Wipe(s);
                }
            } guard8{raw};
            auto config = ParseTotpInput(raw, algorithm, period);
            ValidateTotp(config, true);
            return config;
        }
    }
    void Save() {
        auto config = ReadConfiguration();
        TotpRepository().Bind(id_, username_, config);
        changed_ = true;
        Close();
    }
    void Verify() {
        auto text = Text(phoneCode_);
        SetWindowTextW(phoneCode_, L"");
        auto code = Utf8(text);
        Wipe(text);
        struct Guard {
            std::string& value;
            ~Guard() {
                Wipe(value);
            }
        } guard{code};
        auto config = ReadConfiguration();
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
        auto result = detector_.Observe(config, code, now);
        const auto& matches = result.candidates;
        std::wstring message;
        if (result.state == DetectionState::NoMatch) {
            message = L"常见算法/周期及前后一个周期均未匹配。\n请核对原始密钥、手机时间及所选账号。";
        } else if (result.state == DetectionState::SameWindow) {
            message = L"仍是同一轮手机验证码，请等手机下一次换码后输入新码。";
        } else if (result.state == DetectionState::Ambiguous || matches.size() > 1) {
            message = L"有多个候选匹配，请等手机下一次换码后再核对。";
        } else {
            const auto& match = matches.front();
            message = (result.state == DetectionState::Confirmed ? L"两轮匹配：" : L"第一轮候选：") +
                      Wide(AlgorithmName(match.algorithm)) + L" / " + std::to_wstring(match.periodSeconds) +
                      L" 秒";
            if (match.windowOffset) {
                message += L"（相邻时间窗口，可能正处于换码边界）";
            }
            if (result.state == DetectionState::Confirmed) {
                SendMessageW(algorithm_, CB_SETCURSEL, static_cast<int>(match.algorithm), 0);
                SetWindowTextW(period_, std::to_wstring(match.periodSeconds).c_str());
                auto seed = Wide(config.secretBase32);
                SetWindowTextW(secret_, seed.c_str());
                Wipe(seed);
                message += L"。\n已填入候选参数，请点击“保存绑定”生效。";
            } else {
                message += L"。\n请等手机下一次换码，再输入新码核对。";
            }
        }
        SetWindowTextW(verification_, message.c_str());
    }
    void Close() {
        SetWindowTextW(secret_, L"");
        SetWindowTextW(phoneCode_, L"");
        done_ = true;
        DestroyWindow(window_);
    }
    void ChangeDpi(UINT dpi, const RECT& bounds) {
        ScopedUiRedraw redraw(window_);
        auto nextFont = CreateFontW(-MulDiv(10, static_cast<int>(dpi), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE,
                                    FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        if (!nextFont) {
            throw std::runtime_error("Cannot resize setup font");
        }
        auto previousFont = font_;
        font_ = nextFont;
        dpi_ = dpi;
        SetWindowPos(window_, nullptr, bounds.left, bounds.top, bounds.right - bounds.left,
                     bounds.bottom - bounds.top, SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS);
        for (const auto& p : placements_) {
            MoveWindow(p.control, S(p.x), S(p.y), S(p.width), S(p.height), FALSE);
            SendMessageW(p.control, WM_SETFONT, reinterpret_cast<WPARAM>(font_), FALSE);
        }
        if (previousFont) {
            DeleteObject(previousFont);
        }
    }
    static LRESULT CALLBACK Procedure(HWND window, UINT message, WPARAM wp, LPARAM lp) {
        auto self = reinterpret_cast<SetupDialog*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<SetupDialog*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            self->window_ = window;
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) {
            return DefWindowProcW(window, message, wp, lp);
        }
        try {
            if (message == WM_CREATE) {
                self->Initialize();
                return 0;
            }
            if (message == WM_CLOSE) {
                self->Close();
                return 0;
            }
            if (message == WM_DPICHANGED) {
                self->ChangeDpi(HIWORD(wp), *reinterpret_cast<RECT*>(lp));
                return 0;
            }
            if (message == WM_COMMAND) {
                if (LOWORD(wp) == ID_QR && HIWORD(wp) == BN_CLICKED) {
                    self->ImportQr();
                } else if (LOWORD(wp) == ID_VERIFY && HIWORD(wp) == BN_CLICKED) {
                    self->Verify();
                } else if (LOWORD(wp) == IDOK) {
                    self->Save();
                } else if (LOWORD(wp) == IDCANCEL) {
                    self->Close();
                } else if (LOWORD(wp) == ID_REMOVE && HIWORD(wp) == BN_CLICKED) {
                    if (MessageBoxW(
                            window,
                            L"删除此 VPN 配置下当前用户名的验证码绑定？\n微软验证器上的账号不受影响。",
                            L"删除本机绑定", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                        TotpRepository().Remove(self->id_, self->username_);
                        self->changed_ = true;
                        self->Close();
                    }
                }
                return 0;
            }
        } catch (const std::exception& e) {
            MessageBoxW(window, Wide(e.what()).c_str(), L"验证码设置", MB_OK | MB_ICONERROR);
            return 0;
        }
        return DefWindowProcW(window, message, wp, lp);
    }
};
} // namespace
bool ShowOtpSetupDialog(HWND owner, std::wstring profileId, std::wstring username) {
    return SetupDialog(owner, std::move(profileId), std::move(username)).Show();
}
} // namespace ownvpn
