#include "credential_store.h"
#include "mac_import.h"
#include "mac_platform.h"
#include "settings.h"
#include "totp_store.h"
#import <AppKit/AppKit.h>
#include <chrono>
#include <sys/stat.h>

using namespace ownvpn;
namespace {
NSString* Text(std::string_view text) {
    return [[NSString alloc] initWithBytes:text.data() length:text.size() encoding:NSUTF8StringEncoding]
               ?: @"";
}
NSString* Text(std::wstring_view text) {
    return Text(Utf8(text));
}
std::wstring WideText(NSString* text) {
    return Wide(text.UTF8String ?: "");
}
fs::path Path(NSURL* url) {
    return url ? PathFromUtf8(url.fileSystemRepresentation) : fs::path{};
}
NSButton* Button(NSString* title, id target, SEL action) {
    return [NSButton buttonWithTitle:title target:target action:action];
}
NSButton* Check(NSString* title, id target, SEL action) {
    return [NSButton checkboxWithTitle:title target:target action:action];
}
NSStackView* Row(NSArray<NSView*>* views) {
    auto row = [NSStackView stackViewWithViews:views];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.spacing = 10;
    row.alignment = NSLayoutAttributeCenterY;
    return row;
}
int64_t Now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace

@interface OwnVPNDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate, NSTextFieldDelegate> {
    NSWindow* _window;
    NSPopUpButton* _profile;
    NSTextField *_username, *_plainPassword, *_otp, *_remaining, *_notice;
    NSSecureTextField* _password;
    NSButton *_remember, *_showPassword, *_automatic, *_importButton;
    NSOperationQueue* _work;
    NSTimer* _timer;
    NSStatusItem* _tray;
    std::vector<Profile> _profiles;
    std::shared_ptr<TotpConfig> _binding;
    std::shared_ptr<mac::ImportSession> _importing;
    ProfileDependencyFiles _dependencyFiles;
    fs::path _pem;
    size_t _importIndex;
    uint64_t _accountGeneration;
}
@end

@implementation OwnVPNDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    (void)notification;
    _work = [NSOperationQueue new];
    _work.maxConcurrentOperationCount = 1;
    _window =
        [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 530, 660)
                                    styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                              NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                                      backing:NSBackingStoreBuffered
                                        defer:NO];
    _window.title = @"OwnVPN";
    _window.delegate = self;
    _window.contentMinSize = NSMakeSize(500, 620);
    auto root = [NSStackView new];
    root.orientation = NSUserInterfaceLayoutOrientationVertical;
    root.alignment = NSLayoutAttributeLeading;
    root.spacing = 13;
    root.translatesAutoresizingMaskIntoConstraints = NO;
    [_window.contentView addSubview:root];
    [NSLayoutConstraint activateConstraints:@[
        [root.leadingAnchor constraintEqualToAnchor:_window.contentView.leadingAnchor constant:28],
        [root.trailingAnchor constraintEqualToAnchor:_window.contentView.trailingAnchor constant:-28],
        [root.topAnchor constraintEqualToAnchor:_window.contentView.topAnchor constant:24],
        [root.bottomAnchor constraintLessThanOrEqualToAnchor:_window.contentView.bottomAnchor constant:-20]
    ]];
    auto mark = [NSTextField labelWithString:@"O"];
    mark.font = [NSFont systemFontOfSize:32 weight:NSFontWeightMedium];
    mark.textColor = NSColor.secondaryLabelColor;
    auto status = [NSTextField labelWithString:@"未连接"];
    status.font = [NSFont systemFontOfSize:23 weight:NSFontWeightMedium];
    [root addArrangedSubview:Row(@[ mark, status ])];
    _profile = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
    _profile.target = self;
    _profile.action = @selector(profileChanged:);
    [_profile.widthAnchor constraintGreaterThanOrEqualToConstant:265].active = YES;
    _importButton = Button(@"导入配置", self, @selector(importConfiguration:));
    [root addArrangedSubview:Row(@[ _profile, _importButton ])];
    [root addArrangedSubview:[NSTextField labelWithString:@"账号"]];
    _username = [NSTextField new];
    _username.placeholderString = @"VPN 账号";
    _username.delegate = self;
    [root addArrangedSubview:_username];
    [_username.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;
    [root addArrangedSubview:[NSTextField labelWithString:@"密码"]];
    _password = [NSSecureTextField new];
    _plainPassword = [NSTextField new];
    _plainPassword.hidden = YES;
    auto passwordStack = [NSStackView stackViewWithViews:@[ _password, _plainPassword ]];
    passwordStack.orientation = NSUserInterfaceLayoutOrientationVertical;
    passwordStack.detachesHiddenViews = YES;
    passwordStack.alignment = NSLayoutAttributeLeading;
    [root addArrangedSubview:passwordStack];
    [passwordStack.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;
    [_password.widthAnchor constraintEqualToAnchor:passwordStack.widthAnchor].active = YES;
    [_plainPassword.widthAnchor constraintEqualToAnchor:passwordStack.widthAnchor].active = YES;
    _remember = Check(@"记住密码", nil, nil);
    _showPassword = Check(@"显示密码", self, @selector(showPassword:));
    auto copyPassword = Button(@"复制密码", self, @selector(copyPassword:));
    [root addArrangedSubview:Row(@[ _remember, _showPassword, copyPassword ])];
    [root addArrangedSubview:[NSTextField labelWithString:@"动态验证码"]];
    _otp = [NSTextField new];
    _otp.placeholderString = @"6 位验证码";
    [_otp.widthAnchor constraintEqualToConstant:150].active = YES;
    _remaining = [NSTextField labelWithString:@""];
    [root addArrangedSubview:Row(@[ _otp, Button(@"复制", self, @selector(copyOtp:)), _remaining ])];
    _automatic = Check(@"", self, @selector(automaticChanged:));
    auto bind = Button(@"自动生成", self, @selector(binding:));
    bind.toolTip = @"点击导入认证二维码或绑定密钥";
    auto instant = Button(@"复制即时密码", self, @selector(copyInstant:));
    instant.bezelStyle = NSBezelStyleInline;
    instant.toolTip = @"复制密码和当前六位验证码的拼接结果";
    [root addArrangedSubview:Row(@[ _automatic, bind, instant ])];
    auto save = Button(@"保存登录资料", self, @selector(saveAccount:));
    [root addArrangedSubview:save];
    auto connect = Button(@"连接 VPN", nil, nil);
    connect.enabled = NO;
    [root addArrangedSubview:connect];
    _notice =
        [NSTextField wrappingLabelWithString:@"Mac 开发版：配置导入与验证码可用，VPN 连接服务尚未接入。"];
    _notice.textColor = NSColor.secondaryLabelColor;
    [root addArrangedSubview:_notice];
    [_notice.widthAnchor constraintEqualToAnchor:root.widthAnchor].active = YES;
    auto version = [NSTextField labelWithString:Text(std::string("Mac ") + mac::Version)];
    version.font = [NSFont systemFontOfSize:11];
    version.textColor = NSColor.tertiaryLabelColor;
    [root addArrangedSubview:version];
    auto menu = [NSMenu new];
    auto appItem = [NSMenuItem new];
    [menu addItem:appItem];
    auto appMenu = [NSMenu new];
    [appMenu addItemWithTitle:@"显示 OwnVPN" action:@selector(showWindow:) keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"退出 OwnVPN" action:@selector(terminate:) keyEquivalent:@"q"];
    appItem.submenu = appMenu;
    NSApp.mainMenu = menu;
    _tray = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
    _tray.button.title = @"O";
    _tray.menu = [appMenu copy];
    _timer = [NSTimer scheduledTimerWithTimeInterval:0.1
                                              target:self
                                            selector:@selector(tick:)
                                            userInfo:nil
                                             repeats:YES];
    [_window center];
    [_window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [self reloadProfiles];
}
- (void)showWindow:(id)sender {
    (void)sender;
    [_window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}
- (BOOL)windowShouldClose:(NSWindow*)window {
    [window orderOut:nil];
    return NO;
}
- (void)message:(NSString*)message {
    _notice.stringValue = message ?: @"操作失败";
}
- (std::optional<Profile>)selected {
    auto index = _profile.indexOfSelectedItem;
    if (index < 0 || static_cast<size_t>(index) >= _profiles.size()) {
        return {};
    }
    return _profiles[static_cast<size_t>(index)];
}
- (NSString*)passwordValue {
    return _showPassword.state == NSControlStateValueOn ? _plainPassword.stringValue : _password.stringValue;
}
- (void)showPassword:(id)sender {
    (void)sender;
    BOOL show = _showPassword.state == NSControlStateValueOn;
    if (show) {
        _plainPassword.stringValue = _password.stringValue;
    } else {
        _password.stringValue = _plainPassword.stringValue;
    }
    _plainPassword.hidden = !show;
    _password.hidden = show;
}
- (void)reloadProfiles {
    [_work addOperationWithBlock:^{
      try {
          auto profiles = ProfileRepository().List();
          auto settings = Settings::Load();
          dispatch_async(dispatch_get_main_queue(), ^{
            _profiles = profiles;
            [_profile removeAllItems];
            for (const auto& profile : _profiles) {
                [_profile addItemWithTitle:Text(profile.name)];
            }
            for (size_t i = 0; i < _profiles.size(); ++i) {
                if (_profiles[i].id == settings.profileId) {
                    [_profile selectItemAtIndex:static_cast<NSInteger>(i)];
                }
            }
            if (_profiles.empty()) {
                [_profile addItemWithTitle:@"请先导入配置"];
            }
            [self profileChanged:nil];
          });
      } catch (const std::exception& error) {
          auto text = Text(error.what());
          dispatch_async(dispatch_get_main_queue(), ^{
            [self message:text];
          });
      }
    }];
}
- (void)profileChanged:(id)sender {
    (void)sender;
    _binding.reset();
    _otp.stringValue = @"";
    _password.stringValue = @"";
    _plainPassword.stringValue = @"";
    auto profile = [self selected];
    auto generation = ++_accountGeneration;
    if (!profile) {
        return;
    }
    [_work addOperationWithBlock:^{
      try {
          auto account = LoadCredentials(profile->id);
          Settings{profile->id}.Save();
          auto user = Text(account.username), pass = Text(account.password);
          auto remember = account.rememberPassword;
          account.ClearSecrets();
          dispatch_async(dispatch_get_main_queue(), ^{
            if (generation != _accountGeneration) {
                return;
            }
            _username.stringValue = user;
            _password.stringValue = pass;
            _plainPassword.stringValue = pass;
            _remember.state = remember ? NSControlStateValueOn : NSControlStateValueOff;
            [self loadBinding];
          });
      } catch (const std::exception& error) {
          auto text = Text(error.what());
          dispatch_async(dispatch_get_main_queue(), ^{
            if (generation == _accountGeneration) {
                [self message:text];
            }
          });
      }
    }];
}
- (void)controlTextDidChange:(NSNotification*)notification {
    if (notification.object == _username) {
        ++_accountGeneration;
        _binding.reset();
        [self loadBinding];
    }
}
- (void)loadBinding {
    auto profile = [self selected];
    auto user = WideText(_username.stringValue);
    auto generation = _accountGeneration;
    if (!profile || user.empty()) {
        return;
    }
    [_work addOperationWithBlock:^{
      try {
          TotpRepository repository;
          auto metadata = repository.Metadata(profile->id, user);
          std::shared_ptr<TotpConfig> binding;
          if (metadata.bound) {
              binding = std::make_shared<TotpConfig>(repository.Load(profile->id, user));
          }
          dispatch_async(dispatch_get_main_queue(), ^{
            if (generation != _accountGeneration) {
                return;
            }
            _binding = binding;
            _automatic.state = metadata.automatic ? NSControlStateValueOn : NSControlStateValueOff;
            [self automaticChanged:nil];
          });
      } catch (const std::exception& error) {
          auto text = Text(error.what());
          dispatch_async(dispatch_get_main_queue(), ^{
            if (generation == _accountGeneration) {
                [self message:text];
            }
          });
      }
    }];
}
- (void)automaticChanged:(id)sender {
    BOOL enabled = _automatic.state == NSControlStateValueOn;
    _otp.editable = !enabled;
    _otp.selectable = YES;
    if (enabled && !_binding) {
        _otp.stringValue = @"";
        _remaining.stringValue = @"请导入绑定资料";
    } else if (!enabled) {
        _remaining.stringValue = @"";
    }
    if (sender) {
        auto profile = [self selected];
        auto user = WideText(_username.stringValue);
        if (profile && !user.empty()) {
            [_work addOperationWithBlock:^{
              try {
                  TotpRepository().SetAutomatic(profile->id, user, enabled);
              } catch (const std::exception& error) {
                  auto text = Text(error.what());
                  dispatch_async(dispatch_get_main_queue(), ^{
                    [self message:text];
                  });
              }
            }];
        }
    }
    [self tick:nil];
}
- (void)tick:(id)sender {
    (void)sender;
    if (_automatic.state != NSControlStateValueOn || !_binding) {
        return;
    }
    try {
        auto now = Now();
        auto code = GenerateTotp(*_binding, now);
        auto value = Text(code);
        Wipe(code);
        if (![_otp.stringValue isEqualToString:value]) {
            _otp.stringValue = value;
        }
        auto remaining = [NSString
            stringWithFormat:@"%lld 秒后更新",
                             static_cast<long long>(_binding->periodSeconds - now % _binding->periodSeconds)];
        if (![_remaining.stringValue isEqualToString:remaining]) {
            _remaining.stringValue = remaining;
        }
    } catch (const std::exception& error) {
        [self message:Text(error.what())];
    }
}
- (void)copyValue:(NSString*)value {
    if (!value.length) {
        [self message:@"没有可复制的内容"];
        return;
    }
    auto pasteboard = NSPasteboard.generalPasteboard;
    [pasteboard clearContents];
    [pasteboard setString:value forType:NSPasteboardTypeString];
    [pasteboard setData:[NSData data] forType:@"org.nspasteboard.ConcealedType"];
}
- (void)copyPassword:(id)sender {
    (void)sender;
    [self copyValue:[self passwordValue]];
}
- (BOOL)validOtp {
    auto value = _otp.stringValue;
    return value.length == 6 &&
           [value rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:@"0123456789"]
                                              invertedSet]]
                   .location == NSNotFound;
}
- (void)copyOtp:(id)sender {
    (void)sender;
    [self tick:nil];
    if ([self validOtp]) {
        [self copyValue:_otp.stringValue];
    } else {
        [self message:@"请输入或生成六位验证码"];
    }
}
- (void)copyInstant:(id)sender {
    (void)sender;
    [self tick:nil];
    if (![self validOtp] || ![self passwordValue].length) {
        [self message:@"请先填写密码和六位验证码"];
        return;
    }
    [self copyValue:[[self passwordValue] stringByAppendingString:_otp.stringValue]];
}
- (void)saveAccount:(id)sender {
    (void)sender;
    auto profile = [self selected];
    if (!profile) {
        [self message:@"请先导入配置"];
        return;
    }
    auto account = std::make_shared<Credentials>();
    account->username = WideText(_username.stringValue);
    account->password = WideText([self passwordValue]);
    account->rememberPassword = _remember.state == NSControlStateValueOn;
    [_work addOperationWithBlock:^{
      try {
          SaveCredentials(profile->id, *account);
          account->ClearSecrets();
          dispatch_async(dispatch_get_main_queue(), ^{
            [self message:@"登录资料已保存"];
          });
      } catch (const std::exception& error) {
          account->ClearSecrets();
          auto text = Text(error.what());
          dispatch_async(dispatch_get_main_queue(), ^{
            [self message:text];
          });
      }
    }];
}
- (void)binding:(id)sender {
    (void)sender;
    auto profile = [self selected];
    auto user = WideText(_username.stringValue);
    if (!profile || user.empty()) {
        [self message:@"请先导入配置并填写账号"];
        return;
    }
    auto alert = [NSAlert new];
    alert.messageText = @"绑定验证码";
    [alert addButtonWithTitle:@"导入二维码"];
    [alert addButtonWithTitle:@"输入密钥"];
    [alert addButtonWithTitle:@"取消"];
    [alert beginSheetModalForWindow:_window
                  completionHandler:^(NSModalResponse response) {
                    if (response == NSAlertFirstButtonReturn) {
                        auto panel = [NSOpenPanel openPanel];
                        panel.canChooseDirectories = NO;
                        panel.allowsMultipleSelection = NO;
                        panel.message = @"选择原始认证二维码图片";
                        [panel beginSheetModalForWindow:_window
                                      completionHandler:^(NSModalResponse result) {
                                        if (result != NSModalResponseOK) {
                                            return;
                                        }
                                        auto path = Path(panel.URL);
                                        [_work addOperationWithBlock:^{
                                          try {
                                              auto text = mac::DecodeQr(path);
                                              auto config = ParseTotpUri(text);
                                              Wipe(text);
                                              ValidateTotp(config, true);
                                              TotpRepository().Bind(profile->id, user, config);
                                              dispatch_async(dispatch_get_main_queue(), ^{
                                                [self loadBinding];
                                                [self message:@"验证码已绑定"];
                                              });
                                          } catch (const std::exception& error) {
                                              auto text = Text(error.what());
                                              dispatch_async(dispatch_get_main_queue(), ^{
                                                [self message:text];
                                              });
                                          }
                                        }];
                                      }];
                    } else if (response == NSAlertSecondButtonReturn) {
                        auto input = [NSSecureTextField new];
                        input.frame = NSMakeRect(0, 0, 340, 24);
                        auto dialog = [NSAlert new];
                        dialog.messageText = @"输入绑定密钥或 otpauth URI";
                        dialog.accessoryView = input;
                        [dialog addButtonWithTitle:@"绑定"];
                        [dialog addButtonWithTitle:@"取消"];
                        [dialog beginSheetModalForWindow:_window
                                       completionHandler:^(NSModalResponse result) {
                                         if (result != NSAlertFirstButtonReturn) {
                                             return;
                                         }
                                         auto secret =
                                             std::make_shared<std::string>(input.stringValue.UTF8String);
                                         input.stringValue = @"";
                                         [_work addOperationWithBlock:^{
                                           try {
                                               auto config = ParseTotpInput(*secret, TotpAlgorithm::Sha1, 30);
                                               Wipe(*secret);
                                               ValidateTotp(config, true);
                                               TotpRepository().Bind(profile->id, user, config);
                                               dispatch_async(dispatch_get_main_queue(), ^{
                                                 [self loadBinding];
                                                 [self message:@"验证码已绑定"];
                                               });
                                           } catch (const std::exception& error) {
                                               Wipe(*secret);
                                               auto text = Text(error.what());
                                               dispatch_async(dispatch_get_main_queue(), ^{
                                                 [self message:text];
                                               });
                                           }
                                         }];
                                       }];
                    }
                  }];
}
- (void)importConfiguration:(id)sender {
    (void)sender;
    auto panel = [NSOpenPanel openPanel];
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    panel.message = @"选择原始 ZIP 配置包或 .ovpn 文件";
    [panel beginSheetModalForWindow:_window
                  completionHandler:^(NSModalResponse result) {
                    if (result != NSModalResponseOK) {
                        return;
                    }
                    auto source = Path(panel.URL);
                    _importButton.enabled = NO;
                    [_work addOperationWithBlock:^{
                      try {
                          auto session = std::make_shared<mac::ImportSession>(source);
                          dispatch_async(dispatch_get_main_queue(), ^{
                            _importing = session;
                            _dependencyFiles.clear();
                            _pem.clear();
                            _importIndex = 0;
                            if (session->configurations().size() == 1) {
                                [self choosePem];
                            } else {
                                auto choices = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(0, 0, 340, 28)
                                                                          pullsDown:NO];
                                for (const auto& path : session->configurations()) {
                                    [choices addItemWithTitle:Text(PathText(path.filename()))];
                                }
                                auto alert = [NSAlert new];
                                alert.messageText = @"选择 VPN 配置";
                                alert.accessoryView = choices;
                                [alert addButtonWithTitle:@"继续"];
                                [alert addButtonWithTitle:@"取消"];
                                [alert beginSheetModalForWindow:_window
                                              completionHandler:^(NSModalResponse response) {
                                                if (response == NSAlertFirstButtonReturn) {
                                                    _importIndex =
                                                        static_cast<size_t>(choices.indexOfSelectedItem);
                                                    [self choosePem];
                                                } else {
                                                    [self endImport];
                                                }
                                              }];
                            }
                          });
                      } catch (const std::exception& error) {
                          auto text = Text(error.what());
                          dispatch_async(dispatch_get_main_queue(), ^{
                            [self endImport];
                            [self message:text];
                          });
                      }
                    }];
                  }];
}
- (void)choosePem {
    auto alert = [NSAlert new];
    alert.messageText = @"选择 users.pem";
    alert.informativeText = @"选择客户端证书和私钥。配置包已包含证书时可以跳过。";
    [alert addButtonWithTitle:@"选择文件"];
    [alert addButtonWithTitle:@"跳过"];
    [alert addButtonWithTitle:@"取消"];
    [alert beginSheetModalForWindow:_window
                  completionHandler:^(NSModalResponse response) {
                    if (response == NSAlertSecondButtonReturn) {
                        [self finishImport];
                        return;
                    }
                    if (response != NSAlertFirstButtonReturn) {
                        [self endImport];
                        return;
                    }
                    auto panel = [NSOpenPanel openPanel];
                    panel.canChooseDirectories = NO;
                    panel.allowsMultipleSelection = NO;
                    [panel beginSheetModalForWindow:_window
                                  completionHandler:^(NSModalResponse result) {
                                    if (result != NSModalResponseOK) {
                                        [self endImport];
                                        return;
                                    }
                                    _pem = Path(panel.URL);
                                    [self finishImport];
                                  }];
                  }];
}
- (void)endImport {
    _importing.reset();
    _dependencyFiles.clear();
    _pem.clear();
    _importButton.enabled = YES;
}
- (void)finishImport {
    auto session = _importing;
    auto index = _importIndex;
    auto pem = _pem;
    auto files = _dependencyFiles;
    [_work addOperationWithBlock:^{
      try {
          auto profile = session->Import(index, pem, files);
          Settings{profile.id}.Save();
          dispatch_async(dispatch_get_main_queue(), ^{
            [self endImport];
            [self reloadProfiles];
            [self message:@"配置已导入"];
          });
      } catch (const MissingProfileDependency& error) {
          auto option = error.option();
          auto reference = Text(error.reference());
          dispatch_async(dispatch_get_main_queue(), ^{
            auto panel = [NSOpenPanel openPanel];
            panel.canChooseDirectories = NO;
            panel.allowsMultipleSelection = NO;
            panel.message = [NSString stringWithFormat:@"补齐依赖文件 %@（%@）", reference, Text(option)];
            [panel beginSheetModalForWindow:_window
                          completionHandler:^(NSModalResponse result) {
                            if (result != NSModalResponseOK) {
                                [self endImport];
                                return;
                            }
                            _dependencyFiles[option] = Path(panel.URL);
                            [self finishImport];
                          }];
          });
      } catch (const std::exception& error) {
          auto text = Text(error.what());
          dispatch_async(dispatch_get_main_queue(), ^{
            [self endImport];
            [self message:text];
          });
      }
    }];
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)sender {
    (void)sender;
    if (_work.operationCount) {
        [self message:@"正在保存，请稍后退出"];
        return NSTerminateCancel;
    }
    [_timer invalidate];
    _binding.reset();
    [self endImport];
    return NSTerminateNow;
}
@end

int main() {
    umask(0077);
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        __attribute__((objc_precise_lifetime)) OwnVPNDelegate* delegate = [OwnVPNDelegate new];
        NSApp.delegate = delegate;
        [NSApp run];
    }
    return 0;
}
