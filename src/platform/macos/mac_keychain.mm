#include "mac_platform.h"
#include "protocol.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>

namespace ownvpn::mac {
namespace {
NSString* Text(std::string_view value) {
    auto result = [[NSString alloc] initWithBytes:value.data()
                                           length:value.size()
                                         encoding:NSUTF8StringEncoding];
    if (!result) {
        throw std::runtime_error("Invalid UTF-8 Keychain identifier");
    }
    return result;
}
void Check(OSStatus status) {
    if (status != errSecSuccess) {
        throw std::runtime_error("Keychain operation failed (" + std::to_string(status) + ")");
    }
}
class Keychain final : public ISecretStore {
    std::string service_;
    NSMutableDictionary* Query(std::wstring_view profile, std::wstring_view field) const {
        auto account = Base64(Utf8(profile)) + "/" + Base64(Utf8(field));
        // File-based SecItem storage supports local ad-hoc development builds.
        // No iCloud synchronization or private API, and no plaintext fallback.
        return [@{
            (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService : Text(service_),
            (__bridge id)kSecAttrAccount : Text(account),
            (__bridge id)kSecAttrSynchronizable : @NO
        } mutableCopy];
    }

  public:
    explicit Keychain(std::string service) : service_(std::move(service)) {}
    std::wstring Read(std::wstring_view profile, std::wstring_view field) const override {
        @autoreleasepool {
            auto query = Query(profile, field);
            query[(__bridge id)kSecReturnData] = @YES;
            query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
            CFTypeRef result = nullptr;
            auto status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
            if (status == errSecItemNotFound) {
                return {};
            }
            Check(status);
            NSData* data = CFBridgingRelease(result);
            auto text = std::string(static_cast<const char*>(data.bytes), data.length);
            auto value = Wide(text);
            Wipe(text);
            return value;
        }
    }
    void Write(std::wstring_view profile, std::wstring_view field, std::wstring_view value) override {
        @autoreleasepool {
            auto query = Query(profile, field);
            if (value.empty()) {
                auto status = SecItemDelete((__bridge CFDictionaryRef)query);
                if (status != errSecItemNotFound) {
                    Check(status);
                }
                return;
            }
            auto text = Utf8(value);
            NSData* data = [NSData dataWithBytes:text.data() length:text.size()];
            Wipe(text);
            auto attributes = @{(__bridge id)kSecValueData : data};
            auto status =
                SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
            if (status == errSecItemNotFound) {
                query[(__bridge id)kSecValueData] = data;
                query[(__bridge id)kSecAttrLabel] = @"OwnVPN";
                status = SecItemAdd((__bridge CFDictionaryRef)query, nullptr);
            }
            Check(status);
        }
    }
};
} // namespace
std::unique_ptr<ISecretStore> CreateSecretStore(std::string service) {
    if (!service.starts_with("com.ownvpn.") || service.size() > 200) {
        throw std::runtime_error("Invalid Keychain service");
    }
    return std::make_unique<Keychain>(std::move(service));
}
} // namespace ownvpn::mac
