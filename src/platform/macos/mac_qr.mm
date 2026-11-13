#include "mac_platform.h"
#include "totp.h"
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <Vision/Vision.h>

namespace ownvpn::mac {
std::string DecodeQr(const fs::path& image) {
    @autoreleasepool {
        if (!fs::is_regular_file(image) || fs::file_size(image) > 16 * 1024 * 1024) {
            throw std::runtime_error("二维码图片无效或超过 16 MB");
        }
        auto url = [NSURL fileURLWithFileSystemRepresentation:image.c_str() isDirectory:NO relativeToURL:nil];
        CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)url, nullptr);
        if (!source) {
            throw std::runtime_error("无法读取二维码图片");
        }
        NSDictionary* properties = CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(source, 0, nullptr));
        CFRelease(source);
        auto width = [properties[(__bridge id)kCGImagePropertyPixelWidth] unsignedLongLongValue];
        auto height = [properties[(__bridge id)kCGImagePropertyPixelHeight] unsignedLongLongValue];
        if (!width || !height || width > 8192 || height > 8192) {
            throw std::runtime_error("二维码图片尺寸无效");
        }
        auto request = [VNDetectBarcodesRequest new];
        request.symbologies = @[ VNBarcodeSymbologyQR ];
        auto handler = [[VNImageRequestHandler alloc] initWithURL:url options:@{}];
        NSError* error = nil;
        if (![handler performRequests:@[ request ] error:&error] || request.results.count != 1) {
            throw std::runtime_error("请使用仅包含一个认证二维码的图片");
        }
        NSString* payload = ((VNBarcodeObservation*)request.results.firstObject).payloadStringValue;
        if (!payload) {
            throw std::runtime_error("二维码内容为空");
        }
        std::string text = payload.UTF8String;
        try {
            ValidateTotp(ParseTotpUri(text), true);
        } catch (...) {
            Wipe(text);
            throw;
        }
        return text;
    }
}
} // namespace ownvpn::mac
