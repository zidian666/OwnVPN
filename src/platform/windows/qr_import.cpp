#include "qr_import.h"
#include "windows_platform.h"
#include <ReadBarcode.h>
#include <wincodec.h>

namespace ownvpn {
namespace {
template <class T> class ComPtr {
  public:
    ~ComPtr() {
        if (value_) {
            value_->Release();
        }
    }
    T* operator->() const {
        return value_;
    }
    T* get() const {
        return value_;
    }
    T** out() {
        return &value_;
    }

  private:
    T* value_ = nullptr;
};
void Check(HRESULT result) {
    if (FAILED(result)) {
        throw std::runtime_error("无法读取二维码图片，请使用清晰的 PNG、JPEG 或 BMP 图片");
    }
}
} // namespace
TotpConfig ImportTotpQrImage(const fs::path& imagePath) {
    if (!fs::is_regular_file(imagePath) || fs::file_size(imagePath) > 16 * 1024 * 1024) {
        throw std::runtime_error("二维码图片不存在或超过 16 MiB");
    }
    ComPtr<IWICImagingFactory> factory;
    Check(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_IWICImagingFactory,
                           reinterpret_cast<void**>(factory.out())));
    ComPtr<IWICBitmapDecoder> decoder;
    Check(factory->CreateDecoderFromFilename(imagePath.c_str(), nullptr, GENERIC_READ,
                                             WICDecodeMetadataCacheOnDemand, decoder.out()));
    ComPtr<IWICBitmapFrameDecode> frame;
    Check(decoder->GetFrame(0, frame.out()));
    UINT width = 0, height = 0;
    Check(frame->GetSize(&width, &height));
    if (!width || !height || width > 8192 || height > 8192 ||
        static_cast<uint64_t>(width) * height > 16000000) {
        throw std::runtime_error("二维码图片尺寸过大或无效");
    }
    ComPtr<IWICFormatConverter> converter;
    Check(factory->CreateFormatConverter(converter.out()));
    Check(converter->Initialize(frame.get(), GUID_WICPixelFormat8bppGray, WICBitmapDitherTypeNone, nullptr, 0,
                                WICBitmapPaletteTypeCustom));
    std::vector<unsigned char> pixels(static_cast<size_t>(width) * height);
    struct PixelGuard {
        std::vector<unsigned char>& p;
        ~PixelGuard() {
            if (!p.empty()) {
                SecureZeroMemory(p.data(), p.size());
            }
        }
    } guard{pixels};
    Check(converter->CopyPixels(nullptr, width, static_cast<UINT>(pixels.size()), pixels.data()));
    auto view = ZXing::ImageView(pixels.data(), static_cast<int>(width), static_cast<int>(height),
                                 ZXing::ImageFormat::Lum);
    auto options = ZXing::ReaderOptions()
                       .formats(ZXing::BarcodeFormat::QRCode)
                       .tryHarder(true)
                       .tryRotate(true)
                       .tryInvert(true);
    auto barcodes = ZXing::ReadBarcodes(view, options);
    if (barcodes.empty()) {
        throw std::runtime_error("图片中没有识别到二维码，请提供完整、清晰的绑定二维码");
    }
    if (barcodes.size() != 1) {
        throw std::runtime_error("图片中包含多个二维码，请裁剪到需要绑定的单个二维码");
    }
    auto text = barcodes.front().text();
    struct TextGuard {
        std::string& s;
        ~TextGuard() {
            Wipe(s);
        }
    } textGuard{text};
    auto config = ParseTotpUri(text);
    ValidateTotp(config, true);
    return config;
}
} // namespace ownvpn
