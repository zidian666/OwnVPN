#pragma once
#include "totp.h"
namespace ownvpn {
// WIC loads the local image; ZXing recognizes QR codes. This API never opens
// URLs or sends the image/content over the network.
TotpConfig ImportTotpQrImage(const fs::path& imagePath);
} // namespace ownvpn
