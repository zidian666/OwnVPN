#include "platform.h"
namespace ownvpn {
ICryptoProvider& WindowsCryptoServices();
ISecretStore& WindowsSecretServices();
IPlatformPaths& WindowsPathServices();
INetworkServices& WindowsNetworkServices();
const PlatformServices& Platform() {
    static const PlatformServices services{WindowsCryptoServices(), WindowsSecretServices(),
                                           WindowsPathServices(), WindowsNetworkServices()};
    return services;
}
} // namespace ownvpn
