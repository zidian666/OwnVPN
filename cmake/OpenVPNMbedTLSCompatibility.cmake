# Backport the hostname initialization from official OpenVPN commit
# ee481a02cb6ab946ec388efac7ca13d39305ff7b to the pinned 3.11.8 source.
# OpenVPN's private-PKI CA, EKU and verify-x509-name checks remain unchanged.
# This does NOT enable Mbed TLS's global weak-verification compatibility flag.
set(ssl_header "${openvpn3_SOURCE}/openvpn/mbedtls/ssl/sslctx.hpp")
file(READ "${ssl_header}" ssl_source)
set(old [=[                if (hostname && ((c.flags & SSLConst::ENABLE_CLIENT_SNI) || c.ca_chain))
                {
                    if (mbedtls_ssl_set_hostname(ssl, hostname))
                        throw MbedTLSException("mbedtls_ssl_set_hostname failed");
                }]=])
set(new [=[                // Upstream ee481a02: explicit initialization for non-DNS OpenVPN PKI.
                bool use_hostname = hostname && ((c.flags & SSLConst::ENABLE_CLIENT_SNI) || c.ca_chain);
                if (mbedtls_ssl_set_hostname(ssl, use_hostname ? hostname : nullptr))
                    throw MbedTLSException("mbedtls_ssl_set_hostname failed");]=])
string(FIND "${ssl_source}" "${old}" before)
if(NOT before EQUAL -1)
  string(REPLACE "${old}" "${new}" ssl_source "${ssl_source}")
  file(WRITE "${ssl_header}" "${ssl_source}")
else()
  string(FIND "${ssl_source}" "${new}" after)
  if(after EQUAL -1)
    message(FATAL_ERROR "Pinned OpenVPN Mbed TLS compatibility patch did not match")
  endif()
endif()
