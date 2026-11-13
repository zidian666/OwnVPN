# Pinned, unmodified upstream archives. Sources stay in the ignored build tree.
set(ANDROID_DEPS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../build/android-deps")
set(ANDROID_DOWNLOADS "${CMAKE_CURRENT_LIST_DIR}/../build/android-downloads")
function(android_dependency name directory url sha)
  set(archive "${ANDROID_DOWNLOADS}/${name}.tar.gz")
  file(MAKE_DIRECTORY "${ANDROID_DOWNLOADS}" "${ANDROID_DEPS_ROOT}")
  if(NOT EXISTS "${archive}")
    file(DOWNLOAD "${url}" "${archive}" EXPECTED_HASH "SHA256=${sha}" TLS_VERIFY ON)
  endif()
  file(SHA256 "${archive}" actual)
  if(NOT actual STREQUAL sha)
    message(FATAL_ERROR "Android dependency checksum mismatch: ${name}")
  endif()
  if(NOT EXISTS "${ANDROID_DEPS_ROOT}/${directory}/.ownvpn-extracted")
    file(ARCHIVE_EXTRACT INPUT "${archive}" DESTINATION "${ANDROID_DEPS_ROOT}")
    file(WRITE "${ANDROID_DEPS_ROOT}/${directory}/.ownvpn-extracted" "${sha}")
  endif()
  set(${name}_SOURCE "${ANDROID_DEPS_ROOT}/${directory}" PARENT_SCOPE)
endfunction()
android_dependency(openvpn3 openvpn3-4f3bdef73245d4ee9e8216c5d65baccc9568f6ef
  https://codeload.github.com/OpenVPN/openvpn3/tar.gz/4f3bdef73245d4ee9e8216c5d65baccc9568f6ef
  522faf3f7485117423a9c398606062105c4453c11d4d5ebab45e7c209cc3a9ef)
android_dependency(mbedtls mbedtls-3.6.7 https://codeload.github.com/Mbed-TLS/mbedtls/tar.gz/refs/tags/v3.6.7
  7312b70b067b6a271961c8d36c3b8f9ba3e86fe6b26f18af13cd70430ee52ed1)
android_dependency(mbedtls_framework mbedtls-framework-dde0c4a0e448a0552f18817dcea633bb851fd288
  https://codeload.github.com/Mbed-TLS/mbedtls-framework/tar.gz/dde0c4a0e448a0552f18817dcea633bb851fd288
  3b0d4864fa877dc9165b90ff3d5b68505c6176c0b22d317d99fe8c89a993e9fd)
if(NOT EXISTS "${mbedtls_SOURCE}/framework/CMakeLists.txt")
  file(COPY "${mbedtls_framework_SOURCE}/" DESTINATION "${mbedtls_SOURCE}/framework")
endif()
android_dependency(asio asio-asio-1-39-0 https://codeload.github.com/chriskohlhoff/asio/tar.gz/refs/tags/asio-1-39-0
  cc27087fad4b6d85c6b8e4c896c57144b417cfc5a5eab9e204565f51adaec1de)
android_dependency(fmt fmt-12.2.1 https://codeload.github.com/fmtlib/fmt/tar.gz/refs/tags/12.2.1
  449374d74f31b67796dece454d59b93e6f1538efcce0e9ac78000c98142c139e)
android_dependency(lz4 lz4-1.11.1 https://codeload.github.com/lz4/lz4/tar.gz/refs/tags/v1.11.1
  683fed08a844ad012196381e40badf80c0bbe4962959761416d41c9e67d77ec7)
android_dependency(xxhash xxHash-0.8.4 https://codeload.github.com/Cyan4973/xxHash/tar.gz/refs/tags/v0.8.4
  5738270935e7c3d38a79b3adf7c9692566ce7895a25f67de43ad52ab504acd32)
include("${CMAKE_CURRENT_LIST_DIR}/OpenVPNMbedTLSCompatibility.cmake")
