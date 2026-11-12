# Pinned upstream source; only the core reader and license are extracted.
# Windows tar cannot create the optional wrappers' Unix symlinks without extra
# privileges, so do not extract those wrappers at all.
set(ZXING_VERSION 3.1.1)
set(ZXING_SHA256 7286b1e6ade66fe82b7c8208b4595deeb55d6486b410834fdc65702f46650542)
set(ZXING_ARCHIVE "${CMAKE_BINARY_DIR}/downloads/zxing-cpp-${ZXING_VERSION}.tar.gz")
set(ZXING_SOURCE "${CMAKE_BINARY_DIR}/_deps/zxing-cpp-${ZXING_VERSION}")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/downloads")
if(NOT EXISTS "${ZXING_ARCHIVE}")
  file(DOWNLOAD
    "https://codeload.github.com/zxing-cpp/zxing-cpp/tar.gz/refs/tags/v${ZXING_VERSION}"
    "${ZXING_ARCHIVE}" EXPECTED_HASH "SHA256=${ZXING_SHA256}" TLS_VERIFY ON)
endif()
file(SHA256 "${ZXING_ARCHIVE}" ZXING_ACTUAL_SHA256)
if(NOT ZXING_ACTUAL_SHA256 STREQUAL ZXING_SHA256)
  message(FATAL_ERROR "ZXing source checksum mismatch")
endif()
if(NOT EXISTS "${ZXING_SOURCE}/core/CMakeLists.txt")
  file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/_deps")
  file(ARCHIVE_EXTRACT INPUT "${ZXING_ARCHIVE}" DESTINATION "${CMAKE_BINARY_DIR}/_deps"
    PATTERNS "zxing-cpp-${ZXING_VERSION}/core/*" "zxing-cpp-${ZXING_VERSION}/LICENSE")
endif()
set(BUILD_SHARED_LIBS OFF)
set(ZXING_READERS ON)
set(ZXING_WRITERS OFF)
set(ZXING_C_API OFF)
set(ZXING_DISABLE_PCH ON)
foreach(FORMAT 1D AZTEC DATAMATRIX MAXICODE PDF417)
  set(ZXING_ENABLE_${FORMAT} OFF CACHE BOOL "Only QR codes are needed" FORCE)
endforeach()
set(ZXING_ENABLE_QRCODE ON CACHE BOOL "Read authenticator QR codes" FORCE)
add_subdirectory("${ZXING_SOURCE}/core" "${CMAKE_BINARY_DIR}/zxing" EXCLUDE_FROM_ALL)
if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 16)
  # Avoid GCC 16/WinLibs static libstdc++'s missing out-of-line string move
  # constructor when upstream translation units are compiled with -Os.
  # Use the normal project Release optimization; upstream sources stay intact.
  get_target_property(ZXING_TRANSLATION_UNITS ZXing SOURCES)
  foreach(UNIT IN LISTS ZXING_TRANSLATION_UNITS)
    if(UNIT MATCHES "^src/.*\\.cpp$")
      set_source_files_properties("${ZXING_SOURCE}/core/${UNIT}"
        DIRECTORY "${ZXING_SOURCE}/core" PROPERTIES COMPILE_FLAGS "")
    endif()
  endforeach()
endif()
