cmake_minimum_required(VERSION 3.6)
project(libkmip C)

set(libkmip_srcs
  src/kmip.c
  src/kmip_bio.c
  src/kmip_memset.c
  src/kmip_io.c
)

add_library(kmip STATIC ${libkmip_srcs})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(kmip PRIVATE -D_POSIX_C_SOURCE=1)
endif()
target_include_directories(kmip PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(kmip PUBLIC OpenSSL::Crypto OpenSSL::SSL)

