cmake_minimum_required(VERSION 3.16)
project(http3-implementation VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-O2")

# Find OpenSSL - support both system and custom paths
if(OPENSSL_ROOT_DIR)
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    find_package(OpenSSL REQUIRED)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENSSL REQUIRED openssl>=1.1.1)
endif()

# Find ngtcp2 via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(NGTCP2 REQUIRED libngtcp2)

# Try to find ngtcp2 crypto library - could be openssl or quictls variant
pkg_check_modules(NGTCP2_CRYPTO_QUICTLS libngtcp2_crypto_quictls)
pkg_check_modules(NGTCP2_CRYPTO_OPENSSL libngtcp2_crypto_openssl)

if(NGTCP2_CRYPTO_QUICTLS_FOUND)
    set(NGTCP2_CRYPTO_LIBRARIES ${NGTCP2_CRYPTO_QUICTLS_LIBRARIES})
    set(NGTCP2_CRYPTO_INCLUDE_DIRS ${NGTCP2_CRYPTO_QUICTLS_INCLUDE_DIRS})
    set(NGTCP2_CRYPTO_LIBRARY_DIRS ${NGTCP2_CRYPTO_QUICTLS_LIBRARY_DIRS})
    message(STATUS "Using ngtcp2 crypto with quictls")
elseif(NGTCP2_CRYPTO_OPENSSL_FOUND)
    set(NGTCP2_CRYPTO_LIBRARIES ${NGTCP2_CRYPTO_OPENSSL_LIBRARIES})
    set(NGTCP2_CRYPTO_INCLUDE_DIRS ${NGTCP2_CRYPTO_OPENSSL_INCLUDE_DIRS})
    set(NGTCP2_CRYPTO_LIBRARY_DIRS ${NGTCP2_CRYPTO_OPENSSL_LIBRARY_DIRS})
    message(STATUS "Using ngtcp2 crypto with openssl")
else()
    message(FATAL_ERROR "Could not find ngtcp2 crypto library (neither quictls nor openssl variant)")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${NGTCP2_INCLUDE_DIRS}
    ${NGTCP2_CRYPTO_INCLUDE_DIRS}
)

# Link directories
link_directories(
    ${OPENSSL_LIBRARY_DIRS}
    ${NGTCP2_LIBRARY_DIRS}
    ${NGTCP2_CRYPTO_LIBRARY_DIRS}
)

# Common library
add_library(http3_common STATIC
    src/http3_common.c
)

target_include_directories(http3_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# HTTP/3 Server
add_executable(h3_server
    src/h3_server.c
)

if(OPENSSL_ROOT_DIR)
    target_link_libraries(h3_server
        http3_common
        OpenSSL::SSL
        OpenSSL::Crypto
        ${NGTCP2_LIBRARIES}
        ${NGTCP2_CRYPTO_LIBRARIES}
    )
else()
    target_link_libraries(h3_server
        http3_common
        ${OPENSSL_LIBRARIES}
        ${NGTCP2_LIBRARIES}
        ${NGTCP2_CRYPTO_LIBRARIES}
    )
endif()

# HTTP/3 Client
add_executable(h3_client
    src/h3_client.c
)

if(OPENSSL_ROOT_DIR)
    target_link_libraries(h3_client
        http3_common
        OpenSSL::SSL
        OpenSSL::Crypto
        ${NGTCP2_LIBRARIES}
        ${NGTCP2_CRYPTO_LIBRARIES}
    )
else()
    target_link_libraries(h3_client
        http3_common
        ${OPENSSL_LIBRARIES}
        ${NGTCP2_LIBRARIES}
        ${NGTCP2_CRYPTO_LIBRARIES}
    )
endif()

# Installation
install(TARGETS h3_server h3_client
    RUNTIME DESTINATION bin
)

install(FILES include/http3.h
    DESTINATION include
)

# Create certs directory
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX}/certs)

# Print configuration
message(STATUS "")
message(STATUS "HTTP/3 Implementation Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
if(OPENSSL_ROOT_DIR)
    message(STATUS "  OpenSSL: ${OPENSSL_VERSION} (from ${OPENSSL_ROOT_DIR})")
else()
    message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
endif()
message(STATUS "  ngtcp2: ${NGTCP2_VERSION}")
message(STATUS "")
