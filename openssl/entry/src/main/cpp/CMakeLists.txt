# the minimum version of CMake.
cmake_minimum_required(VERSION 3.4.1)
project(test_openssl)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${NATIVERENDER_ROOT_PATH}
                    ${NATIVERENDER_ROOT_PATH}/include)
# 配置查询路径
add_library(openssl INTERFACE IMPORTED)

target_include_directories(openssl INTERFACE ../../../../ohos-openssl/prelude/arm64-v8a/include)
target_link_directories(openssl INTERFACE ../../../../ohos-openssl/prelude/arm64-v8a/lib)
target_link_libraries(openssl INTERFACE ssl crypto)


add_library(entry SHARED hello.cpp)
target_link_libraries(entry PUBLIC libace_napi.z.so openssl)