# the minimum version of CMake.
cmake_minimum_required(VERSION 3.5.0)
project(MyApplication3)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(NODE_ADDON_API_OHOS_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../oh_modules/@ohos-rs/node-addon-api)
set(CMAKE_MODULE_PATH ${NODE_ADDON_API_OHOS_ROOT_PATH})

find_package(node_addon_api_ohos REQUIRED)

if(DEFINED PACKAGE_FIND_FILE)
    include(${PACKAGE_FIND_FILE})
endif()

include_directories(${NATIVERENDER_ROOT_PATH}
                    ${NATIVERENDER_ROOT_PATH}/include)

add_library(entry SHARED napi_init.cpp)
target_link_libraries(entry PUBLIC libace_napi.z.so node_addon_api_ohos)