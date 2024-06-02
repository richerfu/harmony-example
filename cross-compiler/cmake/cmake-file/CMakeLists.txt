cmake_minimum_required(VERSION 3.28)
project(cmake_file)

include($ENV{OHOS_NDK_HOME}/native/build/cmake/ohos.toolchain.cmake)

set(CMAKE_CXX_STANDARD 17)

add_executable(cmake_file main.cpp)
