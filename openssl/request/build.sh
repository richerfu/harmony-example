#!/bin/sh

# 告诉 openssl-sys 查询路径
export AARCH64_UNKNOWN_LINUX_OHOS_OPENSSL_DIR="${PWD}/../ohos-openssl/prelude/arm64-v8a/"
export ARMV7_UNKNOWN_LINUX_OHOS_OPENSSL_DIR="${PWD}/../ohos-openssl/prelude/armeabi-v7a/"
export X86_64_UNKNOWN_LINUX_OHOS_OPENSSL_DIR="${PWD}/../ohos-openssl/prelude/x86_64/"

# 构建release产物 减少git体积
ohrs build --release