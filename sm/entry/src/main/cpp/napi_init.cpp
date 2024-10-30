#include "sm2.h"
#include "sm3.h"
#include "sm4.h"

// 初始化模块
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "sm2Encrypt"), Napi::Function::New(env, sm2::SM2_ENCRYPT));
    exports.Set(Napi::String::New(env, "sm2Decrypt"), Napi::Function::New(env, sm2::SM2_DECRYPT));
    exports.Set(Napi::String::New(env, "sm3Encrypt"), Napi::Function::New(env, sm3::SM3_ENCRYPT));
    exports.Set(Napi::String::New(env, "sm4Encrypt"), Napi::Function::New(env, sm4::SM4_ENCRYPT));
    exports.Set(Napi::String::New(env, "sm4Decrypt"), Napi::Function::New(env, sm4::SM4_DECRYPT));
    return exports;
}

NODE_API_MODULE(entry, Init)