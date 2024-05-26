#include "napi/native_api.h"
#include "openssl/md5.h"
#include <cstring>
#include <iostream>

static napi_value test_md5(napi_env env, napi_callback_info info) {
    size_t requireArgc = 1;
    size_t argc = 1;
    napi_value args[1] = {nullptr};

    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    napi_valuetype valuetype0;
    napi_typeof(env, args[0], &valuetype0);

    size_t len = 0;
    char *input = nullptr;
    napi_get_value_string_utf8(env, args[0], NULL, 0, &len);
    input = new char[len + 1];
    napi_get_value_string_utf8(env, args[0], input, len + 1, &len);

    unsigned char digest[MD5_DIGEST_LENGTH];

    MD5(reinterpret_cast<const unsigned char *>(input), strlen(input), digest);

    char md5string[2 * MD5_DIGEST_LENGTH + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5string[i * 2], "%02x", (unsigned int)digest[i]);
    }
    
    delete[] input;

    napi_value output;
    napi_create_string_utf8(env, reinterpret_cast<const char*>(md5string), NAPI_AUTO_LENGTH, &output);
    return output;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"md5", nullptr, test_md5, nullptr, nullptr, nullptr, napi_default, nullptr}};
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void) {
    napi_module_register(&demoModule);
}
