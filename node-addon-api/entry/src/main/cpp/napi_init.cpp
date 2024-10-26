#include <napi.h>

// 两数之和的函数
Napi::Number Add(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // 检查参数数量和类型
    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Number expected").ThrowAsJavaScriptException();
        return Napi::Number::New(env, 0);
    }

    // 获取参数并计算和
    double arg0 = info[0].As<Napi::Number>().DoubleValue();
    double arg1 = info[1].As<Napi::Number>().DoubleValue();
    double sum = arg0 + arg1;

    // 返回结果
    return Napi::Number::New(env, sum);
}

// 初始化模块
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "add"), Napi::Function::New(env, Add));
    return exports;
}

NODE_API_MODULE(entry, Init)