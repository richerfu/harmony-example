const napi = @import("napi");

pub fn add(left: f32, right: f32) f32 {
    return left + right;
}

comptime {
    napi.NODE_API_MODULE("zig_napi_example", @This());
}
