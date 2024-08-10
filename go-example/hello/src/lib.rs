use std::ffi::c_int;

use napi_derive_ohos::napi;

extern "C" {
    pub fn Add(left: c_int, right: c_int) -> c_int;
}

#[napi]
pub fn add(left: i32, right: i32) -> i32 {
    unsafe { Add(left, right) }
}
