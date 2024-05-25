use crc32fast::Hasher;
use napi_derive_ohos::*;
use napi_ohos::Result;

#[napi]
pub fn crc32(input: String, initial_state: Option<u32>) -> Result<u32> {
    let mut hasher = Hasher::new_with_initial(initial_state.unwrap_or(0));
    hasher.update(input.as_bytes());
    Ok(hasher.finalize())
}
