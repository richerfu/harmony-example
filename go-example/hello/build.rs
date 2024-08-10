use std::env;

fn main() {
  napi_build_ohos::setup();

  let dir = env::current_dir().unwrap();
  let binding = dir.parent().unwrap().join("go-shared");

  println!("cargo:rustc-link-search={}",binding.to_str().unwrap());
  println!("cargo:rustc-link-lib=dylib=add");
}
