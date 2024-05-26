use napi_derive_ohos::napi;
use napi_ohos::{Error, Result, Status};
use std::fs::File;
use std::io::Read;

#[napi]
pub fn fetch() -> Result<String> {
    let mut buf = Vec::new();
    File::open("/etc/ssl/certs/cacert.pem")?
        .read_to_end(&mut buf)
        .map_err(|e| Error::new(Status::GenericFailure, format!("{:?}", e)))?;
    let cert = reqwest::Certificate::from_pem(&buf)
        .map_err(|e| Error::new(Status::GenericFailure, format!("{:?}", e)))?;

    let client = reqwest::blocking::Client::builder()
        .add_root_certificate(cert)
        .build()
        .map_err(|e| Error::new(Status::GenericFailure, format!("{:?}", e)))?;

    let res = client
        .post("https://www.baidu.com")
        .body("the exact body that is sent")
        .send()
        .map_err(|e| Error::new(Status::GenericFailure, format!("{:?}", e)))?;
    let txt = res
        .text()
        .map_err(|e| Error::new(Status::GenericFailure, format!("{:?}", e)))?;
    Ok(txt)
}
