use crate::DynResult;
use std::ffi::CStr;
use webrtc_ice::url::Url;

// Remarks: Making it easy to edit the binary executable

pub fn signalling_server() -> DynResult<String> {
    bytes_to_str("SIGNAL", b"SIGNAL__wss://icepipe.fly.dev/signaling/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
}

pub fn ice_urls() -> DynResult<Vec<Url>> {
    let urls = bytes_to_str("STUN", b"STUN__stun:stun.l.google.com:19302\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")?;

    urls.split(';')
        .into_iter()
        .map(|url| {
            let mut fields = url.split('&');
            let url = fields
                .next()
                .ok_or_else(|| anyhow::anyhow!("Empty STUN url"))?;
            let username = fields.next();
            let password = fields.next();
            let mut url = Url::parse_url(url)?;
            url.username = username.unwrap_or("").to_owned();
            url.password = password.unwrap_or("").to_owned();

            DynResult::Ok(url)
        })
        .collect::<DynResult<Vec<_>>>()
}

fn bytes_to_str(env: &str, bytes: &'static [u8]) -> DynResult<String> {
    std::env::var(env)
        .map_or_else(
            |_| {
                let fallback = unsafe { CStr::from_ptr(bytes.as_ptr() as *const i8) };
                let fallback = fallback.to_str().unwrap();
                let fallback = match fallback.find("__") {
                    Some(idx) => &fallback[idx + 2..],
                    None => fallback,
                };
                match fallback.len() {
                    0 => None,
                    _ => Some(fallback.to_owned()),
                }
            },
            Some,
        )
        .ok_or_else(|| anyhow::anyhow!("Must provide environment variable {env}."))
}
