use std::ffi::CStr;

// Remarks: Making it easy to edit the binary executable

pub fn signalling_server() -> Option<String> {
    bytes_to_str("SIGNAL", b"SIGNAL__wss://icepipe.fly.dev/signaling/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
}

pub fn ice_urls() -> Vec<String> {
    let urls = bytes_to_str("STUN", b"STUN__stun:stun.l.google.com:19302\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").unwrap_or_default();

    urls.split(';')
        .filter(|x| !x.is_empty())
        .map(|url| url.to_string())
        .collect::<Vec<_>>()
}

fn bytes_to_str(env: &str, bytes: &'static [u8]) -> Option<String> {
    std::env::var(env).map_or_else(
        |_| {
            let fallback = unsafe { CStr::from_ptr(bytes.as_ptr() as *const i8) };
            let fallback = fallback.to_str().unwrap();
            let fallback = match fallback.split_once("__") {
                Some((_, url)) => url,
                None => fallback,
            };
            match fallback.len() {
                0 => None,
                _ => Some(fallback.to_owned()),
            }
        },
        Some,
    )
}
