use std::{
    ffi::{OsStr, OsString},
    path::Path,
};

use os_str_bytes::RawOsStr;

pub fn file_prefix<P: AsRef<Path>>(path: P) -> Option<OsString> {
    let path = path.as_ref();
    path.file_name()
        .map(split_file_at_dot)
        .map(|(before, _after)| before)
}

fn split_file_at_dot(file: &OsStr) -> (OsString, Option<OsString>) {
    let file_raw = RawOsStr::new(file);
    let slice = file_raw.as_raw_bytes();
    if slice == b".." {
        return (file.to_os_string(), None);
    }

    let i = match slice[1..].iter().position(|b| *b == b'.') {
        Some(i) => i + 1,
        None => return (file.to_os_string(), None),
    };
    let before = &slice[..i];
    let after = &slice[i + 1..];

    let before = RawOsStr::assert_from_raw_bytes(before)
        .to_os_str()
        .to_os_string();
    let after = RawOsStr::assert_from_raw_bytes(after)
        .to_os_str()
        .to_os_string();

    (before, Some(after))
}

pub fn get_credentials(api_key: Option<String>, secret: Option<String>) -> (String, String) {
    let api_key = if let Some(api_key) = api_key {
        api_key
    } else {
        let api_key = std::env::var("EVERSCAN_API_KEY");
        match api_key {
            Ok(a) => a,
            Err(_) => {
                println!("Please set `EVERSCAN_API_KEY` environment variable or provide `--api-key` argument");
                std::process::exit(1);
            }
        }
    };

    let secret = if let Some(secret) = secret {
        secret
    } else {
        let secret = std::env::var("EVERSCAN_SECRET");
        match secret {
            Ok(a) => a,
            Err(_) => {
                println!("Please set `EVERSCAN_SECRET` environment variable or provide `--secret` argument");
                std::process::exit(1);
            }
        }
    };
    (api_key, secret)
}
