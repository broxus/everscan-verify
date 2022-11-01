use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::Path,
};

pub fn file_prefix<P: AsRef<Path>>(path: P) -> Option<OsString> {
    let path = path.as_ref();
    path.file_name()
        .map(split_file_at_dot)
        .map(|(before, _after)| before.to_os_string())
}

fn split_file_at_dot(file: &OsStr) -> (&OsStr, Option<&OsStr>) {
    let slice = file.as_bytes();
    if slice == b".." {
        return (file, None);
    }

    let i = match slice[1..].iter().position(|b| *b == b'.') {
        Some(i) => i + 1,
        None => return (file, None),
    };
    let before = &slice[..i];
    let after = &slice[i + 1..];
    (OsStr::from_bytes(before), Some(OsStr::from_bytes(after)))
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
