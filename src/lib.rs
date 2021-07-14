use aes_gcm::{aead::Aead, Aes256Gcm, Key, NewAead, Nonce};
use chrono::{DateTime, NaiveDateTime, Utc};
use cookie::Cookie;
use rusqlite::NO_PARAMS;
use std::path::PathBuf;
use std::ptr::null_mut;
use thiserror::Error;
use winapi::wincrypt::DATA_BLOB;

#[test]
fn is_aes_gcm_data_test() {
    assert_eq!(is_aes_gcm_data(&[118, 49, 48]), true);
    assert_eq!(is_aes_gcm_data(&[2, 2, 2]), false);
}
fn is_aes_gcm_data(value: &[u8]) -> bool {
    &value[0..3] == b"v10"
}
fn get_nonce(encrypted_value: &[u8]) -> &[u8] {
    &encrypted_value[3..15]
}
pub fn decrypt(encrypted_value: &[u8], key: &[u8]) -> String {
    if !is_aes_gcm_data(encrypted_value) {
        panic!("not aes_gcm");
    }

    let nonce = get_nonce(encrypted_value);
    let key = Key::from_slice(&key);
    let nonce = Nonce::from_slice(&nonce);
    let cipher = Aes256Gcm::new(&key);

    let plaintext = cipher.decrypt(nonce, &encrypted_value[15..]).unwrap();
    String::from_utf8_lossy(&plaintext).into()
}
#[derive(Error, Debug)]
pub enum GetCookieError {
    #[error("os_crypt.encrypted_key not found")]
    EncryptedKeyNotFound,
    #[error("Local State file not found")]
    LocalStateNotFound(#[from] std::io::Error),
}
fn get_local_appdata_path() -> PathBuf {
    directories::BaseDirs::new().unwrap().cache_dir().into()
}
fn get_key() -> anyhow::Result<Vec<u8>> {
    let local_appdata = get_local_appdata_path();
    let path = local_appdata.join(r#".\Google\Chrome\User Data\Local State"#);
    let content =
        std::fs::read_to_string(path).or_else(|e| Err(GetCookieError::LocalStateNotFound(e)))?;
    let json_obj: serde_json::Value = serde_json::from_str(&content)?;
    let encrypted_key: &str = &json_obj["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or(GetCookieError::EncryptedKeyNotFound)?;

    let decoded = base64::decode(encrypted_key).unwrap();
    let dpapied_key = &decoded[5..];
    let mut v = dpapied_key.to_vec();
    let decrypted = crypt_unprotect_data(&mut v).unwrap();
    Ok(decrypted.to_vec())
}
fn crypt_unprotect_data(encrypted_data: &Vec<u8>) -> Option<&[u8]> {
    let mut data_in: DATA_BLOB;
    let mut data_out: DATA_BLOB;
    let b = unsafe {
        data_in = std::mem::zeroed();
        data_in.pbData = std::mem::transmute(encrypted_data.as_ptr() as usize);
        data_in.cbData = encrypted_data.len() as u32;
        data_out = std::mem::zeroed();

        crypt32::CryptUnprotectData(
            &mut data_in,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            &mut data_out,
        )
    };
    if b == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };

    Some(slice)
}
pub trait CookieStorage {
    fn get_cookies(&self, domain: &str) -> Vec<Cookie>;
}

pub struct Chrome {
    cookies_path: PathBuf,
}
impl Chrome {
    pub fn new(path: PathBuf) -> Chrome {
        Chrome {
            cookies_path: path,
        }
    }

    fn get_cookies_internal(&self) -> Vec<Cookie> {
        let mut ms = Vec::new();
        let conn = rusqlite::Connection::open(&self.cookies_path).unwrap();
        let key = get_key().unwrap();
        let mut stmt = conn
            .prepare("select name,value,host_key,path,expires_utc,encrypted_value from cookies")
            .unwrap();
        let ss = stmt
            .query_map(NO_PARAMS, |row| {
                let value: String = row.get(1);

                let value: String = match value.is_empty() {
                    false => value,
                    true => {
                        let mut encrypted_value: Vec<u8> = row.get(5);
                        if is_aes_gcm_data(&encrypted_value) {
                            decrypt(&encrypted_value, &key)
                        } else {
                            let slice = crypt_unprotect_data(&mut encrypted_value).unwrap();
                            String::from_utf8_lossy(slice).into()
                        }
                    }
                };
                let name: String = row.get(0);
                let domain: String = row.get(2);
                let path: String = row.get(3);
                let expires_utc: i64 = row.get(4);
                let mut cookie = Cookie::new(name, value);
                cookie.set_domain(domain);
                cookie.set_path(path);
                let date = Chrome::chrome_timestamp_to_time(expires_utc).unwrap_or(
                    DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc),
                );
                cookie.set_expires(time::OffsetDateTime::from_unix_timestamp(date.timestamp()));
                cookie
            })
            .unwrap();

        for c in ss {
            ms.push(c.unwrap());
        }
        ms
    }
    /// Chrome stores time in Microsoft Gregorian calendar epoch, even on Mac. It is the same across all platforms.
    /// See: https://github.com/adobe/chromium/blob/master/base/time_mac.cc#L29
    const NANOSECONDS_IN_SECONDS: i64 = 1000 * 1000;
    const WINDOWS_EPOCH_DELTA_NANOSECONDS: i64 = 11644473600i64 * Chrome::NANOSECONDS_IN_SECONDS;

    /// Convert Chrome timestamp to time
    fn chrome_timestamp_to_time(chrome_timestamp: i64) -> Option<DateTime<Utc>> {
        return if chrome_timestamp == 0 {
            None
        } else {
            let timestamp = chrome_timestamp - Chrome::WINDOWS_EPOCH_DELTA_NANOSECONDS;
            let seconds = timestamp / Chrome::NANOSECONDS_IN_SECONDS;
            let nanoseconds = (timestamp % Chrome::NANOSECONDS_IN_SECONDS) as u32;
            NaiveDateTime::from_timestamp_opt(seconds, nanoseconds)
                .map(|d| DateTime::<Utc>::from_utc(d, Utc))
        };
    }
}
impl CookieStorage for Chrome {
    fn get_cookies(&self, domain: &str) -> Vec<Cookie> {
        let mut ms = Vec::new();
        for cookie in self.get_cookies_internal() {
            match cookie {
                cookie if cookie.domain().unwrap().ends_with(domain) => {
                    ms.push(cookie);
                }
                _ => (),
            }
        }
        ms
    }
}
#[test]
fn chrome_test()->anyhow::Result<()> {
    let path = std::env::current_dir()?;
    let path = path.join(r#".\Cookies"#);
    let chrome = Chrome::new(path);
    let cookies = chrome.get_cookies("nicovideo.jp");
    let cookie0 = &cookies[0];
    assert_eq!(cookie0.name(), "__uuiduz");
    assert_eq!(cookie0.value(), "4aae1b11-b43e-4acc-bab4-3bec71eca3f8");
    Ok(())
}
