
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_family = "windows")]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(target_family = "windows")]
use std::os::windows::prelude::*;
use std::path::Path;
use zeroize::Zeroize;
use safe_pqc_kyber::*;

use crate::{Combinedkey, PqxError};
#[cfg(windows)]
const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &str = "\n";
fn createfile(file: &Path, secure: bool) -> std::io::Result<File> {
    #[cfg(target_family = "windows")]
    #[allow(unreachable_code)]
    {
        return fs::OpenOptions::new()
            .create(true)
            .attributes(winapi::FILE_ATTRIBUTE_READONLY)
            .write(true)
            .open(&file);
    }
    #[cfg(target_family = "unix")]
    #[allow(unreachable_code)]
    {
        let umode: u32 = if secure { 0o600 } else { 0o644 };
        return fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(umode)
            .open(file);
    }
    #[allow(unreachable_code)]
    fs::OpenOptions::new().truncate(true).write(true).open(file)
}
/// Print private key and public key to a file. Keep your private key safe.
/// Keys is the keypair, privatekey is the first to write the private key and publickey the file to create public key.
/// Ex:
/// ```rust
/// use pqx::*;
/// use std::fs;
/// use tempfile::NamedTempFile;
/// use pqx::key::*;
/// use zeroize::Zeroize;
/// let keys = Combinedkey::new();
/// let privatefile = NamedTempFile::new().unwrap();
/// let publicfile = NamedTempFile::new().unwrap();
/// let privatetemp = privatefile.into_temp_path();
/// let publictemp = publicfile.into_temp_path();
/// printkeystofile(
/// keys.getkyberkeypair(),
/// &privatetemp,
/// &publictemp,
/// ).unwrap();
/// ```
pub fn printkeystofile<T>(
    keys: &safe_pqc_kyber::Keypair,
    privatekey: T,
    publickey: T,
) -> std::io::Result<()> where T: AsRef<OsStr> {
    let mut file = createfile(Path::new(privatekey.as_ref()), true)?;
    let mut text = getkeyheader(true, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(keys.secret));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(true, false));
    file.write_all(text.as_bytes())?;
    file = createfile(Path::new(publickey.as_ref()), false)?;
    let mut text = getkeyheader(false, true);
    text.push_str(LINE_ENDING);
    text.push_str(&hex::encode(keys.public));
    text.push_str(LINE_ENDING);
    text.push_str(&getkeyheader(false, false));
    file.write_all(text.as_bytes())?;
    Ok(())
}
/// Extract kyber keys from file
/// ```rust
/// use std::fs;
/// use tempfile::NamedTempFile;
/// use pqx::*;
/// use pqx::key::*;
/// let keys = Combinedkey::new();
/// let privatefile = NamedTempFile::new().unwrap();
/// let publicfile = NamedTempFile::new().unwrap();
/// let privatetemp = privatefile.into_temp_path();
/// let publictemp = publicfile.into_temp_path();
/// printkeystofile(
///     keys.getkyberkeypair(),
///     &privatetemp,
///     &publictemp,
/// )
/// .unwrap();
/// let mut privatefile = fs::File::open(privatetemp).unwrap();
/// let mut publicfile = fs::File::open(publictemp).unwrap();
/// let testkey = extractkyberkeysfromfile(&mut publicfile, &mut privatefile).unwrap();
/// assert!(testkey.checkkeys(&keys),"Invalid key generation, got {} vs {}",hex::encode(keys.displaykyberkey(false)),hex::encode(testkey.displaykyberkey(false)));
/// ```
pub fn extractkyberkeysfromfile(public: &mut File, private: &mut File) -> Result<Combinedkey,PqxError> {
    let mut publicstring = String::new();
    if public.read_to_string(&mut publicstring).is_err() {
        return Err(PqxError::InvalidInput);
    }
    let mut privatestring = String::new();
    if private.read_to_string(&mut privatestring).is_err() {
        return Err(PqxError::InvalidInput);
    }
    let privatekey =
            checkandextractkeys(&privatestring, true).unwrap();
        let publickey =
            checkandextractkeys(&publicstring, false).unwrap();
        let mut privatekey: [u8;KYBER_SECRETKEYBYTES] = hex::decode(privatekey).unwrap().try_into().unwrap();
        let mut publickey: [u8; KYBER_PUBLICKEYBYTES] = hex::decode(publickey).unwrap().try_into().unwrap();
        let mut key = [0u8; KYBER_PUBLICKEYBYTES + KYBER_SECRETKEYBYTES];
        key[..KYBER_PUBLICKEYBYTES].copy_from_slice(&publickey);
        key[KYBER_PUBLICKEYBYTES..].copy_from_slice(&privatekey);
        privatekey.zeroize();
        publickey.zeroize();
        Ok(match Combinedkey::try_from(key) {
            Ok(t) => t,
            _ => return Err(PqxError::InvalidInput)
        })
}
/// Get header of files
fn getkeyheader(private: bool, start: bool) -> String {
    match private {
        true => match start {
            true => String::from("-----BEGIN KYBER PRIVATE KEY-----"),
            false => String::from("-----END KYBER PRIVATE KEY-----"),
        },
        false => match start {
            true => String::from("-----BEGIN KYBER PUBLIC KEY-----"),
            false => String::from("-----END KYBER PUBLIC KEY-----"),
        },
    }
}
/// Extract keys from public or private file containing the key
pub fn checkandextractkeys(key: &str, private: bool) -> std::io::Result<String> {
    let element: Vec<&str> = key.split(LINE_ENDING).collect();
    if element.len() != 3 {
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    }
    if element[0].trim() != getkeyheader(private, true) || element[2].trim() != getkeyheader(private, false) {
        return Err(std::io::Error::from(ErrorKind::InvalidData));
    }
    return Ok(String::from(element[1].trim()));
}
