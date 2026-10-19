use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::env;

use data_encoding::BASE64_MIME;
use hmac::{Hmac, KeyInit, Mac};
use log::debug;
use sha1::Sha1;

use crate::keys::Error;

/// Check whether the host is known, from its standard location.
pub fn check_known_hosts(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
) -> Result<bool, Error> {
    check_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Check that a server key matches the one recorded in file `path`.
pub fn check_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
    path: P,
) -> Result<bool, Error> {
    let check = known_host_keys_path(host, port, path)?
        .into_iter()
        .map(|(line, recorded)| {
            match (
                pubkey.algorithm() == recorded.algorithm(),
                *pubkey == recorded,
            ) {
                (true, true) => Ok(true),
                (true, false) => Err(Error::KeyChanged { line }),
                _ => Ok(false),
            }
        })
        // If any Err was returned, we stop here
        .collect::<Result<Vec<bool>, Error>>()?
        .into_iter()
        // Now we check the results for a match
        .any(|x| x);

    Ok(check)
}

fn known_hosts_path() -> Result<PathBuf, Error> {
    env::home_dir()
        .map(|home_dir| home_dir.join(".ssh").join("known_hosts"))
        .ok_or(Error::NoHomeDir)
}

/// Get the server key that matches the one recorded in the user's known_hosts file.
pub fn known_host_keys(host: &str, port: u16) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    known_host_keys_path(host, port, known_hosts_path()?)
}

/// Get the server key that matches the one recorded in `path`.
pub fn known_host_keys_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    path: P,
) -> Result<Vec<(usize, ssh_key::PublicKey)>, Error> {
    use crate::keys::parse_public_key_base64;

    let mut f = if let Ok(f) = File::open(path) {
        BufReader::new(f)
    } else {
        return Ok(vec![]);
    };
    let mut buffer = String::new();

    let host_port = if port == 22 {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("[{host}]:{port}"))
    };
    debug!("host_port = {host_port:?}");
    let mut line = 1;
    let mut matches = vec![];
    while f.read_line(&mut buffer)? > 0 {
        {
            if buffer.as_bytes().first() == Some(&b'#') {
                buffer.clear();
                continue;
            }
            debug!("line = {buffer:?}");
            let mut s = buffer.split(' ');
            let hosts = s.next();
            let _ = s.next();
            let key = s.next();
            if let (Some(h), Some(k)) = (hosts, key) {
                debug!("{h:?} {k:?}");
                if match_hostname(&host_port, h) {
                    matches.push((line, parse_public_key_base64(k)?));
                }
            }
        }
        buffer.clear();
        line += 1;
    }
    Ok(matches)
}

fn match_hostname(host: &str, pattern: &str) -> bool {
    for entry in pattern.split(',') {
        if entry.starts_with("|1|") {
            let mut parts = entry.split('|').skip(2);
            let Some(Ok(salt)) = parts.next().map(|p| BASE64_MIME.decode(p.as_bytes())) else {
                continue;
            };
            let Some(Ok(hash)) = parts.next().map(|p| BASE64_MIME.decode(p.as_bytes())) else {
                continue;
            };
            if let Ok(hmac) = Hmac::<Sha1>::new_from_slice(&salt)
                && hmac.chain_update(host).verify_slice(&hash).is_ok()
            {
                return true;
            }
        } else if host == entry {
            return true;
        }
    }
    false
}

/// Record a host's public key into the user's known_hosts file.
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &ssh_key::PublicKey) -> Result<(), Error> {
    learn_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Record a host's public key into a nonstandard location.
pub fn learn_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &ssh_key::PublicKey,
    path: P,
) -> Result<(), Error> {
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;

    // Test whether the known_hosts file ends with a \n
    let mut buf = [0; 1];
    let mut ends_in_newline = false;
    if file.seek(SeekFrom::End(-1)).is_ok() {
        file.read_exact(&mut buf)?;
        ends_in_newline = buf[0] == b'\n';
    }

    // Write the key.
    file.seek(SeekFrom::End(0))?;
    let mut file = std::io::BufWriter::new(file);
    if !ends_in_newline {
        file.write_all(b"\n")?;
    }
    if port != 22 {
        write!(file, "[{host}]:{port} ")?
    } else {
        write!(file, "{host} ")?
    }
    file.write_all(pubkey.to_openssh()?.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}