#[cfg(test)]
mod test;

use std::error::Error;

#[derive(Clone, Debug)]
pub enum HashFormat {
    /// Format used by John the Ripper
    John,
    /// Format used by hashcat
    Hashcat,
}

/// given an armored or unarmored, password-protected secret key, extracts the hash in the specified format
pub fn extract_hash(secret_key: &[u8], format: HashFormat) -> Result<String, Box<dyn Error>> {
    let ret = "asdf".into();
    Ok(ret)
}
