use std::fmt::Display;
use strum_macros::FromRepr;

// #[derive(FromPrimitive)]
#[derive(Clone, Copy, Debug, FromRepr, PartialEq, Eq)]
#[repr(i32)]
pub enum Spec {
    /// If no salt, `count` and `salt` are None
    Simple = 0,
    Salted = 1,
    IteratedSalted = 3,
}

#[derive(Clone, Copy, Debug, FromRepr, PartialEq, Eq)]
#[repr(i32)]
pub enum Algorithm {
    Symmetric = 0,
    RSAEncSign = 1,
    ElGamal = 16,
    DSA = 17,
    EG = 20,
}

#[derive(Clone, Copy, Debug, FromRepr)]
#[repr(i32)]
pub enum CipherAlgorithm {
    Unknown = -1,
    CAST5 = 3,
    Blowfish = 4,
    AES128 = 7,
    AES192 = 8,
    AES256 = 9,
    IDEA = 1,
    TripleDES = 2,
    Twofish = 10,
    Camellia128 = 11,
    Camellia192 = 12,
    Camellia256 = 13,
}

#[derive(Clone, Copy, Debug, FromRepr)]
#[repr(i32)]
pub enum HashAlgorithm {
    Unknown = -1,
    MD5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA256 = 8,
    SHA384 = 9,
    SHA512 = 10,
    SHA224 = 11,
}

#[derive(Clone, Copy, Debug, FromRepr, PartialEq, Eq)]
#[repr(i32)]
pub enum Usage {
    Zero = 0,
    Nine = 9,
    Eighteen = 18,
    TwoFiveFour = 254,
    TwoFiveFive = 255,
}

#[derive(Debug)]
pub enum ExtraData {
    /// DSA: p, q, g, y
    Dsa {
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
    /// ElGamal: p, g, y
    ElGamal { p: Vec<u8>, g: Vec<u8>, y: Vec<u8> },
    /// RSA: p
    Rsa { p: Vec<u8> },
}

/// A hash for the OpenPGP format, prefixed with `$gpg$`.
pub struct PgpHash {
    pub algorithm: Algorithm,
    pub data_len: usize,
    /// not set if algorithm == Symmetric
    pub bits: Option<usize>,
    /// data length must be `data_len` (hex string is 2x as long)
    pub data: Vec<u8>,
    pub spec: Spec,
    pub usage: Usage,
    pub hash_algorithm: HashAlgorithm,
    pub cipher_algorithm: CipherAlgorithm,
    /// only if algorithm != Symmetric
    pub iv_len: Option<usize>,
    /// only if algorithm != Symmetric
    pub iv: Option<Vec<u8>>,
    /// only if spec != Simple
    pub count: Option<usize>,
    /// only if spec != Simple
    pub salt: Option<[u8; 8]>,
    pub extra_data: Option<ExtraData>,
}

impl Display for PgpHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "$gpg$*{}*{}", self.algorithm as i32, self.data_len,)?;
        if let Some(b) = self.bits {
            write!(f, "*{}", b)?;
        }
        write!(
            f,
            "*{}*{}*{}*{}*{}",
            hex::encode(&self.data),
            self.spec as i32,
            self.usage as i32,
            self.hash_algorithm as i32,
            self.cipher_algorithm as i32,
        )?;
        // iv_len and iv are optional, and can be left away. need to continue after
        if let Some(c) = self.iv_len {
            write!(f, "*{}", c)?;
        }
        if let Some(c) = &self.iv {
            write!(f, "*{}", hex::encode(c))?;
        }
        // if count and salt are not specified, can't have extra data.
        if let Some(c) = self.count {
            write!(f, "*{}", c)?;
        }
        if let Some(s) = self.salt {
            write!(f, "*{}", hex::encode(&s))?;
        }
        // extra data, if available
        if let Some(extra) = &self.extra_data {
            match extra {
                ExtraData::Dsa { p, q, g, y } => {
                    write!(
                        f,
                        "*{}*{}*{}*{}*{}*{}*{}*{}",
                        p.len(),
                        hex::encode(p),
                        q.len(),
                        hex::encode(q),
                        g.len(),
                        hex::encode(g),
                        y.len(),
                        hex::encode(y)
                    )
                }
                ExtraData::ElGamal { p, g, y } => {
                    write!(
                        f,
                        "*{}*{}*{}*{}*{}*{}",
                        p.len(),
                        hex::encode(p),
                        g.len(),
                        hex::encode(g),
                        y.len(),
                        hex::encode(y)
                    )
                }
                ExtraData::Rsa { p } => {
                    write!(f, "*{}*{}", p.len(), hex::encode(p))
                }
            }?
        }
        Ok(())
    }
}
