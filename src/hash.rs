use pgp::crypto::sym::SymmetricKeyAlgorithm;
use std::convert::TryFrom;
use std::fmt::Display;
use strum_macros::FromRepr;

#[derive(Clone, Copy, Debug, FromRepr, PartialEq, Eq)]
#[repr(i32)]
pub enum StringToKey {
    /// In this case no salt is used, so `count` and `salt` in the hash are None
    Simple = 0,
    Salted = 1,
    IteratedSalted = 3,
}

/// According to RFC4880, Section 9.1. Public-Key Algorithms.
/// 100 to 110 are reserved for Private/Experimental algorithms
#[derive(Clone, Copy, Debug, FromRepr, PartialEq, Eq)]
#[repr(i32)]
pub enum Algorithm {
    /// The value 0 is not in the RFC, and is a john-specific addition
    Symmetric = 0,
    RSAEncSign = 1,
    RSAEncOnly = 2,
    RsaSignOnly = 3,
    ElGamal = 16,
    DSA = 17,
    EC = 18,
    ECDSA = 19,
    /// Reserved (formerly Elgamal Encrypt or Sign)
    ElGamalEncSign = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DH = 21,
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

impl TryFrom<SymmetricKeyAlgorithm> for CipherAlgorithm {
    type Error = String;

    fn try_from(value: SymmetricKeyAlgorithm) -> Result<Self, Self::Error> {
        match value {
            SymmetricKeyAlgorithm::IDEA => Ok(CipherAlgorithm::IDEA),
            SymmetricKeyAlgorithm::TripleDES => Ok(CipherAlgorithm::TripleDES),
            SymmetricKeyAlgorithm::CAST5 => Ok(CipherAlgorithm::CAST5),
            SymmetricKeyAlgorithm::Blowfish => Ok(CipherAlgorithm::Blowfish),
            SymmetricKeyAlgorithm::AES128 => Ok(CipherAlgorithm::AES128),
            SymmetricKeyAlgorithm::AES192 => Ok(CipherAlgorithm::AES192),
            SymmetricKeyAlgorithm::AES256 => Ok(CipherAlgorithm::AES256),
            SymmetricKeyAlgorithm::Twofish => Ok(CipherAlgorithm::Twofish),
            SymmetricKeyAlgorithm::Camellia128 => Ok(CipherAlgorithm::Camellia128),
            SymmetricKeyAlgorithm::Camellia192 => Ok(CipherAlgorithm::Camellia192),
            SymmetricKeyAlgorithm::Camellia256 => Ok(CipherAlgorithm::Camellia256),
            // SymmetricKeyAlgorithm::Plaintext => todo!(),
            // SymmetricKeyAlgorithm::Private10 => CipherAlgorithm::Private10,
            _ => Err("unknown CipherAlgorithm found".into()),
        }
    }
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

/// The string-to-key ID
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
    pub s2k: StringToKey,
    pub usage: Usage,
    pub hash_algorithm: HashAlgorithm,
    pub cipher_algorithm: CipherAlgorithm,
    /// only if algorithm != Symmetric
    pub iv_len: Option<usize>,
    /// only if algorithm != Symmetric
    pub iv: Option<Vec<u8>>,
    /// only if s2k != Simple
    pub count: Option<usize>,
    /// only if s2k != Simple
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
            self.s2k as i32,
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
