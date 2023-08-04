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
    Unknown = 0,
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

/// A hash for the OpenPGP format, usually prefixed with `$gpg$`.
/// *<algorithm>*<length>*<n_bits>*<data_hex>*<spec>*<usage>*<hashalgo>*<cipheralgo>*<iv_len>*<iv_hex>*<count>*<salt_hex>
pub struct PgpHash {
    algorithm: Algorithm,
    data_len: usize,
    /// not set if algorithm == Unknown
    bits: Option<usize>,
    /// data length must be `datalen` (hex string is 2x as long)
    data: Vec<u8>,
    spec: Spec,
    usage: Usage,
    hash_algorithm: HashAlgorithm,
    cipher_algorithm: CipherAlgorithm,
    iv_len: Option<usize>,
    iv: Option<Vec<u8>>,
    count: Option<usize>,
    salt: Option<[u8; 8]>,
    extra_data: Option<ExtraData>,
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
        } else {
            return Ok(());
        }
        if let Some(s) = self.salt {
            write!(f, "*{}", hex::encode(&s))?;
        } else {
            return Ok(());
        }
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

fn parse_extra_fields<'a>(
    mut iter: impl Iterator<Item = &'a str>,
    n_expected: usize,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut ret = Vec::new();
    for i in 0..n_expected {
        let num_bytes = str::parse::<usize>(&iter.next().ok_or("not enough tokens in hash")?)?;
        let data = hex::decode(iter.next().ok_or("not enough tokens in hash")?)?;
        if data.len() != num_bytes {
            return Err(format!("invalid byte length in extra data field {i}").into());
        }
        ret.push(data);
    }
    Ok(ret)
}

fn parse_extra_data<'a>(
    iter: impl Iterator<Item = &'a str>,
    usage: Usage,
    spec: Spec,
    alg: Algorithm,
) -> Result<Option<ExtraData>, Box<dyn std::error::Error>> {
    if usage != Usage::TwoFiveFive {
        return Ok(None);
    }
    Ok(match (spec, alg) {
        (Spec::Salted, Algorithm::DSA) => {
            let mut x = parse_extra_fields(iter, 4)?.into_iter();
            // unwrap OK because function above verifies that we have 4
            Some(ExtraData::Dsa {
                p: x.next().unwrap(),
                q: x.next().unwrap(),
                g: x.next().unwrap(),
                y: x.next().unwrap(),
            })
        }
        (Spec::Salted, Algorithm::ElGamal) => {
            let mut x = parse_extra_fields(iter, 3)?.into_iter();
            Some(ExtraData::ElGamal {
                p: x.next().unwrap(),
                g: x.next().unwrap(),
                y: x.next().unwrap(),
            })
        }
        (Spec::Salted, _) => Some(ExtraData::Rsa {
            p: parse_extra_fields(iter, 1)?.into_iter().next().unwrap(),
        }),
        (Spec::IteratedSalted, Algorithm::DSA) => {
            let mut x = parse_extra_fields(iter, 4)?.into_iter();
            Some(ExtraData::Dsa {
                p: x.next().unwrap(),
                q: x.next().unwrap(),
                g: x.next().unwrap(),
                y: x.next().unwrap(),
            })
        }
        (Spec::IteratedSalted, Algorithm::ElGamal) => {
            let mut x = parse_extra_fields(iter, 3)?.into_iter();
            Some(ExtraData::ElGamal {
                p: x.next().unwrap(),
                g: x.next().unwrap(),
                y: x.next().unwrap(),
            })
        }
        (Spec::IteratedSalted, Algorithm::RSAEncSign) => Some(ExtraData::Rsa {
            p: parse_extra_fields(iter, 1)?.into_iter().next().unwrap(),
        }),
        _ => None,
    })
}

pub fn parse(input: &str) -> Result<PgpHash, Box<dyn std::error::Error>> {
    if !input.starts_with("$gpg$*") {
        return Err("invalid prefix, must be '$pgp$'".into());
    }
    let mut iter = input[6..].split("*");
    let algorithm = Algorithm::from_repr(str::parse::<i32>(
        iter.next().ok_or("not enough tokens in hash")?,
    )?)
    .ok_or("invalid value for 'algorithm'")?;
    let data_len = str::parse::<usize>(iter.next().ok_or("not enough tokens in hash")?)?;
    let bits = match algorithm {
        Algorithm::Unknown => None,
        _ => Some(str::parse::<usize>(
            iter.next().ok_or("not enough tokens in hash")?,
        )?),
    };
    let data = hex::decode(iter.next().ok_or("not enough tokens in hash")?)?;
    let spec = Spec::from_repr(str::parse::<i32>(
        iter.next().ok_or("not enough tokens in hash")?,
    )?)
    .ok_or("invalid value for 'spec'")?;
    let usage = Usage::from_repr(str::parse::<i32>(
        iter.next().ok_or("not enough tokens in hash")?,
    )?)
    .ok_or("invalid value for 'usage'")?;
    let hash_algorithm = HashAlgorithm::from_repr(str::parse::<i32>(
        iter.next().ok_or("not enough tokens in hash")?,
    )?)
    .ok_or("invalid value for 'hash_algorithm'")?;
    let cipher_algorithm = CipherAlgorithm::from_repr(str::parse::<i32>(
        iter.next().ok_or("not enough tokens in hash")?,
    )?)
    .ok_or("invalid value for 'cipher_algorithm'")?;
    // IV only if not in symmetric mode
    let (iv_len, iv) = match algorithm {
        Algorithm::Unknown => (None, None),
        _ => {
            let iv_len = str::parse::<usize>(iter.next().ok_or("not enough tokens in hash")?)?;
            let iv = hex::decode(iter.next().ok_or("not enough tokens in hash")?)?;
            (Some(iv_len), Some(iv))
        }
    };
    // count/salt only if we have a salted hash
    let (count, salt_vec) = match spec {
        Spec::Simple => (None, None),
        _ => {
            let count = str::parse::<usize>(iter.next().ok_or("not enough tokens in hash")?)?;
            let salt_vec = hex::decode(iter.next().ok_or("not enough tokens in hash")?)?;
            (Some(count), Some(salt_vec))
        }
    };
    // handle extra data
    let extra_data = parse_extra_data(iter, usage, spec, algorithm)?;

    // checks
    if data.len() != data_len {
        return Err("data length does not match specified value".into());
    }
    if let Some(x) = &iv {
        if let Some(y) = iv_len {
            if x.len() != y {
                return Err("IV length does not match specified value".into());
            }
        }
    }
    let salt = match salt_vec {
        Some(v) => {
            if v.len() != 8 {
                return Err(format!(
                    "salt length does not match required value (is: {}, should be: 8)",
                    v.len()
                )
                .into());
            }
            let salt: [u8; 8] = v[..8].try_into()?;
            Some(salt)
        }
        None => None,
    };
    match algorithm {
        Algorithm::Unknown => {
            if ![Usage::Nine, Usage::Eighteen].contains(&usage) {
                return Err(
                    "for algorithm=Unknown (=0) (symmetric mode), usage must be either 9 or 18"
                        .into(),
                );
            }
        }
        _ => {
            if ![Usage::Zero, Usage::TwoFiveFour, Usage::TwoFiveFive].contains(&usage) {
                return Err(
                    "for algorithm != Unknown (not 0), usage must be either 0, 254 or 255".into(),
                );
            }
        }
    }

    // if we reach this point, everything is OK!
    Ok(PgpHash {
        algorithm,
        data_len,
        bits,
        data,
        spec,
        usage,
        hash_algorithm,
        cipher_algorithm,
        iv_len,
        iv,
        count,
        salt,
        extra_data,
    })
}
