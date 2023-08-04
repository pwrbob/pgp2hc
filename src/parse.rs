use crate::hash::*;

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

pub fn parse_hash(input: &str) -> Result<PgpHash, Box<dyn std::error::Error>> {
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
        Algorithm::Symmetric => None,
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
        Algorithm::Symmetric => (None, None),
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
        Algorithm::Symmetric => {
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
