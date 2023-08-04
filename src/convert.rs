use crate::hash::{Algorithm, CipherAlgorithm, HashAlgorithm, PgpHash, StringToKey, Usage};
use pgp::packet::SecretKey;
use std::error::Error;

/// This function gets everything needed to output a PgpHash:
/// - public parameters: yields algorithm and bits
/// - secret parameters: yields:
///   - data and length
///   - iv and length
///   - s2k parameters: s2k, usage, count, salt
///   - hash and cipher algorithms
pub(crate) fn secretkey_to_pgphash(key: SecretKey) -> Result<PgpHash, Box<dyn Error>> {
    let (algorithm, bits) = match key.public_params() {
        pgp::types::PublicParams::RSA { n, e: _ } => {
            (Algorithm::RSAEncSign, n.as_bytes().len() * 8)
        }
        pgp::types::PublicParams::DSA { p, q, g: _, y: _ } => (
            Algorithm::DSA,
            (p.as_bytes().len() + q.as_bytes().len()) * 8,
        ),
        pgp::types::PublicParams::ECDSA(params) => {
            let bits = match params {
                pgp::types::EcdsaPublicParams::P256 { key: _, p } => p.as_bytes().len() * 8,
                pgp::types::EcdsaPublicParams::P384 { key: _, p } => p.as_bytes().len() * 8,
                pgp::types::EcdsaPublicParams::Unsupported { curve: _, p } => {
                    p.as_bytes().len() * 8
                }
            };
            (Algorithm::ECDSA, bits)
        }
        pgp::types::PublicParams::ECDH {
            curve: _,
            p,
            hash: _,
            alg_sym: _,
        } => (Algorithm::EC, p.as_bytes().len() * 8),
        pgp::types::PublicParams::Elgamal { p, g: _, y: _ } => {
            (Algorithm::ElGamal, p.as_bytes().len() * 8)
        }
        pgp::types::PublicParams::EdDSA { curve: _, q } => (Algorithm::EC, q.as_bytes().len() * 8),
    };
    match key.secret_params() {
        pgp::types::SecretParams::Plain(_) => {
            Err("unexpectedly found plaintext secret parameters!".into())
        }
        pgp::types::SecretParams::Encrypted(params) => {
            let data = params.data().to_vec();
            let iv = Some(params.iv().to_vec());
            let iv_len = iv.as_ref().map(|z| z.len());
            let cipher_algorithm = CipherAlgorithm::try_from(params.encryption_algorithm())?;
            let usage = Usage::from_repr(params.string_to_key_id() as i32)
                .ok_or("invalid 'usage' parameter from string_to_key_id")?;

            let s2k_obj = params.string_to_key();
            let s2k = match s2k_obj.typ() {
                pgp::types::StringToKeyType::Simple => StringToKey::Simple,
                pgp::types::StringToKeyType::Salted => StringToKey::Salted,
                pgp::types::StringToKeyType::IteratedAndSalted => StringToKey::IteratedSalted,
                _ => return Err("invalid s2k type".into()),
            };
            let salt = match s2k_obj.salt() {
                None => None,
                Some(z) => z.try_into().ok(),
            };
            let hash_algorithm = match s2k_obj.hash() {
                pgp::crypto::hash::HashAlgorithm::MD5 => HashAlgorithm::MD5,
                pgp::crypto::hash::HashAlgorithm::SHA1 => HashAlgorithm::SHA1,
                pgp::crypto::hash::HashAlgorithm::RIPEMD160 => HashAlgorithm::RIPEMD160,
                pgp::crypto::hash::HashAlgorithm::SHA2_256 => HashAlgorithm::SHA256,
                pgp::crypto::hash::HashAlgorithm::SHA2_384 => HashAlgorithm::SHA384,
                pgp::crypto::hash::HashAlgorithm::SHA2_512 => HashAlgorithm::SHA512,
                pgp::crypto::hash::HashAlgorithm::SHA2_224 => HashAlgorithm::SHA224,
                // pgp::crypto::hash::HashAlgorithm::None => HashAlgorithm::Unknown,
                // pgp::crypto::hash::HashAlgorithm::SHA3_256 => HashAlgorithm::SHA3_256,
                // pgp::crypto::hash::HashAlgorithm::SHA3_512 => HashAlgorithm::SHA3_512,
                // pgp::crypto::hash::HashAlgorithm::Private10 => HashAlgorithm::Private10,
                _ => HashAlgorithm::Unknown,
            };

            Ok(PgpHash {
                algorithm,
                data_len: data.len(),
                bits: Some(bits),
                data,
                s2k,
                usage,
                hash_algorithm,
                cipher_algorithm,
                iv_len,
                iv,
                count: s2k_obj.count(),
                salt,
                extra_data: None,
            })
        }
    }
}
