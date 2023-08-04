use pgp::{
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::*,
    Deserializable, SignedSecretKey,
};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use std::{fs::File, io::Read, path::Path};

fn read_file<P: AsRef<Path> + ::std::fmt::Debug>(path: P) -> File {
    // Open the path in read-only mode, returns `io::Result<File>`
    match File::open(&path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {path:?}: {why}"),
        Ok(file) => file,
    }
}

#[test]
fn encrypted_private_key() {
    let p = Path::new("./data/gnupg-v1-001-decrypt.asc");
    let mut file = read_file(p.to_path_buf());

    let mut buf = vec![];
    file.read_to_end(&mut buf).unwrap();

    let input = ::std::str::from_utf8(buf.as_slice()).expect("failed to convert to string");
    let (key, _headers) = SignedSecretKey::from_string(input).expect("failed to parse key");
    key.verify().expect("invalid key");

    let pub_key = key.public_key();
    assert_eq!(pub_key.key_id(), key.key_id());

    let pp = key.primary_key.secret_params().clone();

    match pp {
        SecretParams::Plain(_) => panic!("should be encrypted"),
        SecretParams::Encrypted(pp) => {
            assert_eq!(
                pp.iv(),
                &hex::decode("2271f718af70d3bd9d60c2aed9469b67").unwrap()[..]
            );

            assert_eq!(
                pp.string_to_key().salt().unwrap(),
                &hex::decode("CB18E77884F2F055").unwrap()[..]
            );

            assert_eq!(pp.string_to_key().typ(), StringToKeyType::IteratedAndSalted);

            assert_eq!(pp.string_to_key().count(), Some(65536));

            assert_eq!(pp.string_to_key().hash(), HashAlgorithm::SHA2_256);

            assert_eq!(pp.encryption_algorithm(), SymmetricKeyAlgorithm::AES128);
            assert_eq!(pp.string_to_key_id(), 254);
        }
    }

    key.unlock(
        || "test".to_string(),
        |k| {
            println!("{:?}", k);
            match k {
                SecretKeyRepr::RSA(k) => {
                    assert_eq!(k.e().to_bytes_be(), hex::decode("010001").unwrap().to_vec());
                    assert_eq!(k.n().to_bytes_be(), hex::decode("9AF89C08A8EA84B5363268BAC8A06821194163CBCEEED2D921F5F3BDD192528911C7B1E515DCE8865409E161DBBBD8A4688C56C1E7DFCF639D9623E3175B1BCA86B1D12AE4E4FBF9A5B7D5493F468DA744F4ACFC4D13AD2D83398FFC20D7DF02DF82F3BC05F92EDC41B3C478638A053726586AAAC57E2B66C04F9775716A0C71").unwrap().to_vec());
                    assert_eq!(k.d().to_bytes_be(), hex::decode("33DE47E3421E1442CE9BFA9FA1ACC68D657594604FA7719CC91817F78D604B0DA38CD206D9D571621C589E3DF19CA2BB0C5F045EAC2C25AEB2BCE0D00E2E29538F8239F8A499EAF872497809E524A9EDA88E7ECEE78DF722E33DD62C9E204FE0F90DCF6F4247D1F7C8CE3BB3F0A4BAB23CFD95D41BC8A39C22C99D5BC38BC51D").unwrap().to_vec());
                    assert_eq!(k.primes()[0].to_bytes_be(), hex::decode("C62B8CD033331BFF171188C483B5B87E41A84415A004A83A4109014A671A5A3DA0A467CDB786F0BB75354245DA0DFFF53B6E25A44E28CBFF8CC1AC58A968AF57").unwrap().to_vec());
                    assert_eq!(k.primes()[1].to_bytes_be(), hex::decode("C831D89F49E642383C115413B2CB5F6EC09012B50C1E8596877E8F7B88C82C8F14FC354C21B6032BEF78B3C5EC92E434BEB2436B12C7C9FEDEFD866678DBED77").unwrap().to_vec());
                }
                _ => panic!("wrong key format"),
            }
            Ok(())
        },
    ).unwrap();
}
