/// Conversion of `pgp` data to a `PgpHash` structure.
mod convert;
/// Definition of a `PgpHash` data structure and related enums.
pub mod hash;
/// Functions related to parsing hashes in the john/hashcat format to the data structures defined in this crate
mod parse;
#[cfg(test)]
mod test;

use convert::{secretkey_to_pgphash, secretsubkey_to_pgphash};
use hash::PgpHash;
pub use parse::parse_hash;
use pgp::packet::Packet;
use std::error::Error;

#[derive(Debug)]
pub struct UserInfo {
    pub name: String,
    pub email: String,
}

pub enum Artefact {
    Hash(PgpHash),
    User(UserInfo),
}

pub fn handle_packet(packet: Packet, no_subkeys: bool) -> Result<Option<Artefact>, Box<dyn Error>> {
    Ok(match packet {
        Packet::SecretKey(x) => Some(Artefact::Hash(secretkey_to_pgphash(x)?)),
        Packet::SecretSubkey(x) => match no_subkeys {
            true => None,
            false => Some(Artefact::Hash(secretsubkey_to_pgphash(x)?)),
        },
        Packet::Signature(_) => {
            log::info!("ignoring Signature packet");
            None
        }
        Packet::Trust(_) => {
            log::info!("ignoring Trust packet");
            None
        }
        Packet::UserId(x) => {
            let mut name = x.id().to_string().trim().to_string();
            Some(Artefact::User(match name.find('<') {
                None => UserInfo {
                    name,
                    email: String::new(),
                },
                Some(i) => {
                    let email = name.split_off(i);
                    let name = name.trim();
                    UserInfo {
                        name: name.trim().to_owned(),
                        email,
                    }
                }
            }))
        }
        // Packet::UserAttribute(_) => todo!(),
        // Packet::SymEncryptedData(_) => todo!(),
        // Packet::SymEncryptedProtectedData(_) => todo!(),
        // Packet::SymKeyEncryptedSessionKey(_) => todo!(),
        // Packet::LiteralData(_) => todo!(),
        // Packet::Marker(_) => todo!(),
        // Packet::ModDetectionCode(_) => todo!(),
        // Packet::OnePassSignature(_) => todo!(),
        // Packet::PublicKeyEncryptedSessionKey(_) => todo!(),
        // Packet::CompressedData(_) => todo!(),
        // Packet::PublicKey(_) => todo!(),
        // Packet::PublicSubkey(_) => todo!(),
        _ => {
            log::info!("ignoring unhandled packet");
            None
        }
    })
}
