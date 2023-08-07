/// Conversion of `pgp` data to a `PgpHash` structure.
mod convert;
/// Definition of a `PgpHash` data structure and related enums.
pub mod hash;
/// Functions related to parsing hashes in the john/hashcat format to the data structures defined in this crate
mod parse;
#[cfg(test)]
mod test;

use clap::{Parser, ValueEnum};
use convert::{secretkey_to_pgphash, secretsubkey_to_pgphash};
use hash::PgpHash;
pub use parse::parse_hash;
use pgp::{
    armor::Dearmor,
    packet::{Packet, PacketParser},
};
use std::{error::Error, io::Read, path::PathBuf};

#[derive(Debug)]
pub struct UserInfo {
    pub name: String,
    pub email: String,
}

pub enum Artefact {
    Hash(PgpHash),
    User(UserInfo),
}

#[derive(Clone, Debug, ValueEnum)]
pub enum HashFormat {
    /// Format used by John the Ripper
    John,
    /// Format used by hashcat
    Hashcat,
}

/// Extract hashcat/john hashes from encrypted secret keys in the OpenPGP format
#[derive(Parser)]
#[command(version)]
pub struct Cli {
    /// The file containing the encrypted secret key
    pub path: PathBuf,
    /// The format in which to output the hash
    #[clap(short, long, value_enum, default_value_t=HashFormat::Hashcat)]
    pub format: HashFormat,
    /// don't dearmor the given file
    #[clap(long)]
    pub _no_dearmor: bool,
    /// don't extract hashes from subkeys
    #[clap(long)]
    pub _no_subkeys: bool,
}

pub fn extract_hash(args: &Cli) -> Result<String, Box<dyn Error>> {
    let mut f = std::fs::File::open(&args.path).expect("could not open the specified file");
    let mut buf = Vec::new();
    let read_bytes = match args._no_dearmor {
        true => f.read_to_end(&mut buf),
        false => Dearmor::new(f).read_to_end(&mut buf),
    }
    .unwrap();
    log::info!("read {read_bytes} bytes from file {:?}", args.path);

    Ok(handle_file(&buf[..], &args))
}

fn handle_file(data: &[u8], args: &Cli) -> String {
    let mut ret = String::new();
    let parser = PacketParser::new(data);

    let mut hashes = Vec::new();
    let mut user = None;

    for item in parser {
        match item {
            Ok(packet) => {
                if let Some(art) = handle_packet(packet, args._no_subkeys).unwrap() {
                    match art {
                        Artefact::Hash(h) => hashes.push(h),
                        Artefact::User(u) => user = Some(u),
                    }
                }
            }
            Err(e) => eprintln!("Error getting a packet: {e}"),
        }
    }

    for h in hashes {
        match args.format {
            HashFormat::John => {
                //<username>:<hash>:::<name_with_email>::<filename>
                match &user {
                    Some(u) => {
                        let email_str = if u.email.len() > 0 {
                            String::from(" ") + &u.email
                        } else {
                            String::from("")
                        };
                        if ret.len() > 0 {
                            ret += "\n";
                        }
                        ret += &format!(
                            "{}:{h}:::{}{}::{}",
                            u.name,
                            u.name,
                            email_str,
                            args.path.to_str().unwrap()
                        );
                    }
                    None => {}
                }
            }
            HashFormat::Hashcat => println!("{h}"),
        }
    }

    ret
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
