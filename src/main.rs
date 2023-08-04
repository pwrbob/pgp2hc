use clap::{Parser, ValueEnum};
use pgp::{armor::Dearmor, packet::PacketParser};
use pgp2hc::{handle_packet, Artefact};
use std::{io::Read, path::PathBuf};

#[derive(Clone, Debug, ValueEnum)]
pub enum HashFormat {
    /// Format used by John the Ripper
    John,
    /// Format used by hashcat
    Hashcat,
}

#[derive(Parser)]
struct Cli {
    path: PathBuf,
    /// The format in which to output the hash
    #[clap(short, long, value_enum, default_value_t=HashFormat::Hashcat)]
    format: HashFormat,
    /// don't dearmor the given file
    #[clap(long)]
    _no_dearmor: bool,
}

fn main() {
    env_logger::init();
    let args = Cli::parse();

    eprintln!("\nFile {}", args.path.to_str().unwrap());
    let mut f = std::fs::File::open(&args.path).expect("could not open the specified file");
    let mut buf = Vec::new();
    let read_bytes = match args._no_dearmor {
        true => f.read_to_end(&mut buf),
        false => Dearmor::new(f).read_to_end(&mut buf),
    }
    .unwrap();
    log::info!("read {read_bytes} from file {:?}", args.path);

    let parser = PacketParser::new(&buf[..]);

    let mut hashes = Vec::new();
    let mut user = None;

    for item in parser {
        match item {
            Ok(packet) => {
                if let Some(art) = handle_packet(packet).unwrap() {
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
                        println!(
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
}
