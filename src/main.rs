use clap::Parser;
use pgp::{armor::Dearmor, packet::PacketParser};
use pgp2hc::{handle_packet, Artefact};
use std::{io::Read, path::PathBuf};

#[derive(Parser)]
struct Cli {
    path: PathBuf,
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
            Err(e) => println!("error getting packet: {e}"),
        }
    }

    for h in hashes {
        //<username>:<hash>:::<name_with_email>::<filename>
        if let Some(u) = &user {
            println!(
                "{}:{h}:::{} {}::{}",
                u.name,
                u.name,
                u.email,
                args.path.to_str().unwrap()
            );
        } else {
            println!("{h}");
        }
    }
}
