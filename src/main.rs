use clap::Parser;
use pgp2hc::{extract_hash, Cli, HashFormat};

fn main() {
    env_logger::init();
    let args = Cli::parse();

    if let HashFormat::John = args.format {
        eprintln!("\nFile {}", args.path.to_str().unwrap());
    }
    let output = extract_hash(&args).unwrap();
    println!("{}", output);
}
