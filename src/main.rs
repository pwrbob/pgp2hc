use clap::Parser;
use pgp2hc::{extract_hash, Cli};

fn main() {
    env_logger::init();
    let args = Cli::parse();

    eprintln!("\nFile {}", args.path.to_str().unwrap());
    let output = extract_hash(&args).unwrap();
    println!("{}", output);
}
