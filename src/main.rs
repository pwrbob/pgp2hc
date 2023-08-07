use clap::Parser;
use pgp::armor::Dearmor;
use pgp2hc::{handle_file, Cli};
use std::io::Read;

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
    log::info!("read {read_bytes} bytes from file {:?}", args.path);

    let output = handle_file(&buf[..], &args);
    println!("{}", output);
}
