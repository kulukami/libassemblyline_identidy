use std::path::Path;

use libassemblyline_identidy::*;
use walkdir;

use clap::Parser;

const ENABLE_HASH: u32 = 0b1000_0000;
const ENABLE_ENTROPY: u32 = 0b0000_0001;
const ENABLE_PARTITION_ENTROPY: u32 = 0b0000_0010;
const ENABLE_SSDEEP: u32 = 0b0000_0100;
const ENABLE_TLSH: u32 = 0b0000_1000;
const ENABLE_SHA256: u32 = 0b0001_0000;

const DEFAULT_FLAG: u32 = ENABLE_HASH
    | ENABLE_ENTROPY
    | ENABLE_PARTITION_ENTROPY
    | ENABLE_SSDEEP
    | ENABLE_TLSH
    | ENABLE_SHA256;

const FILE_TYPE_ONLY: u32 = 0;

/// Scanner command line tool
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Number of thread
    #[arg(short, long, default_value_t = DEFAULT_FLAG)]
    uflag: u32,

    // Timeout Hours
    #[arg(short, long, default_value_t = 100 * 1024 * 1024)]
    maxsize: u64,

    /// Number of times to greet
    #[arg(short, long)]
    full_path: String,
}

fn main() {
    let args = Args::parse();
    let gen_hash = (ENABLE_ENTROPY & args.uflag) == ENABLE_ENTROPY;

    let mut identifyer = Identify::new(
        args.maxsize,
        (ENABLE_ENTROPY & args.uflag) == ENABLE_ENTROPY,
        (ENABLE_PARTITION_ENTROPY & args.uflag) == ENABLE_PARTITION_ENTROPY,
        (ENABLE_SSDEEP & args.uflag) == ENABLE_SSDEEP,
        (ENABLE_TLSH & args.uflag) == ENABLE_TLSH,
        (ENABLE_SHA256 & args.uflag) == ENABLE_SHA256,
    );

    let target = Path::new(&args.full_path);
    if !target.exists() {
        println!("file not exist: {}", &args.full_path);
    }

    if target.is_file() {
        let id = identifyer.fileinfo(target.to_path_buf(), gen_hash).unwrap();
        println!("{:?}", serde_json::to_string(&id));

        match serde_json::to_string(&id) {
            Ok(id) => println!("{}", id),
            Err(e) => println!("scan {} : err :{}", &args.full_path, e),
        };
    } else if target.is_dir() {
        let mut it = walkdir::WalkDir::new(&args.full_path).into_iter();
        loop {
            let entry = match it.next() {
                None => break,
                Some(Err(_)) => {
                    continue;
                }
                Some(Ok(entry)) => entry,
            };
            if entry.path().is_dir() {
                continue;
            }
            let tfpath = entry.path().to_string_lossy().to_string();
            match identifyer.fileinfo((&tfpath).into(), gen_hash) {
                Ok(result) => {
                    match serde_json::to_string(&result) {
                        Ok(id) => println!("{}", id),
                        Err(e) => println!("scan {} : err :{}", &tfpath, e),
                    };
                }
                Err(e) => {
                    println!("scan {} : err :{}", &tfpath, e);
                }
            };
        }
    }
}
