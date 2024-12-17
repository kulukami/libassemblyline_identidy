use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use ssdeep::Generator;
use std::{
    cmp::min,
    hash::Hasher,
    io::Read,
    path::{Path, PathBuf},
};

use md5;
use sha2::Digest;

use super::entropy::{Entropy, EntropyBuckets};

pub const DEFAULT_BLOCKSIZE: usize = 65536;
pub const MAXFILESIZE_MD5_M2: usize = 2 * 1024 * 1024;

#[derive(Default)]
pub struct Digests {
    pub md5: String,
    pub m2md5: String,
    pub exehash: String,
    pub sha256: Option<String>,
    pub ssdeep: Option<String>,
    pub tlsh: Option<String>,
    pub size: u64,
    pub entropy: Option<f32>,
    pub partition_entropy: Option<Vec<f32>>,
    pub first_block: Vec<u8>,
}

pub struct Digester {
    m2buffer: Vec<u8>,
    maxfilesize: u64,
    entropy: bool,
    partition_entropy: bool,
    ssdeep: bool,
    tlsh: bool,
    sha256: bool,
}

impl Digester {
    pub fn new(
        maxfilesize: u64,
        entropy: bool,
        partition_entropy: bool,
        ssdeep: bool,
        tlsh: bool,
        sha256: bool,
    ) -> Self {
        return Self {
            m2buffer: vec![0u8; MAXFILESIZE_MD5_M2],
            maxfilesize: maxfilesize,
            entropy: entropy,
            partition_entropy: partition_entropy,
            ssdeep: ssdeep,
            tlsh: tlsh,
            sha256: sha256,
        };
    }
    pub fn scan(&mut self, fpath: &PathBuf) -> Result<Digests> {
        let mut f = std::fs::File::open(fpath)?;
        let m = f.metadata()?;
        let mut result = Digests::default();

        let filesize = m.len();
        result.size = filesize;
        if filesize == 0 {
            return Ok(result);
        }

        let mut f_entropy_hasher = match self.entropy & (self.maxfilesize >= filesize) {
            true => Some(Entropy::new(filesize as _)),
            false => None,
        };
        let mut b_entropy_hasher = match self.partition_entropy & (self.maxfilesize >= filesize) {
            true => Some(EntropyBuckets::new(filesize as _)),
            false => None,
        };
        let mut ssdeep_generator = match self.ssdeep & (self.maxfilesize >= filesize) {
            true => Some(Generator::new()),
            false => None,
        };
        let mut tlsh_hasher = match self.tlsh & (self.maxfilesize >= filesize) {
            true => Some(tlsh2::TlshDefaultBuilder::new()),
            false => None,
        };
        let mut sha256_hasher = match self.sha256 & (self.maxfilesize >= filesize) {
            true => Some(sha2::Sha256::new()),
            false => None,
        };
        let mut md5_context = md5::Context::new();
        let mut xxhasher = twox_hash::XxHash64::default();
        xxhasher.write_u64(filesize);

        loop {
            let read_count = f.read(&mut self.m2buffer)?;
            if read_count == 0 {
                break;
            } else {
                if result.first_block.len() < DEFAULT_BLOCKSIZE {
                    let copyN = min(DEFAULT_BLOCKSIZE - result.first_block.len(), read_count);
                    self.m2buffer[..copyN]
                        .iter()
                        .for_each(|raw| result.first_block.push(raw.to_owned()));
                }
                md5_context.consume(&self.m2buffer[..read_count]);

                if let Some(ref mut inner) = &mut sha256_hasher {
                    inner.update(&self.m2buffer[..read_count]);
                }

                if let Some(ref mut inner) = tlsh_hasher {
                    inner.update(&self.m2buffer[..read_count]);
                }

                if let Some(ref mut inner) = ssdeep_generator {
                    inner.update(&self.m2buffer[..read_count]);
                }

                if let Some(ref mut inner) = f_entropy_hasher {
                    inner.update(&self.m2buffer[..read_count]);
                }

                if let Some(ref mut inner) = b_entropy_hasher {
                    inner.update(&self.m2buffer[..read_count]);
                }

                if result.m2md5.len() == 0 {
                    result.m2md5 = format!("{:x}", &md5_context.clone().compute());
                    match read_count {
                        1..=32768 => {
                            xxhasher.write(&self.m2buffer[..read_count]);
                        }
                        _ => {
                            xxhasher.write(&self.m2buffer[..32768]);
                        }
                    };
                    result.exehash = hex::encode(xxhasher.finish().to_be_bytes()).to_string();
                    if self.maxfilesize < filesize {
                        /*
                        if let Some(inner) = &tlsh_hasher {
                            if let Some(tlshsum) = inner.build() {
                                if let Ok(s) = std::str::from_utf8(tlshsum.hash().as_slice()) {
                                    result.tlsh = Some(s.to_string());
                                }
                            }
                        }

                        if let Some(inner) = &ssdeep_generator {
                            if let Ok(ssdeepsum) = inner.finalize() {
                                result.ssdeep = Some(ssdeepsum.to_string());
                            }
                        }

                        if let Some(inner) = &f_entropy_hasher {
                            result.entropy = Some(inner.finalize());
                        }

                        if let Some(inner) = &b_entropy_hasher {
                            result.partition_entropy = Some(format!("{:?}", inner.finalize()));
                        }
                         */

                        return Ok(result);
                    }
                }
            }
        }

        result.md5 = format!("{:x}", md5_context.compute());
        if let Some(ref mut inner) = tlsh_hasher {
            if let Some(tlshsum) = inner.build() {
                if let Ok(s) = std::str::from_utf8(tlshsum.hash().as_slice()) {
                    result.tlsh = Some(s.to_string());
                }
            }
        }

        if let Some(ref mut inner) = ssdeep_generator {
            if let Ok(ssdeepsum) = inner.finalize() {
                result.ssdeep = Some(ssdeepsum.to_string());
            }
        }

        if let Some(ref mut inner) = &mut sha256_hasher {
            result.sha256 = Some(hex::encode(inner.to_owned().finalize().as_slice()));
        }

        if let Some(ref mut inner) = f_entropy_hasher {
            result.entropy = Some(inner.finalize());
        }

        if let Some(ref mut inner) = b_entropy_hasher {
            result.partition_entropy = Some(inner.finalize());
        }
        return Ok(result);
    }
}
