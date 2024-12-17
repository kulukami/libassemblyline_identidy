use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use digests::{Digester, Digests, DEFAULT_BLOCKSIZE};
use libmagic_rs::{cookie, Cookie};

use println as warn;
use println as info;
use println as error;
use serde::{Deserialize, Serialize};
use yara_x::Rule;
use zip::unstable::LittleEndianReadExt;

pub mod digests;
pub mod entropy;

pub mod defaults;
pub use defaults::*;

pub mod utils;
pub use utils::*;

const YARA_DEFAULT_EXTERNALS: [(&str, &str); 3] = [("mime", ""), ("magic", ""), ("type", "")];

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct FileIdentity {
    pub ascii: String,
    pub entropy: Option<f32>,
    pub partition_entropy: Option<Vec<f32>>,
    pub hex: String,
    pub m2md5: Option<String>,
    pub md5: Option<String>,
    pub magic: String,
    pub mime: Option<String>,
    pub sha256: Option<String>,
    pub size: u64,
    pub ssdeep: Option<String>,
    pub file_type: String,
    pub tlsh: Option<String>,
}

pub struct Identify {
    digester: Digester,
    cookie_file_type: Cookie<cookie::Load>,
    cookie_file_mime: Cookie<cookie::Load>,
    yara_rules: yara_x::Rules,
    custom: regex::Regex,
    trusted_mimes: HashMap<String, String>,
    compiled_magic_patterns: Vec<(String, regex::Regex)>,
}

impl Identify {
    // init with a hashset
    pub fn new(
        maxfilesize: u64,
        entropy: bool,
        partition_entropy: bool,
        ssdeep: bool,
        tlsh: bool,
        sha256: bool,
    ) -> Self {
        let cookie_file_type =
            Cookie::open(cookie::Flags::ERROR | cookie::Flags::COMPRESS | cookie::Flags::RAW)
                .unwrap();
        let cookie_file_mime = Cookie::open(
            cookie::Flags::ERROR
                | cookie::Flags::COMPRESS
                | cookie::Flags::RAW
                | cookie::Flags::MIME,
        )
        .unwrap();
        let database = ["magic.mgc", "default.magic"].try_into().unwrap();
        let cookie_file_type = cookie_file_type.load(&database).unwrap();
        let cookie_file_mime = cookie_file_mime.load(&database).unwrap();

        let mut compiler = yara_x::Compiler::new();
        for (var, value) in YARA_DEFAULT_EXTERNALS {
            compiler.define_global(var, value).unwrap();
        }

        let rulestr = std::fs::read_to_string("default.yara").unwrap();
        //compiler.define_global(ident, value)
        compiler.add_source(rulestr.as_str()).unwrap();
        let rules = compiler.build();

        return Self {
            cookie_file_type: cookie_file_type,
            cookie_file_mime: cookie_file_mime,
            yara_rules: rules,
            compiled_magic_patterns: Self::_load_magic_patterns().unwrap(),
            trusted_mimes: TRUSTED_MIMES
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            custom: regex::RegexBuilder::new("^custom: ")
                .ignore_whitespace(true)
                .build()
                .unwrap(),
            digester: Digester::new(
                maxfilesize,
                entropy,
                partition_entropy,
                ssdeep,
                tlsh,
                sha256,
            ),
        };
    }

    fn _load_magic_patterns() -> Result<Vec<(String, regex::Regex)>> {
        let mut magic_patterns: Vec<(Cow<str>, Cow<str>)> = MAGIC_PATTERNS
            .iter()
            .map(|(a, b)| ((*a).into(), (*b).into()))
            .collect();

        let mut compiled_patterns = vec![];
        for (al_type, pattern) in magic_patterns {
            match regex::RegexBuilder::new(&pattern)
                .case_insensitive(true)
                .build()
            {
                Ok(re) => compiled_patterns.push((al_type.into_owned(), re)),
                Err(err) => error!("Could not process regex for {al_type} [{pattern}] [{err}]"),
            }
        }
        Ok(compiled_patterns)
    }

    pub fn ident(&self, buf: &[u8], path: &Path, digests: Option<Digests>) -> Result<FileIdentity> {
        let mut file_type = "unknown".to_owned();
        let mut magic = String::new();
        let mut mime = None;

        if buf.is_empty() {
            return Ok(FileIdentity {
                ascii: "".to_string(),
                entropy: None,
                partition_entropy: None,
                hex: "".to_string(),
                m2md5: None,
                md5: None,
                magic: "".to_string(),
                mime: None,
                sha256: None,
                size: 0,
                ssdeep: None,
                file_type: "unknown".to_string(),
                tlsh: None,
            });
        }

        let header = &buf[0..64.min(buf.len())];
        let ascii = dotdump_bytes(header);

        //println!("DEBUG: ascii:{:?}", &ascii);

        let mut labels: Vec<String> = match self.cookie_file_type.file(path) {
            Ok(output) => output
                .split('\n')
                .map(|row| row.strip_prefix("- ").unwrap_or(row))
                .map(String::from)
                .collect(),
            Err(err) => {
                error!("Magic error: {err}");
                vec![]
            }
        };

        let mut mimes: Vec<String> = match self.cookie_file_mime.file(path) {
            Ok(output) => output
                .split('\n')
                .map(|row| row.strip_prefix("- ").unwrap_or(row))
                .map(String::from)
                .collect(),
            Err(err) => {
                error!("Magic error: {err}");
                vec![]
            }
        };

        if !labels.is_empty() {
            fn find_special_words(word: &str, labels: &[String]) -> Option<usize> {
                for (index, label) in labels.iter().enumerate() {
                    if label.contains(word) {
                        return Some(index);
                    }
                }
                None
            }

            // If an expected label is not the first label returned by Magic, then make it so
            // Manipulating the mime accordingly varies between special word cases
            let special_word_cases = [
                ("OLE 2 Compound Document : Microsoft Word Document", false),
                ("Lotus 1-2-3 WorKsheet", true),
            ];
            for (word, alter_mime) in special_word_cases {
                if let Some(index) = find_special_words(word, &labels) {
                    let moved_item = labels.remove(index);
                    labels.insert(0, moved_item);
                    if labels.len() == mimes.len() && alter_mime {
                        let moved_item = mimes.remove(index);
                        mimes.insert(0, moved_item);
                    }
                }
            }
            if let Some(label) = labels.first() {
                magic = label.to_string();
            }
        }

        for possible_mime in &mimes {
            if !possible_mime.is_empty() {
                mime = Some(possible_mime.to_string());
                break;
            }
        }

        // First lets try to find any custom types
        for label in &labels {
            let label = dotdump(label);

            if self.custom.is_match(&label) {
                // Some things, like executable have additional data appended to their identification, like
                // ", dynamically linked, stripped" that we do not want to use as part of the type.

                if let Some(item) = label.split("custom: ").nth(1) {
                    if let Some((front, _tail)) = item.split_once(",") {
                        file_type = front.trim().to_owned();
                        break;
                    }
                }
            }
        }

        // Second priority is mime times marked as trusted
        if file_type == "unknown" {
            for mime in &mimes {
                let mime = dotdump(mime);

                if let Some(new_type) = self.trusted_mimes.get(&mime) {
                    file_type = new_type.to_owned();
                    break;
                }
            }
        }

        // As a third priority try matching the magic_patterns
        if file_type == "unknown" {
            'labels: for label in labels {
                for (new_type, pattern) in self.compiled_magic_patterns.iter() {
                    if pattern.find(&dotdump(&label)).is_some() {
                        file_type = new_type.to_string();
                        break 'labels;
                    }
                }
            }
        }

        // If mime is text/* and type is unknown, set text/plain to trigger
        // language detection later.
        if let Some(mime) = &mime {
            if file_type == "unknown" && mime.starts_with("text/") {
                file_type = "text/plain".to_string();
            }
        }

        // Lookup office documents by GUID if we're still not sure what they are
        if file_type == "document/office/unknown" {
            // following byte sequence equivalent to "Root Entry".encode("utf-16-le") in python
            let root_entry_lit: [u8; 20] = [
                82, 0, 111, 0, 111, 0, 116, 0, 32, 0, 69, 0, 110, 0, 116, 0, 114, 0, 121, 0,
            ];
            if let Some(root_entry_property_offset) = find_subsequence(buf, &root_entry_lit) {
                // Get root entry's GUID and try to guess document type
                let clsid_offset = root_entry_property_offset + 0x50;
                if buf.len() >= clsid_offset + 16 {
                    let clsid: [u8; 16] = buf[clsid_offset..clsid_offset + 16].try_into()?;
                    if clsid != vec![0; clsid.len()].as_slice() {
                        // b"\0" * clsid.len()
                        let clsid = uuid::Uuid::from_bytes_le(clsid);
                        // clsid_str = clsid_str.urn.rsplit(":", 1)[-1].upper();
                        if let Some(value) = ole_clsid_guids().get(&clsid) {
                            file_type = value.to_string();
                        }
                    } else {
                        // byte sequence matching "Details".encode("utf-16-le") in python
                        let details: [u8; 14] =
                            [68, 0, 101, 0, 116, 0, 97, 0, 105, 0, 108, 0, 115, 0];
                        let bup_details_offset =
                            find_subsequence(&buf[..root_entry_property_offset + 0x100], &details);
                        if bup_details_offset.is_some() {
                            file_type = "quarantine/mcafee".to_string();
                        }
                    }
                }
            }
        }

        let (m2md5, md5, sha256, size, ssdeep, tlsh, entropy, partition_entropy) =
            if let Some(digests) = digests {
                let Digests {
                    md5,
                    m2md5,
                    sha256,
                    ssdeep,
                    tlsh,
                    size,
                    entropy,
                    partition_entropy,
                    ..
                } = digests;
                (
                    Some(m2md5),
                    Some(md5),
                    sha256,
                    size,
                    ssdeep,
                    tlsh,
                    entropy,
                    partition_entropy,
                )
            } else {
                (None, None, None, 0, None, None, None, None)
            };

        Ok(FileIdentity {
            magic,
            md5,
            m2md5,
            mime,
            sha256,
            size,
            ssdeep,
            tlsh,
            file_type,
            ascii,
            entropy: entropy,
            partition_entropy: partition_entropy,
            hex: hex::encode(header),
        })
    }

    pub fn yara_ident(&self, path: &Path, info: &FileIdentity) -> Result<Option<String>> {
        let mut scanner = yara_x::Scanner::new(&self.yara_rules);
        scanner.set_global("mime", info.mime.as_deref().unwrap_or(""))?;
        scanner.set_global("magic", info.magic.as_str())?;
        scanner.set_global("type", info.file_type.as_str())?;
        let results = scanner.scan_file(path)?;

        let mut scan_matches = match scanner.scan_file(path) {
            Ok(scan_matches) => scan_matches,
            Err(err) => {
                warn!("Yara file identifier failed with error: {err}");
                return Ok(None);
            }
        };
        let mut matches: Vec<Rule> = scan_matches.matching_rules().into_iter().collect();

        matches.sort_by_key(|rule| {
            for meta in rule.metadata() {
                if let yara_x::MetaValue::Integer(score) = meta.1 {
                    return score;
                }
            }
            return 0;
        });

        while let Some(rule) = matches.pop() {
            for meta in rule.metadata() {
                if meta.0 == "type" {
                    if let yara_x::MetaValue::String(file_type) = meta.1 {
                        return Ok(Some(file_type.to_owned()));
                    }
                }
            }
        }
        return Ok(None);
    }

    pub fn fileinfo(&mut self, path: PathBuf, generate_hashes: bool) -> Result<FileIdentity> {
        let mut data: FileIdentity = if generate_hashes {
            let mut digests = self.digester.scan(&path)?;
            let mut first_block = vec![];
            std::mem::swap(&mut first_block, &mut digests.first_block);
            //println!("DEBUG: first_block:{:?}", &first_block);
            self.ident(&first_block, &path, Some(digests))?
        } else {
            let mut file = std::fs::File::open(&path)?;
            let size = file.metadata()?.len();
            let to_read = size.min(DEFAULT_BLOCKSIZE as u64);
            let mut first_block = vec![0u8; to_read as usize];
            file.read_exact(&mut first_block)?;

            let mut data = self.ident(&first_block, &path, None)?;
            data.size = size;
            data
        };

        // Check if file empty
        if data.size == 0 {
            data.file_type = "empty".to_string();

        // Futher identify zip files based of their content
        } else if ["archive/zip", "java/jar", "document/office/unknown"]
            .contains(&data.file_type.as_str())
        {
            data.file_type = zip_ident(&path, data.file_type)?;

        // Further identify dos executables has this may be a PE that has been misidentified
        } else if data.file_type == "executable/windows/dos" {
            data.file_type = dos_ident(&path)?;

        // If we're so far failed to identified the file, lets run the yara rules
        } else if data.file_type.contains("unknown") {
            if let Some(new_type) = self.yara_ident(&path, &data)? {
                data.file_type = new_type;
            }
        } else if data.file_type == "text/plain" {
            // Check if the file is a misidentified json first before running the yara rules
            let body = std::fs::read_to_string(&path)?;
            if serde_json::from_str::<serde_json::Value>(&body).is_ok() {
                data.file_type = "text/json".to_string();
            } else if let Some(new_type) = self.yara_ident(&path, &data)? {
                data.file_type = new_type;
            }
        }

        return Ok(data);
    }
}

fn zip_ident(path: &Path, fallback: String) -> Result<String> {
    let file_list: Vec<String> = {
        match zip::ZipArchive::new(std::fs::File::open(path)?) {
            Ok(zip_file) => zip_file.file_names().map(str::to_string).collect(),
            Err(_) => return Ok(fallback),
        }
    };

    let tot_files = file_list.len();
    let mut tot_class = 0;
    let mut tot_jar = 0;

    let mut is_ipa = false;
    let mut is_jar = false;
    let mut is_word = false;
    let mut is_excel = false;
    let mut is_ppt = false;
    let mut doc_props = false;
    let mut doc_rels = false;
    let mut doc_types = false;
    let mut android_manifest = false;
    let mut android_dex = false;
    let mut nuspec = false;
    let mut psmdcp = false;

    for file_name in file_list {
        // Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_jar.yara#L11
        if file_name.starts_with("META-INF/") {
            is_jar = true;
        } else if file_name == "AndroidManifest.xml" {
            android_manifest = true;
        } else if file_name == "classes.dex" {
            android_dex = true;
        } else if file_name.starts_with("Payload/") && file_name.ends_with(".app/Info.plist") {
            is_ipa = true;
        } else if file_name.ends_with(".nuspec") {
            nuspec = true;
        } else if file_name.starts_with("package/services/metadata/core-properties/")
            && file_name.ends_with(".psmdcp")
        {
            psmdcp = true;
        } else if file_name.ends_with(".class") {
            tot_class += 1
        } else if file_name.ends_with(".jar") {
            tot_jar += 1
        } else if file_name.starts_with("word/") {
            is_word = true;
        } else if file_name.starts_with("xl/") {
            is_excel = true;
        } else if file_name.starts_with("ppt/") {
            is_ppt = true;
        } else if file_name.starts_with("docProps/") {
            doc_props = true;
        } else if file_name.starts_with("_rels/") {
            doc_rels = true;
        // Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_office_open_xml.yara
        } else if file_name == "[Content_Types].xml" {
            doc_types = true;
        }
    }

    if 0 < tot_files && tot_files < (tot_class + tot_jar) * 2 {
        is_jar = true;
    }

    if is_jar && android_manifest && android_dex {
        return Ok("android/apk".to_string());
    } else if is_ipa {
        return Ok("ios/ipa".to_string());
    } else if is_jar {
        return Ok("java/jar".to_string());
    } else if (doc_props || doc_rels) && doc_types {
        if is_word {
            return Ok("document/office/word".to_string());
        } else if is_excel {
            return Ok("document/office/excel".to_string());
        } else if is_ppt {
            return Ok("document/office/powerpoint".to_string());
        } else if nuspec && psmdcp {
            // It is a nupkg file. Identify as archive/zip for now.
            return Ok("archive/zip".to_string());
        } else {
            return Ok("document/office/unknown".to_string());
        }
    } else {
        return Ok("archive/zip".to_string());
    }
}

fn dos_ident(path: &Path) -> Result<String> {
    match _dos_ident(path) {
        Ok(Some(label)) => return Ok(label),
        Err(err) if err.kind() != std::io::ErrorKind::UnexpectedEof => return Err(err.into()),
        _ => {}
    };
    Ok("executable/windows/dos".to_string())
}

fn _dos_ident(path: &Path) -> Result<Option<String>, std::io::Error> {
    let mut fh = std::io::BufReader::new(std::fs::File::open(path)?);

    // file_header = fh.read(0x40)
    let mut file_header = vec![0u8; 0x40];
    fh.read_exact(&mut file_header)?;
    if &file_header[0..2] != b"MZ" {
        return Ok(None);
    }

    let header_pos_array: [u8; 4] = file_header[file_header.len() - 4..].try_into().unwrap();
    let header_pos = u32::from_le_bytes(header_pos_array);
    fh.seek(SeekFrom::Start(header_pos as u64))?;
    let mut sign_buffer = vec![0u8; 4];
    fh.read_exact(&mut sign_buffer)?;
    if sign_buffer != b"PE\x00\x00" {
        return Ok(None);
    }

    // (machine_id,) = struct.unpack("<H", fh.read(2))
    let machine_id = fh.read_u16_le()?;
    let width = if machine_id == 0x014C {
        32
    } else if machine_id == 0x8664 {
        64
    } else {
        return Ok(None);
    };

    // (characteristics,) = struct.unpack("<H", fh.read(18)[-2:])
    fh.seek(SeekFrom::Current(16))?;
    let characteristics = fh.read_u16_le()?;
    let pe_type = if (characteristics & 0x2000) != 0 {
        "dll"
    } else if (characteristics & 0x0002) != 0 {
        "pe"
    } else {
        return Ok(None);
    };
    return Ok(Some(format!("executable/windows/{pe_type}{width}")));
}
