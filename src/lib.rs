use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libmagic_rs as magic;

mod defaults;
mod digests;
mod entropy;

use magic::cookie::Flags;
