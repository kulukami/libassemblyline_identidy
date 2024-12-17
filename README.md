# libassemblyline_identidy

File Type Identifier, Mainly from [assemblyline-rust/assemblyline-server/src/identify](https://github.com/CybercentreCanada/assemblyline-rust/tree/main/assemblyline-server/src/identify)




# Cargo Dependencies
```cargo
[dependencies]
libassemblyline_identidy = { git = "https://github.com/kulukami/libassemblyline_identidy.git", branch = 'main' }
```

# Example
[test/src/main.rs](test/src/main.rs)
```rust
use std::path::Path;
use libassemblyline_identidy::*;

let target = Path::new("/bin/ls");
let mut identifyer = Identify::new(
        1024*1024*100,
        true,
        true,
        true,
        true,
        true,
    );

let id = identifyer.fileinfo(target.to_path_buf(), true).unwrap();

```
