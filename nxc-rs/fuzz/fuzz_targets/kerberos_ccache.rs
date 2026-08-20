#![no_main]

use libfuzzer_sys::fuzz_target;
use nxc_auth::kerberos::ccache::parse_ccache_v4;
use std::io::Write;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    // Fuzz the parsing of Kerberos CCache files (v4)
    if let Ok(mut temp_file) = NamedTempFile::new() {
        let _ = temp_file.write_all(data);
        let path = temp_file.path().to_str().unwrap();
        let _ = parse_ccache_v4(path);
    }
});
