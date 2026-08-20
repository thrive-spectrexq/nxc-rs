#![no_main]

use libfuzzer_sys::fuzz_target;
use nxc_auth::ntlm::NtlmTargetInfo;

fuzz_target!(|data: &[u8]| {
    // Fuzz the NTLM Target Info parser to ensure it never panics on arbitrary binary input
    let _ = NtlmTargetInfo::parse(data);
});
