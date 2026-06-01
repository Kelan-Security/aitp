#![no_main]
use aitp_core::header::AitpHeader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Throws arbitrary bytes at AitpHeader::from_bytes()
    // Must never panic — only return Err
    let _ = AitpHeader::from_bytes(data);
});
