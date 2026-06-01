#![no_main]
use aitp_identity::token::PermitToken;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Throws arbitrary bytes at PermitToken::from_bytes()
    // Must never panic
    let _ = PermitToken::from_bytes(data);
});
