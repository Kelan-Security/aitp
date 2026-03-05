#![no_main]
use aitp_core::handshake::HandshakeMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Throws arbitrary bytes at HandshakeMessage::from_bytes()
    // Must never panic
    let _ = HandshakeMessage::from_bytes(data);
});
