#![no_main]
use aitp_identity::resolver::IdentityResolver;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut resolver = IdentityResolver::new();

    // Fuzz resolution with random entity IDs
    if data.len() >= 32 {
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[..32]);
        let _ = resolver.resolve(&id);
    }

    // Fuzz registration with potentially malformed data if we had a string parser
    // for entity IDs. For now, we test the core resolver logic.
    if let Ok(s) = std::str::from_utf8(data) {
        // Assume a hypothetical "parse hex" function is being fuzzed here
        let _ = hex_to_bytes32(s);
    }
});

fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return None;
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}
