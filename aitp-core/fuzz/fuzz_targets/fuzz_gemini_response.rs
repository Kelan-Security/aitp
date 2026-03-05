#![no_main]
use aitp_ai_engine::gemini_client::GeminiTrustResult;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Gemini response is JSON. Fuzz the JSON parser.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<GeminiTrustResult>(s);
    }
});
