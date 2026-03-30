# Gemini API Tests — TODO (Requires Paid API Access)

The following tests currently gracefully skip on **429 rate limit** errors
because we're on the free tier. Once we have proper paid API access,
these tests should be hardened to **always assert real responses**.

## Tests to Update

### `test_gemini_responds_within_4000ms`
- **File**: `gemini_integration_test.rs`
- **Current**: Passes silently on 429
- **TODO**: Remove the 429 skip path — assert that the API always responds within 4000ms

### `test_gemini_cache_hit_is_fast`
- **File**: `gemini_integration_test.rs`
- **Current**: Returns early on 429 (can't populate cache)
- **TODO**: Remove the early return — assert cache hit < 100µs always works

## New Tests to Add

- [ ] **Retry on 429**: Test that the client retries with exponential backoff on rate limits
- [ ] **Concurrent burst test**: Fire 50 evaluations simultaneously, verify all complete within budget
- [ ] **Cache TTL expiry**: Wait for `cache_ttl_secs` to elapse, verify cache miss triggers a fresh API call
- [ ] **Model fallback**: If `gemini-2.5-flash` is unavailable, fall back to `gemini-1.5-flash`
- [ ] **Malformed response handling**: Inject a response where Gemini returns invalid JSON (non-strict schema)
- [ ] **Token budget test**: Verify prompt + response stays under token limits for billing predictability

## How to Run

```bash
AITP_AI_ENGINE_GEMINI_API_KEY="<your-paid-key>" cargo test -p aitp-ai-engine --test gemini_integration_test -- --include-ignored --nocapture
```
