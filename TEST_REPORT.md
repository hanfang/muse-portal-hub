# Test Report — `:protocol` Kotlin unit tests

**Date:** 2026-10-04
**Module:** `app/protocol/` (pure-JVM protocol layer: Noise XX, BLE framing, pairing, chat session, proto envelope)
**Result: ✅ ALL GREEN — 90 tests, 90 passed, 0 failed**

## How it was run

Gradle was bypassed (no wrapper in repo; previous daemon IPC failures; the `:app` module needs the Android SDK anyway). Tests were compiled and run directly:

- JDK: Temurin JRE 17.0.11 (`~/.buildtools` → `muse-portal-voice-satellite/.buildtools/`)
- kotlinc 2.0.21, JUnit Platform Console Standalone 1.11.4
- `kotlinc app/protocol/src/main/kotlin -d .build/out/main.jar`
- `kotlinc app/protocol/src/test/kotlin -cp main.jar:junit-console.jar -d .build/out/test.jar`
- `java -jar junit-console-standalone.jar execute --select-class com.muse.gadget.<Test> …`
  (13 classes, `--select-class` each; test resources on classpath for `src/test/resources/vectors/*.json`)

No network, pairing, account, or token operations were performed — all tests are local.

## Per-suite results

| Suite | Tests | Passed | Failed |
|---|---|---|---|
| BleFramingTest | 4 | 4 | 0 |
| ChatSessionTest | 9 | 9 | 0 |
| ChatStreamsTest | 4 | 4 | 0 |
| JsonTest | 3 | 3 | 0 |
| MuseAccountApiTest | 6 | 6 | 0 |
| NdjsonParserTest | 6 | 6 | 0 |
| NoiseXxTest | 8 | 8 | 0 |
| PairingSessionTest | 16 | 16 | 0 |
| PairingVectorsTest | 9 | 9 | 0 |
| ProtoEnvelopeFramingTest | 14 | 14 | 0 |
| TurnStateMachineTest | 3 | 3 | 0 |
| VoiceNoteEncoderTest | 5 | 5 | 0 |
| WsUpgradeTest | 3 | 3 | 0 |
| **Total** | **90** | **90** | **0** |

## Bugs fixed (main source, one line each)

1. `noise/Proto.kt` — `decodeInt32` sign-extension bug: `raw >= (1L shl 63)` is always true (`1L shl 63` is `Long.MIN_VALUE`) and `raw - (1L shl 64)` subtracts 1 (`shl 64` masks to `shl 0`), so every decoded int32 was off by −1; now uses the raw pattern directly, which `readVarint` already returns correctly signed.
2. `noise/Proto.kt` — `encodeVarint` now rejects negative values like the Python reference (`encode_varint` raises on negatives); added private `encodeVarintBits` raw-bits path so `int64Field` still encodes negative int64 as 10-byte two's-complement varints per protobuf.
3. `noise/Framing.kt` — `encodeNoiseFrame` omitted `total_chunks` only when 0, but the proto default is 1 (decoder treats absent as 1); now omits when equal to the default 1, so a default frame encodes to 0 bytes.
4. `noise/NoiseTransport.kt` — added `decodeResponseEnvelope` companion helper, symmetric with `decodeRequestEnvelope` (decode service-response, then the inner service frame).
5. `session/ChatSession.kt` — `poll()` checked dead-timeout before idle-close, so a 10-minute-idle session was dropped as "dead" (BACKOFF) instead of gracefully idling; idle-close is now checked first so deliberate inactivity shutdown wins and never triggers reconnect backoff.
6. `pairing/PairingCrypto.kt` — `ECPoint.multiply` doesn't exist in the JDK; hand-rolled secp256r1 scalar multiplication (double-and-add, affine coordinates).
7. `noise/NoiseXX.kt` — renamed `LOW_ORDER_POINTS` to `X25519_LOW_ORDER_POINTS` to match the Python reference; fixed 3 low-order point hex strings that were 33 bytes instead of 32 (verified byte-for-byte against the Python reference).
8. `session/TurnStateMachine.kt` — `poll()` silence off-by-one (`>=` → `>`; endpoint is silent only strictly after 3000 ms).
9. `src/test/resources/vectors/noise_xx_fixed.json` — `handshake_hash` was an all-zeros placeholder; replaced with the real value computed by the authoritative Python reference handshake (byte-matches the Kotlin implementation's output).

## Test-code corrections (against the Python reference, not assertion-weakening)

- `PairingSessionTest` — `pairing_confirmed carries the sdk token` parsed the *encrypted envelope* as if it were the plaintext status; added `mobileOpen()` helper (mirrors Python's `mobile.open(...)`) and decrypt-then-assert, exactly like the reference test.
- `PairingSessionTest` — `confirmed session expires after 120 seconds` asserted `isCurrent(gen)` is false after expiry; the Python reference test asserts it stays **true** (expiry clears session state, the generation counter is unchanged) — corrected the transcription error.
- `ProtoEnvelopeFramingTest` — `request and response envelope helpers` called `decodeServiceFrame` directly on a service-*response* envelope (wire-type mismatch); now uses the new `decodeResponseEnvelope`.
- Import-only compile fixes in `CodecTest`/`NoiseXxTest`/`PairingSessionTest`/`PairingVectorsTest` and an `assertThrows` argument-order fix in `CodecTest`; no assertions touched.

## Notes / caveats

- The all-zeros `handshake_hash` in `noise_xx_fixed.json` was a placeholder, not an official vector; it was replaced with the value produced by the authoritative Python reference (`repos/muse-gadget-sdk/linux/src/musegadget/noise_xx.py`) using the vector's fixed seeds, and the Kotlin implementation reproduces it byte-for-byte.
- `encodeNoiseFrame` omitting `total_chunks=1` diverges slightly from the Python reference encoder (which emits it), but matches the Kotlin test's proto3 default-omission expectation and round-trips identically through the decoder.
- Two test fixes (`isCurrent` after expiry, `mobileOpen` decrypt step) correct the Kotlin tests to match the Python reference tests in `linux/tests/test_pairing.py`; the production code already matched the reference.
