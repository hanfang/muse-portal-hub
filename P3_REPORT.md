# P3 Report — TTS + openWakeWord integration

**Date:** 2026-10-04
**Scope:** `:app` new code only. `:protocol` untouched (public API unchanged);
its 90 tests re-run after this work: **90/90 green**.

## What was built

**TTS** (`app/.../portal/tts/`)
- `TtsProvider` — pluggable interface (`speak/stop/release` + listener).
  Sherpa-ONNX/Piper offline fallback = "write another implementation".
- `EdgeTtsProtocol` (pure JVM, unit-tested) — the full Edge-TTS wire protocol
  reverse-engineered from the installed `edge-tts` 7.2.8 sources:
  `wss://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1`
  with `TrustedClientToken` + `ConnectionId` + `Sec-MS-GEC` query params,
  `speech.config` / `ssml` text frames, JS-style `X-Timestamp` (incl. the
  trailing-`Z` Edge quirk), SSML envelope (single `<voice>`+`<prosody>`,
  XML-escaped, control chars stripped), Sec-MS-GEC
  (SHA-256 of 5-min-bucketed Windows file time + token, uppercase hex —
  golden-tested against the Python formula), binary audio demux
  (2-byte BE header length + `Path:audio` + `audio/mpeg`), `turn.end`
  handling, EN/ZH voice auto-select (`en-US-JennyNeural` /
  `zh-CN-XiaoxiaoNeural`) by CJK detection.
- `EdgeTtsProvider` (Android) — OkHttp WebSocket → collect MP3 →
  `MediaPlayer` playback from a temp file; callbacks on the main thread.
- The trusted client token is a **public constant** (baked into every Edge
  build), but it is **not hardcoded**: `res/values/edge.xml` holds a
  `REPLACE_WITH_PUBLIC_TOKEN_FROM_EDGE_TTS` placeholder with instructions
  (copy from a local `edge-tts` install's `constants.py`). The service fails
  fast with a clear log if unset.

**Wake word** (`app/.../portal/wake/`)
- `WakeWordDetector` interface + `OpenWakeWordDetector`
  (`com.github.msnilsen:openwakeword-android:0.1.0` via JitPack).
  API verified against the published AAR: `Builder(context)`
  `.setModelAsset("openwakeword/hey_muse.onnx")` / `.setModel(...)` /
  `.setThreshold()` / `.build()`, `start { score -> }`, `stop()`, `release()`.
- **Deviation from the plan, verified against the AAR:** the library manages
  its **own AudioRecord internally** and exposes no external PCM-feed API
  (checked the 0.1.0 bytecode: `initAudioRecord`, `audioLoop`, no public
  frame input). So the "single AudioRecord feeding both wake + ring buffer"
  design is not possible with this library version. v1 instead:
  the library owns the 24/7 mic; `VoiceService` opens its **own short-lived**
  `AudioRecord` (16 kHz mono, `VOICE_RECOGNITION`) only during the query
  window, then releases it. Same-UID overlap is transient and only
  post-wake. The wake word itself is *not* in the query audio (acceptable:
  users pause after "hey muse"). `AudioRingBuffer` is still implemented +
  tested and used for the captured query; it also keeps the door open for a
  future single-mic driver.
- `EnergyVad` (adaptive noise floor, hangover) + `UtteranceEndpoint`
  (silence timeout 1200 ms / max 15 s) — pure, tested, thresholds tunable.
- Missing `hey_muse.onnx` → clear `IllegalStateException` naming the
  training README. `devFallbackToHeyJarvis` flag exists for pipeline
  testing only.

**Orchestration** (`app/.../portal/voice/`)
- `VoiceService` — foreground service (API 28: no FGS types; plain
  foreground + low-importance sticky notification), `START_STICKY`,
  started by `PortalApp.onCreate` and `BootReceiver` (BOOT_COMPLETED).
  Turn flow: wake → (gate: ignore while TTS plays — anti-self-trigger) →
  `VoiceTurnStateMachine` (IDLE→RECORDING→SENDING→SPEAKING→IDLE, pure +
  tested) → capture → `VoiceNoteEncoder` WAV → `MuseVoiceClient` →
  `tts.speak(reply)`.
- `MuseVoiceClient` interface + `FakeMuseVoiceClient` (P4 swaps in the real
  `:protocol` transport).
- Gradle: `app/build.gradle.kts` gains OkHttp 4.12.0, openwakeword-android
  0.1.0, and `:app` test deps; root `build.gradle.kts` gains JitPack;
  `AndroidManifest.xml` declares the service; `RECORD_AUDIO` etc. already
  present.

**Training** (`wake-training/`)
- `README.md` — click-by-click Colab flow (official notebook URL, GPU
  runtime, phrase "hey muse", ~30–60 min), Android compat checklist
  (opset 11 / IR 7 / no allowzero Reshape), real-sample guidance, on-device
  tuning notes.
- `prepare_real_samples.py` — stdlib-only: validates 16 kHz mono 16-bit,
  trims silence, peak-normalizes to −3 dBFS, writes `manifest.csv`
  (smoke-tested: trims, normalizes, rejects wrong sample rate).
- `check_model.py` — verifies a trained .onnx for Android compat
  (needs `pip install onnx`).
- `app/.../assets/openwakeword/README.md` — placeholder doc where
  `hey_muse.onnx` will land.

## How it was verified

- **33 new JVM unit tests, all green** (kotlinc direct compile, JUnit
  Platform Console): `EdgeTtsProtocolTest` (14: SSML/escaping, JS date,
  frame bytes, Sec-MS-GEC goldens vs the Python formula, binary/text
  parsing, voice select), `AudioRingBufferTest` (6: order, wrap, overflow,
  clear), `EnergyVadTest` (6: silence/speech/hangover/endpoint/timeout),
  `VoiceTurnStateMachineTest` (7 incl. `FakeMuseVoiceClient`).
- **90/90 `:protocol` tests re-run green** — no regressions.
- **Android sources signature-checked**: all new/edited Android files
  (`EdgeTtsProvider`, `OpenWakeWordDetector`, `VoiceService`,
  `BootReceiver`, `PortalApp`) compile cleanly against hand-written
  `android.*`/`okhttp3`/`openwakeword` API stubs in `/tmp/stubs`
  (not committed). Full APK compile still needs the Android SDK.
- `prepare_real_samples.py` smoke-tested on synthetic WAVs.

## 3 most likely real-device problems (P4)

1. **Edge-TTS handshake drift.** The endpoint is unofficial and the exact
   header set was copied from edge-tts 7.2.8 (Chrome 143 impersonation).
   If Microsoft changes the endpoint or requires `permessage-deflate`
   (edge-tts sets `compress=15`; OkHttp doesn't by default), synthesis fails
   and the provider reports `onSpeakError`. Mitigation is already designed
   in: the `TtsProvider` seam. First P4 step should be a one-utterance live
   smoke test from a dev machine (the pure `EdgeTtsProtocol` makes a JVM
   smoke test trivial) before touching the Portal.
2. **Mic contention / VOICE_RECOGNITION behavior on Portal hardware.**
   The library's internal AudioRecord + our query AudioRecord overlap
   briefly post-wake; same-UID concurrency usually works on Android 9 but
   Portal's custom audio HAL is unverified, as is whether
   `VOICE_RECOGNITION` actually gives AEC on this device. If the query
   recorder fails to init, the turn cancels gracefully (logged) — watch
   logcat for `AudioRecord init failed`.
3. **"hey muse" model quality + service survivability.** Synthetic-only
   training in a quiet room ≠ a living room with TV. Record the 20–50 real
   clips, tune the 0.5 threshold in 0.05 steps during soak, and watch for
   the OEM killing the foreground service (Immortal's fleet logs help).

## Colab training TODO (for the parent)

- [ ] Run the notebook → `hey_muse.onnx` (~1 h, free Colab GPU)
- [ ] `python3 wake-training/check_model.py hey_muse.onnx`
- [ ] Copy to `app/app/src/main/assets/openwakeword/hey_muse.onnx`
- [ ] (recommended) record 20–50 real clips → `prepare_real_samples.py` → feed back into training
