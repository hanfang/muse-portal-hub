# muse-portal-hub

> **Repository:** `github.com/hanfang/muse-portal-hub` (public repo to be created)

Turn a retired **Meta Portal** into a room-scale voice satellite for **Muse**:
"hey muse" wake word → spoken question → spoken answer (e.g. *"hey muse, what's the weather?"*).

> **Status:** early prototype. The `:protocol` module (pure JVM Kotlin) implements the
> Muse gadget session protocol and is unit-tested; the `:app` Android skeleton targets
> Meta Portal (minSdk 28) and is not yet wired end-to-end.

## Architecture

```
┌─────────────────────┐   BLE GATT peripheral   ┌──────────────┐
│  Meta Portal (this  │◄──── pairing v5 ────────►│  Phone (Muse │
│  app)               │   0xFE-framed chunks     │  app)        │
│                     │                          └──────────────┘
│  :app (Android)     │   Noise XX handshake
│   ├─ ChatActivity   │◄──── wss://…/v1/noise ──►┌──────────────┐
│   ├─ PortalBlePeri- │   protobuf envelopes     │  Muse VM     │
│   │   pheral        │   (request/response/     │  (server)    │
│   └─ VoiceService*  │    datagram)             └──────────────┘
│                     │
│  :protocol (JVM)    │   HTTPS (api.muse.ai)
│   ├─ pairing  (BLE pairing v5: ECDH→transcript→HKDF→AES-GCM)
│   ├─ noise    (Noise_XX_25519_AESGCM_SHA256 + protobuf framing)
│   ├─ session  (chat stream/subscribe, NDJSON events, turn state machine)
│   ├─ audio    (16 kHz WAV voice-note encoder)
│   ├─ api      (fetch_vms / device_token/refresh client)
│   └─ identity (hatch-link: device identity constants)
└─────────────────────┘
        * planned
```

Protocol flow: BLE pairing v5 establishes `access_token`/`refresh_token` →
`fetch_vms` picks a VM → WebSocket upgrade → Noise XX handshake → encrypted
`/chat/stream` requests, `/chat/subscribe` NDJSON events → turn state machine
settles the reply → TTS speaks it back.

## Quick start

> TODO: fill in once the build is green on real hardware.

```bash
# 1. Run the protocol unit tests (no Android SDK needed)
cd app
./gradlew :protocol:test

# 2. Build the Android app (requires Android SDK)
# ./gradlew :app:assembleDebug
# adb install app/build/outputs/apk/debug/app-debug.apk
```

## Security policy — tokens and secrets

**No hardcoded tokens, keys, or personal data — ever.** This is enforced by code
review and by `.gitignore`:

- SDK tokens (`mgst_…`), `access_token`/`refresh_token`, keystores, `local.properties`,
  `*.pem`/`*.key` files, and any `*token*.json` / `*credential*.json` config are
  **never committed**. See `.gitignore`.
- At runtime the app reads tokens **only from a local, gitignored config file**
  on the device (e.g. app-private storage / `~/.config/muse-voice-satellite/`),
  never from source code, resources, or build files.
- Test fixtures use obvious placeholders (`mgst_test`, `mgst_x`) — never real tokens.

**If a token leaks** (pasted into a log, committed, screenshotted): revoke it
immediately at **gadgets.muse.ai**, then delete the leaked copy and rotate any
derived credentials.

## Acknowledgments

This project builds on the work of these upstream projects — thank you:

| Project | Used for | License |
|---|---|---|
| [muse-gadget-sdk](https://github.com/facebookincubator/muse-gadget-sdk) (Meta) | Gadget session protocol reference (pairing v5, Noise XX, chat streams) — the `:protocol` module is a Kotlin port of its Linux SDK | Apache 2.0 |
| [immortal](https://github.com/starbrightlab/immortal) (Starbright Lab) | Meta Portal repurposing research (ADB sideload, wake-word notes) | MIT |
| [portal-room-os](https://github.com/jacobturner-king/portal-room-os) | Portal repurposing research (BootReceiver / kiosk patterns) | *No LICENSE file found in the referenced snapshot — verify before redistributing its code* |
| [pylutron-caseta](https://github.com/gurumitts/pylutron-caseta) | Lutron LEAP-over-TLS research for phase-2 smart-home control | Apache 2.0 |

## License

Apache 2.0 — see [LICENSE](LICENSE).
