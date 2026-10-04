package com.muse.gadget.identity

import java.util.UUID

/**
 * Server/app-dependent identifiers. The `hatch` spellings are kept verbatim:
 * the Muse VM host, token prefixes and pairing labels depend on them.
 * (Upstream rule: "Say Muse, never Hatch" — user-visible strings say Muse.)
 */
object Identity {
    // -- Pairing v5 ---------------------------------------------------------
    const val DEVICE_ID_PREFIX = "hatch-link:"
    const val NODE_ID_PREFIX = "homelink-"
    const val PAIRING_MODEL = "hatch_link"
    const val PAIRING_VERSION = 5
    const val PAIRING_SUITE = "p256-hkdf-sha256-aes-gcm-v1"
    const val PAIRING_AUTH_COMMUNITY = "none"
    const val PAIRING_AUTH_OFFICIAL = "fleet_ecdsa_p256_v1"
    const val PAIRING_POLICY_APP = "confirm_app"
    const val PAIRING_POLICY_BUTTON = "confirm_press"
    const val RECORD_LABEL = "hatch-link ble setup v1"
    const val SESSION_ID_LABEL = "hatch-link session id v1"
    const val TRANSCRIPT_FIRST_LINE = "hatch-link-pairing-v5"
    const val BUTTON_CONFIRM_TIMEOUT_S = 60L
    const val CLIENT_FINISHED_TIMEOUT_S = 60L
    const val CONFIRMED_TIMEOUT_S = 120L
    const val PROVISIONING_TIMEOUT_S = 120L

    // -- BLE GATT (spec §1.1) ------------------------------------------------
    val GATT_SERVICE_UUID: UUID = UUID.fromString("7fdd3d1c-38ea-46cf-8b46-314ecf5f240c")
    /** Phone -> device (write). */
    val GATT_RX_UUID: UUID = UUID.fromString("4d593029-28a2-4a6e-a1f0-3c2d5e8f9b01")
    /** Device -> phone (notify). */
    val GATT_TX_UUID: UUID = UUID.fromString("d75dc4ca-7b2b-4e9c-8f0a-1d2e3f4a5b6c")
    const val CHUNK_MAGIC: Byte = 0xFE.toByte()
    const val MAX_NOTIFY_CHUNK = 160

    // -- Cloud ----------------------------------------------------------------
    const val API_BASE = "https://api.muse.ai"
    const val FETCH_VMS_PATH = "/fetch_vms"
    const val REFRESH_PATH = "/device_token/refresh"
    const val NOISE_PATH = "/v1/noise"
    const val DEFAULT_NOISE_HOST = "hatch.metaaivm.com"
    const val NOISE_PROTOCOL_NAME = "Noise_XX_25519_AESGCM_SHA256"
    /** Fixed value from the ESP32 firmware; copy verbatim, do not randomize. */
    const val WS_FIXED_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
    const val APP_ID = "hatch-web"
    const val API_VERSION = "1.0.0"
    const val REFRESH_AUTH_PREFIX = "hatch_refresh:"

    // -- Chat -----------------------------------------------------------------
    const val CHAT_STREAM_PATH = "/chat/stream"
    const val CHAT_SUBSCRIBE_PATH = "/chat/subscribe"

    fun deviceId(mac: String): String = "$DEVICE_ID_PREFIX$mac"

    /** Linux-style BLE name: no hyphen; the app compares the suffix with node id suffix. */
    fun bleName(nodeId: String): String =
        "MuseGadget" + nodeId.removePrefix(NODE_ID_PREFIX)
}
