package com.muse.gadget.session

import com.muse.gadget.identity.Identity

/** `GET /v1/noise` WebSocket upgrade request builder (spec §2.3). */
object WsUpgrade {
    private val UNRESERVED = (('a'..'z') + ('A'..'Z') + ('0'..'9')).toSet()
    private val EXTRA_SAFE = setOf('-', '_', '.', '!', '~', '*', '\'', '(', ')')

    /**
     * vm_id escaping: RFC3986 unreserved + `!~*'()` kept verbatim,
     * everything else %XX uppercase (matches Python `quote(vm_id, safe=...)`).
     */
    fun escapeVmId(vmId: String): String = buildString {
        val bytes = vmId.toByteArray(Charsets.UTF_8)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c < 128 && (c.toChar() in UNRESERVED || c.toChar() in EXTRA_SAFE)) {
                append(c.toChar())
            } else {
                append('%')
                append("0123456789ABCDEF"[c shr 4])
                append("0123456789ABCDEF"[c and 0x0F])
            }
        }
    }

    fun noiseUrl(noiseHost: String, vmId: String): String =
        "wss://$noiseHost${Identity.NOISE_PATH}?vm_id=${escapeVmId(vmId)}"

    /**
     * Raw HTTP upgrade request. `Sec-WebSocket-Key` is the fixed value from the
     * ESP32 firmware — copy verbatim, do not randomize.
     */
    fun buildRequest(noiseHost: String, vmId: String, vmAuthToken: String): String =
        "GET ${Identity.NOISE_PATH}?vm_id=${escapeVmId(vmId)} HTTP/1.1\r\n" +
            "Host: $noiseHost\r\n" +
            "Authorization: Bearer $vmAuthToken\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "Sec-WebSocket-Key: ${Identity.WS_FIXED_KEY}\r\n" +
            "\r\n"
}
