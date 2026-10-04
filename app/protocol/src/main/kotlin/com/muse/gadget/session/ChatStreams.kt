package com.muse.gadget.session

import com.muse.gadget.identity.Identity
import com.muse.gadget.noise.Header
import com.muse.gadget.util.Json

/**
 * Builders for `/chat/stream` (text + voice note) and `/chat/subscribe`.
 * Pure functions returning headers/body chunks; the Noise transport encrypts them.
 */
object ChatStreams {
    const val NOTE_PART_BYTES = 6144
    const val NOTE_MAX_BYTES = 16000 * 2 * 20 // 20s of 16kHz mono PCM16

    /** `{"message":"","output_modality":"text","items":[{"type":"file",...,"data_base64":"` */
    val VOICE_NOTE_HEAD: String =
        "{\"message\":\"\",\"output_modality\":\"text\"," +
            "\"items\":[{\"type\":\"file\",\"mime_type\":\"audio/wav\"," +
            "\"filename\":\"voice_note.wav\",\"data_base64\":\""

    /** Closes the items array: `"}]}` */
    const val VOICE_NOTE_TAIL = "\"}]}"

    fun chatHeaders(requestId: String, appId: String = Identity.APP_ID): List<Header> = listOf(
        Header("Content-Type", "application/json"),
        Header("x-request-id", requestId),
        Header("x-app-id", appId),
    )

    /** Body for a text turn. `deviceId` = node id attributes the turn to the device. */
    fun textBody(message: String, deviceId: String? = null, sessionId: String? = null): ByteArray {
        val fields = LinkedHashMap<String, com.muse.gadget.util.JsonValue>()
        fields["message"] = Json.str(message)
        fields["output_modality"] = Json.str("text")
        if (deviceId != null) fields["device_id"] = Json.str(deviceId)
        if (sessionId != null) fields["session_id"] = Json.str(sessionId)
        // NOTE: `chat_id` is NOT an API field and would be ignored.
        return Json.stringify(Json.obj(*fields.map { it.key to it.value }.toTypedArray()))
            .toByteArray(Charsets.UTF_8)
    }

    fun subscribeBody(): ByteArray = "{}".toByteArray(Charsets.UTF_8)

    fun subscribeHeaders(): List<Header> = listOf(
        Header("Content-Type", "application/json"),
        Header("Accept", "application/x-ndjson"),
    )

    /** Suggested request id shape: `muse-<16 hex>`. */
    fun newRequestId(randomHex16: String): String {
        require(randomHex16.length == 16 && randomHex16.all { it in "0123456789abcdef" })
        return "muse-$randomHex16"
    }
}
