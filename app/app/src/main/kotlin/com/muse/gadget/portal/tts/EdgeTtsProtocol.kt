package com.muse.gadget.portal.tts

import java.security.MessageDigest
import java.util.UUID

/**
 * Pure-Kotlin Edge-TTS ("Microsoft Edge Read Aloud") wire protocol.
 *
 * Reverse-engineered from the `edge-tts` Python package: WebSocket endpoint,
 * `speech.config` + `ssml` text frames, binary audio demux (2-byte big-endian
 * header length + ASCII headers + MP3 bytes), and the Sec-MS-GEC anti-abuse
 * token (SHA-256 of rounded Windows file time + trusted client token).
 *
 * No Android dependencies: fully unit-testable on the JVM.
 *
 * The service is unofficial (no API key, but the endpoint can change without
 * notice) — that is why [TtsProvider] exists as an abstraction and this
 * object only builds/parses protocol bytes, never touches the network.
 *
 * The endpoint requires a "trusted client token", a public constant baked into
 * every Edge build and every edge-tts reimplementation. It is taken as
 * [Config.trustedClientToken] (copy it from a local `edge-tts` install's
 * `constants.py`) rather than hardcoded here.
 */
object EdgeTtsProtocol {
    const val BASE_URL = "speech.platform.bing.com/consumer/speech/synthesize/readaloud"
    const val OUTPUT_FORMAT = "audio-24khz-48kbitrate-mono-mp3"

    const val VOICE_EN_DEFAULT = "en-US-JennyNeural"
    const val VOICE_ZH_DEFAULT = "zh-CN-XiaoxiaoNeural"

    // Browser-impersonation constants (mirror edge-tts constants.py).
    const val USER_AGENT =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
    const val ORIGIN = "chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold"
    const val SEC_MS_GEC_VERSION = "1-143.0.3650.75"

    data class Config(
        /** Public constant from edge-tts `constants.py`; NOT a per-user secret. */
        val trustedClientToken: String,
        val voiceEn: String = VOICE_EN_DEFAULT,
        val voiceZh: String = VOICE_ZH_DEFAULT,
        val rate: String = "+0%",
        val volume: String = "+0%",
        val pitch: String = "+0Hz",
    )

    // ---------- outbound ----------

    fun buildWsUrl(config: Config, connectionId: String, secMsGec: String): String =
        "wss://$BASE_URL/edge/v1" +
            "?TrustedClientToken=${config.trustedClientToken}" +
            "&ConnectionId=$connectionId" +
            "&Sec-MS-GEC=$secMsGec" +
            "&Sec-MS-GEC-Version=$SEC_MS_GEC_VERSION"

    fun newId(): String = UUID.randomUUID().toString().replace("-", "")

    /**
     * JS-style date string, e.g.
     * "Sat Oct 04 2026 21:30:00 GMT+0000 (Coordinated Universal Time)".
     */
    fun jsDateString(epochMillis: Long = System.currentTimeMillis()): String {
        val c = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"))
        c.timeInMillis = epochMillis
        val dow = arrayOf("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")[
            c.get(java.util.Calendar.DAY_OF_WEEK) - 1]
        val mon = arrayOf(
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[c.get(java.util.Calendar.MONTH)]
        fun p(v: Int) = v.toString().padStart(2, '0')
        return "$dow $mon ${p(c.get(java.util.Calendar.DAY_OF_MONTH))} " +
            "${c.get(java.util.Calendar.YEAR)} " +
            "${p(c.get(java.util.Calendar.HOUR_OF_DAY))}:" +
            "${p(c.get(java.util.Calendar.MINUTE))}:" +
            "${p(c.get(java.util.Calendar.SECOND))} " +
            "GMT+0000 (Coordinated Universal Time)"
    }

    /**
     * XML-escapes text and replaces control characters the service rejects
     * (0x00-0x08, 0x0B-0x0C, 0x0E-0x1F) with spaces. Mirrors
     * `xml.sax.saxutils.escape` + `remove_incompatible_characters`.
     */
    fun sanitize(text: String): String {
        val sb = StringBuilder(text.length)
        for (ch in text) {
            val code = ch.code
            if (code in 0..8 || code in 11..12 || code in 14..31) {
                sb.append(' ')
                continue
            }
            when (ch) {
                '&' -> sb.append("&amp;")
                '<' -> sb.append("&lt;")
                '>' -> sb.append("&gt;")
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }

    /**
     * SSML envelope. The service only accepts a single `<voice>` tag with a
     * single `<prosody>` tag inside — anything fancier is rejected server-side.
     */
    fun buildSsml(
        text: String,
        voice: String,
        rate: String = "+0%",
        volume: String = "+0%",
        pitch: String = "+0Hz",
    ): String =
        "<speak version='1.0' xmlns='http://www.w3.org/2001/10/synthesis' xml:lang='en-US'>" +
            "<voice name='$voice'>" +
            "<prosody pitch='$pitch' rate='$rate' volume='$volume'>${sanitize(text)}</prosody>" +
            "</voice></speak>"

    fun buildSpeechConfigFrame(date: String): String =
        "X-Timestamp:$date\r\n" +
            "Content-Type:application/json; charset=utf-8\r\n" +
            "Path:speech.config\r\n\r\n" +
            "{\"context\":{\"synthesis\":{\"audio\":{\"metadataoptions\":" +
            "{\"sentenceBoundaryEnabled\":\"false\",\"wordBoundaryEnabled\":\"false\"}," +
            "\"outputFormat\":\"$OUTPUT_FORMAT\"}}}}\r\n"

    fun buildSsmlFrame(requestId: String, date: String, ssml: String): String =
        "X-RequestId:$requestId\r\n" +
            "Content-Type:application/ssml+xml\r\n" +
            // Trailing "Z" is intentional: mirrors an Edge quirk in edge-tts.
            "X-Timestamp:${date}Z\r\n" +
            "Path:ssml\r\n\r\n" +
            ssml

    /**
     * Sec-MS-GEC token: uppercase hex SHA-256 of
     * "<windows file time rounded down to 5 min><trusted client token>".
     * [clockSkewSeconds] compensates a wrong device clock (edge-tts adjusts it
     * from the server `Date` header after a 403).
     */
    fun secMsGec(
        trustedClientToken: String,
        unixSeconds: Double,
        clockSkewSeconds: Double = 0.0,
    ): String {
        var ticks = unixSeconds + clockSkewSeconds
        ticks += 11_644_473_600.0 // -> Windows file-time epoch (1601-01-01)
        ticks -= ticks % 300 // round down to 5 minutes
        ticks *= 10_000_000.0 // -> 100ns intervals
        val toHash = "${ticks.toLong()}$trustedClientToken"
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(toHash.toByteArray(Charsets.US_ASCII))
        return digest.joinToString("") { "%02X".format(it) }
    }

    /** Picks the EN vs ZH voice by CJK character presence in the reply text. */
    fun selectVoice(text: String, config: Config): String =
        if (text.any { it.code in 0x4E00..0x9FFF || it.code in 0x3400..0x4DBF }) {
            config.voiceZh
        } else {
            config.voiceEn
        }

    // ---------- inbound ----------

    sealed interface WsEvent {
        data object TurnStart : WsEvent
        data object TurnEnd : WsEvent
        data object Response : WsEvent
        data class Audio(val mp3: ByteArray) : WsEvent
        data class Unknown(val path: String?) : WsEvent
    }

    /**
     * Parses a binary WS message: 2-byte big-endian header length, ASCII
     * headers, then audio bytes. Returns [WsEvent.Audio] only for
     * `Path:audio` with `Content-Type: audio/mpeg`; a header-only binary
     * message marks end-of-turn.
     */
    fun parseBinary(msg: ByteArray): WsEvent {
        if (msg.size < 2) return WsEvent.Unknown(null)
        val headerLen = ((msg[0].toInt() and 0xFF) shl 8) or (msg[1].toInt() and 0xFF)
        if (msg.size < 2 + headerLen) return WsEvent.Unknown(null)
        val headers = parseHeaders(
            msg.copyOfRange(2, 2 + headerLen).toString(Charsets.UTF_8))
        if (headers["Path"] != "audio") return WsEvent.Unknown(headers["Path"])
        val audio = msg.copyOfRange(2 + headerLen, msg.size)
        val contentType = headers["Content-Type"]
        if (contentType == null) {
            // End-of-turn marker: binary message with headers but no data.
            return if (audio.isEmpty()) WsEvent.TurnEnd else WsEvent.Unknown("audio?")
        }
        if (contentType != "audio/mpeg" || audio.isEmpty()) {
            return WsEvent.Unknown(headers["Path"])
        }
        return WsEvent.Audio(audio)
    }

    /** Parses a text WS message; dispatches on its `Path` header. */
    fun parseText(msg: String): WsEvent {
        val sep = msg.indexOf("\r\n\r\n")
        val headers = parseHeaders(if (sep < 0) msg else msg.substring(0, sep))
        return when (headers["Path"]) {
            "turn.start" -> WsEvent.TurnStart
            "turn.end" -> WsEvent.TurnEnd
            "response" -> WsEvent.Response
            else -> WsEvent.Unknown(headers["Path"])
        }
    }

    private fun parseHeaders(block: String): Map<String, String> =
        block.split("\r\n").mapNotNull {
            val i = it.indexOf(':')
            if (i < 0) null else it.substring(0, i).trim() to it.substring(i + 1).trim()
        }.toMap()
}
