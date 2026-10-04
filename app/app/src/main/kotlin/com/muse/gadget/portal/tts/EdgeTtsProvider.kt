package com.muse.gadget.portal.tts

import android.content.Context
import android.media.MediaPlayer
import android.os.Handler
import android.os.Looper
import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * [TtsProvider] over the Edge-TTS WebSocket endpoint.
 *
 * Flow: open WS (auth via [EdgeTtsProtocol.buildWsUrl]) -> send
 * `speech.config` + `ssml` frames -> collect MP3 chunks until `turn.end` ->
 * play through [MediaPlayer]. All network I/O on a worker thread; listener
 * callbacks are posted to the main thread.
 *
 * The trusted client token comes from [EdgeTtsProtocol.Config]; see
 * `res/values/edge.xml` for where to put the public constant.
 */
class EdgeTtsProvider(
    private val context: Context,
    private val config: EdgeTtsProtocol.Config,
    private val httpClient: OkHttpClient = defaultClient(),
) : TtsProvider {

    companion object {
        private const val TAG = "EdgeTtsProvider"

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        /** 32 uppercase hex chars, like edge-tts `drm.generate_muid()`. */
        fun newMuid(): String {
            val bytes = ByteArray(16)
            SecureRandom().nextBytes(bytes)
            return bytes.joinToString("") { "%02X".format(it) }
        }
    }

    @Volatile private var listener: TtsProvider.Listener? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile private var webSocket: WebSocket? = null
    @Volatile private var player: MediaPlayer? = null
    @Volatile private var currentTmp: File? = null
    @Volatile private var worker: Thread? = null
    @Volatile private var stopped = false

    override fun setListener(listener: TtsProvider.Listener?) {
        this.listener = listener
    }

    override fun speak(text: String) {
        stop()
        stopped = false
        val t = Thread({ runSynthesis(text) }, "edge-tts")
        worker = t
        t.start()
    }

    private fun runSynthesis(text: String) {
        try {
            val voice = EdgeTtsProtocol.selectVoice(text, config)
            Log.i(TAG, "synthesizing ${text.length} chars with $voice")
            val mp3 = synthesize(text, voice)
            if (stopped || mp3.isEmpty()) return
            playMp3(mp3)
        } catch (e: Exception) {
            Log.w(TAG, "synthesis failed", e)
            if (!stopped) post { listener?.onSpeakError(e) }
        }
    }

    /** Blocking: returns the full MP3 utterance. Throws on any failure. */
    @Throws(Exception::class)
    private fun synthesize(text: String, voice: String): ByteArray {
        val date = EdgeTtsProtocol.jsDateString()
        val secMsGec = EdgeTtsProtocol.secMsGec(
            config.trustedClientToken, System.currentTimeMillis() / 1000.0)
        val url = EdgeTtsProtocol.buildWsUrl(config, EdgeTtsProtocol.newId(), secMsGec)
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", EdgeTtsProtocol.USER_AGENT)
            .header("Accept-Encoding", "gzip, deflate, br, zstd")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Pragma", "no-cache")
            .header("Cache-Control", "no-cache")
            .header("Origin", EdgeTtsProtocol.ORIGIN)
            .header("Cookie", "muid=${newMuid()};")
            .build()

        val done = CountDownLatch(1)
        val audio = ByteArrayOutputStream()
        val failure = AtomicReference<Throwable?>(null)

        val wsListener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                webSocket.send(EdgeTtsProtocol.buildSpeechConfigFrame(date))
                val ssml = EdgeTtsProtocol.buildSsml(
                    text, voice, config.rate, config.volume, config.pitch)
                webSocket.send(
                    EdgeTtsProtocol.buildSsmlFrame(EdgeTtsProtocol.newId(), date, ssml))
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                when (EdgeTtsProtocol.parseText(text)) {
                    is EdgeTtsProtocol.WsEvent.TurnEnd -> webSocket.close(1000, null)
                    else -> Unit // turn.start / response / metadata: nothing to do
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                when (val ev = EdgeTtsProtocol.parseBinary(bytes.toByteArray())) {
                    is EdgeTtsProtocol.WsEvent.Audio -> audio.write(ev.mp3)
                    is EdgeTtsProtocol.WsEvent.TurnEnd -> webSocket.close(1000, null)
                    else -> Unit
                }
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                done.countDown()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                val code = response?.code
                failure.set(RuntimeException("Edge-TTS websocket failed (http=$code)", t))
                done.countDown()
            }
        }

        webSocket = httpClient.newWebSocket(request, wsListener)
        val finished = done.await(45, TimeUnit.SECONDS)
        webSocket = null
        if (!finished) throw RuntimeException("Edge-TTS timed out waiting for turn.end")
        failure.get()?.let { throw it }
        if (audio.size() == 0) throw RuntimeException("Edge-TTS returned no audio")
        return audio.toByteArray()
    }

    private fun playMp3(mp3: ByteArray) {
        val tmp = File.createTempFile("edge-tts", ".mp3", context.cacheDir)
        currentTmp = tmp
        FileOutputStream(tmp).use { it.write(mp3) }
        post {
            if (stopped) {
                tmp.delete()
                return@post
            }
            try {
                val mp = MediaPlayer()
                player = mp
                mp.setDataSource(tmp.absolutePath)
                mp.setOnCompletionListener {
                    Log.i(TAG, "playback done")
                    post { listener?.onSpeakDone() }
                    releasePlayer()
                }
                mp.setOnErrorListener { _, what, extra ->
                    post { listener?.onSpeakError(RuntimeException("MediaPlayer $what/$extra")) }
                    releasePlayer()
                    true
                }
                mp.prepare()
                post { listener?.onSpeakStart() }
                mp.start()
            } catch (e: Exception) {
                post { listener?.onSpeakError(e) }
                releasePlayer()
            }
        }
    }

    private fun releasePlayer() {
        try {
            player?.release()
        } catch (_: Exception) {
        }
        player = null
        try {
            currentTmp?.delete()
        } catch (_: Exception) {
        }
        currentTmp = null
    }

    private fun post(block: () -> Unit) {
        mainHandler.post(block)
    }

    override fun stop() {
        stopped = true
        try {
            webSocket?.close(1000, null)
        } catch (_: Exception) {
        }
        webSocket = null
        try {
            player?.stop()
        } catch (_: Exception) {
        }
        releasePlayer()
        worker?.interrupt()
        worker = null
    }

    override fun release() {
        stop()
        setListener(null)
        try {
            httpClient.dispatcher.executorService.shutdown()
        } catch (_: Exception) {
        }
    }
}
