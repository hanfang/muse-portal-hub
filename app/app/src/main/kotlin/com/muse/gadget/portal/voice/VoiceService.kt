package com.muse.gadget.portal.voice

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.muse.gadget.audio.VoiceNoteEncoder
import com.muse.gadget.portal.R
import com.muse.gadget.portal.audio.AudioRingBuffer
import com.muse.gadget.portal.tts.EdgeTtsProtocol
import com.muse.gadget.portal.tts.EdgeTtsProvider
import com.muse.gadget.portal.tts.TtsProvider
import com.muse.gadget.portal.wake.EnergyVad
import com.muse.gadget.portal.wake.OpenWakeWordDetector
import com.muse.gadget.portal.wake.UtteranceEndpoint
import com.muse.gadget.portal.wake.WakeWordDetector

/**
 * The always-on voice satellite.
 *
 * - Foreground service (API 28 has no FGS types; plain foreground + sticky
 *   notification), restarted on boot by BootReceiver.
 * - [WakeWordDetector] (openWakeWord, own mic) listens 24/7 for "hey muse".
 * - On wake: opens a short-lived [AudioRecord] (16kHz mono, VOICE_RECOGNITION),
 *   endpointed by [UtteranceEndpoint], packs WAV via [VoiceNoteEncoder],
 *   sends through [MuseVoiceClient], speaks the reply via [TtsProvider].
 * - Wake callbacks are gated while TTS is playing (anti-self-trigger).
 *
 * P3 ships the full chain with [FakeMuseVoiceClient]; P4 swaps in the real
 * `:protocol` transport.
 */
class VoiceService : Service() {

    companion object {
        private const val TAG = "VoiceService"
        private const val CHANNEL_ID = "voice"
        private const val NOTIF_ID = 1
        const val ACTION_START = "com.muse.gadget.portal.action.START_VOICE"

        fun start(context: Context) {
            val intent = Intent(context, VoiceService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    private val machine = VoiceTurnStateMachine()
    private lateinit var detector: WakeWordDetector
    private lateinit var tts: TtsProvider
    private var museClient: MuseVoiceClient = FakeMuseVoiceClient()

    @Volatile private var ttsPlaying = false
    @Volatile private var captureThread: Thread? = null

    // ---- service lifecycle ----

    override fun onCreate() {
        super.onCreate()
        if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "RECORD_AUDIO not granted; stopping")
            stopSelf()
            return
        }
        startForeground(NOTIF_ID, buildNotification())

        val ttsConfig = EdgeTtsProtocol.Config(
            trustedClientToken = getString(R.string.edge_trusted_client_token),
        )
        tts = EdgeTtsProvider(this, ttsConfig)
        tts.setListener(object : TtsProvider.Listener {
            override fun onSpeakDone() {
                ttsPlaying = false
                machine.onEvent(VoiceTurnStateMachine.Event.SpeakDone)
                Log.i(TAG, "turn complete")
            }

            override fun onSpeakError(error: Throwable) {
                ttsPlaying = false
                machine.onEvent(VoiceTurnStateMachine.Event.SpeakFailed)
                Log.w(TAG, "tts failed", error)
            }
        })

        detector = OpenWakeWordDetector(this)
        try {
            detector.start(::onWake)
        } catch (e: Exception) {
            Log.e(TAG, "wake detector failed to start", e)
            stopSelf()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onDestroy() {
        captureThread?.interrupt()
        captureThread = null
        try {
            detector.stop()
        } catch (_: Exception) {
        }
        detector.release()
        tts.release()
        museClient.close()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ---- turn handling ----

    private fun onWake(score: Float) {
        if (ttsPlaying) {
            Log.d(TAG, "wake ignored during TTS (score=$score)")
            return // anti-self-trigger: our own speaker would re-wake us
        }
        val state = machine.onEvent(VoiceTurnStateMachine.Event.Wake(score))
        if (state != VoiceTurnStateMachine.State.RECORDING) {
            Log.d(TAG, "wake ignored in state $state")
            return
        }
        Log.i(TAG, "wake accepted (score=$score); capturing query")
        startCapture()
    }

    /**
     * Captures the query on a worker thread: AudioRecord -> ring buffer +
     * VAD endpointing -> WAV -> Muse -> TTS.
     */
    private fun startCapture() {
        captureThread?.interrupt()
        val t = Thread({ runCapture() }, "voice-capture")
        captureThread = t
        t.start()
    }

    private fun runCapture() {
        val minBuf = AudioRecord.getMinBufferSize(
            VoiceNoteEncoder.SAMPLE_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
        )
        if (minBuf <= 0) {
            Log.w(TAG, "bad min buffer size: $minBuf")
            machine.onEvent(VoiceTurnStateMachine.Event.Cancel)
            return
        }
        val recorder = AudioRecord(
            MediaRecorder.AudioSource.VOICE_RECOGNITION,
            VoiceNoteEncoder.SAMPLE_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            minBuf * 4,
        )
        if (recorder.state != AudioRecord.STATE_INITIALIZED) {
            Log.w(TAG, "AudioRecord init failed")
            recorder.release()
            machine.onEvent(VoiceTurnStateMachine.Event.Cancel)
            return
        }
        val ring = AudioRingBuffer(VoiceNoteEncoder.SAMPLE_RATE * 20) // 20s
        val endpoint = UtteranceEndpoint(EnergyVad())
        val frame = ShortArray(EnergyVad.FRAME_SAMPLES)
        try {
            recorder.startRecording()
            endpoint.start(System.currentTimeMillis())
            var endpointed = false
            while (!endpointed && !Thread.currentThread().isInterrupted) {
                val n = recorder.read(frame, 0, frame.size)
                if (n <= 0) continue
                if (n < frame.size) frame.fill(0, n, frame.size)
                ring.write(frame)
                endpointed = endpoint.process(frame, System.currentTimeMillis())
            }
            recorder.stop()
            val timedOut = !endpointed
            val pcm = ring.snapshotLast(VoiceNoteEncoder.NOTE_MAX_BYTES / 2)
            Log.i(TAG, "captured ${pcm.size} samples (timedOut=$timedOut)")
            machine.onEvent(
                if (timedOut) VoiceTurnStateMachine.Event.RecordTimeout
                else VoiceTurnStateMachine.Event.RecordEndpoint,
            )
            if (pcm.isEmpty()) {
                machine.onEvent(VoiceTurnStateMachine.Event.Cancel)
                return
            }
            sendToMuse(pcm)
        } catch (e: InterruptedException) {
            machine.onEvent(VoiceTurnStateMachine.Event.Cancel)
            Thread.currentThread().interrupt()
        } catch (e: Exception) {
            Log.w(TAG, "capture failed", e)
            machine.onEvent(VoiceTurnStateMachine.Event.Cancel)
        } finally {
            recorder.release()
        }
    }

    private fun sendToMuse(pcm: ShortArray) {
        try {
            val pcmBytes = ByteArray(pcm.size * 2)
            for (i in pcm.indices) {
                pcmBytes[2 * i] = (pcm[i].toInt() and 0xFF).toByte()
                pcmBytes[2 * i + 1] = ((pcm[i].toInt() shr 8) and 0xFF).toByte()
            }
            val wav = VoiceNoteEncoder.wavHeader() + pcmBytes
            val reply = museClient.sendVoiceNote(wav)
            Log.i(TAG, "muse reply: ${reply.take(120)}")
            machine.onEvent(VoiceTurnStateMachine.Event.ReplyReceived(reply))
            ttsPlaying = true
            tts.speak(reply)
        } catch (e: Exception) {
            Log.w(TAG, "muse request failed", e)
            machine.onEvent(VoiceTurnStateMachine.Event.ReplyFailed)
        }
    }

    // ---- notification ----

    private fun buildNotification(): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID, "Voice satellite", NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Listening for “hey muse”…")
            .setSmallIcon(android.R.drawable.ic_btn_speak_now)
            .build()
    }
}
