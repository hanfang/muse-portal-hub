package com.muse.gadget.portal.wake

import android.content.Context
import android.util.Log
import com.openwakeword.OpenWakeWord

/**
 * [WakeWordDetector] backed by openwakeword-android (ONNX Runtime, on-device).
 *
 * The library manages its own AudioRecord internally; this class only owns the
 * model selection and lifecycle. The custom "hey muse" model lives at
 * `assets/openwakeword/hey_muse.onnx` (see `wake-training/README.md` for how
 * to train it). Until it exists, [devFallbackToHeyJarvis] can stand in for
 * pipeline testing — never enable it in a release build.
 */
class OpenWakeWordDetector(
    private val context: Context,
    private val modelAsset: String = MODEL_ASSET,
    private var threshold: Float = DEFAULT_THRESHOLD,
    private val devFallbackToHeyJarvis: Boolean = false,
) : WakeWordDetector {

    companion object {
        private const val TAG = "OpenWakeWordDetector"
        const val MODEL_ASSET = "openwakeword/hey_muse.onnx"
        const val DEFAULT_THRESHOLD = 0.5f
    }

    @Volatile private var detector: OpenWakeWord? = null

    override fun setThreshold(threshold: Float) {
        this.threshold = threshold
        // Takes effect on the next start().
    }

    override fun start(onWake: (score: Float) -> Unit) {
        stop()
        val builder = OpenWakeWord.Builder(context).setThreshold(threshold)
        if (assetExists(modelAsset)) {
            Log.i(TAG, "using custom wake model $modelAsset")
            builder.setModelAsset(modelAsset)
        } else if (devFallbackToHeyJarvis) {
            Log.w(TAG, "$modelAsset missing: DEV fallback to HEY_JARVIS")
            builder.setModel(OpenWakeWord.BuiltInModel.HEY_JARVIS)
        } else {
            throw IllegalStateException(
                "Wake model assets/$modelAsset is missing. Train it with " +
                    "wake-training/README.md, or enable devFallbackToHeyJarvis for testing.",
            )
        }
        val d = builder.build()
        detector = d
        d.start { score ->
            Log.i(TAG, "wake! score=$score")
            onWake(score)
        }
        Log.i(TAG, "listening (threshold=$threshold)")
    }

    override fun stop() {
        try {
            detector?.stop()
        } catch (e: Exception) {
            Log.w(TAG, "stop failed", e)
        }
    }

    override fun release() {
        try {
            detector?.release()
        } catch (e: Exception) {
            Log.w(TAG, "release failed", e)
        }
        detector = null
    }

    private fun assetExists(path: String): Boolean =
        try {
            context.assets.open(path).close()
            true
        } catch (_: Exception) {
            false
        }
}
