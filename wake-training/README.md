# Training the "hey muse" wake-word model

There is **no pretrained "hey muse" model** (upstream only ships alexa /
hey_jarvis / hey_mycroft / hey_rhasspy / timer / weather). We train our own
with the official openWakeWord notebook. Cost: $0. Time: ~30–60 min on a free
Colab GPU.

## What comes out

- `hey_muse.onnx` — the wake-word classifier. Input shape `[1, 16, 96]`,
  output `[1, 1]` (score in [0, 1]).
- Drop it at `app/app/src/main/assets/openwakeword/hey_muse.onnx`.
  `OpenWakeWordDetector` loads it via `setModelAsset("openwakeword/hey_muse.onnx")`.
- The model YOU train is yours (no license encumbrance). Note: upstream's
  *pretrained* models are CC BY-NC-SA 4.0 — don't bundle those in a
  commercial product.

## Step-by-step (click-by-click)

1. Open the official training notebook (from the openwakeword-android README):
   <https://colab.research.google.com/drive/1q1oe2zOyZp7UsB3jJiQ1IFn8z5YfjwEb>
2. **Runtime → Change runtime type → Hardware accelerator → GPU** (T4 is fine).
3. In the config cell, set the target phrase to exactly:
   ```
   hey muse
   ```
4. **Runtime → Run all.** The notebook will:
   - synthesize ~1000 positive clips with Piper TTS (multiple voices/pitches),
   - synthesize noise-augmented negatives,
   - train the classifier (~30–60 min on free Colab GPU).
5. When it finishes, download `hey_muse.onnx` from the notebook's output cell.
6. **Android compatibility check** (the notebook exports these correctly by
   default, but verify once):
   - ONNX **opset 11**, **IR version 7** (older ONNX Runtime on the Portal),
   - no `Reshape` with `allowzero=1`.
   Quick check: `python3 check_model.py hey_muse.onnx` (script below).
7. Copy to `app/app/src/main/assets/openwakeword/hey_muse.onnx`, rebuild.

## Making it actually work in a living room (recommended)

Synthetic-only models false-trigger on TV noise and miss far-field speech.
Do this once, ~15 minutes:

1. Record **20–50 real "hey muse" clips**: phone voice memo is fine, at
   1 m / 3 m / 5 m from the Portal spot, quiet + TV-on backgrounds.
2. Run `python3 prepare_real_samples.py <recordings-dir> <out-dir>` —
   validates 16 kHz mono WAV, trims silence, peak-normalizes, writes
   `manifest.csv`.
3. In the notebook, upload `out-dir/*.wav` as **additional positive samples**
   (there is a cell for user clips) and re-run training. This is the single
   biggest quality lever.

## On-device tuning (after the model is in)

- `OpenWakeWordDetector` threshold: default `0.5`. Lower = more sensitive
  (more false wakes), higher = stricter. Tune live: watch logcat
  `OpenWakeWordDetector` "wake! score=" lines during a soak day.
- `EnergyVad` (query endpointing): `speechDb` (default 8.0 dB above noise
  floor), `silenceTimeoutMs` (default 1200 ms), `maxDurationMs` (15 s).
- Soak test: leave the black Portal+ running 24 h, count false wakes in
  logcat, adjust threshold in 0.05 steps.

## Files in this directory

- `README.md` — this file.
- `prepare_real_samples.py` — validate/trim/normalize real recordings (stdlib only).
- `check_model.py` — verify opset/IR version of a trained .onnx (needs `onnx` pip package).
