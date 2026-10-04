#!/usr/bin/env python3
"""Prepare real "hey muse" recordings for the openWakeWord training notebook.

Usage:
    python3 prepare_real_samples.py <recordings-dir> <out-dir>

- Reads every .wav in <recordings-dir> (recorded however you like: phone voice
  memo exported as WAV, `arecord -r 16000 -c 1 -f S16_LE`, etc.).
- Validates: 16 kHz, mono, 16-bit PCM.
- Trims leading/trailing low-energy silence, peak-normalizes to -3 dBFS.
- Writes cleaned clips to <out-dir> plus manifest.csv (path,duration_s,peak_dbfs).

Stdlib only (wave, audioop, csv, os, sys).
"""
import audioop
import csv
import os
import sys
import wave

TARGET_RATE = 16000
TRIM_THRESHOLD = 300  # |sample| below this counts as silence for trimming
FRAME = 160  # 10 ms at 16 kHz


def load_wav(path):
    with wave.open(path, "rb") as w:
        if w.getframerate() != TARGET_RATE:
            raise ValueError(f"{path}: need 16 kHz, got {w.getframerate()}")
        if w.getnchannels() != 1:
            raise ValueError(f"{path}: need mono, got {w.getnchannels()} channels")
        if w.getsampwidth() != 2:
            raise ValueError(f"{path}: need 16-bit, got {w.getsampwidth() * 8}-bit")
        return w.readframes(w.getnframes())


def trim_silence(pcm):
    n = len(pcm) // 2
    lo, hi = 0, n
    while lo < hi:
        seg = pcm[lo * 2:(lo + FRAME) * 2]
        if audioop.max(seg, 2) >= TRIM_THRESHOLD:
            break
        lo += FRAME
    while hi > lo:
        seg = pcm[(hi - FRAME) * 2:hi * 2]
        if audioop.max(seg, 2) >= TRIM_THRESHOLD:
            break
        hi -= FRAME
    # keep 100 ms of padding on each side
    lo = max(0, lo - 1600)
    hi = min(n, hi + 1600)
    return pcm[lo * 2:hi * 2]


def normalize(pcm, target_dbfs=-3.0):
    peak = audioop.max(pcm, 2)
    if peak == 0:
        raise ValueError("clip is all silence")
    import math
    peak_dbfs = 20 * math.log10(peak / 32768.0)
    gain = 10 ** ((target_dbfs - peak_dbfs) / 20.0)
    out, _ = audioop.mul(pcm, 2, min(gain, 10.0)), None
    return out, peak_dbfs


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    src, dst = sys.argv[1], sys.argv[2]
    os.makedirs(dst, exist_ok=True)
    rows = []
    for name in sorted(os.listdir(src)):
        if not name.lower().endswith(".wav"):
            continue
        path = os.path.join(src, name)
        try:
            pcm = trim_silence(load_wav(path))
            pcm, peak_dbfs = normalize(pcm)
        except ValueError as e:
            print(f"SKIP {name}: {e}")
            continue
        if len(pcm) // 2 < TARGET_RATE // 2:  # < 0.5 s after trim: probably a misfire
            print(f"SKIP {name}: too short after trim")
            continue
        out_path = os.path.join(dst, name)
        with wave.open(out_path, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(TARGET_RATE)
            w.writeframes(pcm)
        dur = len(pcm) / 2 / TARGET_RATE
        rows.append((name, f"{dur:.2f}", f"{peak_dbfs:.1f}"))
        print(f"OK {name}: {dur:.2f}s peak {peak_dbfs:.1f} dBFS")
    with open(os.path.join(dst, "manifest.csv"), "w", newline="") as f:
        csv.writer(f).writerows([("file", "duration_s", "peak_dbfs")] + rows)
    print(f"wrote {len(rows)} clips + manifest.csv to {dst}")


if __name__ == "__main__":
    main()
