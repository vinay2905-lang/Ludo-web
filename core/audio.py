"""Audio: spectrogram render, DTMF decode, LSB on WAV samples."""
import os
import wave

from . import util

# DTMF frequency pairs.
DTMF = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
}


def _load(path):
    """Return (samples float array, samplerate) via scipy or wave."""
    try:
        from scipy.io import wavfile
        import numpy as np
        sr, data = wavfile.read(path)
        if data.ndim > 1:
            data = data[:, 0]
        return np.asarray(data, dtype=float), sr
    except Exception:
        pass
    try:
        import numpy as np
        with wave.open(path, "rb") as w:
            sr = w.getframerate()
            n = w.getnframes()
            raw = w.readframes(n)
        data = np.frombuffer(raw, dtype=np.int16)
        return data.astype(float), sr
    except Exception:
        return None, None


def _spectrogram(path, job, out_dir):
    try:
        import numpy as np
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:  # noqa: BLE001
        job.log(f"[!] matplotlib/numpy missing for spectrogram: {e}", "warn")
        return
    data, sr = _load(path)
    if data is None:
        job.log("[!] could not decode audio (is it WAV? try ffmpeg convert)",
                "warn")
        return
    plt.figure(figsize=(14, 6))
    plt.specgram(data, Fs=sr, NFFT=1024, noverlap=512, cmap="inferno")
    plt.title("Spectrogram — look for hidden text")
    plt.xlabel("Time (s)")
    plt.ylabel("Frequency (Hz)")
    out = os.path.join(out_dir, "spectrogram.png")
    plt.savefig(out, dpi=120, bbox_inches="tight")
    plt.close()
    job.log(f"[+] spectrogram saved -> {out} (open it; flags are often "
            "drawn as text in the frequency domain)", "good")


def _dtmf(path, job):
    data, sr = _load(path)
    if data is None:
        return
    try:
        import numpy as np
    except Exception:  # noqa: BLE001
        return
    win = int(0.04 * sr)          # 40 ms windows
    if win < 32:
        return
    low = [697, 770, 852, 941]
    high = [1209, 1336, 1477, 1633]
    seq = []
    last = None
    for i in range(0, len(data) - win, win // 2):   # 50% overlap
        seg = data[i:i + win] * np.hanning(win)
        spec = np.abs(np.fft.rfft(seg))
        freqs = np.fft.rfftfreq(win, 1 / sr)
        mean_mag = np.mean(spec) + 1e-9

        def strongest(group):
            """Return (freq, magnitude) of the loudest bin near the group."""
            best, best_mag = None, 0.0
            for f in group:
                idx = int(np.argmin(np.abs(freqs - f)))
                mag = float(spec[idx])
                if mag > best_mag:
                    best, best_mag = f, mag
            return best, best_mag

        lo, lo_mag = strongest(low)
        hi, hi_mag = strongest(high)
        # Both tones must clearly stand above the noise floor.
        if (lo_mag > mean_mag * 8 and hi_mag > mean_mag * 8
                and (lo, hi) in DTMF):
            d = DTMF[(lo, hi)]
            if d != last:
                seq.append(d)
            last = d
        else:
            last = None
    if seq:
        tones = "".join(seq)
        job.log(f"[+] DTMF tones decoded: {tones}", "good")
        job.scan(tones, "dtmf")


def _wav_lsb(path, job):
    data, sr = _load(path)
    if data is None:
        return
    try:
        import numpy as np
        bits = (np.asarray(data, dtype=np.int64) & 1).astype(np.uint8)
        packed = np.packbits(bits)
        job.scan(packed.tobytes().decode("latin-1", "replace"), "wav-lsb")
    except Exception:  # noqa: BLE001
        pass


def run(path, job, out_dir):
    job.section("5. AUDIO ANALYSIS")
    _spectrogram(path, job, out_dir)
    job.log("[*] attempting DTMF decode")
    _dtmf(path, job)
    _wav_lsb(path, job)
    job.log("[*] note: SSTV images require 'qsstv' — decode manually from "
            "the saved audio if the spectrogram looks like scanlines", "info")
