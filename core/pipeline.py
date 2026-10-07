"""Orchestrates all modules over a file, recursing into extracted artifacts."""
import os

from . import (identify, encodings, embedded, image_stego, audio, pcap,
               archives_docs, memory)

MAX_DEPTH = 3
MAX_FILES = 400


def _analyze_one(path, job, out_dir, depth, visited, counter):
    if counter[0] >= MAX_FILES:
        return
    rp = os.path.realpath(path)
    if rp in visited or not os.path.isfile(path):
        return
    visited.add(rp)
    counter[0] += 1

    info = identify.run(path, job, out_dir)
    ext = info.get("ext")

    # Universal: strings + decoder chain + xor.
    encodings.run(path, job)

    # Type-specific modules (cheap guards inside each).
    lower = path.lower()
    is_img = ext in ("png", "jpg", "gif", "bmp", "webp") or lower.endswith(
        (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"))
    is_audio = ext in ("wav", "mp3", "ogg", "flac") or lower.endswith(
        (".wav", ".mp3", ".ogg", ".flac"))
    is_pcap = ext in ("pcap", "pcapng") or lower.endswith(
        (".pcap", ".pcapng", ".cap"))

    if is_img:
        image_stego.run(path, job, out_dir, ext)
    if is_audio:
        audio.run(path, job, out_dir)
    if is_pcap:
        pcap.run(path, job, out_dir)

    archives_docs.run(path, job, out_dir)
    memory.run(path, job, out_dir)

    # Embedded extraction last, then recurse into whatever came out.
    if depth < MAX_DEPTH:
        extracted = embedded.run(path, job, out_dir)
        for child in extracted:
            child_out = os.path.join(out_dir, "recurse",
                                     os.path.basename(child) + "_d")
            os.makedirs(child_out, exist_ok=True)
            job.log(f"[>] recursing into {os.path.basename(child)} "
                    f"(depth {depth + 1})", "info")
            _analyze_one(child, job, child_out, depth + 1, visited, counter)


def analyze(path, job, work_dir):
    out_dir = os.path.join(work_dir, "out")
    os.makedirs(out_dir, exist_ok=True)
    job.log(f"[*] starting analysis of {job.filename}")
    job.log(f"[*] flag format: {job.flag_format or '(generic fallback only)'}")
    try:
        _analyze_one(path, job, out_dir, 0, set(), [0])
    except Exception as e:  # noqa: BLE001
        import traceback
        job.log(f"[!] pipeline error: {e}", "warn")
        job.log(traceback.format_exc(), "warn")
    finally:
        job.section("ANALYSIS COMPLETE")
        if job.flags:
            job.log(f"[+] {len(job.flags)} confirmed flag(s) found", "flag")
        else:
            job.log("[*] no confirmed flags; review 'likely' panel and the "
                    "saved artifacts (bit planes, spectrogram, extracted "
                    "files)", "info")
        job.done = True
