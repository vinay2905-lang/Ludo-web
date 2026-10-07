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

    job.add_discovered(path, out_dir)

    info = identify.run(path, job, out_dir)
    ext = info.get("ext")

    # Universal: strings + decoder chain + xor (fast portion only).
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
    # Memory analysis (Volatility) is slow — deferred to the deep phase.

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
    """Fast phase: quick checks only. Slow brute force waits for deep scan."""
    out_dir = os.path.join(work_dir, "out")
    os.makedirs(out_dir, exist_ok=True)
    job.phase = "fast"
    job.log(f"[*] FAST scan of {job.filename}")
    job.log(f"[*] flag format: {job.flag_format or '(generic fallback only)'}")
    try:
        _analyze_one(path, job, out_dir, 0, set(), [0])
    except Exception as e:  # noqa: BLE001
        import traceback
        job.log(f"[!] pipeline error: {e}", "warn")
        job.log(traceback.format_exc(), "warn")
    finally:
        job.section("FAST SCAN COMPLETE")
        if job.flags:
            job.log(f"[+] {len(job.flags)} confirmed flag(s) found", "flag")
        else:
            job.log("[*] no confirmed flags yet; review 'likely' panel and "
                    "the saved artifacts, or launch a DEEP scan for rockyou "
                    "brute force + Volatility", "info")
        job.log(f"[*] deep scan will target {len(job.discovered)} discovered "
                "file(s): rockyou steghide/zip, full-file XOR, Volatility 3",
                "info")
        job.deep_available = True
        job.done = True


def deep(job):
    """Deep phase: slow brute force over every file the fast phase found."""
    job.phase = "deep"
    job.done = False
    job.deep_started = True
    job.section("DEEP SCAN (rockyou + Volatility + full XOR)")
    try:
        targets = list(job.discovered)
        for path, out_dir in targets:
            if not os.path.isfile(path):
                continue
            name = os.path.basename(path)
            lower = path.lower()
            job.log(f"[>] deep scanning {name}", "info")

            encodings.deep(path, job)

            if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp",
                               ".webp")):
                image_stego.steghide_deep(path, job, out_dir)

            import zipfile
            if zipfile.is_zipfile(path):
                archives_docs.crack_zip_deep(path, job, out_dir)

            memory.run(path, job, out_dir)
    except Exception as e:  # noqa: BLE001
        import traceback
        job.log(f"[!] deep scan error: {e}", "warn")
        job.log(traceback.format_exc(), "warn")
    finally:
        job.section("DEEP SCAN COMPLETE")
        if job.flags:
            job.log(f"[+] {len(job.flags)} confirmed flag(s) total", "flag")
        else:
            job.log("[*] still no confirmed flags — inspect saved artifacts "
                    "manually", "info")
        job.done = True
