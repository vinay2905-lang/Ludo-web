"""File identification and magic-byte repair (PNG / JPG / ZIP / GIF / PDF ...)."""
import os
import struct

from . import util

# (magic bytes, label, canonical extension)
MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG image", "png"),
    (b"\xff\xd8\xff", "JPEG image", "jpg"),
    (b"GIF87a", "GIF image", "gif"),
    (b"GIF89a", "GIF image", "gif"),
    (b"BM", "BMP image", "bmp"),
    (b"PK\x03\x04", "ZIP archive (or docx/xlsx/jar/apk)", "zip"),
    (b"PK\x05\x06", "ZIP archive (empty)", "zip"),
    (b"Rar!\x1a\x07", "RAR archive", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z"),
    (b"\x1f\x8b", "GZIP", "gz"),
    (b"BZh", "BZIP2", "bz2"),
    (b"\xfd7zXZ\x00", "XZ", "xz"),
    (b"%PDF", "PDF document", "pdf"),
    (b"ID3", "MP3 audio (ID3)", "mp3"),
    (b"RIFF", "RIFF (WAV/AVI/WEBP)", "wav"),
    (b"OggS", "OGG media", "ogg"),
    (b"fLaC", "FLAC audio", "flac"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "MS Office (OLE/doc/xls/ppt)", "ole"),
    (b"\x7fELF", "ELF executable", "elf"),
    (b"MZ", "DOS/PE executable", "exe"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat", "class"),
    (b"\xd4\xc3\xb2\xa1", "PCAP (libpcap LE)", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "PCAP (libpcap BE)", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG", "pcapng"),
]


def sniff(path):
    """Return (label, ext) from magic bytes, or (None, None)."""
    with open(path, "rb") as f:
        head = f.read(32)
    for magic, label, ext in MAGICS:
        if head.startswith(magic):
            return label, ext
    # WEBP is RIFF....WEBP
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "WEBP image", "webp"
    if head.startswith(b"RIFF") and head[8:12] == b"AVI ":
        return "AVI video", "avi"
    return None, None


def repair_png(path, job, out_dir):
    """Fix a wrong/missing PNG header and dump the declared dimensions."""
    with open(path, "rb") as f:
        data = f.read()
    sig = b"\x89PNG\r\n\x1a\n"
    changed = False
    if not data.startswith(sig):
        idx = data.find(b"IHDR")
        if idx != -1 and idx >= 8:
            # Reconstruct a header in front of IHDR's length field.
            data = sig + data[idx - 4:]
            changed = True
            job.log("    [*] reconstructed PNG signature before IHDR", "warn")
    ihdr = data.find(b"IHDR")
    if ihdr != -1 and len(data) >= ihdr + 12:
        w, h = struct.unpack(">II", data[ihdr + 4:ihdr + 12])
        job.log(f"    [*] PNG IHDR declares {w} x {h} px", "info")
        if h > 100000 or w > 100000:
            job.log("    [!] implausible dimension — height/width may be "
                    "altered to hide pixels (try bruteforcing)", "warn")
    if changed:
        fixed = os.path.join(out_dir, "repaired.png")
        with open(fixed, "wb") as f:
            f.write(data)
        job.log(f"    [+] wrote {fixed}", "good")
        return fixed
    return None


def run(path, job, out_dir):
    job.section("1. FILE IDENTIFICATION")
    size = os.path.getsize(path)
    job.log(f"[*] size: {size} bytes")

    label, ext = sniff(path)
    if label:
        job.log(f"[+] magic bytes => {label} (.{ext})", "good")
    else:
        job.log("[!] unknown/zeroed magic bytes — header may be corrupted "
                "or custom", "warn")

    # `file` adds a lot of detail when available.
    if util.have("file"):
        rc, out, _ = util.run(["file", "-b", path])
        if rc == 0:
            job.log(f"[*] file: {out.strip()}")

    # Extension-vs-content mismatch hint.
    actual_ext = os.path.splitext(job.filename)[1].lstrip(".").lower()
    if ext and actual_ext and ext != actual_ext and not (
            ext == "jpg" and actual_ext in ("jpeg",)):
        job.log(f"[!] extension '.{actual_ext}' does not match content "
                f"'.{ext}' — renamed/disguised file", "warn")

    # Header repair for common image types.
    if ext == "png" or actual_ext == "png":
        repair_png(path, job, out_dir)

    return {"label": label, "ext": ext}
