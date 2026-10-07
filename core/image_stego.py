"""Image steganography: exif, zsteg, steghide, LSB, channels, PNG dimension fix."""
import os
import struct
import zlib

from . import util

WORDLIST = "/usr/share/wordlists/rockyou.txt"


def _exif(path, job):
    if util.have("exiftool"):
        rc, out, _ = util.run(["exiftool", path])
        if rc == 0:
            job.log("[*] exiftool metadata:")
            for line in out.splitlines():
                job.log("    " + line)
            job.scan(out, "exiftool")
    else:
        # Minimal pillow fallback.
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(path)
            info = img.info
            job.scan(str(info), "pil-info")
            exif = getattr(img, "_getexif", lambda: None)()
            if exif:
                for k, v in exif.items():
                    job.scan(f"{TAGS.get(k, k)}: {v}", "pil-exif")
        except Exception as e:  # noqa: BLE001
            job.log(f"[!] exif read failed: {e}", "warn")


def _zsteg(path, job):
    if not util.have("zsteg"):
        job.log("[!] zsteg not installed (gem install zsteg) — using "
                "python LSB fallback", "warn")
        return
    rc, out, _ = util.run(["zsteg", "-a", path])
    if rc == 0 and out.strip():
        job.log("[*] zsteg -a output:")
        for line in out.splitlines():
            if line.strip():
                job.log("    " + line)
        job.scan(out, "zsteg")


def _steghide(path, job, out_dir):
    if not util.have("steghide"):
        job.log("[!] steghide not installed", "warn")
        return
    # Try empty password, then a short built-in list + rockyou if present.
    passwords = ["", "password", "flag", "ctf", "secret", "123456", "admin"]
    extra = []
    if os.path.exists(WORDLIST):
        try:
            with open(WORDLIST, encoding="latin-1") as f:
                extra = [w.strip() for w in f]  # full list: "run everything"
            job.log(f"[*] steghide: trying {len(extra)} rockyou passwords "
                    "(this can take a while)")
        except Exception:  # noqa: BLE001
            pass
    for pw in passwords + extra:
        out_file = os.path.join(out_dir, "steghide_out.bin")
        rc, _, err = util.run(
            ["steghide", "extract", "-sf", path, "-p", pw,
             "-xf", out_file, "-f"])
        if rc == 0 and os.path.exists(out_file):
            job.log(f"[+] steghide extracted with password '{pw}' -> "
                    f"{out_file}", "flag")
            try:
                with open(out_file, "rb") as f:
                    job.scan(f.read().decode("latin-1"), "steghide")
            except Exception:  # noqa: BLE001
                pass
            return out_file
    job.log("[*] steghide: no password worked", "info")


def _lsb_and_channels(path, job, out_dir):
    """Pure-python LSB extraction + per-channel bit-plane dumps."""
    try:
        import numpy as np
        from PIL import Image
    except Exception as e:  # noqa: BLE001
        job.log(f"[!] Pillow/numpy missing: {e}", "warn")
        return
    try:
        img = Image.open(path).convert("RGBA")
    except Exception as e:  # noqa: BLE001
        job.log(f"[!] cannot open image: {e}", "warn")
        return
    arr = np.array(img)
    h, w = arr.shape[:2]
    job.log(f"[*] LSB analysis on {w}x{h} image")
    # Extract LSB of each channel, both bit orders, as a byte stream.
    for ci, cname in enumerate(["R", "G", "B", "A"]):
        bits = (arr[:, :, ci] & 1).flatten()
        for order, label in ((bits, "msb"), (bits, "lsb")):
            packed = np.packbits(order if label == "msb" else order)
            txt = packed.tobytes().decode("latin-1", "replace")
            job.scan(txt, f"lsb:{cname}:{label}")
        # Visualise the bit plane (amplified) for the human to inspect.
        plane = ((arr[:, :, ci] & 1) * 255).astype("uint8")
        pimg = Image.fromarray(plane)
        pth = os.path.join(out_dir, f"bitplane_{cname}.png")
        pimg.save(pth)
    # Combined RGB LSB (common in simple challenges).
    rgb_bits = np.stack([(arr[:, :, i] & 1) for i in range(3)], axis=-1)
    packed = np.packbits(rgb_bits.flatten())
    job.scan(packed.tobytes().decode("latin-1", "replace"), "lsb:RGB")
    job.log("[*] saved bit-plane images (bitplane_R/G/B/A.png) for review")


def _png_dimension_bruteforce(path, job, out_dir):
    """PNG height/width is stored in IHDR; recompute CRC to spot/repair edits."""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    ihdr = data.find(b"IHDR")
    if ihdr == -1:
        return
    length_off = ihdr - 4
    chunk = data[ihdr:ihdr + 17]           # 'IHDR' + 13 data bytes
    stored_crc = struct.unpack(">I", data[ihdr + 17:ihdr + 21])[0]
    calc_crc = zlib.crc32(chunk) & 0xffffffff
    if stored_crc != calc_crc:
        w, h = struct.unpack(">II", data[ihdr + 4:ihdr + 12])
        job.log(f"[!] IHDR CRC mismatch (stored {stored_crc:08x} != "
                f"calc {calc_crc:08x}) — dimensions were edited! "
                f"declared {w}x{h}", "warn")
        # Brute force the height that makes the CRC match.
        for newh in range(1, 20000):
            test = chunk[:8] + struct.pack(">I", newh) + chunk[12:]
            if (zlib.crc32(test) & 0xffffffff) == stored_crc:
                job.log(f"[+] real height is {newh} px — flag likely hidden "
                        "in cropped rows", "flag")
                fixed = (data[:ihdr + 8] + struct.pack(">I", newh) +
                         data[ihdr + 12:])
                out = os.path.join(out_dir, "png_fixed_height.png")
                with open(out, "wb") as fo:
                    fo.write(fixed)
                job.log(f"    [+] wrote {out}", "good")
                return out
    else:
        job.log("[*] PNG IHDR CRC is valid")


def run(path, job, out_dir, ext):
    job.section("4. IMAGE STEGANOGRAPHY")
    _exif(path, job)
    if ext in ("png", "bmp") or path.lower().endswith((".png", ".bmp")):
        _zsteg(path, job)
        _png_dimension_bruteforce(path, job, out_dir)
    _steghide(path, job, out_dir)
    _lsb_and_channels(path, job, out_dir)

    # QR / barcode decode if present.
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar
        for code in zbar(Image.open(path)):
            txt = code.data.decode("utf-8", "replace")
            job.log(f"[+] barcode/QR decoded: {txt}", "good")
            job.scan(txt, "qr")
    except Exception:  # noqa: BLE001
        pass
