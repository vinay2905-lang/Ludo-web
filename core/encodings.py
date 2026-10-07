"""Strings extraction + a CyberChef-'magic'-style decoder chain."""
import base64
import binascii
import codecs
import os
import re

from . import util

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")

# Above this many strings, the per-string rot/base64 chain is too slow and too
# noisy (e.g. a disk image). We fall back to decoding only long encoded runs.
DECODER_MAX_STRINGS = 20000

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")


def _targeted_decode(blob, job):
    """For large inputs: decode only long base64/hex runs and flag-match them."""
    n = 0
    for m in _B64_RUN.finditer(blob):
        d = _try_b64(m.group())
        if d:
            job.scan(d, "decode:b64-run")
            n += 1
        if n > 5000:
            break
    for m in _HEX_RUN.finditer(blob):
        d = _try_hex(m.group())
        if d:
            job.scan(d, "decode:hex-run")
            n += 1
        if n > 10000:
            break
    job.log(f"[*] targeted decode examined {n} encoded runs")


def extract_strings(path, min_len=4):
    """Pure-python strings (ASCII + UTF-16LE) so we don't depend on binutils."""
    with open(path, "rb") as f:
        data = f.read()
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("latin-1"))
    # crude UTF-16LE
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        out.append(m.group().decode("utf-16le", "replace"))
    return out


# ---- decoder primitives ---------------------------------------------------
def _try_b64(s):
    try:
        if len(s) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", s):
            d = base64.b64decode(s, validate=True)
            return d.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        pass
    return None


def _try_b32(s):
    try:
        if re.fullmatch(r"[A-Z2-7=]+", s) and len(s) % 8 == 0:
            return base64.b32decode(s).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        pass
    return None


def _try_hex(s):
    try:
        s2 = s.strip().replace(" ", "")
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s2):
            return binascii.unhexlify(s2).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        pass
    return None


def _try_rot(s, n):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def _try_url(s):
    try:
        from urllib.parse import unquote
        if "%" in s:
            return unquote(s)
    except Exception:  # noqa: BLE001
        pass
    return None


def decoder_chain(s):
    """Yield (method, decoded) candidates for a single string."""
    cands = []
    for fn, name in ((_try_b64, "base64"), (_try_b32, "base32"),
                     (_try_hex, "hex")):
        d = fn(s)
        if d and d.isprintable():
            cands.append((name, d))
    u = _try_url(s)
    if u and u != s:
        cands.append(("url", u))
    for n in range(1, 26):
        cands.append((f"rot{n}", _try_rot(s, n)))
    cands.append(("reversed", s[::-1]))
    return cands


def xor_single_byte(data, job):
    """Try all 255 single-byte XOR keys over raw bytes, scan each result."""
    for key in range(1, 256):
        dec = bytes(b ^ key for b in data)
        try:
            txt = dec.decode("latin-1")
        except Exception:  # noqa: BLE001
            continue
        job.scan(txt, f"xor:0x{key:02x}", primary_only=True)


def run(path, job):
    job.section("2. STRINGS & ENCODINGS")
    strings = extract_strings(path)
    job.log(f"[*] extracted {len(strings)} candidate strings")

    blob = "\n".join(strings)
    job.scan(blob, "strings")

    # The decoder chain only ever reports the USER's flag format (primary_only):
    # matching a generic flag shape against decoded random bytes is noise.
    # Methods that compose (base64/base32/hex/url) get one level of nesting;
    # rot/reverse do not (a rot of a rot is just another rot).
    NESTABLE = {"base64", "base32", "hex", "url"}
    if len(strings) <= DECODER_MAX_STRINGS:
        job.log("[*] decoder chain: base64/32, hex, rot-N, url, reverse "
                "(flag-format matches only)")
        tested = 0
        for s in strings:
            s = s.strip()
            if len(s) < 6 or len(s) > 4096:
                continue
            for method, decoded in decoder_chain(s):
                if not decoded or decoded == s:
                    continue
                job.scan(decoded, f"decode:{method}", primary_only=True)
                if method in NESTABLE:
                    for m2, d2 in decoder_chain(decoded):
                        if d2 and d2 != decoded and m2 in NESTABLE:
                            job.scan(d2, f"decode:{method}>{m2}",
                                     primary_only=True)
            tested += 1
        job.log(f"[*] decoder chain tested {tested} strings")
    else:
        # Too many strings (big binary / disk image) to rot-shift them all.
        # Target only long encoded-looking runs, which is where real encoded
        # flags live.
        job.log(f"[*] {len(strings)} strings > {DECODER_MAX_STRINGS}: decoder "
                "chain limited to long base64/hex runs", "warn")
        _targeted_decode(blob, job)

    # Single-byte XOR over the whole file (cheap for small files).
    with open(path, "rb") as f:
        data = f.read()
    if len(data) <= 200_000:
        job.log("[*] brute-forcing single-byte XOR over raw bytes")
        xor_single_byte(data, job)
    else:
        job.log("[*] file >200KB — full-file XOR deferred to deep scan",
                "warn")

    # system `strings` too (catches encodings python missed).
    if util.have("strings"):
        rc, out, _ = util.run(["strings", "-n", "6", path])
        if rc == 0:
            job.scan(out, "strings(binutils)")


def deep(path, job):
    """Deep phase: full-file single-byte XOR for larger files."""
    with open(path, "rb") as f:
        data = f.read()
    if 200_000 < len(data) <= 20_000_000:
        job.log(f"[*] deep: single-byte XOR over {len(data)} bytes "
                f"({os.path.basename(path)})")
        xor_single_byte(data, job)
