"""Embedded / appended files: binwalk, foremost, and a pure-python carver."""
import os
import zipfile

from . import util

# Signatures we can carve ourselves if binwalk/foremost are absent.
CARVE_SIGS = [
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF89a", "gif"),
    (b"GIF87a", "gif"),
    (b"%PDF", "pdf"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gz"),
]


def python_carve(path, job, out_dir):
    """Find known signatures past offset 0 and dump them to files."""
    with open(path, "rb") as f:
        data = f.read()
    found = []
    for sig, ext in CARVE_SIGS:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            if idx != 0:  # offset 0 is the host file itself
                chunk = data[idx:]
                name = os.path.join(out_dir, f"carved_{idx}.{ext}")
                with open(name, "wb") as fo:
                    fo.write(chunk)
                job.log(f"    [+] carved {ext} at offset {idx} -> {name}",
                        "good")
                found.append(name)
            start = idx + 1
    return found


def run(path, job, out_dir):
    job.section("3. EMBEDDED / APPENDED FILES")
    extracted = []

    if util.have("binwalk"):
        rc, out, _ = util.run(["binwalk", path])
        if rc == 0:
            job.log("[*] binwalk signatures:")
            for line in out.splitlines():
                if line.strip():
                    job.log("    " + line)
            job.scan(out, "binwalk")
        ex_dir = os.path.join(out_dir, "binwalk")
        os.makedirs(ex_dir, exist_ok=True)
        util.run(["binwalk", "--dd=.*", "-e", "-C", ex_dir, path])
        for root, _, files in os.walk(ex_dir):
            for fn in files:
                extracted.append(os.path.join(root, fn))
        if extracted:
            job.log(f"[+] binwalk extracted {len(extracted)} files", "good")
    else:
        job.log("[!] binwalk not installed — using python carver", "warn")

    if util.have("foremost"):
        fm_dir = os.path.join(out_dir, "foremost")
        rc, _, _ = util.run(["foremost", "-i", path, "-o", fm_dir])
        if os.path.isdir(fm_dir):
            for root, _, files in os.walk(fm_dir):
                for fn in files:
                    if fn != "audit.txt":
                        extracted.append(os.path.join(root, fn))

    # Always run the python carver too (free, no deps).
    extracted += python_carve(path, job, out_dir)

    # Auto-extract any zip we produced or were handed.
    for f in list(extracted) + [path]:
        if zipfile.is_zipfile(f):
            try:
                with zipfile.ZipFile(f) as z:
                    if not z.namelist():
                        continue
                    if any(zi.flag_bits & 0x1 for zi in z.infolist()):
                        job.log(f"    [!] {os.path.basename(f)} is password "
                                "protected (handled in archives module)",
                                "warn")
                        continue
                    zdir = os.path.join(out_dir, "unzip_" +
                                        os.path.basename(f))
                    z.extractall(zdir)
                    for n in z.namelist():
                        extracted.append(os.path.join(zdir, n))
                    job.log(f"    [+] unzipped {os.path.basename(f)}", "good")
            except Exception as e:  # noqa: BLE001
                job.log(f"    [!] zip error on {f}: {e}", "warn")

    uniq = sorted(set(p for p in extracted if os.path.isfile(p)))
    job.log(f"[*] total extracted/carved files: {len(uniq)}")
    return uniq
